from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime, timedelta, timezone
import hashlib
import logging

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .database import CertificateDatabase
from .crypto_utils import load_certificate


def _compute_issuer_hashes(ca_cert: x509.Certificate) -> Tuple[bytes, bytes]:
    issuer_name_der = ca_cert.subject.public_bytes()
    name_hash = hashlib.sha1(issuer_name_der).digest()

    pub_key = ca_cert.public_key()
    pub_key_der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # SHA1 от BIT STRING значения (без заголовка)
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from asn1crypto import pem as asn1pem, core, keys, algos
    import asn1crypto.public_key as asn1pk
    import asn1crypto.core as asn1core

    # Более надёжный способ через cryptography
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    spki_der = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # Парсим SPKI чтобы извлечь BIT STRING
    # SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING }
    # Нам нужен SHA1 от содержимого BIT STRING
    from cryptography.hazmat.bindings._rust import x509 as rust_x509
    key_hash = hashlib.sha1(
        pub_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
        if isinstance(pub_key, rsa.RSAPublicKey)
        else pub_key.public_bytes(Encoding.DER, PublicFormat.UncompressedPoint)
    ).digest()

    return name_hash, key_hash


def _get_issuer_key_hash(ca_cert: x509.Certificate) -> bytes:
    try:
        ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
        return ski
    except x509.ExtensionNotFound:
        from .crypto_utils import compute_ski
        return compute_ski(ca_cert.public_key())


def _get_issuer_name_hash(ca_cert: x509.Certificate) -> bytes:
    name_der = ca_cert.subject.public_bytes()
    return hashlib.sha1(name_der).digest()


class OCSPHandler:

    def __init__(
        self,
        db: CertificateDatabase,
        ca_cert: x509.Certificate,
        responder_cert: x509.Certificate,
        responder_key,
        cache_ttl: int = 60,
        logger: Optional[logging.Logger] = None
    ):
        self.db = db
        self.ca_cert = ca_cert
        self.responder_cert = responder_cert
        self.responder_key = responder_key
        self.cache_ttl = cache_ttl
        self.logger = logger or logging.getLogger('micropki.ocsp')

        self._issuer_name_hash = _get_issuer_name_hash(ca_cert)
        self._issuer_key_hash = _get_issuer_key_hash(ca_cert)

        self._cache: dict = {}

    def _get_hash_algorithm(self):
        if isinstance(self.responder_key, rsa.RSAPrivateKey):
            return hashes.SHA256()
        elif isinstance(self.responder_key, ec.EllipticCurvePrivateKey):
            return hashes.SHA384()
        return hashes.SHA256()

    def _is_known_issuer(self, req_name_hash: bytes, req_key_hash: bytes) -> bool:
        return (
            req_name_hash == self._issuer_name_hash or
            req_key_hash == self._issuer_key_hash
        )

    def _build_error_response(self, status: ocsp.OCSPResponseStatus) -> bytes:
        return ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(
            serialization.Encoding.DER
        )

    def _get_cert_status(self, serial_hex: str):
        cert_data = self.db.get_certificate(serial_hex)

        if cert_data is None:
            return 'unknown', None, None

        status = cert_data['status']

        if status == 'revoked':
            rev_date_str = cert_data.get('revocation_date')
            rev_date = datetime.fromisoformat(rev_date_str) if rev_date_str else datetime.now(timezone.utc)
            if rev_date.tzinfo is None:
                rev_date = rev_date.replace(tzinfo=timezone.utc)

            reason_str = cert_data.get('revocation_reason', 'unspecified')
            from .revocation import parse_revocation_reason, reason_to_x509_flag
            try:
                reason_enum = parse_revocation_reason(reason_str)
                reason_flag = reason_to_x509_flag(reason_enum)
            except Exception:
                reason_flag = x509.ReasonFlags.unspecified

            return 'revoked', rev_date, reason_flag

        return 'good', None, None

    def handle_request(self, request_der: bytes, client_ip: str = 'unknown') -> bytes:
        import time
        start_time = time.time()

        try:
            ocsp_request = ocsp.load_der_ocsp_request(request_der)
        except Exception as e:
            self.logger.error(f"OCSP malformed request from {client_ip}: {e}")
            return self._build_error_response(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        serial_number = ocsp_request.serial_number
        serial_hex = format(serial_number, 'X')

        req_name_hash = ocsp_request.issuer_name_hash
        req_key_hash = ocsp_request.issuer_key_hash
        req_hash_algorithm = ocsp_request.hash_algorithm

        # Извлекаем nonce
        nonce = None
        try:
            nonce_ext = ocsp_request.extensions.get_extension_for_class(x509.OCSPNonce)
            nonce = nonce_ext.value.nonce
        except x509.ExtensionNotFound:
            pass

        # Проверяем издателя
        if not self._is_known_issuer(req_name_hash, req_key_hash):
            self.logger.warning(
                f"OCSP unauthorized issuer from {client_ip}, serial={serial_hex}"
            )
            return self._build_error_response(ocsp.OCSPResponseStatus.UNAUTHORIZED)

        # Получаем статус
        try:
            status, rev_date, rev_reason = self._get_cert_status(serial_hex)
        except Exception as e:
            self.logger.error(f"OCSP DB error for serial={serial_hex}: {e}")
            return self._build_error_response(ocsp.OCSPResponseStatus.INTERNAL_ERROR)

        # Получаем сертификат из БД для построения ответа
        cert_data = self.db.get_certificate(serial_hex)
        target_cert = None
        if cert_data:
            try:
                target_cert = x509.load_pem_x509_certificate(
                    cert_data['cert_pem'].encode(), default_backend()
                )
            except Exception:
                target_cert = None

        now = datetime.now(timezone.utc)
        next_update = now + timedelta(seconds=self.cache_ttl)

        builder = ocsp.OCSPResponseBuilder()

        if status == 'unknown' or target_cert is None:
            # Для unknown используем add_response_by_hash
            builder = builder.add_response_by_hash(
                issuer_name_hash=req_name_hash,
                issuer_key_hash=req_key_hash,
                serial_number=serial_number,
                algorithm=req_hash_algorithm,
                cert_status=ocsp.OCSPCertStatus.UNKNOWN,
                this_update=now,
                next_update=next_update,
                revocation_time=None,
                revocation_reason=None
            )
        elif status == 'good':
            builder = builder.add_response(
                cert=target_cert,
                issuer=self.ca_cert,
                algorithm=hashes.SHA1(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=now,
                next_update=next_update,
                revocation_time=None,
                revocation_reason=None
            )
        else:  # revoked
            builder = builder.add_response(
                cert=target_cert,
                issuer=self.ca_cert,
                algorithm=hashes.SHA1(),
                cert_status=ocsp.OCSPCertStatus.REVOKED,
                this_update=now,
                next_update=next_update,
                revocation_time=rev_date,
                revocation_reason=rev_reason
            )

        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.HASH, self.responder_cert
        )

        if nonce is not None:
            builder = builder.add_extension(
                x509.OCSPNonce(nonce), critical=False
            )

        response = builder.sign(self.responder_key, self._get_hash_algorithm())
        response_der = response.public_bytes(serialization.Encoding.DER)

        elapsed_ms = int((time.time() - start_time) * 1000)
        self.logger.info(
            f"OCSP request: client={client_ip} serial={serial_hex} "
            f"status={status} nonce={'yes' if nonce else 'no'} time={elapsed_ms}ms"
        )

        return response_der