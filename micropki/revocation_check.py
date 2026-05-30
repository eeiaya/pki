from datetime import datetime, timezone
from typing import Optional, Tuple, List
from dataclasses import dataclass
from pathlib import Path
import logging
import os

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature


@dataclass
class RevocationResult:
    status: str  # 'good', 'revoked', 'unknown'
    method: str  # 'ocsp', 'crl', 'none'
    revocation_time: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    message: str = ""


def extract_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
        for desc in aia:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def extract_crl_urls(cert: x509.Certificate) -> List[str]:
    urls = []
    try:
        cdp = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
        for point in cdp:
            if point.full_name:
                for name in point.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return urls


def load_crl_from_file(path: Path) -> x509.CertificateRevocationList:
    data = Path(path).read_bytes()
    if b'-----BEGIN' in data:
        return x509.load_pem_x509_crl(data, default_backend())
    return x509.load_der_x509_crl(data, default_backend())


def load_crl_from_url(url: str, timeout: int = 10) -> x509.CertificateRevocationList:
    import requests
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.content
    if b'-----BEGIN' in data:
        return x509.load_pem_x509_crl(data, default_backend())
    return x509.load_der_x509_crl(data, default_backend())


def load_crl(source: str) -> x509.CertificateRevocationList:
    if source.startswith(('http://', 'https://')):
        return load_crl_from_url(source)
    return load_crl_from_file(Path(source))


def verify_crl_signature(crl: x509.CertificateRevocationList, issuer_cert: x509.Certificate) -> bool:
    issuer_pub = issuer_cert.public_key()
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            issuer_pub.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ec.ECDSA(crl.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except InvalidSignature:
        return False


def check_crl(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    crl_source: str,
    logger: Optional[logging.Logger] = None
) -> RevocationResult:
    log = logger or logging.getLogger('micropki.revocation')

    try:
        crl = load_crl(crl_source)
    except Exception as e:
        log.warning(f"Failed to load CRL from {crl_source}: {e}")
        return RevocationResult(
            status='unknown',
            method='crl',
            message=f"Failed to load CRL: {e}"
        )

    # Проверка подписи CRL
    if not verify_crl_signature(crl, issuer_cert):
        log.warning("CRL signature verification failed")
        return RevocationResult(
            status='unknown',
            method='crl',
            message="CRL signature invalid"
        )

    # Проверка соответствия издателя
    if crl.issuer != issuer_cert.subject:
        log.warning("CRL issuer mismatch")
        return RevocationResult(
            status='unknown',
            method='crl',
            message="CRL issuer does not match"
        )

    # Проверка актуальности
    now = datetime.now(timezone.utc)
    if crl.next_update_utc and now > crl.next_update_utc:
        log.warning(f"CRL is outdated (nextUpdate: {crl.next_update_utc})")

    # Поиск серийного номера в CRL
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked is not None:
        reason = None
        try:
            reason_ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            reason = 'unspecified'

        return RevocationResult(
            status='revoked',
            method='crl',
            revocation_time=revoked.revocation_date_utc,
            revocation_reason=reason,
            message=f"Certificate revoked on {revoked.revocation_date_utc}"
        )

    return RevocationResult(
        status='good',
        method='crl',
        message="Certificate not in CRL"
    )


def check_ocsp(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    ocsp_url: Optional[str] = None,
    use_nonce: bool = True,
    timeout: int = 10,
    logger: Optional[logging.Logger] = None
) -> RevocationResult:
    log = logger or logging.getLogger('micropki.revocation')
    import requests

    if ocsp_url is None:
        ocsp_url = extract_ocsp_url(cert)
        if ocsp_url is None:
            return RevocationResult(
                status='unknown',
                method='ocsp',
                message="No OCSP URL available (no AIA extension)"
            )

    # Создаём запрос
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, hashes.SHA1())

    nonce = None
    if use_nonce:
        nonce = os.urandom(16)
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)

    req = builder.build()
    req_der = req.public_bytes(serialization.Encoding.DER)

    # Отправляем
    try:
        resp = requests.post(
            ocsp_url,
            data=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=timeout
        )
        resp.raise_for_status()
    except Exception as e:
        log.warning(f"OCSP request failed: {e}")
        return RevocationResult(
            status='unknown',
            method='ocsp',
            message=f"OCSP request failed: {e}"
        )

    # Парсим ответ
    try:
        ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
    except Exception as e:
        return RevocationResult(
            status='unknown',
            method='ocsp',
            message=f"Failed to parse OCSP response: {e}"
        )

    if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return RevocationResult(
            status='unknown',
            method='ocsp',
            message=f"OCSP response status: {ocsp_resp.response_status}"
        )

    # Проверка nonce
    if nonce is not None:
        try:
            resp_nonce = ocsp_resp.extensions.get_extension_for_class(
                x509.OCSPNonce
            ).value.nonce
            if resp_nonce != nonce:
                log.warning("OCSP nonce mismatch")
                return RevocationResult(
                    status='unknown',
                    method='ocsp',
                    message="OCSP nonce mismatch"
                )
        except x509.ExtensionNotFound:
            pass  # Не критично

    # Извлекаем статус
    cert_status = ocsp_resp.certificate_status
    if cert_status == ocsp.OCSPCertStatus.GOOD:
        return RevocationResult(
            status='good',
            method='ocsp',
            message="OCSP responder says: GOOD"
        )
    elif cert_status == ocsp.OCSPCertStatus.REVOKED:
        reason = None
        if ocsp_resp.revocation_reason is not None:
            reason = ocsp_resp.revocation_reason.name
        return RevocationResult(
            status='revoked',
            method='ocsp',
            revocation_time=ocsp_resp.revocation_time_utc,
            revocation_reason=reason,
            message=f"Certificate revoked on {ocsp_resp.revocation_time_utc}"
        )
    else:
        return RevocationResult(
            status='unknown',
            method='ocsp',
            message="OCSP responder says: UNKNOWN"
        )


def check_revocation(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    ocsp_url: Optional[str] = None,
    crl_source: Optional[str] = None,
    prefer_ocsp: bool = True,
    logger: Optional[logging.Logger] = None
) -> RevocationResult:
    log = logger or logging.getLogger('micropki.revocation')

    # Авто-извлечение URLs если не заданы
    if ocsp_url is None:
        ocsp_url = extract_ocsp_url(cert)
    if crl_source is None:
        crl_urls = extract_crl_urls(cert)
        if crl_urls:
            crl_source = crl_urls[0]

    if prefer_ocsp:
        # Шаг 1: пробуем OCSP
        if ocsp_url:
            log.info(f"Trying OCSP: {ocsp_url}")
            ocsp_result = check_ocsp(cert, issuer_cert, ocsp_url, logger=log)
            if ocsp_result.status in ('good', 'revoked'):
                log.info(f"OCSP result: {ocsp_result.status}")
                return ocsp_result
            log.warning(f"OCSP failed ({ocsp_result.message}), falling back to CRL")

        # Шаг 2: fallback на CRL
        if crl_source:
            log.info(f"Trying CRL: {crl_source}")
            crl_result = check_crl(cert, issuer_cert, crl_source, logger=log)
            return crl_result

        return RevocationResult(
            status='unknown',
            method='none',
            message="No OCSP URL or CRL source available"
        )
    else:
        # Только CRL
        if crl_source:
            return check_crl(cert, issuer_cert, crl_source, logger=log)
        return RevocationResult(
            status='unknown',
            method='none',
            message="No CRL source available"
        )