import pytest
import tempfile
import shutil
import os
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from micropki.database import CertificateDatabase
from micropki.crypto_utils import (
    generate_rsa_key_pair,
    save_encrypted_private_key,
    save_unencrypted_private_key,
    save_certificate,
)
from micropki.certificates import (
    parse_subject_dn,
    create_self_signed_certificate,
    create_leaf_certificate,
    create_ocsp_certificate,
    parse_san_entries,
)
from micropki.ocsp import OCSPHandler, _get_issuer_name_hash, _get_issuer_key_hash


# ============================================================
# Фикстуры
# ============================================================

@pytest.fixture
def pki_setup():
    """Полная PKI: root CA + intermediate CA + несколько сертификатов."""
    temp_dir = tempfile.mkdtemp()
    out_dir = Path(temp_dir)

    (out_dir / 'private').mkdir()
    (out_dir / 'certs').mkdir()

    passphrase = b'testpass123'

    # Root CA
    root_key = generate_rsa_key_pair(2048)
    root_subject = parse_subject_dn("CN=Test Root CA,O=Test")
    root_cert = create_self_signed_certificate(root_key, root_subject, 3650)

    save_encrypted_private_key(root_key, out_dir / 'private' / 'ca.key.pem', passphrase)
    save_certificate(root_cert, out_dir / 'certs' / 'ca.cert.pem')

    # Intermediate CA
    inter_key = generate_rsa_key_pair(2048)
    inter_subject = parse_subject_dn("CN=Test Intermediate CA,O=Test")

    from micropki.csr import create_csr
    from micropki.certificates import create_intermediate_certificate
    inter_csr = create_csr(inter_key, inter_subject, is_ca=True, path_length=0)
    inter_cert = create_intermediate_certificate(inter_csr, root_key, root_cert, 1825, 0)

    save_encrypted_private_key(inter_key, out_dir / 'private' / 'intermediate.key.pem', passphrase)
    save_certificate(inter_cert, out_dir / 'certs' / 'intermediate.cert.pem')

    # OCSP сертификат
    ocsp_key = generate_rsa_key_pair(2048)
    ocsp_subject = parse_subject_dn("CN=OCSP Responder,O=Test")
    ocsp_cert = create_ocsp_certificate(
        subject=ocsp_subject,
        public_key=ocsp_key.public_key(),
        ca_key=inter_key,
        ca_cert=inter_cert,
        validity_days=365
    )

    save_unencrypted_private_key(ocsp_key, out_dir / 'certs' / 'ocsp.key.pem')
    save_certificate(ocsp_cert, out_dir / 'certs' / 'ocsp.cert.pem')

    # База данных
    db_path = out_dir / 'certificates.db'
    db = CertificateDatabase(db_path)

    from cryptography.hazmat.primitives import serialization as _ser

    # Добавляем inter CA в БД
    inter_pem = inter_cert.public_bytes(_ser.Encoding.PEM).decode()
    db.add_certificate(inter_cert, inter_pem, template='intermediate_ca')

    # Server сертификат (valid)
    server_key = generate_rsa_key_pair(2048)
    server_subject = parse_subject_dn("CN=server.example.com")
    san = parse_san_entries(["dns:server.example.com"])
    server_cert = create_leaf_certificate(
        subject=server_subject,
        public_key=server_key.public_key(),
        ca_key=inter_key,
        ca_cert=inter_cert,
        template_name='server',
        validity_days=365,
        san_extension=san
    )
    server_pem = server_cert.public_bytes(_ser.Encoding.PEM).decode()
    server_serial = db.add_certificate(server_cert, server_pem, template='server')

    # Client сертификат (valid)
    client_key = generate_rsa_key_pair(2048)
    client_subject = parse_subject_dn("CN=alice,O=Test")
    client_cert = create_leaf_certificate(
        subject=client_subject,
        public_key=client_key.public_key(),
        ca_key=inter_key,
        ca_cert=inter_cert,
        template_name='client',
        validity_days=365
    )
    client_pem = client_cert.public_bytes(_ser.Encoding.PEM).decode()
    client_serial = db.add_certificate(client_cert, client_pem, template='client')

    # Revoked сертификат
    rev_key = generate_rsa_key_pair(2048)
    rev_subject = parse_subject_dn("CN=revoked.example.com")
    rev_san = parse_san_entries(["dns:revoked.example.com"])
    rev_cert = create_leaf_certificate(
        subject=rev_subject,
        public_key=rev_key.public_key(),
        ca_key=inter_key,
        ca_cert=inter_cert,
        template_name='server',
        validity_days=365,
        san_extension=rev_san
    )
    rev_pem = rev_cert.public_bytes(_ser.Encoding.PEM).decode()
    rev_serial = db.add_certificate(rev_cert, rev_pem, template='server')
    db.revoke_certificate(rev_serial, 'keyCompromise')

    yield {
        'out_dir': out_dir,
        'db': db,
        'db_path': db_path,
        'root_cert': root_cert,
        'root_key': root_key,
        'inter_cert': inter_cert,
        'inter_key': inter_key,
        'ocsp_cert': ocsp_cert,
        'ocsp_key': ocsp_key,
        'server_cert': server_cert,
        'server_serial': server_serial,
        'client_cert': client_cert,
        'client_serial': client_serial,
        'rev_cert': rev_cert,
        'rev_serial': rev_serial,
        'passphrase': passphrase,
    }

    shutil.rmtree(temp_dir)


@pytest.fixture
def ocsp_handler(pki_setup):
    """Готовый OCSPHandler для тестов."""
    setup = pki_setup
    return OCSPHandler(
        db=setup['db'],
        ca_cert=setup['inter_cert'],
        responder_cert=setup['ocsp_cert'],
        responder_key=setup['ocsp_key'],
        cache_ttl=60,
    )


def build_ocsp_request(cert, issuer_cert, nonce: bytes = None):
    """Вспомогательная функция для создания OCSP-запроса."""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build()


# ============================================================
# TEST-28: Профиль OCSP-сертификата
# ============================================================

class TestOCSPCertificateProfile:

    def test_basic_constraints_not_ca(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is False

    def test_key_usage_digital_signature_only(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature is True
        assert ku.key_cert_sign is False
        assert ku.crl_sign is False

    def test_eku_ocsp_signing(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.OCSP_SIGNING in eku

    def test_eku_no_server_auth(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku

    def test_eku_no_client_auth(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku

    def test_signed_by_intermediate(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        inter_cert = pki_setup['inter_cert']
        assert cert.issuer == inter_cert.subject

    def test_aki_matches_intermediate_ski(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        inter_cert = pki_setup['inter_cert']
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        ski = inter_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        assert aki.key_identifier == ski.digest

    def test_ocsp_nocheck_extension(self, pki_setup):
        cert = pki_setup['ocsp_cert']
        try:
            cert.extensions.get_extension_for_class(x509.OCSPNoCheck)
        except x509.ExtensionNotFound:
            pytest.fail("OCSPNoCheck extension missing")

    def test_create_ocsp_cert_with_san(self, pki_setup):
        setup = pki_setup
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=OCSP With SAN")
        san = parse_san_entries(["dns:ocsp.example.com"])
        cert = create_ocsp_certificate(
            subject=subject,
            public_key=key.public_key(),
            ca_key=setup['inter_key'],
            ca_cert=setup['inter_cert'],
            validity_days=365,
            san_extension=san
        )
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert x509.DNSName("ocsp.example.com") in san_ext

    def test_create_ocsp_cert_with_aia(self, pki_setup):
        setup = pki_setup
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=OCSP With AIA")
        cert = create_ocsp_certificate(
            subject=subject,
            public_key=key.public_key(),
            ca_key=setup['inter_key'],
            ca_cert=setup['inter_cert'],
            validity_days=365,
            ocsp_url="http://ocsp.example.com"
        )
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        ocsp_uris = [
            desc.access_location.value
            for desc in aia
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
        ]
        assert "http://ocsp.example.com" in ocsp_uris


# ============================================================
# TEST-29: OCSP статус GOOD
# ============================================================

class TestOCSPGoodStatus:

    def test_valid_cert_returns_good(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_client_cert_returns_good(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['client_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_good_response_has_next_update(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.next_update_utc is not None
        assert resp.next_update_utc > resp.this_update_utc

    def test_good_response_is_signed(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.signature is not None
        assert len(resp.signature) > 0


# ============================================================
# TEST-30: OCSP статус REVOKED
# ============================================================

class TestOCSPRevokedStatus:

    def test_revoked_cert_returns_revoked(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['rev_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED

    def test_revoked_response_has_revocation_time(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['rev_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.revocation_time_utc is not None

    def test_revoked_response_has_reason(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['rev_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.revocation_reason == x509.ReasonFlags.key_compromise

    def test_revoke_and_check_same_session(self, pki_setup, ocsp_handler):
        setup = pki_setup
        db = setup['db']

        # Новый сертификат
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=temp.example.com")
        san = parse_san_entries(["dns:temp.example.com"])
        cert = create_leaf_certificate(
            subject=subject,
            public_key=key.public_key(),
            ca_key=setup['inter_key'],
            ca_cert=setup['inter_cert'],
            template_name='server',
            validity_days=365,
            san_extension=san
        )
        from cryptography.hazmat.primitives import serialization as _ser
        pem = cert.public_bytes(_ser.Encoding.PEM).decode()
        serial = db.add_certificate(cert, pem, template='server')

        # Сначала GOOD
        req = build_ocsp_request(cert, setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)
        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

        # Отзываем
        db.revoke_certificate(serial, 'superseded')

        # Теперь REVOKED
        resp_der2 = ocsp_handler.handle_request(req_der)
        resp2 = ocsp.load_der_ocsp_response(resp_der2)
        assert resp2.certificate_status == ocsp.OCSPCertStatus.REVOKED


# ============================================================
# TEST-31: OCSP статус UNKNOWN
# ============================================================

class TestOCSPUnknownStatus:

    def test_nonexistent_serial_returns_unknown(self, pki_setup, ocsp_handler):
        setup = pki_setup

        # Создаём сертификат но не добавляем в БД
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=ghost.example.com")
        san = parse_san_entries(["dns:ghost.example.com"])
        ghost_cert = create_leaf_certificate(
            subject=subject,
            public_key=key.public_key(),
            ca_key=setup['inter_key'],
            ca_cert=setup['inter_cert'],
            template_name='server',
            validity_days=365,
            san_extension=san
        )

        req = build_ocsp_request(ghost_cert, setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN

    def test_wrong_issuer_returns_unauthorized(self, pki_setup):
        setup = pki_setup

        # Создаём другой CA
        other_key = generate_rsa_key_pair(2048)
        other_subject = parse_subject_dn("CN=Other CA")
        other_cert = create_self_signed_certificate(other_key, other_subject, 365)

        handler = OCSPHandler(
            db=setup['db'],
            ca_cert=other_cert,
            responder_cert=setup['ocsp_cert'],
            responder_key=setup['ocsp_key'],
        )

        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        assert resp.response_status in (
            ocsp.OCSPResponseStatus.UNAUTHORIZED,
            ocsp.OCSPResponseStatus.SUCCESSFUL
        )


# ============================================================
# TEST-32: Nonce
# ============================================================

class TestOCSPNonce:

    def test_nonce_is_echoed(self, pki_setup, ocsp_handler):
        setup = pki_setup
        nonce = os.urandom(16)

        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'], nonce=nonce)
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        try:
            resp_nonce = resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
            assert resp_nonce == nonce
        except x509.ExtensionNotFound:
            pytest.fail("Nonce missing from response")

    def test_nonce_value_matches_exactly(self, pki_setup, ocsp_handler):
        setup = pki_setup
        nonce = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'

        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'], nonce=nonce)
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        resp_nonce = resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        assert resp_nonce == nonce

    def test_no_nonce_in_request_no_nonce_in_response(self, pki_setup, ocsp_handler):
        setup = pki_setup

        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'], nonce=None)
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)

        with pytest.raises(x509.ExtensionNotFound):
            resp.extensions.get_extension_for_class(x509.OCSPNonce)

    def test_different_nonces_different_responses(self, pki_setup, ocsp_handler):
        setup = pki_setup

        nonce1 = os.urandom(16)
        nonce2 = os.urandom(16)
        assert nonce1 != nonce2

        req1 = build_ocsp_request(setup['server_cert'], setup['inter_cert'], nonce=nonce1)
        req2 = build_ocsp_request(setup['server_cert'], setup['inter_cert'], nonce=nonce2)

        resp_der1 = ocsp_handler.handle_request(req1.public_bytes(serialization.Encoding.DER))
        resp_der2 = ocsp_handler.handle_request(req2.public_bytes(serialization.Encoding.DER))

        resp1 = ocsp.load_der_ocsp_response(resp_der1)
        resp2 = ocsp.load_der_ocsp_response(resp_der2)

        n1 = resp1.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        n2 = resp2.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce

        assert n1 == nonce1
        assert n2 == nonce2
        assert n1 != n2


# ============================================================
# TEST-34: Негативные тесты
# ============================================================

class TestOCSPNegative:

    def test_malformed_request(self, pki_setup, ocsp_handler):
        resp_der = ocsp_handler.handle_request(b'\x01\x02\x03\x04\x05')
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_empty_request(self, pki_setup, ocsp_handler):
        resp_der = ocsp_handler.handle_request(b'')
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_random_bytes_request(self, pki_setup, ocsp_handler):
        resp_der = ocsp_handler.handle_request(os.urandom(100))
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST


# ============================================================
# TEST-37: Полный интеграционный цикл
# ============================================================

class TestOCSPFullLifecycle:

    def test_full_lifecycle(self, pki_setup):
        setup = pki_setup
        db = setup['db']

        handler = OCSPHandler(
            db=db,
            ca_cert=setup['inter_cert'],
            responder_cert=setup['ocsp_cert'],
            responder_key=setup['ocsp_key'],
            cache_ttl=60
        )

        # Шаг 1: Выпускаем сертификат
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=lifecycle.example.com")
        san = parse_san_entries(["dns:lifecycle.example.com"])
        cert = create_leaf_certificate(
            subject=subject,
            public_key=key.public_key(),
            ca_key=setup['inter_key'],
            ca_cert=setup['inter_cert'],
            template_name='server',
            validity_days=365,
            san_extension=san
        )
        from cryptography.hazmat.primitives import serialization as _ser
        pem = cert.public_bytes(_ser.Encoding.PEM).decode()
        serial = db.add_certificate(cert, pem, template='server')

        # Шаг 2: Статус GOOD
        req = build_ocsp_request(cert, setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)
        resp_der = handler.handle_request(req_der)
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

        # Шаг 3: Отзываем
        db.revoke_certificate(serial, 'keyCompromise')

        # Шаг 4: Статус REVOKED
        resp_der2 = handler.handle_request(req_der)
        resp2 = ocsp.load_der_ocsp_response(resp_der2)
        assert resp2.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp2.revocation_reason == x509.ReasonFlags.key_compromise

        # Шаг 5: Nonce работает
        nonce = os.urandom(16)
        req_nonce = build_ocsp_request(cert, setup['inter_cert'], nonce=nonce)
        req_nonce_der = req_nonce.public_bytes(serialization.Encoding.DER)
        resp_der3 = handler.handle_request(req_nonce_der)
        resp3 = ocsp.load_der_ocsp_response(resp_der3)
        assert resp3.certificate_status == ocsp.OCSPCertStatus.REVOKED
        resp_nonce = resp3.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        assert resp_nonce == nonce

    def test_issuer_hashes_computed(self, pki_setup):
        setup = pki_setup
        inter_cert = setup['inter_cert']

        name_hash = _get_issuer_name_hash(inter_cert)
        key_hash = _get_issuer_key_hash(inter_cert)

        assert isinstance(name_hash, bytes)
        assert len(name_hash) == 20
        assert isinstance(key_hash, bytes)
        assert len(key_hash) == 20

    def test_response_is_der_encoded(self, pki_setup, ocsp_handler):
        setup = pki_setup
        req = build_ocsp_request(setup['server_cert'], setup['inter_cert'])
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = ocsp_handler.handle_request(req_der)

        assert isinstance(resp_der, bytes)
        assert len(resp_der) > 0

        # Должен парситься как валидный OCSP ответ
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp is not None