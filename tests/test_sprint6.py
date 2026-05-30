import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from micropki.crypto_utils import (
    generate_rsa_key_pair,
    save_encrypted_private_key,
    save_unencrypted_private_key,
    save_certificate,
    load_certificate,
)
from micropki.certificates import (
    parse_subject_dn,
    create_self_signed_certificate,
    create_leaf_certificate,
    parse_san_entries,
)
from micropki.csr import create_csr
from micropki.database import CertificateDatabase
from micropki.validation import (
    validate_chain,
    build_chain,
    ValidationResult,
)
from micropki.revocation_check import (
    check_crl,
    check_ocsp,
    check_revocation,
    extract_ocsp_url,
    extract_crl_urls,
    load_crl,
    RevocationResult,
)
from micropki.crl import CRLManager
from micropki.client import client_gen_csr, client_validate
from micropki.ocsp import OCSPHandler
from micropki.certificates import create_ocsp_certificate
from micropki.ca import issue_certificate


# ============================================================
# Фикстура: полный PKI
# ============================================================

@pytest.fixture
def full_pki():
    temp_dir = tempfile.mkdtemp()
    out_dir = Path(temp_dir)

    (out_dir / 'private').mkdir()
    (out_dir / 'certs').mkdir()
    (out_dir / 'crl').mkdir()

    passphrase = b'testpass'
    pass_file = out_dir / 'ca.pass'
    pass_file.write_bytes(passphrase)

    # Root CA
    root_key = generate_rsa_key_pair(2048)
    root_subject = parse_subject_dn("CN=Test Root CA,O=Test")
    root_cert = create_self_signed_certificate(root_key, root_subject, 3650)
    save_encrypted_private_key(root_key, out_dir / 'private' / 'ca.key.pem', passphrase)
    save_certificate(root_cert, out_dir / 'certs' / 'ca.cert.pem')

    # Intermediate CA
    inter_key = generate_rsa_key_pair(2048)
    inter_subject = parse_subject_dn("CN=Test Intermediate CA,O=Test")

    from micropki.certificates import create_intermediate_certificate
    inter_csr = create_csr(inter_key, inter_subject, is_ca=True, path_length=0)
    inter_cert = create_intermediate_certificate(inter_csr, root_key, root_cert, 1825, 0)

    save_encrypted_private_key(inter_key, out_dir / 'private' / 'intermediate.key.pem', passphrase)
    save_certificate(inter_cert, out_dir / 'certs' / 'intermediate.cert.pem')

    # Server cert (valid)
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
    save_certificate(server_cert, out_dir / 'certs' / 'server.cert.pem')
    save_unencrypted_private_key(server_key, out_dir / 'certs' / 'server.key.pem')

    # Client cert (valid)
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
    save_certificate(client_cert, out_dir / 'certs' / 'client.cert.pem')

    # Revoked cert
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
    save_certificate(rev_cert, out_dir / 'certs' / 'revoked.cert.pem')

    # OCSP cert
    ocsp_key = generate_rsa_key_pair(2048)
    ocsp_subject = parse_subject_dn("CN=OCSP Responder")
    ocsp_cert = create_ocsp_certificate(
        subject=ocsp_subject,
        public_key=ocsp_key.public_key(),
        ca_key=inter_key,
        ca_cert=inter_cert,
        validity_days=365
    )
    save_certificate(ocsp_cert, out_dir / 'certs' / 'ocsp.cert.pem')
    save_unencrypted_private_key(ocsp_key, out_dir / 'certs' / 'ocsp.key.pem')

    # БД
    db_path = out_dir / 'certificates.db'
    db = CertificateDatabase(db_path)

    from cryptography.hazmat.primitives import serialization as _ser
    for c, tmpl in [
        (root_cert, 'root_ca'),
        (inter_cert, 'intermediate_ca'),
        (server_cert, 'server'),
        (client_cert, 'client'),
        (rev_cert, 'server'),
        (ocsp_cert, 'ocsp'),
    ]:
        pem = c.public_bytes(_ser.Encoding.PEM).decode()
        db.add_certificate(c, pem, template=tmpl)

    # Отзываем
    rev_serial = format(rev_cert.serial_number, 'X')
    db.revoke_certificate(rev_serial, 'keyCompromise')

    # Генерируем CRL для intermediate
    crl_manager = CRLManager(out_dir)
    revoked_list = db.get_revoked_by_issuer(inter_cert.subject.rfc4514_string())
    crl_path = crl_manager.generate_and_save_crl(
        ca_cert_path=out_dir / 'certs' / 'intermediate.cert.pem',
        ca_key_path=out_dir / 'private' / 'intermediate.key.pem',
        ca_passphrase=passphrase,
        revoked_certs=revoked_list,
        ca_name='intermediate',
        next_update_days=7
    )

    yield {
        'out_dir': out_dir,
        'db': db,
        'db_path': db_path,
        'root_cert': root_cert,
        'root_key': root_key,
        'inter_cert': inter_cert,
        'inter_key': inter_key,
        'server_cert': server_cert,
        'server_cert_path': out_dir / 'certs' / 'server.cert.pem',
        'server_key': server_key,
        'client_cert': client_cert,
        'client_cert_path': out_dir / 'certs' / 'client.cert.pem',
        'rev_cert': rev_cert,
        'rev_cert_path': out_dir / 'certs' / 'revoked.cert.pem',
        'rev_serial': rev_serial,
        'ocsp_cert': ocsp_cert,
        'ocsp_key': ocsp_key,
        'crl_path': crl_path,
        'passphrase': passphrase,
        'pass_file': pass_file,
    }

    shutil.rmtree(temp_dir)


# ============================================================
# TEST-38: Генерация CSR
# ============================================================

class TestCSRGeneration:

    def test_gen_csr_creates_files(self, tmp_path):
        key_path = tmp_path / 'key.pem'
        csr_path = tmp_path / 'request.csr.pem'

        client_gen_csr(
            subject_dn="CN=test.example.com",
            key_type='rsa',
            key_size=2048,
            san_entries=["dns:test.example.com"],
            out_key=key_path,
            out_csr=csr_path,
        )

        assert key_path.exists()
        assert csr_path.exists()

    def test_csr_has_correct_subject(self, tmp_path):
        csr_path = tmp_path / 'req.csr.pem'
        client_gen_csr(
            subject_dn="CN=app.example.com,O=Test",
            key_type='rsa',
            key_size=2048,
            san_entries=[],
            out_key=tmp_path / 'k.pem',
            out_csr=csr_path,
        )
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        assert "CN=app.example.com" in csr.subject.rfc4514_string()

    def test_csr_has_san(self, tmp_path):
        csr_path = tmp_path / 'req.csr.pem'
        client_gen_csr(
            subject_dn="CN=app.example.com",
            key_type='rsa',
            key_size=2048,
            san_entries=["dns:app.example.com", "dns:api.example.com"],
            out_key=tmp_path / 'k.pem',
            out_csr=csr_path,
        )
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = [n.value for n in san if isinstance(n, x509.DNSName)]
        assert "app.example.com" in dns_names
        assert "api.example.com" in dns_names

    def test_csr_signature_valid(self, tmp_path):
        csr_path = tmp_path / 'req.csr.pem'
        client_gen_csr(
            subject_dn="CN=test",
            key_type='rsa',
            key_size=2048,
            san_entries=[],
            out_key=tmp_path / 'k.pem',
            out_csr=csr_path,
        )
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        assert csr.is_signature_valid

    def test_ecc_csr(self, tmp_path):
        csr_path = tmp_path / 'req.csr.pem'
        client_gen_csr(
            subject_dn="CN=test",
            key_type='ecc',
            key_size=256,
            san_entries=[],
            out_key=tmp_path / 'k.pem',
            out_csr=csr_path,
        )
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        assert csr.is_signature_valid
        assert isinstance(csr.public_key(), ec.EllipticCurvePublicKey)


# ============================================================
# TEST-39: Подпись CSR через issue_certificate
# ============================================================

class TestCSRSigning:

    def test_sign_csr_extracts_subject_and_san(self, full_pki, tmp_path):
        setup = full_pki

        # Генерируем CSR
        csr_path = tmp_path / 'req.csr.pem'
        client_gen_csr(
            subject_dn="CN=fromcsr.example.com",
            key_type='rsa',
            key_size=2048,
            san_entries=["dns:fromcsr.example.com"],
            out_key=tmp_path / 'k.pem',
            out_csr=csr_path,
        )

        # Подписываем через issue_certificate с CSR
        serial = issue_certificate(
            ca_cert_path=setup['out_dir'] / 'certs' / 'intermediate.cert.pem',
            ca_key_path=setup['out_dir'] / 'private' / 'intermediate.key.pem',
            ca_passphrase=setup['passphrase'],
            template_name='server',
            subject_dn='',
            san_entries=[],
            out_dir=tmp_path,
            validity_days=365,
            db_path=setup['db_path'],
            csr_path=csr_path
        )

        assert serial is not None
        cert_data = setup['db'].get_certificate(serial)
        assert "fromcsr.example.com" in cert_data['subject']

    def test_csr_with_ca_true_rejected(self, full_pki, tmp_path):
        setup = full_pki

        # Создаём CSR с CA=True (нелегальный для конечного сертификата)
        key = generate_rsa_key_pair(2048)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(parse_subject_dn("CN=evil"))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        csr = builder.sign(key, hashes.SHA256(), default_backend())

        csr_path = tmp_path / 'bad.csr.pem'
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        with pytest.raises(ValueError, match="CA=True"):
            issue_certificate(
                ca_cert_path=setup['out_dir'] / 'certs' / 'intermediate.cert.pem',
                ca_key_path=setup['out_dir'] / 'private' / 'intermediate.key.pem',
                ca_passphrase=setup['passphrase'],
                template_name='server',
                subject_dn='',
                san_entries=[],
                out_dir=tmp_path,
                validity_days=365,
                csr_path=csr_path
            )


# ============================================================
# TEST-40: Валидация цепочки (валидная)
# ============================================================

class TestChainValidation:

    def test_valid_chain(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']]
        )
        assert result.success is True
        assert len(result.chain) == 3

    def test_chain_order(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']]
        )
        assert result.chain[0] == setup['server_cert']
        assert result.chain[1] == setup['inter_cert']
        assert result.chain[2] == setup['root_cert']

    def test_validation_steps_recorded(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']]
        )
        assert len(result.steps) > 0
        assert all(s.passed for s in result.steps)

    def test_result_to_dict(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']]
        )
        d = result.to_dict()
        assert 'success' in d
        assert 'chain' in d
        assert 'steps' in d


# ============================================================
# TEST-41: Просроченный сертификат
# ============================================================

class TestExpiredCertificate:

    def test_expired_cert_fails(self, full_pki):
        setup = full_pki
        # Используем validation_time через 2 года вперёд
        future = datetime.now(timezone.utc) + timedelta(days=730)
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']],
            validation_time=future
        )
        assert result.success is False
        assert 'Expired' in result.error or 'valid' in result.error.lower()

    def test_validation_time_in_past_before_notBefore(self, full_pki):
        setup = full_pki
        past = datetime(2000, 1, 1, tzinfo=timezone.utc)
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']],
            validation_time=past
        )
        assert result.success is False


# ============================================================
# TEST-42: EKU проверка
# ============================================================

class TestEKUCheck:

    def test_server_cert_passes_server_auth(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']],
            check_eku='serverAuth'
        )
        assert result.success is True

    def test_client_cert_fails_server_auth(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['client_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']],
            check_eku='serverAuth'
        )
        assert result.success is False

    def test_client_cert_passes_client_auth(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['client_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']],
            check_eku='clientAuth'
        )
        assert result.success is True


# ============================================================
# TEST-43: Проверка отзыва через CRL
# ============================================================

class TestCRLRevocationCheck:

    def test_valid_cert_good_in_crl(self, full_pki):
        setup = full_pki
        result = check_crl(
            cert=setup['server_cert'],
            issuer_cert=setup['inter_cert'],
            crl_source=str(setup['crl_path'])
        )
        assert result.status == 'good'
        assert result.method == 'crl'

    def test_revoked_cert_in_crl(self, full_pki):
        setup = full_pki
        result = check_crl(
            cert=setup['rev_cert'],
            issuer_cert=setup['inter_cert'],
            crl_source=str(setup['crl_path'])
        )
        assert result.status == 'revoked'
        assert result.method == 'crl'
        assert result.revocation_time is not None
        assert result.revocation_reason is not None

    def test_load_crl_from_pem(self, full_pki):
        crl = load_crl(str(full_pki['crl_path']))
        assert crl is not None


# ============================================================
# TEST-44: Проверка отзыва через OCSP (через handler напрямую)
# ============================================================

class TestOCSPRevocationCheck:

    def test_good_cert_via_ocsp_handler(self, full_pki):
        setup = full_pki

        # Используем OCSPHandler напрямую (без HTTP)
        handler = OCSPHandler(
            db=setup['db'],
            ca_cert=setup['inter_cert'],
            responder_cert=setup['ocsp_cert'],
            responder_key=setup['ocsp_key'],
        )

        from cryptography.x509 import ocsp as _ocsp
        req = _ocsp.OCSPRequestBuilder().add_certificate(
            setup['server_cert'], setup['inter_cert'], hashes.SHA1()
        ).build()
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = handler.handle_request(req_der)
        resp = _ocsp.load_der_ocsp_response(resp_der)

        assert resp.certificate_status == _ocsp.OCSPCertStatus.GOOD

    def test_revoked_cert_via_ocsp_handler(self, full_pki):
        setup = full_pki

        handler = OCSPHandler(
            db=setup['db'],
            ca_cert=setup['inter_cert'],
            responder_cert=setup['ocsp_cert'],
            responder_key=setup['ocsp_key'],
        )

        from cryptography.x509 import ocsp as _ocsp
        req = _ocsp.OCSPRequestBuilder().add_certificate(
            setup['rev_cert'], setup['inter_cert'], hashes.SHA1()
        ).build()
        req_der = req.public_bytes(serialization.Encoding.DER)

        resp_der = handler.handle_request(req_der)
        resp = _ocsp.load_der_ocsp_response(resp_der)

        assert resp.certificate_status == _ocsp.OCSPCertStatus.REVOKED


# ============================================================
# TEST-45: Логика fallback OCSP → CRL
# ============================================================

class TestRevocationFallback:

    def test_no_ocsp_fallback_to_crl_good(self, full_pki):
        setup = full_pki
        # OCSP URL не указан → fallback на CRL
        result = check_revocation(
            cert=setup['server_cert'],
            issuer_cert=setup['inter_cert'],
            ocsp_url=None,
            crl_source=str(setup['crl_path']),
            prefer_ocsp=True
        )
        assert result.status == 'good'
        assert result.method == 'crl'

    def test_no_ocsp_fallback_to_crl_revoked(self, full_pki):
        setup = full_pki
        result = check_revocation(
            cert=setup['rev_cert'],
            issuer_cert=setup['inter_cert'],
            ocsp_url=None,
            crl_source=str(setup['crl_path']),
            prefer_ocsp=True
        )
        assert result.status == 'revoked'
        assert result.method == 'crl'

    def test_ocsp_unreachable_falls_back_to_crl(self, full_pki):
        setup = full_pki
        # Указываем нерабочий OCSP URL
        result = check_revocation(
            cert=setup['rev_cert'],
            issuer_cert=setup['inter_cert'],
            ocsp_url='http://127.0.0.1:1/ocsp',  # порт 1 точно недоступен
            crl_source=str(setup['crl_path']),
            prefer_ocsp=True
        )
        assert result.status == 'revoked'
        assert result.method == 'crl'

    def test_both_unavailable_returns_unknown(self, full_pki):
        setup = full_pki
        result = check_revocation(
            cert=setup['server_cert'],
            issuer_cert=setup['inter_cert'],
            ocsp_url=None,
            crl_source=None,
            prefer_ocsp=True
        )
        assert result.status == 'unknown'


# ============================================================
# TEST-46: Построение цепочки без промежуточного
# ============================================================

class TestChainBuilding:

    def test_missing_intermediate_fails(self, full_pki):
        setup = full_pki
        # Не передаём промежуточный → построение должно провалиться
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[],
            trusted_certs=[setup['root_cert']]
        )
        assert result.success is False
        assert 'chain' in result.error.lower() or 'build' in result.error.lower()

    def test_with_intermediate_succeeds(self, full_pki):
        setup = full_pki
        result = validate_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']]
        )
        assert result.success is True

    def test_build_chain_returns_none_without_root(self, full_pki):
        setup = full_pki
        chain = build_chain(
            leaf_cert=setup['server_cert'],
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[]
        )
        assert chain is None


# ============================================================
# TEST: Извлечение URLs из расширений
# ============================================================

class TestExtensionExtraction:

    def test_extract_ocsp_url_returns_none_when_no_aia(self, full_pki):
        # Server cert не содержит AIA
        url = extract_ocsp_url(full_pki['server_cert'])
        assert url is None

    def test_extract_crl_urls_returns_empty_when_no_cdp(self, full_pki):
        urls = extract_crl_urls(full_pki['server_cert'])
        assert urls == []


# ============================================================
# Интеграционный тест полного жизненного цикла
# ============================================================

class TestSprint6Integration:

    def test_csr_to_validated_cert(self, full_pki, tmp_path):
        setup = full_pki

        # 1. Генерируем CSR
        csr_path = tmp_path / 'app.csr.pem'
        key_path = tmp_path / 'app.key.pem'
        client_gen_csr(
            subject_dn="CN=app.lifecycle.com",
            key_type='rsa',
            key_size=2048,
            san_entries=["dns:app.lifecycle.com"],
            out_key=key_path,
            out_csr=csr_path,
        )
        assert csr_path.exists()
        assert key_path.exists()

        # 2. Подписываем CSR через CA
        serial = issue_certificate(
            ca_cert_path=setup['out_dir'] / 'certs' / 'intermediate.cert.pem',
            ca_key_path=setup['out_dir'] / 'private' / 'intermediate.key.pem',
            ca_passphrase=setup['passphrase'],
            template_name='server',
            subject_dn='',
            san_entries=[],
            out_dir=tmp_path,
            validity_days=365,
            db_path=setup['db_path'],
            csr_path=csr_path
        )
        assert serial is not None

        # 3. Получаем сертификат из БД
        cert_data = setup['db'].get_certificate(serial)
        cert_pem_path = tmp_path / 'app.cert.pem'
        cert_pem_path.write_text(cert_data['cert_pem'])

        # 4. Валидируем цепочку
        cert = load_certificate(cert_pem_path)
        result = validate_chain(
            leaf_cert=cert,
            untrusted_certs=[setup['inter_cert']],
            trusted_certs=[setup['root_cert']]
        )
        assert result.success is True

        # 5. Проверяем что в сертификате есть SAN из CSR
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = [n.value for n in san if isinstance(n, x509.DNSName)]
        assert "app.lifecycle.com" in dns_names

        # 6. Проверка отзыва по CRL → good
        rev = check_crl(
            cert=cert,
            issuer_cert=setup['inter_cert'],
            crl_source=str(setup['crl_path'])
        )
        assert rev.status == 'good'

    def test_revoke_then_revocation_detected(self, full_pki):
        setup = full_pki

        # Используем уже отозванный rev_cert
        result = check_crl(
            cert=setup['rev_cert'],
            issuer_cert=setup['inter_cert'],
            crl_source=str(setup['crl_path'])
        )
        assert result.status == 'revoked'