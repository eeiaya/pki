
import pytest
import tempfile

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


from micropki.crypto_utils import (
    generate_rsa_key_pair,
    generate_ecc_key_pair,
    save_encrypted_private_key,
    load_encrypted_private_key,
    save_unencrypted_private_key,
    read_passphrase_file,
)
from micropki.certificates import (
    parse_subject_dn,
    generate_serial_number,
    create_self_signed_certificate,
    create_intermediate_certificate,
    create_leaf_certificate,
    parse_san_entries,
    get_cn_from_subject,
)
from micropki.csr import create_csr, verify_csr
from micropki.templates import get_template, validate_san_for_template, TEMPLATES
from micropki.chain import verify_chain
from micropki.ca import initialize_root_ca, issue_intermediate_ca, issue_certificate
from micropki.logger import setup_logger


# ============================================================
# Sprint 1 Tests
# ============================================================

class TestCryptoUtils:
    def test_generate_rsa_key(self):
        key = generate_rsa_key_pair(4096)
        assert key.key_size == 4096

    def test_generate_rsa_wrong_size(self):
        with pytest.raises(ValueError):
            generate_rsa_key_pair(1024)

    def test_generate_ecc_key(self):
        key = generate_ecc_key_pair(384)
        assert key.curve.key_size == 384

    def test_generate_ecc_wrong_size(self):
        with pytest.raises(ValueError):
            generate_ecc_key_pair(521)

    def test_save_and_load_encrypted_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / 'test.key'
            passphrase = b'test-passphrase-123'

            private_key = generate_rsa_key_pair(4096)
            save_encrypted_private_key(private_key, key_path, passphrase)
            assert key_path.exists()

            loaded_key = load_encrypted_private_key(key_path, passphrase)
            orig_pub = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            loaded_pub = loaded_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            assert orig_pub == loaded_pub

    def test_read_passphrase_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pass_file = Path(tmpdir) / 'passphrase.txt'
            with open(pass_file, 'wb') as f:
                f.write(b'my-secret-pass\n')
            passphrase = read_passphrase_file(pass_file)
            assert passphrase == b'my-secret-pass'


class TestDNParsing:
    def test_slash_notation(self):
        dn = parse_subject_dn("/CN=Test CA/O=Test Org/C=US")
        assert "CN=Test CA" in dn.rfc4514_string()

    def test_comma_notation(self):
        dn = parse_subject_dn("CN=Test CA,O=Test Org")
        assert "CN=Test CA" in dn.rfc4514_string()

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_subject_dn("")

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_subject_dn("InvalidDN")

    def test_get_cn(self):
        dn = parse_subject_dn("CN=Hello World,O=Test")
        assert get_cn_from_subject(dn) == "Hello World"


class TestSelfSignedCert:
    def test_create(self):
        key = generate_rsa_key_pair(4096)
        subject = parse_subject_dn("CN=Test Root CA")
        cert = create_self_signed_certificate(key, subject, 365)

        assert cert.subject == cert.issuer
        assert cert.version == x509.Version.v3

    def test_extensions(self):
        key = generate_rsa_key_pair(4096)
        subject = parse_subject_dn("CN=Test Root CA")
        cert = create_self_signed_certificate(key, subject, 365)

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

    def test_serial_number_unique(self):
        s1 = generate_serial_number()
        s2 = generate_serial_number()
        assert s1 > 0
        assert s2 > 0
        assert s1 != s2


# ============================================================
# Sprint 2 Tests
# ============================================================

class TestCSR:
    def test_create_csr(self):
        key = generate_rsa_key_pair(4096)
        subject = parse_subject_dn("CN=Intermediate CA")
        csr = create_csr(key, subject, is_ca=True, path_length=0)
        assert csr.subject == subject
        assert csr.is_signature_valid

    def test_csr_with_ecc(self):
        key = generate_ecc_key_pair(384)
        subject = parse_subject_dn("CN=ECC Intermediate")
        csr = create_csr(key, subject, is_ca=True, path_length=0)
        assert csr.is_signature_valid


class TestTemplates:
    def test_get_server_template(self):
        t = get_template("server")
        assert t.name == "server"
        assert t.san_required is True
        assert "serverAuth" in t.extended_key_usages

    def test_get_client_template(self):
        t = get_template("client")
        assert "clientAuth" in t.extended_key_usages

    def test_get_code_signing_template(self):
        t = get_template("code_signing")
        assert "codeSigning" in t.extended_key_usages

    def test_unknown_template_raises(self):
        with pytest.raises(ValueError):
            get_template("unknown")

    def test_validate_san_server_requires_san(self):
        t = get_template("server")
        with pytest.raises(ValueError, match="requires at least one SAN"):
            validate_san_for_template(t, [])

    def test_validate_san_server_valid(self):
        t = get_template("server")
        validate_san_for_template(t, ["dns:example.com"])  # no error

    def test_validate_san_server_rejects_email(self):
        t = get_template("server")
        with pytest.raises(ValueError, match="not allowed"):
            validate_san_for_template(t, ["email:test@example.com"])

    def test_validate_san_code_signing_rejects_ip(self):
        t = get_template("code_signing")
        with pytest.raises(ValueError, match="not allowed"):
            validate_san_for_template(t, ["ip:1.2.3.4"])


class TestSANParsing:
    def test_dns(self):
        san = parse_san_entries(["dns:example.com"])
        names = list(san)
        assert len(names) == 1
        assert isinstance(names[0], x509.DNSName)

    def test_ip(self):
        san = parse_san_entries(["ip:192.168.1.1"])
        names = list(san)
        assert isinstance(names[0], x509.IPAddress)

    def test_email(self):
        san = parse_san_entries(["email:test@example.com"])
        names = list(san)
        assert isinstance(names[0], x509.RFC822Name)

    def test_multiple(self):
        san = parse_san_entries(["dns:a.com", "dns:b.com", "ip:10.0.0.1"])
        assert len(list(san)) == 3

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            parse_san_entries(["no-colon-here"])

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError, match="Invalid IP"):
            parse_san_entries(["ip:not-an-ip"])

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown SAN type"):
            parse_san_entries(["ftp:something"])


class TestIntermediateCA:
    """Тесты для промежуточного CA и цепочки сертификатов."""

    @pytest.fixture
    def pki_setup(self):

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            root_pass = b'root-password'
            inter_pass = b'intermediate-password'

            # Корневой CA
            root_key = generate_rsa_key_pair(4096)
            root_subject = parse_subject_dn("CN=Test Root CA,O=Test")
            root_cert = create_self_signed_certificate(root_key, root_subject, 3650)

            # Промежуточный CA
            inter_key = generate_rsa_key_pair(4096)
            inter_subject = parse_subject_dn("CN=Test Intermediate CA,O=Test")
            csr = create_csr(inter_key, inter_subject, is_ca=True, path_length=0)

            inter_cert = create_intermediate_certificate(
                csr=csr,
                root_key=root_key,
                root_cert=root_cert,
                validity_days=1825,
                path_length=0
            )

            yield {
                'tmpdir': tmpdir,
                'root_key': root_key,
                'root_cert': root_cert,
                'root_pass': root_pass,
                'inter_key': inter_key,
                'inter_cert': inter_cert,
                'inter_pass': inter_pass,
            }

    def test_intermediate_cert_properties(self, pki_setup):
        cert = pki_setup['inter_cert']
        root = pki_setup['root_cert']


        assert cert.issuer == root.subject

        assert cert.subject != cert.issuer

    def test_intermediate_extensions(self, pki_setup):
        cert = pki_setup['inter_cert']

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.value.path_length == 0
        assert bc.critical is True

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

    def test_chain_verification(self, pki_setup):

        inter_key = pki_setup['inter_key']
        inter_cert = pki_setup['inter_cert']
        root_cert = pki_setup['root_cert']


        entity_key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=example.com")
        san = parse_san_entries(["dns:example.com"])

        leaf_cert = create_leaf_certificate(
            subject=subject,
            public_key=entity_key.public_key(),
            ca_key=inter_key,
            ca_cert=inter_cert,
            template_name="server",
            validity_days=365,
            san_extension=san
        )

        errors = verify_chain(leaf_cert, inter_cert, root_cert)
        assert errors == [], f"Chain verification failed: {errors}"


class TestLeafCertificates:
    """Тесты для конечных сертификатов."""

    @pytest.fixture
    def ca_setup(self):

        root_key = generate_rsa_key_pair(4096)
        root_subject = parse_subject_dn("CN=Root CA")
        root_cert = create_self_signed_certificate(root_key, root_subject, 3650)

        inter_key = generate_rsa_key_pair(4096)
        csr = create_csr(inter_key, parse_subject_dn("CN=Intermediate CA"), True, 0)
        inter_cert = create_intermediate_certificate(csr, root_key, root_cert, 1825, 0)

        return {
            'ca_key': inter_key,
            'ca_cert': inter_cert,
            'root_cert': root_cert,
        }

    def test_server_cert(self, ca_setup):
        entity_key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=example.com")
        san = parse_san_entries(["dns:example.com", "dns:www.example.com"])

        cert = create_leaf_certificate(
            subject=subject,
            public_key=entity_key.public_key(),
            ca_key=ca_setup['ca_key'],
            ca_cert=ca_setup['ca_cert'],
            template_name="server",
            validity_days=365,
            san_extension=san
        )


        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False


        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        from cryptography.x509.oid import ExtendedKeyUsageOID
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value


        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert "example.com" in dns_names
        assert "www.example.com" in dns_names

    def test_client_cert(self, ca_setup):
        entity_key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=Alice Smith")
        san = parse_san_entries(["email:alice@example.com"])

        cert = create_leaf_certificate(
            subject=subject,
            public_key=entity_key.public_key(),
            ca_key=ca_setup['ca_key'],
            ca_cert=ca_setup['ca_cert'],
            template_name="client",
            validity_days=365,
            san_extension=san
        )

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        from cryptography.x509.oid import ExtendedKeyUsageOID
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_code_signing_cert(self, ca_setup):
        entity_key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=Code Signer")

        cert = create_leaf_certificate(
            subject=subject,
            public_key=entity_key.public_key(),
            ca_key=ca_setup['ca_key'],
            ca_cert=ca_setup['ca_cert'],
            template_name="code_signing",
            validity_days=365,
        )

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        from cryptography.x509.oid import ExtendedKeyUsageOID
        assert ExtendedKeyUsageOID.CODE_SIGNING in eku.value

    def test_server_cert_without_san_fails(self, ca_setup):
        t = get_template("server")
        with pytest.raises(ValueError, match="requires at least one SAN"):
            validate_san_for_template(t, [])


class TestFullWorkflow:
    """Полный workflow: root -> intermediate -> leaf certificates."""

    def test_full_pki_workflow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / 'pki'
            root_pass_file = Path(tmpdir) / 'root.pass'
            inter_pass_file = Path(tmpdir) / 'inter.pass'

            root_pass_file.write_bytes(b'root-password-123')
            inter_pass_file.write_bytes(b'intermediate-password-456')

            logger = setup_logger()

            try:
                initialize_root_ca(
                    subject_dn="CN=Test Root CA",
                    key_type='rsa', key_size=4096,
                    passphrase=b'root-password-123',
                    out_dir=out_dir, validity_days=3650,
                    logger=logger
                )
                assert (out_dir / 'certs' / 'ca.cert.pem').exists()
                assert (out_dir / 'private' / 'ca.key.pem').exists()

                issue_intermediate_ca(
                    root_cert_path=out_dir / 'certs' / 'ca.cert.pem',
                    root_key_path=out_dir / 'private' / 'ca.key.pem',
                    root_passphrase=b'root-password-123',
                    subject_dn="CN=Test Intermediate CA",
                    key_type='rsa', key_size=4096,
                    passphrase=b'intermediate-password-456',
                    out_dir=out_dir, validity_days=1825,
                    path_length=0, logger=logger
                )
                assert (out_dir / 'certs' / 'intermediate.cert.pem').exists()
                assert (out_dir / 'private' / 'intermediate.key.pem').exists()

                issue_certificate(
                    ca_cert_path=out_dir / 'certs' / 'intermediate.cert.pem',
                    ca_key_path=out_dir / 'private' / 'intermediate.key.pem',
                    ca_passphrase=b'intermediate-password-456',
                    template_name='server',
                    subject_dn='CN=example.com',
                    san_entries=['dns:example.com', 'dns:www.example.com'],
                    out_dir=out_dir / 'certs',
                    validity_days=365,
                    logger=logger
                )
                assert (out_dir / 'certs' / 'example.com.cert.pem').exists()
                assert (out_dir / 'certs' / 'example.com.key.pem').exists()

            finally:
                for handler in logger.handlers[:]:
                    handler.close()
                    logger.removeHandler(handler)