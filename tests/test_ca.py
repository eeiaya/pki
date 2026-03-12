"""
Unit tests for MicroPKI
"""

import pytest
import tempfile
import shutil
from pathlib import Path

from micropki.crypto_utils import (
    generate_rsa_key_pair,
    generate_ecc_key_pair,
    save_encrypted_private_key,
    load_encrypted_private_key,
    read_passphrase_file,
)
from micropki.certificates import (
    parse_subject_dn,
    generate_serial_number,
    create_self_signed_certificate,
)
from micropki.ca import initialize_root_ca
from micropki.logger import setup_logger

# Import for serialization (needed for test)
from cryptography.hazmat.primitives import serialization


class TestCryptoUtils:
    """Test cryptographic utility functions"""

    def test_generate_rsa_key(self):
        """Test RSA key generation"""
        key = generate_rsa_key_pair(4096)
        assert key.key_size == 4096

    def test_generate_rsa_wrong_size(self):
        """Test RSA key generation with wrong size"""
        with pytest.raises(ValueError):
            generate_rsa_key_pair(2048)

    def test_generate_ecc_key(self):
        """Test ECC key generation"""
        key = generate_ecc_key_pair(384)
        assert key.curve.key_size == 384

    def test_generate_ecc_wrong_size(self):
        """Test ECC key generation with wrong size"""
        with pytest.raises(ValueError):
            generate_ecc_key_pair(256)

    def test_save_and_load_encrypted_key(self):
        """Test saving and loading encrypted private key"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / 'test.key'
            passphrase = b'test-passphrase-123'


            private_key = generate_rsa_key_pair(4096)
            save_encrypted_private_key(private_key, key_path, passphrase)


            assert key_path.exists()


            loaded_key = load_encrypted_private_key(key_path, passphrase)


            original_public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            loaded_public = loaded_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            assert original_public == loaded_public

    def test_read_passphrase_file(self):
        """Test reading passphrase from file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pass_file = Path(tmpdir) / 'passphrase.txt'


            with open(pass_file, 'wb') as f:
                f.write(b'my-secret-pass\n')


            passphrase = read_passphrase_file(pass_file)
            assert passphrase == b'my-secret-pass'


class TestCertificates:
    """Test certificate operations"""

    def test_parse_dn_slash_notation(self):
        """Test parsing DN in slash notation"""
        dn = parse_subject_dn("/CN=Test CA/O=Test Org/C=US")
        assert dn.rfc4514_string() == "C=US,O=Test Org,CN=Test CA"

    def test_parse_dn_comma_notation(self):
        """Test parsing DN in comma notation"""
        dn = parse_subject_dn("CN=Test CA,O=Test Org,C=US")
        assert "CN=Test CA" in dn.rfc4514_string()

    def test_parse_dn_empty(self):
        """Test parsing empty DN"""
        with pytest.raises(ValueError):
            parse_subject_dn("")

    def test_parse_dn_invalid(self):
        """Test parsing invalid DN"""
        with pytest.raises(ValueError):
            parse_subject_dn("InvalidDN")

    def test_generate_serial_number(self):
        """Test serial number generation"""
        serial1 = generate_serial_number()
        serial2 = generate_serial_number()


        assert serial1 > 0
        assert serial2 > 0


        assert serial1 != serial2


        assert serial1 < (1 << 160)

    def test_create_self_signed_cert(self):
        """Test self-signed certificate creation"""
        from cryptography import x509

        private_key = generate_rsa_key_pair(4096)
        subject = parse_subject_dn("CN=Test Root CA")

        cert = create_self_signed_certificate(
            private_key=private_key,
            subject=subject,
            validity_days=365
        )


        assert cert.subject == cert.issuer
        assert cert.version == x509.Version.v3


        extensions = {ext.oid._name: ext for ext in cert.extensions}

        assert 'basicConstraints' in extensions
        assert extensions['basicConstraints'].value.ca is True

        assert 'keyUsage' in extensions
        ku = extensions['keyUsage'].value
        assert ku.key_cert_sign is True
        assert ku.crl_sign is True


class TestFullWorkflow:
    """Test complete CA initialization workflow"""

    def test_ca_initialization(self):
        """Test full CA initialization"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup
            out_dir = Path(tmpdir) / 'pki1'
            pass_file = Path(tmpdir) / 'passphrase.txt'
            log_file = Path(tmpdir) / 'ca.log'


            with open(pass_file, 'wb') as f:
                f.write(b'test-password-123')


            logger = setup_logger(log_file=log_file)

            try:
                initialize_root_ca(
                    subject_dn="CN=Test Root CA,O=Test Org",
                    key_type='rsa',
                    key_size=4096,
                    passphrase=b'test-password-123',
                    out_dir=out_dir,
                    validity_days=365,
                    logger=logger
                )


                assert (out_dir / 'private' / 'ca.key.pem').exists()
                assert (out_dir / 'certs' / 'ca.cert.pem').exists()
                assert (out_dir / 'policy.txt').exists()


                assert log_file.exists()
                log_content = log_file.read_text()
                assert 'Root CA initialization completed successfully' in log_content

            finally:

                import logging
                for handler in logger.handlers[:]:
                    handler.close()
                    logger.removeHandler(handler)