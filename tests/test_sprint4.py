import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from micropki.database import CertificateDatabase
from micropki.revocation import (
    parse_revocation_reason,
    get_reason_name,
    validate_reason,
    RevocationReason
)
from micropki.crl import CRLManager, load_crl
from micropki.crypto_utils import (
    generate_rsa_key_pair,
    save_encrypted_private_key,
    save_certificate,
    read_passphrase_file
)
from micropki.certificates import parse_subject_dn, create_self_signed_certificate


class TestRevocationReasons:

    def test_parse_valid_reasons(self):
        assert parse_revocation_reason('unspecified') == RevocationReason.UNSPECIFIED
        assert parse_revocation_reason('keyCompromise') == RevocationReason.KEY_COMPROMISE
        assert parse_revocation_reason('key_compromise') == RevocationReason.KEY_COMPROMISE
        assert parse_revocation_reason('KEYCOMPROMISE') == RevocationReason.KEY_COMPROMISE
        assert parse_revocation_reason('caCompromise') == RevocationReason.CA_COMPROMISE
        assert parse_revocation_reason('superseded') == RevocationReason.SUPERSEDED
        assert parse_revocation_reason('cessationOfOperation') == RevocationReason.CESSATION_OF_OPERATION
        assert parse_revocation_reason('certificateHold') == RevocationReason.CERTIFICATE_HOLD
        assert parse_revocation_reason('removeFromCRL') == RevocationReason.REMOVE_FROM_CRL
        assert parse_revocation_reason('privilegeWithdrawn') == RevocationReason.PRIVILEGE_WITHDRAWN
        assert parse_revocation_reason('aACompromise') == RevocationReason.AA_COMPROMISE

    def test_parse_invalid_reason(self):
        with pytest.raises(ValueError) as exc:
            parse_revocation_reason('invalidReason')
        assert 'Unsupported revocation reason' in str(exc.value)

    def test_get_reason_name(self):
        assert get_reason_name(RevocationReason.KEY_COMPROMISE) == 'Key Compromise'
        assert get_reason_name(RevocationReason.SUPERSEDED) == 'Superseded'

    def test_validate_reason(self):
        assert validate_reason('keyCompromise') is True
        assert validate_reason('superseded') is True
        assert validate_reason('invalidReason') is False


class TestDatabaseRevocation:

    @pytest.fixture
    def temp_db(self):
        temp_dir = tempfile.mkdtemp()
        db_path = Path(temp_dir) / 'test.db'
        db = CertificateDatabase(db_path)
        yield db, temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_cert(self):
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=Test Cert,O=Test Org")
        cert = create_self_signed_certificate(key, subject, 365)
        from cryptography.hazmat.primitives import serialization
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        return cert, pem

    def test_revoke_certificate(self, temp_db, sample_cert):
        db, _ = temp_db
        cert, pem = sample_cert

        serial = db.add_certificate(cert, pem, template='server')

        result = db.revoke_certificate(serial, 'keyCompromise')
        assert result is True

        cert_data = db.get_certificate(serial)
        assert cert_data['status'] == 'revoked'
        assert cert_data['revocation_reason'] == 'keyCompromise'
        assert cert_data['revocation_date'] is not None

    def test_revoke_already_revoked(self, temp_db, sample_cert):
        db, _ = temp_db
        cert, pem = sample_cert

        serial = db.add_certificate(cert, pem)
        db.revoke_certificate(serial, 'keyCompromise')

        result = db.revoke_certificate(serial, 'superseded')
        assert result is False

        cert_data = db.get_certificate(serial)
        assert cert_data['revocation_reason'] == 'keyCompromise'

    def test_revoke_nonexistent(self, temp_db):
        db, _ = temp_db

        with pytest.raises(ValueError) as exc:
            db.revoke_certificate('DEADBEEF', 'unspecified')
        assert 'not found' in str(exc.value)

    def test_get_revoked_by_issuer(self, temp_db, sample_cert):
        db, _ = temp_db
        cert, pem = sample_cert

        serial = db.add_certificate(cert, pem)
        db.revoke_certificate(serial, 'superseded')

        issuer_dn = cert.issuer.rfc4514_string()
        revoked = db.get_revoked_by_issuer(issuer_dn)

        assert len(revoked) == 1
        assert revoked[0]['serial_hex'] == serial

    def test_crl_metadata(self, temp_db):
        db, _ = temp_db

        ca_subject = "CN=Test CA"
        db.update_crl_metadata(ca_subject, 1, "2025-01-01T00:00:00", "/path/to/crl")

        meta = db.get_crl_metadata(ca_subject)
        assert meta is not None
        assert meta['crl_number'] == 1

        db.update_crl_metadata(ca_subject, 2, "2025-02-01T00:00:00", "/path/to/crl")
        meta = db.get_crl_metadata(ca_subject)
        assert meta['crl_number'] == 2


class TestCRLGeneration:

    @pytest.fixture
    def pki_setup(self):
        temp_dir = tempfile.mkdtemp()
        out_dir = Path(temp_dir)

        private_dir = out_dir / 'private'
        certs_dir = out_dir / 'certs'
        crl_dir = out_dir / 'crl'
        private_dir.mkdir(parents=True)
        certs_dir.mkdir(parents=True)
        crl_dir.mkdir(parents=True)

        passphrase = b'testpass123'
        pass_file = out_dir / 'ca.pass'
        pass_file.write_bytes(passphrase)

        ca_key = generate_rsa_key_pair(2048)
        ca_subject = parse_subject_dn("CN=Test Root CA,O=Test")
        ca_cert = create_self_signed_certificate(ca_key, ca_subject, 3650)

        save_encrypted_private_key(ca_key, private_dir / 'ca.key.pem', passphrase)
        save_certificate(ca_cert, certs_dir / 'ca.cert.pem')

        db_path = out_dir / 'certificates.db'
        db = CertificateDatabase(db_path)

        yield {
            'out_dir': out_dir,
            'ca_cert': ca_cert,
            'ca_key': ca_key,
            'ca_cert_path': certs_dir / 'ca.cert.pem',
            'ca_key_path': private_dir / 'ca.key.pem',
            'passphrase': passphrase,
            'db': db,
            'temp_dir': temp_dir
        }

        shutil.rmtree(temp_dir)

    def test_generate_empty_crl(self, pki_setup):
        setup = pki_setup
        manager = CRLManager(setup['out_dir'])

        crl = manager.generate_crl(
            ca_cert=setup['ca_cert'],
            ca_key=setup['ca_key'],
            revoked_certs=[],
            ca_name='root',
            next_update_days=7
        )

        assert crl is not None
        assert len(list(crl)) == 0

    def test_generate_crl_with_revoked(self, pki_setup):
        setup = pki_setup

        revoked_certs = [
            {
                'serial_hex': 'ABC123',
                'revocation_date': datetime.now(timezone.utc).isoformat(),
                'revocation_reason': 'keyCompromise'
            },
            {
                'serial_hex': 'DEF456',
                'revocation_date': datetime.now(timezone.utc).isoformat(),
                'revocation_reason': 'superseded'
            }
        ]

        manager = CRLManager(setup['out_dir'])
        crl = manager.generate_crl(
            ca_cert=setup['ca_cert'],
            ca_key=setup['ca_key'],
            revoked_certs=revoked_certs,
            ca_name='root'
        )

        revoked_list = list(crl)
        assert len(revoked_list) == 2

        serials = [format(r.serial_number, 'X') for r in revoked_list]
        assert 'ABC123' in serials
        assert 'DEF456' in serials

    def test_crl_number_increment(self, pki_setup):
        setup = pki_setup
        manager = CRLManager(setup['out_dir'])

        crl1 = manager.generate_crl(
            setup['ca_cert'], setup['ca_key'], [], 'root'
        )

        crl2 = manager.generate_crl(
            setup['ca_cert'], setup['ca_key'], [], 'root'
        )

        num1 = crl1.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        num2 = crl2.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number

        assert num2 == num1 + 1

    def test_save_and_load_crl(self, pki_setup):
        setup = pki_setup
        manager = CRLManager(setup['out_dir'])

        crl = manager.generate_crl(
            setup['ca_cert'], setup['ca_key'], [], 'root'
        )

        crl_path = manager.save_crl(crl, 'root')

        assert crl_path.exists()
        assert crl_path.name == 'root.crl.pem'

        loaded = load_crl(crl_path)
        assert loaded is not None

    def test_generate_and_save_crl(self, pki_setup):
        setup = pki_setup
        manager = CRLManager(setup['out_dir'])

        crl_path = manager.generate_and_save_crl(
            ca_cert_path=setup['ca_cert_path'],
            ca_key_path=setup['ca_key_path'],
            ca_passphrase=setup['passphrase'],
            revoked_certs=[],
            ca_name='root',
            next_update_days=14
        )

        assert crl_path.exists()

        crl = load_crl(crl_path)
        assert crl.next_update_utc > crl.last_update_utc

    def test_crl_extensions(self, pki_setup):
        setup = pki_setup
        manager = CRLManager(setup['out_dir'])

        crl = manager.generate_crl(
            setup['ca_cert'], setup['ca_key'], [], 'root'
        )

        try:
            aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            assert aki is not None
        except x509.ExtensionNotFound:
            pytest.fail("AKI extension missing")

        try:
            crl_num = crl.extensions.get_extension_for_class(x509.CRLNumber)
            assert crl_num.value.crl_number >= 1
        except x509.ExtensionNotFound:
            pytest.fail("CRL Number extension missing")


class TestCRLWithReasonCodes:

    @pytest.fixture
    def crl_setup(self):
        temp_dir = tempfile.mkdtemp()
        out_dir = Path(temp_dir)

        (out_dir / 'private').mkdir(parents=True)
        (out_dir / 'certs').mkdir(parents=True)
        (out_dir / 'crl').mkdir(parents=True)

        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=Test CA")
        cert = create_self_signed_certificate(key, subject, 365)

        yield {
            'out_dir': out_dir,
            'ca_cert': cert,
            'ca_key': key,
            'temp_dir': temp_dir
        }

        shutil.rmtree(temp_dir)

    def test_crl_reason_code_included(self, crl_setup):
        setup = crl_setup
        manager = CRLManager(setup['out_dir'])

        revoked = [{
            'serial_hex': '123456',
            'revocation_date': datetime.now(timezone.utc).isoformat(),
            'revocation_reason': 'keyCompromise'
        }]

        crl = manager.generate_crl(
            setup['ca_cert'], setup['ca_key'], revoked, 'root'
        )

        revoked_cert = list(crl)[0]

        try:
            reason_ext = revoked_cert.extensions.get_extension_for_class(x509.CRLReason)
            assert reason_ext.value.reason == x509.ReasonFlags.key_compromise
        except x509.ExtensionNotFound:
            pytest.fail("CRL Reason extension not found")

    def test_unspecified_reason_no_extension(self, crl_setup):
        setup = crl_setup
        manager = CRLManager(setup['out_dir'])

        revoked = [{
            'serial_hex': '789ABC',
            'revocation_date': datetime.now(timezone.utc).isoformat(),
            'revocation_reason': 'unspecified'
        }]

        crl = manager.generate_crl(
            setup['ca_cert'], setup['ca_key'], revoked, 'root'
        )

        revoked_cert = list(crl)[0]

        with pytest.raises(x509.ExtensionNotFound):
            revoked_cert.extensions.get_extension_for_class(x509.CRLReason)


class TestFullRevocationLifecycle:

    @pytest.fixture
    def full_pki(self):
        temp_dir = tempfile.mkdtemp()
        out_dir = Path(temp_dir)

        (out_dir / 'private').mkdir(parents=True)
        (out_dir / 'certs').mkdir(parents=True)

        passphrase = b'testpass'

        ca_key = generate_rsa_key_pair(2048)
        ca_subject = parse_subject_dn("CN=Test CA,O=Test")
        ca_cert = create_self_signed_certificate(ca_key, ca_subject, 3650)

        save_encrypted_private_key(ca_key, out_dir / 'private' / 'ca.key.pem', passphrase)
        save_certificate(ca_cert, out_dir / 'certs' / 'ca.cert.pem')

        from cryptography.hazmat.primitives import serialization
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        db = CertificateDatabase(out_dir / 'certificates.db')
        db.add_certificate(ca_cert, ca_pem, template='root_ca')

        server_key = generate_rsa_key_pair(2048)
        server_subject = parse_subject_dn("CN=server.example.com")

        from micropki.certificates import create_leaf_certificate
        server_cert = create_leaf_certificate(
            subject=server_subject,
            public_key=server_key.public_key(),
            ca_key=ca_key,
            ca_cert=ca_cert,
            template_name='server',
            validity_days=365
        )
        server_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode()
        server_serial = db.add_certificate(server_cert, server_pem, template='server')

        yield {
            'out_dir': out_dir,
            'db': db,
            'ca_cert': ca_cert,
            'ca_key': ca_key,
            'passphrase': passphrase,
            'server_serial': server_serial,
            'temp_dir': temp_dir
        }

        shutil.rmtree(temp_dir)

    def test_full_lifecycle(self, full_pki):
        setup = full_pki
        db = setup['db']
        serial = setup['server_serial']

        cert = db.get_certificate(serial)
        assert cert['status'] == 'valid'

        result = db.revoke_certificate(serial, 'keyCompromise')
        assert result is True

        cert = db.get_certificate(serial)
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'keyCompromise'
        assert cert['revocation_date'] is not None

        ca_dn = setup['ca_cert'].subject.rfc4514_string()
        revoked_list = db.get_revoked_by_issuer(ca_dn)
        assert len(revoked_list) == 1
        assert revoked_list[0]['serial_hex'] == serial

        manager = CRLManager(setup['out_dir'])
        crl = manager.generate_crl(
            setup['ca_cert'], setup['ca_key'], revoked_list, 'root'
        )

        crl_revoked = list(crl)
        assert len(crl_revoked) == 1
        assert format(crl_revoked[0].serial_number, 'X') == serial

        crl_path = manager.save_crl(crl, 'root')
        assert crl_path.exists()

        loaded_crl = load_crl(crl_path)
        assert len(list(loaded_crl)) == 1