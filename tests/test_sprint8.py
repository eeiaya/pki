import json
import time
import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from micropki.database import CertificateDatabase
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
    create_intermediate_certificate,
    parse_san_entries,
)
from micropki.csr import create_csr
from micropki.ca import issue_certificate, initialize_root_ca, issue_intermediate_ca
from micropki.validation import validate_chain, build_chain
from micropki.client import (
    client_sign_file,
    client_verify_file,
    client_gen_csr,
)
from micropki.audit import verify_audit_log


# ============================================================
# Фикстура: маленькая PKI для быстрых тестов
# ============================================================

@pytest.fixture
def small_pki(tmp_path):
    out_dir = tmp_path / "pki"
    out_dir.mkdir()

    (out_dir / "private").mkdir()
    (out_dir / "certs").mkdir()

    passphrase = b"testpass"

    root_key = generate_rsa_key_pair(2048)
    root_subject = parse_subject_dn("CN=Test Root")
    root_cert = create_self_signed_certificate(root_key, root_subject, 3650)
    save_encrypted_private_key(root_key, out_dir / "private" / "ca.key.pem", passphrase)
    save_certificate(root_cert, out_dir / "certs" / "ca.cert.pem")

    inter_key = generate_rsa_key_pair(2048)
    inter_subject = parse_subject_dn("CN=Test Intermediate")
    inter_csr = create_csr(inter_key, inter_subject, is_ca=True, path_length=0)
    inter_cert = create_intermediate_certificate(inter_csr, root_key, root_cert, 1825, 0)
    save_encrypted_private_key(inter_key, out_dir / "private" / "intermediate.key.pem", passphrase)
    save_certificate(inter_cert, out_dir / "certs" / "intermediate.cert.pem")

    db = CertificateDatabase(out_dir / "certificates.db")

    return {
        "out_dir": out_dir,
        "db": db,
        "db_path": out_dir / "certificates.db",
        "root_cert": root_cert,
        "root_key": root_key,
        "inter_cert": inter_cert,
        "inter_key": inter_key,
        "passphrase": passphrase,
    }


# ============================================================
# TEST-62: Edge case — просроченные сертификаты
# ============================================================

class TestExpiredEdgeCases:

    def test_expired_via_validation_time(self, small_pki):
        setup = small_pki

        leaf_key = generate_rsa_key_pair(2048)
        leaf_subject = parse_subject_dn("CN=expired.test.com")
        san = parse_san_entries(["dns:expired.test.com"])
        leaf_cert = create_leaf_certificate(
            subject=leaf_subject,
            public_key=leaf_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="server",
            validity_days=365,
            san_extension=san,
        )

        future_time = datetime.now(timezone.utc) + timedelta(days=400)
        result = validate_chain(
            leaf_cert=leaf_cert,
            untrusted_certs=[setup["inter_cert"]],
            trusted_certs=[setup["root_cert"]],
            validation_time=future_time,
        )
        assert result.success is False
        assert "expired" in result.error.lower() or "valid" in result.error.lower()

    def test_not_yet_valid(self, small_pki):
        setup = small_pki

        leaf_key = generate_rsa_key_pair(2048)
        leaf_subject = parse_subject_dn("CN=future.test.com")
        san = parse_san_entries(["dns:future.test.com"])
        leaf_cert = create_leaf_certificate(
            subject=leaf_subject,
            public_key=leaf_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="server",
            validity_days=365,
            san_extension=san,
        )

        past_time = datetime(2000, 1, 1, tzinfo=timezone.utc)
        result = validate_chain(
            leaf_cert=leaf_cert,
            untrusted_certs=[setup["inter_cert"]],
            trusted_certs=[setup["root_cert"]],
            validation_time=past_time,
        )
        assert result.success is False


# ============================================================
# TEST-63: Edge case — неправильное использование ключа (EKU)
# ============================================================

class TestEKUMisuse:

    def test_client_cert_used_as_server(self, small_pki):
        setup = small_pki

        client_key = generate_rsa_key_pair(2048)
        client_subject = parse_subject_dn("CN=alice")
        client_cert = create_leaf_certificate(
            subject=client_subject,
            public_key=client_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="client",
            validity_days=365,
        )

        # Проверка с EKU serverAuth — должна провалиться
        result = validate_chain(
            leaf_cert=client_cert,
            untrusted_certs=[setup["inter_cert"]],
            trusted_certs=[setup["root_cert"]],
            check_eku="serverAuth",
        )
        assert result.success is False

    def test_server_cert_used_as_client(self, small_pki):
        setup = small_pki

        server_key = generate_rsa_key_pair(2048)
        server_subject = parse_subject_dn("CN=server.test.com")
        san = parse_san_entries(["dns:server.test.com"])
        server_cert = create_leaf_certificate(
            subject=server_subject,
            public_key=server_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="server",
            validity_days=365,
            san_extension=san,
        )

        result = validate_chain(
            leaf_cert=server_cert,
            untrusted_certs=[setup["inter_cert"]],
            trusted_certs=[setup["root_cert"]],
            check_eku="clientAuth",
        )
        assert result.success is False


# ============================================================
# TEST-64: Edge case — некорректные входные данные
# ============================================================

class TestCorruptedInputs:

    def test_invalid_pem_certificate(self, tmp_path):
        bad_file = tmp_path / "bad.pem"
        bad_file.write_bytes(b"-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----\n")

        with pytest.raises(Exception):
            load_certificate(bad_file)

    def test_empty_certificate_file(self, tmp_path):
        empty = tmp_path / "empty.pem"
        empty.write_bytes(b"")

        with pytest.raises(Exception):
            load_certificate(empty)

    def test_random_bytes_as_certificate(self, tmp_path):
        random_file = tmp_path / "random.pem"
        random_file.write_bytes(b"\x00\x01\x02\x03\x04\x05" * 100)

        with pytest.raises(Exception):
            load_certificate(random_file)

    def test_corrupted_csr_rejected(self, small_pki, tmp_path):
        setup = small_pki

        # Создаём валидный CSR
        csr_path = tmp_path / "valid.csr.pem"
        client_gen_csr(
            subject_dn="CN=tampered.com",
            key_type="rsa",
            key_size=2048,
            san_entries=["dns:tampered.com"],
            out_key=tmp_path / "k.pem",
            out_csr=csr_path,
        )

        # Портим CSR
        data = csr_path.read_bytes()
        tampered = data[:200] + b"XXXXXXXX" + data[208:]
        csr_path.write_bytes(tampered)

        with pytest.raises(Exception):
            issue_certificate(
                ca_cert_path=setup["out_dir"] / "certs" / "intermediate.cert.pem",
                ca_key_path=setup["out_dir"] / "private" / "intermediate.key.pem",
                ca_passphrase=setup["passphrase"],
                template_name="server",
                subject_dn="",
                san_entries=[],
                out_dir=setup["out_dir"] / "certs",
                validity_days=365,
                db_path=setup["db_path"],
                csr_path=csr_path,
            )

    def test_corrupted_audit_log_detected(self, tmp_path):
        from micropki.audit import AuditLogger

        audit = AuditLogger(tmp_path)
        audit.audit("op1", "success", "a")
        audit.audit("op2", "success", "b")

        # Меняем байт
        content = audit.log_file.read_text()
        tampered = content.replace("success", "FAILURE", 1)
        audit.log_file.write_text(tampered)

        result = verify_audit_log(audit.log_file, audit.chain_file)
        assert result.ok is False


# ============================================================
# TEST: Code Signing — функции
# ============================================================

class TestCodeSigning:

    def test_sign_and_verify(self, small_pki, tmp_path):
        setup = small_pki

        signer_key = generate_rsa_key_pair(2048)
        signer_subject = parse_subject_dn("CN=Test Signer")
        signer_cert = create_leaf_certificate(
            subject=signer_subject,
            public_key=signer_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="code_signing",
            validity_days=365,
        )

        signer_key_path = tmp_path / "signer.key.pem"
        signer_cert_path = tmp_path / "signer.cert.pem"
        save_unencrypted_private_key(signer_key, signer_key_path)
        save_certificate(signer_cert, signer_cert_path)

        file_path = tmp_path / "file.txt"
        file_path.write_text("Important data")
        sig_path = tmp_path / "file.txt.sig"

        client_sign_file(file_path, signer_key_path, sig_path)
        assert sig_path.exists()

        ok = client_verify_file(file_path, signer_cert_path, sig_path)
        assert ok is True

    def test_tampering_detected(self, small_pki, tmp_path):
        setup = small_pki

        signer_key = generate_rsa_key_pair(2048)
        signer_subject = parse_subject_dn("CN=Test Signer 2")
        signer_cert = create_leaf_certificate(
            subject=signer_subject,
            public_key=signer_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="code_signing",
            validity_days=365,
        )

        signer_key_path = tmp_path / "signer.key.pem"
        signer_cert_path = tmp_path / "signer.cert.pem"
        save_unencrypted_private_key(signer_key, signer_key_path)
        save_certificate(signer_cert, signer_cert_path)

        file_path = tmp_path / "file.txt"
        file_path.write_text("Original content")
        sig_path = tmp_path / "file.txt.sig"

        client_sign_file(file_path, signer_key_path, sig_path)

        file_path.write_text("Tampered content")
        ok = client_verify_file(file_path, signer_cert_path, sig_path)
        assert ok is False

    def test_wrong_cert_detected(self, small_pki, tmp_path):
        setup = small_pki

        signer_key = generate_rsa_key_pair(2048)
        signer_subject = parse_subject_dn("CN=Real Signer")
        signer_cert = create_leaf_certificate(
            subject=signer_subject,
            public_key=signer_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="code_signing",
            validity_days=365,
        )

        other_key = generate_rsa_key_pair(2048)
        other_cert = create_leaf_certificate(
            subject=parse_subject_dn("CN=Other Signer"),
            public_key=other_key.public_key(),
            ca_key=setup["inter_key"],
            ca_cert=setup["inter_cert"],
            template_name="code_signing",
            validity_days=365,
        )

        signer_key_path = tmp_path / "signer.key.pem"
        other_cert_path = tmp_path / "other.cert.pem"
        save_unencrypted_private_key(signer_key, signer_key_path)
        save_certificate(other_cert, other_cert_path)

        file_path = tmp_path / "file.txt"
        file_path.write_text("data")
        sig_path = tmp_path / "file.txt.sig"

        client_sign_file(file_path, signer_key_path, sig_path)
        ok = client_verify_file(file_path, other_cert_path, sig_path)
        assert ok is False


# ============================================================
# TEST-65: Performance — issue + validate 100 certificates
# (1000 слишком долго на ноутбуке, делаем 100 — этого достаточно)
# ============================================================

@pytest.mark.perf
class TestPerformance:

    def test_issue_100_certificates(self, small_pki):
        setup = small_pki

        start = time.time()

        for i in range(100):
            leaf_key = generate_rsa_key_pair(2048)
            subject = parse_subject_dn(f"CN=perf{i}.test.com")
            san = parse_san_entries([f"dns:perf{i}.test.com"])
            leaf_cert = create_leaf_certificate(
                subject=subject,
                public_key=leaf_key.public_key(),
                ca_key=setup["inter_key"],
                ca_cert=setup["inter_cert"],
                template_name="server",
                validity_days=365,
                san_extension=san,
            )
            pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
            setup["db"].add_certificate(leaf_cert, pem, template="server")

        elapsed = time.time() - start
        rate = 100 / elapsed
        print(f"\n[PERF] Issued 100 certificates in {elapsed:.2f}s ({rate:.1f}/sec)")

        all_certs = setup["db"].list_certificates(limit=200)
        assert len(all_certs) >= 100

    def test_validate_100_certificates(self, small_pki):
        setup = small_pki

        certs = []
        for i in range(100):
            leaf_key = generate_rsa_key_pair(2048)
            subject = parse_subject_dn(f"CN=val{i}.test.com")
            san = parse_san_entries([f"dns:val{i}.test.com"])
            leaf_cert = create_leaf_certificate(
                subject=subject,
                public_key=leaf_key.public_key(),
                ca_key=setup["inter_key"],
                ca_cert=setup["inter_cert"],
                template_name="server",
                validity_days=365,
                san_extension=san,
            )
            certs.append(leaf_cert)

        start = time.time()
        success_count = 0
        for cert in certs:
            result = validate_chain(
                leaf_cert=cert,
                untrusted_certs=[setup["inter_cert"]],
                trusted_certs=[setup["root_cert"]],
            )
            if result.success:
                success_count += 1
        elapsed = time.time() - start
        rate = 100 / elapsed

        print(f"\n[PERF] Validated 100 chains in {elapsed:.2f}s ({rate:.1f}/sec)")
        assert success_count == 100


# ============================================================
# TEST: CLI smoke — все справки работают
# ============================================================

class TestCLIHelp:

    def _run(self, args):
        import subprocess
        import os
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            ["micropki"] + args,
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            env=env,
        )
        return result

    def test_ca_help(self):
        r = self._run(["ca", "--help"])
        assert r.returncode == 0
        assert "init" in r.stdout

    def test_audit_help(self):
        r = self._run(["audit", "--help"])
        assert r.returncode == 0
        assert "query" in r.stdout
        assert "verify" in r.stdout

    def test_client_help(self):
        r = self._run(["client", "--help"])
        assert r.returncode == 0
        assert "gen-csr" in r.stdout
        assert "sign" in r.stdout
        assert "verify" in r.stdout

    def test_ocsp_help(self):
        r = self._run(["ocsp", "--help"])
        assert r.returncode == 0
        assert "serve" in r.stdout

    def test_db_help(self):
        r = self._run(["db", "--help"])
        assert r.returncode == 0
        assert "init" in r.stdout

    def test_repo_help(self):
        r = self._run(["repo", "--help"])
        assert r.returncode == 0
        assert "serve" in r.stdout