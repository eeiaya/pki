import pytest
import json
import tempfile
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from micropki.audit import (
    AuditLogger,
    verify_audit_log,
    query_audit_entries,
    load_audit_entries,
    ZERO_HASH,
)
from micropki.policy import (
    PolicyViolation,
    validate_key_policy,
    validate_generated_key_params,
    validate_validity_policy,
    validate_san_policy,
    validate_intermediate_policy,
    validate_signature_algorithm_policy,
    validate_csr_policy,
)
from micropki.transparency import CTLog
from micropki.compromise import public_key_hash, certificate_public_key_hash, csr_public_key_hash
from micropki.database import CertificateDatabase
from micropki.crypto_utils import (
    generate_rsa_key_pair,
    save_encrypted_private_key,
    save_certificate,
)
from micropki.certificates import (
    parse_subject_dn,
    create_self_signed_certificate,
    create_leaf_certificate,
    parse_san_entries,
)
from micropki.csr import create_csr
from micropki.ca import (
    initialize_root_ca,
    issue_intermediate_ca,
    issue_certificate,
    compromise_certificate,
)


# ============================================================
# Базовая фикстура: чистая PKI
# ============================================================

@pytest.fixture
def fresh_pki(tmp_path):
    out_dir = tmp_path / "pki"
    out_dir.mkdir()

    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"testpass")

    import logging
    logger = logging.getLogger("test")

    initialize_root_ca(
        subject_dn="CN=Test Root CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=b"testpass",
        out_dir=out_dir,
        validity_days=3650,
        logger=logger,
        db_path=out_dir / "certificates.db",
    )

    issue_intermediate_ca(
        root_cert_path=out_dir / "certs" / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_passphrase=b"testpass",
        subject_dn="CN=Test Intermediate CA,O=Test",
        key_type="rsa",
        key_size=4096,
        passphrase=b"testpass",
        out_dir=out_dir,
        validity_days=1825,
        path_length=0,
        logger=logger,
        db_path=out_dir / "certificates.db",
    )

    return {
        "out_dir": out_dir,
        "pass_file": pass_file,
        "db_path": out_dir / "certificates.db",
        "audit_log": out_dir / "audit" / "audit.log",
        "chain_file": out_dir / "audit" / "chain.dat",
        "ct_log": out_dir / "audit" / "ct.log",
        "ca_cert": out_dir / "certs" / "ca.cert.pem",
        "ca_key": out_dir / "private" / "ca.key.pem",
        "inter_cert": out_dir / "certs" / "intermediate.cert.pem",
        "inter_key": out_dir / "private" / "intermediate.key.pem",
    }


# ============================================================
# AUDIT
# ============================================================

class TestAuditLogger:

    def test_first_entry_has_zero_prev_hash(self, tmp_path):
        audit = AuditLogger(tmp_path)
        entry = audit.audit("test_op", "success", "first")
        assert entry["integrity"]["prev_hash"] == ZERO_HASH
        assert len(entry["integrity"]["hash"]) == 64

    def test_chain_is_linked(self, tmp_path):
        audit = AuditLogger(tmp_path)
        e1 = audit.audit("op1", "success", "first")
        e2 = audit.audit("op2", "success", "second")
        e3 = audit.audit("op3", "success", "third")

        assert e2["integrity"]["prev_hash"] == e1["integrity"]["hash"]
        assert e3["integrity"]["prev_hash"] == e2["integrity"]["hash"]

    def test_chain_file_contains_last_hash(self, tmp_path):
        audit = AuditLogger(tmp_path)
        e1 = audit.audit("op1", "success", "x")
        e2 = audit.audit("op2", "success", "y")

        chain_content = audit.chain_file.read_text().strip()
        assert chain_content == e2["integrity"]["hash"]

    def test_entries_are_ndjson(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("op", "success", "msg")
        audit.audit("op", "success", "msg2")

        lines = audit.log_file.read_text().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            json.loads(line)


class TestAuditVerify:

    def test_verify_ok(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("a", "success", "1")
        audit.audit("b", "success", "2")
        audit.audit("c", "success", "3")

        result = verify_audit_log(audit.log_file, audit.chain_file)
        assert result.ok is True

    def test_tamper_message_detected(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("a", "success", "original")
        audit.audit("b", "success", "second")

        # Меняем содержимое первой строки
        content = audit.log_file.read_text()
        tampered = content.replace("original", "MODIFIED")
        audit.log_file.write_text(tampered)

        result = verify_audit_log(audit.log_file, audit.chain_file)
        assert result.ok is False
        assert result.first_bad_line is not None

    def test_missing_entry_detected(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("a", "success", "A")
        audit.audit("b", "success", "B")
        audit.audit("c", "success", "C")

        lines = audit.log_file.read_text().strip().split("\n")
        # Удаляем среднюю запись B
        audit.log_file.write_text(lines[0] + "\n" + lines[2] + "\n")

        result = verify_audit_log(audit.log_file, audit.chain_file)
        assert result.ok is False

    def test_chain_dat_mismatch_detected(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("a", "success", "x")
        audit.chain_file.write_text("0" * 64)

        result = verify_audit_log(audit.log_file, audit.chain_file)
        assert result.ok is False


class TestAuditQuery:

    def test_filter_by_level(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("op1", "success", "audit msg")
        audit.info("op2", "success", "info msg")
        audit.error("op3", "failure", "err msg")

        audit_only = query_audit_entries(audit.log_file, level="AUDIT")
        assert len(audit_only) == 1
        assert audit_only[0]["operation"] == "op1"

    def test_filter_by_operation(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("issue", "success", "1")
        audit.audit("revoke", "success", "2")
        audit.audit("issue", "success", "3")

        result = query_audit_entries(audit.log_file, operation="issue")
        assert len(result) == 2

    def test_filter_by_serial(self, tmp_path):
        audit = AuditLogger(tmp_path)
        audit.audit("issue", "success", "x", metadata={"serial": "AABBCC"})
        audit.audit("issue", "success", "y", metadata={"serial": "DDEEFF"})

        result = query_audit_entries(audit.log_file, serial="AABBCC")
        assert len(result) == 1


# ============================================================
# POLICY
# ============================================================

class TestKeyPolicy:

    def test_rsa_2048_end_entity_ok(self):
        key = generate_rsa_key_pair(2048)
        validate_key_policy(key.public_key(), "end_entity")

    def test_rsa_1024_rejected(self):
        # cryptography не даст создать 1024, проверим через generated_key_params
        with pytest.raises(PolicyViolation):
            validate_generated_key_params("rsa", 1024, "end_entity")

    def test_root_requires_4096(self):
        with pytest.raises(PolicyViolation):
            validate_generated_key_params("rsa", 2048, "root_ca")

    def test_intermediate_requires_3072(self):
        with pytest.raises(PolicyViolation):
            validate_generated_key_params("rsa", 2048, "intermediate_ca")

    def test_ecc_p256_for_ca_rejected(self):
        with pytest.raises(PolicyViolation):
            validate_generated_key_params("ecc", 256, "root_ca")

    def test_ecc_p384_for_ca_ok(self):
        validate_generated_key_params("ecc", 384, "root_ca")


class TestValidityPolicy:

    def test_end_entity_max_365_ok(self):
        validate_validity_policy(365, "end_entity")

    def test_end_entity_366_rejected(self):
        with pytest.raises(PolicyViolation):
            validate_validity_policy(366, "end_entity")

    def test_intermediate_1825_ok(self):
        validate_validity_policy(1825, "intermediate_ca")

    def test_intermediate_too_long(self):
        with pytest.raises(PolicyViolation):
            validate_validity_policy(2000, "intermediate_ca")

    def test_root_3650_ok(self):
        validate_validity_policy(3650, "root_ca")

    def test_root_too_long(self):
        with pytest.raises(PolicyViolation):
            validate_validity_policy(3651, "root_ca")


class TestSANPolicy:

    def test_server_requires_dns_or_ip(self):
        validate_san_policy("server", ["dns:example.com"])
        validate_san_policy("server", ["ip:10.0.0.1"])

    def test_server_email_rejected(self):
        with pytest.raises(PolicyViolation):
            validate_san_policy("server", ["email:x@y.com"])

    def test_server_wildcard_rejected(self):
        with pytest.raises(PolicyViolation):
            validate_san_policy("server", ["dns:*.example.com"])

    def test_server_requires_san(self):
        with pytest.raises(PolicyViolation):
            validate_san_policy("server", [])

    def test_client_requires_email(self):
        with pytest.raises(PolicyViolation):
            validate_san_policy("client", ["dns:user.example.com"])

    def test_client_with_email_ok(self):
        validate_san_policy("client", ["email:alice@example.com"])

    def test_code_signing_email_rejected(self):
        with pytest.raises(PolicyViolation):
            validate_san_policy("code_signing", ["email:dev@example.com"])

    def test_code_signing_dns_ok(self):
        validate_san_policy("code_signing", ["dns:signer.example.com"])


class TestSignatureAlgorithmPolicy:

    def test_rsa_sha256_ok(self):
        key = generate_rsa_key_pair(2048).public_key()
        validate_signature_algorithm_policy(key, hashes.SHA256())

    def test_rsa_sha1_rejected(self):
        key = generate_rsa_key_pair(2048).public_key()
        with pytest.raises(PolicyViolation):
            validate_signature_algorithm_policy(key, hashes.SHA1())


class TestIntermediatePolicy:

    def test_pathlen_0_ok(self):
        validate_intermediate_policy(0)

    def test_pathlen_1_rejected(self):
        with pytest.raises(PolicyViolation):
            validate_intermediate_policy(1)


# ============================================================
# COMPROMISE
# ============================================================

class TestCompromiseModule:

    def test_public_key_hash_deterministic(self):
        key = generate_rsa_key_pair(2048)
        h1 = public_key_hash(key.public_key())
        h2 = public_key_hash(key.public_key())
        assert h1 == h2
        assert len(h1) == 64

    def test_different_keys_different_hashes(self):
        k1 = generate_rsa_key_pair(2048)
        k2 = generate_rsa_key_pair(2048)
        assert public_key_hash(k1.public_key()) != public_key_hash(k2.public_key())

    def test_csr_and_cert_same_key_same_hash(self):
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=test")
        cert = create_self_signed_certificate(key, subject, 365)
        csr = create_csr(key, subject)

        assert certificate_public_key_hash(cert) == csr_public_key_hash(csr)


class TestCompromisedKeysDB:

    def test_add_and_check(self, tmp_path):
        db = CertificateDatabase(tmp_path / "t.db")
        pk_hash = "a" * 64
        added = db.add_compromised_key(pk_hash, "DEADBEEF", "keyCompromise")
        assert added is True
        assert db.is_key_compromised(pk_hash) is True
        assert db.is_key_compromised("b" * 64) is False

    def test_duplicate_returns_false(self, tmp_path):
        db = CertificateDatabase(tmp_path / "t.db")
        db.add_compromised_key("h" * 64, "AA", "keyCompromise")
        result = db.add_compromised_key("h" * 64, "BB", "keyCompromise")
        assert result is False


# ============================================================
# TRANSPARENCY (CT log)
# ============================================================

class TestCTLog:

    def test_append_and_contains(self, tmp_path):
        key = generate_rsa_key_pair(2048)
        cert = create_self_signed_certificate(key, parse_subject_dn("CN=t"), 365)
        ct = CTLog(tmp_path)
        ct.append(cert)

        serial = format(cert.serial_number, "X")
        assert ct.contains_serial(serial) is True
        assert ct.contains_serial("DEADBEEF") is False

    def test_ct_log_contains_fingerprint(self, tmp_path):
        key = generate_rsa_key_pair(2048)
        cert = create_self_signed_certificate(key, parse_subject_dn("CN=t"), 365)
        ct = CTLog(tmp_path)
        ct.append(cert)

        content = ct.ct_log.read_text()
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        assert fp in content


# ============================================================
# Integration: CA с политиками
# ============================================================

class TestCAPolicyEnforcement:

    def test_issue_cert_with_validity_too_long_rejected(self, fresh_pki):
        setup = fresh_pki
        with pytest.raises(PolicyViolation):
            issue_certificate(
                ca_cert_path=setup["inter_cert"],
                ca_key_path=setup["inter_key"],
                ca_passphrase=b"testpass",
                template_name="server",
                subject_dn="CN=too-long.com",
                san_entries=["dns:too-long.com"],
                out_dir=setup["out_dir"] / "certs",
                validity_days=400,  # > 365
                db_path=setup["db_path"],
            )

    def test_issue_cert_wildcard_rejected(self, fresh_pki, tmp_path):
        setup = fresh_pki

        # Создаём CSR с wildcard
        key = generate_rsa_key_pair(2048)
        subject = parse_subject_dn("CN=*.example.com")
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("*.example.com")]),
            critical=False
        )
        csr = builder.sign(key, hashes.SHA256(), default_backend())
        csr_path = tmp_path / "wild.csr.pem"
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        with pytest.raises(PolicyViolation):
            issue_certificate(
                ca_cert_path=setup["inter_cert"],
                ca_key_path=setup["inter_key"],
                ca_passphrase=b"testpass",
                template_name="server",
                subject_dn="",
                san_entries=[],
                out_dir=setup["out_dir"] / "certs",
                validity_days=365,
                db_path=setup["db_path"],
                csr_path=csr_path,
            )

    def test_issue_code_signing_with_email_rejected(self, fresh_pki):
        setup = fresh_pki
        with pytest.raises((PolicyViolation, ValueError)):
            issue_certificate(
                ca_cert_path=setup["inter_cert"],
                ca_key_path=setup["inter_key"],
                ca_passphrase=b"testpass",
                template_name="code_signing",
                subject_dn="CN=Signer",
                san_entries=["email:dev@example.com"],
                out_dir=setup["out_dir"] / "certs",
                validity_days=365,
                db_path=setup["db_path"],
            )

    def test_issue_server_no_san_rejected(self, fresh_pki):
        setup = fresh_pki
        with pytest.raises(Exception):  # ValueError или PolicyViolation
            issue_certificate(
                ca_cert_path=setup["inter_cert"],
                ca_key_path=setup["inter_key"],
                ca_passphrase=b"testpass",
                template_name="server",
                subject_dn="CN=nosan.com",
                san_entries=[],
                out_dir=setup["out_dir"] / "certs",
                validity_days=365,
                db_path=setup["db_path"],
            )


# ============================================================
# Integration: компрометация
# ============================================================

class TestCompromiseFlow:

    def test_compromise_marks_revoked_and_blocked(self, fresh_pki, tmp_path):
        setup = fresh_pki

        # Выпускаем сертификат
        issue_certificate(
            ca_cert_path=setup["inter_cert"],
            ca_key_path=setup["inter_key"],
            ca_passphrase=b"testpass",
            template_name="server",
            subject_dn="CN=will-be-compromised.com",
            san_entries=["dns:will-be-compromised.com"],
            out_dir=setup["out_dir"] / "certs",
            validity_days=365,
            db_path=setup["db_path"],
        )

        cert_path = setup["out_dir"] / "certs" / "will-be-compromised.com.cert.pem"
        assert cert_path.exists()

        # Компрометируем
        result = compromise_certificate(
            cert_path=cert_path,
            out_dir=setup["out_dir"],
            db_path=setup["db_path"],
            reason="keyCompromise",
        )

        # Проверяем статус в БД
        db = CertificateDatabase(setup["db_path"])
        cert_data = db.get_certificate(result["serial"])
        assert cert_data["status"] == "revoked"

        # Проверяем что ключ в таблице compromised_keys
        assert db.is_key_compromised(result["public_key_hash"]) is True

    def test_csr_with_compromised_key_rejected(self, fresh_pki, tmp_path):
        setup = fresh_pki

        # Выпускаем сертификат
        issue_certificate(
            ca_cert_path=setup["inter_cert"],
            ca_key_path=setup["inter_key"],
            ca_passphrase=b"testpass",
            template_name="server",
            subject_dn="CN=victim.com",
            san_entries=["dns:victim.com"],
            out_dir=setup["out_dir"] / "certs",
            validity_days=365,
            db_path=setup["db_path"],
        )

        cert_path = setup["out_dir"] / "certs" / "victim.com.cert.pem"
        key_path = setup["out_dir"] / "certs" / "victim.com.key.pem"

        # Загружаем ключ для построения нового CSR с тем же ключом
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        victim_key = load_pem_private_key(key_path.read_bytes(), password=None)

        # Компрометируем
        compromise_certificate(
            cert_path=cert_path,
            out_dir=setup["out_dir"],
            db_path=setup["db_path"],
        )

        # Создаём CSR с тем же ключом для нового имени
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(parse_subject_dn("CN=newname.com"))
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("newname.com")]),
            critical=False
        )
        csr = builder.sign(victim_key, hashes.SHA256(), default_backend())
        csr_path = tmp_path / "evil.csr.pem"
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        # Попытка выпустить — должна быть отклонена
        with pytest.raises(PolicyViolation, match="compromised"):
            issue_certificate(
                ca_cert_path=setup["inter_cert"],
                ca_key_path=setup["inter_key"],
                ca_passphrase=b"testpass",
                template_name="server",
                subject_dn="",
                san_entries=[],
                out_dir=setup["out_dir"] / "certs",
                validity_days=365,
                db_path=setup["db_path"],
                csr_path=csr_path,
            )


# ============================================================
# Integration: CT log при выпуске
# ============================================================

class TestCTIntegration:

    def test_issued_cert_appears_in_ct_log(self, fresh_pki):
        setup = fresh_pki

        issue_certificate(
            ca_cert_path=setup["inter_cert"],
            ca_key_path=setup["inter_key"],
            ca_passphrase=b"testpass",
            template_name="server",
            subject_dn="CN=ctcheck.com",
            san_entries=["dns:ctcheck.com"],
            out_dir=setup["out_dir"] / "certs",
            validity_days=365,
            db_path=setup["db_path"],
        )

        # Находим серийник в БД
        db = CertificateDatabase(setup["db_path"])
        all_certs = db.list_certificates()
        target = [c for c in all_certs if "ctcheck" in c["subject"]]
        assert len(target) == 1
        serial = target[0]["serial_hex"]

        ct = CTLog(setup["out_dir"])
        assert ct.contains_serial(serial) is True


# ============================================================
# Integration: аудит CA операций
# ============================================================

class TestAuditIntegration:

    def test_root_init_creates_audit_entry(self, fresh_pki):
        entries = load_audit_entries(fresh_pki["audit_log"])
        ops = [e["operation"] for e in entries]
        assert "ca_init_root" in ops

    def test_intermediate_creates_audit_entry(self, fresh_pki):
        entries = load_audit_entries(fresh_pki["audit_log"])
        ops = [e["operation"] for e in entries]
        assert "ca_issue_intermediate" in ops

    def test_issue_certificate_creates_audit_entry(self, fresh_pki):
        setup = fresh_pki
        issue_certificate(
            ca_cert_path=setup["inter_cert"],
            ca_key_path=setup["inter_key"],
            ca_passphrase=b"testpass",
            template_name="server",
            subject_dn="CN=auditcheck.com",
            san_entries=["dns:auditcheck.com"],
            out_dir=setup["out_dir"] / "certs",
            validity_days=365,
            db_path=setup["db_path"],
        )

        entries = load_audit_entries(setup["audit_log"])
        issue_entries = [e for e in entries if e["operation"] == "issue_certificate"]
        assert len(issue_entries) >= 2  # started + success

    def test_policy_violation_logged(self, fresh_pki):
        setup = fresh_pki
        try:
            issue_certificate(
                ca_cert_path=setup["inter_cert"],
                ca_key_path=setup["inter_key"],
                ca_passphrase=b"testpass",
                template_name="server",
                subject_dn="CN=bad.com",
                san_entries=["dns:*.bad.com"],  # wildcard
                out_dir=setup["out_dir"] / "certs",
                validity_days=365,
                db_path=setup["db_path"],
            )
        except PolicyViolation:
            pass

        entries = load_audit_entries(setup["audit_log"])
        violations = [e for e in entries if e.get("status") == "policy_violation"]
        assert len(violations) >= 1

    def test_audit_integrity_after_full_workflow(self, fresh_pki):
        setup = fresh_pki

        issue_certificate(
            ca_cert_path=setup["inter_cert"],
            ca_key_path=setup["inter_key"],
            ca_passphrase=b"testpass",
            template_name="server",
            subject_dn="CN=integrity-test.com",
            san_entries=["dns:integrity-test.com"],
            out_dir=setup["out_dir"] / "certs",
            validity_days=365,
            db_path=setup["db_path"],
        )

        result = verify_audit_log(setup["audit_log"], setup["chain_file"])
        assert result.ok is True, f"Audit verify failed: {result.message}"