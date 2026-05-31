"""
Certificate Authority operations.
"""

import os
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timezone
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from .crypto_utils import (
    generate_rsa_key_pair,
    generate_ecc_key_pair,
    save_encrypted_private_key,
    save_unencrypted_private_key,
    load_encrypted_private_key,
    save_certificate,
    load_certificate,
)
from .certificates import (
    parse_subject_dn,
    create_self_signed_certificate,
    create_intermediate_certificate,
    create_leaf_certificate,
    get_certificate_info,
    get_cn_from_subject,
    parse_san_entries,
)
from .csr import create_csr, save_csr
from .templates import get_template, validate_san_for_template

from .audit import AuditLogger
from .policy import (
    PolicyViolation,
    validate_generated_key_params,
    validate_validity_policy,
    validate_san_policy,
    validate_csr_policy,
    validate_intermediate_policy,
)
from .transparency import CTLog
from .compromise import public_key_hash, certificate_public_key_hash, csr_public_key_hash

def initialize_root_ca(
        subject_dn: str,
        key_type: str,
        key_size: int,
        passphrase: bytes,
        out_dir: Path,
        validity_days: int,
        logger: logging.Logger,
        db_path: Optional[Path] = None
) -> None:
    """
    Инициализирует корневой CA.

    Args:
        subject_dn: Distinguished Name для CA
        key_type: Тип ключа ('rsa' или 'ecc')
        key_size: Размер ключа (4096 для RSA, 384 для ECC)
        passphrase: Пароль для шифрования приватного ключа
        out_dir: Директория для сохранения файлов
        validity_days: Срок действия сертификата в днях
        logger: Логгер
        db_path: Путь к базе данных (если None - не сохранять в БД)
    """
    logger.info("=" * 60)
    logger.info("Starting Root CA initialization")
    audit = AuditLogger(out_dir)
    audit.audit(
        operation="ca_init_root",
        status="started",
        message=f"Initializing Root CA: {subject_dn}",
        metadata={"subject": subject_dn, "key_type": key_type, "key_size": key_size, "validity_days": validity_days}
    )

    logger.info("=" * 60)


    # Валидация параметров
    try:
        if key_type not in ('rsa', 'ecc'):
            raise PolicyViolation(f"Invalid key type: {key_type}")
        validate_generated_key_params(key_type, key_size, "root_ca")
        if validity_days <= 0:
            raise PolicyViolation("Validity days must be positive")
        validate_validity_policy(validity_days, "root_ca")
    except PolicyViolation as e:
        audit.audit(
            operation="ca_init_root",
            status="policy_violation",
            message=str(e),
            metadata={"subject": subject_dn, "key_type": key_type, "key_size": key_size, "validity_days": validity_days}
        )
        raise

    # Парсим DN
    subject = parse_subject_dn(subject_dn)
    logger.info(f"Subject: {subject.rfc4514_string()}")

    # Генерируем ключи
    logger.info(f"Generating {key_type.upper()} key pair ({key_size} bits)...")
    if key_type == 'rsa':
        private_key = generate_rsa_key_pair(key_size)
    else:
        private_key = generate_ecc_key_pair(key_size)
    logger.info("Key pair generated successfully")

    # Создаём самоподписанный сертификат
    logger.info(f"Creating self-signed certificate (valid for {validity_days} days)...")
    certificate = create_self_signed_certificate(private_key, subject, validity_days)
    logger.info("Certificate created successfully")

    # Создаём директории
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)

    # Сохраняем приватный ключ
    key_path = private_dir / 'ca.key.pem'
    save_encrypted_private_key(private_key, key_path, passphrase)
    logger.info(f"Private key saved: {key_path}")

    if os.name == 'nt':
        logger.warning("Running on Windows - file permission checks skipped")

    # Сохраняем сертификат
    cert_path = certs_dir / 'ca.cert.pem'
    save_certificate(certificate, cert_path)
    logger.info(f"Certificate saved: {cert_path}")

    # Создаём policy.txt
    policy_path = out_dir / 'policy.txt'
    cert_info = get_certificate_info(certificate)
    _create_policy_file(policy_path, cert_info, key_type, key_size)
    logger.info(f"Policy document: {policy_path}")

    # === Сохранение в БД ===
    if db_path:
        try:
            from .database import CertificateDatabase

            cert_pem = certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode('utf-8')

            db = CertificateDatabase(db_path)
            serial_hex = db.add_certificate(
                certificate=certificate,
                certificate_pem=cert_pem,
                template='root_ca',
                san_entries=None
            )
            logger.info(f"Root CA added to database: serial={serial_hex}")
        except Exception as e:
            logger.warning(f"Failed to add root CA to database: {e}")

    # Финальный лог
    logger.info("=" * 60)
    logger.info("Root CA initialization completed successfully")
    audit.audit(
        operation="ca_init_root",
        status="success",
        message=f"Root CA initialized: {cert_info['subject']}",
        metadata={
            "subject": cert_info["subject"],
            "serial": cert_info["serial_number"],
            "validity_days": validity_days,
        }
    )

    ct = CTLog(out_dir)
    ct.append(certificate)
    logger.info(f"Serial: {cert_info['serial_number']}")
    logger.info("=" * 60)


def issue_intermediate_ca(
        root_cert_path: Path,
        root_key_path: Path,
        root_passphrase: bytes,
        subject_dn: str,
        key_type: str,
        key_size: int,
        passphrase: bytes,
        out_dir: Path,
        validity_days: int,
        path_length: int,
        logger: logging.Logger,
        db_path: Optional[Path] = None
) -> None:
    """
    Создаёт промежуточный CA, подписанный корневым.

    Args:
        root_cert_path: Путь к сертификату корневого CA
        root_key_path: Путь к зашифрованному ключу корневого CA
        root_passphrase: Пароль корневого CA
        subject_dn: DN для промежуточного CA
        key_type: Тип ключа ('rsa' или 'ecc')
        key_size: Размер ключа
        passphrase: Пароль для ключа промежуточного CA
        out_dir: Директория для сохранения
        validity_days: Срок действия
        path_length: Ограничение длины пути
        logger: Логгер
        db_path: Путь к базе данных
    """
    logger.info("=" * 60)
    logger.info("Starting Intermediate CA creation")
    logger.info("=" * 60)

    # Валидация
    audit = AuditLogger(out_dir)
    audit.audit(
        operation="ca_issue_intermediate",
        status="started",
        message=f"Issuing intermediate CA: {subject_dn}",
        metadata={"subject": subject_dn, "key_type": key_type, "key_size": key_size,
                  "validity_days": validity_days, "path_length": path_length}
    )

    try:
        validate_generated_key_params(key_type, key_size, "intermediate_ca")
        validate_validity_policy(validity_days, "intermediate_ca")
        validate_intermediate_policy(path_length)
        if validity_days <= 0:
            raise PolicyViolation("Validity days must be positive")
    except PolicyViolation as e:
        audit.audit(
            operation="ca_issue_intermediate",
            status="policy_violation",
            message=str(e),
            metadata={"subject": subject_dn, "validity_days": validity_days, "path_length": path_length}
        )
        raise

    # Загружаем корневой CA
    logger.info(f"Loading root CA certificate: {root_cert_path}")
    root_cert = load_certificate(root_cert_path)

    logger.info("Loading root CA private key")
    root_key = load_encrypted_private_key(root_key_path, root_passphrase)

    # Генерируем ключи промежуточного CA
    subject = parse_subject_dn(subject_dn)
    logger.info(f"Intermediate CA subject: {subject.rfc4514_string()}")

    logger.info(f"Generating {key_type.upper()} key pair ({key_size} bits) for intermediate CA...")
    if key_type == 'rsa':
        intermediate_key = generate_rsa_key_pair(key_size)
    else:
        intermediate_key = generate_ecc_key_pair(key_size)
    logger.info("Key pair generated")

    # Создаём CSR
    logger.info("Creating CSR for intermediate CA...")
    csr = create_csr(intermediate_key, subject, is_ca=True, path_length=path_length)
    logger.info("CSR created")

    # Корневой CA подписывает CSR
    logger.info(f"Signing intermediate CA certificate (valid for {validity_days} days, pathlen={path_length})...")
    intermediate_cert = create_intermediate_certificate(
        csr=csr,
        root_key=root_key,
        root_cert=root_cert,
        validity_days=validity_days,
        path_length=path_length
    )
    logger.info("Intermediate CA certificate signed by root CA")

    # Создаём директории
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    csrs_dir = out_dir / 'csrs'
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)
    csrs_dir.mkdir(parents=True, exist_ok=True)

    # Сохраняем ключ
    key_path = private_dir / 'intermediate.key.pem'
    save_encrypted_private_key(intermediate_key, key_path, passphrase)
    logger.info(f"Intermediate key saved: {key_path}")

    # Сохраняем сертификат
    cert_path = certs_dir / 'intermediate.cert.pem'
    save_certificate(intermediate_cert, cert_path)
    logger.info(f"Intermediate certificate saved: {cert_path}")

    # Сохраняем CSR
    csr_path = csrs_dir / 'intermediate.csr.pem'
    save_csr(csr, csr_path)
    logger.info(f"CSR saved: {csr_path}")

    # Обновляем policy.txt
    policy_path = out_dir / 'policy.txt'
    cert_info = get_certificate_info(intermediate_cert)
    _update_policy_with_intermediate(policy_path, cert_info, key_type, key_size, path_length)
    logger.info("Policy document updated")

    if os.name == 'nt':
        logger.warning("Running on Windows - file permission checks skipped")

    # === Сохранение в БД ===
    if db_path:
        try:
            from .database import CertificateDatabase

            cert_pem = intermediate_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode('utf-8')

            db = CertificateDatabase(db_path)
            serial_hex = db.add_certificate(
                certificate=intermediate_cert,
                certificate_pem=cert_pem,
                template='intermediate_ca',
                san_entries=None
            )
            logger.info(f"Intermediate CA added to database: serial={serial_hex}")
        except Exception as e:
            logger.warning(f"Failed to add intermediate CA to database: {e}")

    # Финальный лог
    logger.info("=" * 60)
    logger.info("Intermediate CA created successfully")
    audit.audit(
        operation="ca_issue_intermediate",
        status="success",
        message=f"Intermediate CA issued: {cert_info['subject']}",
        metadata={
            "subject": cert_info["subject"],
            "serial": cert_info["serial_number"],
            "validity_days": validity_days,
            "path_length": path_length,
        }
    )

    ct = CTLog(out_dir)
    ct.append(intermediate_cert)
    logger.info(f"Serial: {cert_info['serial_number']}")
    logger.info(f"Issuer: {cert_info['issuer']}")
    logger.info("=" * 60)


def issue_certificate(
        ca_cert_path: Path,
        ca_key_path: Path,
        ca_passphrase: bytes,
        template_name: str,
        subject_dn: str,
        san_entries: List[str],
        out_dir: Path,
        validity_days: int,
        key_type: str = 'rsa',
        key_size: int = 2048,
        logger: logging.Logger = None,
        db_path: Optional[Path] = None,
        csr_path: Optional[Path] = None,
        csr_pem: Optional[bytes] = None
) -> Optional[str]:
    if logger is None:
        logger = logging.getLogger('micropki')

    logger.info("=" * 60)
    logger.info(f"Issuing {template_name} certificate")
    # Определяем корень для audit/CT (срезаем certs/ если надо)
    audit_root = Path(out_dir)
    if audit_root.name == 'certs':
        audit_root = audit_root.parent

    audit = AuditLogger(audit_root)
    audit.audit(
        operation="issue_certificate",
        status="started",
        message=f"Issuing {template_name} certificate",
        metadata={"template": template_name, "subject": subject_dn, "csr": bool(csr_path or csr_pem)}
    )
    logger.info("=" * 60)

    # Валидация шаблона
    template = get_template(template_name)
    logger.info(f"Template: {template_name}")

    try:
        validate_validity_policy(validity_days, "end_entity")
    except PolicyViolation as e:
        audit.audit(
            operation="issue_certificate",
            status="policy_violation",
            message=str(e),
            metadata={"template": template_name, "validity_days": validity_days}
        )
        raise

    # Загружаем CA
    logger.info(f"Loading CA certificate: {ca_cert_path}")
    ca_cert = load_certificate(ca_cert_path)

    logger.info("Loading CA private key")
    ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

    # ===== РАЗВЕТВЛЕНИЕ: с CSR или без =====
    csr = None
    if csr_path is not None or csr_pem is not None:
        from .csr import load_csr, verify_csr
        from cryptography import x509 as _x509

        if csr_pem is not None:
            logger.info("Loading CSR from memory")
            csr = _x509.load_pem_x509_csr(csr_pem)
        else:
            logger.info(f"Loading CSR from: {csr_path}")
            csr = load_csr(csr_path)

        # Проверяем подпись CSR
        if not verify_csr(csr):
            raise ValueError("CSR signature is invalid")
        logger.info("CSR signature verified")
        # Sprint 7: политики на CSR
        try:
            san_entries_from_csr = validate_csr_policy(csr, template_name, "end_entity")
        except PolicyViolation as e:
            audit.audit(
                operation="issue_certificate",
                status="policy_violation",
                message=str(e),
                metadata={"template": template_name, "subject": csr.subject.rfc4514_string()}
            )
            raise

        # Sprint 7: блокировка скомпрометированного ключа
        pk_hash = csr_public_key_hash(csr)
        if db_path:
            from .database import CertificateDatabase as _DB
            _db = _DB(db_path)
            if _db.is_key_compromised(pk_hash):
                audit.audit(
                    operation="issue_certificate",
                    status="policy_violation",
                    message="CSR uses a compromised public key",
                    metadata={"public_key_hash": pk_hash}
                )
                raise PolicyViolation("Public key is marked as compromised; refusing to issue")

        # Subject и public_key берём из CSR
        subject = csr.subject
        entity_public_key = csr.public_key()
        logger.info(f"Subject from CSR: {subject.rfc4514_string()}")

        # Проверка что CSR не запрашивает CA=True
        try:
            bc = csr.extensions.get_extension_for_class(_x509.BasicConstraints)
            if bc.value.ca:
                raise ValueError("CSR requests CA=True, which is not allowed for end-entity certificates")
        except _x509.ExtensionNotFound:
            pass

        # SAN из CSR (переопределяет san_entries)
        san_extension = None
        try:
            san_ext = csr.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            san_extension = san_ext.value
            san_entries = [_format_san(n) for n in san_extension]
            logger.info(f"SAN from CSR: {san_entries}")
        except _x509.ExtensionNotFound:
            if san_entries:
                san_extension = parse_san_entries(san_entries)
                logger.info(f"SAN from arguments: {san_entries}")

        # Валидация SAN для шаблона
        validate_san_for_template(template, san_entries)

        entity_key = None  # ключ не генерируем

    else:
        # Старая логика: генерируем ключ сами
        try:
            validate_san_for_template(template, san_entries)
            validate_san_policy(template_name, san_entries)
            validate_generated_key_params(key_type, key_size, "end_entity")
        except PolicyViolation as e:
            audit.audit(
                operation="issue_certificate",
                status="policy_violation",
                message=str(e),
                metadata={"template": template_name, "san": san_entries}
            )
            raise

        subject = parse_subject_dn(subject_dn)

        subject = parse_subject_dn(subject_dn)
        logger.info(f"Subject: {subject.rfc4514_string()}")

        san_extension = None
        if san_entries:
            san_extension = parse_san_entries(san_entries)
            logger.info(f"SAN entries: {san_entries}")

        logger.info(f"Generating {key_type.upper()}-{key_size} key pair for end entity...")
        if key_type == 'rsa':
            entity_key = generate_rsa_key_pair(key_size)
        else:
            entity_key = generate_ecc_key_pair(key_size)
        logger.info("Key pair generated")
        entity_public_key = entity_key.public_key()

    cn = get_cn_from_subject(subject)

    # Создаём сертификат
    logger.info(f"Creating {template_name} certificate (valid for {validity_days} days)...")
    certificate = create_leaf_certificate(
        subject=subject,
        public_key=entity_public_key,
        ca_key=ca_key,
        ca_cert=ca_cert,
        template_name=template_name,
        validity_days=validity_days,
        san_extension=san_extension
    )
    logger.info("Certificate created and signed")

    # Имена файлов
    safe_cn = cn.replace(' ', '_').replace('*', 'wildcard')
    safe_cn = ''.join(c for c in safe_cn if c.isalnum() or c in '._-')
    if not safe_cn:
        safe_cn = format(certificate.serial_number, 'x')[:16]

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    cert_path = out_path / f'{safe_cn}.cert.pem'
    save_certificate(certificate, cert_path)
    logger.info(f"Certificate saved: {cert_path}")

    # Ключ сохраняем только если генерировали сами
    if entity_key is not None:
        key_path = out_path / f'{safe_cn}.key.pem'
        save_unencrypted_private_key(entity_key, key_path)
        logger.warning(f"Private key saved WITHOUT encryption: {key_path}")

    if os.name == 'nt':
        logger.warning("Running on Windows - file permission checks skipped")

    # Сохранение в БД
    serial_hex = None
    if db_path:
        try:
            from .database import CertificateDatabase
            cert_pem_str = certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode('utf-8')

            db = CertificateDatabase(db_path)
            serial_hex = db.add_certificate(
                certificate=certificate,
                certificate_pem=cert_pem_str,
                template=template_name,
                san_entries=san_entries
            )
            logger.info(f"Certificate added to database: serial={serial_hex}")
        except Exception as e:
            logger.warning(f"Failed to add certificate to database: {e}")

    cert_info = get_certificate_info(certificate)
    logger.info("=" * 60)
    logger.info("Certificate issued successfully")
    logger.info(f"Template: {template_name}")
    logger.info(f"Subject: {cert_info['subject']}")
    logger.info(f"Serial: {cert_info['serial_number']}")
    logger.info(f"Issuer: {cert_info['issuer']}")
    logger.info(f"Valid: {cert_info['not_valid_before']} to {cert_info['not_valid_after']}")
    if san_entries:
        logger.info(f"SAN: {', '.join(san_entries)}")
    logger.info(f"Certificate: {cert_path}")
    logger.info("=" * 60)

    # Sprint 7: CT-log + аудит
    try:
        ct = CTLog(audit_root)
        ct.append(certificate)
    except Exception as e:
        logger.warning(f"CT log append failed: {e}")

    audit.audit(
        operation="issue_certificate",
        status="success",
        message=f"Issued {template_name} certificate: {cert_info['subject']}",
        metadata={
            "serial": cert_info["serial_number"],
            "subject": cert_info["subject"],
            "template": template_name,
            "san": san_entries,
        }
    )

    return serial_hex


def _format_san(name) -> str:
    from cryptography import x509 as _x509
    if isinstance(name, _x509.DNSName):
        return f"dns:{name.value}"
    elif isinstance(name, _x509.IPAddress):
        return f"ip:{name.value}"
    elif isinstance(name, _x509.RFC822Name):
        return f"email:{name.value}"
    elif isinstance(name, _x509.UniformResourceIdentifier):
        return f"uri:{name.value}"
    return str(name)



# ============================================================
# Вспомогательные функции для policy.txt
# ============================================================

def _create_policy_file(path: Path, cert_info: dict, key_type: str, key_size: int) -> None:
    """Создаёт policy.txt для корневого CA."""
    content = f"""================================================================================
                    CERTIFICATE POLICY DOCUMENT - MicroPKI
================================================================================

Policy Version: 1.0
Created: {datetime.now(timezone.utc).isoformat()}

--- ROOT CA ---
Subject DN:      {cert_info['subject']}
Serial Number:   {cert_info['serial_number']}
Not Before:      {cert_info['not_valid_before']}
Not After:       {cert_info['not_valid_after']}
Key Algorithm:   {key_type.upper()}-{key_size}
Signature:       {cert_info['signature_algorithm']}
Purpose:         Root of trust for MicroPKI (educational/demo only)

--- SECURITY POLICY ---
Min RSA key:     2048 bits
Min ECC curve:   P-256
Max validity:    Root=10y, Intermediate=5y, End-entity=1y
Key storage:     Encrypted PKCS#8 (AES-256)

DO NOT USE IN PRODUCTION.
================================================================================
"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def _update_policy_with_intermediate(
        path: Path,
        cert_info: dict,
        key_type: str,
        key_size: int,
        path_length: int
) -> None:
    """Дополняет policy.txt информацией о промежуточном CA."""
    addition = f"""
--- INTERMEDIATE CA ---
Subject DN:      {cert_info['subject']}
Serial Number:   {cert_info['serial_number']}
Not Before:      {cert_info['not_valid_before']}
Not After:       {cert_info['not_valid_after']}
Key Algorithm:   {key_type.upper()}-{key_size}
Signature:       {cert_info['signature_algorithm']}
Issuer DN:       {cert_info['issuer']}
Path Length:     {path_length}
Purpose:         Issuing CA for end-entity certificates
================================================================================
"""
    with open(path, 'a', encoding='utf-8') as f:
        f.write(addition)

def issue_ocsp_certificate(
        ca_cert_path: Path,
        ca_key_path: Path,
        ca_passphrase: bytes,
        subject_dn: str,
        key_type: str = 'rsa',
        key_size: int = 2048,
        san_entries: list = None,
        out_dir: Path = None,
        validity_days: int = 365,
        logger: logging.Logger = None,
        db_path: Optional[Path] = None,
        ocsp_url: Optional[str] = None
) -> None:

    if logger is None:
        logger = logging.getLogger('micropki')

    logger.info("=" * 60)
    logger.info("Issuing OCSP Responder certificate")
    logger.info("=" * 60)

    ca_cert = load_certificate(ca_cert_path)
    ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

    subject = parse_subject_dn(subject_dn)

    if key_type == 'rsa':
        ocsp_key = generate_rsa_key_pair(key_size)
    else:
        ocsp_key = generate_ecc_key_pair(key_size)

    san_extension = None
    if san_entries:
        from .certificates import parse_san_entries
        san_extension = parse_san_entries(san_entries)

    from .certificates import create_ocsp_certificate
    cert = create_ocsp_certificate(
        subject=subject,
        public_key=ocsp_key.public_key(),
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=validity_days,
        san_extension=san_extension,
        ocsp_url=ocsp_url
    )

    out_path = Path(out_dir) if out_dir else Path('./pki/pki1/certs')
    out_path.mkdir(parents=True, exist_ok=True)

    cert_path = out_path / 'ocsp.cert.pem'
    key_path = out_path / 'ocsp.key.pem'

    save_certificate(cert, cert_path)
    logger.info(f"OCSP certificate saved: {cert_path}")

    # Ключ БЕЗ шифрования (ответчик должен загружать автоматически)
    save_unencrypted_private_key(ocsp_key, key_path)
    logger.warning(f"OCSP private key saved WITHOUT encryption: {key_path}")
    logger.warning("Protect this file with filesystem permissions (0o600)")

    if db_path:
        try:
            from .database import CertificateDatabase
            from cryptography.hazmat.primitives import serialization
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            db = CertificateDatabase(db_path)
            serial_hex = db.add_certificate(cert, cert_pem, template='ocsp')
            logger.info(f"OCSP certificate added to DB: serial={serial_hex}")
        except Exception as e:
            logger.warning(f"Failed to add OCSP cert to DB: {e}")

    logger.info("=" * 60)
    logger.info("OCSP certificate issued successfully")
    logger.info(f"  Cert: {cert_path}")
    logger.info(f"  Key:  {key_path}")
    logger.info("=" * 60)

def compromise_certificate(
    cert_path: Path,
    out_dir: Path,
    db_path: Path,
    ca_passphrase: Optional[bytes] = None,
    ca_cert_path: Optional[Path] = None,
    ca_key_path: Optional[Path] = None,
    reason: str = "keyCompromise",
    logger: Optional[logging.Logger] = None,
) -> dict:
    if logger is None:
        logger = logging.getLogger("micropki")

    audit = AuditLogger(Path(out_dir))

    cert = load_certificate(Path(cert_path))
    serial_hex = format(cert.serial_number, "X")
    pk_hash = certificate_public_key_hash(cert)

    audit.audit(
        operation="ca_compromise",
        status="started",
        message=f"Compromise simulation for {serial_hex}",
        metadata={"serial": serial_hex, "reason": reason}
    )

    from .database import CertificateDatabase
    db = CertificateDatabase(db_path)

    cert_in_db = db.get_certificate(serial_hex)
    if cert_in_db is None:
        audit.audit(
            operation="ca_compromise",
            status="failure",
            message=f"Certificate not found in DB: {serial_hex}",
            metadata={"serial": serial_hex}
        )
        raise ValueError(f"Certificate {serial_hex} not found in database")

    if cert_in_db["status"] != "revoked":
        db.revoke_certificate(serial_hex, reason)

    db.add_compromised_key(pk_hash, serial_hex, reason)

    emergency_crl_path = None
    if ca_cert_path is not None and ca_key_path is not None and ca_passphrase is not None:
        try:
            from .crl import CRLManager
            issuer_dn = cert.issuer.rfc4514_string()
            ca_name = "intermediate"
            if "intermediate" not in issuer_dn.lower():
                ca_name = "root"

            crl_manager = CRLManager(Path(out_dir), logger)
            revoked_list = db.get_revoked_by_issuer(issuer_dn)
            emergency_crl_path = crl_manager.generate_and_save_crl(
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
                ca_passphrase=ca_passphrase,
                revoked_certs=revoked_list,
                ca_name=ca_name,
                next_update_days=7,
            )
            logger.info(f"Emergency CRL regenerated: {emergency_crl_path}")
        except Exception as e:
            logger.warning(f"Emergency CRL generation failed: {e}")

    audit.audit(
        operation="ca_compromise",
        status="success",
        message=f"Certificate {serial_hex} marked compromised",
        metadata={
            "serial": serial_hex,
            "reason": reason,
            "public_key_hash": pk_hash,
            "emergency_crl": str(emergency_crl_path) if emergency_crl_path else None,
        }
    )

    return {
        "serial": serial_hex,
        "public_key_hash": pk_hash,
        "emergency_crl": str(emergency_crl_path) if emergency_crl_path else None,
    }

