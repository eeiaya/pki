
import os
from pathlib import Path
from typing import Union, Optional, List
from datetime import datetime, timezone
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ec

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
from .csr import create_csr
from .templates import get_template, validate_san_for_template


def initialize_root_ca(
    subject_dn: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: Path,
    validity_days: int,
    logger: logging.Logger
) -> None:
    """Инициализирует корневой CA (из Спринта 1)."""
    logger.info("=" * 60)
    logger.info("Starting Root CA initialization")
    logger.info("=" * 60)

    if key_type not in ('rsa', 'ecc'):
        raise ValueError(f"Invalid key type: {key_type}")
    if key_type == 'rsa' and key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")
    if key_type == 'ecc' and key_size != 384:
        raise ValueError("ECC key size must be 384 bits (P-384)")
    if validity_days <= 0:
        raise ValueError("Validity days must be positive")

    subject = parse_subject_dn(subject_dn)
    logger.info(f"Subject: {subject.rfc4514_string()}")

    logger.info(f"Generating {key_type.upper()} key pair ({key_size} bits)...")
    if key_type == 'rsa':
        private_key = generate_rsa_key_pair(key_size)
    else:
        private_key = generate_ecc_key_pair(key_size)
    logger.info("Key pair generated successfully")

    logger.info(f"Creating self-signed certificate (valid for {validity_days} days)...")
    certificate = create_self_signed_certificate(private_key, subject, validity_days)
    logger.info("Certificate created successfully")

    # Создаём директории и сохраняем файлы
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)

    key_path = private_dir / 'ca.key.pem'
    save_encrypted_private_key(private_key, key_path, passphrase)
    logger.info(f"Private key saved: {key_path}")

    if os.name == 'nt':
        logger.warning("Running on Windows - file permission checks skipped")

    cert_path = certs_dir / 'ca.cert.pem'
    save_certificate(certificate, cert_path)
    logger.info(f"Certificate saved: {cert_path}")

    # Policy file
    policy_path = out_dir / 'policy.txt'
    cert_info = get_certificate_info(certificate)
    _create_policy_file(policy_path, cert_info, key_type, key_size)
    logger.info(f"Policy document: {policy_path}")

    logger.info("=" * 60)
    logger.info("Root CA initialization completed successfully")
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
    logger: logging.Logger
) -> None:

    logger.info("=" * 60)
    logger.info("Starting Intermediate CA creation")
    logger.info("=" * 60)

    # Валидация
    if key_type == 'rsa' and key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if key_type == 'ecc' and key_size != 384:
        raise ValueError("ECC key size must be 384")
    if validity_days <= 0:
        raise ValueError("Validity days must be positive")
    if path_length < 0:
        raise ValueError("Path length must be >= 0")

    # 1. Загружаем корневой CA
    logger.info(f"Loading root CA certificate: {root_cert_path}")
    root_cert = load_certificate(root_cert_path)

    logger.info("Loading root CA private key")
    root_key = load_encrypted_private_key(root_key_path, root_passphrase)

    # 2. Генерируем ключи промежуточного CA
    subject = parse_subject_dn(subject_dn)
    logger.info(f"Intermediate CA subject: {subject.rfc4514_string()}")

    logger.info(f"Generating {key_type.upper()} key pair ({key_size} bits) for intermediate CA...")
    if key_type == 'rsa':
        intermediate_key = generate_rsa_key_pair(key_size)
    else:
        intermediate_key = generate_ecc_key_pair(key_size)
    logger.info("Key pair generated")

    # 3. Создаём CSR
    logger.info("Creating CSR for intermediate CA...")
    csr = create_csr(intermediate_key, subject, is_ca=True, path_length=path_length)
    logger.info("CSR created")

    # 4. Корневой CA подписывает CSR
    logger.info(f"Signing intermediate CA certificate (valid for {validity_days} days, pathlen={path_length})...")
    intermediate_cert = create_intermediate_certificate(
        csr=csr,
        root_key=root_key,
        root_cert=root_cert,
        validity_days=validity_days,
        path_length=path_length
    )
    logger.info("Intermediate CA certificate signed by root CA")

    # 5. Сохраняем
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    csrs_dir = out_dir / 'csrs'
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)
    csrs_dir.mkdir(parents=True, exist_ok=True)

    # Ключ
    key_path = private_dir / 'intermediate.key.pem'
    save_encrypted_private_key(intermediate_key, key_path, passphrase)
    logger.info(f"Intermediate key saved: {key_path}")

    # Сертификат
    cert_path = certs_dir / 'intermediate.cert.pem'
    save_certificate(intermediate_cert, cert_path)
    logger.info(f"Intermediate certificate saved: {cert_path}")

    # CSR (для справки)
    from .csr import save_csr
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

    logger.info("=" * 60)
    logger.info("Intermediate CA created successfully")
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
    logger: logging.Logger = None
) -> None:

    if logger is None:
        import logging
        logger = logging.getLogger('micropki')

    logger.info("=" * 60)
    logger.info(f"Issuing {template_name} certificate")
    logger.info("=" * 60)

    # Валидация шаблона и SAN
    template = get_template(template_name)
    validate_san_for_template(template, san_entries)
    logger.info(f"Template: {template_name}")

    # Загружаем CA
    logger.info(f"Loading CA certificate: {ca_cert_path}")
    ca_cert = load_certificate(ca_cert_path)

    logger.info("Loading CA private key")
    ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

    # Парсим subject
    subject = parse_subject_dn(subject_dn)
    cn = get_cn_from_subject(subject)
    logger.info(f"Subject: {subject.rfc4514_string()}")

    # Парсим SAN
    san_extension = None
    if san_entries:
        san_extension = parse_san_entries(san_entries)
        logger.info(f"SAN entries: {san_entries}")

    # Генерируем ключи
    logger.info(f"Generating {key_type.upper()}-{key_size} key pair for end entity...")
    if key_type == 'rsa':
        entity_key = generate_rsa_key_pair(key_size)
    else:
        entity_key = generate_ecc_key_pair(key_size)
    logger.info("Key pair generated")

    # Создаём сертификат
    logger.info(f"Creating {template_name} certificate (valid for {validity_days} days)...")
    certificate = create_leaf_certificate(
        subject=subject,
        public_key=entity_key.public_key(),
        ca_key=ca_key,
        ca_cert=ca_cert,
        template_name=template_name,
        validity_days=validity_days,
        san_extension=san_extension
    )
    logger.info("Certificate created and signed")

    # Определяем имена файлов
    # Безопасное имя файла из CN
    safe_cn = cn.replace(' ', '_').replace('*', 'wildcard')
    safe_cn = ''.join(c for c in safe_cn if c.isalnum() or c in '._-')
    if not safe_cn:
        safe_cn = format(certificate.serial_number, 'x')[:16]

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    cert_path = out_path / f'{safe_cn}.cert.pem'
    key_path = out_path / f'{safe_cn}.key.pem'

    # Сохраняем сертификат
    save_certificate(certificate, cert_path)
    logger.info(f"Certificate saved: {cert_path}")

    # Сохраняем ключ БЕЗ шифрования (для конечных сертификатов)
    save_unencrypted_private_key(entity_key, key_path)
    logger.warning(f"Private key saved WITHOUT encryption: {key_path}")
    logger.warning("Consider protecting this key with appropriate access controls")

    if os.name == 'nt':
        logger.warning("Running on Windows - file permission checks skipped")

    # Лог аудита
    cert_info = get_certificate_info(certificate)
    logger.info("=" * 60)
    logger.info(f"Certificate issued successfully")
    logger.info(f"Template: {template_name}")
    logger.info(f"Subject: {cert_info['subject']}")
    logger.info(f"Serial: {cert_info['serial_number']}")
    logger.info(f"Issuer: {cert_info['issuer']}")
    logger.info(f"Valid: {cert_info['not_valid_before']} to {cert_info['not_valid_after']}")
    if san_entries:
        logger.info(f"SAN: {', '.join(san_entries)}")
    logger.info(f"Certificate: {cert_path}")
    logger.info(f"Private Key: {key_path}")
    logger.info("=" * 60)


def _create_policy_file(path, cert_info, key_type, key_size):

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


def _update_policy_with_intermediate(path, cert_info, key_type, key_size, path_length):

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