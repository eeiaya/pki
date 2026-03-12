"""
Certificate Authority operations
"""

import os
from pathlib import Path
from typing import Union
from datetime import datetime, timezone
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from .crypto_utils import (
    generate_rsa_key_pair,
    generate_ecc_key_pair,
    save_encrypted_private_key,
    save_certificate,
)
from .certificates import (
    parse_subject_dn,
    create_self_signed_certificate,
    get_certificate_info,
)


def initialize_root_ca(
    subject_dn: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: Path,
    validity_days: int,
    logger: logging.Logger
) -> None:
    """
    Initialize a root Certificate Authority.

    Args:
        subject_dn: Distinguished Name for the CA
        key_type: 'rsa' or 'ecc'
        key_size: Key size in bits (4096 for RSA, 384 for ECC)
        passphrase: Passphrase for encrypting private key
        out_dir: Output directory for PKI files
        validity_days: Certificate validity period in days
        logger: Logger instance

    Raises:
        ValueError: If parameters are invalid
    """
    logger.info("=" * 60)
    logger.info("Starting Root CA initialization")
    logger.info("=" * 60)

    # Validate parameters
    if key_type not in ('rsa', 'ecc'):
        raise ValueError(f"Invalid key type: {key_type}. Must be 'rsa' or 'ecc'")

    if key_type == 'rsa' and key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")

    if key_type == 'ecc' and key_size != 384:
        raise ValueError("ECC key size must be 384 bits (P-384 curve)")

    if validity_days <= 0:
        raise ValueError("Validity days must be positive")

    # Parse subject DN
    logger.info(f"Parsing subject DN: {subject_dn}")
    try:
        subject = parse_subject_dn(subject_dn)
        logger.info(f"Parsed subject: {subject.rfc4514_string()}")
    except Exception as e:
        logger.error(f"Failed to parse subject DN: {e}")
        raise

    # Generate key pair
    logger.info(f"Generating {key_type.upper()} key pair ({key_size} bits)...")
    try:
        if key_type == 'rsa':
            private_key = generate_rsa_key_pair(key_size)
        else:  # ecc
            private_key = generate_ecc_key_pair(key_size)
        logger.info("Key pair generated successfully")
    except Exception as e:
        logger.error(f"Failed to generate key pair: {e}")
        raise

    # Create self-signed certificate
    logger.info(f"Creating self-signed certificate (valid for {validity_days} days)...")
    try:
        certificate = create_self_signed_certificate(
            private_key=private_key,
            subject=subject,
            validity_days=validity_days
        )
        logger.info("Certificate created successfully")
    except Exception as e:
        logger.error(f"Failed to create certificate: {e}")
        raise

    # Create directory structure
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'

    logger.info(f"Creating directory structure in {out_dir}")
    try:
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        certs_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Directories created successfully")
    except Exception as e:
        logger.error(f"Failed to create directories: {e}")
        raise

    # Save encrypted private key
    key_path = private_dir / 'ca.key.pem'
    logger.info(f"Saving encrypted private key to {key_path}")
    try:
        save_encrypted_private_key(private_key, key_path, passphrase)

        # Verify permissions on Unix-like systems
        if os.name != 'nt':  # Not Windows
            stat_info = os.stat(key_path)
            mode = stat_info.st_mode & 0o777
            if mode != 0o600:
                logger.warning(f"Key file permissions are {oct(mode)}, expected 0600")
        else:
            logger.warning("Running on Windows - file permission checks skipped")

        logger.info("Private key saved successfully")
    except Exception as e:
        logger.error(f"Failed to save private key: {e}")
        raise

    # Save certificate
    cert_path = certs_dir / 'ca.cert.pem'
    logger.info(f"Saving certificate to {cert_path}")
    try:
        save_certificate(certificate, cert_path)
        logger.info("Certificate saved successfully")
    except Exception as e:
        logger.error(f"Failed to save certificate: {e}")
        raise

    # Generate policy file
    policy_path = out_dir / 'policy.txt'
    logger.info(f"Generating certificate policy document: {policy_path}")
    try:
        cert_info = get_certificate_info(certificate)
        create_policy_file(policy_path, cert_info, key_type, key_size)
        logger.info("Policy document created successfully")
    except Exception as e:
        logger.error(f"Failed to create policy document: {e}")
        raise

    # Log summary
    logger.info("=" * 60)
    logger.info("Root CA initialization completed successfully")
    logger.info("=" * 60)
    logger.info(f"Subject: {cert_info['subject']}")
    logger.info(f"Serial Number: {cert_info['serial_number']}")
    logger.info(f"Valid From: {cert_info['not_valid_before']}")
    logger.info(f"Valid Until: {cert_info['not_valid_after']}")
    logger.info(f"Key Algorithm: {cert_info['key_type']}-{cert_info['key_size']}")
    logger.info(f"Signature Algorithm: {cert_info['signature_algorithm']}")
    logger.info("=" * 60)
    logger.info(f"Private Key: {key_path}")
    logger.info(f"Certificate: {cert_path}")
    logger.info(f"Policy: {policy_path}")
    logger.info("=" * 60)


def create_policy_file(
    path: Path,
    cert_info: dict,
    key_type: str,
    key_size: int
) -> None:
    """
    Create a Certificate Policy document.

    Args:
        path: Path where to save the policy file
        cert_info: Certificate information dictionary
        key_type: Key type (rsa/ecc)
        key_size: Key size in bits
    """
    # Use timezone-aware datetime
    policy_content = f"""
================================================================================
                    CERTIFICATE POLICY DOCUMENT
                         MicroPKI Root CA
================================================================================

Policy Version: 1.0
Document Date: {datetime.now(timezone.utc).isoformat()}

--------------------------------------------------------------------------------
1. CERTIFICATE AUTHORITY INFORMATION
--------------------------------------------------------------------------------

CA Name (Subject DN):
    {cert_info['subject']}

Certificate Serial Number:
    {cert_info['serial_number']}

Validity Period:
    Not Before: {cert_info['not_valid_before']}
    Not After:  {cert_info['not_valid_after']}

Public Key Algorithm:
    Type: {key_type.upper()}
    Size: {key_size} bits
    {'Curve: NIST P-384 (secp384r1)' if key_type == 'ecc' else ''}

Signature Algorithm:
    {cert_info['signature_algorithm']}

--------------------------------------------------------------------------------
2. PURPOSE AND SCOPE
--------------------------------------------------------------------------------

This is a ROOT Certificate Authority created for the MicroPKI project.

Purpose:
    - Educational demonstration of PKI concepts
    - Root of trust for the MicroPKI certificate hierarchy
    - Signing intermediate CAs and issuing certificates

Scope:
    - This CA is intended for DEMONSTRATION and EDUCATIONAL purposes only
    - NOT for production use
    - NOT for securing real-world applications

--------------------------------------------------------------------------------
3. KEY USAGE
--------------------------------------------------------------------------------

The CA certificate is authorized for:
    - Certificate Signing (keyCertSign)
    - CRL Signing (cRLSign)
    - Digital Signature

Basic Constraints:
    - CA: TRUE
    - Path Length: None (unlimited)

--------------------------------------------------------------------------------
4. SECURITY POLICY
--------------------------------------------------------------------------------

Private Key Protection:
    - Stored encrypted using AES-256-CBC with PBKDF2
    - Passphrase-protected
    - File permissions: 0600 (owner read/write only)

Key Generation:
    - Generated using cryptographically secure random number generator
    - Complies with NIST recommendations for key sizes

Certificate Issuance:
    - Minimum RSA key size: 2048 bits (recommended: 4096)
    - Minimum ECC curve: P-256 (recommended: P-384)
    - Maximum validity period:
        * Root CA: 10 years
        * Intermediate CA: 5 years
        * End-entity: 1 year

Revocation:
    - CRL (Certificate Revocation List) support
    - OCSP (Online Certificate Status Protocol) planned
    - Regular CRL updates required

--------------------------------------------------------------------------------
5. OPERATIONAL CONTACTS
--------------------------------------------------------------------------------

This is a demonstration CA. For the purposes of this project:
    - Technical Contact: [Your Name/Email]
    - Security Contact: [Your Name/Email]

--------------------------------------------------------------------------------
6. LEGAL DISCLAIMER
--------------------------------------------------------------------------------

This Certificate Authority and its certificates are provided for EDUCATIONAL
PURPOSES ONLY. The issuer makes no warranties regarding the security,
reliability, or fitness for any purpose of this CA or any certificates issued
by it.

DO NOT USE IN PRODUCTION ENVIRONMENTS.

================================================================================
                            END OF POLICY DOCUMENT
================================================================================
""".strip()

    with open(path, 'w', encoding='utf-8') as f:
        f.write(policy_content)