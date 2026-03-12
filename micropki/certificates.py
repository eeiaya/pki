"""
X.509 certificate generation and manipulation
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Union

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .crypto_utils import compute_ski


def parse_subject_dn(dn_string: str) -> x509.Name:
    """
    Parse a Distinguished Name string into x509.Name object.
    """
    if not dn_string or not dn_string.strip():
        raise ValueError("DN string cannot be empty")

    dn_string = dn_string.strip()


    if dn_string.startswith('/'):

        parts = [p for p in dn_string.split('/') if p]
    else:

        parts = [p.strip() for p in dn_string.split(',')]


    attributes = []
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'EMAIL': NameOID.EMAIL_ADDRESS,
    }

    for part in parts:
        if '=' not in part:
            raise ValueError(f"Invalid DN component: {part}")

        key, value = part.split('=', 1)
        key = key.strip().upper()
        value = value.strip()

        if not value:
            raise ValueError(f"Empty value for DN component: {key}")

        if key not in oid_map:
            raise ValueError(f"Unsupported DN attribute: {key}")

        attributes.append(x509.NameAttribute(oid_map[key], value))

    if not attributes:
        raise ValueError("DN must contain at least one attribute")

    return x509.Name(attributes)


def generate_serial_number() -> int:
    """
    Generate a cryptographically secure random serial number.
    """

    random_bytes = secrets.token_bytes(20)


    serial = int.from_bytes(random_bytes, byteorder='big')


    serial = serial & ((1 << 159) - 1)

    return serial


def create_self_signed_certificate(
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    subject: x509.Name,
    validity_days: int
) -> x509.Certificate:
    """
    Create a self-signed root CA certificate.
    """
    # Determine hash algorithm based on key type
    if isinstance(private_key, rsa.RSAPrivateKey):
        hash_algorithm = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        hash_algorithm = hashes.SHA384()
    else:
        raise ValueError("Unsupported key type")


    serial = generate_serial_number()


    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)


    public_key = private_key.public_key()
    ski_value = compute_ski(public_key)


    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)  # Self-signed: issuer = subject
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)


    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )


    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )


    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(ski_value),
        critical=False
    )


    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ski_value,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )


    certificate = builder.sign(
        private_key=private_key,
        algorithm=hash_algorithm,
        backend=default_backend()
    )

    return certificate


def get_certificate_info(cert: x509.Certificate) -> dict:
    """
    Extract information from a certificate for display/logging.
    """
    # Determine key type and size
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = "ECC"
        key_size = public_key.curve.key_size
    else:
        key_type = "Unknown"
        key_size = 0

    # Use UTC-aware datetime methods
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': format(cert.serial_number, 'X'),
        'not_valid_before': cert.not_valid_before_utc.isoformat(),
        'not_valid_after': cert.not_valid_after_utc.isoformat(),
        'key_type': key_type,
        'key_size': key_size,
        'signature_algorithm': cert.signature_algorithm_oid._name,
    }