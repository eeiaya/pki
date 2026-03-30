
import secrets
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Union, Optional, List

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .crypto_utils import compute_ski
from .serial import generate_serial_number  # Импортируем из serial.py


def parse_subject_dn(dn_string: str) -> x509.Name:

    if not dn_string or not dn_string.strip():
        raise ValueError("DN string cannot be empty")

    dn_string = dn_string.strip()

    if dn_string.startswith('/'):
        parts = [p for p in dn_string.split('/') if p]
    else:
        parts = [p.strip() for p in dn_string.split(',')]

    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'EMAIL': NameOID.EMAIL_ADDRESS,
    }

    attributes = []
    for part in parts:
        if '=' not in part:
            raise ValueError(f"Invalid DN component: '{part}'. Expected KEY=VALUE")

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


def parse_san_entries(san_strings: List[str]) -> x509.SubjectAlternativeName:

    names = []

    for entry in san_strings:
        if ':' not in entry:
            raise ValueError(f"Invalid SAN: '{entry}'. Use format type:value")

        san_type, san_value = entry.split(':', 1)
        san_type = san_type.lower().strip()
        san_value = san_value.strip()

        if san_type == 'dns':
            names.append(x509.DNSName(san_value))
        elif san_type == 'ip':
            try:
                ip = ipaddress.ip_address(san_value)
            except ValueError:
                raise ValueError(f"Invalid IP address in SAN: {san_value}")
            names.append(x509.IPAddress(ip))
        elif san_type == 'email':
            names.append(x509.RFC822Name(san_value))
        elif san_type == 'uri':
            names.append(x509.UniformResourceIdentifier(san_value))
        else:
            raise ValueError(f"Unknown SAN type: '{san_type}'. Use: dns, ip, email, uri")

    if not names:
        raise ValueError("No SAN entries provided")

    return x509.SubjectAlternativeName(names)


def _get_hash_algorithm(signing_key):

    if isinstance(signing_key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    elif isinstance(signing_key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384()
    else:
        raise ValueError("Unsupported key type")


def create_self_signed_certificate(
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    subject: x509.Name,
    validity_days: int
) -> x509.Certificate:

    hash_algorithm = _get_hash_algorithm(private_key)
    serial = generate_serial_number()
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    public_key = private_key.public_key()
    ski_value = compute_ski(public_key)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)

    # Basic Constraints: CA=TRUE, critical
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )

    # Key Usage: keyCertSign, cRLSign, digitalSignature
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

    # SKI
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(ski_value),
        critical=False
    )

    # AKI = SKI для самоподписанного
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ski_value,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )

    certificate = builder.sign(private_key, hash_algorithm, default_backend())
    return certificate


def create_intermediate_certificate(
    csr: x509.CertificateSigningRequest,
    root_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    root_cert: x509.Certificate,
    validity_days: int,
    path_length: int = 0
) -> x509.Certificate:

    hash_algorithm = _get_hash_algorithm(root_key)
    serial = generate_serial_number()
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    intermediate_ski = compute_ski(csr.public_key())
    root_ski = root_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
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
        x509.SubjectKeyIdentifier(intermediate_ski),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=root_ski,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )

    certificate = builder.sign(root_key, hash_algorithm, default_backend())
    return certificate


def create_leaf_certificate(
    subject: x509.Name,
    public_key,
    ca_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    ca_cert: x509.Certificate,
    template_name: str,
    validity_days: int,
    san_extension: Optional[x509.SubjectAlternativeName] = None
) -> x509.Certificate:

    from .templates import get_template

    template = get_template(template_name)
    hash_algorithm = _get_hash_algorithm(ca_key)
    serial = generate_serial_number()
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    leaf_ski = compute_ski(public_key)
    ca_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )

    is_rsa = isinstance(public_key, rsa.RSAPublicKey)
    use_key_encipherment = template.key_encipherment and is_rsa

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=template.digital_signature,
            key_encipherment=use_key_encipherment,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=template.key_agreement,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    eku_map = {
        "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
        "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
        "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    }
    eku_oids = [eku_map[usage] for usage in template.extended_key_usages]
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(eku_oids),
        critical=False
    )

    if san_extension:
        builder = builder.add_extension(san_extension, critical=False)

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(leaf_ski),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )

    certificate = builder.sign(ca_key, hash_algorithm, default_backend())
    return certificate


def get_certificate_info(cert: x509.Certificate) -> dict:

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


def get_cn_from_subject(subject: x509.Name) -> str:

    for attr in subject:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value
    return "unknown"