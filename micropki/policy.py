from dataclasses import dataclass
from typing import Optional, List
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec


ROOT_MAX_VALIDITY_DAYS = 3650
INTERMEDIATE_MAX_VALIDITY_DAYS = 1825
END_ENTITY_MAX_VALIDITY_DAYS = 365


class PolicyViolation(ValueError):
    pass


def _normalize_template(template_name: str) -> str:
    return (template_name or "").strip().lower()


def _normalize_entity_type(entity_type: str) -> str:
    return (entity_type or "").strip().lower()


def _san_to_string(name) -> str:
    if isinstance(name, x509.DNSName):
        return f"dns:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"ip:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"uri:{name.value}"
    return str(name)


def get_public_key_hashable_info(public_key) -> tuple[str, int]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ecc", public_key.curve.key_size
    raise PolicyViolation("Unsupported public key type")


def validate_key_policy(public_key, entity_type: str) -> None:
    entity_type = _normalize_entity_type(entity_type)
    key_type, size = get_public_key_hashable_info(public_key)

    if key_type == "rsa":
        if entity_type == "root_ca" and size < 4096:
            raise PolicyViolation("Root CA requires RSA key size >= 4096")
        if entity_type == "intermediate_ca" and size < 3072:
            raise PolicyViolation("Intermediate CA requires RSA key size >= 3072")
        if entity_type == "end_entity" and size < 2048:
            raise PolicyViolation("End-entity certificates require RSA key size >= 2048")
        if size < 2048:
            raise PolicyViolation("RSA key size must be >= 2048")

    elif key_type == "ecc":
        if entity_type in ("root_ca", "intermediate_ca") and size < 384:
            raise PolicyViolation("Root/Intermediate CA require ECC key size >= 384 (P-384)")
        if entity_type == "end_entity" and size < 256:
            raise PolicyViolation("End-entity certificates require ECC key size >= 256 (P-256)")
        if size < 256:
            raise PolicyViolation("ECC key size must be >= 256")


def validate_generated_key_params(key_type: str, key_size: int, entity_type: str) -> None:
    key_type = (key_type or "").lower()
    entity_type = _normalize_entity_type(entity_type)

    if key_type == "rsa":
        if entity_type == "root_ca" and key_size < 4096:
            raise PolicyViolation("Root CA requires RSA key size >= 4096")
        if entity_type == "intermediate_ca" and key_size < 3072:
            raise PolicyViolation("Intermediate CA requires RSA key size >= 3072")
        if entity_type == "end_entity" and key_size < 2048:
            raise PolicyViolation("End-entity certificates require RSA key size >= 2048")
        if key_size < 2048:
            raise PolicyViolation("RSA key size must be >= 2048")

    elif key_type == "ecc":
        if entity_type in ("root_ca", "intermediate_ca") and key_size < 384:
            raise PolicyViolation("Root/Intermediate CA require ECC key size >= 384 (P-384)")
        if entity_type == "end_entity" and key_size < 256:
            raise PolicyViolation("End-entity certificates require ECC key size >= 256 (P-256)")
        if key_size < 256:
            raise PolicyViolation("ECC key size must be >= 256")
    else:
        raise PolicyViolation(f"Unsupported key type: {key_type}")


def validate_validity_policy(validity_days: int, entity_type: str) -> None:
    entity_type = _normalize_entity_type(entity_type)

    if entity_type == "root_ca" and validity_days > ROOT_MAX_VALIDITY_DAYS:
        raise PolicyViolation(f"Root CA validity cannot exceed {ROOT_MAX_VALIDITY_DAYS} days")
    if entity_type == "intermediate_ca" and validity_days > INTERMEDIATE_MAX_VALIDITY_DAYS:
        raise PolicyViolation(f"Intermediate CA validity cannot exceed {INTERMEDIATE_MAX_VALIDITY_DAYS} days")
    if entity_type == "end_entity" and validity_days > END_ENTITY_MAX_VALIDITY_DAYS:
        raise PolicyViolation(f"End-entity certificate validity cannot exceed {END_ENTITY_MAX_VALIDITY_DAYS} days")


def _san_type(entry: str) -> str:
    if ":" not in entry:
        raise PolicyViolation(f"Invalid SAN format: {entry}")
    return entry.split(":", 1)[0].strip().lower()


def _san_value(entry: str) -> str:
    return entry.split(":", 1)[1].strip()


def validate_san_policy(template_name: str, san_entries: List[str]) -> None:
    template_name = _normalize_template(template_name)
    san_entries = san_entries or []

    if template_name == "server":
        if not san_entries:
            raise PolicyViolation("Server certificate requires at least one SAN")
        for entry in san_entries:
            san_type = _san_type(entry)
            san_value = _san_value(entry)

            if san_type not in ("dns", "ip"):
                raise PolicyViolation("Server certificates allow only dns and ip SAN")
            if san_type == "dns" and "*" in san_value:
                raise PolicyViolation("Wildcard SAN entries are forbidden by default")

    elif template_name == "client":
        if not san_entries:
            raise PolicyViolation("Client certificate requires at least one email SAN")
        has_email = False
        for entry in san_entries:
            san_type = _san_type(entry)
            if san_type not in ("email", "dns"):
                raise PolicyViolation("Client certificates allow only email and dns SAN")
            if san_type == "email":
                has_email = True
        if not has_email:
            raise PolicyViolation("Client certificate requires at least one email SAN")

    elif template_name == "code_signing":
        for entry in san_entries:
            san_type = _san_type(entry)
            if san_type not in ("dns", "uri"):
                raise PolicyViolation("Code-signing certificates allow only dns and uri SAN")

    elif template_name == "ocsp":
        for entry in san_entries:
            san_type = _san_type(entry)
            if san_type not in ("dns", "uri"):
                raise PolicyViolation("OCSP certificates allow only dns and uri SAN")


def validate_signature_algorithm_policy(public_key, signature_hash_algorithm) -> None:
    if signature_hash_algorithm is None:
        raise PolicyViolation("Missing signature hash algorithm")

    hash_name = signature_hash_algorithm.name.lower()

    if hash_name == "sha1":
        raise PolicyViolation("SHA-1 is forbidden")

    if isinstance(public_key, rsa.RSAPublicKey):
        if hash_name not in ("sha256", "sha384", "sha512"):
            raise PolicyViolation("RSA CSR must use SHA-256 or stronger")

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_size = public_key.curve.key_size
        if curve_size == 256 and hash_name != "sha256":
            raise PolicyViolation("ECC P-256 CSR must use SHA-256")
        if curve_size == 384 and hash_name != "sha384":
            raise PolicyViolation("ECC P-384 CSR must use SHA-384")


def extract_san_entries_from_csr(csr: x509.CertificateSigningRequest) -> List[str]:
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return [_san_to_string(name) for name in san]
    except x509.ExtensionNotFound:
        return []


def validate_csr_policy(
    csr: x509.CertificateSigningRequest,
    template_name: str,
    entity_type: str = "end_entity"
) -> List[str]:
    public_key = csr.public_key()

    validate_key_policy(public_key, entity_type)
    validate_signature_algorithm_policy(public_key, csr.signature_hash_algorithm)

    if entity_type == "end_entity":
        try:
            bc = csr.extensions.get_extension_for_class(x509.BasicConstraints).value
            if bc.ca:
                raise PolicyViolation("CSR requests CA=True, which is forbidden for end-entity certificates")
        except x509.ExtensionNotFound:
            pass

    san_entries = extract_san_entries_from_csr(csr)
    validate_san_policy(template_name, san_entries)

    return san_entries


def validate_intermediate_policy(path_length: int) -> None:
    if path_length != 0:
        raise PolicyViolation("Intermediate CA must use pathLen = 0")