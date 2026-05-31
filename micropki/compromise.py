import hashlib
from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def public_key_hash(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def certificate_public_key_hash(cert: x509.Certificate) -> str:
    return public_key_hash(cert.public_key())


def csr_public_key_hash(csr: x509.CertificateSigningRequest) -> str:
    return public_key_hash(csr.public_key())