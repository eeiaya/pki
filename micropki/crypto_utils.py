"""
Cryptographic utility functions
"""

import os
from pathlib import Path
from typing import Union, Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def generate_rsa_key_pair(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Generate an RSA key pair.
    """
    if key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    return private_key


def generate_ecc_key_pair(curve_size: int = 384) -> ec.EllipticCurvePrivateKey:
    """
    Generate an ECC key pair.

    """
    if curve_size != 384:
        raise ValueError("ECC curve size must be 384 bits (P-384)")

    private_key = ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )

    return private_key


def save_encrypted_private_key(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        path: Path,
        passphrase: bytes
) -> None:
    """
    Save a private key in encrypted PEM format.
"""
    # Ensure parent directory exists with strict permissions
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Serialize key with encryption
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )


    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)


def load_encrypted_private_key(
        path: Path,
        passphrase: bytes
) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    """
    Load an encrypted private key from PEM file.

    """
    with open(path, 'rb') as f:
        pem_data = f.read()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=passphrase,
        backend=default_backend()
    )

    return private_key


def save_certificate(certificate: x509.Certificate, path: Path) -> None:
    """
    Save a certificate in PEM format.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    with open(path, 'wb') as f:
        f.write(pem)


def load_certificate(path: Path) -> x509.Certificate:
    """
    Load a certificate from PEM file.
    """
    with open(path, 'rb') as f:
        pem_data = f.read()

    cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    return cert


def compute_ski(public_key) -> bytes:
    """
    Compute Subject Key Identifier (SKI) from public key.
    Uses SHA-1 hash of the public key as per RFC 5280.
    """
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_bytes)

    return digest.finalize()


def read_passphrase_file(path: Path) -> bytes:
    """
    Read passphrase from file, stripping trailing newline.
    """
    with open(path, 'rb') as f:
        passphrase = f.read()


    if passphrase.endswith(b'\n'):
        passphrase = passphrase[:-1]
    if passphrase.endswith(b'\r'):
        passphrase = passphrase[:-1]

    return passphrase