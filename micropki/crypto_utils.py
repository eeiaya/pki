"""
Cryptographic utility functions.
"""

import os
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def generate_rsa_key_pair(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """Генерирует RSA ключи."""
    if key_size not in (2048, 4096):
        raise ValueError(f"RSA key size must be 2048 or 4096, got {key_size}")

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ecc_key_pair(curve_size: int = 384) -> ec.EllipticCurvePrivateKey:
    """Генерирует ECC ключи."""
    curves = {
        256: ec.SECP256R1(),
        384: ec.SECP384R1(),
    }
    if curve_size not in curves:
        raise ValueError(f"ECC curve size must be 256 or 384, got {curve_size}")

    return ec.generate_private_key(
        curve=curves[curve_size],
        backend=default_backend()
    )


def save_encrypted_private_key(
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    path: Path,
    passphrase: bytes
) -> None:
    """Сохраняет приватный ключ в зашифрованном виде (PKCS#8 + AES-256)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

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


def save_unencrypted_private_key(
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    path: Path
) -> None:
    """Сохраняет приватный ключ БЕЗ шифрования (для конечных сертификатов)."""
    path.parent.mkdir(parents=True, exist_ok=True)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
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
    """Загружает зашифрованный приватный ключ."""
    with open(path, 'rb') as f:
        pem_data = f.read()

    return serialization.load_pem_private_key(
        pem_data,
        password=passphrase,
        backend=default_backend()
    )


def save_certificate(certificate: x509.Certificate, path: Path) -> None:
    """Сохраняет сертификат в PEM формате."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    with open(path, 'wb') as f:
        f.write(pem)


def load_certificate(path: Path) -> x509.Certificate:
    """Загружает сертификат из PEM файла."""
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data, default_backend())


def compute_ski(public_key) -> bytes:
    """Вычисляет Subject Key Identifier (SHA-1 хеш публичного ключа)."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_bytes)
    return digest.finalize()


def read_passphrase_file(path: Path) -> bytes:
    """Читает пароль из файла, убирая перенос строки."""
    with open(path, 'rb') as f:
        passphrase = f.read()

    if passphrase.endswith(b'\n'):
        passphrase = passphrase[:-1]
    if passphrase.endswith(b'\r'):
        passphrase = passphrase[:-1]

    return passphrase