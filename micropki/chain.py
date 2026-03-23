
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from .crypto_utils import load_certificate


def verify_certificate_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:

    issuer_public_key = issuer_cert.public_key()

    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except InvalidSignature:
        return False


def verify_validity(cert: x509.Certificate) -> bool:

    now = datetime.now(timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def verify_basic_constraints(cert: x509.Certificate, expect_ca: bool) -> bool:

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bc.value.ca == expect_ca
    except x509.ExtensionNotFound:
        # Если нет расширения и мы ожидаем не-CA, это допустимо
        return not expect_ca


def verify_chain(
        leaf_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate
) -> List[str]:

    errors = []

    # 1. Проверяем корневой CA (самоподписанный)
    if not verify_certificate_signature(root_cert, root_cert):
        errors.append("Root CA: self-signature verification failed")

    if not verify_validity(root_cert):
        errors.append("Root CA: certificate has expired or is not yet valid")

    if not verify_basic_constraints(root_cert, expect_ca=True):
        errors.append("Root CA: BasicConstraints CA flag is not TRUE")

    # 2. Проверяем промежуточный CA
    if not verify_certificate_signature(intermediate_cert, root_cert):
        errors.append("Intermediate CA: signature verification failed (not signed by root)")

    if not verify_validity(intermediate_cert):
        errors.append("Intermediate CA: certificate has expired or is not yet valid")

    if not verify_basic_constraints(intermediate_cert, expect_ca=True):
        errors.append("Intermediate CA: BasicConstraints CA flag is not TRUE")

    # 3. Проверяем конечный сертификат
    if not verify_certificate_signature(leaf_cert, intermediate_cert):
        errors.append("Leaf certificate: signature verification failed (not signed by intermediate)")

    if not verify_validity(leaf_cert):
        errors.append("Leaf certificate: has expired or is not yet valid")

    if not verify_basic_constraints(leaf_cert, expect_ca=False):
        errors.append("Leaf certificate: BasicConstraints CA flag should be FALSE")

    # 4. Проверяем что issuer совпадает с subject
    if leaf_cert.issuer != intermediate_cert.subject:
        errors.append("Leaf certificate: issuer does not match intermediate CA subject")

    if intermediate_cert.issuer != root_cert.subject:
        errors.append("Intermediate CA: issuer does not match root CA subject")

    return errors