
from typing import Union, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .certificates import parse_subject_dn


def create_csr(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        subject: x509.Name,
        is_ca: bool = False,
        path_length: Optional[int] = None
) -> x509.CertificateSigningRequest:

    if isinstance(private_key, rsa.RSAPrivateKey):
        hash_algo = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        hash_algo = hashes.SHA384()
    else:
        raise ValueError("Unsupported key type")

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)


    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True
        )

    csr = builder.sign(private_key, hash_algo, default_backend())
    return csr


def verify_csr(csr: x509.CertificateSigningRequest) -> bool:

    return csr.is_signature_valid


def save_csr(csr: x509.CertificateSigningRequest, path) -> None:

    from pathlib import Path
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = csr.public_bytes(encoding=serialization.Encoding.PEM)
    with open(path, 'wb') as f:
        f.write(pem_data)


def load_csr(path) -> x509.CertificateSigningRequest:

    from pathlib import Path
    with open(Path(path), 'rb') as f:
        pem_data = f.read()

    return x509.load_pem_x509_csr(pem_data, default_backend())



from cryptography.hazmat.primitives import serialization