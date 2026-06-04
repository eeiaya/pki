from pathlib import Path
from typing import Optional, List
from datetime import datetime, timezone
import logging
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .crypto_utils import (
    generate_rsa_key_pair,
    generate_ecc_key_pair,
    save_unencrypted_private_key,
    load_certificate,
)
from .certificates import parse_subject_dn, parse_san_entries
from .csr import create_csr, save_csr, load_csr
from .validation import validate_chain, ValidationResult
from .revocation_check import (
    check_revocation,
    check_crl,
    check_ocsp,
    extract_ocsp_url,
    extract_crl_urls,
    RevocationResult,
)


def client_gen_csr(
    subject_dn: str,
    key_type: str,
    key_size: int,
    san_entries: List[str],
    out_key: Path,
    out_csr: Path,
    logger: Optional[logging.Logger] = None
) -> None:
    log = logger or logging.getLogger('micropki.client')

    log.info(f"Generating {key_type.upper()}-{key_size} key pair...")
    if key_type == 'rsa':
        key = generate_rsa_key_pair(key_size)
    else:
        key = generate_ecc_key_pair(key_size)

    subject = parse_subject_dn(subject_dn)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    if san_entries:
        san_ext = parse_san_entries(san_entries)
        builder = builder.add_extension(san_ext, critical=False)

    if isinstance(key, rsa.RSAPrivateKey):
        hash_algo = hashes.SHA256()
    else:
        hash_algo = hashes.SHA384()

    csr = builder.sign(key, hash_algo, default_backend())

    # Сохраняем ключ
    out_key = Path(out_key)
    out_key.parent.mkdir(parents=True, exist_ok=True)
    save_unencrypted_private_key(key, out_key)
    log.warning(f"Private key saved WITHOUT encryption: {out_key}")
    log.warning("Protect this file with filesystem permissions (0o600)")

    # Сохраняем CSR
    out_csr = Path(out_csr)
    out_csr.parent.mkdir(parents=True, exist_ok=True)
    out_csr.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    log.info(f"CSR saved: {out_csr}")
    log.info(f"Subject: {subject.rfc4514_string()}")
    if san_entries:
        log.info(f"SAN: {san_entries}")


def client_request_cert(
    csr_path: Path,
    template: str,
    ca_url: str,
    out_cert: Path,
    api_key: str = "changeme",
    logger: Optional[logging.Logger] = None
) -> None:
    import requests

    log = logger or logging.getLogger('micropki.client')

    csr_path = Path(csr_path)
    if not csr_path.exists():
        raise ValueError(f"CSR file not found: {csr_path}")

    csr_data = csr_path.read_bytes()

    url = ca_url.rstrip('/') + f'/request-cert?template={template}'
    log.info(f"Sending CSR to {url}")

    try:
        response = requests.post(
            url,
            data=csr_data,
            headers={
                "Content-Type": "application/x-pem-file",
                "X-API-Key": api_key
            },
            timeout=30
        )
    except requests.exceptions.ConnectionError as e:
        raise ValueError(f"Cannot connect to CA: {e}")
    except requests.exceptions.Timeout:
        raise ValueError(f"Request to CA timed out")

    if response.status_code == 201:
        out_cert = Path(out_cert)
        out_cert.parent.mkdir(parents=True, exist_ok=True)
        out_cert.write_bytes(response.content)
        serial = response.headers.get('X-Certificate-Serial', 'unknown')
        log.info(f"Certificate issued: serial={serial}")
        log.info(f"Saved to: {out_cert}")
    elif response.status_code == 401:
        raise ValueError("Authentication failed: invalid X-API-Key")
    elif response.status_code == 400:
        try:
            err = response.json().get('detail', response.text)
        except Exception:
            err = response.text
        raise ValueError(f"CA rejected CSR: {err}")
    else:
        try:
            err = response.json().get('detail', response.text)
        except Exception:
            err = response.text
        raise ValueError(f"HTTP {response.status_code}: {err}")


def client_validate(
    cert_path: Path,
    trusted_paths: List[Path],
    untrusted_paths: List[Path],
    crl_source: Optional[str] = None,
    use_ocsp: bool = False,
    mode: str = 'full',
    validation_time: Optional[datetime] = None,
    check_eku: Optional[str] = None,
    logger: Optional[logging.Logger] = None
) -> dict:
    log = logger or logging.getLogger('micropki.client')

    cert = load_certificate(Path(cert_path))
    trusted = [load_certificate(Path(p)) for p in trusted_paths]
    untrusted = [load_certificate(Path(p)) for p in untrusted_paths]

    log.info(f"Validating: {cert.subject.rfc4514_string()}")
    log.info(f"Trusted roots: {len(trusted)}")
    log.info(f"Untrusted intermediates: {len(untrusted)}")

    # Шаг 1: проверка цепочки
    result = validate_chain(
        leaf_cert=cert,
        untrusted_certs=untrusted,
        trusted_certs=trusted,
        validation_time=validation_time,
        check_eku=check_eku
    )

    output = result.to_dict()
    output['revocation'] = None

    if not result.success:
        log.error(f"Chain validation failed: {result.error}")
        return output

    log.info("Chain validation: PASSED")

    # Шаг 2: проверка отзыва (только в режиме full)
    if mode == 'full' and (use_ocsp or crl_source):
        if len(result.chain) < 2:
            log.warning("Cannot check revocation: no issuer in chain")
        else:
            issuer = result.chain[1]  # следующий после leaf

            ocsp_url = None
            if use_ocsp:
                ocsp_url = extract_ocsp_url(cert)
                if ocsp_url is None:
                    log.warning("OCSP requested but no AIA extension in cert")

            rev_result = check_revocation(
                cert=cert,
                issuer_cert=issuer,
                ocsp_url=ocsp_url,
                crl_source=crl_source,
                prefer_ocsp=use_ocsp,
                logger=log
            )

            output['revocation'] = {
                'status': rev_result.status,
                'method': rev_result.method,
                'message': rev_result.message,
                'revocation_time': rev_result.revocation_time.isoformat() if rev_result.revocation_time else None,
                'revocation_reason': rev_result.revocation_reason,
            }

            if rev_result.status == 'revoked':
                log.error(f"Certificate is REVOKED ({rev_result.method}): {rev_result.message}")
                output['success'] = False
                output['error'] = f"Certificate revoked: {rev_result.message}"
            elif rev_result.status == 'unknown':
                log.warning(f"Revocation status UNKNOWN: {rev_result.message}")
            else:
                log.info(f"Revocation status: GOOD (via {rev_result.method})")

    return output


def client_check_status(
    cert_path: Path,
    ca_cert_path: Path,
    crl_source: Optional[str] = None,
    ocsp_url: Optional[str] = None,
    logger: Optional[logging.Logger] = None
) -> RevocationResult:
    log = logger or logging.getLogger('micropki.client')

    cert = load_certificate(Path(cert_path))
    ca_cert = load_certificate(Path(ca_cert_path))

    log.info(f"Checking status of: {cert.subject.rfc4514_string()}")
    log.info(f"Issuer: {ca_cert.subject.rfc4514_string()}")

    if ocsp_url is None:
        auto_ocsp = extract_ocsp_url(cert)
        if auto_ocsp:
            log.info(f"OCSP URL from AIA: {auto_ocsp}")
            ocsp_url = auto_ocsp

    if crl_source is None:
        auto_crls = extract_crl_urls(cert)
        if auto_crls:
            log.info(f"CRL URL from CDP: {auto_crls[0]}")
            crl_source = auto_crls[0]

    result = check_revocation(
        cert=cert,
        issuer_cert=ca_cert,
        ocsp_url=ocsp_url,
        crl_source=crl_source,
        prefer_ocsp=True,
        logger=log
    )

    return result


def setup_client_logger(log_file: Optional[Path] = None) -> logging.Logger:
    logger = logging.getLogger('micropki.client')
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    else:
        import sys
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

def client_sign_file(
    file_path: Path,
    key_path: Path,
    out_sig: Path,
    logger: Optional[logging.Logger] = None
) -> None:
    log = logger or logging.getLogger('micropki.client')

    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding, ec as _ec, rsa as _rsa

    file_path = Path(file_path)
    if not file_path.exists():
        raise ValueError(f"File to sign not found: {file_path}")

    key_path = Path(key_path)
    if not key_path.exists():
        raise ValueError(f"Private key not found: {key_path}")

    data = file_path.read_bytes()
    private_key = load_pem_private_key(key_path.read_bytes(), password=None)

    if isinstance(private_key, _rsa.RSAPrivateKey):
        signature = private_key.sign(
            data,
            _padding.PKCS1v15(),
            _hashes.SHA256()
        )
    elif isinstance(private_key, _ec.EllipticCurvePrivateKey):
        signature = private_key.sign(data, _ec.ECDSA(_hashes.SHA256()))
    else:
        raise ValueError("Unsupported key type for signing")

    out_sig = Path(out_sig)
    out_sig.parent.mkdir(parents=True, exist_ok=True)
    out_sig.write_bytes(signature)

    log.info(f"Signed: {file_path} -> {out_sig}")
    log.info(f"Signature size: {len(signature)} bytes")


def client_verify_file(
    file_path: Path,
    cert_path: Path,
    sig_path: Path,
    logger: Optional[logging.Logger] = None
) -> bool:
    log = logger or logging.getLogger('micropki.client')

    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding, ec as _ec, rsa as _rsa
    from cryptography.exceptions import InvalidSignature

    file_path = Path(file_path)
    cert_path = Path(cert_path)
    sig_path = Path(sig_path)

    if not file_path.exists():
        raise ValueError(f"File not found: {file_path}")
    if not cert_path.exists():
        raise ValueError(f"Certificate not found: {cert_path}")
    if not sig_path.exists():
        raise ValueError(f"Signature file not found: {sig_path}")

    data = file_path.read_bytes()
    signature = sig_path.read_bytes()
    cert = load_certificate(cert_path)
    public_key = cert.public_key()

    try:
        if isinstance(public_key, _rsa.RSAPublicKey):
            public_key.verify(
                signature,
                data,
                _padding.PKCS1v15(),
                _hashes.SHA256()
            )
        elif isinstance(public_key, _ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, _ec.ECDSA(_hashes.SHA256()))
        else:
            raise ValueError("Unsupported public key type")
        log.info("Signature is VALID")
        return True
    except InvalidSignature:
        log.warning("Signature is INVALID")
        return False