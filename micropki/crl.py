from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timedelta, timezone
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .revocation import RevocationReason, reason_to_x509_flag, parse_revocation_reason
from .crypto_utils import load_certificate, load_encrypted_private_key, compute_ski


class CRLManager:

    def __init__(self, out_dir: Path, logger: Optional[logging.Logger] = None):
        self.out_dir = Path(out_dir)
        self.crl_dir = self.out_dir / 'crl'
        self.crl_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger or logging.getLogger('micropki.crl')

    def _get_crl_number_path(self, ca_name: str) -> Path:
        return self.crl_dir / f'{ca_name}_crl_number.txt'

    def _read_crl_number(self, ca_name: str) -> int:
        path = self._get_crl_number_path(ca_name)
        if not path.exists():
            return 1
        try:
            return int(path.read_text().strip())
        except (ValueError, IOError):
            return 1

    def _write_crl_number(self, ca_name: str, crl_number: int) -> None:
        path = self._get_crl_number_path(ca_name)
        path.write_text(str(crl_number))

    def generate_crl(
        self,
        ca_cert: x509.Certificate,
        ca_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        revoked_certs: List[Dict[str, Any]],
        ca_name: str,
        next_update_days: int = 7
    ) -> x509.CertificateRevocationList:

        self.logger.info(f"Generating CRL for {ca_name} CA, {len(revoked_certs)} revoked cert(s)")

        current_crl_number = self._read_crl_number(ca_name)
        this_update = datetime.now(timezone.utc)
        next_update = this_update + timedelta(days=next_update_days)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(this_update)
        builder = builder.next_update(next_update)

        for cert_data in revoked_certs:
            serial_int = int(cert_data['serial_hex'], 16)

            rev_date_str = cert_data.get('revocation_date')
            if rev_date_str:
                rev_date = datetime.fromisoformat(rev_date_str)
                if rev_date.tzinfo is None:
                    rev_date = rev_date.replace(tzinfo=timezone.utc)
            else:
                rev_date = this_update

            revoked_builder = x509.RevokedCertificateBuilder()
            revoked_builder = revoked_builder.serial_number(serial_int)
            revoked_builder = revoked_builder.revocation_date(rev_date)

            reason_str = cert_data.get('revocation_reason')
            if reason_str and reason_str != 'unspecified':
                try:
                    reason_enum = parse_revocation_reason(reason_str)
                    reason_flag = reason_to_x509_flag(reason_enum)
                    revoked_builder = revoked_builder.add_extension(
                        x509.CRLReason(reason_flag), critical=False
                    )
                except Exception:
                    pass

            builder = builder.add_revoked_certificate(revoked_builder.build())

        try:
            aki_ext = ca_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            key_id = aki_ext.value.key_identifier
        except x509.ExtensionNotFound:
            key_id = compute_ski(ca_cert.public_key())

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(key_id, None, None), critical=False
        )
        builder = builder.add_extension(
            x509.CRLNumber(current_crl_number), critical=False
        )

        if isinstance(ca_key, rsa.RSAPrivateKey):
            hash_alg = hashes.SHA256()
        elif isinstance(ca_key, ec.EllipticCurvePrivateKey):
            hash_alg = hashes.SHA384() if ca_key.curve.name == 'secp384r1' else hashes.SHA256()
        else:
            hash_alg = hashes.SHA256()

        crl = builder.sign(ca_key, hash_alg, default_backend())

        self.logger.info(f"CRL #{current_crl_number} generated, next update: {next_update.date()}")
        self._write_crl_number(ca_name, current_crl_number + 1)

        return crl

    def save_crl(self, crl: x509.CertificateRevocationList, ca_name: str,
                 out_file: Optional[Path] = None) -> Path:
        if out_file is None:
            out_file = self.crl_dir / f'{ca_name}.crl.pem'
        else:
            out_file = Path(out_file)

        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        self.logger.info(f"CRL saved: {out_file}")
        return out_file

    def generate_and_save_crl(
        self,
        ca_cert_path: Path,
        ca_key_path: Path,
        ca_passphrase: bytes,
        revoked_certs: List[Dict[str, Any]],
        ca_name: str,
        next_update_days: int = 7,
        out_file: Optional[Path] = None
    ) -> Path:
        ca_cert = load_certificate(ca_cert_path)
        ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

        crl = self.generate_crl(ca_cert, ca_key, revoked_certs, ca_name, next_update_days)
        return self.save_crl(crl, ca_name, out_file)


def load_crl(crl_path: Path) -> x509.CertificateRevocationList:
    return x509.load_pem_x509_crl(Path(crl_path).read_bytes(), default_backend())