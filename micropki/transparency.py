import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


class CTLog:
    def __init__(self, out_dir: Path):
        self.out_dir = Path(out_dir)
        self.audit_dir = self.out_dir / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.ct_log = self.audit_dir / "ct.log"

    def append(self, cert: x509.Certificate) -> str:
        serial = format(cert.serial_number, "X")
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        fp = _cert_fingerprint_sha256(cert)

        line = f"{_utc_now_iso()}\t{serial}\t{subject}\t{fp}\t{issuer}"

        with open(self.ct_log, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        try:
            self.ct_log.chmod(0o644)
        except Exception:
            pass

        return line

    def contains_serial(self, serial_hex: str) -> bool:
        serial_hex = serial_hex.upper()
        if not self.ct_log.exists():
            return False

        with open(self.ct_log, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2 and parts[1].upper() == serial_hex:
                    return True
        return False