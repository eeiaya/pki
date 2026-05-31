import csv
import json
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple


ZERO_HASH = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parse_iso(ts: str) -> datetime:
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _compute_entry_hash(entry: dict) -> str:
    tmp = deepcopy(entry)
    if "integrity" not in tmp:
        tmp["integrity"] = {}
    tmp["integrity"].pop("hash", None)
    payload = _canonical_json(tmp).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class AuditVerifyResult:
    ok: bool
    first_bad_line: Optional[int] = None
    message: str = ""


class AuditLogger:
    def __init__(self, out_dir: Path):
        self.out_dir = Path(out_dir)
        self.audit_dir = self.out_dir / "audit"
        self.log_file = self.audit_dir / "audit.log"
        self.chain_file = self.audit_dir / "chain.dat"

        self.audit_dir.mkdir(parents=True, exist_ok=True)

    def _read_last_hash(self) -> str:
        if self.chain_file.exists():
            value = self.chain_file.read_text(encoding="utf-8").strip()
            if value:
                return value
        return ZERO_HASH

    def _write_last_hash(self, value: str) -> None:
        self.chain_file.write_text(value + "\n", encoding="utf-8")

    def write(
        self,
        level: str,
        operation: str,
        status: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> dict:
        metadata = metadata or {}

        prev_hash = self._read_last_hash()

        entry = {
            "timestamp": _utc_now_iso(),
            "level": level,
            "operation": operation,
            "status": status,
            "message": message,
            "metadata": metadata,
            "integrity": {
                "prev_hash": prev_hash,
            },
        }

        entry_hash = _compute_entry_hash(entry)
        entry["integrity"]["hash"] = entry_hash

        line = _canonical_json(entry)

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        self._write_last_hash(entry_hash)
        return entry

    def audit(self, operation: str, status: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> dict:
        return self.write("AUDIT", operation, status, message, metadata)

    def info(self, operation: str, status: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> dict:
        return self.write("INFO", operation, status, message, metadata)

    def error(self, operation: str, status: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> dict:
        return self.write("ERROR", operation, status, message, metadata)


def verify_audit_log(log_file: Path, chain_file: Optional[Path] = None) -> AuditVerifyResult:
    log_file = Path(log_file)
    if chain_file is not None:
        chain_file = Path(chain_file)

    if not log_file.exists():
        return AuditVerifyResult(False, None, f"Audit log not found: {log_file}")

    prev_hash = ZERO_HASH
    last_hash = ZERO_HASH

    with open(log_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                return AuditVerifyResult(False, idx, f"Invalid JSON at line {idx}: {e}")

            integrity = entry.get("integrity", {})
            stored_prev = integrity.get("prev_hash")
            stored_hash = integrity.get("hash")

            if stored_prev != prev_hash:
                return AuditVerifyResult(
                    False,
                    idx,
                    f"Hash chain broken at line {idx}: expected prev_hash={prev_hash}, got {stored_prev}"
                )

            recalculated = _compute_entry_hash(entry)
            if stored_hash != recalculated:
                return AuditVerifyResult(
                    False,
                    idx,
                    f"Entry hash mismatch at line {idx}: expected {recalculated}, got {stored_hash}"
                )

            prev_hash = stored_hash
            last_hash = stored_hash

    if chain_file is not None and chain_file.exists():
        stored_chain_hash = chain_file.read_text(encoding="utf-8").strip()
        if stored_chain_hash and stored_chain_hash != last_hash:
            return AuditVerifyResult(
                False,
                None,
                f"chain.dat mismatch: expected {last_hash}, got {stored_chain_hash}"
            )

    return AuditVerifyResult(True, None, "Audit log integrity verified")


def load_audit_entries(log_file: Path) -> List[dict]:
    log_file = Path(log_file)
    if not log_file.exists():
        return []

    entries = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def query_audit_entries(
    log_file: Path,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    level: Optional[str] = None,
    operation: Optional[str] = None,
    serial: Optional[str] = None,
) -> List[dict]:
    entries = load_audit_entries(log_file)

    dt_from = _parse_iso(from_ts) if from_ts else None
    dt_to = _parse_iso(to_ts) if to_ts else None
    level = level.upper() if level else None
    operation = operation.lower() if operation else None
    serial = serial.upper() if serial else None

    result = []

    for entry in entries:
        ts = _parse_iso(entry["timestamp"])
        if dt_from and ts < dt_from:
            continue
        if dt_to and ts > dt_to:
            continue
        if level and entry.get("level", "").upper() != level:
            continue
        if operation and entry.get("operation", "").lower() != operation:
            continue

        if serial:
            metadata = entry.get("metadata", {})
            meta_serials = [
                str(metadata.get("serial", "")).upper(),
                str(metadata.get("certificate_serial", "")).upper(),
            ]
            if serial not in meta_serials:
                continue

        result.append(entry)

    return result


def format_audit_entries_table(entries: List[dict]) -> str:
    if not entries:
        return "No audit records found."

    lines = []
    lines.append("=" * 140)
    lines.append(f"{'Timestamp':<30} {'Level':<8} {'Operation':<24} {'Status':<10} {'Serial':<20} Message")
    lines.append("-" * 140)

    for e in entries:
        meta = e.get("metadata", {})
        serial = meta.get("serial") or meta.get("certificate_serial") or ""
        lines.append(
            f"{e.get('timestamp',''):<30} "
            f"{e.get('level',''):<8} "
            f"{e.get('operation',''):<24} "
            f"{e.get('status',''):<10} "
            f"{str(serial):<20} "
            f"{e.get('message','')}"
        )

    lines.append("=" * 140)
    return "\n".join(lines)


def format_audit_entries_csv(entries: List[dict]) -> str:
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "level", "operation", "status", "serial", "message"])

    for e in entries:
        meta = e.get("metadata", {})
        serial = meta.get("serial") or meta.get("certificate_serial") or ""
        writer.writerow([
            e.get("timestamp", ""),
            e.get("level", ""),
            e.get("operation", ""),
            e.get("status", ""),
            serial,
            e.get("message", ""),
        ])

    return buf.getvalue().strip()