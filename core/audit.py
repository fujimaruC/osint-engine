"""
core/audit.py
Tamper-evident audit log — wajib untuk distribusi profesional.
Setiap scan tercatat: siapa, kapan, target apa, hasil berapa event.
"""

import json
import hashlib
import os
import socket
import getpass
from datetime import datetime, timezone
from pathlib import Path

AUDIT_FILE = Path(__file__).parent.parent / "audit.log"


def _prev_hash() -> str:
    """Baca hash entry terakhir untuk chaining (tamper-evident)."""
    if not AUDIT_FILE.exists():
        return "GENESIS"
    lines = AUDIT_FILE.read_text().strip().splitlines()
    for line in reversed(lines):
        try:
            entry = json.loads(line)
            if "hash" in entry:
                return entry["hash"]
        except Exception:
            continue
    return "GENESIS"


def _make_hash(entry: dict) -> str:
    payload = json.dumps(entry, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def log_scan_start(target: str, profile: str, scan_id: str, target_type: str):
    """Catat awal scan."""
    prev = _prev_hash()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "SCAN_START",
        "operator": getpass.getuser(),
        "hostname": socket.gethostname(),
        "target": target,
        "target_type": target_type,
        "profile": profile,
        "scan_id": scan_id,
        "prev_hash": prev,
    }
    entry["hash"] = _make_hash(entry)
    _write(entry)


def log_scan_end(scan_id: str, total_events: int, status: str, exports: list[str]):
    """Catat akhir scan."""
    prev = _prev_hash()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "SCAN_END",
        "operator": getpass.getuser(),
        "scan_id": scan_id,
        "total_events": total_events,
        "status": status,
        "exports": exports,
        "prev_hash": prev,
    }
    entry["hash"] = _make_hash(entry)
    _write(entry)


def log_disclaimer_accepted(operator: str):
    """Catat penerimaan disclaimer."""
    prev = _prev_hash()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "DISCLAIMER_ACCEPTED",
        "operator": operator,
        "hostname": socket.gethostname(),
        "prev_hash": prev,
    }
    entry["hash"] = _make_hash(entry)
    _write(entry)


def verify_chain() -> tuple[bool, list[str]]:
    """
    Verifikasi integritas audit log.
    Returns (is_valid, list_of_issues).
    """
    if not AUDIT_FILE.exists():
        return True, []

    issues = []
    lines = AUDIT_FILE.read_text().strip().splitlines()
    prev_hash = "GENESIS"

    for i, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
            stored_hash = entry.pop("hash", None)
            if entry.get("prev_hash") != prev_hash:
                issues.append(f"Line {i}: chain break detected (possible tampering)")
            recomputed = _make_hash(entry)
            if recomputed != stored_hash:
                issues.append(f"Line {i}: hash mismatch (entry may be altered)")
            entry["hash"] = stored_hash
            prev_hash = stored_hash
        except json.JSONDecodeError:
            issues.append(f"Line {i}: invalid JSON")

    return len(issues) == 0, issues


def print_log(last_n: int = 20) -> list[dict]:
    """Baca N entry terakhir dari audit log."""
    if not AUDIT_FILE.exists():
        return []
    lines = AUDIT_FILE.read_text().strip().splitlines()
    entries = []
    for line in lines[-last_n:]:
        try:
            entries.append(json.loads(line))
        except Exception:
            pass
    return entries


def _write(entry: dict):
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    # Read-only setelah tulis (Unix)
    try:
        os.chmod(AUDIT_FILE, 0o444)
        os.chmod(AUDIT_FILE, 0o644)  # buka lagi untuk append berikutnya
    except Exception:
        pass
