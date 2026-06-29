"""
core/scope.py
Scope validator — pastikan target masuk dalam scope yang diizinkan.
Load dari scope.txt, satu entry per baris.
"""

import re
import ipaddress
from pathlib import Path

SCOPE_FILE = Path(__file__).parent.parent / "scope.txt"

SCOPE_TEMPLATE = """# OSINT Engine — Authorized Scope File
# Tambahkan target yang DIIZINKAN untuk di-scan, satu per baris.
# Format yang didukung:
#   domain     : example.com
#   subdomain  : *.example.com
#   IP         : 192.168.1.1
#   CIDR       : 10.0.0.0/8
#   email      : *@example.com
#   wildcard   : * (izinkan semua — HATI-HATI)
#
# Baris diawali # diabaikan (komentar).
#
# Contoh:
# target.mil.id
# *.target.mil.id
# 192.168.100.0/24

"""


def ensure_scope_file():
    """Buat scope.txt template jika belum ada."""
    if not SCOPE_FILE.exists():
        SCOPE_FILE.write_text(SCOPE_TEMPLATE)


def load_scope() -> list[str]:
    """Load scope entries dari scope.txt."""
    ensure_scope_file()
    entries = []
    for line in SCOPE_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def is_in_scope(target: str) -> tuple[bool, str]:
    """
    Cek apakah target masuk dalam scope.
    Returns (is_valid, reason).
    """
    entries = load_scope()

    if not entries:
        return True, "Scope file kosong — semua target diizinkan (mode development)"

    for entry in entries:
        if entry == "*":
            return True, "Wildcard scope — semua target diizinkan"

        # CIDR check
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                try:
                    ip = ipaddress.ip_address(target)
                    if ip in net:
                        return True, f"Target ada dalam CIDR {entry}"
                except ValueError:
                    pass
            except ValueError:
                pass

        # Wildcard domain: *.example.com
        if entry.startswith("*."):
            base = entry[2:]
            if target == base or target.endswith("." + base):
                return True, f"Target match wildcard {entry}"

        # Wildcard email: *@example.com
        if entry.startswith("*@"):
            domain = entry[2:]
            if target.endswith("@" + domain):
                return True, f"Email match {entry}"

        # Exact match
        if target.lower() == entry.lower():
            return True, f"Target exact match: {entry}"

        # Domain contains
        if target.lower().endswith("." + entry.lower()):
            return True, f"Target adalah subdomain dari {entry}"

    return False, f"Target '{target}' TIDAK ada dalam scope yang diizinkan"
