"""
core/profiles.py
Loads scan profiles and auto-detects target types.
"""

import re
import yaml
from pathlib import Path
from typing import Optional


PROFILES_FILE = Path(__file__).parent.parent / "profiles" / "profiles.yaml"


def load_profiles() -> dict:
    """Load all scan profiles from YAML."""
    with open(PROFILES_FILE) as f:
        data = yaml.safe_load(f)
    return data.get("profiles", {})


def get_profile(name: str) -> dict:
    profiles = load_profiles()
    if name not in profiles:
        raise ValueError(
            f"Unknown profile '{name}'. "
            f"Available: {', '.join(profiles.keys())}"
        )
    return profiles[name]


def list_profiles() -> list[dict]:
    """Return list of profiles with metadata for display."""
    profiles = load_profiles()
    result = []
    for key, p in profiles.items():
        result.append({
            "key": key,
            "name": p.get("name", key),
            "description": p.get("description", ""),
            "estimated_time": p.get("estimated_time", "?"),
            "module_count": len(p.get("modules", [])) or "ALL",
        })
    return result


# ── Target Type Detection ──────────────────────────────────────

_IPv4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
_IPv6_RE = re.compile(
    r"^[0-9a-fA-F:]+:[0-9a-fA-F:]*$"
)
_CIDR_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
_PHONE_RE = re.compile(
    r"^\+?[\d\s\-\(\)]{7,20}$"
)
_BTC_RE = re.compile(
    r"^(1|3|bc1)[a-zA-Z0-9]{25,62}$"
)
_AS_RE = re.compile(
    r"^AS\d+$", re.IGNORECASE
)
_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$"
)


def detect_target_type(target: str) -> str:
    """
    Auto-detect SpiderFoot target type from input string.
    Returns SF target type string.
    """
    t = target.strip()

    if _EMAIL_RE.match(t):
        return "EMAILADDR"
    if _IPv4_RE.match(t):
        return "IP_ADDRESS"
    if _IPv6_RE.match(t):
        return "IP_ADDRESS"
    if _CIDR_RE.match(t):
        return "NETBLOCK_OWNER"
    if _BTC_RE.match(t):
        return "BITCOIN_ADDRESS"
    if _AS_RE.match(t):
        return "BGP_AS_MEMBER"
    if _PHONE_RE.match(t):
        return "PHONE_NUMBER"
    if _DOMAIN_RE.match(t):
        return "INTERNET_NAME"

    # Fallback: treat as username or human name
    if " " in t:
        return "HUMAN_NAME"
    return "USERNAME"


TARGET_TYPE_LABELS = {
    "INTERNET_NAME": "Domain / Hostname",
    "IP_ADDRESS": "IP Address",
    "NETBLOCK_OWNER": "CIDR / Netblock",
    "EMAILADDR": "Email Address",
    "PHONE_NUMBER": "Phone Number",
    "BITCOIN_ADDRESS": "Bitcoin Address",
    "BGP_AS_MEMBER": "BGP AS Number",
    "HUMAN_NAME": "Person Name",
    "USERNAME": "Username / Handle",
}
