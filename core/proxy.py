"""
core/proxy.py
Proxy / Tor support untuk OPSEC — route traffic SpiderFoot lewat proxy.
"""

import os
import requests
from rich.console import Console

console = Console()


def configure_proxy(proxy_url: str | None = None, use_tor: bool = False) -> dict | None:
    """
    Konfigurasi proxy untuk requests session.
    
    proxy_url format: socks5://127.0.0.1:9050
                      http://user:pass@proxy.example.com:8080
    
    Returns proxies dict atau None.
    """
    if use_tor:
        proxy_url = "socks5h://127.0.0.1:9050"
        console.print("  [cyan]⟳[/cyan] Routing via [bold]Tor[/bold] (socks5h://127.0.0.1:9050)")

    if not proxy_url:
        # Cek env var
        proxy_url = os.environ.get("OSINT_PROXY") or os.environ.get("HTTP_PROXY")

    if proxy_url:
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        # Set untuk requests global
        os.environ["HTTP_PROXY"] = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url
        os.environ["http_proxy"] = proxy_url
        os.environ["https_proxy"] = proxy_url
        return proxies

    return None


def check_tor_available() -> bool:
    """Cek apakah Tor SOCKS5 tersedia di 9050."""
    try:
        import socks
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        s.settimeout(5)
        s.connect(("check.torproject.org", 80))
        s.close()
        return True
    except Exception:
        # Fallback via requests
        try:
            r = requests.get(
                "http://check.torproject.org",
                proxies={"http": "socks5h://127.0.0.1:9050"},
                timeout=8,
            )
            return "Congratulations" in r.text
        except Exception:
            return False


def get_exit_ip(proxies: dict | None = None) -> str:
    """Cek IP publik yang digunakan (untuk verifikasi proxy/Tor)."""
    try:
        r = requests.get(
            "https://api.ipify.org",
            proxies=proxies,
            timeout=8,
        )
        return r.text.strip()
    except Exception:
        return "Unknown"
