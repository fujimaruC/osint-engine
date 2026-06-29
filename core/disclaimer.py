"""
core/disclaimer.py
Legal disclaimer — wajib di-accept sebelum tool bisa digunakan.
State tersimpan di .disclaimer_accepted (per-user).
"""

import getpass
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

DISCLAIMER_FILE = Path(__file__).parent.parent / ".disclaimer_accepted"

DISCLAIMER_TEXT = """
[bold red]⚠  PERINGATAN HUKUM / LEGAL WARNING[/bold red]

Alat ini ([bold]OSINT Engine[/bold]) dirancang [bold]HANYA[/bold] untuk:
  • Pengintaian informasi terbuka (Open Source Intelligence)
  • Pengujian keamanan terhadap aset yang [bold green]TELAH MENDAPAT IZIN TERTULIS[/bold green]
  • Keperluan investigasi oleh personel yang berwenang

[bold red]DILARANG KERAS digunakan untuk:[/bold red]
  • Memata-matai individu/entitas tanpa izin
  • Kegiatan yang melanggar hukum yang berlaku
  • Pengumpulan data yang melanggar privasi pihak ketiga

[bold yellow]DENGAN MENGGUNAKAN ALAT INI, ANDA MENYATAKAN:[/bold yellow]
  1. Anda memiliki izin yang sah atas target yang akan di-scan
  2. Anda bertanggung jawab penuh atas penggunaan alat ini
  3. Setiap sesi tercatat dalam audit log yang tidak dapat diubah
  4. Penyalahgunaan dapat dikenai sanksi hukum pidana/perdata

[dim]Pengembang tidak bertanggung jawab atas penyalahgunaan alat ini.[/dim]
"""


def _accepted_hash() -> str:
    user = getpass.getuser()
    return hashlib.sha256(user.encode()).hexdigest()[:16]


def is_accepted() -> bool:
    """Cek apakah disclaimer sudah pernah diterima oleh user ini."""
    if not DISCLAIMER_FILE.exists():
        return False
    stored = DISCLAIMER_FILE.read_text().strip()
    return stored == _accepted_hash()


def show_and_require_acceptance() -> bool:
    """
    Tampilkan disclaimer dan minta persetujuan.
    Returns True jika diterima, False jika ditolak.
    """
    if is_accepted():
        return True

    console.print()
    console.print(Panel(
        DISCLAIMER_TEXT,
        title="[bold red]SYARAT PENGGUNAAN / TERMS OF USE[/bold red]",
        border_style="red",
        padding=(1, 3),
    ))
    console.print()

    accepted = Confirm.ask(
        "  [bold yellow]Saya memahami dan menyetujui syarat di atas[/bold yellow]",
        default=False,
    )

    if accepted:
        # Simpan state
        DISCLAIMER_FILE.write_text(_accepted_hash())
        DISCLAIMER_FILE.chmod(0o444)

        # Catat di audit log
        try:
            from core.audit import log_disclaimer_accepted
            log_disclaimer_accepted(getpass.getuser())
        except Exception:
            pass

        console.print("  [green]✓ Persetujuan dicatat.[/green]")
        return True
    else:
        console.print("  [red]✗ Disclaimer tidak disetujui. Program berhenti.[/red]")
        return False


def reset_acceptance():
    """Reset disclaimer (untuk testing atau re-acceptance)."""
    if DISCLAIMER_FILE.exists():
        DISCLAIMER_FILE.chmod(0o644)
        DISCLAIMER_FILE.unlink()
