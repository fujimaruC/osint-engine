"""
core/batch.py
Batch scanner — scan banyak target dari file sekaligus.
Format: satu target per baris, support komentar #
"""

import time
from pathlib import Path
from datetime import datetime
from typing import Callable
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()


def load_targets(filepath: str) -> list[str]:
    """Load target list dari file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Target file tidak ditemukan: {filepath}")

    targets = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


def run_batch(
    targets: list[str],
    profile: str,
    sf,                          # SpiderFootAPI instance
    reports_dir: Path,
    on_scan_start: Callable | None = None,
    on_scan_end: Callable | None = None,
    poll_interval: float = 5.0,
    delay_between: float = 3.0,
) -> list[dict]:
    """
    Jalankan scan untuk setiap target secara berurutan.
    Returns list of result summaries.
    """
    from core.profiles import detect_target_type, get_profile
    from core.reporter import (
        categorize_results, summary_stats,
        export_html, export_json, export_csv
    )
    from core.audit import log_scan_start, log_scan_end

    results_summary = []
    total = len(targets)

    console.print(f"\n  [bold cyan]Batch mode:[/bold cyan] {total} target(s) — profile [yellow]{profile}[/yellow]\n")

    for idx, target in enumerate(targets, 1):
        console.print(f"  [{idx}/{total}] [cyan]{target}[/cyan]", end=" ")

        # Detect type
        t_type = detect_target_type(target)
        p_data = get_profile(profile)
        t_type = p_data.get("target_type_hint") or t_type
        modules = p_data.get("modules", [])

        scan_name = f"BATCH-{target[:15]}-{datetime.now().strftime('%H%M%S')}"

        try:
            # Audit log start
            scan_id = sf.new_scan(
                target=target,
                scan_name=scan_name,
                target_type=t_type,
                modules=modules,
            )
            log_scan_start(target, profile, scan_id, t_type)

            if on_scan_start:
                on_scan_start(target, scan_id)

            # Poll sampai selesai
            DONE = {"FINISHED", "ABORTED", "ERROR-FAILED"}
            status = "RUNNING"
            while status not in DONE:
                time.sleep(poll_interval)
                try:
                    s = sf.scan_status(scan_id)
                    status = s.get("CURRENT", {}).get("status", "UNKNOWN")
                except Exception:
                    break

            # Fetch results
            raw = sf.scan_results(scan_id)
            cats = categorize_results(raw)
            stats = summary_stats(cats)

            # Export
            export_html(target, profile, scan_id, raw, reports_dir)
            export_json(target, profile, scan_id, raw, reports_dir)
            export_csv(target, raw, reports_dir, scan_id)

            # Audit log end
            log_scan_end(scan_id, stats["total_events"], status, ["html", "json", "csv"])

            result = {
                "target": target,
                "scan_id": scan_id,
                "status": status,
                "total_events": stats["total_events"],
                "open_ports": stats["open_ports"],
                "emails": stats["emails"],
                "has_breaches": stats["has_breaches"],
                "error": None,
            }
            console.print(f"[green]✓[/green] {stats['total_events']} events")

            if on_scan_end:
                on_scan_end(target, scan_id, result)

        except Exception as e:
            result = {
                "target": target,
                "scan_id": None,
                "status": "ERROR",
                "total_events": 0,
                "open_ports": 0,
                "emails": 0,
                "has_breaches": False,
                "error": str(e),
            }
            console.print(f"[red]✗ {e}[/red]")

        results_summary.append(result)

        if idx < total:
            time.sleep(delay_between)

    return results_summary


def print_batch_summary(results: list[dict]):
    """Print tabel summary hasil batch scan."""
    table = Table(
        title="[bold cyan]Batch Scan Summary[/bold cyan]",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Target", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Events", justify="right", style="cyan")
    table.add_column("Ports", justify="right")
    table.add_column("Emails", justify="right")
    table.add_column("Breaches", justify="center")
    table.add_column("Error", style="dim red", overflow="ellipsis", max_width=30)

    for r in results:
        st_color = {"FINISHED": "green", "ERROR": "red", "ABORTED": "yellow"}.get(r["status"], "white")
        table.add_row(
            r["target"],
            f"[{st_color}]{r['status']}[/{st_color}]",
            str(r["total_events"]),
            str(r["open_ports"]),
            str(r["emails"]),
            "[red]⚠ YES[/red]" if r["has_breaches"] else "[green]✓[/green]",
            r.get("error") or "",
        )

    console.print()
    console.print(table)
