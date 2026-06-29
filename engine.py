#!/usr/bin/env python3
"""
engine.py
OSINT Engine — Main CLI Entry Point
N-EX / Fujimaru | Kalimantan Timur
"""

import sys
import os
import time
import click
from pathlib import Path
from datetime import datetime

# ── Rich imports ───────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich.prompt import Prompt, Confirm
from rich import box
from rich.rule import Rule
from rich.markup import escape
from rich.live import Live
from rich.layout import Layout

# ── Internal imports ────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from core.spiderfoot import SpiderFootAPI
from core.profiles import (
    load_profiles, get_profile, list_profiles,
    detect_target_type, TARGET_TYPE_LABELS
)
from core.reporter import (
    categorize_results, summary_stats,
    export_json, export_csv, export_html,
    CATEGORY_MAP, PRIORITY_EVENT_TYPES
)

console = Console()
REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ── Banner ─────────────────────────────────────────────────────

BANNER = """[bold cyan]
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝[/bold cyan]
[blue]   ╔═════════════════════════════════╗[/blue]
[blue]   ║  [/blue][bold white]OSINT ENGINE[/bold white] [dim]v1.0[/dim][blue]  |  [/blue][bold cyan]N-EX[/bold cyan][blue]  ║[/blue]
[blue]   ╚═════════════════════════════════╝[/blue]
"""

def print_banner():
    console.print(Panel(BANNER, border_style="blue", padding=(0, 2)))


# ── CLI Groups ─────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="OSINT Engine")
def cli():
    """
    \b
    ⚡ OSINT Engine — Powered by SpiderFoot
    N-EX / Fujimaru | Kalimantan Timur
    """
    pass


# ── SCAN command ───────────────────────────────────────────────

@cli.command()
@click.option("-t", "--target", help="Target to scan (domain, IP, email, username, etc.)")
@click.option("-p", "--profile", default="passive", show_default=True,
              help="Scan profile: quick|passive|deep|full|ctf|email|username")
@click.option("--target-type", default=None,
              help="Override target type detection (e.g. INTERNET_NAME, EMAILADDR)")
@click.option("--host", default="127.0.0.1", show_default=True, help="SpiderFoot host")
@click.option("--port", default=5001, show_default=True, help="SpiderFoot port")
@click.option("--no-html", is_flag=True, help="Skip HTML report")
@click.option("--no-json", is_flag=True, help="Skip JSON export")
@click.option("--no-csv", is_flag=True, help="Skip CSV export")
@click.option("-o", "--output", default=None, help="Custom output directory")
@click.option("-i", "--interactive", is_flag=True, help="Interactive mode (TUI wizard)")
def scan(target, profile, target_type, host, port, no_html, no_json, no_csv, output, interactive):
    """Run an OSINT scan against a target."""
    print_banner()

    # ── Interactive wizard ────────────────────────────────────
    if interactive or not target:
        target, profile, target_type = _interactive_wizard(target, profile, target_type)

    if not target:
        console.print("[red]✗ No target specified. Use -t <target> or --interactive[/red]")
        sys.exit(1)

    # ── Auto-detect target type ───────────────────────────────
    detected_type = detect_target_type(target)
    if target_type:
        t_type = target_type
        console.print(f"  [dim]Target type:[/dim] [bold]{t_type}[/bold] [dim](manual override)[/dim]")
    else:
        # Check profile hint
        p_data = get_profile(profile)
        t_type = p_data.get("target_type_hint") or detected_type
        label = TARGET_TYPE_LABELS.get(t_type, t_type)
        console.print(
            f"  [dim]Target type:[/dim] [bold cyan]{label}[/bold cyan] "
            f"[dim]({t_type})[/dim]"
        )

    # ── Output dir ────────────────────────────────────────────
    out_dir = Path(output) if output else REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Start SpiderFoot ──────────────────────────────────────
    sf = SpiderFootAPI(host=host, port=port)
    scan_name = f"OSINT-{target[:20]}-{datetime.now().strftime('%H%M%S')}"

    console.print()
    console.print(Rule("[bold blue]Starting OSINT Engine[/bold blue]", style="blue"))
    console.print()

    _print_scan_info(target, profile, t_type, scan_name)
    console.print()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}"),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Starting SpiderFoot backend...", total=None)
        if not sf.start(timeout=45):
            console.print("[red]✗ Failed to start SpiderFoot. Check your setup.[/red]")
            sys.exit(1)
        prog.update(task, description="SpiderFoot online ✓")

    console.print("  [green]✓[/green] SpiderFoot backend ready")

    # ── Get modules ───────────────────────────────────────────
    p_data = get_profile(profile)
    modules = p_data.get("modules", [])

    # ── Start scan ────────────────────────────────────────────
    try:
        scan_id = sf.new_scan(
            target=target,
            scan_name=scan_name,
            target_type=t_type,
            modules=modules,
        )
    except Exception as e:
        console.print(f"[red]✗ Failed to start scan: {e}[/red]")
        sf.stop()
        sys.exit(1)

    console.print(f"  [green]✓[/green] Scan started → ID: [bold cyan]{scan_id[:12]}...[/bold cyan]")
    console.print()

    # ── Live progress ─────────────────────────────────────────
    _run_scan_live(sf, scan_id)

    # ── Fetch results ─────────────────────────────────────────
    console.print()
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}"),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Fetching results...", total=None)
        raw_results = sf.scan_results(scan_id)
        prog.update(task, description=f"Fetched {len(raw_results)} events ✓")

    console.print(f"  [green]✓[/green] Retrieved [bold]{len(raw_results)}[/bold] events")

    # ── Display summary ───────────────────────────────────────
    categories = categorize_results(raw_results)
    stats = summary_stats(categories)
    _print_summary(stats, categories)

    # ── Export reports ────────────────────────────────────────
    console.print()
    console.print(Rule("[bold blue]Exporting Reports[/bold blue]", style="blue"))
    console.print()

    exports = []
    if not no_html:
        p = export_html(target, profile, scan_id, raw_results, out_dir)
        exports.append(("HTML", p, "🌐"))
    if not no_json:
        p = export_json(target, profile, scan_id, raw_results, out_dir)
        exports.append(("JSON", p, "📄"))
    if not no_csv:
        p = export_csv(target, raw_results, out_dir, scan_id)
        exports.append(("CSV", p, "📊"))

    for fmt, path, icon in exports:
        console.print(f"  {icon} [green]{fmt}[/green] → [dim]{path}[/dim]")

    # ── Cleanup ───────────────────────────────────────────────
    console.print()
    if Confirm.ask("  Stop SpiderFoot backend?", default=True):
        sf.stop()
        console.print("  [dim]SpiderFoot stopped.[/dim]")

    console.print()
    console.print(Panel(
        f"[bold green]✓ Scan complete![/bold green]\n"
        f"[dim]Target:[/dim] [cyan]{target}[/cyan]  "
        f"[dim]Events:[/dim] [cyan]{stats['total_events']}[/cyan]  "
        f"[dim]Reports in:[/dim] [cyan]{out_dir}[/cyan]",
        border_style="green",
        padding=(0, 2),
    ))


# ── PROFILES command ───────────────────────────────────────────

@cli.command()
def profiles():
    """List all available scan profiles."""
    print_banner()
    profiles_list = list_profiles()
    table = Table(
        title="[bold cyan]Scan Profiles[/bold cyan]",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Key", style="bold yellow", width=12)
    table.add_column("Name", style="bold white", width=20)
    table.add_column("Description", style="dim white")
    table.add_column("Modules", style="cyan", justify="center", width=10)
    table.add_column("Est. Time", style="green", justify="center", width=12)

    for p in profiles_list:
        table.add_row(
            p["key"],
            p["name"],
            p["description"],
            str(p["module_count"]),
            p["estimated_time"],
        )
    console.print()
    console.print(table)


# ── STATUS command ─────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=5001)
def status(host, port):
    """Check SpiderFoot backend status and list recent scans."""
    print_banner()
    sf = SpiderFootAPI(host=host, port=port)

    if not sf.is_running():
        console.print(Panel(
            "[red]✗ SpiderFoot backend is [bold]OFFLINE[/bold][/red]\n"
            "[dim]Start it with:[/dim] [cyan]./osint scan ...[/cyan]",
            border_style="red",
        ))
        return

    console.print(Panel("[green]✓ SpiderFoot backend is [bold]ONLINE[/bold][/green]", border_style="green"))
    console.print()

    try:
        scans = sf.list_scans()
        if not scans:
            console.print("[dim]No scans found.[/dim]")
            return

        table = Table(
            title="Recent Scans",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold cyan",
        )
        table.add_column("Scan ID", style="cyan", width=10)
        table.add_column("Name", style="white")
        table.add_column("Target", style="yellow")
        table.add_column("Status", style="bold")
        table.add_column("Events", justify="right")

        for s in scans[-20:]:
            status_color = {
                "FINISHED": "green",
                "RUNNING": "cyan",
                "ABORTED": "yellow",
                "ERROR-FAILED": "red",
            }.get(s.get("status", ""), "white")

            table.add_row(
                str(s.get("id", ""))[:8],
                str(s.get("name", ""))[:30],
                str(s.get("target", ""))[:25],
                f"[{status_color}]{s.get('status', 'UNKNOWN')}[/{status_color}]",
                str(s.get("events", "")),
            )
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error fetching scan list: {e}[/red]")


# ── RESULTS command ────────────────────────────────────────────

@cli.command()
@click.argument("scan_id")
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=5001)
@click.option("--filter", "event_filter", default=None, help="Filter by event type")
@click.option("--export", is_flag=True, help="Also export reports")
@click.option("-o", "--output", default=None)
def results(scan_id, host, port, event_filter, export, output):
    """Fetch and display results for an existing scan."""
    print_banner()
    sf = SpiderFootAPI(host=host, port=port)

    if not sf.is_running():
        console.print("[red]✗ SpiderFoot is not running.[/red]")
        return

    with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]{task.description}"),
                  console=console, transient=True) as prog:
        task = prog.add_task(f"Fetching results for {scan_id[:8]}...", total=None)
        if event_filter:
            raw = sf.scan_results_by_type(scan_id, event_filter)
        else:
            raw = sf.scan_results(scan_id)

    categories = categorize_results(raw)
    stats = summary_stats(categories)
    _print_summary(stats, categories)

    if export:
        out_dir = Path(output) if output else REPORTS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)
        target = scan_id  # fallback
        p = export_html(target, "custom", scan_id, raw, out_dir)
        console.print(f"\n  [green]HTML exported →[/green] [dim]{p}[/dim]")


# ── STOP command ───────────────────────────────────────────────

@cli.command()
@click.argument("scan_id")
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=5001)
def stop(scan_id, host, port):
    """Abort a running scan."""
    sf = SpiderFootAPI(host=host, port=port)
    sf.stop_scan(scan_id)
    console.print(f"[yellow]Scan {scan_id[:8]} abort requested.[/yellow]")


# ── Helpers ────────────────────────────────────────────────────

def _interactive_wizard(target, profile, target_type):
    """Interactive TUI wizard for scan setup."""
    console.print(Rule("[bold cyan]Scan Setup Wizard[/bold cyan]", style="cyan"))
    console.print()

    if not target:
        target = Prompt.ask("  [bold cyan]Enter target[/bold cyan] [dim](domain, IP, email, username...)[/dim]")

    # Detect and confirm type
    detected = detect_target_type(target)
    label = TARGET_TYPE_LABELS.get(detected, detected)
    console.print(f"  [dim]Detected type:[/dim] [bold cyan]{label}[/bold cyan]")
    if not Confirm.ask("  Use this type?", default=True):
        target_type = Prompt.ask(
            "  Enter type",
            default=detected,
            choices=list(TARGET_TYPE_LABELS.keys()),
        )

    # Profile selection
    profiles_list = list_profiles()
    console.print()
    console.print("  [bold]Available profiles:[/bold]")
    for p in profiles_list:
        console.print(
            f"   [cyan]{p['key']:<12}[/cyan] "
            f"[white]{p['name']:<22}[/white] "
            f"[dim]{p['estimated_time']}[/dim]"
        )
    console.print()
    profile = Prompt.ask(
        "  [bold cyan]Select profile[/bold cyan]",
        default=profile,
        choices=[p["key"] for p in profiles_list],
    )

    return target, profile, target_type


def _print_scan_info(target, profile, t_type, scan_name):
    """Print a nice scan info panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", min_width=14)
    grid.add_column(style="bold cyan")
    grid.add_row("Target:", target)
    grid.add_row("Type:", TARGET_TYPE_LABELS.get(t_type, t_type))
    grid.add_row("Profile:", profile)
    grid.add_row("Scan Name:", scan_name)
    console.print(Panel(grid, title="[bold blue]Scan Configuration[/bold blue]", border_style="blue", padding=(0, 2)))


def _run_scan_live(sf: SpiderFootAPI, scan_id: str):
    """Live progress display while scan runs."""
    DONE_STATES = {"FINISHED", "ABORTED", "ERROR-FAILED"}
    start_time = time.time()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}"),
        BarColumn(complete_style="cyan", finished_style="green"),
        TextColumn("[dim]{task.fields[events]} events[/dim]"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("Scanning...", total=None, events=0)
        prev_events = 0

        while True:
            try:
                status = sf.scan_status(scan_id)
                current = status.get("CURRENT", {})
                state = current.get("status", "UNKNOWN")
                events = current.get("events", {})
                total_events = sum(events.values()) if isinstance(events, dict) else 0

                if total_events != prev_events:
                    prog.update(task, events=total_events)
                    prev_events = total_events

                prog.update(task, description=f"[cyan]{state}[/cyan] — scanning...")

                if state in DONE_STATES:
                    final_color = "green" if state == "FINISHED" else "yellow"
                    prog.update(task, description=f"[{final_color}]{state}[/{final_color}]", completed=100, total=100)
                    break

            except Exception:
                pass

            time.sleep(3)

    elapsed = time.time() - start_time
    console.print(f"  [green]✓[/green] Scan completed in [bold]{elapsed:.0f}s[/bold]")


def _print_summary(stats: dict, categories: dict):
    """Print a nice results summary."""
    console.print()
    console.print(Rule("[bold cyan]Scan Results Summary[/bold cyan]", style="cyan"))
    console.print()

    # Stats row
    stat_panels = [
        Panel(f"[bold cyan]{stats['total_events']}[/bold cyan]\n[dim]Total Events[/dim]", border_style="blue"),
        Panel(f"[bold cyan]{stats['unique_types']}[/bold cyan]\n[dim]Event Types[/dim]", border_style="blue"),
        Panel(f"[bold cyan]{stats['subdomains']}[/bold cyan]\n[dim]Hosts/Domains[/dim]", border_style="blue"),
        Panel(f"[bold cyan]{stats['open_ports']}[/bold cyan]\n[dim]Open Ports[/dim]", border_style="blue"),
        Panel(f"[bold cyan]{stats['emails']}[/bold cyan]\n[dim]Emails[/dim]", border_style="blue"),
        Panel(
            f"[bold {'red' if stats['has_breaches'] else 'green'}]{'⚠ YES' if stats['has_breaches'] else '✓ CLEAN'}[/bold {'red' if stats['has_breaches'] else 'green'}]\n[dim]Breaches[/dim]",
            border_style="red" if stats["has_breaches"] else "green"
        ),
    ]
    console.print(Columns(stat_panels))
    console.print()

    # Results table
    table = Table(
        title="[bold]Top Results by Category[/bold]",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Category", style="white", min_width=30)
    table.add_column("Count", justify="right", style="bold cyan", width=8)
    table.add_column("Sample", style="dim", overflow="ellipsis", max_width=50)

    # Priority types first
    shown_keys = (
        [k for k in PRIORITY_EVENT_TYPES if k in categories]
        + [k for k in sorted(categories) if k not in PRIORITY_EVENT_TYPES]
    )[:20]

    for k in shown_keys:
        entries = categories[k]
        label, color = CATEGORY_MAP.get(k, (k, "white"))
        sample = ""
        if entries:
            first = entries[0]
            sample = first.get("data", "") if isinstance(first, dict) else str(first)
            sample = str(sample)[:50]

        table.add_row(label, str(len(entries)), escape(sample))

    console.print(table)


if __name__ == "__main__":
    cli()
