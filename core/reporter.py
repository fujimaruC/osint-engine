"""
core/reporter.py
Formats and exports scan results to HTML, JSON, CSV, and terminal table.
"""

import json
import csv
import io
from pathlib import Path
from datetime import datetime
from typing import Optional


# ── Result Categorizer ─────────────────────────────────────────

CATEGORY_MAP = {
    "IP_ADDRESS": ("🌐 IP Addresses", "cyan"),
    "INTERNET_NAME": ("🔗 Domains / Hosts", "blue"),
    "EMAILADDR": ("📧 Email Addresses", "green"),
    "PHONE_NUMBER": ("📞 Phone Numbers", "yellow"),
    "URL_FORM": ("📝 Forms Found", "magenta"),
    "LINKED_URL_INTERNAL": ("🔗 Internal URLs", "blue"),
    "LINKED_URL_EXTERNAL": ("🌍 External URLs", "bright_blue"),
    "TCP_PORT_OPEN": ("🚪 Open Ports", "red"),
    "SSL_CERTIFICATE_ISSUED": ("🔒 SSL Certs", "green"),
    "DNS_TEXT": ("📋 DNS TXT Records", "cyan"),
    "DNS_MX": ("📬 MX Records", "cyan"),
    "DNS_NS": ("🔷 NS Records", "cyan"),
    "GEOINFO": ("📍 Geo Info", "yellow"),
    "RAW_RIR_DATA": ("🏢 WHOIS / RIR", "white"),
    "WEBSERVER_BANNER": ("🖥️  Web Banners", "magenta"),
    "SOFTWARE_USED": ("⚙️  Software Detected", "yellow"),
    "VULNERABILITY_CVE_CRITICAL": ("🔴 Critical CVEs", "red"),
    "VULNERABILITY_CVE_HIGH": ("🟠 High CVEs", "bright_red"),
    "VULNERABILITY_CVE_MEDIUM": ("🟡 Medium CVEs", "yellow"),
    "VULNERABILITY_CVE_LOW": ("🟢 Low CVEs", "green"),
    "SOCIAL_MEDIA": ("👤 Social Media", "bright_cyan"),
    "USERNAME": ("👤 Usernames", "bright_cyan"),
    "ACCOUNT_EXTERNAL_OWNED": ("🌐 External Accounts", "cyan"),
    "DARKWEB_MENTION": ("🕸️  Dark Web", "bright_red"),
    "LEAKSITE_CONTENT": ("💧 Leak Sites", "red"),
    "HACKED_EMAIL_ADDRESS": ("⚠️  Pwned Emails", "bright_red"),
    "DATA_BREACH": ("🚨 Data Breaches", "red"),
    "BITCOIN_ADDRESS": ("₿  Bitcoin Addrs", "yellow"),
    "AFFILIATE_IPADDR": ("🔀 Affiliate IPs", "blue"),
    "CO_HOSTED_SITE": ("🏠 Co-Hosted Sites", "blue"),
    "RAW_FILE_META_DATA": ("📄 File Metadata", "white"),
    "INTERESTING_FILE": ("📁 Interesting Files", "magenta"),
    "SIMILARDOMAIN": ("🔄 Similar Domains", "blue"),
    "SUBDOMAIN": ("🌲 Subdomains", "bright_blue"),
    "HTTP_CODE": ("📊 HTTP Codes", "white"),
}

PRIORITY_EVENT_TYPES = [
    "VULNERABILITY_CVE_CRITICAL",
    "VULNERABILITY_CVE_HIGH",
    "HACKED_EMAIL_ADDRESS",
    "DATA_BREACH",
    "DARKWEB_MENTION",
    "LEAKSITE_CONTENT",
    "TCP_PORT_OPEN",
    "EMAILADDR",
    "IP_ADDRESS",
    "SUBDOMAIN",
    "INTERNET_NAME",
    "SOFTWARE_USED",
]


def categorize_results(raw_results: list[dict]) -> dict[str, list[dict]]:
    """Group results by event type."""
    categories: dict[str, list[dict]] = {}
    for row in raw_results:
        # SF returns rows as lists: [id, type, module, data, sourcedata, confidence, visibility, risk, ...]
        if isinstance(row, list):
            evt_type = row[1] if len(row) > 1 else "UNKNOWN"
            data = row[3] if len(row) > 3 else ""
            module = row[2] if len(row) > 2 else ""
            entry = {"type": evt_type, "data": data, "module": module}
        else:
            evt_type = row.get("type", "UNKNOWN")
            entry = row

        categories.setdefault(evt_type, []).append(entry)
    return categories


def summary_stats(categories: dict) -> dict:
    """Generate quick summary stats."""
    total = sum(len(v) for v in categories.values())
    return {
        "total_events": total,
        "unique_types": len(categories),
        "top_categories": sorted(
            categories.items(), key=lambda x: len(x[1]), reverse=True
        )[:5],
        "has_vulns": any(
            k.startswith("VULNERABILITY") for k in categories
        ),
        "has_breaches": "HACKED_EMAIL_ADDRESS" in categories or "DATA_BREACH" in categories,
        "open_ports": len(categories.get("TCP_PORT_OPEN", [])),
        "emails": len(categories.get("EMAILADDR", [])),
        "subdomains": len(categories.get("SUBDOMAIN", [])) + len(categories.get("INTERNET_NAME", [])),
    }


# ── Export Functions ───────────────────────────────────────────

def export_json(
    target: str,
    profile: str,
    scan_id: str,
    raw_results: list,
    output_path: Path,
) -> Path:
    """Export full results as JSON."""
    categories = categorize_results(raw_results)
    payload = {
        "meta": {
            "target": target,
            "profile": profile,
            "scan_id": scan_id,
            "generated_at": datetime.now().isoformat(),
        },
        "summary": summary_stats(categories),
        "results": categories,
    }
    out = output_path / f"{_safe_name(target)}_{scan_id[:8]}.json"
    with open(out, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    return out


def export_csv(
    target: str,
    raw_results: list,
    output_path: Path,
    scan_id: str,
) -> Path:
    """Export results as CSV."""
    out = output_path / f"{_safe_name(target)}_{scan_id[:8]}.csv"
    with open(out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Event Type", "Data", "Module"])
        for row in raw_results:
            if isinstance(row, list):
                writer.writerow([
                    row[1] if len(row) > 1 else "",
                    row[3] if len(row) > 3 else "",
                    row[2] if len(row) > 2 else "",
                ])
            else:
                writer.writerow([
                    row.get("type", ""),
                    row.get("data", ""),
                    row.get("module", ""),
                ])
    return out


def export_html(
    target: str,
    profile: str,
    scan_id: str,
    raw_results: list,
    output_path: Path,
) -> Path:
    """Export results as a styled HTML report."""
    categories = categorize_results(raw_results)
    stats = summary_stats(categories)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = output_path / f"{_safe_name(target)}_{scan_id[:8]}.html"

    # Build category sections
    sections_html = ""
    # Priority types first
    ordered_keys = (
        [k for k in PRIORITY_EVENT_TYPES if k in categories]
        + [k for k in sorted(categories) if k not in PRIORITY_EVENT_TYPES]
    )

    for evt_type in ordered_keys:
        entries = categories[evt_type]
        label, _ = CATEGORY_MAP.get(evt_type, (evt_type, "white"))
        badge_cls = "badge-danger" if "VULN" in evt_type or "BREACH" in evt_type or "HACK" in evt_type else "badge-info"
        rows_html = ""
        for e in entries[:200]:  # cap per section
            data = e["data"] if isinstance(e, dict) else e
            module = e.get("module", "") if isinstance(e, dict) else ""
            rows_html += f"""
            <tr>
              <td class="data-cell">{_esc(str(data))}</td>
              <td><span class="module-tag">{_esc(module)}</span></td>
            </tr>"""
        sections_html += f"""
        <div class="section" id="sec-{evt_type}">
          <div class="section-header" onclick="toggleSection(this)">
            <span class="section-title">{label}</span>
            <span class="badge {badge_cls}">{len(entries)}</span>
            <span class="toggle-icon">▼</span>
          </div>
          <div class="section-body">
            <table>
              <thead><tr><th>Data</th><th>Module</th></tr></thead>
              <tbody>{rows_html}</tbody>
            </table>
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report — {_esc(target)}</title>
<style>
  :root {{
    --bg: #0d0f1a;
    --card: #131626;
    --border: #1e2540;
    --accent: #4d9fff;
    --accent2: #7c5cbf;
    --text: #c8d8f0;
    --text-muted: #5a6888;
    --danger: #ff4d4d;
    --warn: #ffb347;
    --success: #4dff91;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', 'JetBrains Mono', monospace; font-size: 13px; }}
  .header {{ background: linear-gradient(135deg, #0d0f1a 0%, #131a35 100%); border-bottom: 1px solid var(--border); padding: 28px 32px; }}
  .header h1 {{ font-size: 22px; color: var(--accent); letter-spacing: 2px; text-transform: uppercase; }}
  .header .meta {{ color: var(--text-muted); margin-top: 6px; font-size: 12px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px 16px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-card .num {{ font-size: 28px; font-weight: bold; color: var(--accent); }}
  .stat-card .lbl {{ color: var(--text-muted); font-size: 11px; margin-top: 4px; text-transform: uppercase; }}
  .stat-card.danger {{ border-color: var(--danger); }}
  .stat-card.danger .num {{ color: var(--danger); }}
  .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px; overflow: hidden; }}
  .section-header {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; user-select: none; transition: background .15s; }}
  .section-header:hover {{ background: rgba(77,159,255,.06); }}
  .section-title {{ flex: 1; font-size: 13px; font-weight: 600; color: var(--text); }}
  .toggle-icon {{ color: var(--text-muted); transition: transform .2s; }}
  .section-header.collapsed .toggle-icon {{ transform: rotate(-90deg); }}
  .section-body {{ border-top: 1px solid var(--border); display: block; }}
  .section-body.hidden {{ display: none; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: rgba(77,159,255,.08); padding: 8px 12px; text-align: left; color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: 7px 12px; border-top: 1px solid rgba(255,255,255,.04); vertical-align: top; }}
  tr:hover td {{ background: rgba(77,159,255,.04); }}
  .data-cell {{ font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 12px; word-break: break-all; color: #e0eeff; }}
  .module-tag {{ background: rgba(77,159,255,.12); color: var(--accent); border-radius: 4px; padding: 2px 7px; font-size: 11px; white-space: nowrap; }}
  .badge {{ padding: 2px 9px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
  .badge-info {{ background: rgba(77,159,255,.2); color: var(--accent); }}
  .badge-danger {{ background: rgba(255,77,77,.2); color: var(--danger); }}
  .toc {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 20px; }}
  .toc h3 {{ color: var(--accent); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }}
  .toc-grid {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .toc-link {{ background: rgba(77,159,255,.08); border: 1px solid rgba(77,159,255,.2); border-radius: 4px; padding: 4px 10px; color: var(--text); text-decoration: none; font-size: 11px; transition: .15s; }}
  .toc-link:hover {{ background: rgba(77,159,255,.18); color: var(--accent); }}
  .footer {{ text-align: center; padding: 24px; color: var(--text-muted); font-size: 11px; }}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ OSINT Engine Report</h1>
  <div class="meta">
    Target: <strong style="color:#e0eeff">{_esc(target)}</strong>
    &nbsp;|&nbsp; Profile: <strong style="color:#e0eeff">{_esc(profile)}</strong>
    &nbsp;|&nbsp; Scan ID: <code style="color:#4d9fff">{scan_id[:8]}</code>
    &nbsp;|&nbsp; Generated: {ts}
  </div>
</div>
<div class="container">
  <div class="stats-grid">
    <div class="stat-card"><div class="num">{stats['total_events']}</div><div class="lbl">Total Events</div></div>
    <div class="stat-card"><div class="num">{stats['unique_types']}</div><div class="lbl">Event Types</div></div>
    <div class="stat-card"><div class="num">{stats['subdomains']}</div><div class="lbl">Domains / Hosts</div></div>
    <div class="stat-card"><div class="num">{stats['open_ports']}</div><div class="lbl">Open Ports</div></div>
    <div class="stat-card"><div class="num">{stats['emails']}</div><div class="lbl">Emails Found</div></div>
    <div class="stat-card {'danger' if stats['has_breaches'] else ''}"><div class="num">{'⚠' if stats['has_breaches'] else '✓'}</div><div class="lbl">Breach Status</div></div>
  </div>
  <div class="toc">
    <h3>📑 Quick Navigation</h3>
    <div class="toc-grid">
      {''.join(f'<a class="toc-link" href="#sec-{k}">{CATEGORY_MAP.get(k,(k,""))[0]} ({len(categories[k])})</a>' for k in ordered_keys)}
    </div>
  </div>
  {sections_html}
</div>
<div class="footer">Generated by OSINT Engine v1.0 — N-EX / Fujimaru</div>
<script>
  function toggleSection(header) {{
    const body = header.nextElementSibling;
    const collapsed = header.classList.toggle('collapsed');
    body.classList.toggle('hidden', collapsed);
  }}
</script>
</body>
</html>"""

    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    return out


# ── Helpers ────────────────────────────────────────────────────

def _safe_name(s: str) -> str:
    return re.sub(r"[^\w\-.]", "_", s)[:40]


def _esc(s: str) -> str:
    return (s
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;"))


import re
