# 📦 OSINT Engine Core Library (`/core`)

This directory houses the core components of the OSINT Engine. These modules are responsible for scan profiles, formatting outputs, operational safety (scoping & disclaimers), operational security (proxies & Tor), audit logging, and Traffic Light Protocol labeling.

---

## 📋 Module Overview

| File | Primary Purpose | Key Dependencies | Output / State Files |
| :--- | :--- | :--- | :--- |
| [audit.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/audit.py) | Cryptographic, tamper-evident scan logger | `json`, `hashlib`, `socket`, `getpass` | `audit.log` |
| [batch.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/batch.py) | Iterative sequential bulk target scanning | `time`, `rich` | Standard exports per target |
| [disclaimer.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/disclaimer.py) | Policy consent gate & verification | `hashlib`, `getpass`, `rich` | `.disclaimer_accepted` |
| [profiles.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/profiles.py) | Target classification & profile parser | `yaml`, `re` | `profiles/profiles.yaml` |
| [proxy.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/proxy.py) | Tor & proxy routing config (OPSEC) | `requests`, `socks` | Env vars updates |
| [reporter.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/reporter.py) | Multi-format HTML, JSON, and CSV exporter | `json`, `csv`, `io` | Outputs in `reports/` |
| [scope.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/scope.py) | Allowed target scoping guard | `ipaddress`, `re` | `scope.txt` |
| [spiderfoot.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/spiderfoot.py) | SpiderFoot daemon controller & REST client | `subprocess`, `requests` | SpiderFoot subprocess |
| [tlp.py](file:///home/riko/Ctf/Spiderfoot/osint-engine/core/tlp.py) | NATO/FIRST Traffic Light Protocol marking | HTML/CSS strings | Injected into HTML reports |

---

## 🛠️ Module API Specifications

### ⚖️ Legal Disclaimer (`disclaimer.py`)
Intercepts program execution until terms are accepted.

*   `is_accepted() -> bool`
    Checks whether the current system user has already accepted the disclaimer by validating the presence and contents of `.disclaimer_accepted`.
*   `show_and_require_acceptance() -> bool`
    Prints the Indonesian/English terms of use screen using Rich layout. Solicits a prompt response. If agreed, writes a cryptographic hash of the current user's name into `.disclaimer_accepted` (with `0o444` read-only permissions) and files an entry to the audit log.
*   `reset_acceptance()`
    Clears local user consent (removes `.disclaimer_accepted` after temporarily setting chmod to `0o644` write-access).

---

### 🛡️ Scope Guard (`scope.py`)
Protects against unauthorized scans.

*   `ensure_scope_file()`
    Generates a default template `scope.txt` containing documentation and example filters if none exists.
*   `load_scope() -> list[str]`
    Reads valid lines from `scope.txt`, stripping whitespace and ignoring comment lines starting with `#`.
*   `is_in_scope(target: str) -> tuple[bool, str]`
    Matches input `target` against rules:
    *   Wildcard rule `*` (authorizes everything).
    *   Subnet ranges/CIDR checks (e.g. `10.0.0.0/8`, parsed via `ipaddress.ip_network`).
    *   Wildcard domains (e.g. `*.example.com`).
    *   Wildcard emails (e.g. `*@example.com`).
    *   Exact match (case-insensitive hostname/username/value equality).
    *   Subdomain endings.
    *   *Returns:* `(True, reason)` if allowed; `(False, failure_reason)` if unauthorized.

---

### 📝 Tamper-Evident Audit Logging (`audit.py`)
Implements block-chained SHA-256 logs for verification.

*   `log_scan_start(target: str, profile: str, scan_id: str, target_type: str)`
    Logs initial metadata: `timestamp` (UTC ISO format), `event` (`SCAN_START`), `operator`, `hostname`, `target`, `target_type`, `profile`, `scan_id`, and `prev_hash` (the hash of the previous log entry). Computes and embeds a SHA-256 integrity `hash` representing the current log block.
*   `log_scan_end(scan_id: str, total_events: int, status: str, exports: list[str])`
    Logs final metadata (`SCAN_END` event) linked to the matching scan ID, recording totals and exported formats.
*   `log_disclaimer_accepted(operator: str)`
    Logs the disclaimer signature details.
*   `verify_chain() -> tuple[bool, list[str]]`
    Sequentially loops through `audit.log`, parsing JSON lines, matching `prev_hash` fields with recalculations, and evaluating signatures. Returns `(True, [])` if intact, or `(False, [list_of_issues])` identifying compromised line numbers and mismatches.
*   `print_log(last_n: int = 20) -> list[dict]`
    Extracts the tail `last_n` entries in JSON format.

---

### 🌐 OPSEC Proxy & Tor Routing (`proxy.py`)
Configures routing and checks operational security state.

*   `configure_proxy(proxy_url: str | None = None, use_tor: bool = False) -> dict | None`
    Sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` environment variables for execution.
    *   If `use_tor=True`, redirects transport to Tor proxy socks layer (`socks5h://127.0.0.1:9050`).
    *   If no URL is passed, falls back to environment variables (`OSINT_PROXY`, `HTTP_PROXY`).
    *   *Returns:* Standard proxies dictionary configuration or `None`.
*   `check_tor_available() -> bool`
    Performs connection attempt to `check.torproject.org` via Tor socks layer on `127.0.0.1:9050`. Checks for "Congratulations" keyword response.
*   `get_exit_ip(proxies: dict | None = None) -> str`
    Queries external address resolution api `api.ipify.org` to confirm routing. Returns IP address string.

---

### 🚥 Traffic Light Protocol (`tlp.py`)
Standardized NATO classifications (`WHITE`, `GREEN`, `AMBER`, `RED`) for outputs.

*   `TLP_LEVELS` (Dictionary):
    Defines foreground/background CSS hex colors, distribution rules, and labels:
    *   `WHITE` (bg: `#2a2a2a`, fg: `#ffffff`) - Free public distribution.
    *   `GREEN` (bg: `#0d2b0d`, fg: `#33cc33`) - Restricted to community.
    *   `AMBER` (bg: `#2b1f00`, fg: `#ffb300`) - Restricted to internal organization.
    *   `RED` (bg: `#2b0000`, fg: `#ff3333`) - Highly confidential, strictly recipient-only.
*   `get_tlp_banner_html(level: str, operator: str = "", unit: str = "") -> str`
    Generates a styled HTML banner container for the top of reports, appending metadata about the operator and organization.
*   `get_tlp_footer_html(level: str) -> str`
    Generates the corresponding footer bar marking.

---

### 📥 Batch Scan Controller (`batch.py`)
Sequential batch scanning orchestrator.

*   `load_targets(filepath: str) -> list[str]`
    Reads plain-text target list from file path, ignoring empty lines and comments (starting with `#`).
*   `run_batch(targets: list[str], profile: str, sf: SpiderFootAPI, reports_dir: Path, ...)`
    Runs scans one by one:
    1.  Resolves target profiles and types.
    2.  Triggers SpiderFoot start.
    3.  Writes audit logs for `SCAN_START`.
    4.  Runs polling loops until the state lands in `FINISHED`, `ABORTED`, or `ERROR-FAILED`.
    5.  Collects, categorizes, and logs results.
    6.  Generates HTML/JSON/CSV output.
    7.  Writes audit logs for `SCAN_END`.
    8.  Waits for user-configured delays before moving to the next target.
*   `print_batch_summary(results: list[dict])`
    Renders an ASCII-art style dashboard table summarizing batch operations (target name, exit status, total events, ports discovered, breach indicator alerts, errors).

---

## 🚀 Recommended Integration Code Pattern

To tie all these new features together into the main runner (such as `engine.py`), use the following integration flow:

```python
import sys
from pathlib import Path
from core.spiderfoot import SpiderFootAPI
from core.disclaimer import show_and_require_acceptance
from core.scope import is_in_scope
from core.proxy import configure_proxy, check_tor_available, get_exit_ip
from core.audit import verify_chain, print_log
from core.batch import load_targets, run_batch

# 1. Enforce compliance gate
if not show_and_require_acceptance():
    sys.exit("Disclaimer declined.")

# 2. Check log integrity
intact, issues = verify_chain()
if not intact:
    print(f"WARNING: Audit log integrity compromise detected: {issues}")

# 3. Target Scope check
target = "example.com"
allowed, reason = is_in_scope(target)
if not allowed:
    sys.exit(f"Target blocked: {reason}")

# 4. Proxy setup
proxies = configure_proxy(use_tor=True)
exit_ip = get_exit_ip(proxies)
print(f"Traffic routed. Current outbound IP: {exit_ip}")
```
