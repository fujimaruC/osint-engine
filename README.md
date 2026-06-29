<!-- Font Awesome Link for rendering icons -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

# <i class="fa-solid fa-bolt"></i> OSINT Engine

> Standalone SpiderFoot automation wrapper with a user-friendly Rich CLI, scan profiles, and multi-format reporting.
> **by N-EX / Fujimaru | Kalimantan Timur**

---

## <i class="fa-solid fa-rocket"></i> Quick Start

```bash
# 1. Clone / extract this folder
cd osint-engine

# 2. One-shot setup (creates venv + clones SpiderFoot)
chmod +x setup.sh && ./setup.sh

# 3. Run a scan
./osint scan -t example.com -p passive

# 4. Interactive wizard
./osint scan --interactive
```

---

## <i class="fa-solid fa-folder-open"></i> Structure

```
osint-engine/
├── engine.py              # Main CLI entry point
├── setup.sh               # One-shot environment setup
├── osint                  # Wrapper script (created by setup.sh)
├── requirements.txt       # Python dependencies
├── config.yaml.example    # API keys template → copy to config.yaml
│
├── core/
│   ├── audit.py           # Tamper-evident scan audit logging
│   ├── batch.py           # Multi-target batch scan scheduler
│   ├── disclaimer.py      # Legal disclaimer & user consent checker
│   ├── profiles.py        # Scan profiles + target type detection
│   ├── proxy.py           # Tor and proxy routing client (OPSEC)
│   ├── reporter.py        # HTML / JSON / CSV exporter
│   ├── scope.py           # Allowed scanning target scope validator
│   ├── spiderfoot.py      # SpiderFoot REST API wrapper
│   └── tlp.py             # Traffic Light Protocol report classification
│
├── profiles/
│   └── profiles.yaml      # Scan profile definitions
│
├── reports/               # Generated reports (auto-created)
└── tools/
    └── spiderfoot/        # SpiderFoot clone (auto-created by setup.sh)
```

---

## <i class="fa-solid fa-bullseye"></i> Scan Profiles

| Profile    | Description                               | Est. Time    |
|------------|-------------------------------------------|--------------|
| `quick`    | Fast passive — DNS, WHOIS, SSL only       | 1–5 min      |
| `passive`  | Full passive — no active probing (stealth)| 5–20 min     |
| `deep`     | Active + passive — ports, crawling, banners | 20–60 min  |
| `full`     | All modules                               | 60–180 min   |
| `ctf`      | Optimized for CTF/Bug Bounty recon        | 10–30 min    |
| `email`    | Email target — breaches, social, PGP      | 5–15 min     |
| `username` | Username tracking across platforms        | 5–15 min     |

---

## <i class="fa-solid fa-laptop"></i> Usage

```bash
# Basic scan
./osint scan -t example.com

# Specific profile
./osint scan -t 8.8.8.8 -p quick

# Email target
./osint scan -t user@example.com -p email

# Username OSINT
./osint scan -t "n-ex" -p username

# Interactive wizard
./osint scan -i

# List profiles
./osint profiles

# Check backend status + recent scans
./osint status

# Fetch results from existing scan
./osint results <scan_id>

# Stop a running scan
./osint stop <scan_id>

# Skip certain exports
./osint scan -t example.com --no-csv --no-json
```

---

## <i class="fa-solid fa-key"></i> API Keys

Copy `config.yaml.example` to `config.yaml` and fill in keys for:
- **Shodan** — port/service data
- **VirusTotal** — threat intelligence
- **HaveIBeenPwned** — breach data
- **Hunter.io** — email enumeration
- **Censys / ZoomEye** — internet scanning

More keys = more modules = better results. All keys are optional.

---

## <i class="fa-solid fa-chart-column"></i> Reports

Reports are saved in `./reports/` by default:

| Format | Contents |
|--------|----------|
| `.html` | Interactive report with dark theme, collapsible sections, navigation |
| `.json` | Full structured results with metadata + summary |
| `.csv`  | Flat event list — import to Excel/Sheets |

---

## <i class="fa-solid fa-wrench"></i> Requirements

- Python 3.10+
- git
- Internet access (for SpiderFoot clone + module data)

Optional system tools (for active modules):
- `nmap` — port scanning
- `openssl` — SSL analysis

---

## <i class="fa-solid fa-gear"></i> Custom Profiles

Edit `profiles/profiles.yaml` to create your own profiles:

```yaml
profiles:
  myprofile:
    name: "My Custom Profile"
    description: "Custom module selection"
    estimated_time: "10 min"
    modules:
      - sfp_dnsresolve
      - sfp_ssl
      - sfp_whois
      # ... add more SF module names
```

---

## <i class="fa-solid fa-screwdriver-wrench"></i> Advanced Operations (Core Modules)

The newly introduced modules in the `/core` directory add support for compliance, auditing, OPSEC proxying, bulk scanning, and report labeling:

### <i class="fa-solid fa-scale-balanced"></i> Legal Disclaimer (`core/disclaimer.py`)
Ensures authorization compliance prior to execution. Before any scanning is performed, the user must consent to the legal terms:
- **State Preservation:** Stores a hashed consent identifier in `.disclaimer_accepted` for each user so validation is only required once.
- **Audit Integration:** Disclaimer acceptance is immediately recorded in the tamper-evident audit logs.

### <i class="fa-solid fa-shield-halved"></i> Allowed Scope Validation (`core/scope.py`)
Restricts scanning strictly to authorized targets to prevent accidental out-of-scope probes:
- **Scope File:** Defined in `scope.txt` (a default template is created automatically if missing).
- **Rule Syntax:** Supports domains (`example.com`), subdomains (`*.example.com`), IPs, subnet ranges/CIDRs (`10.0.0.0/8`), email patterns (`*@example.com`), and wildcards (`*`).
- **Safety Enforcement:** Blocks any scan attempting to probe a target not present in the allowed scope. An empty `scope.txt` defaults to allowing all targets for development convenience.

### <i class="fa-solid fa-file-signature"></i> Tamper-Evident Audit Logging (`core/audit.py`)
Maintains a cryptographic chain-of-custody logging all operations in `audit.log`:
- **Chained Hashing:** Each log entry (scan start, end, disclaimer acceptance) calculates a SHA-256 hash incorporating the previous entry's hash (`prev_hash`), making the log tamper-evident.
- **Verification Engine:** Features a `verify_chain()` utility that checks for log line modifications, insertions, or deletions.
- **File System Guard:** Dynamically locks file access (chmod 0444 read-only / 0644 read-write) to restrict manual modification.

### <i class="fa-solid fa-globe"></i> OPSEC Proxy & Tor Routing (`core/proxy.py`)
Secures network traffic and preserves anonymity during scans:
- **Tor Native Support:** Configures SOCKS5 and Tor client redirection (`socks5h://127.0.0.1:9050`).
- **Pre-flight Checks:** Verifies proxy/Tor availability via `check.torproject.org` and queries current exit IP via `api.ipify.org` before execution.
- **Proxy Configuration:** Automatically configures standard environment proxy variables (`OSINT_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`).

### <i class="fa-solid fa-traffic-light"></i> Traffic Light Protocol (`core/tlp.py`)
Applies data distribution labels to output reports based on the NATO/FIRST standards:
- **Classifications:** Supports `TLP:RED` (strictly confidential), `TLP:AMBER` (limited internal), `TLP:GREEN` (community-limited), and `TLP:WHITE` (public).
- **Visual Branding:** Generates HTML banners and footers embedded with correct color coding, operator metadata, and sharing restrictions.

### <i class="fa-solid fa-inbox"></i> Bulk Batch Scanning (`core/batch.py`)
Supports automated scanning of multiple targets:
- **Batch Files:** Loads targets from plain-text files (supports comments with `#`).
- **Control Flow:** Progresses sequentially, polling SpiderFoot REST API, enforcing delays between targets, and exporting HTML, JSON, and CSV reports.
- **CLI Visualization:** Renders a summary table using the [Rich](https://github.com/Textualize/rich) library with statuses, event counts, open ports, and breach indicators.

---

## <i class="fa-solid fa-shield-halved"></i> Legal & Ethics

Use this tool only against targets you have explicit permission to test.
Unauthorized scanning is illegal and unethical. The authors are not responsible for misuse.

---

*OSINT Engine v1.0 — Built for defenders, CTF players, and security researchers.*
