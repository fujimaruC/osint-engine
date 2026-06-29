# ⚡ OSINT Engine

> **Gather intelligence on any domain, IP, email, or username — all from your terminal.**
> No hacking skills required. Just point it at a target and let it work.
>
> *by N-EX / Fujimaru | Kalimantan Timur*

---

## 🤔 What is this?

**OSINT Engine** is a tool that automatically searches the internet for publicly available information about a target — such as a website, an IP address, an email address, or a username.

Think of it as a **super-powered Google search** that looks across dozens of databases, security registries, DNS records, and leak archives — and compiles everything into a clean report.

**What can it find?**

| 🔍 You give it… | 📋 It can tell you… |
|-----------------|---------------------|
| A domain (`example.com`) | Who owns it, where it's hosted, subdomains, open ports, SSL cert history, archived pages |
| An IP address (`8.8.8.8`) | What services are running, geographic location, abuse reports, ASN/ISP info |
| An email (`user@example.com`) | Data breach history, linked accounts, PGP keys, social profiles |
| A username (`n-ex`) | Accounts on GitHub, Twitter, Reddit, Keybase, Gravatar, Pastebin leaks |

> ⚠️ **Only use this on targets you own or have explicit permission to investigate.**
> Unauthorized scanning is illegal. This tool is for defenders, security researchers, and CTF players only.

---

## ✅ Requirements

Before you start, make sure you have the following installed:

- **Python 3.10 or newer** — [Download here](https://www.python.org/downloads/)
- **git** — [Download here](https://git-scm.com/)
- An internet connection

> 💡 On Linux/macOS these are usually already installed. Check with `python3 --version` and `git --version`.

---

## 🚀 Getting Started (First Time Setup)

Open your terminal and follow these 3 steps:

```bash
# Step 1 — Go into the project folder
cd osint-engine

# Step 2 — Run the automatic setup script
#          (This installs everything — takes about 1–2 minutes)
chmod +x setup.sh && ./setup.sh

# Step 3 — Run your first scan!
./osint scan -t example.com -p quick
```

That's it. The tool will start scanning and save a report when it's done.

---

## 📖 Basic Usage

All commands start with `./osint`. Here are the most common ones:

### 🔎 Scanning a Target

```bash
# Scan a website (quick scan — done in ~1-5 minutes)
./osint scan -t example.com -p quick

# Scan a website (full passive — done in ~5-20 minutes, no active probing)
./osint scan -t example.com -p passive

# Scan a website (deep active — ports, banners, crawling — 20-60 minutes)
./osint scan -t example.com -p deep

# Scan an IP address
./osint scan -t 192.168.1.1 -p quick

# Scan a public IP (e.g., Google's DNS)
./osint scan -t 8.8.8.8 -p passive

# Investigate an email address
./osint scan -t user@company.com -p email

# Track a username across the internet
./osint scan -t "johndoe" -p username

# Scan a CTF or bug bounty target (optimized recon)
./osint scan -t target.ctf.com -p ctf
```

### 🧙 Interactive Wizard (Recommended for Beginners)

Not sure which options to pick? Use the guided wizard:

```bash
# Launch the step-by-step interactive wizard
./osint scan --interactive

# Short version — same thing
./osint scan -i
```

The wizard will ask you what you want to scan, pick a profile, and walk you through it.

---

## 🎯 Scan Profiles Explained

A **profile** controls *how much* the tool scans. Pick based on how much time you have and how noisy you want to be.

| Profile | What it does | ⏱️ Time | 🔊 Noise Level |
|---------|-------------|---------|---------------|
| `quick` | DNS, WHOIS, SSL only — bare basics | 1–5 min | 🟢 Silent |
| `passive` | All passive sources — no direct contact with target | 5–20 min | 🟢 Silent |
| `deep` | Port scanning, banner grabbing, web crawling | 20–60 min | 🟡 Moderate |
| `full` | Every single module — kitchen sink | 60–180 min | 🔴 Loud |
| `ctf` | Tuned for CTF challenges and bug bounties | 10–30 min | 🟡 Moderate |
| `email` | Focused on email + breach data + social | 5–15 min | 🟢 Silent |
| `username` | Tracks a username across social platforms | 5–15 min | 🟢 Silent |

```bash
# See all available profiles in your terminal
./osint profiles
```

---

## 📦 More Useful Commands

### 📊 Check Status & Active Scans

```bash
# See if the backend is running and list recent scans
./osint status
```

### 📋 Get Results from a Previous Scan

```bash
# Replace <scan_id> with the ID shown after your scan starts
./osint results <scan_id>

# Example:
./osint results abc123xyz
```

### 🛑 Stop a Running Scan

```bash
# Stop a scan that's in progress
./osint stop <scan_id>

# Example:
./osint stop abc123xyz
```

### 📄 Control Report Formats

By default, reports are saved as HTML, JSON, and CSV. You can skip formats you don't need:

```bash
# Save only HTML report (skip CSV and JSON)
./osint scan -t example.com --no-csv --no-json

# Save only CSV (good for importing to Excel or Google Sheets)
./osint scan -t example.com --no-html --no-json

# Save only JSON (for developers or scripting)
./osint scan -t example.com --no-html --no-csv
```

---

## 📂 Where are my reports?

Reports are saved automatically in the `./reports/` folder inside the project directory.

```
osint-engine/
└── reports/
    ├── example.com_2024-01-15_quick.html   ← Open this in your browser
    ├── example.com_2024-01-15_quick.json   ← Full data in JSON format
    └── example.com_2024-01-15_quick.csv    ← Import to Excel/Sheets
```

| File Type | Best for… |
|-----------|-----------|
| `.html` | Reading in your browser — dark theme, searchable, interactive |
| `.json` | Developers or automated processing |
| `.csv` | Importing into Excel, Google Sheets, or databases |

> 💡 **Tip:** Just double-click the `.html` file to open it in your browser — no server needed.

---

## 🔑 Optional: Add API Keys for Better Results

The tool works **without any API keys** — but adding free keys unlocks more modules and deeper results.

### How to set up keys

```bash
# Step 1 — Copy the template
cp config.yaml.example config.yaml

# Step 2 — Open it in a text editor
nano config.yaml
# or on macOS:
open -e config.yaml
```

Then fill in any keys you have. Each line has a link to where you can get a free key:

| Service | What it adds | Free Tier? |
|---------|-------------|------------|
| [Shodan](https://account.shodan.io/) | Open ports & services on any IP | ✅ Yes |
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | Malware & threat intelligence | ✅ Yes |
| [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | Email breach history | 💳 Paid |
| [Hunter.io](https://hunter.io/api-keys) | Email discovery for domains | ✅ Yes (50/mo) |
| [AbuseIPDB](https://www.abuseipdb.com/account/api) | IP abuse reports | ✅ Yes |
| [AlienVault OTX](https://otx.alienvault.com/api) | Threat intelligence | ✅ Yes |
| [URLScan.io](https://urlscan.io/user/) | Website scan history | ✅ Yes |
| [SecurityTrails](https://securitytrails.com/app/account/credentials) | DNS history | ✅ Yes (50/mo) |

> 💡 You don't need all of them. Even 2–3 keys will significantly improve results.

---

## 🌐 Privacy Mode (Scanning Anonymously via Tor)

If you want to hide your IP while scanning, you can route scans through **Tor**:

```bash
# First, install Tor (Linux)
sudo apt install tor && sudo systemctl start tor

# Then scan through Tor
./osint scan -t example.com -p passive --tor

# Check your exit IP before scanning
./osint scan -t example.com --check-proxy
```

> ⚠️ Tor mode significantly slows down scans. Only use it when anonymity is important.

---

## 📦 Batch Scanning (Multiple Targets at Once)

You can scan a list of targets from a text file:

```bash
# Create a targets file (one target per line)
cat > targets.txt << EOF
example.com
testsite.org
192.168.1.1
user@example.com
EOF

# Scan all targets with the passive profile
./osint scan --batch targets.txt -p passive

# Scan all targets with the quick profile
./osint scan --batch targets.txt -p quick
```

> 💡 Lines starting with `#` in the targets file are treated as comments and skipped.

---

## 📁 Project Structure (For the Curious)

```
osint-engine/
├── engine.py              ← The brain of the tool
├── setup.sh               ← First-time setup script
├── osint                  ← The command you run (./osint)
├── requirements.txt       ← Python package list
├── config.yaml.example    ← Copy this to config.yaml for API keys
│
├── core/
│   ├── profiles.py        ← Manages scan profiles
│   ├── reporter.py        ← Generates your HTML/JSON/CSV reports
│   ├── batch.py           ← Multi-target batch scanning
│   ├── proxy.py           ← Tor/proxy anonymity support
│   ├── audit.py           ← Scan history logging
│   ├── scope.py           ← Target whitelist/restriction
│   ├── disclaimer.py      ← Legal consent check
│   └── tlp.py             ← Report classification labels
│
├── profiles/
│   └── profiles.yaml      ← Edit this to customize scan profiles
│
├── reports/               ← Your scan reports appear here
└── tools/
    └── spiderfoot/        ← The scanning engine (auto-installed)
```

---

## ❓ Troubleshooting

**Setup failed / permission denied?**
```bash
chmod +x setup.sh && ./setup.sh
```

**`./osint` command not found?**
```bash
# Make the wrapper executable
chmod +x osint
```

**Scan takes too long?**
```bash
# Use a faster profile
./osint scan -t example.com -p quick

# Or stop it and try a lighter option
./osint stop <scan_id>
```

**Backend not starting?**
```bash
# Check status and see error details
./osint status

# Re-run setup to fix the SpiderFoot installation
./setup.sh
```

**Want to restart fresh?**
```bash
# Re-run setup (safe — won't delete your reports or config)
./setup.sh
```

---

## 🛡️ Legal & Ethics

> [!CAUTION]
> **Only scan targets you own or have written permission to test.**
> Running OSINT scans against targets without authorization may violate computer crime laws in your country (e.g., CFAA in the US, Computer Misuse Act in the UK).
> The authors of this tool are **not responsible** for any misuse.

**Acceptable use:**
- 🏠 Domains and servers you own
- 🐛 Bug bounty programs (within their defined scope)
- 🎮 CTF (Capture The Flag) challenge targets
- 🔬 Security research on test environments
- 🔍 Investigating your own digital footprint

---

## 👏 Credits

Built on top of [SpiderFoot](https://github.com/smicallef/spiderfoot) — the open-source OSINT automation platform.

Wrapper, CLI, profiles, and reporting by **N-EX / Fujimaru** — Kalimantan Timur.

---

*OSINT Engine v1.0 — Built for defenders, CTF players, and security researchers.*
