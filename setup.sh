#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║         OSINT ENGINE - Standalone Setup Script           ║
# ║         by N-EX / Fujimaru  |  Kalimantan Timur          ║
# ╚══════════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BANNER="
${CYAN}╔═══════════════════════════════════════════════════════╗
║   ██████╗ ███████╗██╗███╗   ██╗████████╗            ║
║  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝            ║
║  ██║   ██║███████╗██║██╔██╗ ██║   ██║               ║
║  ██║   ██║╚════██║██║██║╚██╗██║   ██║               ║
║  ╚██████╔╝███████║██║██║ ╚████║   ██║               ║
║   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ENGINE v1.0 ║
╚═══════════════════════════════════════════════════════╝${NC}
"

echo -e "$BANNER"
echo -e "${CYAN}[*] Setting up OSINT Engine standalone environment...${NC}"
echo ""

# ── Check Python ──────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}[!] Python3 not found. Install it first.${NC}"
  exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}[+] Python ${PY_VER} detected${NC}"

# ── Create venv ───────────────────────────────────────────────
VENV_DIR="$(pwd)/.venv"
if [ ! -d "$VENV_DIR" ]; then
  echo -e "${CYAN}[*] Creating virtual environment...${NC}"
  python3 -m venv "$VENV_DIR"
  echo -e "${GREEN}[+] venv created at .venv/${NC}"
else
  echo -e "${YELLOW}[~] venv already exists, skipping${NC}"
fi

source "$VENV_DIR/bin/activate"

# ── Install Python deps ───────────────────────────────────────
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip install --quiet --upgrade pip
pip install --quiet \
  rich \
  requests \
  pyyaml \
  click \
  jinja2 \
  dnspython \
  whois \
  shodan \
  ipwhois \
  colorama \
  tabulate

echo -e "${GREEN}[+] Python deps installed${NC}"

# ── Clone SpiderFoot ──────────────────────────────────────────
SF_DIR="$(pwd)/tools/spiderfoot"
if [ ! -d "$SF_DIR" ]; then
  echo -e "${CYAN}[*] Cloning SpiderFoot...${NC}"
  git clone --quiet --depth=1 https://github.com/smicallef/spiderfoot.git "$SF_DIR"
  echo -e "${GREEN}[+] SpiderFoot cloned${NC}"
else
  echo -e "${YELLOW}[~] SpiderFoot already exists, checking for updates...${NC}"
  cd "$SF_DIR" && git pull --quiet && cd - > /dev/null
fi

# ── Install SpiderFoot deps ───────────────────────────────────
echo -e "${CYAN}[*] Installing SpiderFoot requirements...${NC}"
pip install --quiet -r "$SF_DIR/requirements.txt" || true
echo -e "${GREEN}[+] SpiderFoot deps installed${NC}"

# ── Create SpiderFoot DB dir ──────────────────────────────────
mkdir -p "$(pwd)/tools/spiderfoot/var"

# ── Make engine.py executable ─────────────────────────────────
chmod +x "$(pwd)/engine.py"

# ── Create launch wrapper ─────────────────────────────────────
cat > "$(pwd)/osint" << 'WRAPPER'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/.venv/bin/activate"
python3 "$DIR/engine.py" "$@"
WRAPPER
chmod +x "$(pwd)/osint"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗"
echo -e "║   ✓  OSINT Engine is ready to use!       ║"
echo -e "╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Run with:  ${CYAN}./osint --help${NC}"
echo -e "  Or:        ${CYAN}./osint scan -t example.com${NC}"
echo ""
