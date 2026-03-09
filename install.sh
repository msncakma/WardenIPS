#!/usr/bin/env bash
# WardenIPS — Auto Setup Script
# Usage: sudo bash install.sh
set -euo pipefail

INSTALL_DIR="/opt/wardenips"
DATA_DIR="/var/lib/wardenips"
LOG_DIR="/var/log/wardenips"
SERVICE_FILE="/etc/systemd/system/wardenips.service"
SUDOERS_FILE="/etc/sudoers.d/wardenips"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; exit 1; }

# ── Root check ──
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root.  Use: sudo bash install.sh"
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}   WardenIPS — Automated Installer${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# ── 1. System dependencies ──
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 rsync rsyslog python3-venv ipset iptables git > /dev/null

# ── 2. Create directories ──
log "Creating directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

# ── 3. Copy project files ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    log "Deploying WardenIPS to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    # Copy everything except venv, __pycache__, .git, data
    rsync -a --exclude='venv' --exclude='__pycache__' --exclude='.git' \
          --exclude='data' --exclude='*.pyc' \
          "$SCRIPT_DIR/" "$INSTALL_DIR/"
else
    log "Already in $INSTALL_DIR, skipping copy."
fi

# ── 4. Virtual environment ──
log "Setting up Python virtual environment..."
if [ ! -d "$INSTALL_DIR/venv" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi

# Existing venv can be stale/corrupted after OS upgrades, path changes,
# or copied projects. Recreate it automatically if python/pip is broken.
if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    warn "Existing venv is invalid (python missing). Recreating..."
    rm -rf "$INSTALL_DIR/venv"
    python3 -m venv "$INSTALL_DIR/venv"
fi

if ! "$INSTALL_DIR/venv/bin/python" -m pip --version >/dev/null 2>&1; then
    warn "Existing venv pip is broken. Recreating..."
    rm -rf "$INSTALL_DIR/venv"
    python3 -m venv "$INSTALL_DIR/venv"
fi

"$INSTALL_DIR/venv/bin/python" -m pip install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/python" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt"

# ── 5. Generate secure salt if still default ──
CURRENT_SALT=$(grep -oP 'salt:\s*"\K[^"]+' "$INSTALL_DIR/config.yaml" || true)
if [ "$CURRENT_SALT" = "YOUR-RANaDOM-SECURE-SALT-STRING-HERE" ] || \
   [ "$CURRENT_SALT" = "YOUR-RANDOM-SECURE-SALT-STRING-HERE" ]; then
    NEW_SALT=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s|salt:.*|salt: \"$NEW_SALT\"|" "$INSTALL_DIR/config.yaml"
    log "Generated new secure IP hashing salt."
else
    log "Custom salt already set, skipping."
fi

# ── 6. Install systemd service ──
log "Installing systemd service..."
cp "$INSTALL_DIR/wardenips.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable wardenips

# ── 7. Summary ──
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   WardenIPS installed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Install dir  : ${CYAN}$INSTALL_DIR${NC}"
echo -e "  Database     : ${CYAN}$DATA_DIR/warden.db${NC}"
echo -e "  Logs         : ${CYAN}$LOG_DIR/warden.log${NC}"
echo -e "  Service      : ${CYAN}wardenips.service (enabled)${NC}"
echo ""
echo -e "  ${YELLOW}IMPORTANT — Before starting:${NC}"
echo -e "    1. Edit ${CYAN}$INSTALL_DIR/config.yaml${NC}"
echo -e "       → Add your server IP to whitelist.ips"
echo -e "       → Verify the database salt was generated"
echo ""
echo -e "  ${GREEN}Start WardenIPS:${NC}"
echo -e "    sudo systemctl start wardenips"
echo ""
echo -e "  ${GREEN}Check status:${NC}"
echo -e "    sudo systemctl status wardenips"
echo -e "    sudo journalctl -u wardenips -f"
echo -e "    $INSTALL_DIR/venv/bin/python $INSTALL_DIR/main.py --status"
echo ""
