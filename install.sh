#!/bin/sh
# WardenIPS — Bootstrap Installer
# Supports both local execution and curl | sh style remote execution.
set -eu

INSTALL_DIR="${INSTALL_DIR:-/opt/wardenips}"
DATA_DIR="${DATA_DIR:-/var/lib/wardenips}"
LOG_DIR="${LOG_DIR:-/var/log/wardenips}"
SERVICE_FILE="/etc/systemd/system/wardenips.service"
REPO_URL="${WARDENIPS_REPO_URL:-https://github.com/msncakma/WardenIPS.git}"
REPO_BRANCH="${WARDENIPS_REPO_BRANCH:-master}"
AUTOSTART="${WARDENIPS_AUTOSTART:-0}"
ENABLE_DASHBOARD="${WARDENIPS_ENABLE_DASHBOARD:-1}"

TMP_DIR=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { printf "%b\n" "${GREEN}[+]${NC} $1"; }
warn() { printf "%b\n" "${YELLOW}[!]${NC} $1"; }
error() { printf "%b\n" "${RED}[X]${NC} $1"; exit 1; }

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
    error "This installer must run as root. Use: sudo sh install.sh"
fi

printf "\n"
printf "%b\n" "${CYAN}============================================${NC}"
printf "%b\n" "${CYAN}   WardenIPS — Automated Installer${NC}"
printf "%b\n" "${CYAN}============================================${NC}"
printf "\n"

install_dependencies() {
    if command -v apt-get >/dev/null 2>&1; then
        log "Installing system dependencies..."
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            ca-certificates curl git ipset iptables python3 python3-venv rsync rsyslog \
            >/dev/null
        return
    fi

    error "Unsupported package manager. This installer currently supports apt-based systems."
}

detect_source_dir() {
    SCRIPT_PATH="$0"
    SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_PATH")" 2>/dev/null && pwd || pwd)"

    if [ -f "$SCRIPT_DIR/main.py" ] && [ -d "$SCRIPT_DIR/wardenips" ] && [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        printf "%s" "$SCRIPT_DIR"
        return
    fi

    if [ -f "./main.py" ] && [ -d "./wardenips" ] && [ -f "./requirements.txt" ]; then
        printf "%s" "$(pwd)"
        return
    fi

    TMP_DIR="$(mktemp -d)"
    printf "%b\n" "${GREEN}[+]${NC} Fetching WardenIPS from ${REPO_URL} (${REPO_BRANCH})..." >&2
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$TMP_DIR/repo" >/dev/null 2>&1 || \
        error "Failed to download repository from ${REPO_URL}"
    printf "%s" "$TMP_DIR/repo"
}

deploy_files() {
    SOURCE_DIR="$1"

    log "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"

    if [ -f "$INSTALL_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/config.yaml" "$INSTALL_DIR/config.yaml.backup"
        log "Existing config preserved as $INSTALL_DIR/config.yaml.backup"
        RSYNC_CONFIG_EXCLUDE="--exclude=config.yaml"
    else
        RSYNC_CONFIG_EXCLUDE=""
    fi

    if [ "$SOURCE_DIR" = "$INSTALL_DIR" ]; then
        log "Already running from $INSTALL_DIR, skipping file copy."
        return
    fi

    log "Deploying files to $INSTALL_DIR..."
    # shellcheck disable=SC2086
    rsync -a $RSYNC_CONFIG_EXCLUDE \
        --exclude='venv' \
        --exclude='__pycache__' \
        --exclude='.git' \
        --exclude='data' \
        --exclude='*.pyc' \
        "$SOURCE_DIR/" "$INSTALL_DIR/"
}

ensure_venv() {
    log "Setting up Python virtual environment..."

    if [ ! -d "$INSTALL_DIR/venv" ]; then
        python3 -m venv "$INSTALL_DIR/venv"
    fi

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
}

configure_defaults() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        error "config.yaml was not found after deployment."
    fi

    CURRENT_SALT="$(sed -n 's/^[[:space:]]*salt:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALL_DIR/config.yaml" | head -n 1)"
    if [ "$CURRENT_SALT" = "YOUR-RANaDOM-SECURE-SALT-STRING-HERE" ] || \
       [ "$CURRENT_SALT" = "YOUR-RANDOM-SECURE-SALT-STRING-HERE" ] || \
       [ -z "$CURRENT_SALT" ]; then
        NEW_SALT="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
        python3 - "$INSTALL_DIR/config.yaml" "$NEW_SALT" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
salt = sys.argv[2]
text = path.read_text(encoding='utf-8')
for old in (
    'salt: "YOUR-RANaDOM-SECURE-SALT-STRING-HERE"',
    'salt: "YOUR-RANDOM-SECURE-SALT-STRING-HERE"',
):
    text = text.replace(old, f'salt: "{salt}"')
path.write_text(text, encoding='utf-8')
PY
        log "Generated a secure IP hashing salt."
    else
        log "Custom IP hashing salt already present, skipping."
    fi

    if [ "$ENABLE_DASHBOARD" = "1" ]; then
        python3 - "$INSTALL_DIR/config.yaml" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
text = re.sub(
    r'(dashboard:\s*\n(?:[ \t].*\n)*?[ \t]*enabled:\s*)false',
    r'\1true',
    text,
    count=1,
)
path.write_text(text, encoding='utf-8')
PY
        log "Enabled dashboard by default on 127.0.0.1:7680."
    fi
}

install_service() {
    log "Installing systemd service..."
    cp "$INSTALL_DIR/wardenips.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable wardenips >/dev/null 2>&1

    if [ "$AUTOSTART" = "1" ]; then
        log "Starting WardenIPS service..."
        systemctl restart wardenips
    else
        warn "Autostart is disabled by default for safety. Set WARDENIPS_AUTOSTART=1 to start immediately."
    fi
}

SOURCE_DIR="$(detect_source_dir)"
install_dependencies
deploy_files "$SOURCE_DIR"
ensure_venv
configure_defaults
install_service

printf "\n"
printf "%b\n" "${GREEN}============================================${NC}"
printf "%b\n" "${GREEN}   WardenIPS installed successfully!${NC}"
printf "%b\n" "${GREEN}============================================${NC}"
printf "\n"
printf "%b\n" "  Install dir  : ${CYAN}$INSTALL_DIR${NC}"
printf "%b\n" "  Database     : ${CYAN}$DATA_DIR/warden.db${NC}"
printf "%b\n" "  Logs         : ${CYAN}$LOG_DIR/warden.log${NC}"
printf "%b\n" "  Dashboard    : ${CYAN}http://127.0.0.1:7680/${NC}"
printf "%b\n" "  Service      : ${CYAN}wardenips.service${NC}"
printf "\n"
printf "%b\n" "  ${YELLOW}Before production use:${NC}"
printf "%b\n" "    1. Review ${CYAN}$INSTALL_DIR/config.yaml${NC}"
printf "%b\n" "    2. Add your server/home IPs to whitelist.ips"
printf "%b\n" "    3. Validate plugin log paths"
printf "%b\n" "    4. Start the service when ready"
printf "\n"
printf "%b\n" "  ${GREEN}Start manually:${NC}"
printf "%b\n" "    sudo systemctl start wardenips"
printf "%b\n" "    sudo systemctl status wardenips"
printf "%b\n" "    sudo journalctl -u wardenips -f"
printf "\n"
printf "%b\n" "  ${GREEN}One-line install:${NC}"
printf "%b\n" "    sh -c \"\$(curl -fsSL https://raw.githubusercontent.com/msncakma/WardenIPS/master/install.sh)\""
printf "\n"
