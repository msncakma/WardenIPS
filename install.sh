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
CLI_WRAPPER="/usr/local/bin/wardenips"
VERBOSE="${WARDENIPS_VERBOSE:-0}"
DEBUG_MODE="${WARDENIPS_DEBUG:-0}"
SERVICE_USER="${WARDENIPS_USER:-wardenips}"
SERVICE_GROUP="${WARDENIPS_GROUP:-wardenips}"
FIRST_SETUP_MODE="${WARDENIPS_FIRST_SETUP_MODE:-}"
APP_VERSION="unknown"
APP_AUTHOR="msncakma"
INSTALLED_VERSION=""
INSTALLED_AUTHOR=""
INSTALL_MODE="install"
PREVIOUS_SERVICE_ACTIVE="0"
PREVIOUS_SERVICE_ENABLED="0"
BOOTSTRAP_TOKEN=""
BOOTSTRAP_TOKEN_HASH=""
BOOTSTRAP_EXPIRES_AT=""

TMP_DIR=""
SOURCE_DIR=""
HAS_ADM_GROUP="0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { printf "%b\n" "${GREEN}[+]${NC} $1"; }
warn() { printf "%b\n" "${YELLOW}[!]${NC} $1"; }
error() { printf "%b\n" "${RED}[X]${NC} $1"; exit 1; }

is_verbose() {
    [ "$VERBOSE" = "1" ] || [ "$DEBUG_MODE" = "1" ]
}

run_quiet() {
    if is_verbose; then
        "$@"
    else
        "$@" >/dev/null 2>&1
    fi
}

if [ "$DEBUG_MODE" = "1" ]; then
    set -x
fi

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
        if is_verbose; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                acl ca-certificates curl git ipset iptables python3 python3-venv rsync rsyslog
        else
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                acl ca-certificates curl git ipset iptables python3 python3-venv rsync rsyslog \
                >/dev/null
        fi
        return
    fi

    error "Unsupported package manager. This installer currently supports apt-based systems."
}

detect_source_dir() {
    SCRIPT_PATH="$0"
    SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_PATH")" 2>/dev/null && pwd || pwd)"

    if [ -f "$SCRIPT_DIR/main.py" ] && [ -d "$SCRIPT_DIR/wardenips" ] && [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        SOURCE_DIR="$SCRIPT_DIR"
        return
    fi

    if [ -f "./main.py" ] && [ -d "./wardenips" ] && [ -f "./requirements.txt" ]; then
        SOURCE_DIR="$(pwd)"
        return
    fi

    TMP_DIR="$(mktemp -d)"
    SOURCE_DIR="$TMP_DIR/repo"
    log "Fetching WardenIPS from ${REPO_URL} (${REPO_BRANCH})..."
    if ! git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SOURCE_DIR"; then
        error "Failed to download repository from ${REPO_URL}"
    fi
}

detect_existing_install() {
    if [ -f "$INSTALL_DIR/wardenips/__init__.py" ]; then
        INSTALL_MODE="update"
        EXISTING_METADATA="$(python3 - "$INSTALL_DIR/wardenips/__init__.py" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
version_match = re.search(r'''^__version__\s*=\s*["']([^"']+)["']''', text, re.MULTILINE)
author_match = re.search(r'''^__author__\s*=\s*["']([^"']+)["']''', text, re.MULTILINE)
print((version_match.group(1) if version_match else "unknown") + "\n" + (author_match.group(1) if author_match else "unknown"))
PY
)"
        INSTALLED_VERSION="$(printf '%s\n' "$EXISTING_METADATA" | sed -n '1p')"
        INSTALLED_AUTHOR="$(printf '%s\n' "$EXISTING_METADATA" | sed -n '2p')"
        log "Existing WardenIPS installation detected: v$INSTALLED_VERSION ($INSTALLED_AUTHOR)"
    else
        log "No existing WardenIPS installation detected. Proceeding with a fresh install."
    fi

    if systemctl list-unit-files wardenips.service >/dev/null 2>&1; then
        if systemctl is-enabled wardenips >/dev/null 2>&1; then
            PREVIOUS_SERVICE_ENABLED="1"
        fi
        if systemctl is-active wardenips >/dev/null 2>&1; then
            PREVIOUS_SERVICE_ACTIVE="1"
        fi
    fi
}

prepare_update() {
    if [ "$INSTALL_MODE" != "update" ]; then
        return
    fi

    if [ "$PREVIOUS_SERVICE_ACTIVE" = "1" ]; then
        log "Stopping active WardenIPS service before update..."
        systemctl stop wardenips
    fi
}

prepare_bootstrap_token() {
    if [ "$INSTALL_MODE" = "update" ]; then
        return
    fi

    BOOTSTRAP_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

    BOOTSTRAP_METADATA="$(python3 - "$BOOTSTRAP_TOKEN" <<'PY'
from datetime import datetime, timedelta, timezone
import hashlib
import sys

token = sys.argv[1]
print(hashlib.sha256(token.encode("utf-8")).hexdigest())
print((datetime.now(timezone.utc) + timedelta(hours=24)).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
PY
)"
    BOOTSTRAP_TOKEN_HASH="$(printf '%s\n' "$BOOTSTRAP_METADATA" | sed -n '1p')"
    BOOTSTRAP_EXPIRES_AT="$(printf '%s\n' "$BOOTSTRAP_METADATA" | sed -n '2p')"
}

prompt_first_setup_mode() {
    if [ "$INSTALL_MODE" = "update" ]; then
        return
    fi

    if [ -n "$FIRST_SETUP_MODE" ]; then
        case "$FIRST_SETUP_MODE" in
            7d|14d)
                log "First-setup blocklist mode preset via env: $FIRST_SETUP_MODE"
                return
                ;;
            *)
                warn "Invalid WARDENIPS_FIRST_SETUP_MODE='$FIRST_SETUP_MODE'. Falling back to 7d."
                FIRST_SETUP_MODE="7d"
                return
                ;;
        esac
    fi

    if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        FIRST_SETUP_MODE="7d"
        log "No interactive terminal detected. Using recommended first-setup mode: 7d."
        return
    fi

    printf "%b\n" "${YELLOW}[?]${NC} First-setup blocklist mode"
    printf "%b\n" "    1) 7d  (recommended, lower false-positive risk)"
    printf "%b\n" "    2) 14d (broader initial coverage)"
    printf "%b" "    Select [1/2] (default: 1): "

    if [ -r /dev/tty ]; then
        read -r USER_MODE </dev/tty || USER_MODE=""
    else
        read -r USER_MODE || USER_MODE=""
    fi

    case "$USER_MODE" in
        2|14d|14D)
            FIRST_SETUP_MODE="14d"
            ;;
        *)
            FIRST_SETUP_MODE="7d"
            ;;
    esac

    log "Selected first-setup blocklist mode: $FIRST_SETUP_MODE"
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

load_app_metadata() {
    if [ ! -f "$INSTALL_DIR/wardenips/__init__.py" ]; then
        return
    fi

    APP_METADATA="$(python3 - "$INSTALL_DIR/wardenips/__init__.py" <<'PY'
from pathlib import Path
import re
import sys


text = Path(sys.argv[1]).read_text(encoding="utf-8")
version_match = re.search(r'''^__version__\s*=\s*["']([^"']+)["']''', text, re.MULTILINE)
author_match = re.search(r'''^__author__\s*=\s*["']([^"']+)["']''', text, re.MULTILINE)
version = version_match.group(1) if version_match else "unknown"
author = author_match.group(1) if author_match else "unknown"
print(f"{version}\n{author}")
PY
)"

    APP_VERSION="$(printf '%s\n' "$APP_METADATA" | sed -n '1p')"
    APP_AUTHOR="$(printf '%s\n' "$APP_METADATA" | sed -n '2p')"
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

    if is_verbose; then
        "$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip
        "$INSTALL_DIR/venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"
    else
        "$INSTALL_DIR/venv/bin/python" -m pip install --quiet --upgrade pip
        "$INSTALL_DIR/venv/bin/python" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt"
    fi
}

ensure_service_user() {
    log "Ensuring service account..."

    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        groupadd --system "$SERVICE_GROUP"
    fi

    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        useradd \
            --system \
            --gid "$SERVICE_GROUP" \
            --home-dir "$INSTALL_DIR" \
            --shell /usr/sbin/nologin \
            --comment "WardenIPS service account" \
            "$SERVICE_USER"
    fi

    if getent group adm >/dev/null 2>&1; then
        HAS_ADM_GROUP="1"
        usermod -a -G adm "$SERVICE_USER"
    fi
}

merge_config_template() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ] || [ ! -f "$INSTALL_DIR/config_backup.yaml" ]; then
        return
    fi

    if [ ! -f "$INSTALL_DIR/config.yaml.backup" ]; then
        log "Fresh install detected, no config merge needed."
        return
    fi

    MERGE_RESULT="$($INSTALL_DIR/venv/bin/python - "$INSTALL_DIR/config.yaml" "$INSTALL_DIR/config_backup.yaml" <<'PY'
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from pathlib import Path
import sys

import yaml


def merge_missing(current, template):
    changed = False
    if not isinstance(current, dict) or not isinstance(template, dict):
        return changed

    for key, value in template.items():
        if key not in current:
            current[key] = deepcopy(value)
            changed = True
            continue
        if isinstance(current.get(key), dict) and isinstance(value, dict):
            if merge_missing(current[key], value):
                changed = True
    return changed


config_path = Path(sys.argv[1])
template_path = Path(sys.argv[2])
original_text = config_path.read_text(encoding="utf-8")
current = yaml.safe_load(original_text) or {}
template = yaml.safe_load(template_path.read_text(encoding="utf-8")) or {}

if not isinstance(current, dict) or not isinstance(template, dict):
    print("invalid")
    raise SystemExit(0)

if not merge_missing(current, template):
    print("unchanged")
    raise SystemExit(0)

timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
backup_name = f"config.yaml.pre-update-{timestamp}.bak"
config_path.with_name(backup_name).write_text(original_text, encoding="utf-8")
config_path.write_text(
    yaml.safe_dump(current, sort_keys=False, allow_unicode=True),
    encoding="utf-8",
)
print(backup_name)
PY
)"

    case "$MERGE_RESULT" in
        unchanged)
            log "Config already contains the current template keys."
            ;;
        invalid)
            warn "Config merge skipped because config.yaml or config_backup.yaml is not a valid YAML mapping."
            ;;
        *)
            log "Merged new config keys from config_backup.yaml (backup: $INSTALL_DIR/$MERGE_RESULT)."
            ;;
    esac
}

configure_defaults() {
    if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
        error "config.yaml was not found after deployment."
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

    "$INSTALL_DIR/venv/bin/python" - "$INSTALL_DIR/config.yaml" "$FIRST_SETUP_MODE" <<'PY'
from pathlib import Path
import re
import sys


path = Path(sys.argv[1])
mode = sys.argv[2]
if mode not in {"7d", "14d"}:
    mode = "7d"
text = path.read_text(encoding='utf-8')
text, count = re.subn(
    r'(^[ \t]*mode:\s*)["\']?(?:7d|14d)["\']?(\s*(?:#.*)?)$',
    rf'\1"{mode}"\2',
    text,
    count=1,
    flags=re.MULTILINE,
)
if count:
    path.write_text(text, encoding='utf-8')
PY
    log "Configured first-setup blocklist mode: $FIRST_SETUP_MODE"

    if [ "$INSTALL_MODE" != "update" ] && [ -n "$BOOTSTRAP_TOKEN_HASH" ]; then
        "$INSTALL_DIR/venv/bin/python" - "$INSTALL_DIR/config.yaml" "$BOOTSTRAP_TOKEN_HASH" "$BOOTSTRAP_EXPIRES_AT" <<'PY'
from pathlib import Path
import re
import sys


path = Path(sys.argv[1])
token_hash = sys.argv[2]
expires_at = sys.argv[3]
text = path.read_text(encoding='utf-8')
text = re.sub(r'(^[ \t]*setup_required:\s*)false(\s*(?:#.*)?)$', r'\1true\2', text, count=1, flags=re.MULTILINE)
text = re.sub(r'(^[ \t]*token_hash:\s*).*(\s*(?:#.*)?)$', rf'\1"{token_hash}"\2', text, count=1, flags=re.MULTILINE)
text = re.sub(r'(^[ \t]*token_expires_at:\s*).*(\s*(?:#.*)?)$', rf'\1"{expires_at}"\2', text, count=1, flags=re.MULTILINE)
text = re.sub(r'(^[ \t]*username:\s*).*(\s*(?:#.*)?)$', r'\1""\2', text, count=1, flags=re.MULTILINE)
text = re.sub(r'(^[ \t]*password:\s*).*(\s*(?:#.*)?)$', r'\1""\2', text, count=1, flags=re.MULTILINE)
path.write_text(text, encoding='utf-8')
PY
        log "Prepared first-boot bootstrap token for admin enrollment."
    fi
}

configure_permissions() {
    log "Configuring ownership and permissions..."

    mkdir -p "$DATA_DIR" "$LOG_DIR"
    touch "$LOG_DIR/warden.log"

    chown -R root:"$SERVICE_GROUP" "$INSTALL_DIR"
    chmod -R g=rX,o= "$INSTALL_DIR"
    find "$INSTALL_DIR" -type d -exec chmod 750 {} +
    if [ -f "$INSTALL_DIR/config.yaml" ]; then
        chown "$SERVICE_USER":"$SERVICE_GROUP" "$INSTALL_DIR/config.yaml"
        chmod 660 "$INSTALL_DIR/config.yaml"
    fi
    if [ -f "$INSTALL_DIR/config_backup.yaml" ]; then
        chown "$SERVICE_USER":"$SERVICE_GROUP" "$INSTALL_DIR/config_backup.yaml"
        chmod 660 "$INSTALL_DIR/config_backup.yaml"
    fi
    if [ -f "$INSTALL_DIR/config.yaml.backup" ]; then
        chown "$SERVICE_USER":"$SERVICE_GROUP" "$INSTALL_DIR/config.yaml.backup"
        chmod 660 "$INSTALL_DIR/config.yaml.backup"
    fi

    chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"
    find "$DATA_DIR" "$LOG_DIR" -type d -exec chmod 750 {} +
    find "$DATA_DIR" "$LOG_DIR" -type f -exec chmod 640 {} +
}

grant_plugin_log_access() {
    SSH_LOG_PATH="$($INSTALL_DIR/venv/bin/python - "$INSTALL_DIR/config.yaml" <<'PY'
from pathlib import Path
import sys

import yaml


config_path = Path(sys.argv[1])
config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
print(config.get("plugins", {}).get("ssh", {}).get("log_path", "/var/log/auth.log"))
PY
)"

    if [ -z "$SSH_LOG_PATH" ]; then
        SSH_LOG_PATH="/var/log/auth.log"
    fi

    if [ -d "$(dirname "$SSH_LOG_PATH")" ] && command -v setfacl >/dev/null 2>&1; then
        setfacl -m "u:${SERVICE_USER}:rx" "$(dirname "$SSH_LOG_PATH")" || true
        setfacl -d -m "u:${SERVICE_USER}:rx" "$(dirname "$SSH_LOG_PATH")" || true
    fi

    if [ -f "$SSH_LOG_PATH" ]; then
        if command -v setfacl >/dev/null 2>&1; then
            setfacl -m "u:${SERVICE_USER}:r" "$SSH_LOG_PATH"
            log "Granted $SERVICE_USER read access to $SSH_LOG_PATH."
        else
            warn "setfacl is not available, relying on group-based access for $SSH_LOG_PATH."
        fi
    else
        warn "$SSH_LOG_PATH was not found during install. Default ACLs were prepared on $(dirname "$SSH_LOG_PATH") for future log creation."
    fi
}

download_geoip_database() {
    log "Downloading MaxMind GeoLite2-ASN database (from Loyalsoldier/geoip)..."
    
    ASSETS_DIR="/opt/wardenips/assets"
    GEOIP_URL="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-ASN.mmdb"
    GEOIP_FILE="$ASSETS_DIR/GeoLite2-ASN.mmdb"
    
    mkdir -p "$ASSETS_DIR"
    
    if [ -f "$GEOIP_FILE" ]; then
        warn "GeoLite2-ASN.mmdb already exists, skipping download."
        return
    fi
    
    if command -v curl >/dev/null 2>&1; then
        if ! run_quiet curl -fsSL -o "$GEOIP_FILE" "$GEOIP_URL"; then
            error "Failed to download GeoLite2-ASN.mmdb from GitHub. Check your internet connection."
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! run_quiet wget -q -O "$GEOIP_FILE" "$GEOIP_URL"; then
            error "Failed to download GeoLite2-ASN.mmdb from GitHub. Check your internet connection."
        fi
    else
        error "Neither curl nor wget found. Cannot download GeoLite2-ASN.mmdb. Install curl or wget and try again."
    fi
    
    # Verify file was downloaded correctly (should be ~10MB)
    if [ ! -f "$GEOIP_FILE" ] || [ ! -s "$GEOIP_FILE" ]; then
        error "GeoLite2-ASN.mmdb download failed or file is empty."
    fi
    
    chown "$SERVICE_USER":"$SERVICE_GROUP" "$GEOIP_FILE"
    chmod 640 "$GEOIP_FILE"
    log "GeoLite2-ASN.mmdb downloaded and configured."
}

install_cli_wrapper() {
    log "Installing CLI wrapper..."
    cat > "$CLI_WRAPPER" <<'EOF'
#!/bin/sh
set -eu

INSTALL_DIR="__INSTALL_DIR__"
CONFIG_FILE="$INSTALL_DIR/config.yaml"
PYTHON_BIN="$INSTALL_DIR/venv/bin/python"
MAIN_FILE="$INSTALL_DIR/main.py"
SERVICE_NAME="wardenips"

# Renkler (ANSI kod)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    printf "\n"
    printf "${CYAN}${BOLD}"
    printf "╔════════════════════════════════════════════╗\n"
    printf "║                                            ║\n"
    printf "║  %b   WardenIPS   %b              ║\n" "$BLUE" "$CYAN"
    printf "║                                            ║\n"
    printf "║     Autonomous Intrusion Protection        ║\n"
    printf "║                                            ║\n"
    printf "╚════════════════════════════════════════════╝\n"
    printf "${NC}\n"
}

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        exec "$@"
    fi

    if command -v sudo >/dev/null 2>&1; then
        exec sudo "$@"
    fi

    printf "${RED}✗ This command requires root or sudo.${NC}\n" >&2
    exit 1
}

usage() {
    print_banner
    printf "${GREEN}${BOLD}Usage:${NC} wardenips <command> [args]\n\n"
    printf "${BOLD}Core Commands:${NC}\n"
    printf "  ${CYAN}console${NC}         Run in console mode with direct logs (requires sudo)\n"
    printf "  ${CYAN}start${NC}           Start the WardenIPS service\n"
    printf "  ${CYAN}stop${NC}            Stop the WardenIPS service\n"
    printf "  ${CYAN}restart${NC}         Restart the WardenIPS service\n\n"
    printf "${BOLD}Status & Monitoring:${NC}\n"
    printf "  ${CYAN}status${NC}          Show service status\n"
    printf "  ${CYAN}logs${NC}            Stream live service logs\n"
    printf "  ${CYAN}summary${NC}         Display database statistics\n\n"
    printf "${BOLD}Configuration:${NC}\n"
    printf "  ${CYAN}config${NC}          Print configuration file path\n"
    printf "  ${CYAN}path${NC}            Print installation directory\n"
    printf "  ${CYAN}edit${NC}            Edit configuration (requires sudo)\n\n"
    printf "${BOLD}Utilities:${NC}\n"
    printf "  ${CYAN}version${NC}         Show WardenIPS version\n"
    printf "  ${CYAN}help${NC}            Show this help message\n\n"
}

case "${1:-help}" in
    help|-h|--help)
        usage
        ;;
    version)
        "$PYTHON_BIN" "$MAIN_FILE" --version
        ;;
    summary|status-summary)
        "$PYTHON_BIN" "$MAIN_FILE" --config "$CONFIG_FILE" --status
        ;;
    console)
        print_banner
        run_privileged "$PYTHON_BIN" "$MAIN_FILE" --config "$CONFIG_FILE"
        ;;
    start)
        run_privileged systemctl start "$SERVICE_NAME"
        printf "${GREEN}✓ WardenIPS service started${NC}\n"
        ;;
    stop)
        run_privileged systemctl stop "$SERVICE_NAME"
        printf "${YELLOW}✓ WardenIPS service stopped${NC}\n"
        ;;
    restart)
        run_privileged systemctl restart "$SERVICE_NAME"
        printf "${GREEN}✓ WardenIPS service restarted${NC}\n"
        ;;
    status)
        run_privileged systemctl status "$SERVICE_NAME"
        ;;
    logs)
        run_privileged journalctl -u "$SERVICE_NAME" -f -o cat
        ;;
    config)
        printf "%s\n" "$CONFIG_FILE"
        ;;
    path)
        printf "%s\n" "$INSTALL_DIR"
        ;;
    edit)
        run_privileged env EDITOR="${EDITOR:-nano}" sh -c "exec \"\$EDITOR\" \"$CONFIG_FILE\""
        ;;
    *)
        printf "${RED}✗ Unknown command: ${BOLD}$1${NC}\n" >&2
        printf "Run '${CYAN}wardenips help${NC}' for available commands.\n" >&2
        exit 1
        ;;
esac
EOF
    python3 - "$CLI_WRAPPER" "$INSTALL_DIR" <<'PY'
from pathlib import Path
import sys


wrapper_path = Path(sys.argv[1])
install_dir = sys.argv[2]
text = wrapper_path.read_text(encoding="utf-8")
text = text.replace("__INSTALL_DIR__", install_dir)
wrapper_path.write_text(text, encoding="utf-8")
PY
    chmod +x "$CLI_WRAPPER"
}

install_service() {
    log "Installing systemd service..."
    cp "$INSTALL_DIR/wardenips.service" "$SERVICE_FILE"
    python3 - "$SERVICE_FILE" "$INSTALL_DIR" "$SERVICE_USER" "$SERVICE_GROUP" "$HAS_ADM_GROUP" <<'PY'
from pathlib import Path
import sys


service_path = Path(sys.argv[1])
install_dir = sys.argv[2]
service_user = sys.argv[3]
service_group = sys.argv[4]
has_adm_group = sys.argv[5] == "1"
text = service_path.read_text(encoding="utf-8")
text = text.replace("__SERVICE_USER__", service_user)
text = text.replace("__SERVICE_GROUP__", service_group)
text = text.replace("__INSTALL_DIR__", install_dir)
text = text.replace(
    "__SUPPLEMENTARY_GROUPS__",
    "SupplementaryGroups=adm" if has_adm_group else "",
)
service_path.write_text(text, encoding="utf-8")
PY
    systemctl daemon-reload
    run_quiet systemctl enable wardenips

    if [ "$AUTOSTART" = "1" ] || [ "$PREVIOUS_SERVICE_ACTIVE" = "1" ]; then
        log "Starting WardenIPS service..."
        systemctl restart wardenips
    else
        warn "Autostart is disabled by default for safety. Set WARDENIPS_AUTOSTART=1 to start immediately."
    fi
}

install_dependencies
detect_source_dir
detect_existing_install
prompt_first_setup_mode
prepare_update
prepare_bootstrap_token
deploy_files "$SOURCE_DIR"
load_app_metadata
ensure_service_user
ensure_venv
merge_config_template
configure_defaults
configure_permissions
grant_plugin_log_access
download_geoip_database
install_cli_wrapper
install_service

if [ "$ENABLE_DASHBOARD" = "1" ]; then
    DASHBOARD_SUMMARY="http://127.0.0.1:7680/"
else
    DASHBOARD_SUMMARY="disabled"
fi

if [ "$AUTOSTART" = "1" ] || [ "$PREVIOUS_SERVICE_ACTIVE" = "1" ]; then
    SERVICE_STATE_SUMMARY="enabled and started"
else
    SERVICE_STATE_SUMMARY="enabled, not started"
fi

printf "\n"
printf "%b\n" "${GREEN}============================================${NC}"
printf "%b\n" "${GREEN}   WardenIPS Installation Complete${NC}"
printf "%b\n" "${GREEN}============================================${NC}"
printf "%b\n" "  ${GREEN}Deployment Summary${NC}"
printf "%b\n" "    Mode           : ${CYAN}$INSTALL_MODE${NC}"
if [ "$INSTALL_MODE" = "update" ]; then
    printf "%b\n" "    Previous Ver.  : ${CYAN}v$INSTALLED_VERSION${NC}"
fi
printf "%b\n" "    Version        : ${CYAN}v$APP_VERSION${NC}"
printf "%b\n" "    Maintainer     : ${CYAN}$APP_AUTHOR${NC}"
printf "%b\n" "    Install Path   : ${CYAN}$INSTALL_DIR${NC}"
printf "%b\n" "    Database       : ${CYAN}$DATA_DIR/warden.db${NC}"
printf "%b\n" "    Log File       : ${CYAN}$LOG_DIR/warden.log${NC}"
printf "%b\n" "    Dashboard      : ${CYAN}$DASHBOARD_SUMMARY${NC}"
printf "%b\n" "    Service Unit   : ${CYAN}wardenips.service${NC}"
printf "%b\n" "    Service User   : ${CYAN}$SERVICE_USER${NC}"
printf "%b\n" "    Service State  : ${CYAN}$SERVICE_STATE_SUMMARY${NC}"
if [ "$INSTALL_MODE" != "update" ]; then
    printf "%b\n" "    First-Setup    : ${CYAN}$FIRST_SETUP_MODE${NC}"
fi
if [ "$INSTALL_MODE" = "update" ]; then
    printf "%b\n" "    Config Merge   : ${CYAN}Existing config preserved, missing template keys merged automatically${NC}"
else
    printf "%b\n" "    Bootstrap Flow : ${CYAN}First-boot setup required before /admin can be used${NC}"
fi
printf "\n"
if [ "$INSTALL_MODE" != "update" ] && [ -n "$BOOTSTRAP_TOKEN" ]; then
    printf "%b\n" "  ${YELLOW}First-Boot Bootstrap${NC}"
    printf "%b\n" "    Setup URL      : ${CYAN}http://127.0.0.1:7680/setup${NC}"
    printf "%b\n" "    Bootstrap Token: ${CYAN}$BOOTSTRAP_TOKEN${NC}"
    printf "%b\n" "    Expires At     : ${CYAN}$BOOTSTRAP_EXPIRES_AT${NC}"
fi
printf "%b\n" "  ${YELLOW}Recommended Next Steps${NC}"
printf "%b\n" "    1. Review ${CYAN}$INSTALL_DIR/config.yaml${NC}"
printf "%b\n" "    2. Update whitelist.ips with your trusted addresses"
printf "%b\n" "    3. Verify plugin log paths and notification credentials"
printf "%b\n" "    4. Open /admin and review release notices after login"
printf "%b\n" "  ${GREEN}Quick Start Commands${NC}"
printf "%b\n" "    wardenips start              Start the service"
printf "%b\n" "    wardenips status             Show service status"
printf "%b\n" "    wardenips logs               Show live logs (tail -f)"
printf "%b\n" "    wardenips status             Database summary"
printf "%b\n" "    wardenips config             Show config file path"
printf "%b\n" "    wardenips shell              Open install directory shell"
printf "%b\n" ""
