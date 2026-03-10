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
APP_VERSION="unknown"
APP_AUTHOR="unknown"

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

configure_permissions() {
    log "Configuring ownership and permissions..."

    mkdir -p "$DATA_DIR" "$LOG_DIR"
    touch "$LOG_DIR/warden.log"

    chown -R root:"$SERVICE_GROUP" "$INSTALL_DIR"
    chmod -R g=rX,o= "$INSTALL_DIR"
    find "$INSTALL_DIR" -type d -exec chmod 750 {} +

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

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        exec "$@"
    fi

    if command -v sudo >/dev/null 2>&1; then
        exec sudo "$@"
    fi

    printf "This command requires root or sudo.\n" >&2
    exit 1
}

run_privileged_shell() {
    if [ "$(id -u)" -eq 0 ]; then
        cd "$INSTALL_DIR"
        exec "${SHELL:-/bin/sh}"
    fi

    if command -v sudo >/dev/null 2>&1; then
        exec sudo env INSTALL_DIR="$INSTALL_DIR" WRAPPER_SHELL="${SHELL:-/bin/sh}" sh -c 'cd "$INSTALL_DIR" && exec "$WRAPPER_SHELL"'
    fi

    printf "This command requires root or sudo.\n" >&2
    exit 1
}

usage() {
    printf "WardenIPS command wrapper\n"
    printf "Usage: wardenips <command> [args]\n\n"
    printf "Commands:\n"
    printf "  version         Show installed version\n"
    printf "  status          Show WardenIPS database summary\n"
    printf "  start           Start the systemd service\n"
    printf "  stop            Stop the systemd service\n"
    printf "  restart         Restart the systemd service\n"
    printf "  service-status  Show systemd service status\n"
    printf "  logs            Tail service logs\n"
    printf "  config          Print config path\n"
    printf "  path            Print install path\n"
    printf "  ls              List install directory\n"
    printf "  shell           Open a shell in the install directory\n"
    printf "  run [args]      Run main.py directly with the installed config\n"
}

case "${1:-help}" in
    help|-h|--help)
        usage
        ;;
    version)
        run_privileged "$PYTHON_BIN" "$MAIN_FILE" --version
        ;;
    status)
        run_privileged "$PYTHON_BIN" "$MAIN_FILE" --config "$CONFIG_FILE" --status
        ;;
    start)
        run_privileged systemctl start "$SERVICE_NAME"
        ;;
    stop)
        run_privileged systemctl stop "$SERVICE_NAME"
        ;;
    restart)
        run_privileged systemctl restart "$SERVICE_NAME"
        ;;
    service-status)
        run_privileged systemctl status "$SERVICE_NAME"
        ;;
    logs)
        run_privileged journalctl -u "$SERVICE_NAME" -f
        ;;
    config)
        printf "%s\n" "$CONFIG_FILE"
        ;;
    path)
        printf "%s\n" "$INSTALL_DIR"
        ;;
    ls)
        run_privileged ls -la "$INSTALL_DIR"
        ;;
    shell)
        run_privileged_shell
        ;;
    run)
        shift
        run_privileged "$PYTHON_BIN" "$MAIN_FILE" --config "$CONFIG_FILE" "$@"
        ;;
    *)
        run_privileged "$PYTHON_BIN" "$MAIN_FILE" --config "$CONFIG_FILE" "$@"
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

    if [ "$AUTOSTART" = "1" ]; then
        log "Starting WardenIPS service..."
        systemctl restart wardenips
    else
        warn "Autostart is disabled by default for safety. Set WARDENIPS_AUTOSTART=1 to start immediately."
    fi
}

install_dependencies
detect_source_dir
deploy_files "$SOURCE_DIR"
load_app_metadata
ensure_service_user
ensure_venv
merge_config_template
configure_defaults
configure_permissions
grant_plugin_log_access
install_cli_wrapper
install_service

if [ "$ENABLE_DASHBOARD" = "1" ]; then
    DASHBOARD_SUMMARY="http://127.0.0.1:7680/"
else
    DASHBOARD_SUMMARY="disabled"
fi

if [ "$AUTOSTART" = "1" ]; then
    SERVICE_STATE_SUMMARY="enabled and started"
else
    SERVICE_STATE_SUMMARY="enabled, not started"
fi

printf "\n"
printf "%b\n" "${GREEN}============================================${NC}"
printf "%b\n" "${GREEN}   WardenIPS Installation Complete${NC}"
printf "%b\n" "${GREEN}============================================${NC}"
printf "\n"
printf "%b\n" "  ${GREEN}Deployment Summary${NC}"
printf "%b\n" "    Version        : ${CYAN}v$APP_VERSION${NC}"
printf "%b\n" "    Maintainer     : ${CYAN}$APP_AUTHOR${NC}"
printf "%b\n" "    Install Path   : ${CYAN}$INSTALL_DIR${NC}"
printf "%b\n" "    Database       : ${CYAN}$DATA_DIR/warden.db${NC}"
printf "%b\n" "    Log File       : ${CYAN}$LOG_DIR/warden.log${NC}"
printf "%b\n" "    Dashboard      : ${CYAN}$DASHBOARD_SUMMARY${NC}"
printf "%b\n" "    Service Unit   : ${CYAN}wardenips.service${NC}"
printf "%b\n" "    Service User   : ${CYAN}$SERVICE_USER${NC}"
printf "%b\n" "    Service State  : ${CYAN}$SERVICE_STATE_SUMMARY${NC}"
printf "\n"
printf "%b\n" "  ${YELLOW}Recommended Next Steps${NC}"
printf "%b\n" "    1. Review ${CYAN}$INSTALL_DIR/config.yaml${NC}"
printf "%b\n" "    2. Update whitelist.ips with your trusted addresses"
printf "%b\n" "    3. Verify plugin log paths and notification credentials"
printf "%b\n" "    4. Start the service manually if you kept autostart disabled"
printf "\n"
printf "%b\n" "  ${GREEN}Operational Commands${NC}"
printf "%b\n" "    sudo systemctl start wardenips"
printf "%b\n" "    sudo systemctl status wardenips"
printf "%b\n" "    sudo journalctl -u wardenips -f"
printf "%b\n" "    wardenips status"
printf "%b\n" "    wardenips logs"
printf "%b\n" "    wardenips service-status"
printf "%b\n" "    wardenips shell"
printf "\n"
