#!/bin/sh
# WardenIPS — Uninstall Script
# Default mode preserves config and data. Use --purge for full removal.
set -eu

INSTALL_DIR="${INSTALL_DIR:-/opt/wardenips}"
DATA_DIR="${DATA_DIR:-/var/lib/wardenips}"
LOG_DIR="${LOG_DIR:-/var/log/wardenips}"
SERVICE_NAME="wardenips"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_FILE="${INSTALL_DIR}/config.yaml"
CLI_WRAPPER="/usr/local/bin/wardenips"
PURGE="${WARDENIPS_PURGE:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { printf "%b\n" "${GREEN}[+]${NC} $1"; }
warn() { printf "%b\n" "${YELLOW}[!]${NC} $1"; }
error() { printf "%b\n" "${RED}[X]${NC} $1"; exit 1; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge)
            PURGE="1"
            ;;
        --help|-h)
            printf "Usage: sudo sh uninstall.sh [--purge]\n"
            printf "  default : remove service and runtime hooks, keep config/data\n"
            printf "  --purge : remove service, files, logs, database, and config\n"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    error "This uninstaller must run as root. Use: sudo sh uninstall.sh"
fi

printf "\n"
printf "%b\n" "${CYAN}============================================${NC}"
printf "%b\n" "${CYAN}   WardenIPS — Uninstaller${NC}"
printf "%b\n" "${CYAN}============================================${NC}"
printf "\n"

detect_set_name() {
    if [ -f "$CONFIG_FILE" ]; then
        value="$(sed -n 's/^[[:space:]]*set_name:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
        if [ -n "$value" ]; then
            printf "%s" "$value"
            return
        fi
    fi
    printf "%s" "warden_blacklist"
}

remove_rule_loop() {
    cmd_bin="$1"
    set_name="$2"
    if ! command -v "$cmd_bin" >/dev/null 2>&1; then
        return
    fi
    while "$cmd_bin" -C INPUT -m set --match-set "$set_name" src -j DROP >/dev/null 2>&1; do
        "$cmd_bin" -D INPUT -m set --match-set "$set_name" src -j DROP >/dev/null 2>&1 || break
    done
}

cleanup_firewall() {
    set_name="$(detect_set_name)"
    set_name_v6="${set_name}_v6"

    log "Removing firewall hooks..."
    remove_rule_loop iptables "$set_name"
    remove_rule_loop ip6tables "$set_name_v6"

    if command -v ipset >/dev/null 2>&1; then
        ipset destroy "$set_name" >/dev/null 2>&1 || true
        ipset destroy "$set_name_v6" >/dev/null 2>&1 || true
    fi
}

remove_service() {
    log "Stopping and disabling service..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        if [ -f "$SERVICE_FILE" ]; then
            rm -f "$SERVICE_FILE"
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi
    fi
}

remove_files() {
    rm -f "$CLI_WRAPPER"
    if [ "$PURGE" = "1" ]; then
        warn "Purge mode enabled — removing install directory, logs, and database."
        rm -rf "$INSTALL_DIR"
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"
    else
        warn "Preserving config, logs, and database. Use --purge for full removal."
        if [ -d "$INSTALL_DIR" ]; then
            find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 \
                ! -name 'config.yaml' \
                ! -name 'config.yaml.backup' \
                -exec rm -rf {} +
        fi
    fi
}

remove_service
cleanup_firewall
remove_files

printf "\n"
printf "%b\n" "${GREEN}============================================${NC}"
printf "%b\n" "${GREEN}   WardenIPS removal complete${NC}"
printf "%b\n" "${GREEN}============================================${NC}"
printf "\n"
if [ "$PURGE" = "1" ]; then
    printf "%b\n" "  Mode        : ${CYAN}full purge${NC}"
else
    printf "%b\n" "  Mode        : ${CYAN}service/app removed, data preserved${NC}"
    printf "%b\n" "  Preserved   : ${CYAN}${CONFIG_FILE}${NC}, ${CYAN}${DATA_DIR}${NC}, ${CYAN}${LOG_DIR}${NC}"
fi
printf "\n"