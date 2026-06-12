#!/usr/bin/env bash
set -euo pipefail

DAEMON_BIN="/usr/local/bin/netblind-daemon"
SERVICE_FILE="/etc/systemd/system/netblind.service"
POLKIT_RULE="/etc/polkit-1/rules.d/99-netblind.rules"
DESKTOP_FILE="/usr/share/applications/netblind.desktop"
DB_DIR="/var/lib/netblind"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[netblind]${NC} $*"; }
warn()  { echo -e "${YELLOW}[netblind]${NC} $*"; }
error() { echo -e "${RED}[netblind]${NC} $*" >&2; exit 1; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)."
    fi
}

check_deps() {
    local missing=()
    for cmd in go nft conntrack python3 pip3 systemctl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required commands: ${missing[*]}"
    fi
}

build_daemon() {
    info "Building Go daemon..."
    cd "$(dirname "$0")/daemon"
    go mod download
    CGO_ENABLED=1 go build -ldflags="-s -w" -o netblind-daemon .
    cp netblind-daemon "$DAEMON_BIN"
    chmod 755 "$DAEMON_BIN"
    info "Daemon installed at $DAEMON_BIN"
    cd ..
}

install_python_clients() {
    info "Installing Python clients..."
    pip3 install -e "$(dirname "$0")" --quiet
    info "Python clients installed (netblind, netblind-tui, netblind-gui)"
}

setup_systemd() {
    info "Installing systemd service..."
    cp "$(dirname "$0")/install/netblind.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable netblind
    info "Service enabled. Start with: sudo systemctl start netblind"
}

setup_database_dir() {
    mkdir -p "$DB_DIR"
    chown root:root "$DB_DIR"
    chmod 750 "$DB_DIR"
}

setup_group() {
    if ! getent group netblind &>/dev/null; then
        groupadd netblind
        info "Created group 'netblind'"
    fi
    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG netblind "$SUDO_USER"
        info "Added $SUDO_USER to 'netblind' group"
    fi
    # Adjust socket permissions for group
    if [[ -S /run/netblind.sock ]]; then
        chown root:netblind /run/netblind.sock
        chmod 660 /run/netblind.sock
    fi
}

setup_polkit() {
    if [[ -d /etc/polkit-1/rules.d ]]; then
        cp "$(dirname "$0")/install/99-netblind.rules" "$POLKIT_RULE"
        info "Polkit rule installed"
    else
        warn "polkit rules.d directory not found — skipping polkit setup"
    fi
}

install_desktop_file() {
    cp "$(dirname "$0")/install/netblind.desktop" "$DESKTOP_FILE"
    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database /usr/share/applications/
    fi
    info "Desktop entry installed"
}

main() {
    require_root
    check_deps
    build_daemon
    install_python_clients
    setup_database_dir
    setup_group
    setup_polkit
    setup_systemd
    install_desktop_file

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  netblind installed successfully!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Start the daemon:   sudo systemctl start netblind"
    echo "  Check status:       netblind status"
    echo "  Launch TUI:         netblind-tui"
    echo "  Launch GUI:         netblind-gui"
    echo ""
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo -e "${YELLOW}  NOTE: Log out and back in (or run 'newgrp netblind')${NC}"
        echo -e "${YELLOW}  for group membership to take effect.${NC}"
        echo ""
    fi
    echo "  GitHub: https://github.com/dilates"
    echo ""
}

main "$@"
