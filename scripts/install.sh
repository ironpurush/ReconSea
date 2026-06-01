#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  ReconSea Installer
#  Supports: Kali Linux, Ubuntu, Debian, Parrot OS
#  Author  : Sagar Jondhale (IronPurush)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗███████╗ █████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗█████╗  ███████║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██╔══╝  ██╔══██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "${RESET}"
echo -e "  ${BOLD}⚓  ReconSea Installer${RESET}"
echo -e "  Breaking the internet to make it unbreakable"
echo -e "  By Sagar Jondhale (IronPurush)"
echo ""
echo -e "  ────────────────────────────────────────────────────────────────"
echo ""

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. Some steps may require sudo."
    SUDO="sudo"
else
    SUDO=""
fi

# ── OS detection ─────────────────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_NAME="${NAME:-unknown}"
    else
        die "Cannot detect OS. /etc/os-release not found."
    fi

    case "$OS_ID" in
        kali|ubuntu|debian|parrot) info "Detected OS: $OS_NAME" ;;
        *) warn "OS '$OS_NAME' not officially supported. Proceeding anyway." ;;
    esac
}

# ── Requirement checks ───────────────────────────────────────────────────────
check_requirements() {
    info "Checking system requirements …"

    local missing=()

    command -v curl  &>/dev/null || missing+=("curl")
    command -v git   &>/dev/null || missing+=("git")

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing: ${missing[*]}. Installing …"
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq "${missing[@]}"
    fi
    success "Base requirements satisfied"
}

# ── Go installation ───────────────────────────────────────────────────────────
install_go() {
    local required_major=1 required_minor=21

    if command -v go &>/dev/null; then
        local version
        version=$(go version | awk '{print $3}' | sed 's/go//')
        local major minor
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)

        if [[ "$major" -gt "$required_major" ]] || \
           ([[ "$major" -eq "$required_major" ]] && [[ "$minor" -ge "$required_minor" ]]); then
            success "Go $version already installed"
            return
        fi
        warn "Go $version too old (need ≥ $required_major.$required_minor)"
    fi

    info "Installing Go …"
    local ARCH
    ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$ARCH" in
        amd64|x86_64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) die "Unsupported architecture: $ARCH" ;;
    esac

    local GO_VERSION="1.22.4"
    local GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TAR}"

    info "Downloading Go $GO_VERSION ($ARCH) …"
    curl -fsSL "$GO_URL" -o "/tmp/${GO_TAR}"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"

    # Add to PATH in profile
    for profile in /etc/profile.d/go.sh ~/.bashrc ~/.zshrc; do
        if [[ -f "$profile" ]] || [[ "$profile" == /etc/profile.d/go.sh ]]; then
            grep -q "/usr/local/go/bin" "$profile" 2>/dev/null || \
                echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' | $SUDO tee -a "$profile" >/dev/null
        fi
    done

    export PATH=$PATH:/usr/local/go/bin
    success "Go $GO_VERSION installed"
}

# ── Build ReconSea ────────────────────────────────────────────────────────────
build_reconsea() {
    info "Building ReconSea …"

    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    go mod download 2>&1 | tail -5 || warn "Some dependencies may not be cached"
    go build -trimpath -ldflags "-s -w" -o build/reconsea ./cmd/reconsea

    success "Build successful → build/reconsea"
}

# ── Install binary globally ───────────────────────────────────────────────────
install_binary() {
    local install_dir="/usr/local/bin"
    info "Installing reconsea to $install_dir …"

    $SUDO install -m 0755 build/reconsea "$install_dir/reconsea"
    success "reconsea command available globally"
}

# ── Create report directory ───────────────────────────────────────────────────
setup_dirs() {
    mkdir -p reports
    success "Report directory ready: ./reports/"
}

# ── Final check ───────────────────────────────────────────────────────────────
verify_install() {
    if command -v reconsea &>/dev/null; then
        local ver
        ver=$(reconsea version 2>/dev/null | grep -oP 'v[\d.]+' | head -1 || echo "installed")
        success "reconsea $ver is ready"
    else
        warn "Binary installed but not in current PATH. Restart your shell or run:"
        echo "       export PATH=\$PATH:/usr/local/bin"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    detect_os
    check_requirements
    install_go
    build_reconsea
    install_binary
    setup_dirs
    verify_install

    echo ""
    echo -e "  ${GREEN}${BOLD}Installation complete!${RESET}"
    echo ""
    echo -e "  Usage examples:"
    echo -e "    ${CYAN}reconsea scan example.com${RESET}"
    echo -e "    ${CYAN}reconsea scan example.com --deep --threads 100${RESET}"
    echo -e "    ${CYAN}reconsea dashboard${RESET}"
    echo -e "    ${CYAN}reconsea doctor${RESET}"
    echo ""
    echo -e "  Documentation: https://github.com/IronPurush/reconsea"
    echo ""
}

main "$@"
