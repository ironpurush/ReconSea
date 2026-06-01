#!/usr/bin/env bash
# ReconSea Uninstaller
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
info()    { echo -e "\033[0;36m[*]\033[0m $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]\033[0m $*"; }

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

echo ""
echo -e "  ${RED}ReconSea Uninstaller${RESET}"
echo "  ────────────────────"
echo ""

# Remove binary
if [[ -f /usr/local/bin/reconsea ]]; then
    $SUDO rm -f /usr/local/bin/reconsea
    success "Removed /usr/local/bin/reconsea"
else
    warn "/usr/local/bin/reconsea not found — skipping"
fi

# Remove PATH line from Go profile
$SUDO rm -f /etc/profile.d/reconsea.sh

# Optional: remove reports
echo ""
read -rp "  Remove ./reports/ directory? [y/N] " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    rm -rf ./reports
    success "Removed ./reports/"
fi

echo ""
success "ReconSea uninstalled."
echo ""
