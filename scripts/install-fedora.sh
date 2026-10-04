#!/bin/bash
#
# install-fedora.sh -- Private-C2 Fedora Setup Script
#
# Installs dependencies, builds all binaries, and generates certificates.
# Run from any directory; the script will clone the repo if needed.
#
set -euo pipefail

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[!!]${NC} $*" >&2; }
fatal()   { error "$*"; exit 1; }

header() {
    echo ""
    echo -e "${BOLD}${CYAN}========================================${NC}"
    echo -e "${BOLD}${CYAN}  $*${NC}"
    echo -e "${BOLD}${CYAN}========================================${NC}"
    echo ""
}

# ---- Preflight ----
if [[ $EUID -eq 0 ]]; then
    warn "Running as root. Dependencies will be installed system-wide."
fi

if ! grep -qiE 'fedora|rhel|centos|rocky|alma' /etc/os-release 2>/dev/null; then
    warn "This script is intended for Fedora/RHEL-based systems."
    warn "Detected OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 || echo unknown)"
    read -rp "Continue anyway? [y/N] " confirm
    [[ "${confirm,,}" == "y" ]] || exit 0
fi

REQUIRED_GO_VERSION="1.23"
GO_DOWNLOAD_VERSION="1.23.4"
REPO_URL="https://github.com/AzizBinMohammad/Private-C2.git"

# ---- Step 1: Install Go ----
header "Step 1/5: Go Toolchain"

install_go() {
    local arch
    arch=$(uname -m)
    case "${arch}" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       fatal "Unsupported architecture: ${arch}" ;;
    esac

    local tarball="go${GO_DOWNLOAD_VERSION}.linux-${arch}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    info "Downloading Go ${GO_DOWNLOAD_VERSION} for ${arch}..."
    curl -fsSL -o "/tmp/${tarball}" "${url}" || fatal "Failed to download Go from ${url}"

    info "Installing Go to /usr/local/go..."
    if [[ $EUID -eq 0 ]]; then
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "/tmp/${tarball}"
    else
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    fi
    rm -f "/tmp/${tarball}"

    export PATH="/usr/local/go/bin:${PATH}"

    # Add to shell profile if not already present
    local profile="${HOME}/.bashrc"
    if ! grep -q '/usr/local/go/bin' "${profile}" 2>/dev/null; then
        echo 'export PATH="/usr/local/go/bin:${PATH}"' >> "${profile}"
        info "Added Go to PATH in ${profile}"
    fi
}

go_version_ok() {
    if ! command -v go &>/dev/null; then
        return 1
    fi
    local current
    current=$(go version | grep -oP 'go(\d+\.\d+)' | head -1 | sed 's/go//')
    if [[ -z "${current}" ]]; then
        return 1
    fi
    local major minor req_major req_minor
    major=$(echo "${current}" | cut -d. -f1)
    minor=$(echo "${current}" | cut -d. -f2)
    req_major=$(echo "${REQUIRED_GO_VERSION}" | cut -d. -f1)
    req_minor=$(echo "${REQUIRED_GO_VERSION}" | cut -d. -f2)

    if (( major > req_major )) || { (( major == req_major )) && (( minor >= req_minor )); }; then
        return 0
    fi
    return 1
}

if go_version_ok; then
    success "Go $(go version | grep -oP 'go[\d.]+') is already installed."
else
    if command -v go &>/dev/null; then
        warn "Go is installed but version is below ${REQUIRED_GO_VERSION}."
    else
        info "Go is not installed."
    fi
    install_go
    if go_version_ok; then
        success "Go $(go version | grep -oP 'go[\d.]+') installed successfully."
    else
        fatal "Go installation failed. Please install Go >= ${REQUIRED_GO_VERSION} manually."
    fi
fi

# ---- Step 2: Install system dependencies ----
header "Step 2/5: System Dependencies"

PACKAGES=(openssl git make)
MISSING=()

for pkg in "${PACKAGES[@]}"; do
    if ! command -v "${pkg}" &>/dev/null; then
        MISSING+=("${pkg}")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "Installing missing packages: ${MISSING[*]}"
    if [[ $EUID -eq 0 ]]; then
        dnf install -y "${MISSING[@]}" || fatal "Failed to install packages."
    else
        sudo dnf install -y "${MISSING[@]}" || fatal "Failed to install packages."
    fi
    success "Dependencies installed."
else
    success "All dependencies already present: ${PACKAGES[*]}"
fi

# ---- Step 3: Clone or locate the repo ----
header "Step 3/5: Repository"

PROJECT_DIR=""

# Check if we are already inside the repo
if [[ -f "go.work" ]] && grep -q 'private-c2' go.work 2>/dev/null; then
    PROJECT_DIR="$(pwd)"
    success "Already inside Private-C2 repo: ${PROJECT_DIR}"
elif [[ -f "../go.work" ]] && grep -q 'private-c2' ../go.work 2>/dev/null; then
    PROJECT_DIR="$(cd .. && pwd)"
    success "Found Private-C2 repo at: ${PROJECT_DIR}"
elif [[ -d "Private-C2" ]] && [[ -f "Private-C2/go.work" ]]; then
    PROJECT_DIR="$(cd Private-C2 && pwd)"
    success "Found existing clone: ${PROJECT_DIR}"
else
    info "Cloning Private-C2 repository..."
    git clone "${REPO_URL}" || fatal "Failed to clone repository."
    PROJECT_DIR="$(cd Private-C2 && pwd)"
    success "Cloned to: ${PROJECT_DIR}"
fi

cd "${PROJECT_DIR}"

# ---- Step 4: Build everything ----
header "Step 4/5: Build"

mkdir -p bin

info "Building server..."
go build -trimpath -ldflags="-s -w" -o bin/pc2-server ./cmd/server/... 2>&1 && \
    success "Server built: bin/pc2-server" || \
    warn "Server build failed (may need proto dependencies)."

info "Building client..."
go build -trimpath -ldflags="-s -w" -o bin/pc2-client ./cmd/client/... && \
    success "Client built: bin/pc2-client" || \
    fatal "Client build failed."

info "Building builder..."
go build -trimpath -ldflags="-s -w" -o bin/pc2-builder ./cmd/builder/... 2>&1 && \
    success "Builder built: bin/pc2-builder" || \
    warn "Builder build failed."

# Cross-compile implant for Linux amd64
info "Cross-compiling implant for linux/amd64..."
if GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o bin/implant-linux-amd64 ./implant/... 2>&1; then
    success "Implant built: bin/implant-linux-amd64"
else
    warn "Implant cross-compile failed (may not have a main package yet)."
fi

# ---- Step 5: Generate certificates ----
header "Step 5/5: Certificates"

if [[ -x scripts/setup-ca.sh ]]; then
    info "Running certificate generation..."
    bash scripts/setup-ca.sh
    success "Certificates generated in certs/"
else
    warn "scripts/setup-ca.sh not found or not executable. Skipping certificate generation."
    warn "Run it manually: bash scripts/setup-ca.sh"
fi

# ---- Summary ----
header "Setup Complete"

echo -e "${GREEN}All components are ready.${NC}"
echo ""
echo -e "${BOLD}Quick Start:${NC}"
echo ""
echo -e "  ${CYAN}1. Start the server:${NC}"
echo "     cd ${PROJECT_DIR}"
echo "     export PC2_CA_CERT_PATH=certs/ca-cert.pem"
echo "     export PC2_SERVER_CERT_PATH=certs/server-cert.pem"
echo "     export PC2_SERVER_KEY_PATH=certs/server-key.pem"
echo "     ./bin/pc2-server"
echo ""
echo -e "  ${CYAN}2. Connect with the operator client:${NC}"
echo "     ./bin/pc2-client --server http://127.0.0.1:8080"
echo ""
echo -e "  ${CYAN}3. Deploy the implant to a target (e.g. Kali VM):${NC}"
echo "     scp bin/implant-linux-amd64 user@kali-vm:/tmp/svc"
echo "     ssh user@kali-vm '/tmp/svc &'"
echo ""
echo -e "  ${CYAN}4. Build implant for other platforms:${NC}"
echo "     GOOS=windows GOARCH=amd64 go build -ldflags='-s -w' -o bin/implant.exe ./implant/..."
echo "     GOOS=darwin  GOARCH=arm64 go build -ldflags='-s -w' -o bin/implant-mac   ./implant/..."
echo ""
