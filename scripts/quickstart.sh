#!/bin/bash
#
# quickstart.sh -- Minimal Private-C2 quickstart
#
# Builds server + client + implant, generates certs, starts the server
# in the background, and prints deployment instructions.
#
# Run from the repository root:
#   bash scripts/quickstart.sh
#
set -euo pipefail

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fatal()   { echo -e "${RED}[!!]${NC} $*" >&2; exit 1; }

# ---- Preflight ----
command -v go &>/dev/null || fatal "Go is not installed. Run scripts/install-fedora.sh first."

if [[ ! -f "go.work" ]]; then
    fatal "Run this script from the Private-C2 repository root."
fi

mkdir -p bin

# ---- Step 1: Build ----
info "Building server..."
go build -trimpath -ldflags="-s -w" -o bin/pc2-server ./cmd/server/... 2>&1 && \
    success "bin/pc2-server" || warn "Server build failed."

info "Building client..."
go build -trimpath -ldflags="-s -w" -o bin/pc2-client ./cmd/client/... && \
    success "bin/pc2-client" || fatal "Client build failed."

info "Cross-compiling implant (linux/amd64)..."
if GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o bin/implant-linux-amd64 ./implant/... 2>&1; then
    success "bin/implant-linux-amd64"
else
    warn "Implant build skipped (no main package yet)."
fi

# ---- Step 2: Generate certificates ----
if [[ -f certs/ca-cert.pem ]] && [[ -f certs/server-cert.pem ]]; then
    info "Certificates already exist in certs/, skipping."
else
    info "Generating certificates..."
    if [[ -x scripts/setup-ca.sh ]]; then
        bash scripts/setup-ca.sh
        success "Certificates generated."
    else
        fatal "scripts/setup-ca.sh not found."
    fi
fi

# ---- Step 3: Start server ----
if [[ -x bin/pc2-server ]]; then
    export PC2_CA_CERT_PATH=certs/ca-cert.pem
    export PC2_SERVER_CERT_PATH=certs/server-cert.pem
    export PC2_SERVER_KEY_PATH=certs/server-key.pem

    info "Starting server in the background..."
    nohup ./bin/pc2-server > /tmp/pc2-server.log 2>&1 &
    SERVER_PID=$!
    sleep 1

    if kill -0 "${SERVER_PID}" 2>/dev/null; then
        success "Server running (PID ${SERVER_PID}). Log: /tmp/pc2-server.log"
    else
        warn "Server may have exited. Check /tmp/pc2-server.log for details."
    fi
else
    warn "Server binary not available, skipping auto-start."
fi

# ---- Instructions ----
echo ""
echo -e "${BOLD}${CYAN}============================================${NC}"
echo -e "${BOLD}${CYAN}  Private-C2 Quickstart Complete${NC}"
echo -e "${BOLD}${CYAN}============================================${NC}"
echo ""
echo -e "${BOLD}Deploy the implant to your Kali VM:${NC}"
echo ""
echo "  scp bin/implant-linux-amd64 user@kali-vm:/tmp/svc"
echo "  ssh user@kali-vm 'chmod +x /tmp/svc && /tmp/svc &'"
echo ""
echo -e "${BOLD}Connect with the operator client:${NC}"
echo ""
echo "  ./bin/pc2-client --server http://127.0.0.1:8080"
echo ""
echo -e "${BOLD}Inside the client:${NC}"
echo ""
echo "  sessions          # list active sessions"
echo "  use <id>          # select a session"
echo "  shell whoami      # run a command"
echo "  download /etc/passwd passwd.txt"
echo ""
echo -e "${BOLD}Stop the server:${NC}"
echo ""
if [[ -n "${SERVER_PID:-}" ]]; then
    echo "  kill ${SERVER_PID}"
else
    echo "  kill \$(pgrep pc2-server)"
fi
echo ""
