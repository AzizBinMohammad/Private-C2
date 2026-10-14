#!/bin/bash
#
# run.sh -- Bring up the whole Private-C2 stack with one command.
#
# Builds the server, client and implant, generates certificates if they are
# missing, starts the server and one implant, waits for the implant to
# register, then hands the terminal to the interactive operator console
# already attached to that session. Everything is torn down when the console
# exits, so a run leaves no stray processes behind.
#
# Run from anywhere:
#   bash scripts/run.sh
# or from the repository root:
#   make run
#
set -euo pipefail

# ---- paths ---------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN_DIR="$REPO_ROOT/bin"
CERTS_DIR="$REPO_ROOT/certs"
SERVER_BIN="$BIN_DIR/pc2-server"
CLIENT_BIN="$BIN_DIR/pc2-client"
IMPLANT_BIN="$BIN_DIR/implant"
SERVER_LOG="$BIN_DIR/pc2-run-server.log"
IMPLANT_LOG="$BIN_DIR/pc2-run-implant.log"

LISTEN_ADDR="127.0.0.1:4444"
API_ADDR="127.0.0.1:8080"

# How long to wait for the server to listen and the implant to register.
STARTUP_TIMEOUT=80   # x 0.25s = 20s

# ---- colors --------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fatal()   { echo -e "${RED}[!!]${NC} $*" >&2; exit 1; }
step()    { printf "  %-22s" "$1"; }

SERVER_PID=""
IMPLANT_PID=""

# ---- teardown ------------------------------------------------------------
# Runs however the console exits -- typing 'exit', Ctrl-D, or Ctrl-C. Without
# it every run would leak a listening server and a beaconing implant.
cleanup() {
    local code=$?
    trap - EXIT INT TERM

    # If nothing was started -- a preflight abort, or a build failure -- there
    # is nothing to tear down, and announcing a shutdown would bury the error
    # that caused it.
    if [[ -n "$SERVER_PID" || -n "$IMPLANT_PID" ]]; then
        echo ""
        step "shutting down stack..."
        # The implant goes first: killing the server out from under it just
        # makes it log reconnect errors on the way down.
        for pid in "$IMPLANT_PID" "$SERVER_PID"; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
        done
        sleep 0.5
        for pid in "$IMPLANT_PID" "$SERVER_PID"; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
        echo -e "${GREEN}ok${NC}"
    fi

    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---- preflight -----------------------------------------------------------
command -v go >/dev/null 2>&1 || fatal "Go is not installed. Run scripts/install-fedora.sh first."
[[ -f "$REPO_ROOT/go.work" ]] || fatal "run.sh must live inside the Private-C2 repository (no go.work found)."

# A previous run that was killed uncleanly would otherwise make this one fail
# with a confusing bind error.
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for port in 4444 8080; do
    if port_in_use "$port"; then
        fatal "port $port is already in use. Stop the other process (maybe a previous run: pgrep -af pc2-) and try again."
    fi
done

mkdir -p "$BIN_DIR"

# ---- build ---------------------------------------------------------------
echo -e "${BOLD}Private-C2${NC} -- bringing up a local stack"
echo ""
step "building server..."
go build -trimpath -ldflags="-s -w" -o "$SERVER_BIN" ./cmd/server || fatal "server build failed"
echo -e "${GREEN}ok${NC}"

step "building client..."
go build -trimpath -ldflags="-s -w" -o "$CLIENT_BIN" ./cmd/client || fatal "client build failed"
echo -e "${GREEN}ok${NC}"

step "building implant..."
# Not part of `make build`: ./implant is a library module with no main package,
# so the entry point has to be named explicitly.
go build -trimpath -ldflags="-s -w" -o "$IMPLANT_BIN" ./cmd/implant || fatal "implant build failed"
echo -e "${GREEN}ok${NC}"

# ---- certificates --------------------------------------------------------
if [[ -f "$CERTS_DIR/ca-cert.pem" && -f "$CERTS_DIR/server-cert.pem" \
   && -f "$CERTS_DIR/implant-cert.pem" && -f "$CERTS_DIR/implant-key.pem" ]]; then
    step "certificates..."
    echo -e "${GREEN}ok${NC} (reusing certs/)"
else
    step "certificates..."
    echo -e "${YELLOW}generating${NC}"
    bash "$REPO_ROOT/scripts/setup-ca.sh" >/dev/null || fatal "scripts/setup-ca.sh failed"
fi

# ---- server --------------------------------------------------------------
step "starting server..."
# --ca is what turns on client-certificate verification for implants, so the
# implant below has to present one.
nohup "$SERVER_BIN" \
    --listen "$LISTEN_ADDR" \
    --api "$API_ADDR" \
    --cert "$CERTS_DIR/server-cert.pem" \
    --key "$CERTS_DIR/server-key.pem" \
    --ca "$CERTS_DIR/ca-cert.pem" \
    > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

waited=0
while (( waited < STARTUP_TIMEOUT )); do
    if grep -q "Operator HTTP API" "$SERVER_LOG" 2>/dev/null; then break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo -e "${RED}failed${NC}"
        tail -5 "$SERVER_LOG" >&2
        fatal "server exited during startup (full log: $SERVER_LOG)"
    fi
    sleep 0.25
    waited=$(( waited + 1 ))
done
(( waited < STARTUP_TIMEOUT )) || { echo -e "${RED}timeout${NC}"; fatal "server did not start (log: $SERVER_LOG)"; }
echo -e "${GREEN}ok${NC} (implant :4444, api $API_ADDR)"

# ---- implant -------------------------------------------------------------
step "starting implant..."
nohup "$IMPLANT_BIN" \
    --server "$LISTEN_ADDR" \
    --ca "$CERTS_DIR/ca-cert.pem" \
    --cert "$CERTS_DIR/implant-cert.pem" \
    --key "$CERTS_DIR/implant-key.pem" \
    --interval 2s --jitter 0.3 \
    > "$IMPLANT_LOG" 2>&1 &
IMPLANT_PID=$!

waited=0
while (( waited < STARTUP_TIMEOUT )); do
    if grep -q "registered, session_id=" "$IMPLANT_LOG" 2>/dev/null; then break; fi
    if ! kill -0 "$IMPLANT_PID" 2>/dev/null; then
        echo -e "${RED}failed${NC}"
        tail -5 "$IMPLANT_LOG" >&2
        fatal "implant exited during startup (full log: $IMPLANT_LOG)"
    fi
    sleep 0.25
    waited=$(( waited + 1 ))
done
(( waited < STARTUP_TIMEOUT )) || { echo -e "${RED}timeout${NC}"; fatal "implant did not register (log: $IMPLANT_LOG)"; }

SESSION_ID=$(sed -n 's/.*registered, session_id=\([A-Za-z0-9-]*\).*/\1/p' "$IMPLANT_LOG" | tail -1)
[[ -n "$SESSION_ID" ]] || fatal "could not read the session ID from $IMPLANT_LOG"
echo -e "${GREEN}ok${NC} (session ${SESSION_ID:0:8})"

# ---- console -------------------------------------------------------------
echo ""
info "Attached to ${BOLD}${SESSION_ID:0:8}${NC}. Type 'help' for commands; 'exit' or Ctrl-D to shut everything down."
echo ""
"$CLIENT_BIN" --server "http://$API_ADDR" --session "${SESSION_ID:0:8}"
