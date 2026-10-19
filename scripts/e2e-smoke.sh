#!/usr/bin/env bash
# End-to-end smoke test: real server + real implant over mTLS.
#
# Verifies registration (protocol v2), a task round-trip, persistence, and the
# session/task history endpoints. Requires curl, python3, and generated certs
# (scripts/setup-ca.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_PORT="${PC2_E2E_PORT:-14444}"
API_PORT=$((BASE_PORT + 1))
METRICS_PORT=$((BASE_PORT + 2))

for f in certs/server-cert.pem certs/server-key.pem certs/ca-cert.pem \
         certs/implant-cert.pem certs/implant-key.pem; do
  if [ ! -f "$f" ]; then
    echo "missing $f; run scripts/setup-ca.sh first" >&2
    exit 1
  fi
done

make build >/dev/null
go build -o bin/implant ./cmd/implant

DB="$(mktemp /tmp/pc2-e2e-XXXXXX.db)"
SERVER_LOG="$(mktemp /tmp/pc2-server-XXXX.log)"
IMPLANT_LOG="$(mktemp /tmp/pc2-implant-XXXX.log)"
SRV=""
IMP=""

cleanup() {
  if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; fi
  if [ -n "$IMP" ]; then kill "$IMP" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  rm -f "$DB"
}
trap cleanup EXIT

./bin/private-c2-server \
  --listen "127.0.0.1:${BASE_PORT}" \
  --api "127.0.0.1:${API_PORT}" \
  --metrics-addr "127.0.0.1:${METRICS_PORT}" \
  --db "$DB" \
  --cert certs/server-cert.pem \
  --key certs/server-key.pem \
  --ca certs/ca-cert.pem >"$SERVER_LOG" 2>&1 &
SRV=$!

sleep 1

./bin/implant \
  --server "127.0.0.1:${BASE_PORT}" \
  --ca certs/ca-cert.pem \
  --cert certs/implant-cert.pem \
  --key certs/implant-key.pem \
  --interval 1s \
  --jitter 0 >"$IMPLANT_LOG" 2>&1 &
IMP=$!

sleep 3

API="http://127.0.0.1:${API_PORT}"
TOKEN="$(curl -fsS -X POST "$API/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' |
  python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')"

SESSIONS="$(curl -fsS "$API/api/sessions" -H "Authorization: Bearer $TOKEN")"
SID="$(printf '%s' "$SESSIONS" | python3 -c '
import sys, json
sessions = json.load(sys.stdin)
assert sessions, "no sessions registered"
s = sessions[0]
assert s.get("protocol_version") == 2, f"expected protocol v2, got {s.get('protocol_version')}"
print(s["id"])
')"

TASK="$(curl -fsS -X POST "$API/api/sessions/$SID/task" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"type":"pwd","args":""}')"
TID="$(printf '%s' "$TASK" | python3 -c 'import sys,json; print(json.load(sys.stdin)["task_id"])')"

RESULT=""
for _ in $(seq 1 30); do
  RESULT="$(curl -fsS "$API/api/tasks/$TID" -H "Authorization: Bearer $TOKEN")"
  if ! printf '%s' "$RESULT" | grep -q '"status":"pending"'; then
    break
  fi
  sleep 0.5
done

printf '%s' "$RESULT" | python3 -c '
import sys, json
r = json.load(sys.stdin)
assert r.get("success") is True, f"task failed: {r}"
assert r.get("output", "").strip(), "task returned empty output"
'

HISTORY="$(curl -fsS "$API/api/sessions/history" -H "Authorization: Bearer $TOKEN")"
printf '%s' "$HISTORY" | python3 -c '
import sys, json
rows = json.load(sys.stdin)
assert any(r["id"] == "'"$SID"'" for r in rows), "session not persisted in history"
'

TASKS="$(curl -fsS "$API/api/sessions/$SID/tasks" -H "Authorization: Bearer $TOKEN")"
printf '%s' "$TASKS" | python3 -c '
import sys, json
rows = json.load(sys.stdin)
assert any(t["id"] == "'"$TID"'" and t["state"] == "completed" for t in rows), "task not persisted as completed"
'

echo "E2E OK: session $SID, task $TID"
