#!/usr/bin/env bash
# End-to-end smoke test: real server + real implants over mTLS and HTTPS.
#
# Verifies registration (protocol v2), task round-trips on both carriers,
# persistence, and the session/task history endpoints. Requires curl, python3,
# and generated certs (scripts/setup-ca.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_PORT="${PC2_E2E_PORT:-14444}"
API_PORT=$((BASE_PORT + 1))
METRICS_PORT=$((BASE_PORT + 2))
HTTPS_PORT=$((BASE_PORT + 3))

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
HTTPS_IMPLANT_LOG="$(mktemp /tmp/pc2-implant-https-XXXX.log)"
BUILT_LOG="$(mktemp /tmp/pc2-implant-built-XXXX.log)"
BUILT_PAYLOAD="$(mktemp -d /tmp/pc2-built-XXXXXX)/built-implant"
SRV=""
IMP=""
IMP2=""
IMP3=""

cleanup() {
  if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; fi
  if [ -n "$IMP" ]; then kill "$IMP" 2>/dev/null || true; fi
  if [ -n "$IMP2" ]; then kill "$IMP2" 2>/dev/null || true; fi
  if [ -n "$IMP3" ]; then kill "$IMP3" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  rm -f "$DB"
  rm -rf "$(dirname "$BUILT_PAYLOAD")"
}
trap cleanup EXIT

./bin/private-c2-server \
  --listen "127.0.0.1:${BASE_PORT}" \
  --api "127.0.0.1:${API_PORT}" \
  --metrics-addr "127.0.0.1:${METRICS_PORT}" \
  --https-listen "127.0.0.1:${HTTPS_PORT}" \
  --https-path /api/c2 \
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

./bin/implant \
  --https-url "https://127.0.0.1:${HTTPS_PORT}/api/c2" \
  --ca certs/ca-cert.pem \
  --cert certs/implant-cert.pem \
  --key certs/implant-key.pem \
  --interval 1s \
  --jitter 0 >"$HTTPS_IMPLANT_LOG" 2>&1 &
IMP2=$!

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
transports = {s.get("transport") for s in sessions}
assert {"mtls", "https"} <= transports, f"expected mtls and https sessions, got {transports}"
s = next(s for s in sessions if s.get("transport") == "mtls")
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

HSID="$(printf '%s' "$SESSIONS" | python3 -c '
import sys, json
sessions = json.load(sys.stdin)
print(next(s["id"] for s in sessions if s.get("transport") == "https"))
')"

HTASK="$(curl -fsS -X POST "$API/api/sessions/$HSID/task" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"type":"pwd","args":""}')"
HTID="$(printf '%s' "$HTASK" | python3 -c 'import sys,json; print(json.load(sys.stdin)["task_id"])')"

HRESULT=""
for _ in $(seq 1 30); do
  HRESULT="$(curl -fsS "$API/api/tasks/$HTID" -H "Authorization: Bearer $TOKEN")"
  if ! printf '%s' "$HRESULT" | grep -q '"status":"pending"'; then
    break
  fi
  sleep 0.5
done

printf '%s' "$HRESULT" | python3 -c '
import sys, json
r = json.load(sys.stdin)
assert r.get("success") is True, f"HTTPS task failed: {r}"
assert r.get("output", "").strip(), "HTTPS task returned empty output"
'

PAYLOAD_JSON="$(curl -fsS -X POST "$API/api/payloads/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target_os":"linux","target_arch":"amd64","format":"exe","mode":"beacon","transports":"mtls@127.0.0.1:'"${BASE_PORT}"'"}')"
PAYLOAD_ID="$(printf '%s' "$PAYLOAD_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')"

curl -fsS "$API/api/payloads/$PAYLOAD_ID/download" \
  -H "Authorization: Bearer $TOKEN" -o "$BUILT_PAYLOAD"
chmod +x "$BUILT_PAYLOAD"

# The generated payload runs with no flags: its config, CA, and client
# certificate are embedded.
"$BUILT_PAYLOAD" >"$BUILT_LOG" 2>&1 &
IMP3=$!

sleep 6

SESSIONS3="$(curl -fsS "$API/api/sessions" -H "Authorization: Bearer $TOKEN")"
BSID="$(printf '%s' "$SESSIONS3" | python3 -c '
import sys, json
sessions = json.load(sys.stdin)
match = [s for s in sessions if s.get("process") == "built-implant"]
assert match, "built payload did not register; processes=" + str([s.get("process") for s in sessions])
print(match[0]["id"])
')"

BTASK="$(curl -fsS -X POST "$API/api/sessions/$BSID/task" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"type":"pwd","args":""}')"
BTID="$(printf '%s' "$BTASK" | python3 -c 'import sys,json; print(json.load(sys.stdin)["task_id"])')"

BRESULT=""
for _ in $(seq 1 40); do
  BRESULT="$(curl -fsS "$API/api/tasks/$BTID" -H "Authorization: Bearer $TOKEN")"
  if ! printf '%s' "$BRESULT" | grep -q '"status":"pending"'; then
    break
  fi
  sleep 0.5
done

printf '%s' "$BRESULT" | python3 -c '
import sys, json
r = json.load(sys.stdin)
assert r.get("success") is True, f"built payload task failed: {r}"
assert r.get("output", "").strip(), "built payload task returned empty output"
'

echo "E2E OK: mTLS $SID/$TID; HTTPS $HSID/$HTID; built payload $BSID/$BTID"
