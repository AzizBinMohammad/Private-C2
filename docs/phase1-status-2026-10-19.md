# Phase 1 Status — 2026-10-19

Branch: `feat/redteam-workflow`

This is the first Phase 1 cut ("core parity and truth"). It is deliberately
foundation work: it fixes verified defects, wires durable state and safety into
the live path, and adds a real end-to-end test. It does **not** yet include the
HTTPS carrier, the config-embedded payload builder, or the audit writer; those
remain Phase 1 work.

## Completed

### Protocol and task registry
- Added `pkg/protocol/tasks.go`: one task-type registry shared by the server,
  implant, and portal (20 types).
- Added additive protocol v2 fields (`protocol_version`, capabilities,
  engagement ID, sleep/jitter, transports, heartbeat, session token, kill
  instruction, per-task timeout, result truncation/bytes) without changing any
  v1 JSON key.
- Added `protocol.Negotiate` / capability helpers and legacy golden tests.
- Bounded frames at 64 MiB and added `ReadFrameWithLimit`, which rejects an
  oversized length prefix before allocation.

### Live C2 correctness
- Results are bound to the session that owns the task; a foreign or unknown
  task ID is rejected. The wire `session_id` is no longer trusted.
- Tasking is requeued if the write fails instead of being lost.
- A reconnecting implant supersedes its previous session and its queued tasks
  and lock are transferred to the new session.
- Registration has a 30-second deadline; accepted connections are tracked and
  closed on listener stop.
- Listener start/stop is race-safe; accept errors back off instead of spinning.
- Queue depth and stored-result count are bounded; v2 check-ins require the
  session token; operator-supplied lock identity is still a request field and
  remains a follow-up (RBAC now controls who can call it).

### Implant runtime
- Task handlers moved to `cmd/implant/tasks.go`; all 20 protocol task types are
  registered, including `ifconfig`, `netstat`, `portscan`, `resolve`, `kill`,
  `mkdir`, `rm`, `cp`, and `mv`.
- `implant/task.Runner` executes tasks on bounded workers with per-task
  timeouts, panic recovery, duplicate-ID suppression, and output truncation.
  The beacon loop flushes results at the start of each cycle, so long scans no
  longer block check-ins.
- `implant/safety` is wired into the runner and the beacon loop: kill date,
  scope, time window, data quota, remote kill switch, and an optional command
  allowlist. The implant exits on a fatal check or a server kill instruction.
- Protocol v2 registration/negotiation, server-controlled heartbeat, session
  token on every check-in, and a crypto/rand implant ID.

### Server state and persistence
- Added `models.Task` and `models.TaskResult`.
- Added `c2.Persistence` + `c2.GORMPersistence`; sessions, check-ins,
  disconnects, task queue/dispatch, and results write through to SQLite /
  PostgreSQL. Queueing fails closed if the DB write fails.
- Queued tasks are rebound to a reconnecting implant by `ImplantID`.
- Startup reconciles sessions left "active" by a previous process to
  "disconnected".
- Added session history, per-session task history, and DB fallback for
  completed task results.
- Fixed `SessionRepository.MarkStale` (it previously marked every row stale).

### Authorization and engagement enforcement
- Operators hydrate from the database at startup; `PasswordHash` is a dedicated
  field with fallback to legacy `CertPEM` hashes.
- Token entries carry operator ID and role; logout revokes a token; deleting an
  operator removes credentials and revokes its tokens; expired tokens are
  pruned.
- Added `server/api/authz`: role/permission matrix (`admin`, `operator`,
  `builder`, `observer`, `ot-operator`) and a deny-by-default HTTP middleware
  keyed on method + path. RBAC is enforced on the live REST API.
- Engagement policy at task-queue time: engagement status, kill-switch state,
  time window, authorized techniques, and scope (CIDR/hostname/domain). The
  implant re-checks its own configured scope.
- Kill switch now closes matching live sessions, reaps their queues/results,
  blocks further tasking, and returns v2 implants a `kill` instruction. The
  endpoint reports how many sessions were closed.
- Added `pkg/taskargs` so the server and implant agree on which target a task
  will act on.

## Verification

- `make test` (all 9 modules, `-race`): pass.
- `make lint` (go vet): pass.
- `make build`, `make cross-compile`: pass.
- `make e2e-smoke`: passes against real `private-c2-server` + `implant`
  binaries over mTLS: v2 registration, session token, `pwd` task round-trip,
  persisted history, and persisted task state.
- New tests cover protocol compatibility, frame bounds, result ownership,
  requeueing, reconnect supersession, listener stop, task runner, safety,
  persistence (fake + GORM), session history, auth hydration/revocation, RBAC,
  engagement policy, and the kill switch.

## Remaining Phase 1 work

1. **HTTPS carrier** that carries the same framed protocol. The current
   `server/c2/listener/https.go` uses a different session model and cannot be
   substituted. Do not claim an HTTPS listener until an end-to-end test passes.
2. **Config-embedded payload builder.** `buildImplant()` still runs
   `go build ./cmd/implant` without embedding the server address, trust
   material, mode, sleep/jitter, or engagement. Built payloads still require
   runtime flags. DLL/shellcode/shared formats remain rejected rather than
   producing fake artifacts.
3. **Audit writer and export.** The audit table still has no live writer, and
   the two hash implementations remain unreconciled. `/api/audit/export` is
   still missing.
4. **Event bus / SSE** for live UI updates.
5. **Config wiring** (`PC2_*` env vars vs flags) and a migration ledger/SQLite
   backup before DDL.
6. **Metrics instrumentation** (registered but still never incremented).

Phase 2 (credential access, lateral movement, persistence, BOF/COFF, evasion,
OT execution) has not started.
