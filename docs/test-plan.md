# Test Plan

The 5 most critical flows ranked by what would hurt most if it silently broke.

---

## Recommended Test Framework

**Standard library `testing` package** — already used by all existing tests in `pkg/`.
No external assertion libraries, no testify, no ginkgo. The codebase's established
pattern is table-driven tests with `t.Fatalf` / `t.Errorf` (see
`pkg/engagement/scope_test.go`, `pkg/crypto/aead_test.go`, etc.).

For HTTP handler tests, use `net/http/httptest` (already in the standard library).
For end-to-end implant↔server tests, use `net.Pipe()` to create in-memory
connections that avoid needing real TLS certificates.

**How to run:**

```bash
make test                 # Unit tests: pkg/, server/, client/ with -race
make test-integration     # Integration tests (all currently t.Skip)
go test ./server/... -run TestAuth -v  # Run a specific test subset
```

No new dependencies required.

---

## 1. Implant Registration + Beacon Loop

**Impact if broken**: The entire C2 framework is dead. No implant can connect,
no operator can interact with targets. Every downstream feature depends on this.

### What to test

- Implant sends `register` message → server creates a session and responds with
  `register_ack` containing a valid UUID session ID.
- Subsequent `checkin` messages update the session's `LastCheckin` timestamp.
- When no tasks are queued, `checkin` returns a `tasking` message with an empty
  `Tasks` array.
- Malformed registration (bad JSON, wrong message type) is rejected without
  crashing the server or leaving orphan sessions.
- Connection drop cleans up the session from `ImplantServer.sessions`.

### Files and functions involved

| File | Function | Role |
|------|----------|------|
| `server/c2/handler.go:121` | `ImplantServer.HandleConnection` | Reads registration, creates session, enters message loop |
| `server/c2/handler.go:210` | `ImplantServer.handleCheckin` | Updates `LastCheckin`, drains task queue, sends `tasking` |
| `server/c2/handler.go:277` | `ImplantServer.removeSession` | Cleans up on disconnect |
| `pkg/envelope/framing.go` | `ReadFrame` / `WriteFrame` | Length-prefixed wire framing |
| `cmd/implant/main.go:246` | `register` | Client-side registration handshake |
| `cmd/implant/main.go:356` | `beaconLoop` | Client-side checkin + task execution loop |

### Test type: Unit test

Use `net.Pipe()` to create an in-memory connection pair. Pass one end to
`HandleConnection` in a goroutine; drive the other end with the implant-side
wire protocol. No TLS, no real sockets, no certificates needed. This tests the
core state machine in isolation.

An end-to-end test (real TLS, real implant binary) would also be valuable but
belongs in `tests/integration/` and requires certificate setup.

### What is hard to test

- **`HandleConnection` takes a raw `net.Conn`**, which makes `net.Pipe()` viable,
  but the method logs to the global `log` package and has no way to return errors
  to the caller. Test assertions must be made by reading the connection's
  output frames rather than checking return values.
- **`uuid.New()` in session creation** makes the session ID non-deterministic.
  Tests must extract the ID from the `register_ack` response rather than predicting it.
- **The `conn` field on `ImplantSession` is unexported**, so tests in an external
  `c2_test` package cannot inspect session internals. Tests should use the exported
  `ListSessions()` and `GetSession()` methods.

---

## 2. Task Queuing, Dispatch, and Result Collection

**Impact if broken**: Operators cannot execute any commands on targets. Sessions
would connect but sit idle forever.

### What to test

- `QueueTask` for a valid session returns a task ID and the task appears in the
  session's queue.
- `QueueTask` for a nonexistent session returns an error.
- On the next `checkin`, queued tasks are drained and sent in the `tasking`
  response. A second `checkin` returns an empty task list.
- `handleResult` stores the result, which is then retrievable via `GetResult`.
- `GetResult` returns `nil` for a task that hasn't completed yet.
- Multiple tasks queued between checkins are all delivered in one batch.
- Concurrent `QueueTask` calls from multiple goroutines don't race (the
  `sync.RWMutex` protects the maps).

### Files and functions involved

| File | Function | Role |
|------|----------|------|
| `server/c2/handler.go:284` | `ImplantServer.QueueTask` | Validates session, creates task, appends to queue |
| `server/c2/handler.go:210` | `ImplantServer.handleCheckin` | Drains queue into `tasking` response |
| `server/c2/handler.go:234` | `ImplantServer.handleResult` | Stores result in `taskResults` map |
| `server/c2/handler.go:306` | `ImplantServer.GetResult` | Returns completed result or nil |
| `server/api/httpapi/handler.go:128` | `POST /api/sessions/{id}/task` | HTTP endpoint that calls `QueueTask` |
| `server/api/httpapi/handler.go:197` | `GET /api/tasks/{id}` | HTTP endpoint that calls `GetResult` |

### Test type: Unit test

`QueueTask`, `GetResult`, and `ListSessions` are exported methods on
`ImplantServer` that can be called directly. For the full dispatch cycle
(queue → checkin → drain → result), use `net.Pipe()` as in flow 1.

The HTTP layer (`handler.go` endpoints) should be tested separately with
`httptest.NewServer` wrapping the `NewRouter()` mux.

### What is hard to test

- **`NewRouter()` is a 1084-line function** that captures `implantServer` and `db`
  in closure scope. Testing individual endpoints requires constructing the entire
  router with both a real `ImplantServer` and a real `*gorm.DB` (use SQLite
  in-memory: `store.Open(Config{Dialect: "sqlite", DSN: ":memory:"})`).
- **Task dispatch is coupled to the connection loop** inside `HandleConnection`.
  There is no standalone "dispatch pending tasks for session X" function that can
  be called without an active `net.Conn`. The `handleCheckin` method is unexported.
- **Results are only stored in memory**. There is no persistence, so tests cannot
  verify results survived a restart — because they can't.

---

## 3. Authentication + Token Validation

**Impact if broken**: Either all API endpoints are unprotected (anyone can control
sessions and implants) or all legitimate operators are locked out. Both are
catastrophic for an engagement.

### What to test

- Valid `admin`/`admin` credentials return a token.
- Invalid password returns 401.
- Empty username or password returns 400.
- Valid token passes the `Middleware` check and reaches the handler.
- Missing `Authorization` header returns 401.
- Malformed `Authorization` header (no `Bearer ` prefix) returns 401.
- Expired token (>12h old) returns 401.
- `SetPassword` updates credentials and new password works, old one doesn't.
- Tokens are 64 hex characters (32 bytes).
- Concurrent login requests don't race (mutex-protected maps).

### Files and functions involved

| File | Function | Role |
|------|----------|------|
| `server/api/httpapi/auth.go:36` | `NewAuthManager` | Creates manager, seeds default user |
| `server/api/httpapi/auth.go:45` | `ensureDefaultUser` | Hardcodes `admin`/`admin` |
| `server/api/httpapi/auth.go:61` | `authenticate` | bcrypt comparison |
| `server/api/httpapi/auth.go:71` | `issueToken` | Random token generation + storage |
| `server/api/httpapi/auth.go:85` | `validateToken` | Token lookup + expiry check |
| `server/api/httpapi/auth.go:95` | `LoginHandler` | HTTP handler for `POST /api/auth/login` |
| `server/api/httpapi/auth.go:130` | `Middleware` | Bearer token extraction + validation |

### Test type: Unit test

`AuthManager` is a self-contained struct with no external dependencies. Create
one with `NewAuthManager()`, call `authenticate()` directly for credential tests,
and use `httptest.NewRecorder` + `httptest.NewRequest` for the HTTP handler and
middleware tests. No database, no network.

### What is hard to test

- **Token expiry** requires waiting 12 hours or manipulating time. The `issueToken`
  method uses `time.Now()` directly with no clock injection. To test expiry,
  either: (a) directly modify the `tokenEntry.expiresAt` field after calling
  `issueToken` (possible since tests in the `httpapi` package can access unexported
  fields), or (b) refactor to accept a `clock` interface (requires code change).
- **`ensureDefaultUser` is called in `NewAuthManager` and cannot be skipped**,
  so every test starts with the `admin` user present. Not a blocker, but tests
  must account for it.
- **`bcrypt.GenerateFromPassword` is intentionally slow** (~100ms per call at
  default cost). Tests that create many users will be slow. This is by design
  and should not be worked around by lowering the cost in tests.

---

## 4. Scope Enforcement (Engagement Boundaries)

**Impact if broken**: Operations could silently target out-of-scope systems,
which is a legal liability and breach of the engagement contract. The framework's
core value proposition — authorized-only operations — depends on this.

### What to test

- IP address inside a CIDR range is accepted.
- IP address outside all CIDR ranges is rejected with a reason.
- Exact hostname match (case-insensitive) is accepted.
- Domain suffix match works (e.g., `host.example.com` matches domain `example.com`).
- Excluded hosts are rejected even if they match a CIDR or hostname rule.
- Invalid CIDR in `NewScope` returns an error.
- `TimeWindow.IsActive` returns false before start time and after end time.
- `KillSwitch.Activate` / `IsActive` / `Deactivate` lifecycle works correctly.
- `CheckRemoteKillSwitch` returns `true` (kill) when the endpoint is unreachable
  (fail-closed behavior).
- `CheckRemoteKillSwitch` returns `true` when the endpoint returns non-200.
- `CheckRemoteKillSwitch` returns `false` (continue) on HTTP 200.
- `DataQuota.Consume` rejects when the quota would be exceeded.

### Files and functions involved

| File | Function | Role |
|------|----------|------|
| `pkg/engagement/scope.go:18` | `NewScope` | Parses CIDRs, constructs scope |
| `pkg/engagement/scope.go:37` | `Scope.Contains` | CIDR, hostname, domain, exclusion checks |
| `pkg/engagement/scope.go:75` | `TimeWindow.IsActive` | Time-based scope |
| `pkg/engagement/safeguards.go:11` | `KillSwitch` | Per-engagement kill switch |
| `pkg/engagement/safeguards.go:47` | `CheckRemoteKillSwitch` | HTTP-based remote kill (fail-closed) |
| `pkg/engagement/safeguards.go:69` | `DataQuota` | Byte-counting limiter |
| `server/api/httpapi/handler.go:433` | `scope-check` endpoint | HTTP API scope check (uses `strings.Contains` — different from library) |

### Test type: Unit test

`Scope`, `KillSwitch`, and `DataQuota` are pure in-memory structs with no
dependencies. Existing tests in `pkg/engagement/scope_test.go` and
`pkg/engagement/safeguards_test.go` already cover basic cases — this plan
identifies the gaps.

For `CheckRemoteKillSwitch`, use `httptest.NewServer` to simulate the remote
endpoint returning 200, non-200, or being unreachable (close the server
before calling).

### What is hard to test

- **The HTTP API scope check (`handler.go:455`) uses `strings.Contains` instead
  of `Scope.Contains`**. These are two different implementations with different
  semantics. Testing the API endpoint does not validate the library, and vice
  versa. Both need separate tests.
- **`TimeWindow.IsActive` uses `time.Now()` directly**. Testing boundary
  conditions (exactly at start/end time) is racy unless the window is set to
  a large range that definitely includes or excludes `Now()`.
- **`CheckRemoteKillSwitch` uses `http.DefaultClient`**. This is a global that
  could be affected by other tests or environment settings (proxy, etc.).

---

## 5. Audit Log Hash Chain Integrity

**Impact if broken**: The tamper-evident audit trail — required for engagement
reports and legal defensibility — would either silently accept tampered entries
or reject valid ones. An operator might not discover the problem until presenting
evidence to a client or in court.

### What to test

- A sequence of logged entries forms a valid hash chain (each entry's
  `PreviousHash` matches the prior entry's `EntryHash`).
- Recomputing any entry's hash from its fields produces the stored `EntryHash`.
- Modifying any field in a middle entry breaks the chain at that point.
- Deleting an entry breaks the chain.
- An empty log is reported as valid.
- A single-entry log (no predecessor) is valid with `PreviousHash` = `""`.
- The `Logger.Log` method writes entries to all registered `Writer` implementations.
- Export formats (JSON, CEF, LEEF) produce parseable output.

### Files and functions involved

| File | Function | Role |
|------|----------|------|
| `pkg/audit/logger.go:64` | `Logger.Log` | Creates entry, computes hash, writes to writers |
| `pkg/audit/logger.go:96` | `computeHash` | JSON-serializes selected fields → SHA-256 |
| `pkg/audit/export.go` | `ExportJSON`, `ExportCEF`, `ExportLEEF` | Audit export formats |
| `server/api/httpapi/handler.go:814` | `GET /api/audit/verify` | Loads entries from DB, walks chain, verifies hashes |

### Test type: Unit test (library) + integration test (API endpoint)

The `pkg/audit` library is self-contained — create a `Logger` with a
`Writer` that collects entries into a slice, log several entries, then
verify the chain programmatically. Existing tests in `pkg/audit/logger_test.go`
may already cover some of this.

The API verification endpoint (`/api/audit/verify`) requires a GORM database
with `AuditEntry` records. Use SQLite in-memory for this.

### What is hard to test

- **Two incompatible hash implementations exist**. The `pkg/audit/logger.go`
  `computeHash` function serializes `{id, timestamp, operator_id, event_type,
  action, previous_hash}` as JSON, then hashes. The `handler.go:851-857`
  verification endpoint concatenates raw bytes: `id + created_at_rfc3339nano +
  action + previous_hash`. These will produce different hashes for the same entry.
  Tests must be written against each implementation separately, and a test should
  explicitly document and assert that they are incompatible.
- **`Logger.Log` uses `time.Now().UTC()` and `uuid.New()`**, making entries
  non-deterministic. Hash chain validation tests should verify the chain property
  (each entry links to the previous) rather than asserting exact hash values.
- **No code currently writes `AuditEntry` records to the database**. To test the
  API verification endpoint, tests must insert entries manually with `db.Create`.
  The entries must use the `handler.go` hash algorithm (not the `pkg/audit` one)
  to pass the endpoint's verification.
- **The `AuditEntry` GORM model and the `audit.Entry` struct are separate types**
  with similar but not identical fields. There is no mapping function between them.

---

## Summary Matrix

| # | Flow | Test type | Blocks | Existing coverage |
|---|------|-----------|--------|-------------------|
| 1 | Registration + beacon loop | Unit (`net.Pipe`) | Everything downstream | None |
| 2 | Task queue + dispatch + results | Unit + HTTP (`httptest`) | All operator interaction | None |
| 3 | Authentication + tokens | Unit (`httptest`) | All protected endpoints | None |
| 4 | Scope enforcement | Unit (extend existing) | Legal compliance | Partial (`pkg/engagement/*_test.go`) |
| 5 | Audit hash chain | Unit + integration | Engagement reports | Partial (`pkg/audit/logger_test.go`) |

Flows 1-3 have zero test coverage today. Flow 4 has partial coverage in the
`pkg/engagement` tests but the HTTP API scope-check endpoint (`strings.Contains`
path) is untested. Flow 5 has partial coverage in `pkg/audit` tests but the
API verification endpoint and the hash incompatibility are untested.
