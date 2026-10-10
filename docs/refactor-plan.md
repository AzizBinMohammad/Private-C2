# Refactor Plan

Ordered, incremental cleanup steps derived from CLAUDE.md "Known Problem Areas"
and docs/known-issues.md. Each step is safe to commit independently. No new
features, no behavior changes, no new dependencies.

Steps are ordered lowest risk first.

---

## Phase A: Extract Shared Types (Lowest Risk)

### Step 1 — Add tests for wire protocol type serialization

- **Goal**: Establish a test baseline before extracting the duplicated wire
  protocol types into a shared package.
- **Files touched**: new file `server/c2/handler_wire_test.go` (or extend
  existing `server/c2/handler_test.go`)
- **Existing test coverage**: `server/c2/handler_test.go` tests registration and
  task flows but does not test round-trip JSON serialization of each wire type
  (`Message`, `RegisterData`, `CheckinData`, `TaskingData`, `ResultData`,
  `TaskWire`) in isolation.
- **Risk level**: Low — adding tests only, no production code changes.
- **Verify**: `make test` passes.

### Step 2 — Extract wire protocol types into `pkg/protocol`

- **Goal**: Eliminate the three independent copies of `Message`, `RegisterData`,
  `CheckinData`, `TaskingData`, `ResultData`, and `TaskWire` by placing them in
  a single shared package.
- **Files touched**:
  - New file: `pkg/protocol/types.go` (shared type definitions)
  - `server/c2/handler.go` — remove local type definitions, import `pkg/protocol`
  - `cmd/implant/main.go` — remove local type definitions, import `pkg/protocol`
  - `cmd/client/main.go` — remove local type definitions (if it uses them),
    import `pkg/protocol`
  - `server/c2/handler_test.go` — update imports
  - `server/api/httpapi/handler_test.go` — update imports if needed
- **Existing test coverage**: Step 1 tests + `server/c2/handler_test.go` +
  `server/api/httpapi/handler_test.go` cover registration, beacon, and task
  flows that exercise these types end-to-end.
- **Risk level**: Low — purely mechanical rename. JSON tags stay identical, so
  the wire protocol does not change. The types are already structurally identical
  across the three files.
- **Verify**:
  1. `make test` passes.
  2. `go vet ./...` passes.
  3. `grep -r 'type Message struct' cmd/ server/c2/` finds only `pkg/protocol`.

---

## Phase B: Split handler.go Monolith (Low-Medium Risk)

### Step 3 — Add HTTP API handler tests for routes that lack coverage

- **Goal**: Establish test coverage for endpoint groups before extracting them
  into separate files.
- **Files touched**: extend `server/api/httpapi/handler_test.go`
- **Existing test coverage**: `handler_test.go` (731 lines) covers auth,
  sessions, tasks, and audit verification. Check coverage for: listener CRUD,
  engagement CRUD + scope-check, payload generation, operator CRUD, beacon CRUD,
  OT endpoints, and server status. Add tests for any gaps.
- **Risk level**: Low — tests only.
- **Verify**: `make test` passes.

### Step 4 — Extract session/task HTTP handlers to `server/api/httpapi/sessions.go`

- **Goal**: Move the session listing, session detail, and task submission/polling
  handler closures out of `NewRouter()` into named functions in a dedicated file.
- **Files touched**:
  - New file: `server/api/httpapi/sessions.go`
  - `server/api/httpapi/handler.go` — remove extracted closures, call new
    functions in route registration
- **Existing test coverage**: `handler_test.go` has tests for `GET /api/sessions`,
  `POST /api/sessions/{id}/task`, and `GET /api/tasks/{id}`.
- **Risk level**: Low — moving code within the same package. Closures become
  methods or package-level functions. No behavior change.
- **Verify**:
  1. `make test` passes (existing handler tests exercise the same routes).
  2. `curl` smoke test: start server, verify `GET /api/sessions` still returns
     JSON.

### Step 5 — Extract engagement HTTP handlers to `server/api/httpapi/engagements.go`

- **Goal**: Move engagement CRUD, scope-check, and killswitch handlers to their
  own file.
- **Files touched**:
  - New file: `server/api/httpapi/engagements.go`
  - `server/api/httpapi/handler.go` — remove extracted closures
- **Existing test coverage**: Step 3 should have added engagement tests. If not,
  add them before this step.
- **Risk level**: Low — same-package code move.
- **Verify**: `make test` passes.

### Step 6 — Extract remaining handler groups

- **Goal**: Move listener, beacon, operator, payload, audit, OT, and server-status
  handlers into dedicated files.
- **Files touched**:
  - New files: `listeners.go`, `beacons.go`, `operators.go`, `payloads.go`,
    `audit.go`, `ot.go`, `status.go` (all in `server/api/httpapi/`)
  - `server/api/httpapi/handler.go` — reduced to `NewRouter()` with route
    registration only
- **Existing test coverage**: Steps 3-5 tests + existing `handler_test.go`.
- **Risk level**: Low — same-package code moves. Each file compiles in the same
  package and has access to the same types.
- **Verify**:
  1. `make test` passes.
  2. `handler.go` is under 200 lines (route registration + helper types only).
  3. `go vet ./...` passes.

---

## Phase C: Extract Shared TLS Config (Low Risk)

### Step 7 — Add tests for TLS config construction

- **Goal**: Test baseline before extracting duplicated `buildTLSConfig`.
- **Files touched**: new file `cmd/server/tls_test.go` or
  `cmd/implant/tls_test.go` (depending on which is easier to test in isolation)
- **Existing test coverage**: None. `buildTLSConfig` in `cmd/server/main.go` and
  `cmd/implant/main.go` are untested.
- **Risk level**: Low — tests only.
- **Verify**: `make test` passes.

### Step 8 — Extract `buildTLSConfig` into `pkg/tlsutil`

- **Goal**: Remove the duplicated TLS config setup by sharing a single
  implementation.
- **Files touched**:
  - New file: `pkg/tlsutil/config.go`
  - `cmd/server/main.go` — replace local `buildTLSConfig` with `tlsutil` call
  - `cmd/implant/main.go` — replace local TLS setup with `tlsutil` call
- **Existing test coverage**: Step 7 tests.
- **Risk level**: Low — the two implementations do the same thing (load cert/key,
  set min TLS version, configure client auth). Behavioral equivalence is easy to
  verify.
- **Verify**:
  1. `make test` passes.
  2. Manual: start server + implant, confirm TLS handshake succeeds.
  3. `grep -r 'buildTLSConfig\|tls.Config{' cmd/` confirms no remaining
     duplicates.

---

## Phase D: Reconcile Audit Hash Implementations (Medium Risk)

### Step 9 — Add a cross-implementation audit hash test

- **Goal**: Document and test the incompatibility between the two audit hash
  algorithms before choosing which one to keep.
- **Files touched**: new file `pkg/audit/compat_test.go` or extend
  `pkg/audit/hashchain_test.go`
- **Existing test coverage**: `pkg/audit/logger_test.go` and
  `pkg/audit/hashchain_test.go` test the library hash. `handler_test.go` tests
  the API verification endpoint. Neither tests cross-compatibility.
- **Risk level**: Low — tests only.
- **Verify**: `make test` passes. The test should assert that the two algorithms
  produce different hashes for the same input (documenting the known issue).

### Step 10 — Align audit hash computation

- **Goal**: Make `pkg/audit/logger.go:computeHash` and the verification logic in
  `handler.go` use the same algorithm, so entries written by the library pass API
  verification.
- **Files touched**:
  - `pkg/audit/logger.go` — update `computeHash` to match the field set and
    serialization format used by the API, OR
  - `server/api/httpapi/handler.go` (or `audit.go` after step 6) — update
    verification to match the library
  - `pkg/audit/logger_test.go` — update expected hashes
  - `pkg/audit/hashchain_test.go` — update expected hashes
- **Existing test coverage**: Step 9 cross-compatibility test will flip from
  "assert different" to "assert same".
- **Risk level**: Medium — changes hash computation. However, no code currently
  writes `AuditEntry` records through `pkg/audit`, so no existing data is
  affected. The API endpoint is the only consumer.
- **Why medium**: If any external tool or manual process has written audit entries
  using either algorithm, changing the algorithm would break verification of those
  entries. Confirmed via known-issues.md that no code currently writes entries, so
  the risk is theoretical.
- **Verify**:
  1. `make test` passes.
  2. Step 9 cross-compatibility test now passes with "same hash" assertion.
  3. `handler_test.go` audit verification tests still pass.

---

## Phase E: Add `AuditEntry` ↔ `audit.Entry` Mapping (Medium Risk)

### Step 11 — Create a mapping between `models.AuditEntry` and `audit.Entry`

- **Goal**: Provide conversion functions between the GORM model and the library
  struct so they can be used together.
- **Files touched**:
  - New file: `server/store/models/audit_convert.go` (two functions:
    `AuditEntryFromLib`, `AuditEntryToLib`)
  - New file: `server/store/models/audit_convert_test.go`
- **Existing test coverage**: None for conversion. `pkg/audit/logger_test.go`
  tests the library type. `handler_test.go` tests the GORM model via DB queries.
- **Risk level**: Medium — introduces a new mapping layer. Getting field mappings
  wrong (e.g., `Timestamp` ↔ `CreatedAt`, `Metadata map` ↔ `Metadata string`)
  could cause silent data loss.
- **Verify**:
  1. `make test` passes.
  2. Round-trip test: `Entry → AuditEntry → Entry` preserves all fields.

---

## Phase F: Resolve `store.Open` SQLite `:memory:` Bug (Low Risk)

### Step 12 — Fix GORM SQLite in-memory migration with `PrepareStmt: true`

- **Goal**: Make `store.Open` work with DSN `:memory:` so tests do not need temp
  file workarounds.
- **Files touched**:
  - `server/store/db.go` — disable `PrepareStmt` for SQLite `:memory:`, or use
    `file::memory:?cache=shared` DSN
  - `server/store/db_test.go` (new) — test that `Open` + `Migrate` succeeds
    with `:memory:`
- **Existing test coverage**: None for `store.Open` itself.
  `handler_test.go:setupTestRouter` works around this with `t.TempDir()`.
- **Risk level**: Low — the fix only affects the `:memory:` path, which is only
  used in tests. Production uses file-based SQLite or PostgreSQL.
- **Verify**:
  1. `make test` passes.
  2. New test confirms `:memory:` open + migrate succeeds.

---

## Phase G: Bug Fixes from known-issues.md (Separate from Refactoring)

These are the bugs documented in `docs/known-issues.md`. They require behavior
changes and should be done as separate PRs after the refactoring steps above are
complete. Listed here for tracking, not for inclusion in the refactoring PRs.

### Bug Fix A — Replace `strings.Contains` scope check with `Scope.Contains`

- **Ref**: known-issues.md #1
- **File**: `server/api/httpapi/handler.go:455` (or `engagements.go` after step 5)
- **What**: The HTTP API scope-check endpoint uses `strings.Contains` on raw JSON
  instead of `pkg/engagement.Scope.Contains` with proper CIDR/hostname/domain
  parsing.
- **Risk**: Medium — changes endpoint behavior. Could reject targets that were
  previously (incorrectly) accepted.
- **Prerequisite**: Step 5 (extract engagement handlers) and step 3 (add
  engagement endpoint tests including false-positive cases).

### Bug Fix B — Align or unify audit hash computation

- **Ref**: known-issues.md #2
- **What**: Covered by steps 9-10 above. Listed here for completeness since
  known-issues.md tracks it as a bug.

### Bug Fix C — Bridge `AuditEntry` and `audit.Entry` types

- **Ref**: known-issues.md #3
- **What**: Covered by step 11 above. Listed here for completeness.

### Bug Fix D — Fix SQLite `:memory:` migration

- **Ref**: known-issues.md #4
- **What**: Covered by step 12 above. Listed here for completeness.
