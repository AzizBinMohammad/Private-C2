# Known Issues

Issues discovered while writing tests against the test plan. No application
code was changed.

---

## ~~1. HTTP API scope-check uses `strings.Contains` instead of `Scope.Contains`~~

**RESOLVED** — commit `769ad3d` on branch `bugfix-A-scope-contains`.

The scope-check endpoint (`server/api/httpapi/engagements.go`) now unmarshals
`ScopeConfig` JSON, merges `hostnames`/`hosts`/`targets` keys for backwards
compatibility, builds a `pkg/engagement.Scope`, and calls `scope.Contains(target)`.
Returns proper errors for malformed or empty configs. Covered by 13 tests
(4 original + 9 regression) including CIDR containment, partial-string rejection,
case-insensitive hostname, domain suffix, exclusion enforcement, and edge cases.

---

## 2. Two incompatible audit hash algorithms

**File (library):** `pkg/audit/logger.go:96-114`
**File (API):** `server/api/httpapi/handler.go:851-857`

**Symptom:** The `pkg/audit` library computes hashes by JSON-serializing a struct
containing `{id, timestamp, operator_id, event_type, action, previous_hash}` and
then SHA-256 hashing the JSON. The API verification endpoint (`/api/audit/verify`)
computes hashes by concatenating raw bytes: `id + created_at_RFC3339Nano + action +
previous_hash`.

These produce different hashes for the same entry. Entries written by the library
will fail verification by the API endpoint, and vice versa.

**How to reproduce:**
1. Use `pkg/audit.Logger.Log()` to write entries with hash chaining
2. Store them in the database as `AuditEntry` records
3. Call `GET /api/audit/verify`
4. Verification fails because the hashes don't match

Currently no code writes `pkg/audit` entries to the database, so this has not caused
a runtime failure yet, but it will as soon as the two systems are connected.

---

## 3. `AuditEntry` GORM model and `audit.Entry` struct are separate types

**File:** `server/store/models/models.go:121-136`
**File:** `pkg/audit/logger.go:33-48`

**Symptom:** The `models.AuditEntry` (GORM model for database persistence) and
`audit.Entry` (library struct for hash computation) have similar but not identical
fields. There is no mapping function between them. The library struct uses
`Timestamp time.Time` while the model uses `CreatedAt time.Time`; the library has
`Metadata map[string]any` while the model has `Metadata string`. Any integration
between the two will require a manual mapping layer.

---

## 4. GORM SQLite in-memory migration fails with `PrepareStmt: true`

**File:** `server/store/db.go:36`

**Symptom:** When using `store.Open` with DSN `:memory:` and the default config
(which sets `PrepareStmt: true`), GORM's `AutoMigrate` fails with
`no such table: main.operators` after successfully executing the `CREATE TABLE`
statement. The `CREATE UNIQUE INDEX` that follows cannot find the table.

**How to reproduce:**
```go
db, _ := store.Open(store.Config{Dialect: "sqlite", DSN: ":memory:"})
store.Migrate(db) // fails
```

**Workaround:** Use a temp file path instead of `:memory:` for test databases.
- ~~go vet warnings: fmt.Sprintf("%s:%d", ...) for network addresses~~
  **RESOLVED** — branch `bugfix-ipv6-joinhostport`. Replaced all 21 call sites
  across 10 files with net.JoinHostPort (11 flagged by go vet, 10 additional
  inline-in-DialTimeout sites that go vet missed). Display-only address strings
  (iec104.go, mqtt.go, opcua.go) left as-is. Files: modules/ot/protocols/coap.go,
  modules/ot/protocols/common.go, modules/network/network.go,
  modules/ot/discovery.go (8 sites), modules/ot/fingerprint.go,
  modules/ot/historian.go, modules/ot/hmi.go, modules/ot/segmentation.go,
  modules/ot/serial.go, modules/ot/wireless.go.

- Test suite timeout: `make test` (or CI) using `-race` with a 2-minute
  timeout is too tight now that server/api/httpapi/handler_test.go has grown
  (bcrypt login is slow under race instrumentation, multiplied across many
  tests). Confirmed tests pass correctly with -race given a 5-minute timeout
  (165.9s). Fix: raise the timeout in the test command/CI config to at least
  3-5 minutes, or share a single pre-hashed test user across tests instead of
  calling the real login/bcrypt path each time.

UPDATE: Resolved in step 3. setupTestRouter tests now use a bcrypt.MinCost
override (test-only, via newAuthManagerFn indirection in handler.go) instead
of DefaultCost. Full suite with -race now runs in ~75s instead of ~300s.

---

## ~~5. Implant silently falls back to InsecureSkipVerify when no CA is provided~~

**RESOLVED 2026-10-15.** `tlsutil.ClientTLSConfig` now returns an error when
neither a CA nor the explicit `--insecure` flag is supplied, so verification
cannot be disabled by omission — only deliberately. See the 2026-10-15 section
at the end of this file. The original report is retained below for history.

**File:** `cmd/implant/main.go:74`

**Symptom:** When the implant's `--ca` flag is empty (the default), `buildTLSConfig`
sets `InsecureSkipVerify: true` without any warning or log message. This means the
implant will connect to any server presenting any certificate, making it vulnerable
to MITM attacks. The operator has no indication that verification was skipped.

By contrast, `implant/transport/mtls/mtls.go` explicitly hardcodes
`InsecureSkipVerify: false` and requires a CA cert, and
`implant/transport/https/https.go` exposes `InsecureSkipVerify` as an explicit
config option rather than a silent fallback.

**Origin:** Introduced in commit `fd8349b` ("Wire up C2 framework end-to-end") as
part of the initial implant entry point. No commit message, code comment, or
`docs/decisions.md` entry documents this as an intentional tradeoff.
`docs/decisions.md` documents the server's self-signed cert fallback as intentional
but does not mention the implant's corresponding insecure-verification fallback.

**Security relevance:** A deployed implant without a `--ca` flag accepts any
certificate, enabling interception of C2 traffic. This is likely a development
convenience (pairing with the server's self-signed cert fallback) that should either
be documented as an accepted risk for local development, or changed to require an
explicit `--insecure` flag rather than silently degrading.

**Not fixing in this refactor** — flagging for a separate security review.

---

## Issues found by the 2026-10-15 audit

See `docs/audit-2026-10-15.md` for the full report, evidence and roadmap.
Everything below was verified against source and, where stated, reproduced
against a running server.

### RESOLVED on 2026-10-15

R1. **Operator CLI was completely non-functional (401 on every command).**
   `cmd/client/main.go` never called `POST /api/auth/login` and never set an
   `Authorization` header, so every request hit the auth middleware. Reproduced:
   the console printed `Failed to list sessions: server returned 401`. Fixed by
   introducing the shared authenticated client in `client/api` and logging in at
   startup.
R2. **CLI could never detect task completion.** The console tested
   `result.Status == "completed"`, but the server's completed `TaskResult` has no
   `status` field — only the pending case returns `{"status":"pending"}`. Every
   task polled to the 30 s timeout and its output was discarded. The web portal
   already used the correct "not pending means done" test; the CLI now matches it.
R3. **CLI `upload` silently dropped the file body.** The console sent the base64
   payload in a `data` field the API's `TaskRequest` does not define, so the
   implant received `upload` with no payload and failed with
   `upload args must be 'base64data|filepath'`. Fixed by sending the implant's
   documented `"<base64>|<remote-path>"` args format.
R4. **`make cross-compile` failed.** `IMPLANT_SRC` pointed at `./implant`, a
   library module with no `main` package (`no Go files in .../implant`). The
   working entry point is `./cmd/implant`. Same defect in `scripts/quickstart.sh`,
   which masked it behind a warning. Both fixed.
R5. **Stored XSS in the web portal.** `esc()` escaped `&`, `<` and `>` but not
   quotes, while server-supplied engagement and operator names were interpolated
   into `onclick="fn('...')"` handlers. Escaping quotes alone is not sufficient
   either — the HTML parser decodes `&#39;` back to `'` before the JS parser sees
   the handler. Added `jsArg()`, which JS-escapes then HTML-escapes, and applied
   it to all nine inline-handler sites.
R6. **Portal rendered `undefined` / empty values.** Audit "Verify Chain" read
   `d.entries_checked` and `d.first_broken` (the API returns `entries` and
   `broken_at_index`); the server status card read `d.memory_mb` (the API returns
   `memory_alloc` in bytes) and a `hostname` field that did not exist. The field
   names are now aligned and `hostname` was added to the status response.
R7. **Payload download was dead in the portal.** The Download control was a plain
   `<a href>`, and a top-level browser navigation cannot send the
   `Authorization` header, so it always 401'd. Replaced with an authenticated
   fetch through the new `apiFetchRaw()` helper and a blob download.
R8. **Tests in `cmd/` and `implant/` never ran.** `make test` covered only
   `./pkg/... ./server/... ./client/...`, so the `cmd/server` and `cmd/implant`
   TLS tests were dead weight. `make test` and `make lint` now cover all nine
   workspace modules.

### RESOLVED on 2026-10-15 (second batch)

R9. **mTLS was never enforced on the implant listener.**
   `pkg/tlsutil/config.go:54` set `ClientAuth = tls.NoClientCert` even when
   `--ca` was supplied, so the flag documented as "CA certificate PEM for
   verifying implants" verified nothing and any host that could reach the port
   could register. Now `ClientAuth = tls.RequireAndVerifyClientCert`.
   `scripts/setup-ca.sh` also issues an implant client certificate, and
   `scripts/quickstart.sh` passes `--ca/--cert/--key` to both the server and the
   implant. Verified end to end: an implant with a CA-signed client certificate
   registers; one without is rejected with `tls: certificate required`; one
   presenting a certificate from a different CA is rejected. Covered by three
   handshake tests in `pkg/tlsutil/config_test.go`.

   Related: `ClientTLSConfig` no longer silently sets `InsecureSkipVerify` when
   no CA is given (previously known-issues #5). It returns an error unless
   `--ca` or the new explicit `--insecure` flag is passed, so verification can
   only be disabled deliberately.

R10. **Duplicate TLS test files removed.** `cmd/server/tls_test.go` and
    `cmd/implant/tls_test.go` were test-for-test copies of
    `pkg/tlsutil/config_test.go`, left over from before the extraction. The
    tlsutil suite is a strict superset (it adds the handshake tests above), so
    the copies were deleted rather than updated.

### RESOLVED on 2026-10-15 (third batch — session and listener control)

R11. **Session kill / lock / unlock and listener start / stop were deceptive.**
    They wrote `models.Session` / `models.Listener` rows that never exist for
    live in-memory sessions, then reported success. Now:
    - `DELETE /api/sessions/{id}` calls `ImplantServer.CloseSession`, which
      closes the connection (ending the session), reaps the session's task queue
      and results, and returns 404 when the session is not live. Documented
      behaviour: an implant configured to reconnect comes back as a *new*
      session; the portal no longer claims the action is irreversible.
    - `lock` / `unlock` act on a new in-memory `LockedBy` field. A second
      operator attempting to take a held lock gets 409 instead of silently
      overwriting it.
    - `POST /api/listeners` now binds a real TLS socket through
      `ImplantServer.StartListener` and only records `running` after the bind
      succeeds; `DELETE` closes the socket. Verified live: an implant connected
      to a listener created through the API and registered; deleting it freed
      the port; a repeated DELETE returns 404.
    - Unimplemented transports (`https`, `dns`, `wireguard`) are refused with a
      400 and a clear message instead of being stored as `running`. They cannot
      be substituted for the live path: `server/c2/listener/*` models sessions
      by client-certificate CN with a request/response data handler, whereas the
      implant speaks the register/checkin/result protocol.
    - `GET /api/listeners` reports status and `active_connections` from the
      running processes, so the column can no longer claim a listener is up
      when nothing is bound.

R12. **Unbounded in-memory growth (partially fixed).** `removeSession` now reaps
    `taskQueues[sessionID]` and every `taskResults` entry belonging to the
    session, and `CloseSession` does the same. Still open: `taskResults` for
    live sessions are never pruned, and expired auth tokens are never removed
    from `AuthManager.tokens` (no logout/revoke path exists).

R13. **Data race on `ImplantSession` (fixed).** `ListSessions`/`GetSession` now
    return copies via `snapshot()`, so the HTTP layer no longer marshals a
    session while the connection loop writes `LastCheckin` under the mutex. The
    new `LockedBy` field would otherwise have widened this race.

### OPEN — confirmed, not yet fixed

1. **The entire OT/ICS assessment capability has no execution path.** The
    headline feature (32 files, 17 protocol clients, 10 models, a portal tab, OT
    CLI commands) cannot produce results: `cmd/implant/main.go` implements only
    eleven task types (shell, ls, pwd, cd, ps, cat, upload, download, screenshot,
    nmap, scan) and none of them is OT. `implant/modules/ot/**` is imported by
    nothing, and the six `/api/ot/*` routes are read-only database queries
    with no endpoint that starts an assessment.
2. **`make proto` is a placeholder and no `.pb.go` exists.** `server/api/grpc/*`
    and `server/core/*` are unreachable — nothing constructs a `grpc.NewServer`.
3. **`/api/audit/export` does not exist** although the portal has an Export
    button and `pkg/audit/export.go` implements JSON/CEF/LEEF. The button 404s.
4. **No authorization layer on the HTTP API.** Only authentication is wired
    (`handler.go:35-131`). Any authenticated user can `POST /api/operators` with
    `role:"admin"`, delete operators, generate payloads, and read the audit log.
    The RBAC code in `server/api/middleware/rbac.go` is gRPC-only, unreachable,
    and itself fail-open (`checkPermission` returns `nil` for unmapped methods).
5. **Deleting an operator does not revoke credentials.**
    `operators.go:92-101` deletes the DB row only; the bcrypt hash stays in
    `AuthManager.users`, so a "deleted" operator can still log in.
6. **59 files fail `gofmt`.** Not fixed here because reformatting them is
    unrelated to the audit and would bury the real diff. Worth a dedicated
    `gofmt -w` commit.
7. **`docker-compose.yml` / `Dockerfile` cannot start a working stack.**
    Compose sets `PC2_*` variables the server ignores (`server/config` is
    imported by nothing) and exposes port 31337 ("gRPC") where nothing listens,
    while the real ports (4444 implant TLS, 8080 API) are unexposed. The runtime
    image has no `WORKDIR`, so the non-root `pc2` user cannot create the default
    `pc2.db` in `/` and the container exits on startup. Payload generation also
    cannot work in the container: `buildImplant()` shells out to `go build`, but
    the runtime image ships no Go toolchain and no source tree.
8. **The portal's task dropdown offers task types the implant does not
    implement.** `#cmd-type` in `server/api/httpapi/webui/index.html` lists
    `kill`, `ifconfig`, `netstat`, `portscan`, `mkdir`, `rm`, `cp`, `mv` and
    `resolve`, none of which has a case in `handleTask`
    (`cmd/implant/main.go`). Selecting one queues a task that comes back as
    `unknown task type: <name>`. The dropdown is a static list, so it cannot
    drift back into sync on its own — it needs either handlers or pruning.
    (`portscan` in particular looks supported because
    `implant/modules/network/network.go` implements a scope-checked port scan,
    but that package is imported by nothing.)
9. **A `vulns` scan blocks the implant's beacon loop for its whole duration.**
    `handleTask` in `cmd/implant/main.go` runs inline in a serial loop, so while
    a scan runs the implant sends no checkins: the session looks stale in the
    portal and any other queued task waits. It is bounded (the profile's
    `--host-timeout` is 4 minutes and the module's own deadline 7), but a
    `vulns` scan was measured at ~6m10s against a single loopback host, so in
    practice the session reads as stale for minutes. Fixing it properly means
    running tasks off the beacon loop with a separate result channel, which
    changes the task model; the timeout values in `implant/modules/nmap`,
    `cmd/client` (`scanPollTimeout`) and the portal (`taskPollAttempts`) are
    sized to match each other and must move together.
