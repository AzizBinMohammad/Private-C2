# Technical Decisions

> Check this file before changing anything listed here. Add a new entry
> whenever a major decision is made.

---

## Language and Runtime

* **Decision**: Go 1.23 with a `go.work` workspace linking 9 modules.
* **Why (inferred)**: Go's static binaries and cross-compilation make it straightforward to produce implants for linux/amd64, windows/amd64, and darwin/arm64 from one source tree. The multi-module workspace keeps server, client, implant, and shared library dependency trees separate so the implant binary doesn't link server-only packages.
* **What would conflict with it**: Introducing `replace` directives that break workspace resolution; adding CGO dependencies to the implant (prevents `CGO_ENABLED=0` cross-compilation); collapsing all modules into one `go.mod` (loses per-component dependency isolation).

---

## API Transport: HTTP REST (Not gRPC)

* **Decision**: The operator-facing API is plain HTTP REST using `net/http` with `http.NewServeMux`. No web framework.
* **Why (inferred)**: Minimizes dependencies and keeps the attack surface small. The standard library router is sufficient for the current endpoint count. gRPC stubs and proto definitions exist in the codebase but are not wired in; the REST API is the only functional operator interface.
* **What would conflict with it**: Switching to gRPC for operator traffic would require rewriting the CLI client, the web portal's fetch calls, and adding a gRPC-Web or gRPC-gateway proxy for browser access. Adding a framework (chi, gin, echo) would be a dependency change that requires approval per project rules.

---

## Implant Wire Protocol: Length-Prefixed JSON over TLS

* **Decision**: Implant-to-server communication uses 4-byte little-endian length-prefixed frames carrying JSON-encoded `Message{Type, Data}` structs over a raw TLS connection (port 4444).
* **Why (inferred)**: JSON is human-debuggable during development. Length-prefix framing avoids HTTP overhead and gives a persistent bidirectional channel. TLS 1.3 (implant) / TLS 1.2+ (server) provides transport encryption without a separate envelope layer.
* **What would conflict with it**: Switching to protobuf wire encoding without updating all three locations that define message types (`server/c2/handler.go`, `cmd/implant/main.go`, `cmd/client/main.go`). Introducing HTTP/2 or gRPC for implant traffic would change the reconnection model. Enabling the `pkg/envelope` Seal/Open path (sign+encrypt+compress) would double-encrypt unless the TLS layer is removed.

---

## Data Storage: GORM with SQLite Default, PostgreSQL for Production

* **Decision**: GORM ORM with auto-migration. SQLite is the default (single-file, zero-config). PostgreSQL is the production dialect, configured via `PC2_DB_DIALECT` / Docker Compose.
* **Why (inferred)**: SQLite for local development removes the need for any database server. GORM's dialect abstraction lets the same model code target both. Auto-migration avoids maintaining separate migration files during early development.
* **What would conflict with it**: Using raw SQL queries that aren't portable across SQLite and PostgreSQL. Adding a migration tool (goose, atlas) would conflict with auto-migration unless auto-migration is removed first. Introducing a third dialect without adding it to `store.Open()`.

---

## Model IDs: UUID Strings

* **Decision**: All GORM models embed a `Base` struct whose `ID` is a UUID string, auto-generated in a `BeforeCreate` hook via `github.com/google/uuid`.
* **Why (inferred)**: UUIDs are safe for distributed/multi-server scenarios, avoid sequential enumeration, and are consistent across SQLite and PostgreSQL.
* **What would conflict with it**: Switching to auto-increment integers would break API consumers that expect UUID strings. Using binary UUID columns would require dialect-specific handling.

---

## Authentication: In-Memory bcrypt + Bearer Tokens

* **Decision**: Operator authentication uses bcrypt-hashed passwords stored in an in-memory map. Login returns a 32-byte hex token with 12-hour TTL, validated with constant-time comparison. No external auth provider.
* **Why (inferred)**: Self-contained authentication with no external dependencies. Suitable for a tool that runs on isolated engagement infrastructure. bcrypt provides brute-force resistance; constant-time comparison prevents timing attacks.
* **What would conflict with it**: Adding LDAP/OIDC/SSO would require a fundamentally different auth flow. Token persistence (surviving server restarts) would require moving tokens to the database. JWT tokens would remove the need for server-side token storage but would require a signing key management story.

---

## Listeners: Runtime Registry Backed by Sockets, Not Just Rows

* **Decision**: A listener is a running socket owned by `ImplantServer`
  (`server/c2/listeners.go`). `GET /api/listeners` reports status and
  `active_connections` from the running listener; the `models.Listener` row is
  kept as the record of what was configured but is never the source of truth for
  whether something is up. `POST` binds first and only then records `running`;
  `DELETE` closes the socket. Only `mtls` is implemented, and requesting any
  other transport returns 400 rather than a listener that was never bound.
* **Why**: Listener status was previously a database column nothing backed —
  creating a listener stored `running` and returned 201 without binding
  anything, so the portal showed an active listener that could not accept a
  connection, and `DELETE` removed a row while the socket (had there been one)
  kept listening. Runtime state must be read from the runtime.
* **What would conflict with it**: Treating the database row as authoritative
  would reintroduce the bug. Substituting `server/c2/listener/*` for this path
  requires changing the implant's wire protocol: those implementations identify
  sessions by client-certificate CN and dispatch through a request/response data
  handler, whereas the live path uses server-assigned UUID sessions with a
  register/checkin/result loop.

---

## Session Locks: Held In Memory Alongside the Session

* **Decision**: A session lock is a `LockedBy` field on the in-memory
  `ImplantSession`. Locking a session already held by a different operator is
  rejected with 409. `ListSessions`/`GetSession` return copies so callers cannot
  mutate live state or race the connection loop.
* **Why**: The lock previously wrote `models.Session.locked_by`, a row that does
  not exist for a live session (sessions are in-memory), so the write silently
  affected zero rows and every lock appeared to succeed. A lock on a
  disconnected session has no meaning, which is why it belongs with the session.
* **What would conflict with it**: Persisting locks would require persisting
  sessions first; see "Session State" above.

---

## Session State: In-Memory Maps in ImplantServer

* **Decision**: Live implant sessions, task queues, and task results are stored in `sync.RWMutex`-protected Go maps inside `server/c2/handler.go`. They are not persisted to the database.
* **Why (inferred)**: Simplicity for a single-server deployment. Sessions are inherently ephemeral (tied to a TCP connection), and in-memory maps give lock-free-read performance for the hot path (checkins).
* **What would conflict with it**: Multi-server clustering requires shared state (database or Redis). Adding task persistence would require writing tasks/results to the database on every state change. The existing `server/core/sessions.go` state machine is designed for this but is not wired in; integrating it is a prerequisite for any persistence work.

---

## Cryptography: XChaCha20-Poly1305 + Ed25519 + X25519 + ECDSA P-384

* **Decision**: The `pkg/crypto` library uses XChaCha20-Poly1305 (AEAD), Ed25519 (signing), X25519 (key exchange), ECDSA P-384 (PKI/certificates). Replay detection via SHA-256 digest dedup.
* **Why (inferred)**: XChaCha20-Poly1305 has a large nonce (192-bit) that is safe for random generation, avoiding nonce-reuse bugs. Ed25519 is fast and has a simple API. ECDSA P-384 aligns with common TLS certificate practices.
* **What would conflict with it**: Switching to AES-GCM would reintroduce nonce-management complexity. Changing the signing algorithm requires re-generating all signing keys. Note: this crypto library is used only by `pkg/envelope`, which is itself not wired into the current implant-server wire path.

---

## Audit Logging: Append-Only with SHA-256 Hash Chaining

* **Decision**: Audit entries form a hash chain where each entry's hash covers its own fields plus the previous entry's hash (tamper-evident log).
* **Why (inferred)**: Provides cryptographic proof that the audit log has not been modified after the fact, which is important for engagement reports and legal defensibility.
* **What would conflict with it**: Allowing audit entry deletion or update would break the chain. **Caution**: two incompatible hash implementations exist (`pkg/audit/logger.go` uses JSON serialization; `server/api/httpapi/handler.go` uses concatenated raw bytes). Wiring in one without updating the other will break verification.

---

## Web Portal: Embedded Single-Page HTML

* **Decision**: The operator web portal is a single HTML file (`server/api/httpapi/webui/index.html`, 1732 lines) with inline CSS and vanilla JavaScript, served via Go's `embed` filesystem at `/`.
* **Why (inferred)**: Zero frontend build toolchain. The portal ships inside the server binary with no separate deployment step. No Node.js, no bundler, no framework dependencies.
* **What would conflict with it**: Introducing React/Vue/Svelte would require a build pipeline, a separate dev server, and a strategy for embedding the built output. Splitting into multiple files requires updating the embed directive. Any API response shape change requires a manual update to the inline JS.

---

## Deployment: Multi-Stage Docker with Alpine

* **Decision**: `golang:1.23-alpine` builder stage, `alpine:3.19` runtime stage. Docker Compose pairs the server with PostgreSQL 16. The runtime runs as a non-root `pc2` user.
* **Why (inferred)**: Alpine produces small images. Multi-stage build keeps build tools out of the runtime image. Non-root user follows least-privilege. Docker Compose provides a one-command production-like stack.
* **What would conflict with it**: Switching to a distroless or scratch base would require static compilation (no musl). Adding runtime tools (e.g., `go build` for payload generation inside Docker) would require keeping the Go toolchain in the runtime image or using a sidecar.

---

## Implant Cross-Compilation: CGO_ENABLED=0 Static Binaries

* **Decision**: Implant binaries are cross-compiled with `CGO_ENABLED=0`, producing fully static binaries for linux/amd64, windows/amd64, darwin/arm64.
* **Why (inferred)**: Static binaries run on any target without shared library dependencies. `CGO_ENABLED=0` allows cross-compilation from a single host without target-specific C toolchains.
* **What would conflict with it**: Any dependency requiring CGO (e.g., go-sqlite3 in the implant) would break cross-compilation. Platform-specific features that need CGO (certain syscall wrappers) would require a build matrix with cross-compilers. Note: the server Dockerfile uses `CGO_ENABLED=1` because SQLite's C driver needs it.

---

## Scope Enforcement: CIDR + Hostname + Domain Matching

* **Decision**: Engagement scope is defined as lists of CIDR ranges, hostnames, and domain suffixes, with exclusion lists. The `pkg/engagement/scope.go` library validates targets against these rules. The implant safety checker (`implant/safety/safety.go`) is designed to enforce scope before every operation.
* **Why (inferred)**: Scope enforcement is a legal and operational requirement for authorized penetration testing. CIDR matching handles network-level scope; hostname/domain matching handles application-level scope.
* **What would conflict with it**: The HTTP API's scope-check endpoint currently uses `strings.Contains` instead of the structured library — replacing it with proper scope checking is an improvement, not a conflict. Removing scope enforcement would make the tool unsuitable for authorized engagements.

---

## Safety Architecture: Fail-Closed with Kill Switch

* **Decision**: The implant safety system is fail-closed: if the kill switch endpoint is unreachable, the implant shuts down. Safety checks (kill switch, kill date, time window, scope, data quota) run before every operation.
* **Why (inferred)**: In an authorized engagement, failing open (continuing when controls can't be verified) is worse than failing closed (stopping operations). This protects against scope creep and ensures the engagement can be terminated remotely.
* **What would conflict with it**: Making the implant fail-open would violate the safety design. Removing the remote kill switch check would lose the ability to emergency-stop an engagement. The `isSafetyCritical()` stub in OT modules (`implant/modules/ot/ot.go`) returning `false` is a known gap.

---

## Metrics: Prometheus

* **Decision**: Prometheus client library for metrics exposition at `/metrics`. Ten metric counters/gauges are registered covering sessions, tasks, payloads, data exfiltration, scope violations, and kill switch activations.
* **Why (inferred)**: Prometheus is the standard for Go service observability. The metrics are engagement-relevant: operators need visibility into active sessions, task throughput, and safety events.
* **What would conflict with it**: Switching to OpenTelemetry would require replacing the Prometheus client. Note: metrics are currently registered but never incremented — instrumenting them requires touching `handler.go` and `c2/handler.go`.

---

## Go Workspace Module Boundaries

* **Decision**: Nine separate Go modules (`pkg`, `server`, `client`, `implant`, `cmd/server`, `cmd/client`, `cmd/builder`, `cmd/implant`, `cmd/mcp`) linked by `go.work`.
* **Why (inferred)**: The implant module must not transitively pull in server dependencies (database drivers, HTTP router, Prometheus). Separate modules enforce this at the dependency level — the implant binary stays small and reveals nothing about the server.
* **What would conflict with it**: Adding a shared types package imported by both server and implant would create a dependency bridge. Moving to a single `go.mod` would lose the isolation guarantee.

---

## TLS Certificate Management: Self-Signed Fallback + Script-Generated CA

* **Decision**: The server generates a self-signed certificate at startup if no cert/key files are provided. The `scripts/setup-ca.sh` script generates a proper CA + server cert for production use. Operator client certs are generated with `scripts/add-operator.sh`.
* **Why (inferred)**: Self-signed fallback allows quick local development. Script-generated CA supports mutual TLS authentication for production engagements without depending on external PKI.
* **What would conflict with it**: Integrating with an external CA (Let's Encrypt, Vault PKI) would be an addition, not a conflict, but would change the cert provisioning workflow. Removing the self-signed fallback would break the zero-config developer experience.

---

## OT/ICS Assessment: Read-Only with Safety Interlocks

* **Decision**: The OT/ICS module is designed as read-only assessment with pre-flight safety checks (kill switch, scope, connection limits, rate limiting, watchdog auto-shutdown). 17 industrial protocol clients are implemented. A separate set of 10 GORM models stores OT findings.
* **Why (inferred)**: OT/ICS environments are safety-critical. Write operations to industrial controllers could cause physical harm. Read-only assessment with multiple safety interlocks is the appropriate posture for authorized security testing in these environments.
* **What would conflict with it**: Adding write capabilities to OT protocol clients without corresponding safety interlocks. Bypassing the pre-flight checks. The `isSafetyCritical()` stub is a known gap that needs to be implemented before real OT assessments.

---

## Configuration: CLI Flags (Actual) vs Environment Variables (Designed)

* **Decision**: The running server uses `flag` package CLI flags (`--listen`, `--api`, `--db`, etc.). A `server/config/config.go` module exists that reads `PC2_*` environment variables but is not imported by the server entry point.
* **Why (inferred, unclear)**: CLI flags were likely chosen for early development simplicity. The env-var config module appears designed for the Docker/production path (the `docker-compose.yml` references `PC2_*` vars) but was never wired in. This is a known architectural gap.
* **What would conflict with it**: The Docker Compose stack sets `PC2_*` environment variables that the current server binary ignores. Connecting `server/config` would be a fix, but would need to reconcile flag-based and env-var-based configuration (flags for local dev, env vars for containers, with a clear precedence).

---

## CORS: Wide Open

* **Decision**: `Access-Control-Allow-Origin: *` is set on all API responses.
* **Why (inferred)**: Simplifies development when the web portal or external tools make cross-origin requests. The assumption is that the server runs on a private network during engagements, not exposed to the public internet.
* **What would conflict with it**: Restricting CORS to specific origins would require knowing the portal's origin at startup. This is a known security concern flagged in CLAUDE.md.

---

## Inherited from the Original Project

This project does not appear to be a fork of a public C2 framework (no fork metadata in git, no attribution headers, no recognizable framework structure from Sliver, Covenant, Mythic, or similar). The following patterns *may* reflect influence from established C2 frameworks, but their origin is **unclear**:

* **Beacon/session model with jittered sleep**: Common across most C2 frameworks (Cobalt Strike, Sliver, Mythic). Whether this was directly inspired by one is unclear.
* **Length-prefixed framing for implant comms**: A standard pattern in custom C2 protocols. Not specific to any one framework.
* **Engagement-scoped operations with kill switches**: More structured than most open-source C2 frameworks. This appears to be an original design decision, possibly influenced by commercial red-team tooling requirements rather than a specific open-source project.
* **OT/ICS assessment module**: Unusual for a C2 framework. No widely-known C2 framework includes a dedicated OT assessment module with 17 industrial protocol clients. This appears to be original.
* **Append-only hash-chained audit log**: Not standard in open-source C2 frameworks. This appears to be driven by compliance/legal requirements for authorized engagements.

---

## MCP Server: HTTP API Wrapper for Claude Code Integration

* **Decision**: The MCP server (`cmd/mcp/`) is a standalone Go module that wraps the existing HTTP REST API as MCP tools. It communicates with the C2 server over HTTP using bearer token authentication. It does NOT import any internal packages — it is a pure API client.
* **Why**: Enables Claude Code (AI operator console) to interact with the C2 directly. Using the HTTP API as the integration layer means the MCP server gets all API features for free and does not add coupling to server internals. The stdio transport is the standard for Claude Code MCP servers.
* **What would conflict with it**: Breaking changes to the HTTP API without updating the MCP server's endpoint calls. Switching the operator API from REST to gRPC would require rewriting the MCP server's HTTP client layer. Adding MCP tools that need functionality not exposed by the HTTP API would require adding new API endpoints first (which benefits all clients, not just MCP).

---

## Operator HTTP Client: Shared `client/api` Package

* **Decision**: Operator-facing interfaces authenticate through a single small
  HTTP client in `client/api` (`New`, `Login`, `Get`, `Post`, `Delete`,
  `GetBytes`, plus a `StatusError` carrying the HTTP status and body). It uses
  only the standard library. `cmd/client` is the first consumer; `cmd/mcp`
  currently has its own equivalent `c2Client`.
* **Why**: The CLI previously issued unauthenticated requests — it never called
  `POST /api/auth/login` and never set an `Authorization` header — so every
  command returned 401 against the shipped server. Centralising token handling
  keeps the CLI, the portal and (eventually) the MCP server on one contract
  instead of three private copies, and makes the auth behaviour testable with
  `httptest` without a running server.
* **What would conflict with it**: Adding a framework or an external HTTP client
  would defeat the stdlib-only constraint. Diverging response shapes per
  interface would reintroduce the bug class this fixes — the CLI's task polling
  disagreed with the portal's about when a task is finished, and only the
  portal's version matched the server. `cmd/mcp` retaining its own client is a
  known duplication; migrating it is a follow-up, not a conflict.

---

## nmap Port Scanning: Runs on the Target, Not the Teamserver

* **Decision**: The `nmap` task type executes nmap **on the implant's host**, via
  a new `implant/modules/nmap` package called from the `handleTask` switch in
  `cmd/implant/main.go`. Availability is checked with `exec.LookPath("nmap")`
  followed by absolute-path probes (`/usr/bin`, `/usr/local/bin`,
  `/opt/homebrew/bin`). Arguments are tokenised into separate
  `exec.CommandContext` argv elements — never `/bin/sh -c`.
* **Why**: Scanning from the target reaches networks the implant can route to
  and the teamserver cannot, which is the point of having an implant there.
  Availability is checked because nmap is usually absent on a target, and the
  check follows absolute paths as well as `PATH` because an implant started from
  cron or systemd inherits a minimal `PATH` that can hide an installed binary.
  Passing argv separately rather than through a shell keeps operator-supplied
  targets and options from being interpreted as commands. A fixed timeout
  (`DefaultTimeout`, 3 minutes) bounds the run because `handleTask` executes
  inline in the implant's **serial** beacon loop: during a scan the implant
  sends no checkins at all, so the session looks stale and other queued tasks
  wait.
* **What would conflict with it**: Wiring an engagement scope into
  `cmd/implant` (TODO.md Priority 2) would add a pre-execution check this task
  type currently bypasses — a scan target is validated only for being non-empty,
  not for being in scope. Running the scan on the teamserver instead would
  require a new `POST /api/nmap/scan` endpoint and a server-side execution path
  that the REST API does not have today. Moving the scan off the beacon loop
  (background execution with a separate result channel) would change the
  serial-task model in `cmd/implant`. Raising `DefaultTimeout` past
  `nmapPollTimeout` in `cmd/client` and the portal's `taskPollAttempts` would
  make a running scan invisible to both interfaces before it finishes.

---

## Scanner: Structured nmap on the Target, With Opt-In Vulnerability Scripts

* **Decision**: A `scan` task type runs nmap **on the implant's host** and returns
  structured JSON rather than nmap's text. It offers three profiles — `quick`
  (`-T4 -F`), `services` (`-sV -T4`, the default) and `vulns`
  (`-sV -T4 -F --script vuln --host-timeout 4m`). nmap's XML is requested on
  stdout (`-oX -`) and decoded with `encoding/xml` into services and findings.
  The surfaces are a `scan <target> [--quick|--services|--vulns]` console command
  and a Scanner tab in the portal.
* **Why**: A raw `nmap` run returns an opaque string, so an operator cannot see a
  list of services or vulnerabilities and nothing can be rendered as a table.
  Scanning on the target keeps the reach that motivated the earlier `nmap`
  decision. Vulnerability scripts are opt-in and confirmed in the portal because
  NSE's `vuln` category actively probes the service it tests and can crash or
  wedge it — unacceptable as a default against production or OT hosts.
  `--host-timeout` is set deliberately: a scan that nmap ends itself produces a
  closed XML document, whereas a scan killed by the caller stops mid-write. The
  XML decoder is tolerant for the same reason, keeping whatever arrived before a
  truncation instead of discarding a six-minute scan's results, and it verifies
  the closing `</nmaprun>` so a half-document is flagged rather than presented as
  a clean scan.
* **No severity is reported.** nmap's XML carries none, and nmap has never
  emitted one — the colour a human sees on a terminal comes from the script's own
  output text. Findings therefore record what the output asserted (`vulnerable`)
  and the CVE identifiers it named, rather than a ranking inferred from the
  script's name.
* **What would conflict with it**: A long scan blocks the implant's serial beacon
  loop for its duration, so the session looks stale while `vulns` runs; fixing
  that means background task execution with a separate result channel, which
  would change the task model in `cmd/implant`. Wiring an engagement scope into
  `cmd/implant` (TODO.md Priority 2) would add a pre-execution check this task
  type currently bypasses. Raising a profile's timeout past the console's
  `scanPollTimeout` or the portal's `taskPollAttempts` would make a running scan
  invisible before it finishes. Persisting results (a planned follow-up) needs a
  result hook in `server/c2`, which today holds live state only in memory.
