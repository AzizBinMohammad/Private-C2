# CLAUDE.md

## Project Purpose

Private-C2 is a Command and Control (C2) framework built in Go for **authorized penetration testing and red team engagements only**. It provides multi-transport implant management, engagement-scoped operations with fail-closed safety interlocks, append-only audit logging with SHA-256 hash chaining, and a dedicated read-only OT/ICS assessment interface with 17 industrial protocol clients. The framework enforces scope boundaries (CIDR, hostname, domain) and kill switches at both the server and implant level.

## Tech Stack

| Component | Version / Detail |
|---|---|
| Go | 1.23 (go.work workspace with 9 modules) |
| GORM | 1.25.12 (ORM for database access) |
| SQLite driver | gorm.io/driver/sqlite 1.5.6 |
| PostgreSQL driver | gorm.io/driver/postgres 1.5.9 (pgx v5.5.5) |
| gRPC | google.golang.org/grpc 1.67.1 |
| Protobuf | google.golang.org/protobuf 1.34.2 |
| Prometheus | github.com/prometheus/client_golang 1.20.4 |
| UUID | github.com/google/uuid 1.6.0 |
| Crypto | golang.org/x/crypto 0.28.0 (XChaCha20-Poly1305 via chacha20poly1305, bcrypt for auth) |
| Docker base | golang:1.23-alpine (builder), alpine:3.19 (runtime) |
| MCP SDK | github.com/mark3labs/mcp-go v1.2.1 |
| Proto definitions | proto/v1/*.proto (7 files, code generation not wired up yet) |

## Folder Structure

```
Private-C2/
  go.work                  # Go workspace linking 9 modules
  Makefile                 # Build, test, lint, docker, cross-compile targets
  Dockerfile               # Multi-stage Docker build for the server
  docker-compose.yml       # Server + PostgreSQL stack

  cmd/
    server/main.go         # Server entry point: TLS listener, HTTP API, metrics
    client/main.go         # Operator CLI: interactive console over HTTP API
    builder/main.go        # Payload builder CLI (stub, prints usage only)
    implant/main.go        # Implant entry point: beacon loop, task execution
    mcp/main.go            # MCP server: wraps HTTP API for Claude Code

  server/
    api/
      httpapi/
        handler.go         # REST API router: sessions, tasks, beacons, listeners,
                           #   engagements, payloads (with real compilation),
                           #   operators, audit, OT endpoints, server status
        auth.go            # Bearer-token auth: bcrypt password hashing, token
                           #   issuance (12h TTL), middleware
        webui/index.html   # Embedded single-page web portal (1732 lines)
      grpc/                # gRPC service stubs (engagement, operator, OT)
      middleware/          # Middleware stubs (audit, auth, OT auth, rate limit, RBAC)
    build/
      config.go            # Build pipeline configuration model
      queue/               # Build job queue and worker
      stages/              # Build stages: configure, compile, obfuscate, postprocess, stager
    c2/
      handler.go           # Core implant server: connection handling, session tracking,
                           #   task queuing/dispatch, result collection (in-memory)
      listener/            # Listener implementations: DNS, HTTPS, mTLS, WireGuard
      profile/             # C2 communication profiles
    config/config.go       # Server configuration via env vars (PC2_* prefix)
    core/
      events.go            # In-process event bus (pub/sub by event type)
      sessions.go          # Session state machine (connecting->active->stale->lost->disconnected)
      security.go          # Security policy enforcement
    store/
      db.go                # Database init (SQLite or PostgreSQL via GORM)
      models/
        models.go          # Core ORM models: Operator, Session, Beacon, Listener,
                           #   PayloadArtifact, Engagement, AuditEntry, C2Profile, Role
        ot.go              # OT/ICS models: OTAssetRecord, OTCredentialFinding,
                           #   OTVulnFinding, OTSegmentationGap, OTComplianceFinding,
                           #   OTTopologyEdge, OTCaptureSession, OTAssessmentReport,
                           #   OTHMIFinding, OTWirelessFinding
      repository/          # Repository-pattern data access (one file per entity)
    telemetry/
      health.go            # /healthz endpoint
      metrics.go           # Prometheus metrics registration

  client/
    api/                   # Authenticated HTTP client for the operator REST API
                           #   (Login/Get/Post/Delete + StatusError). Used by
                           #   cmd/client; stdlib only.
    cli/commands/          # CLI command definitions: admin, audit, beacons,
                           #   engagement, listeners, ot, payloads, sessions, tasks
                           #   NOTE: dead code -- every handler is a stub and
                           #   nothing imports this package. See
                           #   docs/audit-2026-10-15.md roadmap item 18.
    console/               # Interactive console: REPL loop, context, events, output
                           #   NOTE: dead code, reachable only from cli/commands.
    transport/             # Client-side gRPC transport with TLS
                           #   NOTE: dead code stub; the operator API is REST.

  implant/
    runtime/               # Implant runtime: config, registration, main loop,
                           #   system info collection (platform-specific: darwin,
                           #   linux, windows, default)
    modules/
      filesystem/          # File operations module
      logs/                # Log collection (platform-specific + timestomping)
      network/             # Network recon module
      nmap/                # nmap on the target. nmap.go: availability check
                           #   (LookPath + absolute-path fallback), argv-separated
                           #   execution, bounded timeout. xml.go + scan.go:
                           #   structured scans (quick/services/vulns) that parse
                           #   nmap's XML into services and findings
      ot/                  # OT/ICS assessment: 17 protocol clients (Modbus, OPC UA,
                           #   S7comm, DNP3, BACnet, IEC 104, IEC 61850, EtherNet/IP,
                           #   PROFINET, FINS, HART, MELSEC, Crimson, PC WORX,
                           #   MQTT, CoAP), discovery, fingerprinting, credential
                           #   testing, vulnerability scanning, compliance analysis,
                           #   topology mapping, traffic capture, HMI scanning,
                           #   wireless detection, PLC logic analysis, serial comms
      process/             # Process listing (platform-specific)
      screenshot/          # Screenshot capture
      shell/               # Shell command execution (Unix/Windows)
    safety/
      safety.go            # Pre-execution safety checker: kill switch, kill date,
                           #   time window, scope, data quota, fail-closed design
      allowlist.go         # Task type allowlist
    task/
      executor.go          # Task execution engine
      registry.go          # Task type registry
    transport/
      transport.go         # Transport interface definition
      manager.go           # Transport manager (failover/selection)
      mtls/                # mTLS transport
      https/               # HTTPS transport (domain fronting support)
      dns/                 # DNS tunneling transport + encoding
      wireguard/           # WireGuard transport
      pivot/               # Peer-to-peer pivot transport
    evasion/
      stealth/             # Anti-forensics: trace cleanup
      syscalls/            # Direct syscall invocation (Windows-specific)

  pkg/                     # Shared library modules
    crypto/
      aead.go              # XChaCha20-Poly1305 encryption with replay detection
      keyexchange.go       # X25519 key exchange
      pki.go               # ECDSA P-384 PKI helpers
      signing.go           # Ed25519 signing/verification
      wipe.go              # Secure memory wiping
    envelope/
      envelope.go          # Seal/Open: sign + encrypt + compress pipeline
      framing.go           # Length-prefixed wire framing (4-byte LE header)
      compression.go       # Payload compression
    engagement/
      scope.go             # Scope enforcement: CIDR, hostname, domain matching
      safeguards.go        # Kill switch, data quotas, remote kill switch
    audit/
      logger.go            # Append-only audit logger with SHA-256 hash chaining
      export.go            # Audit export (JSON, CEF, LEEF formats)
    platform/
      matrix.go            # OS/arch support matrix
      validation.go        # Platform validation helpers

  proto/v1/                # Protobuf definitions (7 .proto files)
  tests/integration/       # Integration test stubs (all t.Skip, 7 test files)
  phases/                  # Development roadmap (8 phase documents)
  scripts/
    run.sh                 # `make run`: full local stack + attached console
    setup-ca.sh            # Generate CA + server TLS certificates (OpenSSL)
    add-operator.sh        # Generate operator client certificate
    quickstart.sh          # Quick setup script
    install-fedora.sh      # Fedora dependency installation
```

## Data Flow

### Implant -> Server -> Operator

1. **Implant starts** (`cmd/implant/main.go`): connects via TLS to the server, sends a `register` message with system info (hostname, OS, arch, PID, username).

2. **Server accepts** (`server/c2/handler.go`): `ImplantServer.HandleConnection` reads the registration frame via length-prefixed framing (`pkg/envelope/framing.go`), creates an `ImplantSession` in memory, sends `register_ack` with a UUID session ID.

3. **Beacon loop**: the implant sleeps for `interval +/- jitter`, then sends a `checkin` message. The server responds with a `tasking` message containing any queued tasks.

4. **Task execution**: the implant executes tasks (shell, ls, pwd, cd, ps, cat, upload, download, screenshot, nmap, scan), sends `result` messages back. The server stores results in memory (`taskResults` map) and responds with `result_ack`.

5. **Operator CLI** (`cmd/client/main.go`): connects to the HTTP API (`server/api/httpapi/handler.go`), lists sessions via `GET /api/sessions`, submits tasks via `POST /api/sessions/{id}/task`, polls results via `GET /api/tasks/{id}`.

6. **Web portal** (`server/api/httpapi/webui/index.html`): embedded SPA served at `/`, authenticates via `POST /api/auth/login` (receives Bearer token), provides dashboard with session management, task submission, listener control, engagement management, payload generation with download, audit log viewer, a scanner (set a target, read back services and findings), and the OT assessment interface.

### Database

- **ORM**: GORM with auto-migration on startup (`store.Migrate`)
- **Dialects**: SQLite (default, file-based) or PostgreSQL (via `PC2_DB_DIALECT` env var)
- **Models**: 19 tables total (9 core + 10 OT/ICS)
- **In-memory state**: live sessions, task queues, and task results are kept in `ImplantServer` maps (not persisted to DB during the TLS connection lifecycle)

### Wire Protocol

- Length-prefixed framing: 4-byte little-endian uint32 length prefix + payload
- JSON-encoded `Message{Type, Data}` envelope
- Message types: `register`, `register_ack`, `checkin`, `tasking`, `result`, `result_ack`
- Higher-level envelope (`pkg/envelope`): Ed25519 signature + XChaCha20-Poly1305 encryption + zlib compression (available but not used in the current `cmd/implant` wire path)

## Conventions

### Naming
- Go standard: `PascalCase` exported, `camelCase` unexported
- Package names are short lowercase nouns (`store`, `core`, `safety`, `envelope`)
- Environment variables prefixed with `PC2_` (e.g., `PC2_DB_DIALECT`, `PC2_GRPC_ADDR`)
- GORM model IDs are UUID strings, auto-generated in `BeforeCreate` hook
- JSON tags use `snake_case`

### Error Handling
- Errors wrapped with `fmt.Errorf("context: %w", err)` for context
- HTTP API returns `ErrorResponse{Error string}` JSON on failure
- Safety checks return `CheckResult{Passed, Reason, Fatal}` struct (fatal = implant should terminate)
- Kill switch is fail-closed: unreachable remote kill endpoint causes shutdown

### State Management
- Session state machine in `server/core/sessions.go` with defined transitions: connecting -> registering -> active -> stale -> lost -> disconnected
- In-process event bus (`server/core/events.go`) for session lifecycle events
- Live implant state (sessions, task queues, results) stored in `sync.RWMutex`-protected maps in `ImplantServer`
- Auth tokens stored in-memory with 12-hour TTL, not persisted across restarts

### API Style
- REST over HTTP with `net/http` standard library (no framework)
- All routes registered with `http.NewServeMux` and `HandleFunc`
- CORS headers set on all API responses
- Bearer token authentication via middleware for protected routes
- Public routes: `POST /api/auth/login`, static web UI at `/`
- MCP server (`cmd/mcp/`) exposes the same API as MCP tools over stdio for Claude Code integration

### Security Patterns
- TLS 1.2+ minimum (server), TLS 1.3 minimum (implant)
- Self-signed certificate generation as fallback when no cert/key provided
- bcrypt for password hashing
- Constant-time token comparison
- XChaCha20-Poly1305 with replay detection (SHA-256 digest dedup)
- Engagement scope enforced before every operation

## How to Run, Build, and Test

### Run Everything Locally (One Command)
```bash
make run                      # or: bash scripts/run.sh
```
Builds all four binaries, reuses or generates `certs/`, starts the server and one
implant, waits for it to register, then hands you the interactive operator
console already attached to that session. `exit`, Ctrl-D or Ctrl-C shuts the
whole stack down again. Requires ports 4444 and 8080 free.

### Build
```bash
make build                    # Build server, client, builder binaries to bin/
make server                   # Build server only
make client                   # Build client only
make cross-compile            # Cross-compile implant for linux/amd64, windows/amd64, darwin/arm64
make docker                   # Build Docker image
```

### Setup Certificates
```bash
./scripts/setup-ca.sh         # Generate CA + server certs in ./certs/
./scripts/add-operator.sh op1 # Generate operator client cert
```

### Run Server
```bash
# Locally with SQLite (defaults)
go run ./cmd/server/...

# With flags
go run ./cmd/server/... --listen :4444 --api 127.0.0.1:8080 --db pc2.db

# With Docker Compose (PostgreSQL)
docker-compose up -d          # broken -- see known-issues #7; use `make run`
```

### Run Operator CLI
```bash
go run ./cmd/client/... --server http://127.0.0.1:8080

# Attach to a specific session on startup (what scripts/run.sh does)
go run ./cmd/client/... --server http://127.0.0.1:8080 --session <id-prefix>

# Console commands for scanning (both need an active session):
#   nmap [target] [opts]              raw nmap; no args reports the version
#   scan <target> [--quick|--services|--vulns]   structured, rendered as tables
```

### Run Implant
```bash
go run ./cmd/implant/... --server 127.0.0.1:4444 --interval 5s --jitter 0.3
```

### Test
```bash
make test                     # Unit tests (pkg, server, client) with -race
make test-integration         # Integration tests (requires full stack, all currently t.Skip)
make lint                     # go vet + golangci-lint if available
```

### Web Portal
Navigate to `http://127.0.0.1:8080/` after starting the server. Default credentials: `admin` / `admin`.

## Known Problem Areas

### Large Files
- ~~`server/api/httpapi/handler.go` (1084 lines)~~ **RESOLVED**: reduced to route registration; endpoints now live in `sessions.go`, `beacons.go`, `listeners.go`, `engagements.go`, `payloads.go`, `operators.go`, `audit.go`, `ot.go`, `status.go`.
- `server/api/httpapi/webui/index.html` (~1790 lines): entire web portal in a single embedded HTML file with inline CSS and JavaScript.
- `cmd/client/main.go` (~650 lines): all CLI logic and rendering in one file. The HTTP/auth layer has been extracted to `client/api`.
- `cmd/implant/main.go` (362 lines): full implant logic (TLS, registration, beacon loop, task handlers) in one file, bypassing the structured `implant/` packages.

### Duplicated Logic
- ~~Wire protocol types defined independently in three places~~ **RESOLVED**: they now live in `pkg/protocol/types.go`.
- ~~`buildTLSConfig` implemented separately~~ **RESOLVED**: shared via `pkg/tlsutil`.
- Session models exist both as GORM models (`server/store/models`) and as in-memory structs (`server/c2/handler.go`), with no mapping between them.
- `cmd/mcp/main.go` has its own authenticated HTTP client (`c2Client`) duplicating `client/api`. Migrating it is a follow-up.

### Architectural Gaps
- **`cmd/implant` bypasses `implant/` packages**: the working implant in `cmd/implant/main.go` does not use the structured runtime, safety, transport, or module packages under `implant/`. Those packages exist as well-designed code but are not wired into any entry point.
- **gRPC server not wired**: `cmd/server/main.go` runs a raw TLS socket listener and HTTP API, not the gRPC server defined in `proto/v1/` and `server/api/grpc/`.
- **Proto codegen not wired**: `make proto` prints a TODO message. No generated `.pb.go` files exist.
- **Config module not used**: `server/config/config.go` (`config.Load()`) reads `PC2_*` env vars but `cmd/server/main.go` uses `flag` package and hardcoded defaults instead.
- **Session manager not integrated**: `server/core/sessions.go` (state machine with health checking) is not used by `server/c2/handler.go` which tracks sessions in its own maps.
- **Integration tests are all stubs**: every test in `tests/integration/` calls `t.Skip("requires full server/implant stack")`.
- **No unit tests** for `server/`, `client/`, or `implant/` packages. Only `pkg/` has unit tests.
- ~~**In-memory task results**~~ **PARTIALLY RESOLVED (2026-10-19)**: sessions,
  tasks, dispatches, and results now persist through `c2.Persistence` /
  `c2.GORMPersistence`, and queued tasks are rebound by `ImplantID`. See
  `docs/phase1-status-2026-10-19.md`.
- **Builder CLI is still a stub**: `cmd/builder/main.go` only prints usage.
  The server-side builder (`server/build.Build`) now produces self-contained
  payloads with embedded configuration.
- **mTLS and HTTPS carriers are live.** HTTPS uses a streaming POST and the
  same framed protocol. DNS/WireGuard remain unwired; `server/c2/listener/*`
  uses a different session model.
- **Audit writer is live**: `server/store/auditwriter` persists the canonical
  hash chain, and `/api/audit/export` supports JSON/CEF/LEEF.
- **RBAC is now enforced on the REST API** via `server/api/authz` (roles:
  `admin`, `operator`, `builder`, `observer`, `ot-operator`). Engagement policy
  (scope, time window, authorized techniques, kill switch) is enforced before
  task queueing; the implant re-checks its own safety configuration.
- **Protocol v2 is negotiated**: v1 JSON remains supported; v2 adds session
  tokens, server-controlled heartbeat, kill tasking, and per-task timeouts.

### Security Concerns
- Default `admin`/`admin` credentials are hardcoded in `auth.go:ensureDefaultUser()`.
- `Access-Control-Allow-Origin: *` on all API responses (wide-open CORS).
- Auth tokens stored in memory only; no session invalidation on logout; expired tokens are never pruned.
- OT safety-critical check (`isSafetyCritical`) is a stub returning `false`.
- ~~mTLS is never enforced~~ **RESOLVED**: the listener now requires and verifies a client certificate when `--ca` is supplied, and the implant refuses to start without a CA unless `--insecure` is passed explicitly. See known-issues R9.
- **No authorization layer on the REST API** — authentication only. Any authenticated operator can create admin operators, delete operators, and read the audit log. See known-issues #4.
- Deleting an operator does not revoke credentials (DB row only; bcrypt hash stays in the auth manager).

### Known Issue Tracking
- `docs/known-issues.md` is the authoritative defect list.
- `docs/audit-2026-10-15.md` is the full audit: per-phase verification, CLI↔UI feature matrix, and prioritized roadmap.
- `docs/phase1-status-2026-10-19.md` records the first Phase 1 implementation
  cut, what was verified, and what remains (HTTPS carrier, embedded payload
  builder, audit writer/export, SSE, config wiring, migration ledger).
- `docs/prompt-template.md` is the template for requesting new features, and lists the project facts worth stating up front (notably: which packages are live vs. unreachable).

### Writing Requirements for New Work
State **where** a feature must run. Much of this codebase compiles but is never
executed, so "add OT support to `implant/modules/ot`" can produce working code
that no binary calls. See `docs/prompt-template.md`.

## Open Questions

- Is the intended primary API transport gRPC (as implied by proto definitions and `server/api/grpc/`) or HTTP REST (as currently wired)? Both exist but only REST is functional.
- Should `cmd/implant/main.go` be refactored to use the `implant/runtime`, `implant/safety`, and `implant/transport` packages, or are those library packages intended for a future version?
- The `server/build/` pipeline has structured stages but the web API's `buildImplant()` function calls `go build` directly. Which is the intended build path?
- `server/core/events.go` and `server/core/sessions.go` appear designed for the gRPC path. Are they intended to replace the in-memory tracking in `server/c2/handler.go`?
- The `tests/` module has its own `go.mod` but no working tests. What is the plan for integration test infrastructure?

## Rules for AI

1. **Plan before coding**: list the files you'll change and wait for my approval.
2. **Never touch files outside the task scope**.
3. **Reuse existing helpers/components before writing new ones** -- check `pkg/`, `server/core/`, and `implant/safety/` first.
4. **Do not add dependencies without asking**.
5. **Run tests after every change** (`make test`) and don't finish until they pass.
6. **Keep files small and single-purpose** -- the handler.go and main.go monoliths are cautionary examples.
7. **Update CLAUDE.md and docs/decisions.md when you change architecture**.
