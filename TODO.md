# Private-C2 Roadmap & Improvement Plan (TODO.md)

This roadmap outlines targeted improvements, additions, and architectural fixes for **Private-C2**, directly synthesized from the comparative analysis against Bishop Fox's Sliver in [`docs/origin.md`](file:///home/Fedora/Desktop/Private-C2/docs/origin.md) and current repository audits.

---

## Priority 1: Legal, Licensing & Attribution (Critical Governance)

- [ ] **Establish Project License**
  - Select and commit an explicit `LICENSE` file in the repository root.
  - Evaluate GPLv3 compliance requirements (as documented in `docs/origin.md` Section 0): if Private-C2 is distributed or deemed a derivative work of Bishop Fox Sliver, license under GNU General Public License v3.0 (GPLv3).
- [ ] **Document Attribution & Architectural Provenance**
  - Add a `NOTICE` file or section in `README.md` acknowledging Bishop Fox Sliver as the reference architecture for Private-C2's multi-transport layout and directory conventions.

---

## Priority 2: Core Wiring & Safety Interlocks (Activating Unique Strengths)

Approximately 40% of the codebase consists of original security and industrial assessment capabilities that are currently implemented in libraries but disconnected from the live execution loop.

- [ ] **Wire 17 OT/ICS Protocol Clients into Implant Tasking**
  - *Location*: [`cmd/implant/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/implant/main.go) and [`implant/modules/ot/`](file:///home/Fedora/Desktop/Private-C2/implant/modules/ot/)
  - *Description*: Add task dispatchers for OT assessment modules (`ot_discover`, `ot_modbus_read`, `ot_s7_read`, `ot_opcua_read`, `ot_dnp3_read`, etc.) so operators can execute read-only queries against industrial control systems through active implant sessions.
  - *Reference*: 32 protocol implementation files in `implant/modules/ot/protocols/`.
- [ ] **Enforce Safety & Scope Checks at Task Execution Time**
  - *Location*: [`implant/safety/safety.go`](file:///home/Fedora/Desktop/Private-C2/implant/safety/safety.go), [`implant/safety/allowlist.go`](file:///home/Fedora/Desktop/Private-C2/implant/safety/allowlist.go), and [`cmd/implant/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/implant/main.go)
  - *Description*: Call `SafetyChecker.RunAllChecks()` prior to executing any incoming task (shell commands, file reads, uploads). Ensure fail-closed kill switch, expiration dates, operational time windows, and CIDR/domain scope boundaries halt execution before commands run.
- [ ] **Adopt Cryptographic Envelope Pipeline on the Wire**
  - *Location*: [`pkg/envelope/envelope.go`](file:///home/Fedora/Desktop/Private-C2/pkg/envelope/envelope.go) and [`server/c2/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/handler.go)
  - *Description*: Wrap the raw JSON wire communications with `pkg/envelope.Seal` (Ed25519 signing + zlib compression + XChaCha20-Poly1305 encryption) and `pkg/envelope.Open` to provide true application-layer end-to-end security and replay protection.
- [ ] **Automate Hash-Chained Audit Logging on Server Operations**
  - *Location*: [`pkg/audit/logger.go`](file:///home/Fedora/Desktop/Private-C2/pkg/audit/logger.go) and [`server/c2/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/handler.go)
  - *Description*: Automatically append an audit record to the append-only SHA-256 hash chain whenever a session registers, checks in, executes a task, or returns results.

---

## Priority 3: Server Core State Management & Persistence

- [ ] **Persist Sessions and Task History to Database**
  - *Location*: [`server/c2/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/handler.go) and [`server/store/models/models.go`](file:///home/Fedora/Desktop/Private-C2/server/store/models/models.go)
  - *Description*: Sync live sessions (`ImplantSession`), task queues, and task results to GORM database models (`models.Session`, `models.Task`, `models.Beacon`) so that active contexts and operational history survive teamserver restarts.
- [ ] **Integrate `server/core/sessions.go` State Machine**
  - *Location*: [`server/core/sessions.go`](file:///home/Fedora/Desktop/Private-C2/server/core/sessions.go) and [`server/c2/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/handler.go)
  - *Description*: Replace ad-hoc mutex maps with `SessionManager`, activating the 6-state machine (`connecting → registering → active → stale → lost → disconnected`) and background health checks.
- [ ] **Emit Live Events on EventBus**
  - *Location*: [`server/core/events.go`](file:///home/Fedora/Desktop/Private-C2/server/core/events.go)
  - *Description*: Publish structured events (`SessionConnected`, `SessionDisconnected`, `TaskQueued`, `TaskCompleted`) to `EventBus` so API consumers, CLI clients, and the web portal receive real-time notifications.

---

## Priority 4: Operational Parity & Multi-Transport Listeners

- [ ] **Activate Multi-Transport Server Listeners**
  - *Location*: [`server/c2/listener/`](file:///home/Fedora/Desktop/Private-C2/server/c2/listener/) (`dns.go`, `https.go`, `mtls.go`, `wireguard.go`)
  - *Description*: Connect the listener implementations to the HTTP API and CLI so operators can dynamically start, stop, and configure DNS tunneling, HTTPS with domain fronting, and mTLS endpoints.
- [ ] **Connect Payload Builder Pipeline**
  - *Location*: [`cmd/builder/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/builder/main.go) and [`server/build/`](file:///home/Fedora/Desktop/Private-C2/server/build/)
  - *Description*: Replace the stub in `cmd/builder/main.go` and the raw `go build` call in `server/api/httpapi/payloads.go` with the modular pipeline (`stages/configure.go`, `compile.go`, `obfuscate.go`, `postprocess.go`, `stager.go`) with automated key injection and artifact generation.
- [ ] **Implement Interactive Streaming & Pivoting**
  - *Location*: [`implant/transport/pivot/pivot.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/pivot/pivot.go)
  - *Description*: Transition from polling-only task execution to bidirectional PTY/interactive shell streaming, and activate TCP/named-pipe P2P pivot relays across compromised boundaries.
- [ ] **Wire Evasion & Direct Syscalls into Implant Execution**
  - *Location*: [`implant/evasion/syscalls/`](file:///home/Fedora/Desktop/Private-C2/implant/evasion/syscalls/) and [`implant/evasion/stealth/`](file:///home/Fedora/Desktop/Private-C2/implant/evasion/stealth/)
  - *Description*: Incorporate PEB-walking indirect syscalls for process operations and trigger `TraceCleanup` (history clearing, timestomping) according to selected operational stealth profiles.

---

## Priority 5: Security Hardening & Hygiene

- [ ] **Eliminate Silent Insecure TLS Fallback**
  - *Location*: [`cmd/implant/main.go:74`](file:///home/Fedora/Desktop/Private-C2/cmd/implant/main.go#L74)
  - *Description*: Address Known Issue #5. Remove silent degradation to `InsecureSkipVerify: true` when `--ca` is missing. Require an explicit `--insecure` flag with loud console warnings if certificate validation is bypassed.
- [ ] **Harden Default Credentials & Authentication**
  - *Location*: [`server/api/httpapi/auth.go`](file:///home/Fedora/Desktop/Private-C2/server/api/httpapi/auth.go)
  - *Description*: Replace hardcoded `admin:admin` with an interactive initial password generation prompt on first teamserver launch, implement token revocation on logout, and add rate limiting to `/api/auth/login`.
- [ ] **Restrict CORS Configuration**
  - *Location*: [`server/api/httpapi/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/api/httpapi/handler.go)
  - *Description*: Replace `Access-Control-Allow-Origin: *` with an allowlist matching the configured web portal domain/IP.
- [ ] **Implement OT Safety-Critical Detection**
  - *Location*: [`implant/modules/ot/ot.go`](file:///home/Fedora/Desktop/Private-C2/implant/modules/ot/ot.go)
  - *Description*: Replace the `isSafetyCritical` stub (currently returns `false`) with actual register/tag boundary checks to prevent probing safety-instrumented systems (SIS) or shutdown circuits.
