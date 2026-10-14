# Origin Analysis: Private-C2 vs. Bishop Fox Sliver

> [!NOTE]
> This analysis was produced on 2026-10-13 by comparing the local Private-C2
> codebase (`github.com/AzizBinMohammad/Private-C2`) against the public
> Bishop Fox Sliver repository (`github.com/bishopfox/sliver`, master branch).
> Every claim cites file paths from both projects. Where a claim cannot be
> verified from source code alone, it is marked **"unverified"** or
> **"per docs"**.

---

## 0. Original Project License & Attribution Requirements

Sliver is licensed under **GNU General Public License v3.0 (GPLv3)**.

- **File:** [`LICENSE`](https://github.com/bishopfox/sliver/blob/master/LICENSE)
- **Copyright holder:** Bishop Fox

### GPLv3 key obligations (if code is derived and distributed)

| Obligation | Detail |
|---|---|
| Copyleft | Any derivative work distributed to third parties must also be released under GPLv3 |
| Source disclosure | Complete corresponding source code must be provided |
| Notice preservation | Original copyright notices and license text must be retained |
| Modification marking | Changes from the original must be documented |

### Current state of Private-C2

- **No `LICENSE` file** exists in the Private-C2 repository.
- **No copyright headers** referencing Bishop Fox or Sliver appear in any source file.
- **No attribution comments** exist anywhere in the codebase.
- The only mention of Sliver is in [`docs/decisions.md` L170-172](file:///home/Fedora/Desktop/Private-C2/docs/decisions.md#L170-L172), which states the project "does not appear to be a fork" and lists Sliver among frameworks whose patterns "may reflect influence."

> [!WARNING]
> If Private-C2 is determined to be a derivative work of Sliver under copyright
> law, the GPLv3 requires that Private-C2 be distributed under GPLv3 with full
> source code, preserved copyright notices, and documented modifications.
> This analysis documents the evidence; the legal determination is outside its scope.

---

## 1. What Is Similar to the Original

### 1.1 Directory Structure

The top-level layout mirrors Sliver's organization closely:

| Sliver Path | Private-C2 Path | Purpose |
|---|---|---|
| `server/c2/` | `server/c2/` | C2 connection handling |
| `server/core/events.go` | `server/core/events.go` | In-process event pub/sub |
| `server/core/sessions.go` | `server/core/sessions.go` | Session state tracking |
| `server/db/` (GORM+SQLite) | `server/store/` (GORM+SQLite/Postgres) | Database persistence |
| `server/configs/` | `server/config/` | Server configuration |
| `server/generate/` | `server/build/` | Payload generation pipeline |
| `server/handlers/` | `server/api/httpapi/` | Request handling |
| `client/console/` | `client/console/` | Interactive operator REPL |
| `client/command/` | `client/cli/commands/` | CLI command definitions |
| `client/transport/` | `client/transport/` | Client-side transport |
| `implant/sliver/transports/mtls/` | `implant/transport/mtls/` | mTLS transport |
| `implant/sliver/transports/httpclient/` | `implant/transport/https/` | HTTPS transport |
| `implant/sliver/transports/dnsclient/` | `implant/transport/dns/` | DNS tunneling |
| `implant/sliver/transports/wireguard/` | `implant/transport/wireguard/` | WireGuard transport |
| `implant/sliver/transports/pivots/` | `implant/transport/pivot/` | P2P pivot transport |
| `implant/sliver/evasion/` | `implant/evasion/` | Evasion techniques |
| `implant/sliver/syscalls/` | `implant/evasion/syscalls/` | Direct Windows syscalls |
| `protobuf/` | `proto/` | Protocol definitions |
| `util/` | `pkg/` | Shared libraries |

**Verdict:** The directory layout is clearly modeled after Sliver's architecture. Identical directory names (`server/c2/`, `server/core/`, `client/console/`, `client/transport/`) and the same decomposition of transports into `mtls/`, `https/`, `dns/`, `wireguard/`, `pivot/` subdirectories indicate structural derivation.

### 1.2 Feature Matrix Overlap

Both frameworks implement the same core feature set:

| Feature | Sliver | Private-C2 |
|---|---|---|
| mTLS transport with TLS 1.3 | ✓ (`implant/sliver/transports/mtls/`) | ✓ ([`implant/transport/mtls/mtls.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/mtls/mtls.go)) |
| HTTPS transport with domain fronting | ✓ (`implant/sliver/transports/http/`) | ✓ ([`implant/transport/https/https.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/https/https.go)) |
| DNS tunneling (Base32 subdomains, TXT/CNAME) | ✓ (`implant/sliver/transports/dnsclient/`) | ✓ ([`implant/transport/dns/dns.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/dns/dns.go)) |
| WireGuard transport | ✓ (`implant/sliver/transports/wireguard/`) | ✓ ([`implant/transport/wireguard/wireguard.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/wireguard/wireguard.go)) |
| TCP + named-pipe pivot | ✓ (`implant/sliver/transports/pivots/`) | ✓ ([`implant/transport/pivot/pivot.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/pivot/pivot.go)) |
| Event broker / pub-sub | ✓ (`server/core/events.go`) | ✓ ([`server/core/events.go`](file:///home/Fedora/Desktop/Private-C2/server/core/events.go)) |
| Session map behind RWMutex | ✓ (`server/core/sessions.go`) | ✓ ([`server/core/sessions.go`](file:///home/Fedora/Desktop/Private-C2/server/core/sessions.go)) |
| Beacon mode with jittered sleep | ✓ (`server/core/beacons.go`) | ✓ ([`cmd/implant/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/implant/main.go)) |
| GORM database with SQLite | ✓ (`server/db/`) | ✓ ([`server/store/db.go`](file:///home/Fedora/Desktop/Private-C2/server/store/db.go)) |
| Server-side payload compilation | ✓ (`server/generate/`, `server/gogo/`) | ✓ ([`server/build/`](file:///home/Fedora/Desktop/Private-C2/server/build/)) |
| 4-byte LE length-prefixed framing | ✓ (mTLS handler) | ✓ ([`pkg/envelope/framing.go`](file:///home/Fedora/Desktop/Private-C2/pkg/envelope/framing.go)) |
| Direct Windows syscalls (PEB walking) | ✓ (`implant/sliver/syscalls/`) | ✓ ([`implant/evasion/syscalls/syscalls_windows.go`](file:///home/Fedora/Desktop/Private-C2/implant/evasion/syscalls/syscalls_windows.go)) |
| Cross-compilation for linux/windows/darwin | ✓ (`Makefile`) | ✓ ([`Makefile`](file:///home/Fedora/Desktop/Private-C2/Makefile)) |

### 1.3 Event System Pattern

Both implement an in-process event pub/sub with similar naming:

| Aspect | Sliver (`server/core/events.go`) | Private-C2 ([`server/core/events.go`](file:///home/Fedora/Desktop/Private-C2/server/core/events.go)) |
|---|---|---|
| Event type naming | `SessionConnectedEvent`, `SessionDisconnectedEvent`, `JobStartedEvent`, `JobStoppedEvent` | `SessionConnected`, `SessionDisconnected`, `ListenerStarted`, `ListenerStopped` |
| Event struct | `Event{EventType string, Session, Job, Client, Beacon, Data, Err}` | `Event{Type EventType, Data interface{}, Timestamp time.Time}` |
| Broker pattern | Channel-based broker with central goroutine (`EventBroker`) | Mutex-guarded map of typed channels (`EventBus`) |

**Verdict:** Same concept, same constant naming convention (session connected/disconnected, listener/job started/stopped), but different implementation mechanisms. The pattern is **structurally inspired** but the code is independently written.

### 1.4 Session Management Pattern

| Aspect | Sliver (`server/core/sessions.go`) | Private-C2 ([`server/core/sessions.go`](file:///home/Fedora/Desktop/Private-C2/server/core/sessions.go)) |
|---|---|---|
| Storage | `map[uint32]*Session` + `sync.RWMutex` | `map[string]*ManagedSession` + `sync.RWMutex` |
| API methods | `Add()`, `Get()`, `Remove()`, `All()` | `AddSession()`, `RemoveSession()`, `GetSession()`, `ListSessions()` |
| Session ID | `uint32` | UUID `string` |
| Singleton vs instance | Package-level `Sessions` variable | Instantiated `SessionManager` struct |

**Verdict:** Same map+mutex pattern and similar CRUD methods — standard Go patterns for concurrent state. Private-C2 extends this significantly with a formal state machine (`connecting → registering → active → stale → lost → disconnected`), health checking, and per-session locking. **Pattern-inspired with substantial additions.**

### 1.5 Cryptographic Primitives Overlap

| Primitive | Sliver | Private-C2 |
|---|---|---|
| Key exchange | X25519 (via NaCl Box / Curve25519) | X25519 ([`pkg/crypto/keyexchange.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/keyexchange.go)) |
| Signing | Ed25519 (in some paths) | Ed25519 ([`pkg/crypto/signing.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/signing.go)) |
| AEAD | ChaCha20-Poly1305 | **X**ChaCha20-Poly1305 ([`pkg/crypto/aead.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/aead.go)) |
| PKI curves | RSA/ECDSA (various) | ECDSA P-384 ([`pkg/crypto/pki.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/pki.go)) |

**Verdict:** Both use modern DJB-family cryptographic primitives (X25519, Ed25519, ChaCha20-Poly1305) — these are standard choices for security tooling. Private-C2 uses XChaCha20 (extended nonce variant) rather than Sliver's standard ChaCha20, and adds replay detection via SHA-256 digest caching. The crypto code appears independently implemented. **Same algorithm family, different implementations.**

### 1.6 Wire Framing

Both use 4-byte little-endian length-prefixed framing for TCP connections:

- **Sliver:** In mTLS handler, reads 4-byte header then payload
- **Private-C2:** [`pkg/envelope/framing.go`](file:///home/Fedora/Desktop/Private-C2/pkg/envelope/framing.go) — `WriteFrame()` / `ReadFrame()` with `binary.LittleEndian`

**Verdict:** Length-prefixed framing is ubiquitous in network programming. This is a standard technique, not specific to Sliver.

---

## 2. What Was Added or Changed, and Why

### 2.1 Entirely New: OT/ICS Assessment Module

- **Files:** 32 files under [`implant/modules/ot/`](file:///home/Fedora/Desktop/Private-C2/implant/modules/ot/) + [`server/store/models/ot.go`](file:///home/Fedora/Desktop/Private-C2/server/store/models/ot.go) (10 OT database models) + OT API endpoints in `server/api/httpapi/`
- **Added in:** Commit `f7ed3db` ("Add OT/ICS assessment capabilities with 17 industrial protocol clients", 2025-06-14)
- **Content:** 17 industrial protocol clients (Modbus, OPC UA, S7comm, DNP3, BACnet, IEC 104, IEC 61850, EtherNet/IP, PROFINET, FINS, HART, MELSEC, Crimson, PC WORX, MQTT, CoAP), plus discovery, fingerprinting, credential testing, vulnerability scanning, compliance analysis, topology mapping, traffic capture, HMI scanning, wireless detection, PLC logic analysis, and serial communications.
- **Why (per docs):** README describes the framework as designed for "authorized penetration testing and red team engagements" with a "dedicated read-only OT/ICS assessment interface." Safety interlocks enforce read-only operation (write function codes explicitly excluded from protocol clients).
- **Sliver comparison:** Sliver has **no OT/ICS modules whatsoever**. This is entirely original to Private-C2.

### 2.2 Entirely New: Engagement Scope Enforcement

- **Files:** [`pkg/engagement/scope.go`](file:///home/Fedora/Desktop/Private-C2/pkg/engagement/scope.go), [`pkg/engagement/safeguards.go`](file:///home/Fedora/Desktop/Private-C2/pkg/engagement/safeguards.go), [`implant/safety/safety.go`](file:///home/Fedora/Desktop/Private-C2/implant/safety/safety.go), [`implant/safety/allowlist.go`](file:///home/Fedora/Desktop/Private-C2/implant/safety/allowlist.go)
- **Added in:** Commits `00a42c5` and `07a4ab8` (2025-06-14)
- **Content:** CIDR/hostname/domain scope checking, fail-closed kill switches (local + remote), kill dates, operational time windows, data exfiltration quotas, task type allowlists.
- **Why (per docs):** README emphasizes "scope boundaries (CIDR, hostname, domain) and kill switches at both the server and implant level."
- **Sliver comparison:** Sliver has **no scope enforcement, kill switches, time windows, or data quotas**. Operators are trusted to self-regulate.

### 2.3 Entirely New: Hash-Chained Audit Logging

- **Files:** [`pkg/audit/logger.go`](file:///home/Fedora/Desktop/Private-C2/pkg/audit/logger.go), [`pkg/audit/export.go`](file:///home/Fedora/Desktop/Private-C2/pkg/audit/export.go)
- **Added in:** Commit `00a42c5` (2025-06-14)
- **Content:** Append-only audit logger with SHA-256 hash chaining (each entry includes hash of previous entry). Export to JSON, CEF (Common Event Format), and LEEF (IBM QRadar format).
- **Why (per docs):** Per `docs/decisions.md`: designed for "compliance/legal requirements for authorized engagements."
- **Sliver comparison:** Sliver writes flat unchained JSON lines to `~/.sliver/logs/audit.json`. No hash chaining, no CEF/LEEF export.

### 2.4 Entirely New: Embedded Web Portal

- **Files:** [`server/api/httpapi/webui/index.html`](file:///home/Fedora/Desktop/Private-C2/server/api/httpapi/webui/index.html) (1732 lines)
- **Added in:** Commit `2cb8d12` (2025-06-14)
- **Content:** Single-page web application with dashboard, session management, task submission, listener control, engagement management, payload generation, audit log viewer, and OT assessment interface.
- **Sliver comparison:** Sliver has no embedded web portal (there is a separate `sliver-gui` project).

### 2.5 Entirely New: MCP Server Integration

- **Files:** [`cmd/mcp/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/mcp/main.go)
- **Added in:** Commit `1291ec3` (2025-06-14)
- **Content:** Model Context Protocol server wrapping the HTTP API for AI assistant (Claude Code) integration.
- **Sliver comparison:** No equivalent in Sliver.

### 2.6 Changed: Operator API (HTTP REST instead of gRPC)

- **Sliver:** Operators connect via mTLS gRPC (`server/rpc/`, `protobuf/rpcpb/`)
- **Private-C2:** HTTP REST API with bearer token auth ([`server/api/httpapi/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/api/httpapi/handler.go), [`auth.go`](file:///home/Fedora/Desktop/Private-C2/server/api/httpapi/auth.go))
- **Why (per docs):** `docs/decisions.md` documents this as a deliberate choice: "HTTP REST over gRPC" for the operator-facing API, with gRPC stubs present but not wired.

### 2.7 Changed: Wire Protocol (JSON instead of Protobuf)

- **Sliver:** Protobuf `Envelope{Type, ID, Data}` encoded as binary protobuf
- **Private-C2:** JSON `Message{Type, Data}` encoded as JSON text ([`server/c2/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/handler.go), [`cmd/implant/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/implant/main.go))
- The higher-level `Seal`/`Open` envelope ([`pkg/envelope/envelope.go`](file:///home/Fedora/Desktop/Private-C2/pkg/envelope/envelope.go)) with sign+encrypt+compress is entirely different from Sliver's approach.

### 2.8 Changed: Multi-Module Workspace

- **Sliver:** Single `go.mod` monorepo
- **Private-C2:** `go.work` with 9 separate modules
- **Why (per docs):** `docs/decisions.md` documents "Go 1.23 multi-module workspace" as a design decision.

### 2.9 Changed: Database Dialect Support

- **Sliver:** SQLite only (`server/db/`)
- **Private-C2:** SQLite + PostgreSQL ([`server/store/db.go`](file:///home/Fedora/Desktop/Private-C2/server/store/db.go), [`docker-compose.yml`](file:///home/Fedora/Desktop/Private-C2/docker-compose.yml))

### 2.10 Changed: Cryptographic Envelope Pipeline

- **Sliver:** NaCl Box key exchange → ChaCha20-Poly1305 symmetric encryption, with traffic-masking encoders (Base64, Hex, PNG stego) rotated via nonce modulus
- **Private-C2:** X25519 key exchange → XChaCha20-Poly1305 AEAD with SHA-256 replay detection → Ed25519 signing → zlib compression → all wrapped in `Seal`/`Open` pipeline ([`pkg/envelope/envelope.go`](file:///home/Fedora/Desktop/Private-C2/pkg/envelope/envelope.go))
- The `Seal` pipeline (compress → encrypt → sign → prepend signature) is architecturally distinct from Sliver's approach.

### 2.11 Added: Session State Machine with Health Checking

- **Sliver:** Sessions are either active or removed. No formal state machine.
- **Private-C2:** Six-state machine (`connecting → registering → active → stale → lost → disconnected`) with validated transitions, automatic health checking, and configurable stale/lost thresholds ([`server/core/sessions.go`](file:///home/Fedora/Desktop/Private-C2/server/core/sessions.go))

### 2.12 Added: Trace Cleanup & Timestomping

- **Files:** [`implant/evasion/stealth/stealth.go`](file:///home/Fedora/Desktop/Private-C2/implant/evasion/stealth/stealth.go), [`implant/evasion/stealth/traces.go`](file:///home/Fedora/Desktop/Private-C2/implant/evasion/stealth/traces.go)
- **Content:** Bash history cleaning, SSH known_hosts cleaning, log file cleaning, timestomping, self-deletion, stealth profiles (Normal/Low/Paranoid), working-hours restrictions
- **Sliver comparison:** Sliver's `evasion/` focuses on sandbox detection and anti-analysis, not operational trace cleanup.

### 2.13 Added: Secure Memory Wiping

- **Files:** [`pkg/crypto/wipe.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/wipe.go)
- **Content:** Compiler-resistant zeroing using atomic side-effects; unsafe string wiping via `unsafe.Pointer`
- **Sliver comparison:** No dedicated memory wiping module.

### 2.14 Added: Transport Manager with Failover

- **Files:** [`implant/transport/manager.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/manager.go), [`implant/transport/transport.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/transport.go)
- **Content:** Unified `Transport` interface, health scoring (0.0–1.0), priority-ordered failover with exponential backoff, dynamic re-promotion
- **Sliver comparison:** Sliver's transports each have their own connection logic without a shared interface or failover manager.

---

## 3. Files Most Heavily Derived from the Original

> [!IMPORTANT]
> "Derived" here means the file's **structure, purpose, and position in the
> architecture** closely follow Sliver's design. In no case was verbatim code
> copying verified — the implementations are written independently with
> different struct names, different mechanisms, and different dependencies.
> The derivation is **architectural/structural**, not code-level.

### Tier 1: Architecturally Derived (same position, same purpose, same pattern)

| Private-C2 File | Sliver Equivalent | Evidence |
|---|---|---|
| [`server/core/events.go`](file:///home/Fedora/Desktop/Private-C2/server/core/events.go) | `server/core/events.go` | Same package, same file name, same pub/sub pattern, parallel event type names (`SessionConnected` ↔ `SessionConnectedEvent`) |
| [`server/core/sessions.go`](file:///home/Fedora/Desktop/Private-C2/server/core/sessions.go) | `server/core/sessions.go` | Same package, same file name, same map+mutex pattern, same CRUD API shape |
| [`server/c2/handler.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/handler.go) | `server/c2/mtls.go`, `server/handlers/sessions.go` | Same directory, same connection handling responsibility, same framed message loop |
| [`implant/transport/mtls/mtls.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/mtls/mtls.go) | `implant/sliver/transports/mtls/` | Same subdirectory structure, same TLS 1.3 mTLS client pattern |
| [`implant/transport/https/https.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/https/https.go) | `implant/sliver/transports/httpclient/` | Same domain fronting, custom User-Agent, proxy support |
| [`implant/transport/dns/dns.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/dns/dns.go) | `implant/sliver/transports/dnsclient/` | Same DNS tunneling approach: Base32 subdomains, TXT/CNAME records, chunk reassembly |
| [`implant/transport/wireguard/wireguard.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/wireguard/wireguard.go) | `implant/sliver/transports/wireguard/` | Same transport type in same directory position |
| [`implant/transport/pivot/pivot.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/pivot/pivot.go) | `implant/sliver/transports/pivots/` | Same TCP + named-pipe peer-to-peer pivot pattern |
| [`implant/evasion/syscalls/syscalls_windows.go`](file:///home/Fedora/Desktop/Private-C2/implant/evasion/syscalls/syscalls_windows.go) | `implant/sliver/syscalls/` | Same PEB-walking syscall resolution technique for NT APIs |
| [`server/c2/listener/dns.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/listener/dns.go) | `server/c2/dns.go` | Same authoritative DNS server with Base32 subdomain decoding, TXT/CNAME response generation |
| [`server/c2/listener/https.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/listener/https.go) | `server/c2/http.go` | Same HTTP/2 TLS listener with C2 profile-based routing, domain fronting detection |
| [`server/c2/listener/mtls.go`](file:///home/Fedora/Desktop/Private-C2/server/c2/listener/mtls.go) | `server/c2/mtls.go` | Same mTLS listener with client cert verification |

### Tier 2: Pattern-Inspired (same design decisions, different implementation)

| Private-C2 File | Sliver Equivalent | Notes |
|---|---|---|
| [`server/store/db.go`](file:///home/Fedora/Desktop/Private-C2/server/store/db.go) | `server/db/sql.go` | Both use GORM with AutoMigrate; Private-C2 adds PostgreSQL |
| [`server/store/models/models.go`](file:///home/Fedora/Desktop/Private-C2/server/store/models/models.go) | `server/db/models/` | Similar model concepts (Session, Beacon, Operator, Listener) but different field sets |
| [`pkg/crypto/keyexchange.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/keyexchange.go) | Sliver's NaCl Box (uses X25519) | Same underlying algorithm, different API and wrapping |
| [`pkg/crypto/aead.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/aead.go) | Sliver's ChaCha20-Poly1305 | Same algorithm family, Private-C2 uses extended nonce variant + replay detection |
| [`client/console/`](file:///home/Fedora/Desktop/Private-C2/client/console/) | `client/console/` | Same directory name, same REPL concept; Sliver uses Grumble, Private-C2 uses bufio |
| [`cmd/implant/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/implant/main.go) | `implant/sliver/sliver.go` | Same register → beacon-loop → task-execute pattern |

### Tier 3: No Sliver Equivalent (original to Private-C2)

| Private-C2 File(s) | Feature |
|---|---|
| [`implant/modules/ot/`](file:///home/Fedora/Desktop/Private-C2/implant/modules/ot/) (32 files) | OT/ICS assessment with 17 protocol clients |
| [`pkg/engagement/scope.go`](file:///home/Fedora/Desktop/Private-C2/pkg/engagement/scope.go), [`safeguards.go`](file:///home/Fedora/Desktop/Private-C2/pkg/engagement/safeguards.go) | Engagement scope enforcement & kill switches |
| [`implant/safety/`](file:///home/Fedora/Desktop/Private-C2/implant/safety/) | Implant-side safety framework |
| [`pkg/audit/logger.go`](file:///home/Fedora/Desktop/Private-C2/pkg/audit/logger.go), [`export.go`](file:///home/Fedora/Desktop/Private-C2/pkg/audit/export.go) | Hash-chained audit log with CEF/LEEF export |
| [`server/api/httpapi/webui/index.html`](file:///home/Fedora/Desktop/Private-C2/server/api/httpapi/webui/index.html) | Embedded web portal |
| [`pkg/envelope/envelope.go`](file:///home/Fedora/Desktop/Private-C2/pkg/envelope/envelope.go) | Sign+encrypt+compress envelope pipeline |
| [`pkg/crypto/wipe.go`](file:///home/Fedora/Desktop/Private-C2/pkg/crypto/wipe.go) | Secure memory wiping |
| [`implant/transport/manager.go`](file:///home/Fedora/Desktop/Private-C2/implant/transport/manager.go) | Transport failover manager |
| [`implant/evasion/stealth/`](file:///home/Fedora/Desktop/Private-C2/implant/evasion/stealth/) | Trace cleanup, timestomping, stealth profiles |
| [`server/store/models/ot.go`](file:///home/Fedora/Desktop/Private-C2/server/store/models/ot.go) | 10 OT/ICS database models |
| [`cmd/mcp/main.go`](file:///home/Fedora/Desktop/Private-C2/cmd/mcp/main.go) | MCP server for AI integration |
| [`server/core/security.go`](file:///home/Fedora/Desktop/Private-C2/server/core/security.go) | Security policy enforcement |

---

## 4. Project Timeline & Provenance

### Git History Summary

- **Repository:** `https://github.com/AzizBinMohammad/Private-C2.git`
- **Additional remotes:** `Nua-org/Private-C2`, `Nua-org/PT-Team` (Nua Security Penetration Testing Team)
- **Sole contributor:** `AzizBinMohammad` (with recent `Claude Opus 4.6` co-authored commits)
- **Not a GitHub fork** — independent repository with no fork metadata

### Initial Commit Timeline (2025-06-14)

All foundational code was committed in a **38-minute window** on June 14, 2025:

| Time (UTC+3) | Commit | Content |
|---|---|---|
| 14:06 | `6b2e7c0` | Initial project structure: cmd entry points, server config |
| 14:09 | `6f00ab3` | Implant with beacon loop, multi-platform support |
| 14:11 | `ad5a8ea` | Operator CLI client |
| 14:14 | `fa39fac` | C2 handler with session management and wire protocol |
| 14:17 | `a8bb7cc` | Infrastructure: go.work, Makefile, Dockerfile, scripts |
| 14:22 | `d20afd7` | gRPC stubs and protobuf definitions |
| 14:24 | `c58a22f` | HTTP API, auth, event bus, session management, database |
| 14:27 | `f5a18e4` | Cryptographic primitives and envelope protocol |
| 14:30 | `00a42c5` | Engagement scope enforcement and audit logging |
| 14:33 | `eeddd2f` | Server build pipeline, listeners, middleware stubs |
| 14:35 | `07a4ab8` | Implant modules, evasion, safety framework |
| 14:37 | `f7ed3db` | OT/ICS assessment (17 protocol clients) |
| 14:40 | `dd94cac` | HTTP API enhancements (payload build, OT endpoints) |
| 14:42 | `2cb8d12` | Web portal |
| 14:44 | `1291ec3` | MCP server integration |

The 38-minute commit burst for ~26,000 lines across ~170 files is consistent with a project developed offline and committed in structured batches, or with AI-assisted code generation.

### Subsequent Development (2026-10-13)

Refactoring and testing work was done in a single day, including:
- Wire protocol type extraction to shared `pkg/protocol/` package
- HTTP handler monolith split into per-resource files
- TLS config deduplication to `pkg/tlsutil/`
- Test suite for critical flows
- Bug fixes (IPv6, scope checking, SQLite migration)
- Screenshot capture implementation

---

## 5. Overall Assessment

### Summary of Findings

| Category | Assessment |
|---|---|
| **Directory structure** | Closely modeled after Sliver |
| **Feature matrix** | Same core transport set (mTLS, HTTPS, DNS, WireGuard, pivot) as Sliver |
| **Code-level copying** | **Not verified** — no identical code blocks found across the two codebases |
| **Implementation approach** | Independently written: different wire protocol (JSON vs protobuf), different API style (REST vs gRPC), different crypto wrapping, different concurrency patterns |
| **Original additions** | Substantial: OT/ICS (32 files), scope enforcement, hash-chained audit, safety framework, web portal, transport failover manager, stealth profiles, MCP integration |
| **Attribution** | None present. No license file, no copyright headers, no Sliver references in code |

### Characterization

Private-C2 is best characterized as a **clean-room reimplementation inspired by Sliver's architecture** with significant original additions (OT/ICS assessment, engagement safety, audit compliance). The code is not a fork and contains no verbatim Sliver code that could be identified. However, the directory structure, feature set, and architectural decomposition closely parallel Sliver's design, indicating the original author used Sliver as a reference architecture.

### Unverified Items

- Whether any Private-C2 code was written by reading and reimplementing Sliver source (vs. independently arriving at similar designs from C2 domain knowledge) — **unverified**
- Whether the project's development predates the initial Git commit date — **unverified**
- The author's relationship to the `Nua-org/PT-Team` remote and whether that organization has Sliver-related tooling — **unverified**
- Whether the 38-minute initial commit window represents AI-assisted generation, a squashed import from a private repo, or manual batch commits — **unverified**
