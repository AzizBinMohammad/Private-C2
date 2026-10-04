# Architecture

Private-C2 is a Go 1.23 multi-module workspace organized into 7 modules. This document explains the project structure, how the modules interact, and the key design decisions.

## Module Overview

```
go.work
  pkg/          Shared libraries, no external dependencies beyond stdlib + crypto
  server/       C2 server: gRPC API, listeners, build pipeline, database
  client/       Operator CLI: interactive console, command framework
  implant/      Implant agent: runtime loop, task modules, transports, evasion
  cmd/server/   Server entry point
  cmd/client/   Client entry point
  cmd/builder/  Builder entry point
```

### Dependency Flow

```
cmd/server  --> server --> pkg
cmd/client  --> client --> pkg
cmd/builder --> server --> pkg
                implant --> pkg  (built separately via build pipeline)
```

The `implant` module is never linked into the server or client. It is cross-compiled by the build pipeline (`server/build/`) into standalone binaries for target platforms.

---

## Directory Structure

```
Private-C2/
|
|-- go.work                          # Workspace: pkg, server, client, implant, cmd/*
|
|-- pkg/                             # Shared libraries
|   |-- crypto/
|   |   |-- aead.go                  # XChaCha20-Poly1305 encryption with replay detection
|   |   |-- keyexchange.go           # X25519 ECDH key exchange
|   |   |-- signing.go               # Ed25519 digital signatures
|   |   |-- pki.go                   # ECDSA P-384 certificate authority
|   |   |-- wipe.go                  # Secure memory wiping
|   |   +-- *_test.go                # Unit tests for each
|   |
|   |-- envelope/
|   |   |-- framing.go               # 4-byte length-prefix wire framing (2GB max)
|   |   |-- envelope.go              # Seal (compress->encrypt->sign) / Open (verify->decrypt->decompress)
|   |   |-- compression.go           # Gzip BestSpeed wrappers
|   |   +-- *_test.go
|   |
|   |-- platform/
|   |   |-- matrix.go                # 6 OS x N arch support matrix with capabilities
|   |   |-- validation.go            # Payload config validation against platform matrix
|   |   +-- *_test.go
|   |
|   |-- audit/
|   |   |-- logger.go                # Append-only audit log with SHA256 hash chaining
|   |   |-- export.go                # JSON, CEF, LEEF export formats
|   |   +-- *_test.go
|   |
|   +-- engagement/
|       |-- scope.go                 # CIDR, hostname, domain suffix scope enforcement
|       |-- safeguards.go            # KillSwitch (fail-closed), DataQuota, TimeWindow
|       +-- *_test.go
|
|-- server/                          # C2 server
|   |-- api/
|   |   |-- grpc/
|   |   |   |-- operator.go          # Session listing, locking, live state overlay
|   |   |   |-- engagement.go        # Engagement CRUD, scope checking
|   |   |   +-- ot.go                # OT/ICS gRPC service (hidden from reflection)
|   |   |
|   |   +-- middleware/
|   |       |-- auth.go              # mTLS client certificate authentication
|   |       |-- rbac.go              # 5 roles: admin, operator, ot-operator, builder, observer
|   |       |-- ratelimit.go         # Token bucket rate limiter
|   |       |-- audit.go             # gRPC audit interceptors
|   |       +-- ot_auth.go           # OT dual-authorization middleware
|   |
|   |-- c2/
|   |   |-- listener/
|   |   |   |-- listener.go          # Base Listener interface
|   |   |   |-- mtls.go              # mTLS TCP with bidirectional framed streaming
|   |   |   |-- https.go             # HTTP/2 TLS with C2 profile routing
|   |   |   |-- dns.go               # Authoritative DNS server (UDP+TCP)
|   |   |   +-- wireguard.go         # WireGuard tunnel (stub)
|   |   |
|   |   +-- profile/
|   |       +-- profile.go           # C2 traffic profiles (HTTP paths, headers, DNS config)
|   |
|   |-- build/
|   |   |-- config.go                # BuildConfig with platform validation
|   |   |-- stages/
|   |   |   |-- configure.go         # Generate implant config, embed crypto keys
|   |   |   |-- compile.go           # Cross-compile with GOOS/GOARCH
|   |   |   |-- postprocess.go       # Output format transforms (exe, dll, shellcode, shared)
|   |   |   |-- obfuscate.go         # Assessment-grade string encryption, symbol rename
|   |   |   +-- stager.go            # Download-and-execute stager generation
|   |   |
|   |   +-- queue/
|   |       |-- queue.go             # Concurrent build queue with job tracking
|   |       +-- worker.go            # Worker goroutine with timeout
|   |
|   |-- config/
|   |   +-- config.go                # Server config from environment variables
|   |
|   |-- core/
|   |   |-- events.go                # Typed event bus with async pub/sub
|   |   |-- sessions.go              # Session state machine (active->stale->lost)
|   |   +-- security.go              # Input validation (UUID, names, paths, IPs, CIDRs)
|   |
|   |-- store/
|   |   |-- db.go                    # GORM database init (SQLite/PostgreSQL)
|   |   |-- models/
|   |   |   |-- models.go            # Core models: Operator, Session, Beacon, Listener, etc.
|   |   |   +-- ot.go                # OT models: OTAssetRecord, OTVulnFinding, etc.
|   |   |
|   |   +-- repository/
|   |       |-- sessions.go          # Session CRUD + locking
|   |       |-- beacons.go           # Beacon CRUD
|   |       |-- listeners.go         # Listener CRUD + connection tracking
|   |       |-- operators.go         # Operator lookup by cert fingerprint
|   |       |-- engagements.go       # Engagement CRUD + operator associations
|   |       |-- audit.go             # Audit log insert, query, chain verification
|   |       |-- payloads.go          # PayloadArtifact CRUD
|   |       +-- ot.go                # OT asset/finding/scan CRUD
|   |
|   +-- telemetry/
|       |-- metrics.go               # Prometheus metrics
|       +-- health.go                # /healthz endpoint
|
|-- client/                          # Operator CLI
|   |-- transport/
|   |   |-- config.go                # Operator config (server address, certs, JSON serialization)
|   |   +-- grpc.go                  # gRPC client interface
|   |
|   |-- console/
|   |   |-- console.go               # Interactive REPL
|   |   |-- context.go               # Console state (active engagement, session, beacon)
|   |   |-- output.go                # Table formatting, ANSI colors, JSON mode
|   |   +-- events.go                # Background event listener (14 notification types)
|   |
|   +-- cli/commands/
|       |-- commands.go              # Command struct, registry, dispatch
|       |-- sessions.go              # sessions list/interact/lock/unlock/kill
|       |-- beacons.go               # beacons list/interact/watch
|       |-- listeners.go             # listeners start/stop/profiles
|       |-- payloads.go              # generate/payloads/download/revoke
|       |-- tasks.go                 # shell/upload/download/ls/ps/kill/ifconfig/netstat/screenshot/portscan
|       |-- engagement.go            # engagements create/use/status/killswitch/scope
|       |-- audit.go                 # audit query/export/verify
|       |-- admin.go                 # operators/server management
|       +-- ot.go                    # OT commands (hidden unless ot-operator role)
|
|-- implant/                         # Implant agent
|   |-- runtime/
|   |   |-- config.go                # Implant config (server URLs, ID, mode, keys, kill date)
|   |   |-- runtime.go               # Main loop: session (persistent) and beacon (interval) modes
|   |   |-- register.go              # Registration handshake with sysinfo
|   |   |-- sysinfo.go               # SystemInfo struct + Collector interface
|   |   |-- sysinfo_linux.go         # Linux: /etc/os-release, hostname, uname
|   |   |-- sysinfo_windows.go       # Windows: GetComputerName, RtlGetVersion
|   |   |-- sysinfo_darwin.go        # macOS: sysctl, sw_vers
|   |   +-- sysinfo_default.go       # Fallback for other OS
|   |
|   |-- transport/
|   |   |-- transport.go             # Transport interface (Connect, Send, Recv, Close, Name)
|   |   |-- manager.go               # Fallback chain with health scoring and re-promotion
|   |   |-- mtls/mtls.go             # TLS 1.3 dialer with reconnect + exponential backoff
|   |   |-- https/https.go           # HTTP client with proxy, domain fronting, user-agent rotation
|   |   |-- dns/
|   |   |   |-- dns.go               # DNS transport with multi-record queries
|   |   |   +-- encoding.go          # Base32 encoding, chunk/reassemble with sequence IDs
|   |   |-- wireguard/wireguard.go   # WireGuard userspace client (stub)
|   |   +-- pivot/pivot.go           # Peer-to-peer TCP relay + named pipe (Windows)
|   |
|   |-- task/
|   |   |-- executor.go              # Task dispatcher with timeout + concurrency semaphore
|   |   +-- registry.go              # Module registry: task type string -> handler function
|   |
|   |-- modules/
|   |   |-- shell/
|   |   |   |-- shell.go             # Common types
|   |   |   |-- shell_unix.go        # /bin/sh -c execution
|   |   |   +-- shell_windows.go     # cmd.exe /c execution
|   |   |
|   |   |-- filesystem/
|   |   |   +-- filesystem.go        # ls, cat, upload, download (quota-checked), rm, mkdir, cp, mv, pwd, cd
|   |   |
|   |   |-- process/
|   |   |   |-- process.go           # Common ps/kill interface
|   |   |   |-- process_linux.go     # /proc enumeration
|   |   |   |-- process_windows.go   # Windows process APIs (stub)
|   |   |   |-- process_darwin.go    # macOS (stub)
|   |   |   +-- process_default.go   # Fallback
|   |   |
|   |   |-- network/
|   |   |   +-- network.go           # ifconfig, netstat, portscan (scope-checked), resolve
|   |   |
|   |   |-- screenshot/
|   |   |   +-- screenshot.go        # Screen capture (stub)
|   |   |
|   |   |-- logs/
|   |   |   |-- logs.go              # Log clearing interface
|   |   |   +-- logs_*.go            # Platform-specific + timestomp
|   |   |
|   |   +-- ot/                      # OT/ICS assessment (all read-only)
|   |       |-- ot.go                # Safety interlocks, kill switch, rate limiter, watchdog
|   |       |-- discovery.go         # Passive/active OT asset discovery
|   |       |-- capture.go           # Traffic capture, comm matrix, polling detection
|   |       |-- fingerprint.go       # MAC OUI, HTTP, TLS fingerprinting + CVE cross-ref
|   |       |-- topology.go          # Purdue model mapping, GraphViz DOT export
|   |       |-- credentials.go       # Single-attempt default credential testing
|   |       |-- vulnscan.go          # Offline CVE correlation, insecure protocol detection
|   |       |-- segmentation.go      # Purdue segmentation analysis, VLAN detection
|   |       |-- wireless.go          # WirelessHART, ISA100.11a, WiFi, Zigbee, BLE
|   |       |-- historian.go         # Historian/SCADA detection (PI, Wonderware, etc.)
|   |       |-- hmi.go               # HMI web interface assessment (HTTP GET only)
|   |       |-- plclogic.go          # PLC program metadata reader
|   |       |-- serial.go            # Serial-to-Ethernet converter detection
|   |       |-- compliance.go        # IEC 62443 / NIST 800-82 / NERC CIP gap analysis
|   |       |-- reporting.go         # JSON/Markdown/CSV/MITRE ATT&CK Navigator export
|   |       +-- protocols/
|   |           |-- common.go        # ProtocolClient interface, helpers
|   |           |-- modbus.go        # Modbus TCP read-only (FC 01-04, 07, 08, 11-12, 17, 43)
|   |           |-- opcua.go         # OPC UA (GetEndpoints, Browse, Read)
|   |           |-- s7comm.go        # Siemens S7Comm (SZL reads, CPU info)
|   |           |-- dnp3.go          # DNP3 (Class 0-3 reads, device attributes)
|   |           |-- ethernetip.go    # EtherNet/IP CIP (ListIdentity, Get_Attribute)
|   |           |-- bacnet.go        # BACnet (Who-Is, ReadProperty)
|   |           |-- iec104.go        # IEC 60870-5-104 (monitoring ASDUs)
|   |           |-- iec61850.go      # IEC 61850 MMS (GetNameList, Read)
|   |           |-- profinet.go      # PROFINET DCP discovery
|   |           |-- hart.go          # HART-IP (Commands 0-3, 12-15, 48)
|   |           |-- mqtt.go          # MQTT broker enumeration, topic sniffing
|   |           |-- coap.go          # CoAP resource discovery
|   |           |-- fins.go          # Omron FINS (Memory/CPU/Status Read)
|   |           |-- melsec.go        # Mitsubishi MELSEC (Batch Read, CPU info)
|   |           |-- pcworx.go        # Phoenix Contact PC Worx
|   |           +-- crimson.go       # Red Lion Crimson
|   |
|   |-- safety/
|   |   |-- safety.go                # Pre-execution checks: kill switch, kill date, scope, quota
|   |   +-- allowlist.go             # Command allowlist for simulation mode
|   |
|   +-- evasion/
|       |-- stealth/
|       |   |-- stealth.go           # Stealth profiles (Normal/Low/Paranoid), working hours, jitter
|       |   +-- traces.go            # Trace cleanup
|       |
|       +-- syscalls/
|           |-- syscalls.go          # Syscaller interface
|           |-- syscalls_windows.go  # Windows NT direct syscall stubs
|           +-- syscalls_default.go  # Non-Windows fallback
|
|-- cmd/
|   |-- server/main.go               # Server: TLS 1.3, gRPC + middleware, metrics, graceful shutdown
|   |-- client/main.go               # Client: CLI entry point
|   +-- builder/main.go              # Builder: payload generation entry point
|
|-- proto/v1/                        # Protocol Buffer definitions
|   |-- common.proto                 # Shared enums and base types
|   |-- client.proto                 # Session, Beacon, Listener, PayloadConfig, Role
|   |-- implant.proto                # Envelope, Register, Task request/response
|   |-- engagement.proto             # Engagement, Scope, TimeWindow, DataHandling
|   |-- audit.proto                  # AuditEntry with hash chaining, AuditQuery
|   |-- services.proto               # OperatorService, EngagementService, AuditService, AdminService, ImplantService
|   +-- ot.proto                     # OTService (17 RPCs), OTAuthToken, all OT message types
|
|-- tests/integration/               # Integration test stubs
|   |-- session_lifecycle_test.go
|   |-- beacon_lifecycle_test.go
|   |-- engagement_scope_test.go
|   |-- build_pipeline_test.go
|   |-- transport_fallback_test.go
|   |-- multi_operator_test.go
|   +-- ot_assessment_test.go
|
|-- phases/                          # Development phase documentation (all DONE)
|-- scripts/                         # setup-ca.sh, add-operator.sh
|-- Dockerfile                       # Multi-stage build, alpine, non-root
|-- docker-compose.yml               # Server + PostgreSQL 16
+-- Makefile                         # build, test, lint, docker, cross-compile
```

---

## Key Design Decisions

### Multi-Module Workspace

The project uses Go workspaces (`go.work`) to keep modules independent. The `implant` module has minimal dependencies to keep compiled binaries small. The `pkg` module contains only shared code with no server/client-specific logic.

### Wire Protocol

All communication uses the envelope layer (`pkg/envelope`):

```
Data -> Gzip compress -> XChaCha20-Poly1305 encrypt -> Ed25519 sign -> Length-prefix frame
```

This is transport-agnostic. Whether data travels over mTLS, HTTPS, DNS, or WireGuard, the same envelope wraps it.

### Transport Fallback

The implant transport manager maintains a priority-ordered list of transports. If the primary fails, it falls back to the next. Each transport gets a health score based on success/failure rate. Higher-priority transports are periodically re-attempted for promotion.

### Engagement Scoping

Every operation is bound to an engagement. The engagement defines:
- **Scope**: which targets (IPs, hostnames, domains) are in bounds
- **Time window**: when operations are permitted
- **Kill switch**: emergency halt for all engagement activity
- **Data quota**: maximum bytes that can be exfiltrated

The implant checks these constraints before every task execution.

### Session State Machine

```
ACTIVE  --(no heartbeat for StaleThreshold)-->  STALE
STALE   --(no heartbeat for LostThreshold)--->  LOST
STALE   --(heartbeat received)--------------->  ACTIVE
```

A background sweep goroutine runs every 10 seconds to transition sessions.

### RBAC

Five roles with distinct permission sets:

| Role | Permissions |
|------|------------|
| admin | All permissions including operator management |
| operator | Session/beacon read+write, listener management, builds, audit read |
| ot-operator | Same as operator + `ot.assess` permission |
| builder | Payload generation only |
| observer | Read-only access to sessions, beacons, listeners, audit |

Authentication is via mTLS client certificates. The operator's cert fingerprint is looked up in the database to determine their role.

### OT/ICS Safety Architecture

The OT module has two layers of safety:

1. **Hard interlocks** (code-level, cannot be overridden):
   - No write function codes exist in the codebase for any protocol
   - No firmware modification commands
   - No process start/stop/reset commands
   - Rate limiting on all queries (default 500ms between packets)

2. **Soft constraints** (configurable per engagement):
   - Maximum concurrent OT connections
   - Query timeout limits
   - Scan rate limits
   - Credential testing on/off
   - Traffic capture duration and size caps

### Database

GORM with support for SQLite (development) and PostgreSQL (production). All models embed a `Base` struct that auto-generates UUIDs and tracks created/updated timestamps.

### Build Pipeline

The server compiles implant binaries on demand:

```
BuildConfig -> Configure (embed keys) -> Compile (cross-compile) -> Postprocess (format) -> Obfuscate -> Store artifact
```

A concurrent queue limits parallel builds to `runtime.NumCPU()`. Each build gets a unique implant ID and fresh cryptographic keys.

---

## Stats

- **~170 source files** across all modules
- **~26,000 lines** of Go code
- **49 unit tests** covering all `pkg/` packages
- **7 integration test stubs** ready for CI
- **17 OT protocol clients**, all strictly read-only
- **5 transport types** (mTLS, HTTPS, DNS, WireGuard, pivot)
- **6 target operating systems** supported
