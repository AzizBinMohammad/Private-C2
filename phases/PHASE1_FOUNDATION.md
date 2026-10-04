# Phase 1: Foundation (COMPLETED)

## Status: DONE

## What Was Built

### Go Workspace (`go.work`)
- 7-module Go 1.23 workspace: `pkg`, `server`, `client`, `implant`, `cmd/server`, `cmd/client`, `cmd/builder`
- Replace directives linking local modules

### Protocol Buffers (`proto/v1/`)
- `common.proto` — Shared enums: TargetPlatform, SessionHealth, ImplantMode, TransportType, OutputFormat, Severity, Operator, Pagination, Response, Empty
- `client.proto` — Session, Beacon, Listener, PayloadConfig (ImplantConfig, TransportConfig, FeatureConfig, EvasionConfig, OutputConfig), PayloadArtifact, BuildJob, OperatorConfig, Permission, Role
- `implant.proto` — Envelope, Register, Ping, TaskRequest/Response, ShellRequest/Response, FileRequest/Response, ProcessListRequest/Response, NetworkInfo, ScreenshotRequest/Response, KillSwitchCheck/Status
- `engagement.proto` — Engagement, Scope, TimeWindow, DataHandling, AdversaryProfile, ScopeCheckRequest/Response, KillSwitchRequest
- `audit.proto` — AuditEntry with cryptographic chaining, AuditEventType, AuditQuery, AuditEntries
- `services.proto` — OperatorService, EngagementService, AuditService, AdminService, ImplantService

### Shared Libraries (`pkg/`)
- `pkg/crypto/aead.go` — ChaCha20Poly1305 (XChaCha20, 24-byte nonce), CipherContext with sync.Map replay detection, DeriveKey via SHA256
- `pkg/crypto/keyexchange.go` — X25519 key exchange: GenerateX25519KeyPair(), ComputeSharedSecret()
- `pkg/crypto/signing.go` — Ed25519: GenerateEd25519KeyPair(), Sign(), Verify()
- `pkg/crypto/pki.go` — ECDSA P-384 CA with NewCertificateAuthority(), IssueCertificate(), CertPool()
- `pkg/envelope/framing.go` — 4-byte little-endian length-prefix wire framing, 2GB max
- `pkg/envelope/envelope.go` — Seal() compress→encrypt→sign, Open() verify→decrypt→decompress
- `pkg/envelope/compression.go` — Gzip BestSpeed wrappers
- `pkg/platform/matrix.go` — Platform support matrix: 6 OS × multiple archs → PlatformCapabilities{Transports, Features, ImplantModes}
- `pkg/platform/validation.go` — ValidatePayloadConfig() with structured error codes
- `pkg/audit/logger.go` — Append-only audit with SHA256 hash chaining, sequential entries
- `pkg/audit/export.go` — JSON, CEF, LEEF export formats
- `pkg/engagement/scope.go` — Scope enforcement: CIDRs, hostnames, domain suffixes, exclusion list
- `pkg/engagement/safeguards.go` — Kill switch (per-engagement, fail-closed), DataQuota for exfil limits

### Server (`server/`)
- `server/store/models/models.go` — GORM models: Base (UUID auto-gen), Operator, Session, Beacon, Listener, PayloadArtifact, Engagement, AuditEntry, C2Profile, Role
- `server/store/db.go` — Database init with SQLite/PostgreSQL dialectors, connection pooling, AutoMigrate
- `server/store/repository/` — Repository pattern: sessions (CRUD, lock/unlock, health), beacons, listeners, operators, engagements, audit (insert, query with filters, chain verification)
- `server/api/middleware/auth.go` — mTLS client cert authentication, OperatorLookup from CN, context injection
- `server/api/middleware/rbac.go` — 4 roles (admin/operator/builder/observer), per-method permission mapping
- `server/api/middleware/ratelimit.go` — Token bucket rate limiter per operator/IP
- `server/api/middleware/audit.go` — gRPC audit interceptors with correlation IDs
- `server/api/grpc/operator.go` — Session listing/locking with live state overlay
- `server/api/grpc/engagement.go` — Engagement CRUD, scope checking
- `server/core/events.go` — Typed event bus with async publish/subscribe
- `server/core/sessions.go` — Session state machine: connecting→registering→active→stale→lost→disconnected, health check sweep
- `server/telemetry/metrics.go` — Prometheus: active sessions/beacons/listeners, gRPC requests/latency, tasks, payloads, data exfil, scope violations, kill switch activations
- `server/telemetry/health.go` — /healthz endpoint with runtime stats

### Entry Points (`cmd/`)
- `cmd/server/main.go` — TLS 1.3, gRPC with middleware chain, metrics server, graceful shutdown
- `cmd/client/main.go` — CLI placeholder with command listing
- `cmd/builder/main.go` — Builder placeholder with option listing

## Verification
```bash
go build ./pkg/... ./server/...
go build -o /tmp/pc2-server ./cmd/server/...
go vet ./pkg/... ./server/...
```
