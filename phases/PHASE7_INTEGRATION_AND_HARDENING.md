# Phase 7: Integration Testing, Security Hardening & Deployment

## Status: NOT STARTED

## Objective
End-to-end integration tests, security audit of the codebase, deployment packaging, and documentation.

## Tasks

### 7.1 Integration Tests
**File: `tests/integration/session_lifecycle_test.go`**
- Full lifecycle: start server → start listener → implant connects → session appears → send task → receive result → disconnect → session marked lost
- Test with mTLS transport
- Test with HTTPS transport
- Verify audit trail captures all events

**File: `tests/integration/beacon_lifecycle_test.go`**
- Beacon mode: implant checks in → tasks queued → next check-in retrieves tasks → results returned
- Verify interval and jitter behavior
- Test missed check-in → stale → lost transitions

**File: `tests/integration/engagement_scope_test.go`**
- Create engagement with scope
- Implant tries to scan out-of-scope target → blocked
- Implant operates on in-scope target → allowed
- Activate kill switch → implant stops operating
- Verify audit trail records scope violations

**File: `tests/integration/build_pipeline_test.go`**
- Submit build config → job queued → job completes → artifact stored
- Download artifact → verify SHA256 matches
- Cross-compile for different OS/arch combos
- Build with different feature sets

**File: `tests/integration/transport_fallback_test.go`**
- Implant configured with [mTLS, HTTPS] fallback chain
- Block mTLS → implant falls back to HTTPS
- Unblock mTLS → implant re-promotes to mTLS
- Verify all transitions logged

**File: `tests/integration/multi_operator_test.go`**
- Multiple operators connect simultaneously
- Session locking prevents conflicts
- RBAC enforcement: observer cannot execute tasks
- Audit trail attributes actions to correct operator

### 7.2 Security Hardening
**File: `server/core/security.go`**
- Input validation on all gRPC handlers (max lengths, allowed characters, path traversal prevention)
- SQL injection prevention audit (GORM parameterized queries — verify no raw SQL)
- Rate limit tuning per endpoint
- Certificate rotation support: reload CA/certs without restart

**Review checklist:**
- [ ] No hardcoded credentials or keys anywhere in codebase
- [ ] All crypto uses `crypto/rand`, never `math/rand`
- [ ] TLS 1.3 minimum everywhere
- [ ] No path traversal in file upload/download (canonicalize paths, jail to allowed directories)
- [ ] Implant binary: no debug symbols, no source paths (`-trimpath -ldflags "-s -w"`)
- [ ] Audit log: append-only, chain verification covers all entries
- [ ] Kill switch: fail-closed verified (network unreachable = kill)
- [ ] Memory: sensitive data (keys, passwords) zeroed after use
- [ ] Graceful shutdown: all connections drained, no data loss

**File: `pkg/crypto/wipe.go`**
- `Wipe([]byte)` — Zero out sensitive byte slices
- Use in all crypto operations after key material is no longer needed

### 7.3 Server Configuration
**File: `server/config/config.go`**
- Server configuration struct loaded from YAML:
  ```yaml
  server:
    grpc_addr: ":31337"
    metrics_addr: ":9090"
  database:
    dialect: postgres
    dsn: "host=localhost dbname=privatec2 sslmode=require"
  tls:
    ca_cert: /etc/pc2/ca.pem
    server_cert: /etc/pc2/server.pem
    server_key: /etc/pc2/server-key.pem
  security:
    rate_limit_rps: 100
    rate_limit_burst: 200
    session_stale_threshold: 30s
    session_lost_threshold: 2m
  logging:
    level: info
    format: json
    audit_file: /var/log/pc2/audit.log
  ```
- Environment variable overrides: `PC2_DB_DSN`, `PC2_GRPC_ADDR`, etc.
- Config validation on startup

### 7.4 Deployment Packaging
**File: `Dockerfile`**
- Multi-stage build: Go builder → minimal runtime (distroless or alpine)
- Server binary only in production image
- Config mounted via volume
- Health check endpoint configured

**File: `docker-compose.yml`**
- Server + PostgreSQL stack
- Volume mounts for certs and config
- Network isolation

**File: `Makefile`**
- `make build` — Build all binaries
- `make test` — Run all tests
- `make test-integration` — Run integration tests
- `make lint` — Run golangci-lint
- `make proto` — Regenerate protobuf Go code
- `make docker` — Build Docker image
- `make clean` — Clean build artifacts
- `make cross-compile` — Build implant for all supported platforms

### 7.5 Operator Onboarding
**File: `scripts/setup-ca.sh`**
- Generate CA and server certificates
- Output configuration file template

**File: `scripts/add-operator.sh`**
- Generate operator client certificate signed by CA
- Create operator config file
- Register operator in server database

### 7.6 Web UI Foundation (Optional)
**Directory: `ui/src/`**
- React + TypeScript SPA
- gRPC-Web client connecting to server (via Envoy proxy or grpc-web handler)
- Dashboard: active sessions, beacons, listeners count
- Session table with real-time updates
- Engagement management forms
- Audit log viewer with filters
- NOTE: This is a stretch goal — CLI is the primary interface

## Key Design Decisions
- Integration tests use real server and implant binaries, not mocks
- Tests run in isolated network namespace or Docker containers
- Security hardening is a review + fix pass, not new features
- Deployment supports both bare-metal and containerized
- Web UI is optional — full functionality available via CLI

## Dependencies
- All previous phases must be complete
- External: `docker`, `docker-compose`, `golangci-lint`, `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`

## Verification
```bash
make test
make test-integration
make lint
make docker
docker-compose up -d
# Verify server starts, accepts connections, serves metrics
curl -k https://localhost:9090/healthz
```

### 7.7 OT Integration Tests
**File: `tests/integration/ot_assessment_test.go`**
- OT safety interlocks: write command → hard block, verified per protocol
- Dual authorization: scan without OT token → rejected
- Kill switch: activate mid-OT-scan → all OT connections drop
- Rate limiting: burst of OT queries → enforced inter-packet delay
- Hidden interface: operator without `ot.assess` → OT service not visible
- Scope: OT scan against out-of-scope target → blocked
- Safety-critical tag: query safety-rated device → read-only interlock
- Full details in `PHASE8_OT_INTERFACE.md`

## Dependencies
- All previous phases (1-6) must be complete
- Phase 8 (OT) can be tested in parallel with Phase 7 integration work
- External: `docker`, `docker-compose`, `golangci-lint`, `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`
- OT testing: Modbus simulator (ModRSsim2), OPC UA test server (open62541)

## Definition of Done
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] `golangci-lint` clean
- [ ] `go vet ./...` clean
- [ ] Docker image builds and runs
- [ ] Server accepts operator connection with mTLS
- [ ] Implant connects, registers, executes tasks
- [ ] Engagement scope enforced end-to-end
- [ ] Kill switch terminates all engagement activity
- [ ] Audit trail complete and verifiable
- [ ] No hardcoded secrets
- [ ] TLS 1.3 only
- [ ] OT interface hidden from standard enumeration
- [ ] OT read-only interlocks verified per protocol
- [ ] OT dual-auth gate tested
- [ ] OT rate limiting validated against simulator
