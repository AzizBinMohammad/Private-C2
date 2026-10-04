# Phase 2: Unit Tests & Implant Runtime Skeleton

## Status: DONE

## What Was Built
- 14 test files with 49 unit tests covering all `pkg/` packages (crypto, envelope, platform, audit, engagement)
- `implant/runtime/config.go` — Implant configuration struct (server URLs, implant ID, mode, sleep interval, jitter, kill date, encryption keys)
- `implant/runtime/runtime.go` — Main implant loop with session (persistent) and beacon (interval-based) modes
- `implant/runtime/register.go` — Registration handshake with system info collection
- `implant/runtime/sysinfo.go` — Cross-platform system info with build-tagged implementations (`sysinfo_linux.go`, `sysinfo_windows.go`, `sysinfo_darwin.go`, `sysinfo_default.go`)
- `implant/transport/transport.go` — Transport interface (Connect, Send, Recv, Close, Name)
- `implant/transport/manager.go` — Transport manager with fallback chain, health scoring, backoff, re-promotion

## Objective
Add comprehensive unit tests for all `pkg/` packages, build the implant runtime skeleton, and create the implant-side transport interface layer.

## Tasks

### 2.1 Unit Tests for `pkg/crypto`
**Files to create:**
- `pkg/crypto/aead_test.go`
- `pkg/crypto/keyexchange_test.go`
- `pkg/crypto/signing_test.go`
- `pkg/crypto/pki_test.go`

**Test coverage required:**
- AEAD: encrypt/decrypt round-trip, replay detection (same ciphertext rejected), different keys fail decryption, nonce uniqueness, DeriveKey determinism, RandomSymmetricKey entropy
- Key exchange: X25519 key pair generation, shared secret derivation (both sides agree), different key pairs produce different secrets
- Signing: Ed25519 sign/verify round-trip, tampered message fails verify, wrong key fails verify
- PKI: CA creation with valid cert, leaf cert issuance, leaf cert validates against CA pool, expired cert handling, CertPool() returns usable pool

### 2.2 Unit Tests for `pkg/envelope`
**Files to create:**
- `pkg/envelope/framing_test.go`
- `pkg/envelope/envelope_test.go`
- `pkg/envelope/compression_test.go`

**Test coverage required:**
- Framing: WriteFrame/ReadFrame round-trip, max message size enforcement, empty message, large message near limit
- Envelope: Seal/Open round-trip, tampered ciphertext fails Open, wrong signing key fails Open, wrong encryption key fails Open, replay detection via cipher context
- Compression: Compress/Decompress round-trip, empty input, large input

### 2.3 Unit Tests for `pkg/platform`
**Files to create:**
- `pkg/platform/matrix_test.go`
- `pkg/platform/validation_test.go`

**Test coverage required:**
- Matrix: all 6 OS entries present, known arch capabilities correct, unknown OS/arch returns nil
- Validation: valid config passes, unsupported OS fails, unsupported arch fails, incompatible transport on platform, feature not available generates warning

### 2.4 Unit Tests for `pkg/audit`
**Files to create:**
- `pkg/audit/logger_test.go`
- `pkg/audit/export_test.go`

**Test coverage required:**
- Logger: sequential entries with hash chaining, PreviousHash of entry N == EntryHash of entry N-1, first entry has empty PreviousHash, concurrent writes are serialized
- Export: JSON format valid, CEF format valid, LEEF format valid, all fields populated

### 2.5 Unit Tests for `pkg/engagement`
**Files to create:**
- `pkg/engagement/scope_test.go`
- `pkg/engagement/safeguards_test.go`

**Test coverage required:**
- Scope: IP in CIDR matches, IP outside CIDR rejected, hostname exact match, domain suffix match, excluded target rejected even if in CIDR, invalid CIDR returns error
- TimeWindow: active within window, inactive before start, inactive after end
- Kill switch: activate/deactivate toggle, IsActive reflects state, CheckRemoteKillSwitch with fail-closed (unreachable = killed)
- DataQuota: within limit succeeds, exceeding limit fails, Remaining() accurate

### 2.6 Implant Runtime Skeleton
**Files to create:**
- `implant/runtime/config.go` — Implant configuration struct: server URLs, transport settings, sleep interval, jitter, kill date, implant ID, encryption keys
- `implant/runtime/runtime.go` — Main implant loop: init → register → task loop (fetch tasks, execute, return results) with jitter sleep. Must handle both session (persistent) and beacon (interval-based) modes
- `implant/runtime/register.go` — Registration handshake: collect system info (hostname, username, OS, arch, PID, process name), send Register message, receive config
- `implant/runtime/sysinfo.go` — Cross-platform system info collection with build tags: `sysinfo_windows.go`, `sysinfo_linux.go`, `sysinfo_darwin.go`, `sysinfo_default.go`

**Architecture notes:**
- Runtime uses `pkg/envelope` for all wire communication
- Runtime uses `pkg/crypto` for key exchange on first connect
- Session mode: persistent TCP connection, tasks streamed
- Beacon mode: periodic HTTP(S)/DNS check-in, tasks queued
- Kill date: implant self-terminates after configured expiry
- Kill switch: check remote endpoint each cycle, fail-closed

### 2.7 Implant Transport Interface
**Files to create:**
- `implant/transport/transport.go` — Transport interface definition:
  ```go
  type Transport interface {
      Connect(ctx context.Context) error
      Send(data []byte) error
      Recv() ([]byte, error)
      Close() error
      Name() string
  }
  ```
- `implant/transport/manager.go` — Transport manager with fallback chain: try transports in priority order, rotate on failure, backoff on repeated failures

## Dependencies
- `pkg/` modules must pass `go vet` (Phase 1 ✓)
- `testing` stdlib
- `github.com/stretchr/testify` for assertions (optional, stdlib `testing` is fine)

## Verification
```bash
go test ./pkg/... -v -count=1
go build ./implant/...
go vet ./implant/...
```
