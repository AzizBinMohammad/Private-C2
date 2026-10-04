# Phase 5: Build Pipeline & Payload Generation

## Status: NOT STARTED

## Objective
Build the cross-compilation pipeline that generates implant binaries for all supported platforms, with configurable features, transports, and output formats.

## Tasks

### 5.1 Build Configuration
**File: `server/build/config.go`**
- BuildConfig struct encompassing all build-time decisions:
  ```go
  type BuildConfig struct {
      TargetOS     string
      TargetArch   string
      Mode         string   // session, beacon
      Transports   []string // mtls, https, dns, wireguard
      Features     []string // shell, filesystem, process, network, screenshot
      Evasion      bool
      SafeMode     bool     // enable command allowlist
      Debug        bool
      C2Servers    []string // callback URLs/addresses
      Interval     time.Duration // beacon check-in interval
      Jitter       float64 // jitter percentage 0.0-1.0
      KillDate     *time.Time
      ImplantID    string
      OutputFormat string // exe, dll, shellcode, shared
  }
  ```
- Validate config against `pkg/platform` matrix before building

### 5.2 Build Stages
**File: `server/build/stages/configure.go`**
- Generate implant config source file from BuildConfig
- Embed crypto keys (X25519 public key, server CA cert) into implant binary
- Set build tags based on selected features and transports
- Generate unique implant ID

**File: `server/build/stages/compile.go`**
- Cross-compile implant using `go build` with appropriate GOOS/GOARCH
- Build tag selection: `-tags "transport_mtls,transport_https,mod_shell,mod_fs"`
- CGO handling: disable for pure-Go builds, enable for Windows syscall modules
- Strip debug info: `-ldflags "-s -w"` for release builds
- Output to temp directory

**File: `server/build/stages/postprocess.go`**
- Output format transformations:
  - `exe` — Standalone executable (default)
  - `dll` — Windows DLL with DllMain export
  - `shellcode` — Convert PE to position-independent shellcode (Windows, using donut-style transform)
  - `shared` — Shared library (.so/.dylib)
- Binary signing (optional): sign with operator's key for attribution

**File: `server/build/stages/obfuscate.go`**
- String encryption: encrypt string literals, decrypt at runtime
- Symbol renaming: randomize exported symbol names
- Import table obfuscation (Windows PE)
- NOTE: Assessment-grade obfuscation for testing detection capabilities, not for evading production security

### 5.3 Build Queue
**File: `server/build/queue/queue.go`**
- Concurrent build queue with configurable parallelism (default: NumCPU)
- Job tracking: pending, building, completed, failed
- Build artifact storage: completed binaries stored in DB (PayloadArtifact model)
- SHA256 hash of every artifact for integrity verification
- Build log capture for debugging

**File: `server/build/queue/worker.go`**
- Worker goroutine: pull from queue, execute build stages, store result
- Timeout per build (default: 5 minutes)
- Cleanup temp files after build

### 5.4 Staging Server
**File: `server/build/stages/stager.go`**
- Generate small stager payloads that download and execute the full implant
- HTTP/S stager: download from staging URL, execute in memory
- DNS stager: reassemble payload from DNS TXT records
- Stager binary is minimal: just download + execute, no modules

### 5.5 Build API Integration
**Extend: `server/api/grpc/operator.go`**
- `GeneratePayload` RPC handler: validate config, enqueue build, return job ID
- `GetBuildStatus` — poll build job status
- `DownloadPayload` — retrieve completed artifact by ID

**Extend: `server/store/repository/` — add:**
- `payloads.go` — PayloadArtifact repository: create, get by ID, get by SHA256, list by engagement, delete

### 5.6 Implant Build Tags
**Update all `implant/` source files with build tags:**
- Transport selection: `//go:build transport_mtls`, `transport_https`, `transport_dns`, `transport_wireguard`
- Module selection: `//go:build mod_shell`, `mod_filesystem`, `mod_process`, `mod_network`, `mod_screenshot`
- Evasion: `//go:build evasion`
- Platform: existing GOOS/GOARCH tags

## Key Design Decisions
- Build happens server-side — operators submit config via gRPC, server compiles
- Every build generates a unique implant ID and fresh crypto keys
- Build artifacts are engagement-scoped — PayloadArtifact links to engagement
- Stager payloads use the same transport as the full implant
- Build queue prevents resource exhaustion from parallel compilation

## Dependencies
- Phase 1: `pkg/platform` for validation, `pkg/crypto` for key generation, `server/store` for artifact storage (DONE)
- Phase 4: Implant source code with build tags must exist

## Verification
```bash
# Build the builder itself
go build -o /tmp/pc2-builder ./cmd/builder/...

# Test cross-compilation
GOOS=linux GOARCH=amd64 go build -tags "transport_mtls,mod_shell" ./implant/...
GOOS=windows GOARCH=amd64 go build -tags "transport_https,mod_shell,mod_filesystem" ./implant/...
GOOS=darwin GOARCH=arm64 go build -tags "transport_mtls,mod_shell" ./implant/...

# Test build queue
go test ./server/build/... -v
```
