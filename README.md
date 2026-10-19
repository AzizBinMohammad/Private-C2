# Private-C2

A full-featured Command and Control framework built in Go 1.23 for **authorized penetration testing engagements only**. Designed with safety-first architecture: engagement-scoped operations, fail-closed kill switches, append-only audit logging, and a dedicated OT/ICS assessment interface with hard read-only interlocks.

## Features

- **C2 transport**: a live mTLS listener with protocol v2 negotiation; HTTPS, DNS, WireGuard, and pivot transport libraries exist but are not yet wired into the live listener path
- **Engagement scoping**: CIDR, hostname, and domain-based scope enforcement with an operational kill switch (closes sessions, blocks tasking)
- **Cryptography**: XChaCha20-Poly1305 AEAD, X25519 key exchange, Ed25519 signing, ECDSA P-384 PKI
- **Cross-platform implant**: Windows, Linux, macOS, FreeBSD, OpenBSD, NetBSD across amd64/arm64/386 (mTLS over CGO-free Go builds)
- **Durable state**: sessions, tasks, dispatches, and results persist to SQLite/PostgreSQL; queued tasks rebind after reconnect/restart
- **Background tasking**: bounded worker pool with per-task timeouts, panic recovery, output caps, and continued check-ins
- **Build pipeline**: server-side cross-compilation (payload configuration embedding is still in progress)
- **mTLS implant listener**: client certificates are required and verified against the engagement CA
- **RBAC**: admin, operator, ot-operator, builder, observer roles enforced on the REST API (`server/api/authz`)
- **OT/ICS assessment**: 17 industrial protocol clients (Modbus, OPC UA, S7, DNP3, etc.), all strictly read-only
- **Audit trail**: Append-only with SHA256 hash chaining, exportable as JSON/CEF/LEEF
- **Compliance**: IEC 62443, NIST SP 800-82, NERC CIP gap analysis
- **Deployment**: Docker, docker-compose, Makefile with cross-compile targets

## Quick Start

### Prerequisites

- Go 1.23+
- Docker and docker-compose (for containerized deployment)
- OpenSSL (for certificate generation)

### Build

```bash
# Build all binaries
make build

# Run tests
make test

# Build Docker image
make docker
```

### Setup Certificates

```bash
# Generate the CA plus the server and implant certificates
./scripts/setup-ca.sh

# Add an operator
./scripts/add-operator.sh <operator-name>
```

`setup-ca.sh` writes three certificate pairs into `certs/`:

| File | Purpose |
|---|---|
| `ca-cert.pem` / `ca-key.pem` | Root CA that signs everything else |
| `server-cert.pem` / `server-key.pem` | Server certificate for the implant listener |
| `implant-cert.pem` / `implant-key.pem` | Client certificate every implant presents |

Passing `--ca` to the server makes the implant listener **require** a client
certificate, and the implant must present one:

```bash
./bin/private-c2-server --cert certs/server-cert.pem --key certs/server-key.pem --ca certs/ca-cert.pem

./bin/implant --server <host>:4444 \
    --ca certs/ca-cert.pem \
    --cert certs/implant-cert.pem \
    --key certs/implant-key.pem
```

An implant given no `--ca` refuses to start rather than connecting
unauthenticated; `--insecure` disables server verification explicitly and is
for development only.

### Run with Docker

```bash
docker-compose up -d
```

### Run Locally

```bash
# Set environment variables
export PC2_DB_DIALECT=sqlite
export PC2_DB_DSN="file:pc2.db"
export PC2_TLS_CA_CERT=certs/ca.pem
export PC2_TLS_SERVER_CERT=certs/server.pem
export PC2_TLS_SERVER_KEY=certs/server-key.pem

# Start the server
go run ./cmd/server/...
```

### Connect as Operator

```bash
go run ./cmd/client/... connect --config operator-config.json
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full project structure, module breakdown, and design decisions.

## Safety Design

Every operation is scoped to an authorized engagement with:

- **Scope enforcement**: Targets validated against CIDR ranges, hostnames, and domain suffixes before any action
- **Kill switch**: Fail-closed design; if the server is unreachable, operations halt
- **Data quotas**: Configurable limits on data exfiltration volume
- **Time windows**: Operations restricted to engagement-approved time ranges
- **Audit trail**: Every action logged with cryptographic hash chaining for tamper detection

### OT/ICS Safety

The OT assessment interface has additional hard interlocks:

- Zero write function codes implemented for any industrial protocol
- No firmware modification, no process manipulation, no denial-of-service capabilities
- Dual authorization required (operator + OT safety contact)
- Rate limiting on all protocol queries (default 500ms inter-packet delay)
- Watchdog: auto-disconnect if server contact lost for >60 seconds
- Hidden from standard UI; requires `ot-operator` role

## Project Layout

```
Private-C2/
  go.work                    # Go 1.23 workspace (7 modules)
  pkg/                       # Shared libraries (crypto, envelope, platform, audit, engagement)
  server/                    # C2 server (gRPC API, listeners, build pipeline, store)
  client/                    # Operator CLI (console, commands, transport)
  implant/                   # Implant agent (runtime, modules, transports, evasion, safety)
  cmd/                       # Entry points (server, client, builder)
  proto/v1/                  # Protocol Buffer definitions
  tests/integration/         # Integration test stubs
  phases/                    # Development phase documentation
  scripts/                   # Setup and utility scripts
```

## Development

```bash
# Verify everything compiles
go build ./pkg/... ./server/... ./implant/... ./client/...

# Run unit tests
go test ./pkg/... -count=1

# Run vet
go vet ./pkg/... ./server/... ./implant/... ./client/...

# Cross-compile implant
make cross-compile
```

## Legal

This software is intended exclusively for authorized penetration testing, red team exercises, and security assessments conducted with explicit written permission from the system owner. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.
