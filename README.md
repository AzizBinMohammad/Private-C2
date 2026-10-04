# Private-C2

A full-featured Command and Control framework built in Go 1.23 for **authorized penetration testing engagements only**. Designed with safety-first architecture: engagement-scoped operations, fail-closed kill switches, append-only audit logging, and a dedicated OT/ICS assessment interface with hard read-only interlocks.

## Features

- **Multi-transport C2**: mTLS, HTTPS (with domain fronting), DNS, WireGuard, and peer-to-peer pivot
- **Engagement scoping**: CIDR, hostname, and domain-based scope enforcement with kill switch (fail-closed)
- **Cryptography**: XChaCha20-Poly1305 AEAD, X25519 key exchange, Ed25519 signing, ECDSA P-384 PKI
- **Cross-platform implant**: Windows, Linux, macOS, FreeBSD, OpenBSD, NetBSD across amd64/arm64/386
- **Build pipeline**: Server-side cross-compilation with configurable features, transports, and obfuscation
- **RBAC**: admin, operator, ot-operator, builder, observer roles with mTLS client certificate auth
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
# Generate CA and server certificates
./scripts/setup-ca.sh

# Add an operator
./scripts/add-operator.sh <operator-name>
```

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
