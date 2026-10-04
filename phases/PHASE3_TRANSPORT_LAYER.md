# Phase 3: Transport Layer

## Status: NOT STARTED

## Objective
Implement all transport protocols for both server-side listeners and implant-side clients, with C2 profile support for traffic shaping.

## Tasks

### 3.1 mTLS Transport
**Server side — `server/c2/listener/mtls.go`:**
- TCP listener with mutual TLS 1.3
- Client certificate validation against CA
- Session registration on connect
- Bidirectional streaming for task dispatch/results
- Connection tracking per listener

**Implant side — `implant/transport/mtls/mtls.go`:**
- Implement `Transport` interface from Phase 2
- TLS dialer with embedded client cert + CA cert
- Persistent connection with reconnect logic
- Exponential backoff on connection failure

### 3.2 HTTPS Transport
**Server side — `server/c2/listener/https.go`:**
- HTTP/2 server with TLS
- Configurable URL paths for check-in, task fetch, task result, file upload/download
- Request/response body encryption with session key (envelope layer)
- Cookie or header-based session tracking
- Malleable C2 profile support: custom headers, URI patterns, response transforms

**Implant side — `implant/transport/https/https.go`:**
- Implement `Transport` interface
- HTTP client with configurable proxy support
- Chunked upload for large payloads
- User-Agent rotation from C2 profile
- Domain fronting support (configurable Host header vs SNI)

**C2 profile format — `server/c2/profile/profile.go`:**
```go
type C2Profile struct {
    Name        string
    HTTPConfig  HTTPProfileConfig
    DNSConfig   DNSProfileConfig
    Jitter      JitterConfig
}

type HTTPProfileConfig struct {
    GetPaths     []string   // URI paths for GET requests
    PostPaths    []string   // URI paths for POST requests
    Headers      map[string]string
    UserAgents   []string
    ServerHeaders map[string]string
    DataTransform string   // base64, hex, raw
}
```

### 3.3 DNS Transport
**Server side — `server/c2/listener/dns.go`:**
- Authoritative DNS server (UDP + TCP)
- Data encoding in TXT, CNAME, A, AAAA record responses
- Subdomain-based data exfiltration decoding
- Rate-aware to avoid DNS anomaly detection
- Configurable parent domain

**Implant side — `implant/transport/dns/dns.go`:**
- Implement `Transport` interface
- Data encoding in subdomain labels (max 63 chars per label, 253 total)
- Multiple record type support for responses
- Chunked data transfer with sequence numbers
- Configurable resolver (system default or custom)

**DNS encoding — `implant/transport/dns/encoding.go`:**
- Base32 encoding for subdomain data (DNS-safe charset)
- Chunk/reassemble logic with sequence IDs
- Max payload size calculation per query

### 3.4 WireGuard Transport
**Server side — `server/c2/listener/wireguard.go`:**
- WireGuard tunnel endpoint using `golang.zx2c4.com/wireguard`
- Dynamic peer management (add/remove implant peers)
- Tunnel wraps mTLS for inner authentication
- Key management integration with `pkg/crypto`

**Implant side — `implant/transport/wireguard/wireguard.go`:**
- Implement `Transport` interface
- Userspace WireGuard client
- Pre-shared key from build config
- Inner connection to server over tunnel

### 3.5 Pivot Transport
**Implant side — `implant/transport/pivot/pivot.go`:**
- Peer-to-peer communication between implants
- Named pipe transport (Windows)
- TCP relay (cross-platform)
- SMB transport (Windows)
- Allows implants without direct internet to route through a pivot implant

### 3.6 Transport Fallback Chain
**File: `implant/transport/manager.go`** (extend from Phase 2)
- Ordered list of transports to try
- Automatic failover: if primary transport fails, try next
- Configurable retry count and backoff per transport
- Health scoring: track success/failure rates, prefer healthy transports
- Re-promotion: periodically retry higher-priority transports

## Key Design Decisions
- All transports use `pkg/envelope` for encryption — transport layer only handles delivery
- Server listeners are engagement-scoped: each listener belongs to an engagement
- C2 profiles are stored in DB (`server/store/models.C2Profile`) and applied at listener start
- Transport selection at build time determines which transport code is compiled into the implant

## Dependencies
- Phase 1: `pkg/crypto`, `pkg/envelope` (DONE)
- Phase 2: `implant/transport/transport.go` interface
- External: `golang.zx2c4.com/wireguard` for WireGuard, `github.com/miekg/dns` for DNS server

## Verification
```bash
go build ./server/c2/...
go build ./implant/transport/...
go test ./server/c2/... -v
go test ./implant/transport/... -v
```

## Integration Test
- Start mTLS listener on server
- Connect implant with mTLS transport
- Send task, receive result
- Disconnect, verify reconnect
- Test fallback: block mTLS, verify HTTPS fallback
