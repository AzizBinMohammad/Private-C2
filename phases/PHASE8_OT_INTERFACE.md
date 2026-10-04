# Phase 8: Covert OT/ICS Assessment Interface

## Status: NOT STARTED

## Classification: HIDDEN INTERFACE
This module is isolated from the main C2 UI surface. It is accessible only through a separate authentication gate (OT-operator role + engagement with OT scope authorization). The interface does not appear in standard command listings, help output, or tab completion unless the operator holds the `ot.assess` permission.

## Objective
Provide a dedicated, safety-constrained interface for assessing Operational Technology (OT) and Industrial Control System (ICS) environments during authorized engagements. Assessment-only — no write commands to PLCs, RTUs, or safety systems. Read-only reconnaissance and protocol analysis with hard safety interlocks.

## Safety Architecture

### Hard Interlocks (cannot be overridden)
1. **No write to safety systems** — SIS (Safety Instrumented Systems), SIL-rated controllers, and any device tagged `safety-critical` in scope config are READ-ONLY, permanently
2. **No firmware modification** — firmware upload/flash commands are not implemented
3. **No denial-of-service** — no flood, fuzz, or stress commands against OT targets
4. **Rate limiting** — all OT protocol queries enforce configurable inter-packet delay (default 500ms) to avoid disrupting real-time control loops
5. **Kill switch integration** — OT operations halt immediately on engagement kill switch
6. **Dual authorization** — OT tasks require approval from both the operator AND the engagement's designated OT safety contact before execution

### Soft Constraints (configurable per engagement)
- Maximum concurrent OT connections (default: 1)
- Protocol query timeout (default: 5s, max: 30s)
- Scan rate limit (default: 1 target/second)
- Data collection level for OT (default: metadata-only, no process values)

## Directory Structure
```
implant/modules/ot/
  ot.go              — OT module interface, safety interlocks, dual-auth gate
  discovery.go       — Passive and active OT asset discovery
  protocols/
    modbus.go        — Modbus TCP/RTU read-only client
    opcua.go         — OPC UA read-only client
    s7comm.go        — Siemens S7Comm read-only client
    dnp3.go          — DNP3 read-only client
    ethernetip.go    — EtherNet/IP (CIP) read-only client
    bacnet.go        — BACnet read-only client
    common.go        — Shared protocol types, response parsing
  fingerprint.go     — OT device fingerprinting from protocol responses
  topology.go        — Network topology mapping for OT segments

server/api/grpc/ot.go          — OT-specific gRPC service (hidden from standard service listing)
server/api/middleware/ot_auth.go — OT dual-authorization middleware
server/store/models/ot.go      — OT asset, scan result, topology models
server/store/repository/ot.go  — OT data access layer

client/cli/commands/ot.go      — OT console commands (hidden unless ot.assess permission)

proto/v1/ot.proto              — OT-specific protobuf definitions
```

## Tasks

### 8.1 OT Safety Module
**File: `implant/modules/ot/ot.go`**
```go
type OTConfig struct {
    MaxConcurrentConns int
    QueryTimeoutMs     int
    ScanRatePerSec     float64
    InterPacketDelayMs int
    DataLevel          string // "metadata", "config", "values"
    SafetyCriticalTags []string
    DualAuthRequired   bool
}

type OTModule struct {
    config     OTConfig
    safetyLock sync.Mutex
    activeConns int
    killSwitch *engagement.KillSwitch
}

func (m *OTModule) PreFlightCheck(target string, protocol string) error
func (m *OTModule) IsSafetyCritical(target string) bool
func (m *OTModule) AcquireConnection() error
func (m *OTModule) ReleaseConnection()
```
- Every OT operation goes through `PreFlightCheck` which validates:
  1. Target is in engagement OT scope
  2. Target is not tagged safety-critical (for anything beyond passive discovery)
  3. Kill switch is not active
  4. Connection limit not exceeded
  5. Dual authorization token is valid (if required)

### 8.2 OT Asset Discovery
**File: `implant/modules/ot/discovery.go`**

**Passive discovery (network sniffing, no packets sent):**
- Listen for Modbus TCP on port 502
- Listen for EtherNet/IP on port 44818
- Listen for S7Comm on port 102
- Listen for BACnet on port 47808
- Listen for OPC UA on port 4840
- Listen for DNP3 on port 20000
- Parse broadcast/multicast: BACnet Who-Is, EtherNet/IP ListIdentity
- Collect: IP, MAC, protocol, vendor, device type

**Active discovery (rate-limited, scope-checked):**
- Port scan for known OT ports (scope-checked against OT scope)
- Protocol identification probes (single lightweight query per port)
- Banner grabbing with timeout

**Output: `OTAsset` struct:**
```go
type OTAsset struct {
    IP           string
    MAC          string
    Hostname     string
    Vendor       string
    Model        string
    Firmware     string
    Protocol     string
    Role         string // PLC, HMI, RTU, historian, engineering workstation
    SafetyRated  bool
    Ports        []int
    LastSeen     time.Time
    DiscoveryMethod string // passive, active
}
```

### 8.3 Modbus Read-Only Client
**File: `implant/modules/ot/protocols/modbus.go`**
- Read Coils (FC 01) — read-only
- Read Discrete Inputs (FC 02) — read-only
- Read Holding Registers (FC 03) — read-only
- Read Input Registers (FC 04) — read-only
- Read Device Identification (FC 43/14) — read-only
- **NOT implemented:** Write Single Coil (FC 05), Write Single Register (FC 06), Write Multiple Coils (FC 15), Write Multiple Registers (FC 16)
- Unit ID enumeration (scan unit IDs 1-247)
- Inter-packet delay enforcement

### 8.4 OPC UA Read-Only Client
**File: `implant/modules/ot/protocols/opcua.go`**
- GetEndpoints — discover server capabilities and security policies
- Browse — walk the address space tree (read-only)
- Read — read node attributes and values (if DataLevel permits)
- FindServers — discover OPC UA servers on network
- **NOT implemented:** Write, Call (method invocation), CreateSubscription for writes
- Security policy detection: None, Basic128Rsa15, Basic256, Basic256Sha256
- Authentication mode detection: Anonymous, Username, Certificate

### 8.5 S7Comm Read-Only Client
**File: `implant/modules/ot/protocols/s7comm.go`**
- Connection setup (COTP + S7 negotiation)
- Read SZL (System Status List) — hardware/firmware info, diagnostic buffers
- Read DB (Data Blocks) — read-only if DataLevel permits
- CPU state query (RUN/STOP/unknown)
- Module identification
- **NOT implemented:** Write DB, PLC Start/Stop, Download blocks, firmware operations
- Protection level detection (1-4)

### 8.6 DNP3 Read-Only Client
**File: `implant/modules/ot/protocols/dnp3.go`**
- Data link layer framing
- Read Class 0/1/2/3 data (poll)
- Device attribute queries
- Internal Indication (IIN) bit parsing
- **NOT implemented:** Direct Operate, Select-Before-Operate, Freeze, Cold/Warm Restart
- Unsolicited response handling

### 8.7 EtherNet/IP Read-Only Client
**File: `implant/modules/ot/protocols/ethernetip.go`**
- ListIdentity — device identification broadcast
- ListServices — available services
- RegisterSession / UnregisterSession
- CIP: Get_Attribute_Single, Get_Attribute_All (read-only)
- Identity object: vendor, product name, serial, firmware revision
- **NOT implemented:** Set_Attribute, Forward_Open for I/O, CIP write services

### 8.8 BACnet Read-Only Client
**File: `implant/modules/ot/protocols/bacnet.go`**
- Who-Is / I-Am for device discovery
- ReadProperty / ReadPropertyMultiple (read-only)
- Device object: vendor, model, firmware, application software version
- Object list enumeration
- **NOT implemented:** WriteProperty, SubscribeCOV, ReinitializeDevice

### 8.9 Device Fingerprinting
**File: `implant/modules/ot/fingerprint.go`**
- Correlate protocol responses to identify specific device models
- Vendor identification from MAC OUI + protocol-level vendor fields
- Firmware version extraction
- Known vulnerability mapping (CVE lookup by vendor/model/firmware — reference only, no exploitation)
- MITRE ATT&CK for ICS technique mapping

### 8.10 Topology Mapping
**File: `implant/modules/ot/topology.go`**
- Build network topology from discovered assets
- Identify: DMZ boundaries, IT/OT boundary devices, dual-homed hosts
- Layer mapping: Enterprise → DMZ → Control → Field/Safety (Purdue model)
- Export as JSON graph for visualization
- Identify segmentation gaps (OT devices reachable from IT network)

### 8.11 OT gRPC Service (Hidden)
**File: `server/api/grpc/ot.go`**
```go
type OTServer struct {
    // not registered in standard service reflection
}

// RPCs:
// DiscoverOTAssets — passive + active discovery
// ScanModbus — Modbus read operations
// ScanOPCUA — OPC UA browse/read
// ScanS7 — S7Comm read operations
// ScanDNP3 — DNP3 poll
// ScanEtherNetIP — EtherNet/IP identity + CIP read
// ScanBACnet — BACnet discovery + read
// GetOTTopology — retrieve topology map
// ListOTAssets — list discovered assets
```
- Service registered only when engagement has `ot_authorized: true`
- Service not included in gRPC reflection (hidden from service enumeration)
- All RPCs require `ot.assess` permission

### 8.12 OT Dual-Authorization Middleware
**File: `server/api/middleware/ot_auth.go`**
- OT operations require two-factor authorization:
  1. Operator's RBAC role includes `ot.assess` permission
  2. A separate OT authorization token issued by the engagement's OT safety contact
- Token is time-limited (default: 1 hour)
- Token is scope-limited to specific OT targets
- Token generation requires out-of-band confirmation (not automatable)

### 8.13 OT Data Models
**File: `server/store/models/ot.go`**
```go
type OTAssetRecord struct {
    Base
    EngagementID string
    IP           string
    MAC          string
    Vendor       string
    Model        string
    Firmware     string
    Protocol     string
    Role         string
    SafetyRated  bool
    PurdueLevel  int
    FirstSeen    time.Time
    LastSeen     time.Time
    RawData      string // JSON protocol responses
}

type OTScanResult struct {
    Base
    EngagementID string
    AssetID      string
    Protocol     string
    Operation    string
    ResponseData string // JSON
    OperatorID   string
    AuthToken    string
}

type OTTopology struct {
    Base
    EngagementID string
    GraphJSON    string // JSON adjacency graph
    PurdueMap    string // JSON Purdue level assignments
    Gaps         string // JSON segmentation findings
}
```

### 8.14 OT Console Commands (Hidden)
**File: `client/cli/commands/ot.go`**
- Commands are NOT registered in standard help/tab-completion
- Activated only after `ot-mode` command with valid OT auth token
- Commands:
  - `ot-discover [--passive] [--active]` — asset discovery
  - `ot-scan modbus <target> [--unit-ids 1-10]` — Modbus enumeration
  - `ot-scan opcua <target>` — OPC UA browse
  - `ot-scan s7 <target>` — S7Comm identification
  - `ot-scan dnp3 <target>` — DNP3 poll
  - `ot-scan enip <target>` — EtherNet/IP identity
  - `ot-scan bacnet <target>` — BACnet discovery
  - `ot-topology` — show discovered topology
  - `ot-assets` — list discovered assets
  - `ot-exit` — leave OT mode, lock OT commands

### 8.15 OT Protobuf Definitions
**File: `proto/v1/ot.proto`**
- OTAsset, OTScanRequest, OTScanResponse messages
- OTTopology message with Purdue level mapping
- OTService with all scan/discover RPCs
- OTAuthToken for dual-authorization

## RBAC Extension

Add to existing role permissions in `server/api/middleware/rbac.go`:
```go
PermOTAssess Permission = "ot.assess"

// Only admin can grant OT access
"admin": { ..., PermOTAssess },
// New role specifically for OT operators
"ot-operator": {
    PermSessionRead, PermSessionWrite,
    PermListenerRead, PermEngagementManage,
    PermAuditRead, PermOTAssess,
},
```

## Audit Requirements
- Every OT protocol query logged with: target, protocol, function code, response summary
- OT scan sessions logged as a group with correlation ID
- Safety interlock denials logged as critical events
- Dual-auth token usage logged with issuer and scope

## Dependencies
- Phase 1: `pkg/engagement` scope/kill switch, `server/store`, middleware (DONE)
- Phase 2: Implant runtime skeleton
- Phase 3: At least one transport working
- Phase 4: Task execution engine
- External: protocol libraries or raw TCP/UDP implementations
  - Modbus: `github.com/goburrow/modbus` or raw TCP
  - OPC UA: `github.com/gopcua/opcua`
  - BACnet: raw UDP implementation
  - S7Comm/DNP3/EtherNet/IP: raw TCP implementations (no mature Go libs)

## Verification
```bash
go build ./implant/modules/ot/...
go test ./implant/modules/ot/... -v
go build ./server/api/grpc/...
go vet ./implant/modules/ot/...

# Integration test with OT simulator:
# 1. Start ModRSsim2 or similar Modbus simulator
# 2. Run ot-discover --active against simulator subnet
# 3. Run ot-scan modbus against simulator
# 4. Verify read-only: attempt write → hard interlock blocks
# 5. Verify dual-auth: scan without OT token → rejected
# 6. Verify kill switch: activate → all OT ops halt
```

## Key Constraint
This entire module tree is ASSESSMENT-ONLY. There are zero write, control, or modify operations implemented for any OT protocol. The purpose is to map OT environments and identify exposure during authorized engagements — never to disrupt or control industrial processes.
