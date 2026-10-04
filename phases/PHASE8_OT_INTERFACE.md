# Phase 8: Covert OT/ICS Assessment Interface

## Status: NOT STARTED

## Classification: HIDDEN INTERFACE
This module is isolated from the main C2 UI surface. It is accessible only through a separate authentication gate (OT-operator role + engagement with OT scope authorization). The interface does not appear in standard command listings, help output, or tab completion unless the operator holds the `ot.assess` permission.

## Objective
Provide a complete, safety-constrained OT/ICS penetration testing interface for authorized engagements. Covers the full OT pentest lifecycle: reconnaissance, asset discovery, protocol interrogation, credential assessment, vulnerability identification, network segmentation analysis, wireless assessment, historian/SCADA evaluation, PLC logic review, compliance gap analysis, and structured reporting — all read-only with hard safety interlocks.

## Safety Architecture

### Hard Interlocks (cannot be overridden, enforced at code level)
1. **No write to any OT controller** — SIS, SIL-rated, PLC, RTU, DCS controllers are permanently READ-ONLY. No function codes that alter state, setpoints, or outputs are implemented
2. **No firmware modification** — firmware upload, flash, or download-to-PLC commands do not exist in the codebase
3. **No denial-of-service** — no flood, fuzz, stress, or replay-attack commands against OT targets
4. **No process manipulation** — no commands to start/stop/reset PLCs, change operating modes, or alter control logic
5. **Rate limiting** — all OT protocol queries enforce configurable inter-packet delay (default 500ms) to avoid disrupting real-time control loops
6. **Kill switch integration** — OT operations halt immediately on engagement kill switch, all connections gracefully closed
7. **Dual authorization** — OT tasks require approval from both the operator AND the engagement's designated OT safety contact before execution
8. **Watchdog** — if implant loses contact with server for >60s during OT operations, all OT connections are closed automatically

### Soft Constraints (configurable per engagement)
- Maximum concurrent OT connections (default: 1)
- Protocol query timeout (default: 5s, max: 30s)
- Scan rate limit (default: 1 target/second)
- Data collection level for OT (default: metadata-only, no process values)
- Credential testing mode (default: off, requires explicit per-engagement flag)
- Traffic capture duration limit (default: 5 minutes)
- Maximum PCAP file size (default: 50MB)

---

## Directory Structure
```
implant/modules/ot/
  ot.go                    — OT module interface, safety interlocks, dual-auth gate, watchdog
  discovery.go             — Passive and active OT asset discovery
  capture.go               — OT protocol traffic capture and decode
  protocols/
    common.go              — Shared protocol types, response parsing, protocol detection
    modbus.go              — Modbus TCP/RTU read-only client
    opcua.go               — OPC UA read-only client
    s7comm.go              — Siemens S7Comm/S7CommPlus read-only client
    dnp3.go                — DNP3 read-only client
    ethernetip.go          — EtherNet/IP (CIP) read-only client
    bacnet.go              — BACnet read-only client
    iec104.go              — IEC 60870-5-104 read-only client
    iec61850.go            — IEC 61850 MMS read-only client
    profinet.go            — PROFINET DCP discovery + read-only
    hart.go                — HART-IP read-only client
    mqtt.go                — MQTT broker enumeration and topic sniffing
    coap.go                — CoAP resource discovery
    fins.go                — Omron FINS read-only client
    melsec.go              — Mitsubishi MELSEC read-only client
    pcworx.go              — Phoenix Contact PC Worx read-only
    crimson.go             — Red Lion Crimson read-only
  fingerprint.go           — OT device fingerprinting from protocol responses
  topology.go              — Purdue model network topology mapping
  credentials.go           — Default/weak credential assessment (read-only auth probes)
  vulnscan.go              — Known vulnerability identification (CVE mapping, no exploitation)
  segmentation.go          — IT/OT network segmentation analysis
  wireless.go              — OT wireless protocol detection
  historian.go             — Historian/SCADA server assessment
  hmi.go                   — HMI web interface assessment
  plclogic.go              — PLC program logic read-only analysis
  serial.go                — Serial port and field bus enumeration
  compliance.go            — IEC 62443 / NIST 800-82 / NERC CIP gap analysis
  reporting.go             — OT-specific assessment report generation

server/api/grpc/ot.go              — OT-specific gRPC service (hidden from service reflection)
server/api/middleware/ot_auth.go    — OT dual-authorization middleware + watchdog
server/store/models/ot.go          — OT asset, scan, credential, vuln, topology models
server/store/repository/ot.go      — OT data access layer

client/cli/commands/ot.go          — OT console commands (hidden unless ot.assess permission)

proto/v1/ot.proto                  — OT-specific protobuf definitions
```

---

## Tasks

### 8.1 OT Safety Module & Watchdog
**File: `implant/modules/ot/ot.go`**
```go
type OTConfig struct {
    MaxConcurrentConns   int
    QueryTimeoutMs       int
    ScanRatePerSec       float64
    InterPacketDelayMs   int
    DataLevel            string   // "metadata", "config", "values"
    SafetyCriticalTags   []string
    DualAuthRequired     bool
    CredentialTestingOn  bool
    WatchdogTimeoutSec   int      // auto-close OT conns if server contact lost
    CaptureMaxDuration   time.Duration
    CaptureMaxBytes      int64
}

type OTModule struct {
    config       OTConfig
    safetyLock   sync.Mutex
    activeConns  int
    killSwitch   *engagement.KillSwitch
    scope        *engagement.Scope
    watchdog     *OTWatchdog
    auditChan    chan OTAuditEvent
    connTracker  map[string]*OTConnection // target → connection
}

type OTWatchdog struct {
    lastServerContact time.Time
    timeout           time.Duration
    shutdownFunc      func() // closes all OT connections
}

func (m *OTModule) PreFlightCheck(target, protocol string) error
func (m *OTModule) IsSafetyCritical(target string) bool
func (m *OTModule) AcquireConnection(target string) (*OTConnection, error)
func (m *OTModule) ReleaseConnection(target string)
func (m *OTModule) EmergencyShutdown()  // close all OT connections immediately
func (m *OTModule) WatchdogTick()       // called by runtime loop
```
- `PreFlightCheck` validates before every OT operation:
  1. Target is in engagement OT scope
  2. Target is not tagged safety-critical (for anything beyond passive discovery)
  3. Kill switch is not active
  4. Connection limit not exceeded
  5. Dual authorization token is valid and not expired
  6. Watchdog has not triggered
  7. Engagement time window is active
- `EmergencyShutdown` gracefully closes all OT protocol connections, called by watchdog and kill switch

---

### 8.2 OT Asset Discovery
**File: `implant/modules/ot/discovery.go`**

**Passive discovery (network sniffing, zero packets sent):**
- Listen on all known OT ports simultaneously:
  - Modbus TCP: 502
  - EtherNet/IP: 44818, 2222
  - S7Comm: 102
  - BACnet: 47808
  - OPC UA: 4840
  - DNP3: 20000
  - IEC 104: 2404
  - IEC 61850 MMS: 102 (TPKT/COTP)
  - PROFINET DCP: UDP 34964
  - HART-IP: 5094
  - MQTT: 1883, 8883
  - Omron FINS: 9600
  - Mitsubishi MELSEC: 5007
  - CoAP: 5683
  - Modbus RTU over TCP: 502 (detect RTU framing)
- Parse broadcast/multicast traffic: BACnet Who-Is/I-Am, EtherNet/IP ListIdentity, PROFINET DCP Identify, LLDP, mDNS
- ARP table passive collection for MAC → IP mapping
- Detect OT vendor OUIs (Siemens, Rockwell, Schneider, ABB, Honeywell, Emerson, Yokogawa, GE, Mitsubishi, Omron, Phoenix Contact, WAGO, Beckhoff, Moxa, SEL)
- Duration-configurable capture window

**Active discovery (rate-limited, scope-checked):**
- Port scan for all known OT ports (scope-checked)
- Protocol identification probes: single lightweight read query per port to confirm protocol
- Banner grabbing: HTTP, Telnet, SSH, FTP on OT devices
- SNMP community string probe (read-only, `public`/`private` + configurable list)
- NetBIOS/SMB enumeration for Windows-based HMIs and historians
- DNS zone transfer attempt for OT DNS zones
- mDNS/DNS-SD service discovery

**ARP/Neighbor discovery:**
- Gratuitous ARP detection (duplicate IP, possible MitM indicators)
- IPv6 neighbor solicitation in OT segments

**Output: `OTAsset` struct:**
```go
type OTAsset struct {
    IP              string
    MAC             string
    MACVendor       string    // OUI lookup result
    Hostname        string
    FQDN            string
    Vendor          string    // device vendor (from protocol)
    Model           string
    SerialNumber    string
    Firmware        string
    HardwareRev     string
    Protocol        []string  // all protocols detected
    Role            string    // PLC, HMI, RTU, DCS, historian, EWS, gateway, switch, firewall, IO-module, drive, relay
    SafetyRated     bool
    SILLevel        int       // 0-4, 0 = not safety
    PurdueLevel     int       // 0-5 per Purdue model
    Ports           []PortInfo
    Services        []string
    OSFingerprint   string
    LastSeen        time.Time
    FirstSeen       time.Time
    DiscoveryMethod string    // passive, active, protocol-probe
    NetworkSegment  string    // detected subnet/VLAN
    GatewayIP       string
    Vulnerabilities []VulnRef // CVE references from fingerprint
}

type PortInfo struct {
    Port     int
    Protocol string
    State    string
    Banner   string
    Service  string
}
```

---

### 8.3 Protocol Clients (All Read-Only)

#### 8.3.1 Modbus TCP/RTU
**File: `implant/modules/ot/protocols/modbus.go`**
- **Implemented (read-only):**
  - FC 01: Read Coils
  - FC 02: Read Discrete Inputs
  - FC 03: Read Holding Registers
  - FC 04: Read Input Registers
  - FC 07: Read Exception Status
  - FC 08: Diagnostics (sub-function 00: Return Query Data — echo test only)
  - FC 11: Get Comm Event Counter
  - FC 12: Get Comm Event Log
  - FC 17: Report Server ID
  - FC 43/14: Read Device Identification (basic, regular, extended)
  - FC 43/13: CANopen General Reference (read-only)
- **NOT implemented (writes/control):** FC 05, 06, 15, 16, 22, 23
- Unit ID enumeration: scan IDs 1-247 with configurable range
- Modbus RTU over TCP detection and parsing
- Register data type interpretation: INT16, UINT16, INT32, UINT32, FLOAT32, STRING
- Exception code decoding (illegal function, address, value, failure, acknowledge, busy)
- Inter-packet delay enforcement (configurable, default 500ms)
- Connection reuse with keepalive

#### 8.3.2 OPC UA
**File: `implant/modules/ot/protocols/opcua.go`**
- GetEndpoints — discover security policies and authentication modes
- FindServers — discover OPC UA servers via LDS
- Browse — walk the full address space tree (read-only)
- Read — read node attributes, values, timestamps (if DataLevel permits)
- TranslateBrowsePathsToNodeIds — resolve paths to node IDs
- **Security assessment:**
  - Detect servers accepting SecurityPolicy None (critical finding)
  - Detect Anonymous authentication enabled
  - Detect self-signed certificates
  - Enumerate user identity tokens
  - Test if encryption is required vs optional
- **NOT implemented:** Write, Call, CreateMonitoredItems for writes, HistoryUpdate, AddNodes, DeleteNodes
- Node class enumeration: Variable, Object, Method, View, ObjectType, VariableType
- Extract server certificate for analysis

#### 8.3.3 Siemens S7Comm / S7CommPlus
**File: `implant/modules/ot/protocols/s7comm.go`**
- COTP connection setup (CR/CC)
- S7 communication setup (negotiate PDU size)
- **Read-only operations:**
  - SZL (System Status List) read — full SZL ID enumeration:
    - 0x0011: Module identification
    - 0x001C: Component identification (name, serial, version)
    - 0x0019: Module status
    - 0x0014: Diagnostic buffer
    - 0x0074: CPU status (RUN/STOP)
    - 0x0222: Module protection level
    - 0x0132: Communication parameters
  - Read DB/M/I/Q/T/C areas (data blocks, flags, inputs, outputs, timers, counters) — read-only, DataLevel-gated
- CPU protection level detection (levels 1-4, keyswitch state)
- PLC name and location extraction
- Detect S7CommPlus (V17+ TIA Portal) vs legacy S7Comm
- Detect if CPU password is set / complexity
- **NOT implemented:** Write, PLC Start/Stop, Download/Upload blocks, PI services, firmware operations

#### 8.3.4 DNP3
**File: `implant/modules/ot/protocols/dnp3.go`**
- Data link layer framing (FT3, CRC validation)
- Transport function reassembly
- Application layer parsing
- **Read-only operations:**
  - Read Class 0/1/2/3 data (integrity poll, event poll)
  - Read specific object groups/variations
  - Device attributes (Group 0)
  - Internal Indications (IIN) bit parsing
  - Time synchronization detection (read-only: detect if time sync is used, don't send)
- **Security assessment:**
  - Detect DNP3 Secure Authentication (SA) version
  - Detect if SA is enabled or disabled (critical if disabled)
  - Challenge/response mechanism detection
  - Aggressive mode detection
- **NOT implemented:** Direct Operate, Select-Before-Operate, Freeze, Cold/Warm Restart, Assign Class, Write, Enable/Disable Unsolicited
- Unsolicited response passive capture

#### 8.3.5 EtherNet/IP (CIP)
**File: `implant/modules/ot/protocols/ethernetip.go`**
- ListIdentity — device identification (vendor, product, serial, firmware)
- ListServices — available services enumeration
- ListInterfaces — network interface listing
- RegisterSession / UnregisterSession
- **CIP read-only services:**
  - Get_Attribute_Single / Get_Attribute_All on:
    - Identity Object (0x01)
    - Message Router (0x02)
    - Connection Manager (0x06)
    - Port Object (0x0B) — network port info
    - TCP/IP Object (0xF5) — IP configuration
    - Ethernet Link Object (0xF6)
  - Get_Attribute_List for bulk reads
- Rockwell-specific: read controller properties, module info, tag listing
- **NOT implemented:** Set_Attribute, Forward_Open for I/O, any CIP write or control services
- PCCC (legacy DF1) read-only detection

#### 8.3.6 BACnet
**File: `implant/modules/ot/protocols/bacnet.go`**
- Who-Is / I-Am broadcast discovery
- Who-Has / I-Have for object discovery
- ReadProperty / ReadPropertyMultiple (read-only)
- **Object enumeration:**
  - Device object: vendor, model, firmware, app version, protocol version
  - Analog/Binary/MultiState Input/Output/Value objects
  - Schedule, Calendar, Trend Log objects
  - Network Port objects
- Object list full walk
- Supported services detection
- **Security assessment:**
  - Detect if authentication (BACnet SC) is enabled
  - Detect BBMD (BACnet Broadcast Management Device) configuration
  - Foreign device registration detection
- **NOT implemented:** WriteProperty, CreateObject, DeleteObject, SubscribeCOV, ReinitializeDevice, DeviceCommunicationControl

#### 8.3.7 IEC 60870-5-104
**File: `implant/modules/ot/protocols/iec104.go`**
- APCI (Application Protocol Control Information) handling
- STARTDT / TESTFR activation
- **Read-only ASDUs (Application Service Data Units):**
  - Type 1-21: Monitoring direction (process information from RTU)
  - Type 100: Interrogation command (general interrogation — read-only poll)
  - Type 103: Clock synchronization (read time only)
- Cause of Transmission parsing
- Originator address detection
- **Security assessment:**
  - IEC 62351 security extension detection
  - Detect if TLS is used on the transport
- **NOT implemented:** Type 45-69 (control direction commands), any setpoint or control

#### 8.3.8 IEC 61850 MMS
**File: `implant/modules/ot/protocols/iec61850.go`**
- TPKT/COTP/MMS connection establishment
- MMS Initiate service
- **Read-only operations:**
  - GetNameList — enumerate logical devices, datasets, logs
  - GetVariableAccessAttributes — read data model structure
  - Read — read named variables, datasets (DataLevel-gated)
  - GetServerDirectory
  - GetLogicalDeviceDirectory
  - GetLogicalNodeDirectory
- SCL (Substation Configuration Language) model extraction
- GOOSE (Generic Object Oriented Substation Event) passive capture
- Sampled Values (SV) passive capture
- **NOT implemented:** Write, Control (Operate/Select/Cancel), Define/DeleteNamedVariableList, reporting writes

#### 8.3.9 PROFINET
**File: `implant/modules/ot/protocols/profinet.go`**
- PROFINET DCP (Discovery and Configuration Protocol):
  - Identify request/response (device discovery)
  - Read device name, IP, vendor, role
- LLDP frame parsing for PROFINET extensions
- PROFINET IO connection detection (passive only)
- GSD (General Station Description) file identification
- **Security assessment:**
  - Detect if PROFINET security (per IEC 62443) is enabled
  - Detect unauthorized DCP Set operations (passive)
- **NOT implemented:** DCP Set (IP, name), PROFINET IO write, parameter write

#### 8.3.10 HART-IP
**File: `implant/modules/ot/protocols/hart.go`**
- HART-IP session establishment
- **Read-only commands:**
  - Command 0: Read Unique Identifier
  - Command 1: Read Primary Variable
  - Command 2: Read Loop Current and Percent of Range
  - Command 3: Read Dynamic Variables and Primary Variable Current
  - Command 12: Read Message
  - Command 13: Read Tag, Descriptor, Date
  - Command 14: Read Primary Variable Transducer Information
  - Command 15: Read Device Information
  - Command 48: Read Additional Device Status
- Device identification from manufacturer/device type codes
- **NOT implemented:** Any command that writes configuration or calibration data

#### 8.3.11 MQTT Broker Assessment
**File: `implant/modules/ot/protocols/mqtt.go`**
- Connect with Anonymous / no auth to detect open brokers
- Detect MQTT version (3.1.1, 5.0)
- Topic enumeration via `$SYS/#` subscription (read-only, broker stats)
- Wildcard subscription `#` to enumerate active topics (passive listen only)
- **Security assessment:**
  - Anonymous access detection (critical in OT)
  - TLS vs plaintext detection
  - Detect if authentication is required
  - Detect if ACLs are enforced (try subscribing to `$SYS/+` vs `#`)
  - MQTT 5.0 enhanced auth detection
- Message payload sampling (configurable duration, for data classification)
- **NOT implemented:** Publish (no messages sent to topics)

#### 8.3.12 CoAP Resource Discovery
**File: `implant/modules/ot/protocols/coap.go`**
- `/.well-known/core` resource discovery (RFC 6690)
- GET on discovered resources (read-only)
- Detect DTLS vs plaintext
- Observe option passive monitoring
- **NOT implemented:** PUT, POST, DELETE

#### 8.3.13 Omron FINS
**File: `implant/modules/ot/protocols/fins.go`**
- FINS/TCP and FINS/UDP address resolution
- **Read-only commands:**
  - Memory Area Read (CIO, WR, HR, DM, AR, EM)
  - CPU Unit Data Read (controller model, version)
  - CPU Unit Status Read (operating mode, fatal/non-fatal errors)
  - Clock Read
  - Network Status Read
- Unit address enumeration
- **NOT implemented:** Memory Area Write, CPU Run/Stop, Program Area Write, Forced Set/Reset

#### 8.3.14 Mitsubishi MELSEC
**File: `implant/modules/ot/protocols/melsec.go`**
- SLMP (Seamless Message Protocol) / MC Protocol
- **Read-only commands:**
  - Batch Read (D, M, X, Y, R, B registers)
  - CPU Model Read
  - CPU Status Read
- Binary and ASCII frame support
- **NOT implemented:** Batch Write, Remote Run/Stop/Pause/Reset

#### 8.3.15 Phoenix Contact PC Worx / Crimson / Other
**Files: `implant/modules/ot/protocols/pcworx.go`, `crimson.go`**
- PC Worx protocol identification and device info read
- Red Lion Crimson protocol device enumeration
- Generic Telnet/SSH banner grabbing for OT devices with management interfaces
- HTTP/HTTPS web interface detection and basic page fetch (for HMI assessment)

---

### 8.4 OT Protocol Traffic Capture & Analysis
**File: `implant/modules/ot/capture.go`**

**Passive capture (no injection):**
- Raw packet capture on OT network interfaces (requires root/admin)
- Protocol-aware filtering: capture only OT protocols, discard IT noise
- Duration and size-limited (configurable, hard cap)
- Real-time protocol decode for:
  - Modbus request/response pairs with function code and register mapping
  - DNP3 frames with object group identification
  - S7Comm PDUs with area/DB identification
  - EtherNet/IP CIP service identification
  - BACnet service identification
  - IEC 104 ASDU type identification
  - GOOSE/SV frame parsing
  - PROFINET IO cycle detection
- Export as structured JSON (not raw PCAP, to avoid exfiltrating raw traffic)

**Analysis outputs:**
- Communication matrix: which devices talk to which, over what protocol
- Polling interval detection per controller-device pair
- Anomaly indicators: unexpected source IPs, unusual function codes, broadcast storms
- Unencrypted credential detection in OT traffic (Telnet, HTTP Basic, SNMP community strings)
- Cleartext process data identification

---

### 8.5 Default Credential Assessment
**File: `implant/modules/ot/credentials.go`**

**Assessment method: single-attempt auth probe per service, not brute force.**
- Vendor default credential database (embedded, offline):
  - Siemens: S7 default password, TIA Portal defaults, WinCC defaults
  - Rockwell/Allen-Bradley: default PCCC, RSLogix defaults
  - Schneider Electric: Unity Pro defaults, Vijeo defaults
  - ABB: default web interface credentials
  - Honeywell: Experion defaults
  - GE: Mark VIe/ControlST defaults
  - Emerson: DeltaV defaults
  - Yokogawa: CENTUM VP defaults
  - Omron: CX-Programmer defaults
  - Mitsubishi: GX Works defaults
  - Moxa: default serial server/switch credentials
  - Generic: admin/admin, admin/password, admin/1234, root/root
- Per-service probes:
  - HTTP/HTTPS: single GET with Basic/Digest auth
  - Telnet: single login attempt
  - SSH: single auth attempt (keyboard-interactive or password)
  - FTP: single login attempt
  - SNMP: community string read test (`public`, `private`, + engagement-specific list)
  - VNC: auth probe (detect no-auth, password-only, or certificate)
  - RDP: NLA detection, no actual login attempt
  - OPC UA: test anonymous access, test with common credentials
  - Modbus: no auth (flag as finding if reachable)
  - S7Comm: test if CPU password is blank or default
  - Web HMI: single login attempt with vendor defaults
- **Constraints:**
  - ONE attempt per credential per service (no lockout risk)
  - Configurable: `CredentialTestingOn` must be explicitly enabled
  - Account lockout detection: if server returns lockout indicator, log and stop
  - All attempts audit-logged with timestamp, target, service, result (success/fail/lockout)
- **NOT implemented:** Brute force, password spraying, hash cracking, credential relay

---

### 8.6 Known Vulnerability Identification
**File: `implant/modules/ot/vulnscan.go`**

**Method: offline CVE correlation, no active exploitation.**
- Embedded vulnerability database (JSON, updated at build time):
  - ICS-CERT advisories (CISA) for OT devices
  - Vendor-specific advisories: Siemens ProductCERT, Rockwell, Schneider SEVD
  - NVD CVE data filtered to OT CPE entries
- Correlation engine:
  - Input: vendor + model + firmware version (from fingerprinting)
  - Output: list of matching CVEs with severity, CVSS score, description, advisory link
- **Assessment categories:**
  - Critical: RCE, authentication bypass, firmware manipulation
  - High: information disclosure, denial of service
  - Medium: insecure defaults, weak crypto
  - Low: information leaks, minor misconfigurations
- Known insecure protocol detection:
  - Modbus with no authentication (inherent to protocol — always flagged)
  - DNP3 without Secure Authentication
  - OPC UA with SecurityPolicy None
  - BACnet without BACnet SC
  - Telnet/HTTP in OT segment (cleartext management)
  - SNMP v1/v2c with default community strings
  - MQTT without TLS or authentication
  - IEC 104 without IEC 62351
- End-of-life / end-of-support device identification
- **NOT implemented:** Exploit execution, proof-of-concept triggering, active vulnerability validation

---

### 8.7 Network Segmentation Analysis
**File: `implant/modules/ot/segmentation.go`**

**Purdue Model mapping (Level 0-5):**
- Level 0: Physical process (sensors, actuators) — identified by protocol role
- Level 1: Basic control (PLCs, RTUs, DCS controllers) — identified by device type
- Level 2: Supervisory control (HMIs, SCADA servers) — identified by services
- Level 3: Manufacturing operations (historians, MES) — identified by data flow
- Level 3.5: DMZ (data diodes, firewalls) — identified by network position
- Level 4/5: Enterprise/Internet — IT network boundary

**Segmentation tests (all read-only network probes):**
- Cross-zone reachability: can Level 4 reach Level 1 directly? (TCP connect probes to discovered OT devices from implant's position)
- Firewall rule inference: what OT ports are reachable from what segments
- VLAN detection: detect if OT devices are on separate VLANs or flat network
- Dual-homed host identification: devices with IPs on multiple subnets
- Default gateway analysis: shared gateways between IT and OT segments
- Route analysis: traceroute to OT devices to identify hop path
- NAT detection: identify if NAT separates IT from OT

**Remote access identification:**
- VPN endpoint detection (port 500/4500 IKE, OpenVPN, WireGuard)
- RDP/VNC/SSH reachable from IT network to OT devices
- TeamViewer/AnyDesk/similar remote access tool detection on HMI/EWS ports
- Web-based remote access portals
- Modem/cellular gateway detection (serial servers with SIM)

**Outputs:**
- Purdue model diagram data (JSON graph with levels and connections)
- Segmentation gap list with severity
- Cross-zone communication matrix
- Unauthorized access path identification

---

### 8.8 OT Wireless Assessment
**File: `implant/modules/ot/wireless.go`**

**WiFi in OT environments:**
- Detect WiFi access points in OT segments (if wireless interface available)
- Identify WEP, WPA, WPA2, WPA3, Open networks
- SSID enumeration, BSSID collection
- Detect wireless bridges to OT segments
- Client enumeration (passive probe request sniffing)

**Industrial wireless protocols (passive detection only):**
- WirelessHART (IEEE 802.15.4 at 2.4GHz) — detect network manager advertisements
- ISA100.11a — detect beacons
- Zigbee — detect PAN IDs, coordinator identification
- Bluetooth/BLE — detect beacons from OT devices (some smart sensors)
- LoRa/LoRaWAN — detect if LoRa gateway is present (port scan)
- Cellular (4G/5G) — detect cellular gateways via management interfaces

**Outputs:**
- Wireless access point inventory
- Encryption assessment per AP
- Unauthorized wireless bridge detection
- Industrial wireless protocol presence map

---

### 8.9 Historian & SCADA Server Assessment
**File: `implant/modules/ot/historian.go`**

**Historian database assessment (read-only):**
- Detect historian software: OSIsoft PI, Wonderware/AVEVA Historian, GE Proficy, Honeywell PHD, AspenTech IP.21, FactoryTalk Historian
- PI Web API enumeration (REST, read-only GET requests):
  - Asset database browse
  - Point enumeration
  - Archive data sampling (limited, to confirm access)
  - Security configuration read
- SQL Server connection test for SQL-based historians (read-only SELECT)
- Detect if historian is directly accessible from IT network (segmentation finding)
- Detect if historian exposes data to cloud/external services

**SCADA server assessment:**
- Detect SCADA software: Ignition, WinCC, FactoryTalk View, Citect, Wonderware InTouch
- Web interface identification and version detection
- Detect default/open ports
- Certificate analysis for web interfaces

---

### 8.10 HMI Web Interface Assessment
**File: `implant/modules/ot/hmi.go`**

**Web-based HMI assessment (read-only HTTP(S)):**
- Identify HMI web interfaces (Ignition, Weintek, Beijer, Siemens Comfort Panels, Rockwell PanelView)
- HTTP response analysis: server headers, technology fingerprinting
- Detect authentication requirements (or lack of)
- Detect embedded web servers with default configurations
- TLS/SSL assessment: protocol version, cipher suites, certificate validity
- Detect exposed process visualization pages (screenshot via headless if available)
- Directory traversal susceptibility detection (safe probes: request known bad paths, observe response code pattern without injecting)
- API endpoint enumeration (REST/JSON/WebSocket detection)
- **NOT implemented:** No active exploitation, no injection, no file upload, no parameter tampering

---

### 8.11 PLC Program Logic Analysis (Read-Only)
**File: `implant/modules/ot/plclogic.go`**

**Read-only program retrieval and analysis:**
- S7: Read OB/FC/FB/DB block list and sizes (not upload — just metadata unless DataLevel = "config")
- Rockwell: Read tag database, program names, routine names, rung count
- Modbus: Infer logic from register naming conventions and polling patterns
- **Analysis (offline, on collected metadata):**
  - Identify unused/orphan program blocks
  - Detect if program is protected/password-locked
  - Detect if online program matches known-good baseline (requires baseline from engagement)
  - Identify custom function blocks vs. vendor library blocks
- **NOT implemented:** Program upload (full block transfer), program download, online edit, program comparison at instruction level

---

### 8.12 Serial Port & Field Bus Enumeration
**File: `implant/modules/ot/serial.go`**

**Serial interface discovery:**
- Enumerate serial ports (COM ports on Windows, /dev/ttyS* and /dev/ttyUSB* on Linux)
- Detect USB-to-serial adapters
- Identify connected serial protocols:
  - Modbus RTU (baud rate detection: 9600, 19200, 38400, 115200)
  - HART (Bell 202 FSK detection)
  - Profibus DP (RS-485 detection)
  - DF1 (Allen-Bradley serial)
- Serial port permission assessment (who can access serial ports)

**Network-attached serial servers:**
- Detect Moxa NPort, Lantronix, Digi, Perle serial servers
- Port mapping: which serial port connects to what OT device
- Detect if serial server authentication is enabled

---

### 8.13 IEC 62443 / NIST 800-82 / NERC CIP Compliance Gap Analysis
**File: `implant/modules/ot/compliance.go`**

**Automated gap checks mapped to standards:**

**IEC 62443 (Industrial Automation and Control Systems Security):**
- FR 1 (Identification and Authentication Control):
  - [ ] All OT components require authentication → check default creds findings
  - [ ] Unique identification per user → detect shared accounts
  - [ ] Authentication strength → detect weak/no passwords
- FR 2 (Use Control):
  - [ ] Authorization enforcement → check for unrestricted protocol access
  - [ ] Least privilege → detect devices with full admin access open
- FR 3 (System Integrity):
  - [ ] Communication integrity → detect unencrypted OT protocols
  - [ ] Software integrity → detect unsigned firmware, no integrity monitoring
- FR 4 (Data Confidentiality):
  - [ ] Information confidentiality → detect cleartext process data
  - [ ] Network segmentation → use segmentation analysis results
- FR 5 (Restricted Data Flow):
  - [ ] Network segmentation → Purdue model compliance
  - [ ] Zone/conduit model → cross-zone access findings
- FR 6 (Timely Response to Events):
  - [ ] Audit log capability → detect if logging is enabled
  - [ ] Monitoring capability → detect IDS/SIEM presence
- FR 7 (Resource Availability):
  - [ ] Denial of service protection → detect devices without rate limiting
  - [ ] Backup/recovery → detect if backups are accessible

**NIST SP 800-82 (Guide to ICS Security):**
- Network architecture assessment against recommended topology
- Remote access security evaluation
- Wireless security in ICS environments

**NERC CIP (Critical Infrastructure Protection, power sector):**
- CIP-002: BES Cyber System identification → asset inventory completeness
- CIP-005: Electronic Security Perimeter → segmentation findings
- CIP-007: System Security Management → patch level, port/service assessment
- CIP-010: Configuration Change Management → detect baseline deviations

**Output: Structured findings report:**
```go
type ComplianceFinding struct {
    Standard      string // "IEC62443", "NIST800-82", "NERCCIP"
    Requirement   string // "FR1.1", "CIP-005-R1"
    Level         string // "critical", "high", "medium", "low"
    Finding       string
    Evidence      string // what was observed
    Recommendation string
    AffectedAssets []string
    MITREMapping  string // ATT&CK for ICS technique ID
}
```

---

### 8.14 OT Assessment Reporting
**File: `implant/modules/ot/reporting.go`**

**Report generation from collected assessment data:**
- Executive summary: overall OT security posture rating
- Asset inventory: complete device list with vendor/model/firmware
- Network architecture: Purdue model mapping with segmentation gaps
- Vulnerability summary: CVEs by severity, grouped by device/vendor
- Protocol security: per-protocol findings (auth, encryption, access control)
- Credential findings: default/weak credentials by device
- Compliance gap matrix: IEC 62443 / NIST 800-82 / NERC CIP
- Wireless findings: unauthorized APs, weak encryption
- Remote access findings: exposed management interfaces
- Prioritized remediation roadmap
- MITRE ATT&CK for ICS technique coverage map

**Export formats:**
- JSON (structured data for integration)
- Markdown (human-readable report)
- CSV (asset inventory, vulnerability list)
- MITRE ATT&CK Navigator layer JSON (for visualization)

**MITRE ATT&CK for ICS mapping:**
- Discovery techniques used: T0842 (Network Sniffing), T0846 (Remote System Discovery), T0888 (Remote System Information Discovery)
- Collection techniques: T0802 (Automated Collection), T0811 (Data from Information Repositories)
- Map each finding to applicable technique for reporting

---

### 8.15 Device Fingerprinting
**File: `implant/modules/ot/fingerprint.go`**
- Multi-source correlation for accurate identification:
  - MAC OUI → vendor (IEEE OUI database subset for OT vendors)
  - Protocol-level vendor/model fields
  - HTTP server headers (for web-enabled devices)
  - SNMP sysDescr/sysObjectID
  - Banner strings from Telnet/SSH/FTP
  - SSL/TLS certificate fields
  - LLDP/CDP chassis/port descriptions
- Firmware version extraction and normalization
- Device family classification (PLC, HMI, RTU, DCS, IO module, VFD, relay, switch, firewall, historian, EWS, gateway)
- Confidence scoring per identification method
- Known vulnerability cross-reference: vendor + model + firmware → CVE list
- End-of-life / end-of-support status lookup

---

### 8.16 Topology Mapping
**File: `implant/modules/ot/topology.go`**
- Build network topology graph from all discovery sources
- Assign Purdue levels based on device role and network position
- Identify:
  - IT/OT boundary devices (firewalls, routers, data diodes)
  - DMZ hosts (historians, jump servers, data gateways)
  - Dual-homed devices (hosts in multiple segments)
  - Flat network indicators (no segmentation between levels)
  - Unauthorized cross-level connections
- Export as:
  - JSON adjacency graph with metadata per node/edge
  - Purdue model level assignments
  - Segmentation gap findings
  - GraphViz DOT format for diagram generation

---

### 8.17 OT gRPC Service (Hidden)
**File: `server/api/grpc/ot.go`**
```go
type OTServer struct {
    // not registered in standard service reflection
}
```
**RPCs:**
- `DiscoverOTAssets` — passive + active discovery
- `ScanProtocol` — protocol-specific read operations (modbus, opcua, s7, dnp3, enip, bacnet, iec104, iec61850, profinet, hart, mqtt, coap, fins, melsec)
- `CaptureOTTraffic` — start/stop traffic capture with duration/size limits
- `AssessCredentials` — default credential assessment (must be explicitly enabled)
- `IdentifyVulnerabilities` — CVE correlation from fingerprint data
- `AnalyzeSegmentation` — cross-zone reachability and Purdue mapping
- `ScanWireless` — wireless AP and industrial wireless detection
- `AssessHistorian` — historian/SCADA server read-only assessment
- `AssessHMI` — web HMI interface assessment
- `ReadPLCInfo` — PLC program metadata (read-only)
- `EnumerateSerial` — serial port and field bus discovery
- `RunComplianceCheck` — IEC 62443 / NIST / NERC CIP gap analysis
- `GenerateOTReport` — compile assessment report
- `GetOTTopology` — retrieve topology map
- `ListOTAssets` — list discovered assets with filters
- `GetOTFinding` — retrieve specific finding detail
- Service registered ONLY when engagement has `ot_authorized: true`
- Service NOT included in gRPC reflection (hidden from enumeration)
- All RPCs require `ot.assess` permission + dual-auth token

### 8.18 OT Dual-Authorization Middleware
**File: `server/api/middleware/ot_auth.go`**
- OT operations require two-factor authorization:
  1. Operator's RBAC role includes `ot.assess` permission
  2. A separate OT authorization token issued by the engagement's OT safety contact
- Token structure:
  ```go
  type OTAuthToken struct {
      TokenID       string
      EngagementID  string
      IssuedBy      string    // OT safety contact name
      IssuedAt      time.Time
      ExpiresAt     time.Time
      AllowedScopes []string  // specific OT subnets/devices
      AllowedOps    []string  // which operations (discover, scan, creds, etc.)
      Signature     []byte    // Ed25519 signature by safety contact's key
  }
  ```
- Token is time-limited (default: 1 hour, max: 8 hours)
- Token is scope-limited to specific OT targets and operation types
- Token generation requires out-of-band confirmation (not automatable from CLI)
- Token validation: signature check, expiry check, scope match, operation match
- Expired/revoked token → immediate halt of all in-progress OT operations

### 8.19 OT Data Models
**File: `server/store/models/ot.go`**
```go
type OTAssetRecord struct {
    Base
    EngagementID   string
    IP             string
    MAC            string
    MACVendor      string
    Hostname       string
    Vendor         string
    Model          string
    SerialNumber   string
    Firmware       string
    HardwareRev    string
    Protocols      string     // JSON array
    Role           string
    SafetyRated    bool
    SILLevel       int
    PurdueLevel    int
    Ports          string     // JSON array of PortInfo
    OSFingerprint  string
    NetworkSegment string
    FirstSeen      time.Time
    LastSeen       time.Time
    DiscoveryMethod string
    RawData        string     // JSON protocol responses
}

type OTCredentialFinding struct {
    Base
    EngagementID string
    AssetID      string
    Service      string     // ssh, telnet, http, snmp, opcua, s7, vnc
    Port         int
    Username     string
    IsDefault    bool       // true = vendor default cred
    Result       string     // "success", "failed", "lockout", "no_auth_required"
    OperatorID   string
    AuthToken    string
}

type OTVulnFinding struct {
    Base
    EngagementID string
    AssetID      string
    CVE          string
    CVSS         float64
    Severity     string
    Title        string
    Description  string
    Advisory     string     // URL to advisory
    Remediation  string
    Vendor       string
    AffectedFW   string
    Confirmed    bool       // true = version match, false = possible
}

type OTSegmentationFinding struct {
    Base
    EngagementID string
    SourceLevel  int        // Purdue level of source
    TargetLevel  int        // Purdue level of target
    SourceIP     string
    TargetIP     string
    Port         int
    Protocol     string
    Severity     string
    Description  string
}

type OTComplianceFinding struct {
    Base
    EngagementID   string
    Standard       string
    Requirement    string
    Level          string
    Finding        string
    Evidence       string
    Recommendation string
    AffectedAssets string // JSON array of asset IDs
    MITREMapping   string
}

type OTScanResult struct {
    Base
    EngagementID string
    AssetID      string
    Protocol     string
    Operation    string
    RequestData  string     // JSON
    ResponseData string     // JSON
    OperatorID   string
    AuthToken    string
    Duration     int64      // milliseconds
}

type OTTopology struct {
    Base
    EngagementID string
    GraphJSON    string     // JSON adjacency graph with node/edge metadata
    PurdueMap    string     // JSON Purdue level assignments
    Gaps         string     // JSON segmentation findings
    WirelessMap  string     // JSON wireless AP locations
    RemoteAccess string     // JSON remote access points
}

type OTReport struct {
    Base
    EngagementID string
    Format       string     // json, markdown, csv
    Content      []byte
    GeneratedBy  string
    AssetCount   int
    FindingCount int
    CriticalCount int
    HighCount    int
}
```

### 8.20 OT Console Commands (Hidden)
**File: `client/cli/commands/ot.go`**
- Commands are NOT registered in standard help/tab-completion
- Activated only after `ot-mode` command with valid OT auth token
- Prompt changes to: `[OT:engagement-name] operator@pc2 > `
- Commands:
  - `ot-discover [--passive] [--active] [--duration 5m] [--subnet 10.0.0.0/24]` — asset discovery
  - `ot-assets [--vendor siemens] [--role plc] [--purdue 1]` — list/filter discovered assets
  - `ot-asset <id>` — show full asset detail including vulns and findings
  - `ot-scan modbus <target> [--unit-ids 1-10] [--registers 0-99]` — Modbus enumeration
  - `ot-scan opcua <target> [--browse] [--endpoints]` — OPC UA
  - `ot-scan s7 <target> [--szl] [--cpu-info]` — S7Comm
  - `ot-scan dnp3 <target> [--class 0,1,2,3]` — DNP3 poll
  - `ot-scan enip <target> [--identity] [--cip-read]` — EtherNet/IP
  - `ot-scan bacnet <target> [--whois] [--read-all]` — BACnet
  - `ot-scan iec104 <target>` — IEC 104
  - `ot-scan iec61850 <target>` — IEC 61850 MMS
  - `ot-scan profinet [--dcp-identify]` — PROFINET
  - `ot-scan hart <target>` — HART-IP
  - `ot-scan mqtt <target> [--topics] [--duration 30s]` — MQTT
  - `ot-scan fins <target>` — Omron FINS
  - `ot-scan melsec <target>` — Mitsubishi MELSEC
  - `ot-capture [--duration 5m] [--interface eth0]` — traffic capture
  - `ot-creds [--target <ip>] [--service ssh,http,snmp]` — credential assessment
  - `ot-vulns [--asset <id>] [--severity critical,high]` — vulnerability findings
  - `ot-segmentation [--test] [--map]` — segmentation analysis
  - `ot-wireless [--scan] [--duration 60s]` — wireless assessment
  - `ot-historian [--detect] [--assess <target>]` — historian assessment
  - `ot-hmi [--detect] [--assess <target>]` — HMI web assessment
  - `ot-plc-info <target>` — PLC program metadata
  - `ot-serial [--list] [--detect-protocols]` — serial/fieldbus enumeration
  - `ot-compliance [--standard iec62443,nist,nerccip]` — compliance gap analysis
  - `ot-topology` — show Purdue model topology
  - `ot-report [--format md] [--output report.md]` — generate assessment report
  - `ot-findings [--severity critical] [--type vuln,cred,segmentation]` — browse all findings
  - `ot-mitre` — show MITRE ATT&CK for ICS technique coverage
  - `ot-exit` — leave OT mode, lock all OT commands

### 8.21 OT Protobuf Definitions
**File: `proto/v1/ot.proto`**
```protobuf
syntax = "proto3";
package privatec2.v1;

service OTService {
  rpc DiscoverAssets(OTDiscoverRequest) returns (OTDiscoverResponse);
  rpc ScanProtocol(OTScanRequest) returns (OTScanResponse);
  rpc CaptureTraffic(OTCaptureRequest) returns (stream OTCaptureEvent);
  rpc AssessCredentials(OTCredRequest) returns (OTCredResponse);
  rpc IdentifyVulnerabilities(OTVulnRequest) returns (OTVulnResponse);
  rpc AnalyzeSegmentation(OTSegRequest) returns (OTSegResponse);
  rpc ScanWireless(OTWirelessRequest) returns (OTWirelessResponse);
  rpc AssessHistorian(OTHistorianRequest) returns (OTHistorianResponse);
  rpc AssessHMI(OTHMIRequest) returns (OTHMIResponse);
  rpc ReadPLCInfo(OTPLCRequest) returns (OTPLCResponse);
  rpc EnumerateSerial(OTSerialRequest) returns (OTSerialResponse);
  rpc RunComplianceCheck(OTComplianceRequest) returns (OTComplianceResponse);
  rpc GenerateReport(OTReportRequest) returns (OTReportResponse);
  rpc GetTopology(OTTopologyRequest) returns (OTTopologyResponse);
  rpc ListAssets(OTListAssetsRequest) returns (OTListAssetsResponse);
  rpc GetFinding(OTFindingRequest) returns (OTFindingResponse);
}

message OTAuthToken {
  string token_id = 1;
  string engagement_id = 2;
  string issued_by = 3;
  int64 expires_at = 4;
  repeated string allowed_scopes = 5;
  repeated string allowed_ops = 6;
  bytes signature = 7;
}

// ... (full message definitions for each RPC)
```

---

## RBAC Extension

Already added to `server/api/middleware/rbac.go` (Phase 1):
```go
PermOTAssess Permission = "ot.assess"

"admin":       { ..., PermOTAssess },
"ot-operator": { PermSessionRead, PermSessionWrite, PermListenerRead,
                 PermEngagementManage, PermAuditRead, PermOTAssess },
```

---

## Audit Requirements
- Every OT protocol query logged: target, protocol, function code, data level, response summary, duration
- OT scan sessions logged as a group with correlation ID
- Safety interlock denials logged as CRITICAL events
- Dual-auth token usage logged: issuer, scope, operations, expiry
- Credential test attempts logged: target, service, username (NOT password), result
- Watchdog triggers logged as CRITICAL events
- All findings logged with their generation timestamp and basis
- OT report generation logged with scope and content hash

---

## Dependencies
- Phase 1: `pkg/engagement` scope/kill switch, `server/store`, middleware, RBAC with ot.assess (DONE)
- Phase 2: Implant runtime skeleton
- Phase 3: At least one transport working
- Phase 4: Task execution engine, safety layer
- External protocol libraries:
  - Modbus: `github.com/goburrow/modbus` or raw TCP
  - OPC UA: `github.com/gopcua/opcua`
  - MQTT: `github.com/eclipse/paho.mqtt.golang`
  - SNMP: `github.com/gosnmp/gosnmp`
  - SSH: `golang.org/x/crypto/ssh`
  - BACnet/S7Comm/DNP3/IEC104/IEC61850/PROFINET/HART/FINS/MELSEC: raw TCP/UDP implementations
  - PCAP: `github.com/google/gopacket` + `github.com/google/gopacket/pcap`
  - LLDP: `github.com/google/gopacket/layers`

---

## Verification
```bash
go build ./implant/modules/ot/...
go test ./implant/modules/ot/... -v -count=1
go build ./server/api/grpc/...
go vet ./implant/modules/ot/...

# Safety interlock unit tests (MUST pass):
go test ./implant/modules/ot/ -run TestSafetyInterlocks -v
go test ./implant/modules/ot/ -run TestWriteBlocked -v
go test ./implant/modules/ot/ -run TestDualAuth -v
go test ./implant/modules/ot/ -run TestWatchdog -v
go test ./implant/modules/ot/ -run TestKillSwitch -v
go test ./implant/modules/ot/ -run TestRateLimit -v

# Integration test with OT simulators:
# 1. Start ModRSsim2 (Modbus), open62541 (OPC UA), MQTT broker
# 2. Run full discovery pipeline against simulator subnet
# 3. Run protocol scans against each simulator
# 4. Verify read-only: attempt write function codes → hard interlock blocks
# 5. Verify dual-auth: scan without OT token → rejected
# 6. Verify kill switch: activate → all OT connections drop within 1s
# 7. Verify watchdog: cut server connection → OT conns close within 60s
# 8. Verify rate limiting: burst → enforced inter-packet delay
# 9. Verify credential assessment: single attempt only, no lockout
# 10. Generate report, verify all findings included
```

---

## Key Constraint
This entire module tree is ASSESSMENT-ONLY. There are zero write, control, or modify operations implemented for any OT protocol. The purpose is to comprehensively map OT environments, identify security exposures, test segmentation, assess credential hygiene, correlate known vulnerabilities, and evaluate compliance posture during authorized engagements — never to disrupt, control, or manipulate industrial processes or safety systems.
