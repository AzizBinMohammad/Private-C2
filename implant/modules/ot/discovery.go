package ot

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// OTAsset represents a discovered OT/ICS device.
type OTAsset struct {
	IP           string    `json:"ip"`
	MAC          string    `json:"mac"`
	Vendor       string    `json:"vendor"`
	Model        string    `json:"model"`
	Firmware     string    `json:"firmware"`
	Protocol     string    `json:"protocol"`
	Protocols    []string  `json:"protocols"`
	Role         string    `json:"role"` // PLC, HMI, RTU, DCS, EWS, Historian, Gateway, IO, Sensor
	SafetyRated  bool      `json:"safety_rated"`
	SILLevel     int       `json:"sil_level"`     // 0-4
	PurdueLevel  int       `json:"purdue_level"`  // 0-5
	Hostname     string    `json:"hostname"`
	Description  string    `json:"description"`
	SerialNumber string    `json:"serial_number"`
	ProductCode  string    `json:"product_code"`
	OpenPorts    []int     `json:"open_ports"`
	Services     []string  `json:"services"`
	Banners      map[string]string `json:"banners"`
	LastSeen     time.Time `json:"last_seen"`
	FirstSeen    time.Time `json:"first_seen"`
	DiscoveryMethod string `json:"discovery_method"`
	Confidence   float64   `json:"confidence"` // 0.0-1.0
	Tags         []string  `json:"tags"`
	RawData      map[string]any `json:"raw_data,omitempty"`
}

// DiscoveryConfig controls how discovery operates.
type DiscoveryConfig struct {
	Passive      bool          `json:"passive"`
	Active       bool          `json:"active"`
	Timeout      time.Duration `json:"timeout"`
	PortList     []int         `json:"port_list"`
	ARPScan      bool          `json:"arp_scan"`
	OUILookup    bool          `json:"oui_lookup"`
	BannerGrab   bool          `json:"banner_grab"`
	ProbeProtos  []string      `json:"probe_protocols"`
}

// DefaultDiscoveryConfig returns conservative defaults for OT discovery.
func DefaultDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		Passive:   true,
		Active:    false,
		Timeout:   time.Second * 5,
		PortList:  commonOTPorts(),
		ARPScan:   false,
		OUILookup: true,
		BannerGrab: true,
		ProbeProtos: []string{"modbus", "ethernetip", "s7comm", "bacnet", "dnp3"},
	}
}

// commonOTPorts returns well-known OT/ICS ports.
func commonOTPorts() []int {
	return []int{
		102,   // S7Comm / ISO-TSAP
		502,   // Modbus TCP
		2404,  // IEC 60870-5-104
		4840,  // OPC UA
		4843,  // OPC UA TLS
		9600,  // FINS (Omron)
		20000, // DNP3
		44818, // EtherNet/IP
		47808, // BACnet
		1883,  // MQTT
		5683,  // CoAP
		34962, // PROFINET
		34963, // PROFINET
		34964, // PROFINET
		1089,  // FF HSE
		2222,  // EtherCAT
		18245, // GE SRTP
		5007,  // OSIsoft PI
		8089,  // GE iFIX
		1911,  // Niagara Fox
		789,   // Red Lion Crimson
		20547, // ProConOS
		5094,  // HART-IP
	}
}

// Discovery handles OT/ICS asset discovery.
type Discovery struct {
	module *OTModule
	config DiscoveryConfig
	assets map[string]*OTAsset // keyed by IP
	mu     sync.Mutex
}

// NewDiscovery creates a new discovery engine.
func NewDiscovery(module *OTModule, config DiscoveryConfig) *Discovery {
	return &Discovery{
		module: module,
		config: config,
		assets: make(map[string]*OTAsset),
	}
}

// PassiveDiscover listens for OT protocol broadcasts and multicast traffic.
func (d *Discovery) PassiveDiscover(ctx context.Context, iface string) ([]OTAsset, error) {
	if d.module.IsShutdown() {
		return nil, fmt.Errorf("OT module is shut down")
	}

	var results []OTAsset

	// Listen on common OT broadcast/multicast ports
	listenTargets := []struct {
		port    int
		proto   string
		network string
	}{
		{47808, "bacnet", "udp4"},  // BACnet
		{34962, "profinet", "udp4"}, // PROFINET DCP
		{1883, "mqtt", "tcp4"},      // MQTT (only listen, no connect)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, lt := range listenTargets {
		lt := lt
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := d.listenOnPort(ctx, lt.port, lt.proto, lt.network)
			if err != nil {
				return
			}
			mu.Lock()
			results = append(results, assets...)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return results, nil
}

// listenOnPort passively listens for traffic on a specific port.
func (d *Discovery) listenOnPort(ctx context.Context, port int, proto, network string) ([]OTAsset, error) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, fmt.Errorf("listening on %s %s: %w", network, addr, err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(d.config.Timeout)
	}
	_ = conn.SetReadDeadline(deadline)

	var results []OTAsset
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return results, nil
		default:
		}

		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return results, nil
			}
			return results, nil
		}
		if n == 0 {
			continue
		}

		host, _, _ := net.SplitHostPort(remoteAddr.String())
		asset := d.parsePassiveData(buf[:n], host, proto)
		if asset != nil {
			asset.DiscoveryMethod = "passive"
			asset.FirstSeen = time.Now()
			asset.LastSeen = time.Now()
			results = append(results, *asset)
			d.recordAsset(asset)
		}
	}
}

// parsePassiveData extracts device info from captured OT protocol data.
func (d *Discovery) parsePassiveData(data []byte, srcIP, proto string) *OTAsset {
	asset := &OTAsset{
		IP:       srcIP,
		Protocol: proto,
		Banners:  make(map[string]string),
		RawData:  make(map[string]any),
	}

	switch proto {
	case "bacnet":
		if len(data) >= 4 && data[0] == 0x81 { // BVLC header
			asset.Protocol = "bacnet"
			asset.Role = "BACnet Device"
			// Parse I-Am if present
			if len(data) > 7 {
				asset.RawData["bvlc_function"] = data[1]
			}
		}
	case "profinet":
		if len(data) >= 14 {
			asset.Protocol = "profinet"
			asset.Role = "PROFINET Device"
		}
	default:
		return nil
	}

	return asset
}

// ActiveDiscover performs active scanning within scope.
func (d *Discovery) ActiveDiscover(ctx context.Context, targets []string) ([]OTAsset, error) {
	if d.module.IsShutdown() {
		return nil, fmt.Errorf("OT module is shut down")
	}

	var results []OTAsset
	var mu sync.Mutex

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if err := d.module.PreFlightCheck(target, "discovery"); err != nil {
			continue
		}

		d.module.rateLimiter.Wait()

		assets, err := d.scanTarget(ctx, target)
		if err != nil {
			continue
		}

		mu.Lock()
		results = append(results, assets...)
		mu.Unlock()
	}

	return results, nil
}

// scanTarget performs port scanning and protocol probing on a single target.
func (d *Discovery) scanTarget(ctx context.Context, target string) ([]OTAsset, error) {
	asset := &OTAsset{
		IP:        target,
		Banners:   make(map[string]string),
		RawData:   make(map[string]any),
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		DiscoveryMethod: "active",
	}

	// Port scan
	openPorts := d.scanPorts(ctx, target, d.config.PortList)
	asset.OpenPorts = openPorts

	if len(openPorts) == 0 {
		return nil, nil
	}

	// Identify services from open ports
	for _, port := range openPorts {
		svc := identifyServiceByPort(port)
		if svc != "" {
			asset.Services = append(asset.Services, svc)
		}
	}

	// Banner grabbing
	if d.config.BannerGrab {
		for _, port := range openPorts {
			banner := d.grabBanner(ctx, target, port)
			if banner != "" {
				asset.Banners[fmt.Sprintf("%d", port)] = banner
			}
		}
	}

	// Protocol probing
	for _, port := range openPorts {
		protoInfo := d.probeProtocol(ctx, target, port)
		if protoInfo != "" {
			if asset.Protocol == "" {
				asset.Protocol = protoInfo
			}
			asset.Protocols = append(asset.Protocols, protoInfo)
		}
	}

	// OUI lookup
	if d.config.OUILookup && asset.MAC != "" {
		asset.Vendor = lookupOUI(asset.MAC)
	}

	d.recordAsset(asset)
	return []OTAsset{*asset}, nil
}

// scanPorts checks for open TCP ports on the target.
func (d *Discovery) scanPorts(ctx context.Context, target string, ports []int) []int {
	var open []int
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return open
		default:
		}

		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", addr, d.config.Timeout)
		if err != nil {
			continue
		}
		conn.Close()
		open = append(open, port)
		time.Sleep(d.module.InterPacketDelay())
	}
	return open
}

// grabBanner connects to a port and reads any initial data sent.
func (d *Discovery) grabBanner(ctx context.Context, target string, port int) string {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, d.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	// Return printable portion
	banner := sanitizeBanner(buf[:n])
	return banner
}

// sanitizeBanner removes non-printable characters from banner data.
func sanitizeBanner(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		if c >= 32 && c <= 126 {
			b.WriteByte(c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

// probeProtocol sends a minimal protocol-specific read-only probe.
func (d *Discovery) probeProtocol(ctx context.Context, target string, port int) string {
	switch port {
	case 502:
		return d.probeModbus(ctx, target, port)
	case 44818:
		return d.probeEtherNetIP(ctx, target, port)
	case 102:
		return d.probeS7(ctx, target, port)
	case 47808:
		return d.probeBACnet(ctx, target, port)
	case 2404:
		return d.probeIEC104(ctx, target, port)
	case 20000:
		return d.probeDNP3(ctx, target, port)
	default:
		return ""
	}
}

// probeModbus sends a Modbus read device identification request (FC43/14).
func (d *Discovery) probeModbus(_ context.Context, target string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), d.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Modbus TCP: Transaction ID(2) + Protocol ID(2) + Length(2) + Unit ID(1) + FC43(1) + MEI type(1) + Read Dev ID(1) + Object ID(1)
	req := []byte{
		0x00, 0x01, // Transaction ID
		0x00, 0x00, // Protocol ID (Modbus)
		0x00, 0x05, // Length
		0x01,       // Unit ID
		0x2B,       // FC 43 (Read Device Identification)
		0x0E,       // MEI type 14
		0x01,       // Read Device ID code: basic
		0x00,       // Object ID: VendorName
	}

	_ = conn.SetDeadline(time.Now().Add(d.config.Timeout))
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 9 {
		return ""
	}

	// Verify Modbus response
	if n >= 9 && resp[7] == 0x2B {
		return "modbus"
	}
	return ""
}

// probeEtherNetIP sends a ListIdentity request.
func (d *Discovery) probeEtherNetIP(_ context.Context, target string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), d.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// EtherNet/IP ListIdentity command
	req := make([]byte, 24)
	binary.LittleEndian.PutUint16(req[0:2], 0x0063) // ListIdentity
	// Rest is zero-filled (session handle, status, context, options)

	_ = conn.SetDeadline(time.Now().Add(d.config.Timeout))
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 24 {
		return ""
	}

	cmd := binary.LittleEndian.Uint16(resp[0:2])
	if cmd == 0x0063 {
		return "ethernetip"
	}
	return ""
}

// probeS7 sends a COTP Connection Request to detect S7Comm.
func (d *Discovery) probeS7(_ context.Context, target string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), d.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// TPKT header + COTP Connection Request
	req := []byte{
		0x03, 0x00, 0x00, 0x16, // TPKT: version 3, length 22
		0x11, 0xE0, 0x00, 0x00, // COTP CR, dst ref 0, src ref 0
		0x00, 0x01, 0x00,       // Class 0
		0xC0, 0x01, 0x0A,       // TPDU size: 1024
		0xC1, 0x02, 0x01, 0x00, // Source TSAP
		0xC2, 0x02, 0x01, 0x02, // Destination TSAP
	}

	_ = conn.SetDeadline(time.Now().Add(d.config.Timeout))
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		return ""
	}

	if resp[0] == 0x03 && resp[1] == 0x00 { // TPKT header
		return "s7comm"
	}
	return ""
}

// probeBACnet sends a BACnet Who-Is broadcast.
func (d *Discovery) probeBACnet(_ context.Context, target string, port int) string {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), d.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// BVLC header + NPDU + Who-Is
	req := []byte{
		0x81, 0x0A, 0x00, 0x11, // BVLC: type 0x81, Original-Unicast, length 17
		0x01, 0x04,             // NPDU: version 1, control
		0x00, 0x05,             // DNET: broadcast
		0x00,                   // DLEN: 0
		0xFF,                   // Hop count
		0x10, 0x08,             // APDU: Unconfirmed Who-Is
	}

	_ = conn.SetDeadline(time.Now().Add(d.config.Timeout))
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		return ""
	}

	if resp[0] == 0x81 {
		return "bacnet"
	}
	return ""
}

// probeIEC104 sends a STARTDT act APCI frame.
func (d *Discovery) probeIEC104(_ context.Context, target string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), d.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// IEC 104 STARTDT act
	req := []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00}

	_ = conn.SetDeadline(time.Now().Add(d.config.Timeout))
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 6 {
		return ""
	}

	if resp[0] == 0x68 {
		return "iec104"
	}
	return ""
}

// probeDNP3 sends a DNP3 link layer request (read class 0).
func (d *Discovery) probeDNP3(_ context.Context, target string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), d.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// DNP3 FT3 data link layer header
	req := []byte{
		0x05, 0x64, // Start bytes
		0x05,       // Length
		0xC0,       // Control: DIR=1, PRM=1, FCV=0, FCB=0, FC=0 (Reset Link)
		0x01, 0x00, // Destination
		0x00, 0x00, // Source
		0x00, 0x00, // CRC (placeholder)
	}

	_ = conn.SetDeadline(time.Now().Add(d.config.Timeout))
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 2 {
		return ""
	}

	if resp[0] == 0x05 && resp[1] == 0x64 {
		return "dnp3"
	}
	return ""
}

// identifyServiceByPort maps well-known OT ports to service names.
func identifyServiceByPort(port int) string {
	services := map[int]string{
		102:   "s7comm/iso-tsap",
		502:   "modbus",
		2404:  "iec-104",
		4840:  "opcua",
		4843:  "opcua-tls",
		9600:  "fins",
		20000: "dnp3",
		44818: "ethernetip",
		47808: "bacnet",
		1883:  "mqtt",
		5683:  "coap",
		34962: "profinet",
		34963: "profinet",
		34964: "profinet",
		5094:  "hart-ip",
		1089:  "ff-hse",
		2222:  "ethercat",
		18245: "ge-srtp",
		5007:  "osisoft-pi",
		8089:  "ge-ifix",
		1911:  "niagara-fox",
		789:   "crimson",
		20547: "proconos/pcworx",
	}
	return services[port]
}

// lookupOUI returns the vendor name for a MAC address OUI prefix.
func lookupOUI(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(mac) < 6 {
		return ""
	}
	oui := mac[:6]

	// Common OT vendor OUIs
	ouiDB := map[string]string{
		"00A0F4": "Siemens",
		"000E8C": "Siemens",
		"001C06": "Siemens",
		"0080F4": "Siemens",
		"001D9C": "Rockwell Automation",
		"00005A": "Rockwell/Allen-Bradley",
		"0001FA": "ABB",
		"000BBC": "Schneider Electric",
		"000EF0": "Schneider Electric",
		"0060B0": "Schneider Electric",
		"0800C8": "Emerson/Fisher",
		"00A0EC": "Emerson",
		"000168": "Honeywell",
		"00D0ED": "Honeywell",
		"000FB5": "GE Fanuc",
		"000D56": "GE Energy",
		"0060E9": "Yokogawa",
		"00E04C": "Moxa",
		"000C29": "VMware (virtual)",
		"080027": "VirtualBox (virtual)",
		"001E0B": "Hewlett-Packard",
		"009069": "Omron",
		"00070E": "Mitsubishi Electric",
		"0006D7": "Phoenix Contact",
		"00304A": "WAGO",
		"000D87": "Beckhoff",
		"00E098": "ABB",
		"00A09F": "Pilz",
		"0002B3": "Endress+Hauser",
	}

	return ouiDB[oui]
}

// recordAsset stores or updates an asset in the discovery cache.
func (d *Discovery) recordAsset(asset *OTAsset) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if existing, ok := d.assets[asset.IP]; ok {
		existing.LastSeen = time.Now()
		if asset.Vendor != "" {
			existing.Vendor = asset.Vendor
		}
		if asset.Model != "" {
			existing.Model = asset.Model
		}
		if asset.Protocol != "" && existing.Protocol == "" {
			existing.Protocol = asset.Protocol
		}
		for _, p := range asset.Protocols {
			found := false
			for _, ep := range existing.Protocols {
				if ep == p {
					found = true
					break
				}
			}
			if !found {
				existing.Protocols = append(existing.Protocols, p)
			}
		}
		for k, v := range asset.Banners {
			existing.Banners[k] = v
		}
	} else {
		d.assets[asset.IP] = asset
	}
}

// GetAssets returns all discovered assets.
func (d *Discovery) GetAssets() []OTAsset {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := make([]OTAsset, 0, len(d.assets))
	for _, a := range d.assets {
		result = append(result, *a)
	}
	return result
}

// GetAsset returns a specific asset by IP.
func (d *Discovery) GetAsset(ip string) (*OTAsset, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.assets[ip]
	if !ok {
		return nil, false
	}
	copy := *a
	return &copy, true
}
