package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// PROFINET DCP Frame IDs
const (
	PNDCPFrameIDIdentifyReq  = 0xFEFE
	PNDCPFrameIDIdentifyResp = 0xFEFF
)

// PROFINET DCP Service IDs
const (
	PNDCPServiceGet      = 0x03
	PNDCPServiceIdentify = 0x05
	// SAFETY: NOT implementing PNDCPServiceSet = 0x04
)

// PROFINET DCP Option/Suboption constants
const (
	PNDCPOptionIPAddr         = 0x01
	PNDCPSuboptionIPParam     = 0x02
	PNDCPOptionDevProp        = 0x02
	PNDCPSuboptionNameOfStation = 0x02
	PNDCPSuboptionDeviceID    = 0x03
	PNDCPSuboptionDeviceRole  = 0x04
	PNDCPSuboptionDeviceVendor = 0x08
)

// SAFETY: PROFINET client implements ONLY DCP Identify (read) and LLDP parsing.
// Explicitly NOT implementing: DCP Set (service 0x04), any PROFINET IO connections,
// AR establishment, write operations.

// PROFINETClient handles PROFINET DCP discovery and LLDP parsing.
type PROFINETClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
}

// PROFINETDevice holds information about a discovered PROFINET device.
type PROFINETDevice struct {
	NameOfStation string `json:"name_of_station"`
	VendorID      uint16 `json:"vendor_id"`
	DeviceID      uint16 `json:"device_id"`
	DeviceRole    byte   `json:"device_role"`
	DeviceRoleName string `json:"device_role_name"`
	IPAddress     string `json:"ip_address"`
	SubnetMask    string `json:"subnet_mask"`
	Gateway       string `json:"gateway"`
	MACAddress    string `json:"mac_address"`
	VendorName    string `json:"vendor_name"`
	DeviceType    string `json:"device_type"`
}

// LLDPInfo holds parsed LLDP (Link Layer Discovery Protocol) data.
type LLDPInfo struct {
	ChassisID    string `json:"chassis_id"`
	PortID       string `json:"port_id"`
	TTL          uint16 `json:"ttl"`
	SystemName   string `json:"system_name"`
	SystemDesc   string `json:"system_desc"`
	PortDesc     string `json:"port_desc"`
	MgmtAddr     string `json:"mgmt_addr"`
	ManufacturerName string `json:"manufacturer_name,omitempty"`
}

// NewPROFINETClient creates a new read-only PROFINET client.
func NewPROFINETClient(config ConnConfig) *PROFINETClient {
	return &PROFINETClient{
		config: config,
	}
}

func (c *PROFINETClient) Name() string { return "profinet" }

func (c *PROFINETClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 34964
	}

	conn, err := udpConnect(target, port, c.config.Timeout)
	if err != nil {
		return err
	}
	c.conn = conn
	c.target = target
	c.port = port
	c.connected = true
	return nil
}

func (c *PROFINETClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *PROFINETClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *PROFINETClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	devices, err := c.DCPIdentify()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no PROFINET devices responded")
	}

	dev := devices[0]
	return &DeviceInfo{
		Vendor:      dev.VendorName,
		ProductName: dev.DeviceType,
		Protocol:    "profinet",
		Description: dev.NameOfStation,
		Extra: map[string]string{
			"vendor_id":  fmt.Sprintf("0x%04X", dev.VendorID),
			"device_id":  fmt.Sprintf("0x%04X", dev.DeviceID),
			"device_role": dev.DeviceRoleName,
			"ip":         dev.IPAddress,
		},
	}, nil
}

// DCPIdentify sends a PROFINET DCP Identify request - READ ONLY.
func (c *PROFINETClient) DCPIdentify() ([]PROFINETDevice, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	// Build DCP Identify request
	// This is sent as a UDP/IP frame for testing; real PROFINET DCP
	// uses raw Ethernet frames with EtherType 0x8892
	req := buildDCPIdentifyRequest()

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(req); err != nil {
		return nil, err
	}

	var devices []PROFINETDevice
	deadline := time.Now().Add(c.config.Timeout)

	for time.Now().Before(deadline) {
		_ = c.conn.SetReadDeadline(deadline)
		buf := make([]byte, 1500)
		n, err := c.conn.Read(buf)
		if err != nil {
			break
		}
		if n < 12 {
			continue
		}

		dev := parseDCPResponse(buf[:n])
		if dev != nil {
			devices = append(devices, *dev)
		}
	}

	return devices, nil
}

// buildDCPIdentifyRequest constructs a DCP Identify multicast request.
func buildDCPIdentifyRequest() []byte {
	// DCP Header
	req := make([]byte, 0, 60)

	// Frame ID: DCP Identify Multicast Request
	fid := make([]byte, 2)
	binary.BigEndian.PutUint16(fid, PNDCPFrameIDIdentifyReq)
	req = append(req, fid...)

	// Service ID: Identify
	req = append(req, PNDCPServiceIdentify)
	// Service Type: Request
	req = append(req, 0x00)
	// Xid (transaction)
	req = append(req, 0x00, 0x00, 0x00, 0x01)
	// Response delay
	req = append(req, 0x00, 0x01)
	// DCPDataLength
	req = append(req, 0x00, 0x04)

	// Block: NameOfStation (option 0x02, suboption 0x02)
	req = append(req, 0xFF, 0xFF) // All devices
	req = append(req, 0x00, 0x00) // Block length

	return req
}

// parseDCPResponse parses a DCP Identify response.
func parseDCPResponse(data []byte) *PROFINETDevice {
	if len(data) < 12 {
		return nil
	}

	frameID := binary.BigEndian.Uint16(data[0:2])
	if frameID != PNDCPFrameIDIdentifyResp {
		return nil
	}

	dev := &PROFINETDevice{}

	// Parse DCP blocks
	pos := 12
	for pos+4 <= len(data) {
		option := data[pos]
		suboption := data[pos+1]
		blockLen := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4

		if pos+int(blockLen) > len(data) {
			break
		}

		blockData := data[pos : pos+int(blockLen)]

		switch {
		case option == PNDCPOptionIPAddr && suboption == PNDCPSuboptionIPParam:
			if len(blockData) >= 14 {
				// Skip block info (2 bytes)
				dev.IPAddress = fmt.Sprintf("%d.%d.%d.%d", blockData[2], blockData[3], blockData[4], blockData[5])
				dev.SubnetMask = fmt.Sprintf("%d.%d.%d.%d", blockData[6], blockData[7], blockData[8], blockData[9])
				dev.Gateway = fmt.Sprintf("%d.%d.%d.%d", blockData[10], blockData[11], blockData[12], blockData[13])
			}
		case option == PNDCPOptionDevProp && suboption == PNDCPSuboptionNameOfStation:
			if len(blockData) > 2 {
				dev.NameOfStation = string(blockData[2:])
			}
		case option == PNDCPOptionDevProp && suboption == PNDCPSuboptionDeviceID:
			if len(blockData) >= 6 {
				dev.VendorID = binary.BigEndian.Uint16(blockData[2:4])
				dev.DeviceID = binary.BigEndian.Uint16(blockData[4:6])
			}
		case option == PNDCPOptionDevProp && suboption == PNDCPSuboptionDeviceRole:
			if len(blockData) >= 3 {
				dev.DeviceRole = blockData[2]
				dev.DeviceRoleName = pnDeviceRoleName(blockData[2])
			}
		}

		pos += int(blockLen)
		// Align to 2-byte boundary
		if blockLen%2 != 0 {
			pos++
		}
	}

	return dev
}

// ParseLLDP parses an LLDP frame for network topology mapping - READ ONLY.
func ParseLLDP(data []byte) (*LLDPInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short for LLDP")
	}

	info := &LLDPInfo{}
	pos := 0

	for pos+2 <= len(data) {
		tlvHeader := binary.BigEndian.Uint16(data[pos : pos+2])
		tlvType := tlvHeader >> 9
		tlvLen := int(tlvHeader & 0x01FF)
		pos += 2

		if pos+tlvLen > len(data) {
			break
		}

		tlvData := data[pos : pos+tlvLen]

		switch tlvType {
		case 0: // End of LLDPDU
			return info, nil
		case 1: // Chassis ID
			if len(tlvData) > 1 {
				info.ChassisID = fmt.Sprintf("%x", tlvData[1:])
			}
		case 2: // Port ID
			if len(tlvData) > 1 {
				info.PortID = string(tlvData[1:])
			}
		case 3: // TTL
			if len(tlvData) >= 2 {
				info.TTL = binary.BigEndian.Uint16(tlvData)
			}
		case 4: // Port Description
			info.PortDesc = string(tlvData)
		case 5: // System Name
			info.SystemName = string(tlvData)
		case 6: // System Description
			info.SystemDesc = string(tlvData)
		case 8: // Management Address
			if len(tlvData) > 2 {
				info.MgmtAddr = fmt.Sprintf("%d.%d.%d.%d", tlvData[2], tlvData[3], tlvData[4], tlvData[5])
			}
		}

		pos += tlvLen
	}

	return info, nil
}

// pnDeviceRoleName converts a PROFINET device role byte to a name.
func pnDeviceRoleName(role byte) string {
	switch role {
	case 0x01:
		return "IO Device"
	case 0x02:
		return "IO Controller"
	case 0x04:
		return "IO Supervisor"
	default:
		return fmt.Sprintf("Unknown (0x%02X)", role)
	}
}
