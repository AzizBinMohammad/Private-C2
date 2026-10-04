package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// EtherNet/IP Encapsulation Commands
const (
	EIPCmdListIdentity    = 0x0063
	EIPCmdListInterfaces  = 0x0064
	EIPCmdListServices    = 0x0004
	EIPCmdRegisterSession = 0x0065
	EIPCmdSendRRData      = 0x006F
)

// CIP Service Codes - READ ONLY
// Explicitly NOT implementing: Set_Attribute_Single (0x10), Set_Attribute_All (0x02),
// Forward_Open for I/O connections, Reset, Create, Delete.
const (
	CIPGetAttributeAll    = 0x01
	CIPGetAttributeSingle = 0x0E
)

// CIP Object Class IDs
const (
	CIPClassIdentity     = 0x01
	CIPClassTCPIP        = 0xF5
	CIPClassEthernetLink = 0xF6
)

// SAFETY: EtherNet/IP client implements ONLY read-only operations.
// Explicitly NOT implementing: Set_Attribute, Forward_Open for I/O,
// Reset Service, any CIP write services.

// EtherNetIPClient is a read-only EtherNet/IP CIP client.
type EtherNetIPClient struct {
	conn       net.Conn
	target     string
	port       int
	config     ConnConfig
	mu         sync.Mutex
	connected  bool
	sessionID  uint32
	context    uint64
}

// EIPIdentity holds ListIdentity response data.
type EIPIdentity struct {
	VendorID       uint16 `json:"vendor_id"`
	VendorName     string `json:"vendor_name"`
	DeviceType     uint16 `json:"device_type"`
	DeviceTypeName string `json:"device_type_name"`
	ProductCode    uint16 `json:"product_code"`
	MajorRevision  byte   `json:"major_revision"`
	MinorRevision  byte   `json:"minor_revision"`
	SerialNumber   uint32 `json:"serial_number"`
	ProductName    string `json:"product_name"`
	State          byte   `json:"state"`
	Status         uint16 `json:"status"`
	IP             string `json:"ip"`
}

// EIPService describes an available EtherNet/IP service.
type EIPService struct {
	TypeCode    uint16 `json:"type_code"`
	Name        string `json:"name"`
	CapFlags    uint16 `json:"capability_flags"`
	TCPPort     uint16 `json:"tcp_port"`
	UDPPort     uint16 `json:"udp_port"`
}

// CIPAttributeData holds data read from a CIP object attribute.
type CIPAttributeData struct {
	ClassID    uint16 `json:"class_id"`
	InstanceID uint16 `json:"instance_id"`
	AttrID     uint16 `json:"attr_id,omitempty"`
	Data       []byte `json:"data"`
	Status     byte   `json:"status"`
}

// NewEtherNetIPClient creates a new read-only EtherNet/IP client.
func NewEtherNetIPClient(config ConnConfig) *EtherNetIPClient {
	return &EtherNetIPClient{
		config: config,
	}
}

func (c *EtherNetIPClient) Name() string { return "ethernetip" }

func (c *EtherNetIPClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 44818
	}

	conn, err := tcpConnect(target, port, c.config.Timeout)
	if err != nil {
		return err
	}
	c.conn = conn
	c.target = target
	c.port = port
	c.connected = true
	return nil
}

func (c *EtherNetIPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *EtherNetIPClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *EtherNetIPClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	identity, err := c.ListIdentity()
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, fmt.Errorf("no identity response")
	}
	return &DeviceInfo{
		Vendor:       identity.VendorName,
		ProductName:  identity.ProductName,
		Firmware:     fmt.Sprintf("%d.%d", identity.MajorRevision, identity.MinorRevision),
		SerialNumber: fmt.Sprintf("%08X", identity.SerialNumber),
		Protocol:     "ethernetip",
		Extra: map[string]string{
			"vendor_id":    fmt.Sprintf("%d", identity.VendorID),
			"device_type":  identity.DeviceTypeName,
			"product_code": fmt.Sprintf("%d", identity.ProductCode),
		},
	}, nil
}

// buildEncapHeader constructs an EtherNet/IP encapsulation header.
func (c *EtherNetIPClient) buildEncapHeader(cmd uint16, dataLen int) []byte {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint16(header[0:2], cmd)
	binary.LittleEndian.PutUint16(header[2:4], uint16(dataLen))
	binary.LittleEndian.PutUint32(header[4:8], c.sessionID)
	// Status, sender context, options all zero
	return header
}

// ListIdentity sends a ListIdentity request - READ ONLY.
func (c *EtherNetIPClient) ListIdentity() (*EIPIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	header := c.buildEncapHeader(EIPCmdListIdentity, 0)

	resp, err := sendAndReceive(c.conn, header, 1024, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	if len(resp) < 26 {
		return nil, fmt.Errorf("ListIdentity response too short")
	}

	// Parse encapsulation header
	cmd := binary.LittleEndian.Uint16(resp[0:2])
	if cmd != EIPCmdListIdentity {
		return nil, fmt.Errorf("unexpected response command: 0x%04X", cmd)
	}

	// Parse identity items
	identity := &EIPIdentity{}

	// Skip encap header (24) + item count (2) + item type (2) + item length (2)
	pos := 30
	if pos+2 > len(resp) {
		return identity, nil
	}

	// Protocol version (skip 2)
	pos += 2

	// Socket address (skip 16)
	if pos+16 <= len(resp) {
		// Extract IP from socket address
		if pos+8 <= len(resp) {
			ip := fmt.Sprintf("%d.%d.%d.%d", resp[pos+4], resp[pos+5], resp[pos+6], resp[pos+7])
			identity.IP = ip
		}
		pos += 16
	}

	// Vendor ID
	if pos+2 <= len(resp) {
		identity.VendorID = binary.LittleEndian.Uint16(resp[pos : pos+2])
		identity.VendorName = lookupCIPVendor(identity.VendorID)
		pos += 2
	}

	// Device Type
	if pos+2 <= len(resp) {
		identity.DeviceType = binary.LittleEndian.Uint16(resp[pos : pos+2])
		identity.DeviceTypeName = lookupCIPDeviceType(identity.DeviceType)
		pos += 2
	}

	// Product Code
	if pos+2 <= len(resp) {
		identity.ProductCode = binary.LittleEndian.Uint16(resp[pos : pos+2])
		pos += 2
	}

	// Revision
	if pos+2 <= len(resp) {
		identity.MajorRevision = resp[pos]
		identity.MinorRevision = resp[pos+1]
		pos += 2
	}

	// Status
	if pos+2 <= len(resp) {
		identity.Status = binary.LittleEndian.Uint16(resp[pos : pos+2])
		pos += 2
	}

	// Serial Number
	if pos+4 <= len(resp) {
		identity.SerialNumber = binary.LittleEndian.Uint32(resp[pos : pos+4])
		pos += 4
	}

	// Product Name
	if pos+1 <= len(resp) {
		nameLen := int(resp[pos])
		pos++
		if pos+nameLen <= len(resp) {
			identity.ProductName = string(resp[pos : pos+nameLen])
			pos += nameLen
		}
	}

	// State
	if pos+1 <= len(resp) {
		identity.State = resp[pos]
	}

	time.Sleep(c.config.InterPacketDelay)
	return identity, nil
}

// ListServices sends a ListServices request - READ ONLY.
func (c *EtherNetIPClient) ListServices() ([]EIPService, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	header := c.buildEncapHeader(EIPCmdListServices, 0)

	resp, err := sendAndReceive(c.conn, header, 1024, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	if len(resp) < 26 {
		return nil, fmt.Errorf("ListServices response too short")
	}

	var services []EIPService

	// Parse item count
	if len(resp) >= 26 {
		itemCount := binary.LittleEndian.Uint16(resp[24:26])
		pos := 26
		for i := 0; i < int(itemCount) && pos+4 <= len(resp); i++ {
			svc := EIPService{}
			svc.TypeCode = binary.LittleEndian.Uint16(resp[pos : pos+2])
			itemLen := binary.LittleEndian.Uint16(resp[pos+2 : pos+4])
			pos += 4
			if pos+int(itemLen) <= len(resp) && itemLen >= 20 {
				svc.CapFlags = binary.LittleEndian.Uint16(resp[pos+2 : pos+4])
				nameBytes := resp[pos+4 : pos+int(itemLen)]
				svc.Name = sanitizeString(nameBytes)
			}
			pos += int(itemLen)
			services = append(services, svc)
		}
	}

	return services, nil
}

// ListInterfaces sends a ListInterfaces request - READ ONLY.
func (c *EtherNetIPClient) ListInterfaces() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	header := c.buildEncapHeader(EIPCmdListInterfaces, 0)

	resp, err := sendAndReceive(c.conn, header, 1024, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// GetIdentityObject reads the Identity CIP object (Class 0x01) - READ ONLY.
func (c *EtherNetIPClient) GetIdentityObject() (*CIPAttributeData, error) {
	return c.GetAttributeAll(CIPClassIdentity, 1)
}

// GetTCPIPObject reads the TCP/IP Interface CIP object (Class 0xF5) - READ ONLY.
func (c *EtherNetIPClient) GetTCPIPObject() (*CIPAttributeData, error) {
	return c.GetAttributeAll(CIPClassTCPIP, 1)
}

// GetEthernetLinkObject reads the Ethernet Link CIP object (Class 0xF6) - READ ONLY.
func (c *EtherNetIPClient) GetEthernetLinkObject() (*CIPAttributeData, error) {
	return c.GetAttributeAll(CIPClassEthernetLink, 1)
}

// GetAttributeAll reads all attributes of a CIP object - READ ONLY.
func (c *EtherNetIPClient) GetAttributeAll(classID, instanceID uint16) (*CIPAttributeData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	// Register session first if needed
	if c.sessionID == 0 {
		if err := c.registerSession(); err != nil {
			return nil, fmt.Errorf("session registration failed: %w", err)
		}
	}

	// Build CIP request
	cipPath := []byte{
		0x20, byte(classID),      // Class segment
		0x24, byte(instanceID),   // Instance segment
	}

	cipReq := []byte{CIPGetAttributeAll}
	cipReq = append(cipReq, byte(len(cipPath)/2)) // Path size in words
	cipReq = append(cipReq, cipPath...)

	// Wrap in SendRRData
	sendRR := c.buildSendRRData(cipReq)
	resp, err := sendAndReceive(c.conn, sendRR, 2048, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	result := &CIPAttributeData{
		ClassID:    classID,
		InstanceID: instanceID,
	}

	if len(resp) > 24 {
		result.Data = resp[24:]
	}

	time.Sleep(c.config.InterPacketDelay)
	return result, nil
}

// registerSession registers an EtherNet/IP session.
func (c *EtherNetIPClient) registerSession() error {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint16(data[0:2], 1) // Protocol version 1
	// Options flags: 0

	header := c.buildEncapHeader(EIPCmdRegisterSession, len(data))
	packet := append(header, data...)

	resp, err := sendAndReceive(c.conn, packet, 256, c.config.Timeout)
	if err != nil {
		return err
	}

	if len(resp) < 8 {
		return fmt.Errorf("register session response too short")
	}

	c.sessionID = binary.LittleEndian.Uint32(resp[4:8])
	return nil
}

// buildSendRRData wraps CIP data in a SendRRData encapsulation.
func (c *EtherNetIPClient) buildSendRRData(cipData []byte) []byte {
	// Common Packet Format: 2 items
	// Item 1: Null Address (type 0x0000, length 0)
	// Item 2: Unconnected Data (type 0x00B2, length = cipData length)
	cpf := make([]byte, 0, 10+len(cipData))
	cpf = append(cpf, 0x00, 0x00, 0x00, 0x00) // Interface handle + timeout
	cpf = append(cpf, 0x02, 0x00)               // Item count: 2

	// Null Address item
	cpf = append(cpf, 0x00, 0x00) // Type: Null
	cpf = append(cpf, 0x00, 0x00) // Length: 0

	// Unconnected Data item
	cpf = append(cpf, 0xB2, 0x00) // Type: Unconnected Data
	itemLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(itemLen, uint16(len(cipData)))
	cpf = append(cpf, itemLen...)
	cpf = append(cpf, cipData...)

	header := c.buildEncapHeader(EIPCmdSendRRData, len(cpf))
	return append(header, cpf...)
}

// lookupCIPVendor returns vendor name for a CIP vendor ID.
func lookupCIPVendor(id uint16) string {
	vendors := map[uint16]string{
		1:    "Rockwell Automation",
		2:    "Namco Controls",
		5:    "Parker Hannifin",
		9:    "Danaher Controls",
		12:   "Schneider Electric",
		40:   "Turck",
		43:   "Molex",
		44:   "Beckhoff Automation",
		48:   "Siemens",
		50:   "ODVA",
		67:   "Pilz",
		69:   "WAGO",
		88:   "ABB",
		100:  "GE Fanuc",
		283:  "Phoenix Contact",
		291:  "Omron",
		529:  "Banner Engineering",
		674:  "HMS Industrial",
		748:  "Honeywell",
		1177: "Emerson",
	}
	if name, ok := vendors[id]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", id)
}

// lookupCIPDeviceType returns device type name for a CIP device type ID.
func lookupCIPDeviceType(id uint16) string {
	types := map[uint16]string{
		0:   "Generic Device",
		2:   "AC Drive",
		3:   "Motor Overload",
		4:   "Limit Switch",
		5:   "Inductive Proximity Switch",
		6:   "Photoelectric Sensor",
		7:   "General Purpose Discrete I/O",
		12:  "Communications Adapter",
		14:  "Programmable Logic Controller",
		27:  "AC/DC Drive",
		33:  "Human-Machine Interface",
		43:  "Mass Flow Controller",
		50:  "Safety Discrete I/O Device",
	}
	if name, ok := types[id]; ok {
		return name
	}
	return fmt.Sprintf("Device Type %d", id)
}

// sanitizeString cleans up CIP string data.
func sanitizeString(data []byte) string {
	var result []byte
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result = append(result, b)
		}
	}
	return string(result)
}
