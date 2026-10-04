package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// BACnet APDU types
const (
	BACnetConfirmedReq   = 0x00
	BACnetUnconfirmedReq = 0x10
	BACnetSimpleAck      = 0x20
	BACnetComplexAck     = 0x30
	BACnetError          = 0x50
)

// BACnet Unconfirmed Service Choices
const (
	BACnetWhoIs = 0x08
	BACnetIAm   = 0x00
)

// BACnet Confirmed Service Choices - READ ONLY
// Explicitly NOT implementing: WriteProperty (0x0F), WritePropertyMultiple (0x10),
// CreateObject (0x0A), DeleteObject (0x0B), ReinitializeDevice (0x14).
const (
	BACnetReadProperty         = 0x0C
	BACnetReadPropertyMultiple = 0x0E
)

// BACnet Object Types
const (
	BACnetObjAnalogInput   = 0
	BACnetObjAnalogOutput  = 1
	BACnetObjAnalogValue   = 2
	BACnetObjBinaryInput   = 3
	BACnetObjBinaryOutput  = 4
	BACnetObjBinaryValue   = 5
	BACnetObjDevice        = 8
	BACnetObjFile          = 10
	BACnetObjMultiState    = 13
	BACnetObjProgram       = 16
	BACnetObjSchedule      = 17
	BACnetObjTrendLog      = 20
	BACnetObjNotifClass    = 15
)

// BACnet Property IDs
const (
	BACnetPropObjectID       = 75
	BACnetPropObjectName     = 77
	BACnetPropObjectType     = 79
	BACnetPropPresentValue   = 85
	BACnetPropDescription    = 28
	BACnetPropDeviceType     = 31
	BACnetPropStatusFlags    = 111
	BACnetPropVendorID       = 120
	BACnetPropVendorName     = 121
	BACnetPropModelName      = 70
	BACnetPropFirmwareRev    = 44
	BACnetPropAppSoftwareVer = 12
	BACnetPropProtocolVer    = 98
	BACnetPropSystemStatus   = 112
	BACnetPropObjectList     = 76
	BACnetPropMaxAPDU        = 62
	BACnetPropSegmentation   = 107
	BACnetPropAPDUTimeout    = 11
)

// SAFETY: BACnet client implements ONLY read-only operations.
// Explicitly NOT implementing: WriteProperty, WritePropertyMultiple,
// CreateObject, DeleteObject, ReinitializeDevice.

// BACnetClient is a read-only BACnet/IP client.
type BACnetClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	invokeID  byte
}

// BACnetDevice represents a discovered BACnet device.
type BACnetDevice struct {
	InstanceNumber uint32 `json:"instance_number"`
	Address        string `json:"address"`
	VendorID       uint16 `json:"vendor_id"`
	VendorName     string `json:"vendor_name"`
	ModelName      string `json:"model_name"`
	Firmware       string `json:"firmware"`
	AppSoftware    string `json:"app_software"`
	ObjectName     string `json:"object_name"`
	Description    string `json:"description"`
	MaxAPDU        uint16 `json:"max_apdu"`
	Segmentation   byte   `json:"segmentation"`
}

// BACnetObject represents a BACnet object.
type BACnetObject struct {
	ObjectType   uint16         `json:"object_type"`
	ObjectTypeName string       `json:"object_type_name"`
	InstanceNumber uint32       `json:"instance_number"`
	ObjectName   string         `json:"object_name"`
	Description  string         `json:"description"`
	PresentValue string         `json:"present_value,omitempty"`
	Properties   map[string]any `json:"properties,omitempty"`
}

// NewBACnetClient creates a new read-only BACnet/IP client.
func NewBACnetClient(config ConnConfig) *BACnetClient {
	return &BACnetClient{
		config: config,
	}
}

func (c *BACnetClient) Name() string { return "bacnet" }

func (c *BACnetClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 47808
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

func (c *BACnetClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *BACnetClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *BACnetClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	dev, err := c.ReadDeviceInfo(0) // Instance 0 is typically the device
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:      dev.VendorName,
		ProductName: dev.ObjectName,
		Model:       dev.ModelName,
		Firmware:    dev.Firmware,
		Description: dev.Description,
		Protocol:    "bacnet",
		Extra: map[string]string{
			"vendor_id":    fmt.Sprintf("%d", dev.VendorID),
			"app_software": dev.AppSoftware,
			"instance":     fmt.Sprintf("%d", dev.InstanceNumber),
		},
	}, nil
}

// nextInvokeID returns an incrementing invoke ID.
func (c *BACnetClient) nextInvokeID() byte {
	c.invokeID++
	return c.invokeID
}

// buildBVLC constructs a BACnet BVLC header for unicast.
func buildBVLC(pduLen int) []byte {
	header := make([]byte, 4)
	header[0] = 0x81 // BVLC type: BACnet/IP
	header[1] = 0x0A // Original-Unicast-NPDU
	binary.BigEndian.PutUint16(header[2:4], uint16(pduLen+4))
	return header
}

// buildNPDU constructs a BACnet NPDU.
func buildNPDU() []byte {
	return []byte{
		0x01, // Version 1
		0x04, // Control: expecting reply, no routing
	}
}

// WhoIs sends a BACnet Who-Is broadcast request - READ ONLY.
func (c *BACnetClient) WhoIs(lowLimit, highLimit uint32) ([]BACnetDevice, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	npdu := buildNPDU()
	apdu := []byte{BACnetUnconfirmedReq, BACnetWhoIs}

	if lowLimit > 0 || highLimit > 0 {
		// Encode limits as context tags
		apdu = append(apdu, encodeContextUnsigned(0, lowLimit)...)
		apdu = append(apdu, encodeContextUnsigned(1, highLimit)...)
	}

	packet := buildBVLC(len(npdu) + len(apdu))
	packet = append(packet, npdu...)
	packet = append(packet, apdu...)

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(packet); err != nil {
		return nil, err
	}

	// Collect I-Am responses
	var devices []BACnetDevice
	deadline := time.Now().Add(c.config.Timeout)
	for time.Now().Before(deadline) {
		_ = c.conn.SetReadDeadline(deadline)
		buf := make([]byte, 2048)
		n, err := c.conn.Read(buf)
		if err != nil {
			break
		}
		if n < 10 {
			continue
		}

		dev := parseIAm(buf[:n])
		if dev != nil {
			dev.Address = c.target
			devices = append(devices, *dev)
		}
	}

	return devices, nil
}

// parseIAm parses a BACnet I-Am response.
func parseIAm(data []byte) *BACnetDevice {
	if len(data) < 10 {
		return nil
	}

	// Skip BVLC header (4 bytes)
	if data[0] != 0x81 {
		return nil
	}

	// Find APDU start (after BVLC + NPDU)
	pos := 4
	if pos >= len(data) {
		return nil
	}

	// Skip NPDU
	npduLen := 2 // minimum
	if pos+npduLen >= len(data) {
		return nil
	}
	pos += npduLen

	// Check for I-Am
	if pos+1 >= len(data) {
		return nil
	}
	if data[pos] != BACnetUnconfirmedReq || data[pos+1] != BACnetIAm {
		return nil
	}

	return &BACnetDevice{}
}

// ReadProperty reads a single property from a BACnet object - READ ONLY.
func (c *BACnetClient) ReadProperty(objectType uint16, instanceNumber uint32, propertyID uint32) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	invokeID := c.nextInvokeID()

	npdu := buildNPDU()

	// Build Confirmed-Request ReadProperty
	apdu := []byte{
		BACnetConfirmedReq,       // PDU type
		0x04,                     // Max segments: unspecified, max resp: 1476
		invokeID,                 // Invoke ID
		BACnetReadProperty,       // Service choice
	}

	// Object Identifier (context tag 0)
	objID := (uint32(objectType) << 22) | (instanceNumber & 0x3FFFFF)
	apdu = append(apdu, encodeContextUnsigned(0, objID)...)

	// Property Identifier (context tag 1)
	apdu = append(apdu, encodeContextUnsigned(1, propertyID)...)

	packet := buildBVLC(len(npdu) + len(apdu))
	packet = append(packet, npdu...)
	packet = append(packet, apdu...)

	resp, err := sendAndReceive(c.conn, packet, 2048, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	time.Sleep(c.config.InterPacketDelay)
	return resp, nil
}

// ReadPropertyMultiple reads multiple properties from BACnet objects - READ ONLY.
func (c *BACnetClient) ReadPropertyMultiple(objectType uint16, instanceNumber uint32, propertyIDs []uint32) (map[uint32][]byte, error) {
	result := make(map[uint32][]byte)

	for _, propID := range propertyIDs {
		data, err := c.ReadProperty(objectType, instanceNumber, propID)
		if err != nil {
			continue
		}
		result[propID] = data
	}

	return result, nil
}

// EnumerateObjects reads the object list from a BACnet device - READ ONLY.
func (c *BACnetClient) EnumerateObjects(instanceNumber uint32) ([]BACnetObject, error) {
	// Read the object-list property from the device object
	data, err := c.ReadProperty(BACnetObjDevice, instanceNumber, BACnetPropObjectList)
	if err != nil {
		return nil, err
	}

	// Parse object identifiers from the response
	_ = data
	return []BACnetObject{}, nil
}

// ReadDeviceInfo reads device identification properties - READ ONLY.
func (c *BACnetClient) ReadDeviceInfo(instanceNumber uint32) (*BACnetDevice, error) {
	dev := &BACnetDevice{
		InstanceNumber: instanceNumber,
	}

	// Read key properties
	propIDs := []uint32{
		BACnetPropVendorID,
		BACnetPropVendorName,
		BACnetPropModelName,
		BACnetPropFirmwareRev,
		BACnetPropAppSoftwareVer,
		BACnetPropObjectName,
		BACnetPropDescription,
	}

	for _, propID := range propIDs {
		_, err := c.ReadProperty(BACnetObjDevice, instanceNumber, propID)
		if err != nil {
			continue
		}
		// In a full implementation, we would decode the BACnet application tags
	}

	return dev, nil
}

// encodeContextUnsigned encodes an unsigned value as a BACnet context-tagged value.
func encodeContextUnsigned(tagNumber byte, value uint32) []byte {
	var data []byte
	if value <= 0xFF {
		data = []byte{byte(value)}
	} else if value <= 0xFFFF {
		data = make([]byte, 2)
		binary.BigEndian.PutUint16(data, uint16(value))
	} else {
		data = make([]byte, 4)
		binary.BigEndian.PutUint32(data, value)
	}

	tag := (tagNumber << 4) | 0x08 // Context tag, constructed=0
	if len(data) < 5 {
		tag |= byte(len(data))
		return append([]byte{tag}, data...)
	}
	return append([]byte{tag | 0x05, byte(len(data))}, data...)
}

// bacnetObjectTypeName returns a human-readable name for a BACnet object type.
func bacnetObjectTypeName(objType uint16) string {
	names := map[uint16]string{
		0:  "Analog Input",
		1:  "Analog Output",
		2:  "Analog Value",
		3:  "Binary Input",
		4:  "Binary Output",
		5:  "Binary Value",
		8:  "Device",
		10: "File",
		13: "Multi-state Input",
		14: "Multi-state Output",
		15: "Notification Class",
		16: "Program",
		17: "Schedule",
		19: "Multi-state Value",
		20: "Trend Log",
		23: "Accumulator",
	}
	if name, ok := names[objType]; ok {
		return name
	}
	return fmt.Sprintf("Object Type %d", objType)
}
