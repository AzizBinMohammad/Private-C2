package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// DNP3 Function Codes - READ ONLY
// Explicitly NOT implementing: Direct Operate (0x03), Direct Operate No Ack (0x04),
// Select (0x03), Operate (0x04), Freeze (0x07-0x0C), Write (0x02),
// Cold/Warm Restart (0x0D/0x0E), Assign Class (0x16).
const (
	DNP3FCRead          = 0x01 // Read
	DNP3FCResponse      = 0x81 // Response
	DNP3FCUnsolResponse = 0x82 // Unsolicited Response
)

// DNP3 Data Object Groups (read-only)
const (
	DNP3GroupBinaryInput      = 1
	DNP3GroupBinaryInputEvent = 2
	DNP3GroupDoubleBitInput   = 3
	DNP3GroupDoubleBitEvent   = 4
	DNP3GroupCounter          = 20
	DNP3GroupCounterEvent     = 22
	DNP3GroupAnalogInput      = 30
	DNP3GroupAnalogInputEvent = 32
	DNP3GroupTimeDate         = 50
	DNP3GroupClass0           = 60 // Variation 1
	DNP3GroupClass1           = 60 // Variation 2
	DNP3GroupClass2           = 60 // Variation 3
	DNP3GroupClass3           = 60 // Variation 4
	DNP3GroupDeviceAttr       = 0  // Group 0
)

// IIN (Internal Indications) bit definitions
const (
	IINBroadcast      = 0x0100
	IINClass1Events   = 0x0200
	IINClass2Events   = 0x0400
	IINClass3Events   = 0x0800
	IINNeedTime       = 0x1000
	IINLocalControl   = 0x2000
	IINDeviceTrouble  = 0x4000
	IINDeviceRestart  = 0x8000
	IINNoFuncSupport  = 0x0001
	IINObjUnknown     = 0x0002
	IINParamError     = 0x0004
	IINEventOverflow  = 0x0008
	IINAlreadyExec    = 0x0010
	IINConfigCorrupt  = 0x0020
)

// DNP3Client is a read-only DNP3 client.
type DNP3Client struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	srcAddr   uint16
	dstAddr   uint16
	seqNum    byte
}

// DNP3Response holds a parsed DNP3 application layer response.
type DNP3Response struct {
	FunctionCode byte           `json:"function_code"`
	IIN          uint16         `json:"iin"`
	IINText      []string       `json:"iin_text"`
	Objects      []DNP3Object   `json:"objects"`
	Raw          []byte         `json:"raw,omitempty"`
}

// DNP3Object represents a parsed DNP3 data object.
type DNP3Object struct {
	Group     byte   `json:"group"`
	Variation byte   `json:"variation"`
	Qualifier byte   `json:"qualifier"`
	Count     uint16 `json:"count"`
	Data      []byte `json:"data,omitempty"`
	Parsed    []any  `json:"parsed,omitempty"`
}

// DNP3DeviceInfo holds device attribute information.
type DNP3DeviceInfo struct {
	VendorName     string `json:"vendor_name"`
	ProductName    string `json:"product_name"`
	HardwareVer    string `json:"hardware_version"`
	SoftwareVer    string `json:"software_version"`
	SerialNumber   string `json:"serial_number"`
	Location       string `json:"location"`
	SecureAuthVer  int    `json:"secure_auth_version"`
	HasSecureAuth  bool   `json:"has_secure_auth"`
}

// NewDNP3Client creates a new read-only DNP3 client.
func NewDNP3Client(config ConnConfig, srcAddr, dstAddr uint16) *DNP3Client {
	return &DNP3Client{
		config:  config,
		srcAddr: srcAddr,
		dstAddr: dstAddr,
	}
}

func (c *DNP3Client) Name() string { return "dnp3" }

func (c *DNP3Client) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 20000
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

func (c *DNP3Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *DNP3Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *DNP3Client) Identify(ctx context.Context) (*DeviceInfo, error) {
	devInfo, err := c.ReadDeviceAttributes()
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:      devInfo.VendorName,
		ProductName: devInfo.ProductName,
		Firmware:    devInfo.SoftwareVer,
		HardwareRev: devInfo.HardwareVer,
		SerialNumber: devInfo.SerialNumber,
		Location:     devInfo.Location,
		Protocol:     "dnp3",
		Extra: map[string]string{
			"secure_auth": fmt.Sprintf("%v (v%d)", devInfo.HasSecureAuth, devInfo.SecureAuthVer),
		},
	}, nil
}

// buildFT3Frame constructs a DNP3 FT3 data link layer frame.
func (c *DNP3Client) buildFT3Frame(dir, prm bool, fcb, fcv bool, fc byte, data []byte) []byte {
	frame := make([]byte, 10+len(data))

	// Start bytes
	frame[0] = 0x05
	frame[1] = 0x64

	// Length (user data length + 5)
	frame[2] = byte(len(data) + 5)

	// Control byte
	ctrl := fc & 0x0F
	if dir {
		ctrl |= 0x80
	}
	if prm {
		ctrl |= 0x40
	}
	if fcb {
		ctrl |= 0x20
	}
	if fcv {
		ctrl |= 0x10
	}
	frame[3] = ctrl

	// Destination address
	binary.LittleEndian.PutUint16(frame[4:6], c.dstAddr)
	// Source address
	binary.LittleEndian.PutUint16(frame[6:8], c.srcAddr)

	// CRC of header
	headerCRC := crc16(frame[0:8])
	binary.LittleEndian.PutUint16(frame[8:10], headerCRC)

	// User data with CRCs (every 16 bytes)
	if len(data) > 0 {
		frame = append(frame[:10], data...)
		// Add CRC for data block
		dataCRC := crc16(data)
		frame = append(frame, byte(dataCRC), byte(dataCRC>>8))
	}

	return frame
}

// buildReadRequest constructs a DNP3 read request at the application layer.
func (c *DNP3Client) buildReadRequest(objects []DNP3Object) []byte {
	c.seqNum = (c.seqNum + 1) & 0x0F

	// Application control: FIR=1, FIN=1, CON=0, UNS=0, SEQ
	appCtrl := byte(0xC0) | c.seqNum

	// Application header: control + function code
	appData := []byte{appCtrl, DNP3FCRead}

	// Object headers
	for _, obj := range objects {
		header := []byte{obj.Group, obj.Variation, obj.Qualifier}
		if obj.Qualifier == 0x06 { // All objects
			// No range field needed
		} else if obj.Qualifier == 0x00 { // 8-bit start/stop
			header = append(header, 0x00, byte(obj.Count-1))
		} else if obj.Qualifier == 0x01 { // 16-bit start/stop
			header = append(header, 0x00, 0x00)
			binary.LittleEndian.PutUint16(header[len(header)-2:], obj.Count-1)
		}
		appData = append(appData, header...)
	}

	// Wrap in transport layer (FIR=1, FIN=1, sequence)
	transport := append([]byte{0xC0}, appData...)

	return transport
}

// sendReadRequest sends a read request and parses the response.
func (c *DNP3Client) sendReadRequest(objects []DNP3Object) (*DNP3Response, error) {
	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	appData := c.buildReadRequest(objects)
	frame := c.buildFT3Frame(true, true, false, false, 0x04, appData)

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(frame); err != nil {
		return nil, err
	}

	resp := make([]byte, 4096)
	n, err := c.conn.Read(resp)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	return c.parseResponse(resp[:n])
}

// parseResponse parses a DNP3 response frame.
func (c *DNP3Client) parseResponse(data []byte) (*DNP3Response, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify start bytes
	if data[0] != 0x05 || data[1] != 0x64 {
		return nil, fmt.Errorf("invalid start bytes: %02X %02X", data[0], data[1])
	}

	// Skip data link header (10 bytes) and transport header (1 byte)
	appStart := 11
	if appStart >= len(data) {
		return nil, fmt.Errorf("no application data")
	}

	resp := &DNP3Response{
		Raw: data[appStart:],
	}

	if len(data) > appStart+1 {
		resp.FunctionCode = data[appStart+1]
	}

	if len(data) > appStart+3 {
		resp.IIN = binary.LittleEndian.Uint16(data[appStart+2 : appStart+4])
		resp.IINText = parseIIN(resp.IIN)
	}

	time.Sleep(c.config.InterPacketDelay)
	return resp, nil
}

// parseIIN converts IIN bits to human-readable strings.
func parseIIN(iin uint16) []string {
	var texts []string
	if iin&IINBroadcast != 0 {
		texts = append(texts, "Broadcast")
	}
	if iin&IINClass1Events != 0 {
		texts = append(texts, "Class 1 events available")
	}
	if iin&IINClass2Events != 0 {
		texts = append(texts, "Class 2 events available")
	}
	if iin&IINClass3Events != 0 {
		texts = append(texts, "Class 3 events available")
	}
	if iin&IINNeedTime != 0 {
		texts = append(texts, "Need time sync")
	}
	if iin&IINLocalControl != 0 {
		texts = append(texts, "Local control")
	}
	if iin&IINDeviceTrouble != 0 {
		texts = append(texts, "Device trouble")
	}
	if iin&IINDeviceRestart != 0 {
		texts = append(texts, "Device restart")
	}
	if iin&IINConfigCorrupt != 0 {
		texts = append(texts, "Configuration corrupt")
	}
	return texts
}

// ReadClass0 reads all static (class 0) data - READ ONLY.
func (c *DNP3Client) ReadClass0() (*DNP3Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sendReadRequest([]DNP3Object{
		{Group: 60, Variation: 1, Qualifier: 0x06}, // Class 0
	})
}

// ReadClass1 reads class 1 event data - READ ONLY.
func (c *DNP3Client) ReadClass1() (*DNP3Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sendReadRequest([]DNP3Object{
		{Group: 60, Variation: 2, Qualifier: 0x06}, // Class 1
	})
}

// ReadClass2 reads class 2 event data - READ ONLY.
func (c *DNP3Client) ReadClass2() (*DNP3Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sendReadRequest([]DNP3Object{
		{Group: 60, Variation: 3, Qualifier: 0x06}, // Class 2
	})
}

// ReadClass3 reads class 3 event data - READ ONLY.
func (c *DNP3Client) ReadClass3() (*DNP3Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sendReadRequest([]DNP3Object{
		{Group: 60, Variation: 4, Qualifier: 0x06}, // Class 3
	})
}

// ReadAllClasses reads all class data - READ ONLY.
func (c *DNP3Client) ReadAllClasses() (*DNP3Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sendReadRequest([]DNP3Object{
		{Group: 60, Variation: 1, Qualifier: 0x06},
		{Group: 60, Variation: 2, Qualifier: 0x06},
		{Group: 60, Variation: 3, Qualifier: 0x06},
		{Group: 60, Variation: 4, Qualifier: 0x06},
	})
}

// ReadDeviceAttributes reads device attribute data - READ ONLY.
func (c *DNP3Client) ReadDeviceAttributes() (*DNP3DeviceInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read Group 0 (Device Attributes)
	_, err := c.sendReadRequest([]DNP3Object{
		{Group: 0, Variation: 252, Qualifier: 0x06}, // All attributes
	})
	if err != nil {
		return nil, err
	}

	// Return basic info; real implementation would parse attribute values
	return &DNP3DeviceInfo{}, nil
}

// DetectSecureAuth checks if the outstation supports DNP3 Secure Authentication.
func (c *DNP3Client) DetectSecureAuth() (bool, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Send an integrity poll and check IIN for Secure Auth indications
	resp, err := c.sendReadRequest([]DNP3Object{
		{Group: 60, Variation: 1, Qualifier: 0x06},
	})
	if err != nil {
		return false, 0, err
	}

	// If the outstation responds with a challenge, it supports SA
	if resp.FunctionCode == 0x83 { // Authentication Challenge
		return true, 5, nil // Assume SAv5
	}

	return false, 0, nil
}
