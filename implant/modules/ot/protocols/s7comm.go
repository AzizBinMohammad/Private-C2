package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// S7Comm area identifiers for READ operations.
const (
	S7AreaDB = 0x84 // Data blocks
	S7AreaMK = 0x83 // Merker (flags)
	S7AreaIN = 0x81 // Inputs
	S7AreaOUT = 0x82 // Outputs
	S7AreaCT = 0x1C // Counters
	S7AreaTM = 0x1D // Timers
)

// SZL (System Status List) IDs for READ operations.
const (
	SZL0011 = 0x0011 // Module Identification
	SZL001C = 0x001C // Component Identification
	SZL0019 = 0x0019 // Module Status
	SZL0014 = 0x0014 // CPU Diagnostics
	SZL0074 = 0x0074 // LED Status
	SZL0222 = 0x0222 // Interrupt Status
	SZL0132 = 0x0132 // Communication Settings
)

// SAFETY: S7Comm client implements ONLY read-only operations.
// Explicitly NOT implementing: Write (0x05), Start/Stop CPU (0x28/0x29),
// Download Block (0x1A/0x1B/0x1C), PLC Password operations.

// S7Client is a read-only S7Comm client.
type S7Client struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	pduRef    uint16
}

// S7CPUInfo holds S7 PLC identification data.
type S7CPUInfo struct {
	ModuleType    string `json:"module_type"`
	SerialNumber  string `json:"serial_number"`
	ASName        string `json:"as_name"`
	ModuleName    string `json:"module_name"`
	Copyright     string `json:"copyright"`
	PlantID       string `json:"plant_id"`
	HardwareRev   string `json:"hardware_rev"`
	FirmwareRev   string `json:"firmware_rev"`
	MemorySerial  string `json:"memory_serial"`
	OrderCode     string `json:"order_code"`
}

// S7MemoryData holds data read from PLC memory areas.
type S7MemoryData struct {
	Area     byte   `json:"area"`
	DBNumber uint16 `json:"db_number"`
	Start    uint16 `json:"start"`
	Length   uint16 `json:"length"`
	Data     []byte `json:"data"`
}

// S7SZLEntry holds an SZL list entry.
type S7SZLEntry struct {
	SZLID  uint16         `json:"szl_id"`
	Index  uint16         `json:"index"`
	Fields map[string]any `json:"fields"`
	Raw    []byte         `json:"raw"`
}

// NewS7Client creates a new read-only S7Comm client.
func NewS7Client(config ConnConfig) *S7Client {
	return &S7Client{
		config: config,
	}
}

func (c *S7Client) Name() string { return "s7comm" }

func (c *S7Client) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 102
	}

	conn, err := tcpConnect(target, port, c.config.Timeout)
	if err != nil {
		return err
	}
	c.conn = conn
	c.target = target
	c.port = port

	// COTP Connection Request
	if err := c.cotpConnect(); err != nil {
		conn.Close()
		return fmt.Errorf("COTP connection failed: %w", err)
	}

	// S7Comm Setup Communication
	if err := c.s7Setup(); err != nil {
		conn.Close()
		return fmt.Errorf("S7 setup failed: %w", err)
	}

	c.connected = true
	return nil
}

func (c *S7Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *S7Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *S7Client) Identify(ctx context.Context) (*DeviceInfo, error) {
	cpuInfo, err := c.ReadCPUInfo()
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:       "Siemens",
		ProductName:  cpuInfo.ModuleType,
		Model:        cpuInfo.OrderCode,
		Firmware:     cpuInfo.FirmwareRev,
		SerialNumber: cpuInfo.SerialNumber,
		HardwareRev:  cpuInfo.HardwareRev,
		Description:  cpuInfo.ModuleName,
		Protocol:     "s7comm",
		Extra: map[string]string{
			"as_name":       cpuInfo.ASName,
			"plant_id":      cpuInfo.PlantID,
			"memory_serial": cpuInfo.MemorySerial,
		},
	}, nil
}

// cotpConnect sends a COTP Connection Request and reads the response.
func (c *S7Client) cotpConnect() error {
	// TPKT Header (4) + COTP CR PDU
	req := []byte{
		// TPKT Header
		0x03, 0x00, 0x00, 0x16, // Version 3, length 22
		// COTP Connection Request
		0x11,       // Length indicator: 17
		0xE0,       // PDU type: CR
		0x00, 0x00, // Destination reference
		0x00, 0x01, // Source reference
		0x00,       // Class 0
		// Parameters
		0xC0, 0x01, 0x0A, // TPDU size: 1024
		0xC1, 0x02, 0x01, 0x00, // Source TSAP: 0x0100
		0xC2, 0x02, 0x01, 0x02, // Destination TSAP: 0x0102 (Rack 0, Slot 2)
	}

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 256)
	n, err := c.conn.Read(resp)
	if err != nil {
		return err
	}
	if n < 7 {
		return fmt.Errorf("COTP response too short")
	}

	// Check for CC (Connection Confirm)
	if resp[5] != 0xD0 {
		return fmt.Errorf("COTP connection rejected: PDU type 0x%02X", resp[5])
	}

	return nil
}

// s7Setup sends the S7 Setup Communication request.
func (c *S7Client) s7Setup() error {
	req := []byte{
		// TPKT Header
		0x03, 0x00, 0x00, 0x19, // Version 3, length 25
		// COTP Data
		0x02, 0xF0, 0x80, // DT Data, TPDU number 0, last data unit
		// S7 Header
		0x32,       // Protocol ID
		0x01,       // ROSCTR: Job (1)
		0x00, 0x00, // Redundancy identification
		0x00, 0x00, // PDU reference
		0x00, 0x08, // Parameter length
		0x00, 0x00, // Data length
		// S7 Setup Communication parameters
		0xF0,       // Function: Setup Communication
		0x00,       // Reserved
		0x00, 0x01, // Max AmQ calling
		0x00, 0x01, // Max AmQ called
		0x01, 0xE0, // PDU size: 480
	}

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 512)
	n, err := c.conn.Read(resp)
	if err != nil {
		return err
	}
	if n < 12 {
		return fmt.Errorf("S7 setup response too short")
	}

	// Verify S7 header
	if resp[7] != 0x32 {
		return fmt.Errorf("invalid S7 protocol ID: 0x%02X", resp[7])
	}

	return nil
}

// nextPDURef returns an incrementing PDU reference.
func (c *S7Client) nextPDURef() uint16 {
	c.pduRef++
	return c.pduRef
}

// ReadSZL reads a System Status List - READ ONLY.
func (c *S7Client) ReadSZL(szlID, szlIndex uint16) ([]S7SZLEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	pduRef := c.nextPDURef()

	// Build SZL read request
	req := []byte{
		// TPKT Header
		0x03, 0x00, 0x00, 0x21, // Version 3, length 33
		// COTP Data
		0x02, 0xF0, 0x80,
		// S7 Header
		0x32, 0x07, // Protocol ID, ROSCTR: Userdata
		0x00, 0x00, // Redundancy
		0x00, 0x00, // PDU ref (filled below)
		0x00, 0x08, // Parameter length
		0x00, 0x08, // Data length
		// S7 Userdata parameter
		0x00, 0x01, 0x12, // Parameter head
		0x04,       // Parameter length
		0x11,       // Method: Request
		0x44,       // Type/Group: SZL
		0x01,       // Subfunction: Read SZL
		0x00,       // Sequence number
		// S7 Userdata data
		0xFF,       // Return code
		0x09,       // Transport size
		0x00, 0x04, // Data length
		0x00, 0x00, // SZL ID (filled below)
		0x00, 0x00, // SZL Index (filled below)
	}

	binary.BigEndian.PutUint16(req[11:13], pduRef)
	binary.BigEndian.PutUint16(req[29:31], szlID)
	binary.BigEndian.PutUint16(req[31:33], szlIndex)

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(req); err != nil {
		return nil, err
	}

	resp := make([]byte, 2048)
	n, err := c.conn.Read(resp)
	if err != nil {
		return nil, err
	}
	if n < 27 {
		return nil, fmt.Errorf("SZL response too short: %d bytes", n)
	}

	// Parse SZL response data
	var entries []S7SZLEntry

	// Data starts after headers; the exact offset depends on the response
	dataStart := 27
	if dataStart >= n {
		return entries, nil
	}

	// Read SZL header from data portion
	if dataStart+4 > n {
		return entries, nil
	}
	respSZLID := binary.BigEndian.Uint16(resp[dataStart : dataStart+2])
	szlLen := binary.BigEndian.Uint16(resp[dataStart+2 : dataStart+4])

	if szlLen == 0 {
		return entries, nil
	}

	pos := dataStart + 4
	for pos+int(szlLen) <= n {
		entry := S7SZLEntry{
			SZLID:  respSZLID,
			Fields: make(map[string]any),
			Raw:    make([]byte, szlLen),
		}
		copy(entry.Raw, resp[pos:pos+int(szlLen)])

		if szlLen >= 2 {
			entry.Index = binary.BigEndian.Uint16(resp[pos : pos+2])
		}

		entries = append(entries, entry)
		pos += int(szlLen)
	}

	time.Sleep(c.config.InterPacketDelay)
	return entries, nil
}

// ReadCPUInfo reads CPU identification via SZL 0x001C - READ ONLY.
func (c *S7Client) ReadCPUInfo() (*S7CPUInfo, error) {
	entries, err := c.ReadSZL(SZL001C, 0x0000)
	if err != nil {
		return nil, err
	}

	info := &S7CPUInfo{}
	for _, e := range entries {
		if len(e.Raw) < 34 {
			continue
		}
		switch e.Index {
		case 0x0001: // Name of the PLC
			info.ModuleName = trimS7String(e.Raw[2:])
		case 0x0002: // Name of the module
			info.ModuleType = trimS7String(e.Raw[2:])
		case 0x0003: // Plant identification
			info.PlantID = trimS7String(e.Raw[2:])
		case 0x0004: // Copyright
			info.Copyright = trimS7String(e.Raw[2:])
		case 0x0005: // Serial number
			info.SerialNumber = trimS7String(e.Raw[2:])
		case 0x0007: // Module type name
			info.OrderCode = trimS7String(e.Raw[2:])
		}
	}

	// Also try SZL 0x0011 for module identification
	modEntries, err := c.ReadSZL(SZL0011, 0x0000)
	if err == nil {
		for _, e := range modEntries {
			if len(e.Raw) >= 28 {
				if e.Index == 0x0001 {
					info.OrderCode = trimS7String(e.Raw[2:22])
					info.HardwareRev = fmt.Sprintf("V%d", e.Raw[24])
					info.FirmwareRev = fmt.Sprintf("V%d.%d.%d", e.Raw[25], e.Raw[26], e.Raw[27])
				}
			}
		}
	}

	return info, nil
}

// ReadModuleStatus reads module status via SZL 0x0019 - READ ONLY.
func (c *S7Client) ReadModuleStatus() ([]S7SZLEntry, error) {
	return c.ReadSZL(SZL0019, 0x0000)
}

// ReadDiagnostics reads CPU diagnostics via SZL 0x0014 - READ ONLY.
func (c *S7Client) ReadDiagnostics() ([]S7SZLEntry, error) {
	return c.ReadSZL(SZL0014, 0x0000)
}

// ReadLEDStatus reads LED status via SZL 0x0074 - READ ONLY.
func (c *S7Client) ReadLEDStatus() ([]S7SZLEntry, error) {
	return c.ReadSZL(SZL0074, 0x0000)
}

// ReadCommSettings reads communication settings via SZL 0x0132 - READ ONLY.
func (c *S7Client) ReadCommSettings() ([]S7SZLEntry, error) {
	return c.ReadSZL(SZL0132, 0x0000)
}

// ReadArea reads data from a PLC memory area - READ ONLY.
func (c *S7Client) ReadArea(area byte, dbNumber, start, length uint16) (*S7MemoryData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	if length > 200 { // Limit read size for safety
		length = 200
	}

	pduRef := c.nextPDURef()

	// Calculate byte offset from bit address
	startByte := start
	startBit := byte(0)

	// Build S7 Read Variable request
	req := []byte{
		// TPKT Header
		0x03, 0x00, 0x00, 0x1F, // Version 3, length 31
		// COTP Data
		0x02, 0xF0, 0x80,
		// S7 Header
		0x32, 0x01, // Protocol ID, ROSCTR: Job
		0x00, 0x00, // Redundancy
		0x00, 0x00, // PDU ref (filled below)
		0x00, 0x0E, // Parameter length: 14
		0x00, 0x00, // Data length: 0
		// S7 Read Variable parameter
		0x04,       // Function: Read Variable
		0x01,       // Item count: 1
		// Item specification
		0x12,       // Variable specification
		0x0A,       // Length of following address spec
		0x10,       // Syntax ID: S7ANY
		0x02,       // Transport size: BYTE
		0x00, 0x00, // Length (filled below)
		0x00, 0x00, // DB number (filled below)
		0x00,       // Area (filled below)
		0x00, 0x00, 0x00, // Address: byte.bit (filled below)
	}

	binary.BigEndian.PutUint16(req[11:13], pduRef)
	binary.BigEndian.PutUint16(req[23:25], length)
	binary.BigEndian.PutUint16(req[25:27], dbNumber)
	req[27] = area

	// Address is encoded as byte*8 + bit in 3 bytes
	addr := uint32(startByte)*8 + uint32(startBit)
	req[28] = byte(addr >> 16)
	req[29] = byte(addr >> 8)
	req[30] = byte(addr)

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(req); err != nil {
		return nil, err
	}

	resp := make([]byte, 2048)
	n, err := c.conn.Read(resp)
	if err != nil {
		return nil, err
	}

	// Parse response
	if n < 21 {
		return nil, fmt.Errorf("read response too short: %d bytes", n)
	}

	// Check for error in S7 header
	if resp[7] != 0x32 {
		return nil, fmt.Errorf("invalid S7 protocol ID")
	}

	// Data starts at offset 18 (after headers), plus return code and transport size
	dataOffset := 21
	if dataOffset >= n {
		return nil, fmt.Errorf("no data in response")
	}

	returnCode := resp[dataOffset-4]
	if returnCode != 0xFF {
		return nil, fmt.Errorf("read error: return code 0x%02X", returnCode)
	}

	result := &S7MemoryData{
		Area:     area,
		DBNumber: dbNumber,
		Start:    start,
		Length:   length,
	}

	// Extract data bytes
	dataLen := binary.BigEndian.Uint16(resp[dataOffset-2 : dataOffset])
	if dataLen > 0 {
		actualLen := int(dataLen) / 8 // Convert bits to bytes
		if actualLen == 0 {
			actualLen = int(dataLen)
		}
		end := dataOffset + actualLen
		if end > n {
			end = n
		}
		result.Data = make([]byte, end-dataOffset)
		copy(result.Data, resp[dataOffset:end])
	}

	time.Sleep(c.config.InterPacketDelay)
	return result, nil
}

// ReadDB reads data from a data block - READ ONLY.
func (c *S7Client) ReadDB(dbNumber, start, length uint16) (*S7MemoryData, error) {
	return c.ReadArea(S7AreaDB, dbNumber, start, length)
}

// ReadMerkers reads merker (flag) data - READ ONLY.
func (c *S7Client) ReadMerkers(start, length uint16) (*S7MemoryData, error) {
	return c.ReadArea(S7AreaMK, 0, start, length)
}

// ReadInputs reads input data - READ ONLY.
func (c *S7Client) ReadInputs(start, length uint16) (*S7MemoryData, error) {
	return c.ReadArea(S7AreaIN, 0, start, length)
}

// ReadOutputs reads output data - READ ONLY.
func (c *S7Client) ReadOutputs(start, length uint16) (*S7MemoryData, error) {
	return c.ReadArea(S7AreaOUT, 0, start, length)
}

// trimS7String extracts a null-terminated string from S7 data.
func trimS7String(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
