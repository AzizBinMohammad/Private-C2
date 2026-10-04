package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// FINS Command Codes - READ ONLY
// Explicitly NOT implementing: Memory Area Write (0x0102), Memory Area Fill (0x0103),
// Memory Area Transfer (0x0104), CPU Run/Stop (0x0401/0x0402), any write operations.
const (
	FINSCmdMemoryAreaRead  = 0x0101 // Memory Area Read
	FINSCmdCPUUnitDataRead = 0x0501 // CPU Unit Data Read
	FINSCmdCPUStatusRead   = 0x0601 // CPU Unit Status Read
	FINSCmdClockRead       = 0x0701 // Clock Read
	FINSCmdNetworkStatus   = 0x0620 // Network Status Read
)

// FINS Memory Area Codes
const (
	FINSAreaCIO = 0x30 // CIO (Core I/O)
	FINSAreaWR  = 0x31 // Work Area
	FINSAreaHR  = 0x32 // Holding Area
	FINSAreaAR  = 0x33 // Auxiliary Area
	FINSAreaDM  = 0x02 // Data Memory
	FINSAreaEM  = 0x20 // Extended Memory
	FINSAreaTK  = 0x06 // Task Flag
)

// SAFETY: FINS client implements ONLY read operations.
// Explicitly NOT implementing: Memory Area Write (0x0102), Fill (0x0103),
// Transfer (0x0104), CPU Run (0x0401), CPU Stop (0x0402),
// Program Area Write/Clear, File operations.

// FINSClient is a read-only Omron FINS client.
type FINSClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	sid       byte
	srcNode   byte
	dstNode   byte
}

// FINSCPUInfo holds Omron PLC CPU information.
type FINSCPUInfo struct {
	Model      string `json:"model"`
	Version    string `json:"version"`
	InternalVer string `json:"internal_version"`
	AreaData   []byte `json:"area_data,omitempty"`
}

// FINSCPUStatus holds CPU status information.
type FINSCPUStatus struct {
	RunMode    string `json:"run_mode"`
	FatalError bool   `json:"fatal_error"`
	NonFatal   bool   `json:"non_fatal"`
	MessageOn  bool   `json:"message_on"`
	Batteries  byte   `json:"batteries"`
	ErrorCode  uint16 `json:"error_code"`
}

// FINSMemoryData holds data read from PLC memory.
type FINSMemoryData struct {
	AreaCode byte   `json:"area_code"`
	Address  uint16 `json:"address"`
	BitPos   byte   `json:"bit_pos"`
	Count    uint16 `json:"count"`
	Data     []byte `json:"data"`
}

// FINSClock holds PLC clock data.
type FINSClock struct {
	Year   byte `json:"year"`
	Month  byte `json:"month"`
	Day    byte `json:"day"`
	Hour   byte `json:"hour"`
	Minute byte `json:"minute"`
	Second byte `json:"second"`
	DayOfWeek byte `json:"day_of_week"`
}

// NewFINSClient creates a new read-only FINS client.
func NewFINSClient(config ConnConfig, srcNode, dstNode byte) *FINSClient {
	return &FINSClient{
		config:  config,
		srcNode: srcNode,
		dstNode: dstNode,
	}
}

func (c *FINSClient) Name() string { return "fins" }

func (c *FINSClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 9600
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

func (c *FINSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *FINSClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *FINSClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	cpuInfo, err := c.ReadCPUUnitData()
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:   "Omron",
		Model:    cpuInfo.Model,
		Firmware: cpuInfo.Version,
		Protocol: "fins",
	}, nil
}

// buildFINSFrame constructs a FINS/UDP frame.
func (c *FINSClient) buildFINSFrame(cmdCode uint16, data []byte) []byte {
	c.sid++

	frame := make([]byte, 0, 34+len(data))

	// FINS/UDP header (for FINS/TCP, the framing is different)
	// ICF: 0x80 (command, response required)
	frame = append(frame, 0x80)
	// RSV: 0x00
	frame = append(frame, 0x00)
	// GCT: 0x02 (gateway count)
	frame = append(frame, 0x02)
	// DNA: Destination Network Address (0 = local)
	frame = append(frame, 0x00)
	// DA1: Destination Node Address
	frame = append(frame, c.dstNode)
	// DA2: Destination Unit Address (0 = CPU)
	frame = append(frame, 0x00)
	// SNA: Source Network Address
	frame = append(frame, 0x00)
	// SA1: Source Node Address
	frame = append(frame, c.srcNode)
	// SA2: Source Unit Address
	frame = append(frame, 0x00)
	// SID: Service ID
	frame = append(frame, c.sid)

	// Command code (2 bytes, big-endian)
	cmd := make([]byte, 2)
	binary.BigEndian.PutUint16(cmd, cmdCode)
	frame = append(frame, cmd...)

	// Command data
	frame = append(frame, data...)

	return frame
}

// sendCommand sends a FINS command and reads the response.
func (c *FINSClient) sendCommand(cmdCode uint16, data []byte) ([]byte, error) {
	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	frame := c.buildFINSFrame(cmdCode, data)

	resp, err := sendAndReceive(c.conn, frame, 2048, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	if len(resp) < 14 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	// Check response code (bytes 12-13, after FINS header)
	endCode := binary.BigEndian.Uint16(resp[12:14])
	if endCode != 0x0000 {
		return nil, fmt.Errorf("FINS error: end code 0x%04X", endCode)
	}

	time.Sleep(c.config.InterPacketDelay)

	// Return data after header + response code
	if len(resp) > 14 {
		return resp[14:], nil
	}
	return nil, nil
}

// ReadMemoryArea reads PLC memory area - READ ONLY.
func (c *FINSClient) ReadMemoryArea(areaCode byte, address uint16, bitPos byte, count uint16) (*FINSMemoryData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build command data
	data := make([]byte, 6)
	data[0] = areaCode
	binary.BigEndian.PutUint16(data[1:3], address)
	data[3] = bitPos
	binary.BigEndian.PutUint16(data[4:6], count)

	resp, err := c.sendCommand(FINSCmdMemoryAreaRead, data)
	if err != nil {
		return nil, err
	}

	return &FINSMemoryData{
		AreaCode: areaCode,
		Address:  address,
		BitPos:   bitPos,
		Count:    count,
		Data:     resp,
	}, nil
}

// ReadCPUUnitData reads CPU unit model and version - READ ONLY.
func (c *FINSClient) ReadCPUUnitData() (*FINSCPUInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(FINSCmdCPUUnitDataRead, nil)
	if err != nil {
		return nil, err
	}

	info := &FINSCPUInfo{
		AreaData: resp,
	}

	if len(resp) >= 40 {
		info.Model = trimNullString(resp[0:20])
		info.Version = trimNullString(resp[20:40])
	}

	return info, nil
}

// ReadCPUStatus reads CPU status - READ ONLY.
func (c *FINSClient) ReadCPUStatus() (*FINSCPUStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(FINSCmdCPUStatusRead, nil)
	if err != nil {
		return nil, err
	}

	status := &FINSCPUStatus{}
	if len(resp) >= 2 {
		mode := resp[0]
		switch mode {
		case 0x00:
			status.RunMode = "PROGRAM"
		case 0x01:
			status.RunMode = "DEBUG"
		case 0x02:
			status.RunMode = "MONITOR"
		case 0x04:
			status.RunMode = "RUN"
		default:
			status.RunMode = fmt.Sprintf("UNKNOWN(0x%02X)", mode)
		}
		status.FatalError = resp[1]&0x01 != 0
		status.NonFatal = resp[1]&0x02 != 0
	}

	return status, nil
}

// ReadClock reads the PLC clock - READ ONLY.
func (c *FINSClient) ReadClock() (*FINSClock, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(FINSCmdClockRead, nil)
	if err != nil {
		return nil, err
	}

	clock := &FINSClock{}
	if len(resp) >= 7 {
		clock.Year = resp[0]
		clock.Month = resp[1]
		clock.Day = resp[2]
		clock.Hour = resp[3]
		clock.Minute = resp[4]
		clock.Second = resp[5]
		clock.DayOfWeek = resp[6]
	}

	return clock, nil
}

// ReadNetworkStatus reads network status - READ ONLY.
func (c *FINSClient) ReadNetworkStatus() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sendCommand(FINSCmdNetworkStatus, nil)
}

// trimNullString extracts a string from FINS data, removing trailing nulls and spaces.
func trimNullString(data []byte) string {
	end := len(data)
	for end > 0 && (data[end-1] == 0x00 || data[end-1] == ' ') {
		end--
	}
	return string(data[:end])
}
