package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// MELSEC SLMP Commands - READ ONLY
// Explicitly NOT implementing: Batch Write (0x1401), Remote Run (0x1001),
// Remote Stop (0x1002), Remote Reset (0x1006), any write operations.
const (
	MELSECCmdBatchRead     = 0x0401 // Device Read
	MELSECCmdCPUModelRead  = 0x0101 // Read CPU Model Name
	MELSECCmdCPUStatusRead = 0x0000 // Read CPU Status (via self-test)
)

// MELSEC Device Codes
const (
	MELSECDevD  = 0xA8 // Data Register
	MELSECDevM  = 0x90 // Internal Relay
	MELSECDevY  = 0x9D // Output
	MELSECDevX  = 0x9C // Input
	MELSECDevR  = 0xAF // File Register
	MELSECDevW  = 0xB4 // Link Register
	MELSECDevTS = 0xC1 // Timer (current value)
	MELSECDevCS = 0xC4 // Counter (current value)
)

// SAFETY: MELSEC client implements ONLY read operations.
// Explicitly NOT implementing: Batch Write (0x1401), Remote Run (0x1001),
// Remote Stop (0x1002), Remote Pause (0x1003), Remote Reset (0x1006),
// Remote Latch Clear (0x1005).

// MELSECClient is a read-only Mitsubishi MELSEC SLMP client.
type MELSECClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	serial    uint16
}

// MELSECCPUInfo holds Mitsubishi PLC CPU information.
type MELSECCPUInfo struct {
	ModelName string `json:"model_name"`
	CPUType   string `json:"cpu_type"`
	Status    string `json:"status"`
}

// MELSECDeviceData holds data read from PLC devices.
type MELSECDeviceData struct {
	DeviceCode byte   `json:"device_code"`
	DeviceName string `json:"device_name"`
	StartAddr  uint32 `json:"start_addr"`
	Count      uint16 `json:"count"`
	Data       []byte `json:"data"`
	Words      []uint16 `json:"words,omitempty"`
}

// NewMELSECClient creates a new read-only MELSEC SLMP client.
func NewMELSECClient(config ConnConfig) *MELSECClient {
	return &MELSECClient{
		config: config,
	}
}

func (c *MELSECClient) Name() string { return "melsec" }

func (c *MELSECClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 5007 // Common SLMP port
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

func (c *MELSECClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *MELSECClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *MELSECClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	cpuInfo, err := c.ReadCPUModel()
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:   "Mitsubishi Electric",
		Model:    cpuInfo.ModelName,
		Protocol: "melsec",
		Extra: map[string]string{
			"cpu_type": cpuInfo.CPUType,
		},
	}, nil
}

// buildSLMPFrame constructs an SLMP (Seamless Message Protocol) binary frame.
func (c *MELSECClient) buildSLMPFrame(cmd uint16, subCmd uint16, data []byte) []byte {
	c.serial++

	// SLMP binary header
	frame := make([]byte, 0, 20+len(data))

	// Subheader (binary: 0x5400 for request)
	frame = append(frame, 0x54, 0x00)

	// Serial number (2 bytes)
	sn := make([]byte, 2)
	binary.LittleEndian.PutUint16(sn, c.serial)
	frame = append(frame, sn...)

	// Reserved (2 bytes)
	frame = append(frame, 0x00, 0x00)

	// Network number (1 byte)
	frame = append(frame, 0x00)
	// Station number (1 byte)
	frame = append(frame, 0xFF)
	// Module I/O number (2 bytes)
	frame = append(frame, 0xFF, 0x03)
	// Module station number (1 byte)
	frame = append(frame, 0x00)

	// Data length (2 bytes) = timer(2) + command(2) + subcommand(2) + data
	dataLen := 2 + 2 + 2 + len(data)
	dl := make([]byte, 2)
	binary.LittleEndian.PutUint16(dl, uint16(dataLen))
	frame = append(frame, dl...)

	// Monitoring timer (2 bytes, x250ms)
	frame = append(frame, 0x10, 0x00) // 4 seconds

	// Command (2 bytes)
	cmdBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(cmdBytes, cmd)
	frame = append(frame, cmdBytes...)

	// Sub-command (2 bytes)
	subBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(subBytes, subCmd)
	frame = append(frame, subBytes...)

	// Command data
	frame = append(frame, data...)

	return frame
}

// sendCommand sends an SLMP command and reads the response.
func (c *MELSECClient) sendCommand(cmd, subCmd uint16, data []byte) ([]byte, error) {
	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	frame := c.buildSLMPFrame(cmd, subCmd, data)

	resp, err := sendAndReceive(c.conn, frame, 4096, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	// Parse SLMP response
	if len(resp) < 15 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	// Check subheader (0xD400 for response)
	if resp[0] != 0xD4 || resp[1] != 0x00 {
		return nil, fmt.Errorf("invalid response subheader: %02X%02X", resp[0], resp[1])
	}

	// End code at offset 13-14
	endCode := binary.LittleEndian.Uint16(resp[13:15])
	if endCode != 0x0000 {
		return nil, fmt.Errorf("SLMP error: end code 0x%04X", endCode)
	}

	time.Sleep(c.config.InterPacketDelay)

	// Return data after headers
	if len(resp) > 15 {
		return resp[15:], nil
	}
	return nil, nil
}

// BatchRead reads device data in batch - READ ONLY.
func (c *MELSECClient) BatchRead(deviceCode byte, startAddr uint32, count uint16) (*MELSECDeviceData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build read command data
	data := make([]byte, 6)

	// Start device address (3 bytes, little-endian)
	data[0] = byte(startAddr)
	data[1] = byte(startAddr >> 8)
	data[2] = byte(startAddr >> 16)

	// Device code (1 byte)
	data[3] = deviceCode

	// Number of device points (2 bytes)
	binary.LittleEndian.PutUint16(data[4:6], count)

	resp, err := c.sendCommand(MELSECCmdBatchRead, 0x0000, data)
	if err != nil {
		return nil, err
	}

	result := &MELSECDeviceData{
		DeviceCode: deviceCode,
		DeviceName: melsecDeviceName(deviceCode),
		StartAddr:  startAddr,
		Count:      count,
		Data:       resp,
	}

	// Parse words
	if len(resp) >= int(count)*2 {
		for i := 0; i < int(count); i++ {
			word := binary.LittleEndian.Uint16(resp[i*2 : i*2+2])
			result.Words = append(result.Words, word)
		}
	}

	return result, nil
}

// ReadCPUModel reads CPU model name - READ ONLY.
func (c *MELSECClient) ReadCPUModel() (*MELSECCPUInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(MELSECCmdCPUModelRead, 0x0000, nil)
	if err != nil {
		return nil, err
	}

	info := &MELSECCPUInfo{}
	if len(resp) >= 16 {
		// CPU model name is ASCII
		end := 16
		for i, b := range resp[:end] {
			if b == 0 {
				end = i
				break
			}
		}
		info.ModelName = string(resp[:end])
	}

	return info, nil
}

// ReadCPUStatus reads CPU operational status - READ ONLY.
func (c *MELSECClient) ReadCPUStatus() (*MELSECCPUInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Self-test / status read
	resp, err := c.sendCommand(0x0619, 0x0000, nil) // Read CPU status
	if err != nil {
		return nil, err
	}

	info := &MELSECCPUInfo{}
	if len(resp) >= 2 {
		switch resp[0] {
		case 0x00:
			info.Status = "RUN"
		case 0x01:
			info.Status = "STOP"
		case 0x02:
			info.Status = "PAUSE"
		default:
			info.Status = fmt.Sprintf("UNKNOWN(0x%02X)", resp[0])
		}
	}

	return info, nil
}

// melsecDeviceName returns a human-readable name for a device code.
func melsecDeviceName(code byte) string {
	names := map[byte]string{
		MELSECDevD:  "Data Register (D)",
		MELSECDevM:  "Internal Relay (M)",
		MELSECDevY:  "Output (Y)",
		MELSECDevX:  "Input (X)",
		MELSECDevR:  "File Register (R)",
		MELSECDevW:  "Link Register (W)",
		MELSECDevTS: "Timer (TS)",
		MELSECDevCS: "Counter (CS)",
	}
	if name, ok := names[code]; ok {
		return name
	}
	return fmt.Sprintf("Device 0x%02X", code)
}
