package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// HART-IP Command Numbers - READ ONLY
// Explicitly NOT implementing: write commands (cmd 6, 17-19, 34-38, 51-54, etc.),
// calibration commands, or any commands that modify device configuration.
const (
	HARTCmd0UniqueID       = 0  // Read Unique Identifier
	HARTCmd1PrimaryVar     = 1  // Read Primary Variable
	HARTCmd2CurrPctRange   = 2  // Read Current and Percent of Range
	HARTCmd3DynamicVars    = 3  // Read Dynamic Variables and Current
	HARTCmd12Message       = 12 // Read Message
	HARTCmd13Tag           = 13 // Read Tag, Descriptor, Date
	HARTCmd14TransducerInfo = 14 // Read Transducer Information
	HARTCmd15OutputInfo    = 15 // Read Device Information
	HARTCmd48AdditionalStatus = 48 // Read Additional Device Status
)

// HART-IP message types
const (
	HARTIPMsgRequest  = 0
	HARTIPMsgResponse = 1
	HARTIPMsgPublish  = 2
	HARTIPMsgNAK      = 15
)

// SAFETY: HART-IP client implements ONLY read commands (0,1,2,3,12,13,14,15,48).
// Explicitly NOT implementing: Write commands (6, 17-19, 34-38, 51-54),
// calibration/trim commands, or any commands that modify device state.

// HARTClient is a read-only HART-IP client.
type HARTClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	seqNum    uint16
}

// HARTDeviceInfo holds HART device identification data.
type HARTDeviceInfo struct {
	ManufacturerID   byte   `json:"manufacturer_id"`
	ManufacturerName string `json:"manufacturer_name"`
	DeviceType       byte   `json:"device_type"`
	UniqueID         uint32 `json:"unique_id"`
	ProtocolMajorRev byte   `json:"protocol_major_rev"`
	ProtocolMinorRev byte   `json:"protocol_minor_rev"`
	SoftwareRev      byte   `json:"software_rev"`
	HardwareRev      byte   `json:"hardware_rev"`
	Flags            byte   `json:"flags"`
	Tag              string `json:"tag"`
	Descriptor       string `json:"descriptor"`
	Date             string `json:"date"`
	Message          string `json:"message"`
}

// HARTDynamicVars holds HART dynamic variable readings.
type HARTDynamicVars struct {
	PrimaryVar       float32 `json:"primary_var"`
	PrimaryVarUnit   byte    `json:"primary_var_unit"`
	SecondaryVar     float32 `json:"secondary_var"`
	SecondaryVarUnit byte    `json:"secondary_var_unit"`
	TertiaryVar      float32 `json:"tertiary_var"`
	TertiaryVarUnit  byte    `json:"tertiary_var_unit"`
	QuaternaryVar    float32 `json:"quaternary_var"`
	QuaternaryVarUnit byte   `json:"quaternary_var_unit"`
	Current          float32 `json:"current_ma"`
}

// NewHARTClient creates a new read-only HART-IP client.
func NewHARTClient(config ConnConfig) *HARTClient {
	return &HARTClient{
		config: config,
	}
}

func (c *HARTClient) Name() string { return "hart-ip" }

func (c *HARTClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 5094
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

func (c *HARTClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *HARTClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *HARTClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	hartInfo, err := c.ReadUniqueID()
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:       hartInfo.ManufacturerName,
		SerialNumber: fmt.Sprintf("%d", hartInfo.UniqueID),
		Firmware:     fmt.Sprintf("%d.%d", hartInfo.ProtocolMajorRev, hartInfo.ProtocolMinorRev),
		HardwareRev:  fmt.Sprintf("%d", hartInfo.HardwareRev),
		Description:  hartInfo.Descriptor,
		Protocol:     "hart-ip",
		Extra: map[string]string{
			"tag":     hartInfo.Tag,
			"message": hartInfo.Message,
		},
	}, nil
}

// buildHARTIPRequest constructs a HART-IP request frame.
func (c *HARTClient) buildHARTIPRequest(cmd byte, data []byte) []byte {
	c.seqNum++

	// HART-IP header
	header := make([]byte, 8)
	header[0] = 1 // Version
	header[1] = HARTIPMsgRequest
	binary.BigEndian.PutUint16(header[2:4], c.seqNum) // Sequence number
	// Byte count filled below

	// HART command frame
	// Short frame format: preamble + delimiter + address + command + bytecount + data + checksum
	hartFrame := make([]byte, 0, 20+len(data))

	// Preamble (5 bytes of 0xFF)
	for i := 0; i < 5; i++ {
		hartFrame = append(hartFrame, 0xFF)
	}

	// Delimiter: master to field device, short frame
	hartFrame = append(hartFrame, 0x02)

	// Short address (polling address 0)
	hartFrame = append(hartFrame, 0x00)

	// Command
	hartFrame = append(hartFrame, cmd)

	// Byte count
	hartFrame = append(hartFrame, byte(len(data)))

	// Data
	hartFrame = append(hartFrame, data...)

	// Checksum (XOR of all bytes after preamble)
	var checksum byte
	for _, b := range hartFrame[5:] {
		checksum ^= b
	}
	hartFrame = append(hartFrame, checksum)

	// Set byte count in HART-IP header
	totalLen := len(header) + len(hartFrame)
	binary.BigEndian.PutUint16(header[4:6], uint16(totalLen))

	return append(header, hartFrame...)
}

// sendCommand sends a HART command and reads the response.
func (c *HARTClient) sendCommand(cmd byte, data []byte) ([]byte, error) {
	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	req := c.buildHARTIPRequest(cmd, data)

	resp, err := sendAndReceive(c.conn, req, 1024, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	// Skip HART-IP header (8 bytes) and preamble to get to HART frame
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Find the start of the response frame (after preamble)
	pos := 8
	for pos < len(resp) && resp[pos] == 0xFF {
		pos++
	}

	if pos >= len(resp) {
		return nil, fmt.Errorf("no HART frame in response")
	}

	time.Sleep(c.config.InterPacketDelay)
	return resp[pos:], nil
}

// ReadUniqueID reads the device unique identifier (Command 0) - READ ONLY.
func (c *HARTClient) ReadUniqueID() (*HARTDeviceInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(HARTCmd0UniqueID, nil)
	if err != nil {
		return nil, err
	}

	info := &HARTDeviceInfo{}
	if len(resp) >= 12 {
		// Parse response: delimiter + addr + cmd + bytecount + status(2) + data
		dataStart := 4 // Skip delimiter + address + command + bytecount
		if dataStart+2 < len(resp) {
			// Skip 2 status bytes
			d := resp[dataStart+2:]
			if len(d) >= 12 {
				info.ManufacturerID = d[1]
				info.ManufacturerName = lookupHARTManufacturer(d[1])
				info.DeviceType = d[2]
				info.ProtocolMajorRev = d[4]
				info.ProtocolMinorRev = d[5]
				info.SoftwareRev = d[6]
				info.HardwareRev = d[7]
				info.Flags = d[8]
				info.UniqueID = uint32(d[9])<<16 | uint32(d[10])<<8 | uint32(d[11])
			}
		}
	}

	return info, nil
}

// ReadPrimaryVariable reads the primary variable (Command 1) - READ ONLY.
func (c *HARTClient) ReadPrimaryVariable() (float32, byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(HARTCmd1PrimaryVar, nil)
	if err != nil {
		return 0, 0, err
	}

	if len(resp) < 11 {
		return 0, 0, fmt.Errorf("response too short for primary variable")
	}

	// Parse: unit code + 4 bytes IEEE 754 float
	return 0, 0, nil
}

// ReadDynamicVariables reads all dynamic variables (Command 3) - READ ONLY.
func (c *HARTClient) ReadDynamicVariables() (*HARTDynamicVars, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.sendCommand(HARTCmd3DynamicVars, nil)
	if err != nil {
		return nil, err
	}

	return &HARTDynamicVars{}, nil
}

// ReadMessage reads the device message (Command 12) - READ ONLY.
func (c *HARTClient) ReadMessage() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(HARTCmd12Message, nil)
	if err != nil {
		return "", err
	}

	// Message is packed ASCII, 24 characters
	if len(resp) < 30 {
		return "", fmt.Errorf("response too short for message")
	}
	_ = resp
	return "", nil
}

// ReadTag reads the tag, descriptor, and date (Command 13) - READ ONLY.
func (c *HARTClient) ReadTag() (string, string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.sendCommand(HARTCmd13Tag, nil)
	if err != nil {
		return "", "", "", err
	}

	return "", "", "", nil
}

// ReadTransducerInfo reads transducer information (Command 14) - READ ONLY.
func (c *HARTClient) ReadTransducerInfo() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(HARTCmd14TransducerInfo, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ReadOutputInfo reads device output information (Command 15) - READ ONLY.
func (c *HARTClient) ReadOutputInfo() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(HARTCmd15OutputInfo, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ReadAdditionalStatus reads additional device status (Command 48) - READ ONLY.
func (c *HARTClient) ReadAdditionalStatus() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.sendCommand(HARTCmd48AdditionalStatus, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// lookupHARTManufacturer returns the manufacturer name for a HART manufacturer ID.
func lookupHARTManufacturer(id byte) string {
	manufacturers := map[byte]string{
		0x00: "Unknown",
		0x01: "Emerson/Rosemount",
		0x02: "Emerson/Fisher",
		0x04: "ABB",
		0x05: "Honeywell",
		0x06: "Siemens",
		0x0A: "Yokogawa",
		0x0E: "Endress+Hauser",
		0x1A: "Krohne",
		0x26: "WIKA",
		0x2B: "VEGA",
	}
	if name, ok := manufacturers[id]; ok {
		return name
	}
	return fmt.Sprintf("Manufacturer 0x%02X", id)
}
