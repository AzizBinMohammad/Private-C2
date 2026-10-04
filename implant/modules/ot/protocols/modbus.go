package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

// Modbus function codes - READ ONLY
// Explicitly NOT implementing: FC05 (Write Single Coil), FC06 (Write Single Register),
// FC15 (Write Multiple Coils), FC16 (Write Multiple Registers),
// FC22 (Mask Write Register), FC23 (Read/Write Multiple Registers)
const (
	ModbusFCReadCoils              = 0x01
	ModbusFCReadDiscreteInputs     = 0x02
	ModbusFCReadHoldingRegisters   = 0x03
	ModbusFCReadInputRegisters     = 0x04
	ModbusFCReadExceptionStatus    = 0x07
	ModbusFCDiagnostics            = 0x08
	ModbusFCGetCommEventCounter    = 0x0B
	ModbusFCGetCommEventLog        = 0x0C
	ModbusFCReportServerID         = 0x11
	ModbusFCReadDeviceID           = 0x2B
	// Sub-function for diagnostics - ONLY 00 (Return Query Data) is allowed
	ModbusDiagReturnQueryData      = 0x0000
)

// ModbusClient is a read-only Modbus TCP client.
type ModbusClient struct {
	conn     net.Conn
	target   string
	port     int
	config   ConnConfig
	mu       sync.Mutex
	txnID    uint16
	connected bool
}

// ModbusRegisterData holds register read results.
type ModbusRegisterData struct {
	UnitID     byte     `json:"unit_id"`
	Function   byte     `json:"function"`
	StartAddr  uint16   `json:"start_addr"`
	Count      uint16   `json:"count"`
	RawValues  []uint16 `json:"raw_values"`
	Interpreted []ModbusValue `json:"interpreted,omitempty"`
}

// ModbusValue represents an interpreted register value.
type ModbusValue struct {
	Address    uint16  `json:"address"`
	RawUint16  uint16  `json:"raw_uint16"`
	AsInt16    int16   `json:"as_int16"`
	AsFloat32  float32 `json:"as_float32,omitempty"`
	BitValues  []bool  `json:"bit_values,omitempty"`
}

// ModbusDeviceID holds device identification from FC43/14.
type ModbusDeviceID struct {
	VendorName     string `json:"vendor_name"`
	ProductCode    string `json:"product_code"`
	MajorMinorRev  string `json:"major_minor_rev"`
	VendorURL      string `json:"vendor_url,omitempty"`
	ProductName    string `json:"product_name,omitempty"`
	ModelName      string `json:"model_name,omitempty"`
	UserAppName    string `json:"user_app_name,omitempty"`
}

// NewModbusClient creates a new read-only Modbus TCP client.
func NewModbusClient(config ConnConfig) *ModbusClient {
	return &ModbusClient{
		config: config,
	}
}

func (c *ModbusClient) Name() string { return "modbus" }

func (c *ModbusClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 502
	}

	conn, err := tcpConnect(target, port, c.config.Timeout)
	if err != nil {
		return err
	}

	c.conn = conn
	c.target = target
	c.port = port
	c.connected = true
	c.txnID = 0
	return nil
}

func (c *ModbusClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *ModbusClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *ModbusClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	devID, err := c.ReadDeviceIdentification(1, 0x00)
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:      devID.VendorName,
		ProductName: devID.ProductName,
		Model:       devID.ModelName,
		Firmware:    devID.MajorMinorRev,
		Protocol:    "modbus",
		Extra: map[string]string{
			"product_code": devID.ProductCode,
			"vendor_url":   devID.VendorURL,
		},
	}, nil
}

// nextTxnID returns the next transaction ID.
func (c *ModbusClient) nextTxnID() uint16 {
	c.txnID++
	return c.txnID
}

// buildMBAPHeader constructs a Modbus TCP MBAP header.
func (c *ModbusClient) buildMBAPHeader(unitID byte, pduLen int) []byte {
	txn := c.nextTxnID()
	header := make([]byte, 7)
	binary.BigEndian.PutUint16(header[0:2], txn)     // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x0000)   // Protocol ID (Modbus)
	binary.BigEndian.PutUint16(header[4:6], uint16(pduLen+1)) // Length (PDU + Unit ID)
	header[6] = unitID
	return header
}

// sendRequest sends a Modbus request and reads the response.
func (c *ModbusClient) sendRequest(unitID byte, pdu []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	header := c.buildMBAPHeader(unitID, len(pdu))
	packet := append(header, pdu...)

	resp, err := sendAndReceive(c.conn, packet, 260, c.config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("modbus request failed: %w", err)
	}

	if len(resp) < 9 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	// Check for exception response
	if resp[7]&0x80 != 0 {
		excCode := byte(0)
		if len(resp) > 8 {
			excCode = resp[8]
		}
		return nil, fmt.Errorf("modbus exception: FC=0x%02X code=0x%02X", resp[7]&0x7F, excCode)
	}

	time.Sleep(c.config.InterPacketDelay)
	return resp[7:], nil // Return from function code onward
}

// ReadCoils reads coils (FC01) - READ ONLY.
func (c *ModbusClient) ReadCoils(unitID byte, startAddr, count uint16) (*ModbusRegisterData, error) {
	if count == 0 || count > 2000 {
		return nil, fmt.Errorf("invalid coil count: %d (max 2000)", count)
	}

	pdu := make([]byte, 5)
	pdu[0] = ModbusFCReadCoils
	binary.BigEndian.PutUint16(pdu[1:3], startAddr)
	binary.BigEndian.PutUint16(pdu[3:5], count)

	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return nil, err
	}

	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}

	byteCount := int(resp[1])
	if len(resp) < 2+byteCount {
		return nil, fmt.Errorf("incomplete response data")
	}

	result := &ModbusRegisterData{
		UnitID:    unitID,
		Function:  ModbusFCReadCoils,
		StartAddr: startAddr,
		Count:     count,
	}

	for i := 0; i < int(count); i++ {
		byteIdx := i / 8
		bitIdx := uint(i % 8)
		if byteIdx < byteCount {
			val := uint16(0)
			if resp[2+byteIdx]&(1<<bitIdx) != 0 {
				val = 1
			}
			result.RawValues = append(result.RawValues, val)
		}
	}

	return result, nil
}

// ReadDiscreteInputs reads discrete inputs (FC02) - READ ONLY.
func (c *ModbusClient) ReadDiscreteInputs(unitID byte, startAddr, count uint16) (*ModbusRegisterData, error) {
	if count == 0 || count > 2000 {
		return nil, fmt.Errorf("invalid input count: %d (max 2000)", count)
	}

	pdu := make([]byte, 5)
	pdu[0] = ModbusFCReadDiscreteInputs
	binary.BigEndian.PutUint16(pdu[1:3], startAddr)
	binary.BigEndian.PutUint16(pdu[3:5], count)

	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return nil, err
	}

	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}

	byteCount := int(resp[1])
	if len(resp) < 2+byteCount {
		return nil, fmt.Errorf("incomplete response data")
	}

	result := &ModbusRegisterData{
		UnitID:    unitID,
		Function:  ModbusFCReadDiscreteInputs,
		StartAddr: startAddr,
		Count:     count,
	}

	for i := 0; i < int(count); i++ {
		byteIdx := i / 8
		bitIdx := uint(i % 8)
		if byteIdx < byteCount {
			val := uint16(0)
			if resp[2+byteIdx]&(1<<bitIdx) != 0 {
				val = 1
			}
			result.RawValues = append(result.RawValues, val)
		}
	}

	return result, nil
}

// ReadHoldingRegisters reads holding registers (FC03) - READ ONLY.
func (c *ModbusClient) ReadHoldingRegisters(unitID byte, startAddr, count uint16) (*ModbusRegisterData, error) {
	if count == 0 || count > 125 {
		return nil, fmt.Errorf("invalid register count: %d (max 125)", count)
	}

	pdu := make([]byte, 5)
	pdu[0] = ModbusFCReadHoldingRegisters
	binary.BigEndian.PutUint16(pdu[1:3], startAddr)
	binary.BigEndian.PutUint16(pdu[3:5], count)

	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return nil, err
	}

	return c.parseRegisterResponse(resp, unitID, ModbusFCReadHoldingRegisters, startAddr, count)
}

// ReadInputRegisters reads input registers (FC04) - READ ONLY.
func (c *ModbusClient) ReadInputRegisters(unitID byte, startAddr, count uint16) (*ModbusRegisterData, error) {
	if count == 0 || count > 125 {
		return nil, fmt.Errorf("invalid register count: %d (max 125)", count)
	}

	pdu := make([]byte, 5)
	pdu[0] = ModbusFCReadInputRegisters
	binary.BigEndian.PutUint16(pdu[1:3], startAddr)
	binary.BigEndian.PutUint16(pdu[3:5], count)

	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return nil, err
	}

	return c.parseRegisterResponse(resp, unitID, ModbusFCReadInputRegisters, startAddr, count)
}

// parseRegisterResponse parses a register read response.
func (c *ModbusClient) parseRegisterResponse(resp []byte, unitID, fc byte, startAddr, count uint16) (*ModbusRegisterData, error) {
	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}

	byteCount := int(resp[1])
	if len(resp) < 2+byteCount {
		return nil, fmt.Errorf("incomplete response data")
	}

	result := &ModbusRegisterData{
		UnitID:    unitID,
		Function:  fc,
		StartAddr: startAddr,
		Count:     count,
	}

	for i := 0; i < byteCount/2; i++ {
		val := binary.BigEndian.Uint16(resp[2+i*2 : 4+i*2])
		result.RawValues = append(result.RawValues, val)
		result.Interpreted = append(result.Interpreted, interpretRegister(startAddr+uint16(i), val))
	}

	return result, nil
}

// interpretRegister converts raw register data to multiple representations.
func interpretRegister(addr, raw uint16) ModbusValue {
	mv := ModbusValue{
		Address:   addr,
		RawUint16: raw,
		AsInt16:   int16(raw),
	}
	// Bit decomposition
	bits := make([]bool, 16)
	for i := 0; i < 16; i++ {
		bits[i] = raw&(1<<uint(i)) != 0
	}
	mv.BitValues = bits
	return mv
}

// InterpretAsFloat32 interprets two consecutive registers as a 32-bit float.
func InterpretAsFloat32(high, low uint16) float32 {
	bits := uint32(high)<<16 | uint32(low)
	return math.Float32frombits(bits)
}

// ReadExceptionStatus reads exception status (FC07) - READ ONLY.
func (c *ModbusClient) ReadExceptionStatus(unitID byte) (byte, error) {
	pdu := []byte{ModbusFCReadExceptionStatus}
	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return 0, err
	}
	if len(resp) < 2 {
		return 0, fmt.Errorf("response too short")
	}
	return resp[1], nil
}

// DiagnosticsReturnQueryData sends a diagnostics echo request (FC08, sub 0x0000) - READ ONLY.
// ONLY sub-function 0x0000 (Return Query Data) is implemented.
func (c *ModbusClient) DiagnosticsReturnQueryData(unitID byte, data uint16) (uint16, error) {
	pdu := make([]byte, 5)
	pdu[0] = ModbusFCDiagnostics
	binary.BigEndian.PutUint16(pdu[1:3], ModbusDiagReturnQueryData) // Sub-function 0x0000 ONLY
	binary.BigEndian.PutUint16(pdu[3:5], data)

	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return 0, err
	}
	if len(resp) < 5 {
		return 0, fmt.Errorf("response too short")
	}
	return binary.BigEndian.Uint16(resp[3:5]), nil
}

// GetCommEventCounter reads the communication event counter (FC11) - READ ONLY.
func (c *ModbusClient) GetCommEventCounter(unitID byte) (uint16, uint16, error) {
	pdu := []byte{ModbusFCGetCommEventCounter}
	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return 0, 0, err
	}
	if len(resp) < 5 {
		return 0, 0, fmt.Errorf("response too short")
	}
	status := binary.BigEndian.Uint16(resp[1:3])
	eventCount := binary.BigEndian.Uint16(resp[3:5])
	return status, eventCount, nil
}

// GetCommEventLog reads the communication event log (FC12) - READ ONLY.
func (c *ModbusClient) GetCommEventLog(unitID byte) ([]byte, error) {
	pdu := []byte{ModbusFCGetCommEventLog}
	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}
	byteCount := int(resp[1])
	if len(resp) < 2+byteCount {
		return nil, fmt.Errorf("incomplete response")
	}
	return resp[2 : 2+byteCount], nil
}

// ReportServerID reads server identification (FC17) - READ ONLY.
func (c *ModbusClient) ReportServerID(unitID byte) ([]byte, error) {
	pdu := []byte{ModbusFCReportServerID}
	resp, err := c.sendRequest(unitID, pdu)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}
	byteCount := int(resp[1])
	if len(resp) < 2+byteCount {
		return nil, fmt.Errorf("incomplete response")
	}
	return resp[2 : 2+byteCount], nil
}

// ReadDeviceIdentification reads device identification (FC43/14) - READ ONLY.
func (c *ModbusClient) ReadDeviceIdentification(readDevIDCode, objectID byte) (*ModbusDeviceID, error) {
	pdu := []byte{
		ModbusFCReadDeviceID,
		0x0E,           // MEI type 14 (Read Device Identification)
		readDevIDCode,  // 01=basic, 02=regular, 03=extended, 04=specific
		objectID,       // Starting object ID
	}

	resp, err := c.sendRequest(1, pdu)
	if err != nil {
		return nil, err
	}

	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short for device ID")
	}

	// Parse response objects
	devID := &ModbusDeviceID{}
	numObjects := int(resp[7])
	pos := 8

	for i := 0; i < numObjects && pos+2 < len(resp); i++ {
		objID := resp[pos]
		objLen := int(resp[pos+1])
		pos += 2
		if pos+objLen > len(resp) {
			break
		}
		objVal := string(resp[pos : pos+objLen])
		pos += objLen

		switch objID {
		case 0x00:
			devID.VendorName = objVal
		case 0x01:
			devID.ProductCode = objVal
		case 0x02:
			devID.MajorMinorRev = objVal
		case 0x03:
			devID.VendorURL = objVal
		case 0x04:
			devID.ProductName = objVal
		case 0x05:
			devID.ModelName = objVal
		case 0x06:
			devID.UserAppName = objVal
		}
	}

	return devID, nil
}

// EnumerateUnitIDs scans for responding Modbus unit IDs (1-247).
func (c *ModbusClient) EnumerateUnitIDs(ctx context.Context) ([]byte, error) {
	var responding []byte

	for uid := byte(1); uid <= 247; uid++ {
		select {
		case <-ctx.Done():
			return responding, ctx.Err()
		default:
		}

		// Try reading a single holding register
		pdu := make([]byte, 5)
		pdu[0] = ModbusFCReadHoldingRegisters
		binary.BigEndian.PutUint16(pdu[1:3], 0) // Address 0
		binary.BigEndian.PutUint16(pdu[3:5], 1) // 1 register

		_, err := c.sendRequest(uid, pdu)
		if err == nil {
			responding = append(responding, uid)
		}
	}

	return responding, nil
}
