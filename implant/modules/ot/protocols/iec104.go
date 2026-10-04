package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// IEC 60870-5-104 APCI control field types
const (
	IEC104TypeI = iota // Information transfer (numbered)
	IEC104TypeS        // Supervisory (numbered)
	IEC104TypeU        // Unnumbered
)

// IEC 104 U-frame function codes
const (
	IEC104StartDTAct = 0x07
	IEC104StartDTCon = 0x0B
	IEC104StopDTAct  = 0x13
	IEC104StopDTCon  = 0x23
	IEC104TestFRAct  = 0x43
	IEC104TestFRCon  = 0x83
)

// IEC 104 ASDU Type IDs - MONITORING direction only (1-21)
// Explicitly NOT implementing: Control direction types (45-69),
// System commands (100-107 except 100 for interrogation).
const (
	IEC104TypeSinglePoint        = 1  // M_SP_NA_1
	IEC104TypeSinglePointTS      = 2  // M_SP_TA_1
	IEC104TypeDoublePoint        = 3  // M_DP_NA_1
	IEC104TypeDoublePointTS      = 4  // M_DP_TA_1
	IEC104TypeStepPosition       = 5  // M_ST_NA_1
	IEC104TypeStepPositionTS     = 6  // M_ST_TA_1
	IEC104TypeBitstring32        = 7  // M_BO_NA_1
	IEC104TypeBitstring32TS      = 8  // M_BO_TA_1
	IEC104TypeMeasuredNorm       = 9  // M_ME_NA_1
	IEC104TypeMeasuredNormTS     = 10 // M_ME_TA_1
	IEC104TypeMeasuredScaled     = 11 // M_ME_NB_1
	IEC104TypeMeasuredScaledTS   = 12 // M_ME_TB_1
	IEC104TypeMeasuredFloat      = 13 // M_ME_NC_1
	IEC104TypeMeasuredFloatTS    = 14 // M_ME_TC_1
	IEC104TypeIntegratedTotals   = 15 // M_IT_NA_1
	IEC104TypeIntegratedTotalsTS = 16 // M_IT_TA_1
	IEC104TypeProtEquipEvent     = 17 // M_EP_TA_1
	IEC104TypePackedProtStart    = 18 // M_EP_TB_1
	IEC104TypePackedProtOutput   = 19 // M_EP_TC_1
	IEC104TypePackedSPChange     = 20 // M_PS_NA_1
	IEC104TypeMeasuredNormNoQD   = 21 // M_ME_ND_1

	// General Interrogation is read-only: it requests class data
	IEC104TypeInterrogation = 100 // C_IC_NA_1
)

// Cause of Transmission (COT) values
const (
	IEC104CotCyclic       = 1
	IEC104CotBackground   = 2
	IEC104CotSpontaneous  = 3
	IEC104CotRequest      = 5
	IEC104CotActivation   = 6
	IEC104CotActCon       = 7
	IEC104CotActTerm      = 10
	IEC104CotInterrogated = 20
)

// SAFETY: IEC 104 client implements ONLY monitoring (read) operations.
// Explicitly NOT implementing: Single/Double Command (types 45-46),
// Regulating Step Command (type 47), Set-point commands (types 48-51),
// Bitstring Command (type 51), any control direction types.

// IEC104Client is a read-only IEC 60870-5-104 client.
type IEC104Client struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	sendSeq   uint16
	recvSeq   uint16
}

// IEC104ASDU represents a parsed Application Service Data Unit.
type IEC104ASDU struct {
	TypeID         byte           `json:"type_id"`
	TypeName       string         `json:"type_name"`
	NumObjects     byte           `json:"num_objects"`
	CauseOfTx      byte           `json:"cause_of_tx"`
	CauseText      string         `json:"cause_text"`
	Negative       bool           `json:"negative"`
	Test           bool           `json:"test"`
	OriginAddr     byte           `json:"origin_addr"`
	CommonAddr     uint16         `json:"common_addr"`
	InformationObj []IEC104InfoObj `json:"information_objects"`
	Raw            []byte         `json:"raw,omitempty"`
}

// IEC104InfoObj represents an information object in an ASDU.
type IEC104InfoObj struct {
	IOA       uint32 `json:"ioa"` // Information Object Address (3 bytes)
	Value     any    `json:"value"`
	Quality   byte   `json:"quality"`
	Timestamp []byte `json:"timestamp,omitempty"`
}

// NewIEC104Client creates a new read-only IEC 104 client.
func NewIEC104Client(config ConnConfig) *IEC104Client {
	return &IEC104Client{
		config: config,
	}
}

func (c *IEC104Client) Name() string { return "iec104" }

func (c *IEC104Client) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 2404
	}

	conn, err := tcpConnect(target, port, c.config.Timeout)
	if err != nil {
		return err
	}
	c.conn = conn
	c.target = target
	c.port = port

	// Send STARTDT act
	if err := c.sendUFrame(IEC104StartDTAct); err != nil {
		conn.Close()
		return fmt.Errorf("STARTDT failed: %w", err)
	}

	// Wait for STARTDT con
	resp, err := c.readAPCI()
	if err != nil {
		conn.Close()
		return fmt.Errorf("waiting for STARTDT con: %w", err)
	}
	if len(resp) >= 6 && resp[2] != IEC104StartDTCon {
		conn.Close()
		return fmt.Errorf("unexpected response to STARTDT: 0x%02X", resp[2])
	}

	c.connected = true
	return nil
}

func (c *IEC104Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		// Send STOPDT act
		_ = c.sendUFrame(IEC104StopDTAct)
		return c.conn.Close()
	}
	return nil
}

func (c *IEC104Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *IEC104Client) Identify(ctx context.Context) (*DeviceInfo, error) {
	return &DeviceInfo{
		Protocol: "iec104",
		Extra: map[string]string{
			"target": fmt.Sprintf("%s:%d", c.target, c.port),
		},
	}, nil
}

// sendUFrame sends an unnumbered control frame.
func (c *IEC104Client) sendUFrame(controlField byte) error {
	frame := []byte{
		0x68,         // Start byte
		0x04,         // APDU length (4 bytes)
		controlField, // Control field 1
		0x00,         // Control field 2
		0x00,         // Control field 3
		0x00,         // Control field 4
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.config.Timeout))
	_, err := c.conn.Write(frame)
	return err
}

// sendIFrame sends an information transfer frame with an ASDU.
func (c *IEC104Client) sendIFrame(asdu []byte) error {
	apduLen := 4 + len(asdu)
	frame := make([]byte, 2+apduLen)
	frame[0] = 0x68 // Start byte
	frame[1] = byte(apduLen)

	// I-format: bit 0 of first octet = 0
	sendSeq := c.sendSeq << 1
	binary.LittleEndian.PutUint16(frame[2:4], sendSeq)
	recvSeq := c.recvSeq << 1
	binary.LittleEndian.PutUint16(frame[4:6], recvSeq)

	copy(frame[6:], asdu)

	c.sendSeq++

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.config.Timeout))
	_, err := c.conn.Write(frame)
	return err
}

// readAPCI reads an APCI frame from the connection.
func (c *IEC104Client) readAPCI() ([]byte, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(c.config.Timeout))

	// Read start byte and length
	header := make([]byte, 2)
	if _, err := c.conn.Read(header); err != nil {
		return nil, err
	}
	if header[0] != 0x68 {
		return nil, fmt.Errorf("invalid start byte: 0x%02X", header[0])
	}

	apduLen := int(header[1])
	apdu := make([]byte, apduLen)
	total := 0
	for total < apduLen {
		n, err := c.conn.Read(apdu[total:])
		if err != nil {
			return nil, err
		}
		total += n
	}

	return apdu, nil
}

// TestConnection sends a TESTFR act and waits for TESTFR con.
func (c *IEC104Client) TestConnection() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.sendUFrame(IEC104TestFRAct); err != nil {
		return err
	}

	resp, err := c.readAPCI()
	if err != nil {
		return err
	}
	if len(resp) >= 1 && resp[0] != IEC104TestFRCon {
		return fmt.Errorf("expected TESTFR con, got 0x%02X", resp[0])
	}
	return nil
}

// GeneralInterrogation sends a general interrogation command (type 100) - READ ONLY.
// This requests class data from the controlled station.
func (c *IEC104Client) GeneralInterrogation(commonAddr uint16) ([]IEC104ASDU, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	// Build general interrogation ASDU
	asdu := []byte{
		IEC104TypeInterrogation, // Type ID: C_IC_NA_1
		0x01,                    // SQ=0, number of objects=1
		IEC104CotActivation,     // Cause of transmission: Activation
		0x00,                    // Originator address
	}
	// Common address (2 bytes, little-endian)
	ca := make([]byte, 2)
	binary.LittleEndian.PutUint16(ca, commonAddr)
	asdu = append(asdu, ca...)

	// Information object: IOA=0, QOI=20 (station interrogation)
	asdu = append(asdu, 0x00, 0x00, 0x00) // IOA (3 bytes)
	asdu = append(asdu, 0x14)              // QOI: station interrogation

	if err := c.sendIFrame(asdu); err != nil {
		return nil, err
	}

	// Collect responses
	var responses []IEC104ASDU
	deadline := time.Now().Add(c.config.Timeout * 3) // Allow longer for interrogation

	for time.Now().Before(deadline) {
		apdu, err := c.readAPCI()
		if err != nil {
			break
		}

		if len(apdu) < 4 {
			continue
		}

		// Check if I-format (bit 0 of first byte = 0)
		if apdu[0]&0x01 == 0 && len(apdu) > 4 {
			c.recvSeq++

			parsed := c.parseASDU(apdu[4:])
			if parsed != nil {
				responses = append(responses, *parsed)

				// Check for activation termination
				if parsed.CauseOfTx == IEC104CotActTerm {
					break
				}
			}
		}
	}

	return responses, nil
}

// MonitorASDUs passively receives ASDUs for a given duration - READ ONLY.
func (c *IEC104Client) MonitorASDUs(ctx context.Context, duration time.Duration) ([]IEC104ASDU, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	var responses []IEC104ASDU
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return responses, ctx.Err()
		default:
		}

		_ = c.conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		apdu, err := c.readAPCI()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}

		if len(apdu) < 4 {
			continue
		}

		// I-format contains ASDU data
		if apdu[0]&0x01 == 0 && len(apdu) > 4 {
			c.recvSeq++
			parsed := c.parseASDU(apdu[4:])
			if parsed != nil {
				responses = append(responses, *parsed)
			}
		}
	}

	return responses, nil
}

// parseASDU parses an ASDU from raw bytes.
func (c *IEC104Client) parseASDU(data []byte) *IEC104ASDU {
	if len(data) < 6 {
		return nil
	}

	asdu := &IEC104ASDU{
		TypeID:     data[0],
		TypeName:   iec104TypeName(data[0]),
		NumObjects: data[1] & 0x7F,
		CauseOfTx:  data[2] & 0x3F,
		CauseText:  iec104CotName(data[2] & 0x3F),
		Negative:   data[2]&0x40 != 0,
		Test:       data[2]&0x80 != 0,
		OriginAddr: data[3],
		CommonAddr: binary.LittleEndian.Uint16(data[4:6]),
		Raw:        data,
	}

	return asdu
}

// iec104TypeName returns a human-readable name for an IEC 104 type ID.
func iec104TypeName(typeID byte) string {
	names := map[byte]string{
		1:   "Single-point information",
		2:   "Single-point with time tag",
		3:   "Double-point information",
		4:   "Double-point with time tag",
		5:   "Step position information",
		7:   "Bitstring of 32 bits",
		9:   "Measured value, normalized",
		11:  "Measured value, scaled",
		13:  "Measured value, short floating point",
		15:  "Integrated totals",
		20:  "Packed single-point with status change",
		21:  "Measured value, normalized without quality",
		100: "Interrogation command",
	}
	if name, ok := names[typeID]; ok {
		return name
	}
	return fmt.Sprintf("Type %d", typeID)
}

// iec104CotName returns a human-readable cause of transmission.
func iec104CotName(cot byte) string {
	names := map[byte]string{
		1:  "Cyclic",
		2:  "Background",
		3:  "Spontaneous",
		5:  "Request",
		6:  "Activation",
		7:  "Activation confirm",
		10: "Activation termination",
		20: "Interrogated by station",
	}
	if name, ok := names[cot]; ok {
		return name
	}
	return fmt.Sprintf("COT %d", cot)
}
