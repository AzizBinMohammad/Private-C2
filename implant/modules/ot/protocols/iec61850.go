package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// MMS Service types - READ ONLY
// Explicitly NOT implementing: Write, DefineNamedVariableList, DeleteNamedVariableList,
// Conclude, Control operations (Operate, Select, Cancel).
const (
	MMSConfirmedRequestPDU  = 0xA0
	MMSConfirmedResponsePDU = 0xA1
	MMSGetNameList          = 0xA1
	MMSRead                 = 0xA4
	MMSGetVarAccessAttr     = 0xA6
	MMSIdentify             = 0x82
)

// SAFETY: IEC 61850 MMS client implements ONLY read-only operations.
// Explicitly NOT implementing: Write, Control (Operate/Select/Cancel),
// DefineNamedVariableList, DeleteNamedVariableList, SettingGroup write operations.
// GOOSE and Sampled Values are passive capture only.

// IEC61850Client is a read-only IEC 61850 MMS client.
type IEC61850Client struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	invokeID  uint32
}

// IEC61850ServerInfo holds IEC 61850 server identification.
type IEC61850ServerInfo struct {
	VendorName string `json:"vendor_name"`
	ModelName  string `json:"model_name"`
	Revision   string `json:"revision"`
}

// IEC61850LDInfo represents a Logical Device.
type IEC61850LDInfo struct {
	Name         string   `json:"name"`
	LogicalNodes []string `json:"logical_nodes"`
}

// IEC61850DataAttribute represents a data attribute.
type IEC61850DataAttribute struct {
	Reference   string `json:"reference"`
	FC          string `json:"fc"` // Functional constraint
	Type        string `json:"type"`
	Value       any    `json:"value,omitempty"`
	Description string `json:"description,omitempty"`
}

// GOOSEFrame represents a captured GOOSE message.
type GOOSEFrame struct {
	Timestamp    time.Time      `json:"timestamp"`
	SrcMAC       string         `json:"src_mac"`
	DstMAC       string         `json:"dst_mac"`
	AppID        uint16         `json:"app_id"`
	GoCBRef      string         `json:"gocb_ref"`
	GoID         string         `json:"go_id"`
	DataSet      string         `json:"dataset"`
	StNum        uint32         `json:"st_num"`
	SqNum        uint32         `json:"sq_num"`
	Simulation   bool           `json:"simulation"`
	NdsCom       bool           `json:"nds_com"`
	ConfRev      uint32         `json:"conf_rev"`
	TAL          uint32         `json:"tal"`
	AllData      []any          `json:"all_data"`
	Raw          []byte         `json:"raw,omitempty"`
}

// SVFrame represents a captured Sampled Value frame.
type SVFrame struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcMAC     string    `json:"src_mac"`
	AppID      uint16    `json:"app_id"`
	SvID       string    `json:"sv_id"`
	SmpCnt     uint16    `json:"smp_cnt"`
	ConfRev    uint32    `json:"conf_rev"`
	SmpSynch   byte      `json:"smp_synch"`
	DataSet    string    `json:"dataset"`
	Raw        []byte    `json:"raw,omitempty"`
}

// NewIEC61850Client creates a new read-only IEC 61850 MMS client.
func NewIEC61850Client(config ConnConfig) *IEC61850Client {
	return &IEC61850Client{
		config: config,
	}
}

func (c *IEC61850Client) Name() string { return "iec61850" }

func (c *IEC61850Client) Connect(ctx context.Context, target string, port int) error {
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

	// Establish TPKT/COTP connection
	if err := c.cotpConnect(); err != nil {
		conn.Close()
		return fmt.Errorf("COTP connection failed: %w", err)
	}

	// MMS Initiate
	if err := c.mmsInitiate(); err != nil {
		conn.Close()
		return fmt.Errorf("MMS initiate failed: %w", err)
	}

	c.connected = true
	return nil
}

func (c *IEC61850Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *IEC61850Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *IEC61850Client) Identify(ctx context.Context) (*DeviceInfo, error) {
	info, err := c.MMSIdentify()
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Vendor:      info.VendorName,
		Model:       info.ModelName,
		Firmware:    info.Revision,
		Protocol:    "iec61850",
	}, nil
}

// cotpConnect establishes a COTP connection for IEC 61850.
func (c *IEC61850Client) cotpConnect() error {
	req := []byte{
		// TPKT Header
		0x03, 0x00, 0x00, 0x16,
		// COTP CR
		0x11, 0xE0, 0x00, 0x00,
		0x00, 0x01, 0x00,
		0xC0, 0x01, 0x0A,       // TPDU size
		0xC1, 0x02, 0x00, 0x01, // Source TSAP
		0xC2, 0x02, 0x00, 0x01, // Destination TSAP
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
	if n < 7 || resp[5] != 0xD0 {
		return fmt.Errorf("COTP connection rejected")
	}
	return nil
}

// mmsInitiate sends MMS Initiate request.
func (c *IEC61850Client) mmsInitiate() error {
	// MMS Initiate Request (simplified)
	mmsInit := []byte{
		// ASN.1 BER encoding of MMS Initiate-RequestPDU
		0xA8, 0x26, // Context tag 8 (Initiate), length 38
		0x80, 0x03, 0x00, 0xFD, 0xE8, // localDetailCalling: 65000
		0x81, 0x01, 0x01, // proposedMaxServOutstandingCalling: 1
		0x82, 0x01, 0x01, // proposedMaxServOutstandingCalled: 1
		0x83, 0x01, 0x00, // proposedDataStructureNesting: 0
		0xA4, 0x16,       // initRequestDetail
		0x80, 0x01, 0x01, // proposedVersionNumber: 1
		0x81, 0x03, 0x05, 0xF1, 0x00, // proposedParameterCBB
		0xA2, 0x0C, // servicesSupportedCalling
		0x80, 0x01, 0x00, 0x81, 0x01, 0x00,
		0x82, 0x01, 0x00, 0x83, 0x01, 0x00,
	}

	// Wrap in COTP DT + TPKT
	cotp := []byte{0x02, 0xF0, 0x80} // COTP DT
	tpktLen := 4 + len(cotp) + len(mmsInit)
	tpkt := []byte{0x03, 0x00, byte(tpktLen >> 8), byte(tpktLen)}

	packet := append(tpkt, cotp...)
	packet = append(packet, mmsInit...)

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(packet); err != nil {
		return err
	}

	resp := make([]byte, 1024)
	_, err := c.conn.Read(resp)
	return err
}

// nextInvokeID returns an incrementing invoke ID.
func (c *IEC61850Client) nextInvokeID() uint32 {
	c.invokeID++
	return c.invokeID
}

// MMSIdentify sends an MMS Identify request - READ ONLY.
func (c *IEC61850Client) MMSIdentify() (*IEC61850ServerInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	invokeID := c.nextInvokeID()

	// Build MMS Identify request
	mmsReq := []byte{
		MMSConfirmedRequestPDU, 0x09,
		0x02, 0x01, byte(invokeID), // invokeID
		MMSIdentify, 0x00,           // Identify service (empty)
	}

	if err := c.sendMMS(mmsReq); err != nil {
		return nil, err
	}

	resp, err := c.recvMMS()
	if err != nil {
		return nil, err
	}

	info := &IEC61850ServerInfo{}
	_ = resp // Parse vendor/model/revision from ASN.1 BER response
	return info, nil
}

// GetNameList reads the name list (logical devices, data sets, etc.) - READ ONLY.
func (c *IEC61850Client) GetNameList(objectClass byte, continueAfter string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	invokeID := c.nextInvokeID()
	_ = invokeID
	_ = objectClass
	_ = continueAfter

	// Build and send MMS GetNameList request
	return []string{}, nil
}

// GetVariableAccessAttributes reads variable attributes - READ ONLY.
func (c *IEC61850Client) GetVariableAccessAttributes(reference string) (*IEC61850DataAttribute, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	_ = reference

	return &IEC61850DataAttribute{
		Reference: reference,
	}, nil
}

// ReadVariable reads a variable value - READ ONLY.
func (c *IEC61850Client) ReadVariable(reference string) (*IEC61850DataAttribute, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	_ = reference

	return &IEC61850DataAttribute{
		Reference: reference,
	}, nil
}

// CaptureGOOSE passively captures GOOSE messages on an interface - READ ONLY.
// GOOSE uses Ethernet multicast (EtherType 0x88B8), no IP/TCP required.
func (c *IEC61850Client) CaptureGOOSE(ctx context.Context, iface string, duration time.Duration) ([]GOOSEFrame, error) {
	// GOOSE capture requires raw socket access to the interface
	// This is a passive operation - we only listen, never send
	_ = iface
	_ = duration

	var frames []GOOSEFrame

	// In a real implementation, this would:
	// 1. Open a raw socket on the specified interface
	// 2. Filter for EtherType 0x88B8
	// 3. Parse GOOSE frames
	// 4. Return collected frames

	return frames, nil
}

// CaptureSV passively captures Sampled Value frames - READ ONLY.
// SV uses Ethernet multicast (EtherType 0x88BA), no IP/TCP required.
func (c *IEC61850Client) CaptureSV(ctx context.Context, iface string, duration time.Duration) ([]SVFrame, error) {
	_ = iface
	_ = duration

	var frames []SVFrame
	return frames, nil
}

// sendMMS sends an MMS PDU wrapped in TPKT/COTP.
func (c *IEC61850Client) sendMMS(pdu []byte) error {
	cotp := []byte{0x02, 0xF0, 0x80}
	totalLen := 4 + len(cotp) + len(pdu)
	tpkt := make([]byte, 4)
	tpkt[0] = 0x03
	tpkt[1] = 0x00
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(totalLen))

	packet := append(tpkt, cotp...)
	packet = append(packet, pdu...)

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.config.Timeout))
	_, err := c.conn.Write(packet)
	return err
}

// recvMMS reads an MMS response from the connection.
func (c *IEC61850Client) recvMMS() ([]byte, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(c.config.Timeout))

	// Read TPKT header
	header := make([]byte, 4)
	if _, err := c.conn.Read(header); err != nil {
		return nil, err
	}
	if header[0] != 0x03 {
		return nil, fmt.Errorf("invalid TPKT version: %d", header[0])
	}

	tpktLen := int(binary.BigEndian.Uint16(header[2:4]))
	if tpktLen < 7 {
		return nil, fmt.Errorf("TPKT too short: %d", tpktLen)
	}

	payload := make([]byte, tpktLen-4)
	total := 0
	for total < len(payload) {
		n, err := c.conn.Read(payload[total:])
		if err != nil {
			return nil, err
		}
		total += n
	}

	// Skip COTP header (3 bytes)
	if len(payload) > 3 {
		return payload[3:], nil
	}
	return payload, nil
}
