package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

// CoAP Message Types
const (
	CoAPTypeCON = 0 // Confirmable
	CoAPTypeNON = 1 // Non-confirmable
	CoAPTypeACK = 2 // Acknowledgement
	CoAPTypeRST = 3 // Reset
)

// CoAP Method Codes - READ ONLY
// Explicitly NOT implementing: PUT (0.03), POST (0.02), DELETE (0.04)
const (
	CoAPMethodGET = 1 // 0.01 GET - READ ONLY
)

// CoAP Option Numbers
const (
	CoAPOptionUriHost       = 3
	CoAPOptionUriPort       = 7
	CoAPOptionUriPath       = 11
	CoAPOptionContentFormat = 12
	CoAPOptionUriQuery      = 15
	CoAPOptionAccept        = 17
)

// CoAP Content Formats
const (
	CoAPContentTextPlain     = 0
	CoAPContentAppLinkFormat = 40
	CoAPContentAppXML        = 41
	CoAPContentAppJSON       = 50
	CoAPContentAppCBOR       = 60
)

// SAFETY: CoAP client implements ONLY GET requests.
// Explicitly NOT implementing: PUT, POST, DELETE methods.

// CoAPClient is a read-only CoAP client.
type CoAPClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	messageID uint16
	token     []byte
}

// CoAPResource represents a discovered CoAP resource.
type CoAPResource struct {
	Path          string            `json:"path"`
	Title         string            `json:"title,omitempty"`
	ResourceType  string            `json:"rt,omitempty"`
	InterfaceDesc string            `json:"if,omitempty"`
	ContentFormat int               `json:"ct,omitempty"`
	Size          int               `json:"sz,omitempty"`
	Observable    bool              `json:"obs,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// CoAPResponse holds a CoAP response.
type CoAPResponse struct {
	Type          byte           `json:"type"`
	Code          byte           `json:"code"`
	CodeClass     byte           `json:"code_class"`
	CodeDetail    byte           `json:"code_detail"`
	MessageID     uint16         `json:"message_id"`
	Token         []byte         `json:"token"`
	Payload       []byte         `json:"payload"`
	ContentFormat int            `json:"content_format"`
	Options       map[int][]byte `json:"options,omitempty"`
}

// CoAPSecurityInfo holds CoAP/DTLS security assessment.
type CoAPSecurityInfo struct {
	DTLSSupported bool     `json:"dtls_supported"`
	DTLSPort      int      `json:"dtls_port"`
	CipherSuites  []string `json:"cipher_suites,omitempty"`
	Certificate   string   `json:"certificate,omitempty"`
}

// NewCoAPClient creates a new read-only CoAP client.
func NewCoAPClient(config ConnConfig) *CoAPClient {
	return &CoAPClient{
		config: config,
		token:  []byte{0x01},
	}
}

func (c *CoAPClient) Name() string { return "coap" }

func (c *CoAPClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 5683
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

func (c *CoAPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *CoAPClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *CoAPClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	resources, err := c.Discover()
	if err != nil {
		return nil, err
	}

	info := &DeviceInfo{
		Protocol:     "coap",
		Capabilities: make([]string, 0),
		Extra:        make(map[string]string),
	}

	for _, r := range resources {
		info.Capabilities = append(info.Capabilities, r.Path)
	}

	return info, nil
}

// buildRequest constructs a CoAP request.
func (c *CoAPClient) buildRequest(msgType byte, method byte, uriPath string) []byte {
	c.messageID++

	// Header: 4 bytes
	header := make([]byte, 4)
	header[0] = (1 << 6) | (msgType << 4) | byte(len(c.token)) // Version 1, type, token length
	header[1] = method                                         // Code
	binary.BigEndian.PutUint16(header[2:4], c.messageID)       // Message ID

	packet := append(header, c.token...)

	// Add URI-Path options
	if uriPath != "" {
		uriPath = strings.TrimPrefix(uriPath, "/")
		parts := strings.Split(uriPath, "/")
		prevOptNum := 0
		for _, part := range parts {
			if part == "" {
				continue
			}
			delta := CoAPOptionUriPath - prevOptNum
			prevOptNum = CoAPOptionUriPath
			packet = append(packet, encodeCoAPOption(delta, []byte(part))...)
		}
	}

	return packet
}

// encodeCoAPOption encodes a single CoAP option.
func encodeCoAPOption(delta int, value []byte) []byte {
	var opt []byte

	d := delta
	l := len(value)

	firstByte := byte(0)
	if d < 13 {
		firstByte = byte(d) << 4
	} else {
		firstByte = 13 << 4
	}
	if l < 13 {
		firstByte |= byte(l)
	} else {
		firstByte |= 13
	}

	opt = append(opt, firstByte)

	if d >= 13 && d < 269 {
		opt = append(opt, byte(d-13))
	}
	if l >= 13 && l < 269 {
		opt = append(opt, byte(l-13))
	}

	opt = append(opt, value...)
	return opt
}

// Get sends a CoAP GET request - READ ONLY.
func (c *CoAPClient) Get(path string) (*CoAPResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	req := c.buildRequest(CoAPTypeCON, CoAPMethodGET, path)

	resp, err := sendAndReceive(c.conn, req, 1500, c.config.Timeout)
	if err != nil {
		return nil, err
	}

	return c.parseResponse(resp)
}

// Discover performs CoAP resource discovery via /.well-known/core - READ ONLY.
func (c *CoAPClient) Discover() ([]CoAPResource, error) {
	resp, err := c.Get("/.well-known/core")
	if err != nil {
		return nil, err
	}

	if resp == nil || len(resp.Payload) == 0 {
		return nil, fmt.Errorf("empty discovery response")
	}

	return parseLinkFormat(string(resp.Payload)), nil
}

// DetectDTLS checks if the CoAP server supports DTLS on port 5684.
func (c *CoAPClient) DetectDTLS() (*CoAPSecurityInfo, error) {
	info := &CoAPSecurityInfo{
		DTLSPort: 5684,
	}

	// Try connecting to the DTLS port
	addr := net.JoinHostPort(c.target, "5684")
	conn, err := net.DialTimeout("udp", addr, c.config.Timeout)
	if err != nil {
		info.DTLSSupported = false
		return info, nil
	}
	conn.Close()

	// DTLS detection would need a ClientHello
	// For now, just check if the port is reachable
	info.DTLSSupported = true
	return info, nil
}

// parseResponse parses a CoAP response packet.
func (c *CoAPClient) parseResponse(data []byte) (*CoAPResponse, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("response too short")
	}

	resp := &CoAPResponse{
		Options: make(map[int][]byte),
	}

	// Parse header
	tokenLen := data[0] & 0x0F
	resp.Type = (data[0] >> 4) & 0x03
	resp.Code = data[1]
	resp.CodeClass = resp.Code >> 5
	resp.CodeDetail = resp.Code & 0x1F
	resp.MessageID = binary.BigEndian.Uint16(data[2:4])

	pos := 4

	// Token
	if pos+int(tokenLen) <= len(data) {
		resp.Token = data[pos : pos+int(tokenLen)]
		pos += int(tokenLen)
	}

	// Options
	optionNumber := 0
	for pos < len(data) && data[pos] != 0xFF {
		if pos >= len(data) {
			break
		}
		delta := int(data[pos] >> 4)
		length := int(data[pos] & 0x0F)
		pos++

		if delta == 13 && pos < len(data) {
			delta = int(data[pos]) + 13
			pos++
		}
		if length == 13 && pos < len(data) {
			length = int(data[pos]) + 13
			pos++
		}

		optionNumber += delta
		if pos+length <= len(data) {
			resp.Options[optionNumber] = data[pos : pos+length]
			if optionNumber == CoAPOptionContentFormat && length > 0 {
				resp.ContentFormat = int(data[pos])
			}
		}
		pos += length
	}

	// Payload marker and payload
	if pos < len(data) && data[pos] == 0xFF {
		pos++
		resp.Payload = data[pos:]
	}

	return resp, nil
}

// parseLinkFormat parses CoRE Link Format (RFC 6690) from /.well-known/core.
func parseLinkFormat(data string) []CoAPResource {
	var resources []CoAPResource

	entries := strings.Split(data, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		resource := CoAPResource{
			Attributes: make(map[string]string),
		}

		parts := strings.Split(entry, ";")
		for i, part := range parts {
			part = strings.TrimSpace(part)
			if i == 0 {
				// URI reference
				part = strings.TrimPrefix(part, "<")
				part = strings.TrimSuffix(part, ">")
				resource.Path = part
			} else {
				kv := strings.SplitN(part, "=", 2)
				key := strings.TrimSpace(kv[0])
				value := ""
				if len(kv) > 1 {
					value = strings.Trim(strings.TrimSpace(kv[1]), "\"")
				}

				switch key {
				case "title":
					resource.Title = value
				case "rt":
					resource.ResourceType = value
				case "if":
					resource.InterfaceDesc = value
				case "obs":
					resource.Observable = true
				default:
					resource.Attributes[key] = value
				}
			}
		}

		resources = append(resources, resource)
	}

	return resources
}
