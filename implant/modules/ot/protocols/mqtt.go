package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// MQTT Packet Types
const (
	MQTTConnect    = 1
	MQTTConnack    = 2
	MQTTPublish    = 3  // Receiving only - we never publish
	MQTTSubscribe  = 8
	MQTTSuback     = 9
	MQTTDisconnect = 14
)

// MQTT Connect Return Codes
const (
	MQTTConnAccepted          = 0x00
	MQTTConnRefusedProtocol   = 0x01
	MQTTConnRefusedIdentifier = 0x02
	MQTTConnRefusedServer     = 0x03
	MQTTConnRefusedCredentials = 0x04
	MQTTConnRefusedAuth       = 0x05
)

// SAFETY: MQTT client implements ONLY connect, subscribe, and receive.
// Explicitly NOT implementing: Publish (sending messages to topics),
// which could affect control systems subscribing to those topics.

// MQTTClient is a read-only MQTT client for OT topic discovery.
type MQTTClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
	packetID  uint16
}

// MQTTBrokerInfo holds MQTT broker assessment information.
type MQTTBrokerInfo struct {
	Target          string   `json:"target"`
	Port            int      `json:"port"`
	AllowsAnonymous bool     `json:"allows_anonymous"`
	ProtocolVersion byte     `json:"protocol_version"`
	ConnectCode     byte     `json:"connect_code"`
	SysTopics       map[string]string `json:"sys_topics"`
	DiscoveredTopics []MQTTTopic      `json:"discovered_topics"`
}

// MQTTTopic represents a discovered MQTT topic.
type MQTTTopic struct {
	Name      string `json:"name"`
	QoS       byte   `json:"qos"`
	Retained  bool   `json:"retained"`
	Payload   string `json:"payload,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewMQTTClient creates a new read-only MQTT client.
func NewMQTTClient(config ConnConfig) *MQTTClient {
	return &MQTTClient{
		config: config,
	}
}

func (c *MQTTClient) Name() string { return "mqtt" }

func (c *MQTTClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = 1883
	}

	conn, err := tcpConnect(target, port, c.config.Timeout)
	if err != nil {
		return err
	}
	c.conn = conn
	c.target = target
	c.port = port

	// Send MQTT CONNECT (anonymous)
	if err := c.sendConnect(); err != nil {
		conn.Close()
		return err
	}

	c.connected = true
	return nil
}

func (c *MQTTClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		// Send DISCONNECT
		_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c.conn.Write([]byte{MQTTDisconnect << 4, 0x00})
		return c.conn.Close()
	}
	return nil
}

func (c *MQTTClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *MQTTClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	return &DeviceInfo{
		Protocol: "mqtt",
		Extra: map[string]string{
			"target": fmt.Sprintf("%s:%d", c.target, c.port),
		},
	}, nil
}

// sendConnect sends an MQTT CONNECT packet with anonymous credentials.
func (c *MQTTClient) sendConnect() error {
	clientID := "ot-assess"

	// Variable header
	varHeader := []byte{
		0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol name
		0x04,       // Protocol level (4 = MQTT 3.1.1)
		0x02,       // Connect flags: Clean Session
		0x00, 0x3C, // Keep alive: 60s
	}

	// Payload: Client ID
	payload := make([]byte, 2+len(clientID))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(clientID)))
	copy(payload[2:], clientID)

	remainingLen := len(varHeader) + len(payload)
	packet := []byte{MQTTConnect << 4}
	packet = append(packet, encodeRemainingLength(remainingLen)...)
	packet = append(packet, varHeader...)
	packet = append(packet, payload...)

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(packet); err != nil {
		return fmt.Errorf("sending CONNECT: %w", err)
	}

	// Read CONNACK
	resp := make([]byte, 4)
	n, err := c.conn.Read(resp)
	if err != nil {
		return fmt.Errorf("reading CONNACK: %w", err)
	}
	if n < 4 {
		return fmt.Errorf("CONNACK too short")
	}

	if resp[0]>>4 != MQTTConnack {
		return fmt.Errorf("expected CONNACK, got type %d", resp[0]>>4)
	}

	returnCode := resp[3]
	if returnCode != MQTTConnAccepted {
		return fmt.Errorf("connection refused: code %d", returnCode)
	}

	return nil
}

// Subscribe subscribes to a topic filter - READ ONLY (no publish).
func (c *MQTTClient) Subscribe(topicFilter string, qos byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("not connected")
	}

	c.packetID++
	pid := c.packetID

	// Variable header
	varHeader := make([]byte, 2)
	binary.BigEndian.PutUint16(varHeader, pid)

	// Payload: topic filter + QoS
	payload := make([]byte, 2+len(topicFilter)+1)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(topicFilter)))
	copy(payload[2:], topicFilter)
	payload[2+len(topicFilter)] = qos

	remainingLen := len(varHeader) + len(payload)
	packet := []byte{MQTTSubscribe<<4 | 0x02} // Subscribe with mandatory 0x02 flag
	packet = append(packet, encodeRemainingLength(remainingLen)...)
	packet = append(packet, varHeader...)
	packet = append(packet, payload...)

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(packet); err != nil {
		return err
	}

	// Read SUBACK
	_ = c.conn.SetReadDeadline(time.Now().Add(c.config.Timeout))
	resp := make([]byte, 5)
	_, err := c.conn.Read(resp)
	if err != nil {
		return fmt.Errorf("reading SUBACK: %w", err)
	}

	return nil
}

// DiscoverTopics subscribes to wildcard topics and collects published messages - READ ONLY.
func (c *MQTTClient) DiscoverTopics(ctx context.Context, duration time.Duration) (*MQTTBrokerInfo, error) {
	info := &MQTTBrokerInfo{
		Target:    c.target,
		Port:      c.port,
		SysTopics: make(map[string]string),
	}

	// Subscribe to $SYS topics for broker info
	_ = c.Subscribe("$SYS/#", 0)

	// Subscribe to wildcard for topic discovery
	_ = c.Subscribe("#", 0)

	// Collect messages
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return info, nil
		default:
		}

		_ = c.conn.SetReadDeadline(time.Now().Add(time.Second * 2))
		buf := make([]byte, 4096)
		n, err := c.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}

		if n < 2 {
			continue
		}

		topic := c.parsePublish(buf[:n])
		if topic != nil {
			topic.Timestamp = time.Now()
			if len(topic.Name) > 4 && topic.Name[:5] == "$SYS/" {
				info.SysTopics[topic.Name] = topic.Payload
			} else {
				info.DiscoveredTopics = append(info.DiscoveredTopics, *topic)
			}
		}
	}

	info.AllowsAnonymous = true // If we got here, anonymous worked
	return info, nil
}

// parsePublish parses an MQTT PUBLISH packet.
func (c *MQTTClient) parsePublish(data []byte) *MQTTTopic {
	if len(data) < 2 {
		return nil
	}

	packetType := data[0] >> 4
	if packetType != MQTTPublish {
		return nil
	}

	retain := data[0]&0x01 != 0
	qos := (data[0] >> 1) & 0x03

	// Decode remaining length
	pos := 1
	remainLen, bytesUsed := decodeRemainingLength(data[pos:])
	pos += bytesUsed
	_ = remainLen

	if pos+2 > len(data) {
		return nil
	}

	// Topic name
	topicLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+topicLen > len(data) {
		return nil
	}
	topicName := string(data[pos : pos+topicLen])
	pos += topicLen

	// Skip packet ID for QoS > 0
	if qos > 0 {
		pos += 2
	}

	// Payload
	var payload string
	if pos < len(data) {
		payload = string(data[pos:])
	}

	return &MQTTTopic{
		Name:     topicName,
		QoS:      qos,
		Retained: retain,
		Payload:  payload,
	}
}

// encodeRemainingLength encodes an MQTT remaining length value.
func encodeRemainingLength(length int) []byte {
	var encoded []byte
	for {
		encodedByte := byte(length % 128)
		length /= 128
		if length > 0 {
			encodedByte |= 0x80
		}
		encoded = append(encoded, encodedByte)
		if length == 0 {
			break
		}
	}
	return encoded
}

// decodeRemainingLength decodes an MQTT remaining length value.
func decodeRemainingLength(data []byte) (int, int) {
	multiplier := 1
	value := 0
	index := 0

	for index < len(data) && index < 4 {
		encodedByte := data[index]
		value += int(encodedByte&0x7F) * multiplier
		multiplier *= 128
		index++
		if encodedByte&0x80 == 0 {
			break
		}
	}

	return value, index
}
