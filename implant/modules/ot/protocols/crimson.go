package protocols

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Crimson default port
const crimsonDefaultPort = 789

// SAFETY: Crimson client is an identification-only stub.
// No write, configuration, or control operations are implemented.

// CrimsonClient is a protocol identification stub for Red Lion Crimson devices.
type CrimsonClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
}

// CrimsonInfo holds Red Lion Crimson device identification data.
type CrimsonInfo struct {
	Detected   bool   `json:"detected"`
	Vendor     string `json:"vendor"`
	Model      string `json:"model"`
	Firmware   string `json:"firmware"`
	HostName   string `json:"hostname,omitempty"`
	Banner     string `json:"banner,omitempty"`
}

// NewCrimsonClient creates a new Crimson device identification client.
func NewCrimsonClient(config ConnConfig) *CrimsonClient {
	return &CrimsonClient{
		config: config,
	}
}

func (c *CrimsonClient) Name() string { return "crimson" }

func (c *CrimsonClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = crimsonDefaultPort
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

func (c *CrimsonClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *CrimsonClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *CrimsonClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	info, err := c.DetectCrimson()
	if err != nil {
		return nil, err
	}
	if !info.Detected {
		return nil, fmt.Errorf("Crimson protocol not detected")
	}
	return &DeviceInfo{
		Vendor:   info.Vendor,
		Model:    info.Model,
		Firmware: info.Firmware,
		Protocol: "crimson",
	}, nil
}

// DetectCrimson attempts to identify a Red Lion Crimson device - READ ONLY.
func (c *CrimsonClient) DetectCrimson() (*CrimsonInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	info := &CrimsonInfo{
		Vendor: "Red Lion Controls",
	}

	// Crimson v3 uses a proprietary protocol on port 789
	// Send a minimal discovery/info probe
	probe := []byte{
		0x00, 0x00, 0x00, 0x00, 0x16, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(probe); err != nil {
		return info, nil
	}

	resp := make([]byte, 512)
	n, err := c.conn.Read(resp)
	if err != nil {
		return info, nil
	}

	if n > 0 {
		info.Detected = true
		info.Banner = sanitizeString(resp[:n])
	}

	time.Sleep(c.config.InterPacketDelay)
	return info, nil
}
