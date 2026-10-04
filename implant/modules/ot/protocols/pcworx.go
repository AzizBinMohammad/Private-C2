package protocols

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// PC Worx default port
const pcworxDefaultPort = 20547

// SAFETY: PC Worx client is an identification-only stub.
// No write, configuration, or control operations are implemented.

// PCWorxClient is a protocol identification stub for Phoenix Contact PC Worx.
type PCWorxClient struct {
	conn      net.Conn
	target    string
	port      int
	config    ConnConfig
	mu        sync.Mutex
	connected bool
}

// PCWorxInfo holds PC Worx device identification data.
type PCWorxInfo struct {
	Detected    bool   `json:"detected"`
	Vendor      string `json:"vendor"`
	ProductName string `json:"product_name"`
	FirmwareVer string `json:"firmware_ver"`
	SerialNum   string `json:"serial_num"`
	Banner      string `json:"banner,omitempty"`
}

// NewPCWorxClient creates a new PC Worx identification client.
func NewPCWorxClient(config ConnConfig) *PCWorxClient {
	return &PCWorxClient{
		config: config,
	}
}

func (c *PCWorxClient) Name() string { return "pcworx" }

func (c *PCWorxClient) Connect(ctx context.Context, target string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if port == 0 {
		port = pcworxDefaultPort
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

func (c *PCWorxClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *PCWorxClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *PCWorxClient) Identify(ctx context.Context) (*DeviceInfo, error) {
	info, err := c.DetectPCWorx()
	if err != nil {
		return nil, err
	}
	if !info.Detected {
		return nil, fmt.Errorf("PC Worx protocol not detected")
	}
	return &DeviceInfo{
		Vendor:       info.Vendor,
		ProductName:  info.ProductName,
		Firmware:     info.FirmwareVer,
		SerialNumber: info.SerialNum,
		Protocol:     "pcworx",
	}, nil
}

// DetectPCWorx attempts to identify a PC Worx/ProConOS device - READ ONLY.
func (c *PCWorxClient) DetectPCWorx() (*PCWorxInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	info := &PCWorxInfo{
		Vendor: "Phoenix Contact",
	}

	// Send a minimal init probe
	// PC Worx/ProConOS uses a proprietary binary protocol
	initProbe := []byte{
		0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	}

	_ = c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	if _, err := c.conn.Write(initProbe); err != nil {
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
