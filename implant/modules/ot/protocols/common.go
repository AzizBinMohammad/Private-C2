// Package protocols implements read-only OT/ICS protocol clients.
// SAFETY: No protocol client in this package implements any write,
// control, or modification operations. All interactions are strictly
// read-only assessment operations.
package protocols

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ProtocolClient is the interface all OT protocol clients must implement.
type ProtocolClient interface {
	// Name returns the protocol name.
	Name() string
	// Connect establishes a connection to the target.
	Connect(ctx context.Context, target string, port int) error
	// Close terminates the connection.
	Close() error
	// Identify reads device identification information.
	Identify(ctx context.Context) (*DeviceInfo, error)
	// IsConnected reports whether the client is connected.
	IsConnected() bool
}

// ProtocolResponse holds a generic protocol response.
type ProtocolResponse struct {
	Protocol  string         `json:"protocol"`
	Target    string         `json:"target"`
	Port      int            `json:"port"`
	Timestamp time.Time      `json:"timestamp"`
	Success   bool           `json:"success"`
	Error     string         `json:"error,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	RawBytes  []byte         `json:"raw_bytes,omitempty"`
	LatencyMs float64        `json:"latency_ms"`
}

// DeviceInfo holds identity information read from an OT device.
type DeviceInfo struct {
	Vendor       string            `json:"vendor"`
	ProductName  string            `json:"product_name"`
	Model        string            `json:"model"`
	Firmware     string            `json:"firmware"`
	SerialNumber string            `json:"serial_number"`
	HardwareRev  string            `json:"hardware_rev"`
	Description  string            `json:"description"`
	Location     string            `json:"location"`
	Protocol     string            `json:"protocol"`
	Capabilities []string          `json:"capabilities"`
	Extra        map[string]string `json:"extra,omitempty"`
}

// ConnConfig holds connection configuration.
type ConnConfig struct {
	Timeout        time.Duration
	InterPacketDelay time.Duration
	MaxRetries     int
}

// DefaultConnConfig returns conservative connection defaults for OT devices.
func DefaultConnConfig() ConnConfig {
	return ConnConfig{
		Timeout:          5 * time.Second,
		InterPacketDelay: 200 * time.Millisecond,
		MaxRetries:       1,
	}
}

// tcpConnect establishes a TCP connection with timeout.
func tcpConnect(target string, port int, timeout time.Duration) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	return conn, nil
}

// udpConnect creates a UDP connection.
func udpConnect(target string, port int, timeout time.Duration) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// readFull reads exactly n bytes from a connection.
func readFull(conn net.Conn, n int, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, n)
	total := 0
	for total < n {
		read, err := conn.Read(buf[total:])
		if err != nil {
			return buf[:total], err
		}
		total += read
	}
	return buf, nil
}

// readResponse reads available data from a connection up to maxLen bytes.
func readResponse(conn net.Conn, maxLen int, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxLen)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// sendAndReceive sends data and reads the response.
func sendAndReceive(conn net.Conn, data []byte, maxResp int, timeout time.Duration) ([]byte, error) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("sending data: %w", err)
	}
	return readResponse(conn, maxResp, timeout)
}

// crc16 computes a CRC-16 for DNP3 and similar protocols.
func crc16(data []byte) uint16 {
	var crc uint16 = 0xFFFF
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFF
}
