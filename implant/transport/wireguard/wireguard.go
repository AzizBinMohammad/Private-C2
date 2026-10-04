package wireguard

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrClosed       = errors.New("transport closed")
)

// Transport implements the Transport interface as a userspace WireGuard client stub.
// It establishes a WireGuard tunnel to the server and runs an inner transport
// (typically mTLS) over the encrypted tunnel.
//
// TODO: Integrate with a userspace WireGuard implementation (e.g., wireguard-go)
// for actual tunnel establishment. Currently acts as a pass-through stub.
type Transport struct {
	mu         sync.Mutex
	privateKey string
	publicKey  string
	endpoint   string
	peerKey    string
	allowedIPs []string
	listenPort int
	connected  bool
	closed     bool
	sendCh     chan []byte
	recvCh     chan []byte
	cancelFunc context.CancelFunc
}

// Config holds the configuration for the WireGuard transport.
type Config struct {
	PrivateKey string
	PublicKey  string
	Endpoint   string   // server endpoint (host:port)
	PeerKey    string   // server's public key
	AllowedIPs []string // CIDRs to route through tunnel
	ListenPort int
}

// New creates a new WireGuard transport stub.
func New(cfg Config) (*Transport, error) {
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("WireGuard private key is required")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("WireGuard endpoint is required")
	}
	if cfg.PeerKey == "" {
		return nil, fmt.Errorf("WireGuard peer public key is required")
	}

	allowedIPs := cfg.AllowedIPs
	if len(allowedIPs) == 0 {
		allowedIPs = []string{"0.0.0.0/0"}
	}

	return &Transport{
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PublicKey,
		endpoint:   cfg.Endpoint,
		peerKey:    cfg.PeerKey,
		allowedIPs: allowedIPs,
		listenPort: cfg.ListenPort,
		sendCh:     make(chan []byte, 64),
		recvCh:     make(chan []byte, 64),
	}, nil
}

// Connect establishes the WireGuard tunnel.
// TODO: Actually create a userspace WireGuard device and configure it.
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrClosed
	}

	// TODO: Initialize wireguard-go device:
	// 1. Create TUN device
	// 2. Configure private key, listen port
	// 3. Add peer with public key, endpoint, allowed IPs
	// 4. Bring up the interface

	ctx, cancel := context.WithCancel(ctx)
	t.cancelFunc = cancel
	t.connected = true

	// Stub: run a goroutine that would normally forward packets.
	go func() {
		<-ctx.Done()
	}()

	return nil
}

// Send transmits data through the WireGuard tunnel.
// TODO: Write data to the TUN device for encryption and transmission.
func (t *Transport) Send(data []byte) error {
	t.mu.Lock()
	if !t.connected {
		t.mu.Unlock()
		return ErrNotConnected
	}
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.mu.Unlock()

	// TODO: Write to the WireGuard TUN device.
	select {
	case t.sendCh <- data:
		return nil
	default:
		return fmt.Errorf("send buffer full")
	}
}

// Recv receives data from the WireGuard tunnel.
// TODO: Read data from the TUN device after decryption.
func (t *Transport) Recv() ([]byte, error) {
	data, ok := <-t.recvCh
	if !ok {
		return nil, ErrClosed
	}
	return data, nil
}

// Close shuts down the WireGuard tunnel.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	t.connected = false
	if t.cancelFunc != nil {
		t.cancelFunc()
	}

	close(t.sendCh)
	close(t.recvCh)

	// TODO: Close the WireGuard TUN device and clean up.
	return nil
}

// Name returns the transport name.
func (t *Transport) Name() string {
	return "wireguard"
}
