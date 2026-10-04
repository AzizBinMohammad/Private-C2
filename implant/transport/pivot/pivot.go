package pivot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrClosed       = errors.New("transport closed")
)

// PivotMode defines the type of pivot transport.
type PivotMode string

const (
	// ModeTCPRelay uses a TCP connection for cross-platform relay.
	ModeTCPRelay PivotMode = "tcp"
	// ModeNamedPipe uses Windows named pipes.
	ModeNamedPipe PivotMode = "namedpipe"
)

// Transport implements the Transport interface for peer-to-peer communication,
// supporting TCP relay (cross-platform) and named pipes (Windows).
type Transport struct {
	mu         sync.Mutex
	mode       PivotMode
	targetAddr string // TCP address or pipe name
	conn       net.Conn
	closed     bool
	connected  bool
	isServer   bool // true if this side listens for connections
	listener   net.Listener
	cancelFunc context.CancelFunc
}

// Config holds the configuration for the pivot transport.
type Config struct {
	Mode       PivotMode
	TargetAddr string // host:port for TCP, \\.\pipe\name for named pipe
	IsServer   bool   // if true, listen for incoming connections instead of dialing
}

// New creates a new pivot transport.
func New(cfg Config) (*Transport, error) {
	if cfg.TargetAddr == "" {
		return nil, fmt.Errorf("target address is required")
	}

	mode := cfg.Mode
	if mode == "" {
		mode = ModeTCPRelay
	}

	return &Transport{
		mode:       mode,
		targetAddr: cfg.TargetAddr,
		isServer:   cfg.IsServer,
	}, nil
}

// Connect establishes the pivot connection.
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrClosed
	}

	ctx, cancel := context.WithCancel(ctx)
	t.cancelFunc = cancel

	switch t.mode {
	case ModeTCPRelay:
		return t.connectTCP(ctx)
	case ModeNamedPipe:
		return t.connectNamedPipe(ctx)
	default:
		return fmt.Errorf("unsupported pivot mode: %s", t.mode)
	}
}

// connectTCP establishes a TCP relay connection.
func (t *Transport) connectTCP(ctx context.Context) error {
	if t.isServer {
		ln, err := net.Listen("tcp", t.targetAddr)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", t.targetAddr, err)
		}
		t.listener = ln

		// Accept one connection (point-to-point relay).
		go func() {
			<-ctx.Done()
			ln.Close()
		}()

		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accepting peer connection: %w", err)
		}
		t.conn = conn
		t.connected = true
		return nil
	}

	// Client mode: dial the peer.
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", t.targetAddr)
	if err != nil {
		return fmt.Errorf("connecting to peer at %s: %w", t.targetAddr, err)
	}
	t.conn = conn
	t.connected = true
	return nil
}

// connectNamedPipe establishes a named pipe connection.
// TODO: Implement Windows named pipe support using platform-specific APIs.
func (t *Transport) connectNamedPipe(_ context.Context) error {
	// Named pipes are Windows-specific and require platform-specific code.
	// On non-Windows platforms, fall back to TCP.
	return fmt.Errorf("named pipe transport not available on this platform; use TCP mode")
}

// Send writes framed data to the connected peer.
func (t *Transport) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || t.conn == nil {
		return ErrNotConnected
	}
	if t.closed {
		return ErrClosed
	}

	return envelope.WriteFrame(t.conn, data)
}

// Recv reads a framed message from the connected peer.
func (t *Transport) Recv() ([]byte, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return nil, ErrNotConnected
	}

	return envelope.ReadFrame(conn)
}

// Close shuts down the pivot transport.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	t.connected = false

	if t.cancelFunc != nil {
		t.cancelFunc()
	}

	var firstErr error
	if t.conn != nil {
		if err := t.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.conn = nil
	}
	if t.listener != nil {
		if err := t.listener.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.listener = nil
	}

	return firstErr
}

// Name returns the transport name.
func (t *Transport) Name() string {
	return fmt.Sprintf("pivot-%s", t.mode)
}
