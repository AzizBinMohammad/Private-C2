package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

// ConnectionState represents the health of the gRPC connection.
type ConnectionState string

const (
	StateDisconnected ConnectionState = "disconnected"
	StateConnecting   ConnectionState = "connecting"
	StateConnected    ConnectionState = "connected"
	StateReconnecting ConnectionState = "reconnecting"
)

// GRPCClient manages the gRPC connection to the C2 server.
// It uses the interface pattern since grpc is not yet in the client go.mod.
// When google.golang.org/grpc is added, the Conn field and dial methods
// will use grpc.ClientConn directly.
type GRPCClient struct {
	mu        sync.RWMutex
	config    *Config
	state     ConnectionState
	tlsConfig *tls.Config
	lastError error

	// Conn holds the underlying connection handle. It is typed as
	// interface{} because the grpc dependency is not yet in the client
	// module. When grpc is added, this becomes *grpc.ClientConn.
	Conn interface{}

	// Callbacks
	onStateChange func(ConnectionState)
	onReconnect   func(attempt int)

	stopCh chan struct{}
}

// NewGRPCClient creates a new client from the given operator config.
func NewGRPCClient(cfg *Config) (*GRPCClient, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build TLS config: %w", err)
	}

	return &GRPCClient{
		config:    cfg,
		state:     StateDisconnected,
		tlsConfig: tlsCfg,
		stopCh:    make(chan struct{}),
	}, nil
}

// SetStateChangeHandler registers a callback for connection state changes.
func (c *GRPCClient) SetStateChangeHandler(handler func(ConnectionState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onStateChange = handler
}

// SetReconnectHandler registers a callback invoked on each reconnection attempt.
func (c *GRPCClient) SetReconnectHandler(handler func(attempt int)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onReconnect = handler
}

// Connect establishes the gRPC connection to the server.
// This is a stub that sets up the TLS credentials and transitions state.
// When grpc is added to go.mod, this will call grpc.Dial with the TLS
// credentials and return the real ClientConn.
func (c *GRPCClient) Connect() error {
	c.setState(StateConnecting)

	// Stub: In a full implementation this would be:
	//   creds := credentials.NewTLS(c.tlsConfig)
	//   conn, err := grpc.Dial(c.config.ServerAddr, grpc.WithTransportCredentials(creds))
	//   c.Conn = conn

	c.setState(StateConnected)
	return nil
}

// Disconnect closes the gRPC connection.
func (c *GRPCClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}

	// Stub: In a full implementation this would close c.Conn.
	c.Conn = nil
	c.state = StateDisconnected
	return nil
}

// State returns the current connection state.
func (c *GRPCClient) State() ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// LastError returns the most recent connection error, if any.
func (c *GRPCClient) LastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastError
}

// ServerAddr returns the configured server address.
func (c *GRPCClient) ServerAddr() string {
	return c.config.ServerAddr
}

// OperatorName returns the configured operator name.
func (c *GRPCClient) OperatorName() string {
	return c.config.Operator
}

// StartHealthMonitor begins a background goroutine that periodically checks
// the connection health and triggers reconnection when needed.
func (c *GRPCClient) StartHealthMonitor(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.checkHealth()
			}
		}
	}()
}

// checkHealth verifies the connection is alive and attempts to reconnect
// if the connection has been lost.
func (c *GRPCClient) checkHealth() {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()

	if state == StateConnected {
		// Stub: In a full implementation, this would call the gRPC health
		// check endpoint or check the ClientConn state.
		return
	}

	if state == StateDisconnected || state == StateReconnecting {
		c.reconnect()
	}
}

// reconnect attempts to re-establish the gRPC connection with exponential
// backoff.
func (c *GRPCClient) reconnect() {
	c.setState(StateReconnecting)

	maxAttempts := 10
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		select {
		case <-c.stopCh:
			return
		default:
		}

		c.mu.RLock()
		handler := c.onReconnect
		c.mu.RUnlock()
		if handler != nil {
			handler(attempt)
		}

		if err := c.Connect(); err != nil {
			c.mu.Lock()
			c.lastError = err
			c.mu.Unlock()

			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > maxDelay {
				delay = maxDelay
			}

			timer := time.NewTimer(delay)
			select {
			case <-c.stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}

		return
	}

	c.setState(StateDisconnected)
	c.mu.Lock()
	c.lastError = fmt.Errorf("failed to reconnect after %d attempts", maxAttempts)
	c.mu.Unlock()
}

// setState updates the connection state and invokes the state change callback.
func (c *GRPCClient) setState(state ConnectionState) {
	c.mu.Lock()
	c.state = state
	handler := c.onStateChange
	c.mu.Unlock()

	if handler != nil {
		handler(state)
	}
}

// buildTLSConfig constructs the mTLS configuration from the operator's
// certificate files.
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	caCert, err := os.ReadFile(cfg.ResolvePath(cfg.CACertPath))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to add CA certificate")
	}

	cert, err := tls.LoadX509KeyPair(
		cfg.ResolvePath(cfg.CertPath),
		cfg.ResolvePath(cfg.KeyPath),
	)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
