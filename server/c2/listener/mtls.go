package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
)

// MTLSListener implements a mutual TLS TCP listener with TLS 1.3,
// client certificate validation, bidirectional streaming, and connection tracking.
type MTLSListener struct {
	BaseListener
	tlsConfig  *tls.Config
	listener   net.Listener
	conns      map[string]net.Conn
	connsMu    sync.RWMutex
	cancelFunc context.CancelFunc
}

// MTLSConfig holds the configuration for an mTLS listener.
type MTLSConfig struct {
	ID             string
	BindAddr       string
	EngagementID   string
	ServerCertPEM  []byte
	ServerKeyPEM   []byte
	CACertPEM      []byte
}

// NewMTLSListener creates a new mutual TLS listener.
func NewMTLSListener(cfg MTLSConfig) (*MTLSListener, error) {
	cert, err := tls.X509KeyPair(cfg.ServerCertPEM, cfg.ServerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(cfg.CACertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	return &MTLSListener{
		BaseListener: NewBaseListener(cfg.ID, "mtls", cfg.BindAddr, cfg.EngagementID),
		tlsConfig:    tlsConfig,
		conns:        make(map[string]net.Conn),
	}, nil
}

// Start begins listening for mTLS connections.
func (m *MTLSListener) Start(ctx context.Context) error {
	ln, err := tls.Listen("tcp", m.bindAddr, m.tlsConfig)
	if err != nil {
		return fmt.Errorf("starting mTLS listener on %s: %w", m.bindAddr, err)
	}
	m.listener = ln
	m.SetActive(true)

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFunc = cancel

	log.Printf("[mtls] listener %s started on %s", m.id, m.bindAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[mtls] accept error: %v", err)
				continue
			}
		}
		go m.handleConnection(ctx, conn)
	}
}

// Stop shuts down the mTLS listener and closes all tracked connections.
func (m *MTLSListener) Stop() error {
	m.SetActive(false)
	if m.cancelFunc != nil {
		m.cancelFunc()
	}

	m.connsMu.Lock()
	for id, conn := range m.conns {
		conn.Close()
		delete(m.conns, id)
	}
	m.connsMu.Unlock()

	if m.listener != nil {
		return m.listener.Close()
	}
	return nil
}

// ID returns the listener's unique identifier.
func (m *MTLSListener) ID() string { return m.id }

// Type returns the listener type.
func (m *MTLSListener) Type() string { return m.listenerType }

// Addr returns the listener's bind address.
func (m *MTLSListener) Addr() string { return m.bindAddr }

// ActiveConnections returns the number of active connections.
func (m *MTLSListener) ActiveConnections() int {
	m.connsMu.RLock()
	defer m.connsMu.RUnlock()
	return len(m.conns)
}

// handleConnection processes a single mTLS connection.
func (m *MTLSListener) handleConnection(ctx context.Context, conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Printf("[mtls] handshake failed from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("[mtls] no client certificate from %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	clientCN := state.PeerCertificates[0].Subject.CommonName
	sessionID := clientCN

	m.connsMu.Lock()
	m.conns[sessionID] = conn
	m.connsMu.Unlock()

	m.OnSession(sessionID, m.engagementID, map[string]string{
		"remote_addr": conn.RemoteAddr().String(),
		"transport":   "mtls",
		"cn":          clientCN,
	})

	defer func() {
		m.connsMu.Lock()
		delete(m.conns, sessionID)
		m.connsMu.Unlock()
		conn.Close()
	}()

	// Bidirectional streaming loop: read framed messages and dispatch.
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, err := envelope.ReadFrame(conn)
		if err != nil {
			log.Printf("[mtls] read error from %s: %v", sessionID, err)
			return
		}

		response, err := m.OnData(sessionID, data)
		if err != nil {
			log.Printf("[mtls] handler error for %s: %v", sessionID, err)
			continue
		}

		if response != nil {
			if err := envelope.WriteFrame(conn, response); err != nil {
				log.Printf("[mtls] write error to %s: %v", sessionID, err)
				return
			}
		}
	}
}

// SendTo sends data to a specific connected session.
func (m *MTLSListener) SendTo(sessionID string, data []byte) error {
	m.connsMu.RLock()
	conn, ok := m.conns[sessionID]
	m.connsMu.RUnlock()
	if !ok {
		return fmt.Errorf("session %s not connected", sessionID)
	}
	return envelope.WriteFrame(conn, data)
}
