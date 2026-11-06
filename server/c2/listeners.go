package c2

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ListenerTypeMTLS is the only transport the implant currently speaks: a raw
// TLS connection carrying the register/checkin/result protocol handled by
// HandleConnection. The other transport implementations under
// server/c2/listener model sessions differently (client-certificate CN as the
// session ID, request/response data handler) and cannot be substituted here
// without changing the implant's wire protocol.
const ListenerTypeMTLS = "mtls"

// ListenerInfo describes a listener that the server is actually running.
type ListenerInfo struct {
	ID                string `json:"id"`
	Type              string `json:"type"`
	BindAddr          string `json:"bind_addr"`
	Port              int    `json:"port"`
	EngagementID      string `json:"engagement_id"`
	Status            string `json:"status"`
	ActiveConnections int    `json:"active_connections"`
}

// ListenerConfig describes a listener to start.
type ListenerConfig struct {
	ID           string
	Type         string
	BindAddr     string
	Port         int
	EngagementID string
	TLSConfig    *tls.Config
}

// runningListener is the internal record for a bound listener.
type runningListener struct {
	info     ListenerInfo
	ln       net.Listener
	cancel   context.CancelFunc
	conns    sync.WaitGroup
	connMu   sync.Mutex
	connsNow int
	connSet  map[net.Conn]struct{}
}

// StartListener binds a listener and begins accepting implant connections.
//
// Only ListenerTypeMTLS is supported. Requesting any other type returns an
// error rather than reporting a listener that was never bound.
func (s *ImplantServer) StartListener(cfg ListenerConfig) (ListenerInfo, error) {
	if cfg.Type != ListenerTypeMTLS {
		return ListenerInfo{}, fmt.Errorf("listener type %q is not supported yet (only %q is implemented)", cfg.Type, ListenerTypeMTLS)
	}
	if cfg.TLSConfig == nil {
		return ListenerInfo{}, fmt.Errorf("listener %s: TLS configuration is required", cfg.Type)
	}
	if cfg.BindAddr == "" {
		return ListenerInfo{}, fmt.Errorf("listener %s: bind address is required", cfg.Type)
	}
	// Port 0 asks the OS for a free port; the assigned one is reported back.
	if cfg.Port < 0 || cfg.Port > 65535 {
		return ListenerInfo{}, fmt.Errorf("listener %s: port %d is out of range", cfg.Type, cfg.Port)
	}

	id := cfg.ID
	if id == "" {
		id = uuid.New().String()
	}

	// Reserve the ID and bind while holding the lock. The previous check-then-
	// insert sequence let two concurrent starts with the same ID both bind,
	// with the second overwriting the first in the map and leaking its socket.
	s.mu.Lock()
	if s.listeners == nil {
		s.listeners = make(map[string]*runningListener)
	}
	if _, exists := s.listeners[id]; exists {
		s.mu.Unlock()
		return ListenerInfo{}, fmt.Errorf("listener %s is already running", id)
	}

	addr := net.JoinHostPort(cfg.BindAddr, fmt.Sprintf("%d", cfg.Port))
	ln, err := tls.Listen("tcp", addr, cfg.TLSConfig)
	if err != nil {
		s.mu.Unlock()
		return ListenerInfo{}, fmt.Errorf("binding %s listener on %s: %w", cfg.Type, addr, err)
	}

	// Report the address actually bound: with port 0 the OS picks one.
	boundPort := cfg.Port
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		boundPort = tcpAddr.Port
	}

	ctx, cancel := context.WithCancel(context.Background())
	rl := &runningListener{
		info: ListenerInfo{
			ID:           id,
			Type:         cfg.Type,
			BindAddr:     cfg.BindAddr,
			Port:         boundPort,
			EngagementID: cfg.EngagementID,
			Status:       "running",
		},
		ln:      ln,
		cancel:  cancel,
		connSet: make(map[net.Conn]struct{}),
	}
	s.listeners[id] = rl
	s.mu.Unlock()

	go s.acceptLoop(ctx, rl)

	log.Printf("[c2] %s listener %s started on %s", cfg.Type, id, ln.Addr())
	return rl.info, nil
}

// acceptLoop serves connections until the listener is stopped.
func (s *ImplantServer) acceptLoop(ctx context.Context, rl *runningListener) {
	delay := 50 * time.Millisecond
	for {
		conn, err := rl.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// A persistent accept error (EMFILE, transient network failure)
			// must not turn into a busy spin.
			log.Printf("[c2] listener %s accept error: %v (retry in %v)", rl.info.ID, err, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			if delay < 5*time.Second {
				delay *= 2
			}
			continue
		}
		delay = 50 * time.Millisecond

		rl.connMu.Lock()
		rl.connsNow++
		if rl.connSet == nil {
			rl.connSet = make(map[net.Conn]struct{})
		}
		rl.connSet[conn] = struct{}{}
		rl.connMu.Unlock()
		rl.conns.Add(1)

		go func(c net.Conn) {
			defer func() {
				rl.connMu.Lock()
				delete(rl.connSet, c)
				rl.connsNow--
				rl.connMu.Unlock()
				rl.conns.Done()
			}()
			s.HandleConnection(c)
		}(conn)
	}
}

// StopListener shuts down a running listener and closes its socket. The
// server's own sessions are not affected; only new connections are refused.
func (s *ImplantServer) StopListener(id string) error {
	s.mu.Lock()
	rl, ok := s.listeners[id]
	if ok {
		delete(s.listeners, id)
	}
	s.mu.Unlock()

	if !ok {
		return ErrListenerNotFound
	}
	rl.cancel()
	if err := rl.ln.Close(); err != nil {
		log.Printf("[c2] listener %s: closing: %v", id, err)
	}

	// Close accepted connections so their handler goroutines exit. Waiting
	// keeps StopListener from returning while sessions still believe they are
	// served by this listener.
	rl.connMu.Lock()
	active := make([]net.Conn, 0, len(rl.connSet))
	for c := range rl.connSet {
		active = append(active, c)
	}
	rl.connMu.Unlock()
	for _, c := range active {
		_ = c.Close()
	}

	done := make(chan struct{})
	go func() {
		rl.conns.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Printf("[c2] listener %s: timed out waiting for %d connection(s) to close", id, len(active))
	}

	log.Printf("[c2] listener %s stopped", id)
	return nil
}

// Listeners returns every listener the server is currently running.
func (s *ImplantServer) Listeners() []ListenerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ListenerInfo, 0, len(s.listeners))
	for _, rl := range s.listeners {
		info := rl.info
		rl.connMu.Lock()
		info.ActiveConnections = rl.connsNow
		rl.connMu.Unlock()
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// GetListener returns a single running listener by ID.
func (s *ImplantServer) GetListener(id string) (ListenerInfo, bool) {
	s.mu.RLock()
	rl, ok := s.listeners[id]
	s.mu.RUnlock()
	if !ok {
		return ListenerInfo{}, false
	}

	info := rl.info
	rl.connMu.Lock()
	info.ActiveConnections = rl.connsNow
	rl.connMu.Unlock()
	return info, true
}

// ErrListenerNotFound is returned when the given listener is not running.
var ErrListenerNotFound = fmt.Errorf("listener not found")
