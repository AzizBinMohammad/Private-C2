package listener

import (
	"context"
	"fmt"
	"sync"
)

// Listener defines the interface that all C2 listeners must implement.
type Listener interface {
	// Start begins accepting connections. Blocks until ctx is cancelled or an error occurs.
	Start(ctx context.Context) error
	// Stop gracefully shuts down the listener.
	Stop() error
	// ID returns the unique identifier for this listener instance.
	ID() string
	// Type returns the listener type (e.g., "mtls", "https", "dns", "wireguard").
	Type() string
	// Addr returns the address the listener is bound to.
	Addr() string
}

// SessionHandler is called when a new implant session is established.
type SessionHandler func(sessionID, engagementID string, meta map[string]string)

// DataHandler is called when data is received from an implant.
type DataHandler func(sessionID string, data []byte) (response []byte, err error)

// BaseListener provides common fields shared by all listener implementations.
type BaseListener struct {
	mu             sync.RWMutex
	id             string
	listenerType   string
	bindAddr       string
	engagementID   string
	sessionHandler SessionHandler
	dataHandler    DataHandler
	active         bool
}

// NewBaseListener creates a new BaseListener with the given parameters.
func NewBaseListener(id, listenerType, bindAddr, engagementID string) BaseListener {
	return BaseListener{
		id:           id,
		listenerType: listenerType,
		bindAddr:     bindAddr,
		engagementID: engagementID,
	}
}

// SetSessionHandler sets the callback for new sessions.
func (b *BaseListener) SetSessionHandler(h SessionHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessionHandler = h
}

// SetDataHandler sets the callback for incoming data.
func (b *BaseListener) SetDataHandler(h DataHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dataHandler = h
}

// OnSession invokes the session handler if set.
func (b *BaseListener) OnSession(sessionID, engagementID string, meta map[string]string) {
	b.mu.RLock()
	h := b.sessionHandler
	b.mu.RUnlock()
	if h != nil {
		h(sessionID, engagementID, meta)
	}
}

// OnData invokes the data handler if set.
func (b *BaseListener) OnData(sessionID string, data []byte) ([]byte, error) {
	b.mu.RLock()
	h := b.dataHandler
	b.mu.RUnlock()
	if h == nil {
		return nil, fmt.Errorf("no data handler registered")
	}
	return h(sessionID, data)
}

// IsActive reports whether the listener is currently running.
func (b *BaseListener) IsActive() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.active
}

// SetActive marks the listener as active or inactive.
func (b *BaseListener) SetActive(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active = v
}
