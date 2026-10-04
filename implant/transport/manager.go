package transport

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

var (
	ErrNoTransports       = errors.New("no transports configured")
	ErrAllTransportsFailed = errors.New("all transports failed to connect")
)

// transportEntry tracks a registered transport and its health metrics.
type transportEntry struct {
	transport   Transport
	priority    int     // lower is higher priority (original order index)
	failures    int     // consecutive failure count
	healthScore float64 // 1.0 = healthy, 0.0 = dead
	lastFailure time.Time
	backoffUntil time.Time
}

// Manager handles transport selection, failover, health scoring,
// backoff timing, and re-promotion of higher-priority transports.
type Manager struct {
	mu        sync.Mutex
	entries   []*transportEntry
	active    int // index into entries of the currently active transport
	maxBackoff time.Duration
}

// NewManager creates a transport manager from an ordered list of transports.
// The first transport in the list has the highest priority.
func NewManager(transports []Transport) *Manager {
	entries := make([]*transportEntry, len(transports))
	for i, t := range transports {
		entries[i] = &transportEntry{
			transport:   t,
			priority:    i,
			healthScore: 1.0,
		}
	}
	return &Manager{
		entries:    entries,
		active:     -1,
		maxBackoff: 5 * time.Minute,
	}
}

// Connect attempts to establish a connection using the highest-priority
// available transport. It walks the transport list in priority order,
// skipping entries that are in backoff.
func (m *Manager) Connect(ctx context.Context) (Transport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.entries) == 0 {
		return nil, ErrNoTransports
	}

	now := time.Now()

	// Try each transport in priority order
	for i, entry := range m.entries {
		// Skip transports still in backoff
		if now.Before(entry.backoffUntil) {
			continue
		}

		if err := entry.transport.Connect(ctx); err != nil {
			m.recordFailureLocked(i)
			continue
		}

		// Success
		entry.failures = 0
		entry.healthScore = 1.0
		m.active = i
		return entry.transport, nil
	}

	return nil, ErrAllTransportsFailed
}

// Failover disconnects the current transport and attempts to connect
// using the next available transport in priority order.
func (m *Manager) Failover(ctx context.Context) (Transport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.entries) == 0 {
		return nil, ErrNoTransports
	}

	// Mark current transport as failed
	if m.active >= 0 && m.active < len(m.entries) {
		m.recordFailureLocked(m.active)
		_ = m.entries[m.active].transport.Close()
	}

	now := time.Now()

	// Try each transport in priority order, skipping the failed one and
	// any in backoff
	for i, entry := range m.entries {
		if i == m.active {
			continue
		}
		if now.Before(entry.backoffUntil) {
			continue
		}

		if err := entry.transport.Connect(ctx); err != nil {
			m.recordFailureLocked(i)
			continue
		}

		entry.failures = 0
		entry.healthScore = 1.0
		m.active = i
		return entry.transport, nil
	}

	return nil, ErrAllTransportsFailed
}

// Active returns the currently active transport, or nil if none is connected.
func (m *Manager) Active() Transport {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active >= 0 && m.active < len(m.entries) {
		return m.entries[m.active].transport
	}
	return nil
}

// TryPromote checks whether a higher-priority transport has recovered
// from its backoff period and, if so, attempts to reconnect to it.
// If successful, the current transport is replaced. This should be
// called periodically to re-promote preferred transports.
func (m *Manager) TryPromote(ctx context.Context) (Transport, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active < 0 || len(m.entries) == 0 {
		return nil, false
	}

	now := time.Now()

	// Look for a higher-priority transport that is past its backoff
	for i := 0; i < m.active; i++ {
		entry := m.entries[i]
		if now.Before(entry.backoffUntil) {
			continue
		}

		if err := entry.transport.Connect(ctx); err != nil {
			m.recordFailureLocked(i)
			continue
		}

		// Higher-priority transport recovered; switch to it
		_ = m.entries[m.active].transport.Close()
		entry.failures = 0
		entry.healthScore = 1.0
		m.active = i
		return entry.transport, true
	}

	return nil, false
}

// HealthScores returns a snapshot of each transport's health score.
func (m *Manager) HealthScores() map[string]float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	scores := make(map[string]float64, len(m.entries))
	for _, entry := range m.entries {
		scores[entry.transport.Name()] = entry.healthScore
	}
	return scores
}

// recordFailureLocked updates health metrics and computes the exponential
// backoff for a failed transport. Must be called with m.mu held.
func (m *Manager) recordFailureLocked(idx int) {
	entry := m.entries[idx]
	entry.failures++
	entry.lastFailure = time.Now()

	// Exponential backoff: base 2s, capped at maxBackoff
	backoff := time.Duration(math.Min(
		float64(2*time.Second)*math.Pow(2, float64(entry.failures-1)),
		float64(m.maxBackoff),
	))
	entry.backoffUntil = time.Now().Add(backoff)

	// Decay health score based on failures (min 0.0)
	entry.healthScore = math.Max(0.0, 1.0-float64(entry.failures)*0.2)
}
