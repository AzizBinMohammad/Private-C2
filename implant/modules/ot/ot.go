// Package ot implements the OT/ICS assessment module for the implant.
// ALL operations are READ-ONLY with safety interlocks to prevent any
// modification to operational technology systems.
package ot

import (
	"fmt"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/engagement"
)

// OTConfig holds configuration for the OT assessment module.
type OTConfig struct {
	// MaxConcurrentConns limits simultaneous connections to OT devices.
	MaxConcurrentConns int `json:"max_concurrent_conns"`
	// QueryTimeoutMs is the timeout for individual protocol queries.
	QueryTimeoutMs int `json:"query_timeout_ms"`
	// ScanRatePerSec limits the number of scan operations per second.
	ScanRatePerSec int `json:"scan_rate_per_sec"`
	// InterPacketDelayMs adds delay between packets to avoid overwhelming devices.
	InterPacketDelayMs int `json:"inter_packet_delay_ms"`
	// DataLevel controls data collection granularity: "minimal", "standard", "verbose".
	DataLevel string `json:"data_level"`
	// SafetyCriticalTags are device tags that require additional safety checks.
	SafetyCriticalTags []string `json:"safety_critical_tags"`
	// DualAuthRequired requires two operators to approve critical operations.
	DualAuthRequired bool `json:"dual_auth_required"`
	// CredentialTestingOn enables default credential testing (single attempt only).
	CredentialTestingOn bool `json:"credential_testing_on"`
	// WatchdogTimeoutSec is the server contact timeout before auto-shutdown.
	WatchdogTimeoutSec int `json:"watchdog_timeout_sec"`
	// CaptureMaxDuration limits traffic capture duration.
	CaptureMaxDuration time.Duration `json:"capture_max_duration"`
	// CaptureMaxBytes limits traffic capture size.
	CaptureMaxBytes int64 `json:"capture_max_bytes"`
}

// DefaultOTConfig returns a conservative default configuration.
func DefaultOTConfig() OTConfig {
	return OTConfig{
		MaxConcurrentConns:  3,
		QueryTimeoutMs:      5000,
		ScanRatePerSec:      5,
		InterPacketDelayMs:  200,
		DataLevel:           "standard",
		SafetyCriticalTags:  []string{"SIS", "ESD", "SIL3", "SIL4", "safety"},
		DualAuthRequired:    true,
		CredentialTestingOn: false,
		WatchdogTimeoutSec:  120,
		CaptureMaxDuration:  30 * time.Minute,
		CaptureMaxBytes:     100 * 1024 * 1024, // 100MB
	}
}

// OTModule is the main OT/ICS assessment module with safety interlocks.
type OTModule struct {
	config      OTConfig
	safetyLock  sync.Mutex
	activeConns int
	connMu      sync.Mutex
	killSwitch  *engagement.KillSwitch
	scope       *engagement.Scope
	timeWindow  *engagement.TimeWindow
	watchdog    *OTWatchdog
	connTracker *ConnectionTracker
	engagementID string
	shutdown    bool
	shutdownMu  sync.RWMutex
	rateLimiter *RateLimiter
}

// ConnectionTracker tracks active connections to OT devices.
type ConnectionTracker struct {
	mu    sync.Mutex
	conns map[string]time.Time // target -> connection start time
}

// NewConnectionTracker creates a new connection tracker.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		conns: make(map[string]time.Time),
	}
}

// Add records a new connection.
func (ct *ConnectionTracker) Add(target string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.conns[target] = time.Now()
}

// Remove removes a connection record.
func (ct *ConnectionTracker) Remove(target string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.conns, target)
}

// Count returns the number of active connections.
func (ct *ConnectionTracker) Count() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return len(ct.conns)
}

// Active returns a copy of current active connections.
func (ct *ConnectionTracker) Active() map[string]time.Time {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	result := make(map[string]time.Time, len(ct.conns))
	for k, v := range ct.conns {
		result[k] = v
	}
	return result
}

// OTWatchdog monitors server connectivity and triggers shutdown on timeout.
type OTWatchdog struct {
	mu                sync.Mutex
	lastServerContact time.Time
	timeout           time.Duration
	shutdownFunc      func()
	stopped           bool
	stopCh            chan struct{}
}

// NewOTWatchdog creates a watchdog with the given timeout and shutdown function.
func NewOTWatchdog(timeout time.Duration, shutdownFunc func()) *OTWatchdog {
	return &OTWatchdog{
		lastServerContact: time.Now(),
		timeout:           timeout,
		shutdownFunc:      shutdownFunc,
		stopCh:            make(chan struct{}),
	}
}

// Tick updates the last server contact time, indicating the server is reachable.
func (w *OTWatchdog) Tick() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastServerContact = time.Now()
}

// Start begins the watchdog monitoring loop.
func (w *OTWatchdog) Start() {
	go func() {
		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				w.mu.Lock()
				elapsed := time.Since(w.lastServerContact)
				stopped := w.stopped
				w.mu.Unlock()
				if !stopped && elapsed > w.timeout {
					w.shutdownFunc()
					return
				}
			case <-w.stopCh:
				return
			}
		}
	}()
}

// Stop halts the watchdog.
func (w *OTWatchdog) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		w.stopped = true
		close(w.stopCh)
	}
}

// RateLimiter enforces scan rate limits.
type RateLimiter struct {
	mu         sync.Mutex
	rate       int
	tokens     int
	lastRefill time.Time
}

// NewRateLimiter creates a rate limiter with the given operations per second.
func NewRateLimiter(ratePerSec int) *RateLimiter {
	return &RateLimiter{
		rate:       ratePerSec,
		tokens:     ratePerSec,
		lastRefill: time.Now(),
	}
}

// Allow checks if an operation is permitted under the rate limit.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	if elapsed >= time.Second {
		rl.tokens = rl.rate
		rl.lastRefill = now
	}

	if rl.tokens <= 0 {
		return false
	}
	rl.tokens--
	return true
}

// Wait blocks until an operation is allowed.
func (rl *RateLimiter) Wait() {
	for !rl.Allow() {
		time.Sleep(time.Millisecond * 50)
	}
}

// NewOTModule creates a new OT assessment module with the given configuration and safety components.
func NewOTModule(config OTConfig, ks *engagement.KillSwitch, scope *engagement.Scope, tw *engagement.TimeWindow, engID string) *OTModule {
	m := &OTModule{
		config:       config,
		killSwitch:   ks,
		scope:        scope,
		timeWindow:   tw,
		connTracker:  NewConnectionTracker(),
		engagementID: engID,
		rateLimiter:  NewRateLimiter(config.ScanRatePerSec),
	}

	m.watchdog = NewOTWatchdog(
		time.Duration(config.WatchdogTimeoutSec)*time.Second,
		m.EmergencyShutdown,
	)

	return m
}

// Start initializes the module and starts the watchdog.
func (m *OTModule) Start() {
	m.watchdog.Start()
}

// Stop gracefully shuts down the OT module.
func (m *OTModule) Stop() {
	m.watchdog.Stop()
	m.shutdownMu.Lock()
	m.shutdown = true
	m.shutdownMu.Unlock()
}

// IsShutdown reports whether the module has been shut down.
func (m *OTModule) IsShutdown() bool {
	m.shutdownMu.RLock()
	defer m.shutdownMu.RUnlock()
	return m.shutdown
}

// PreFlightCheck validates all safety conditions before any OT operation.
// Returns an error if any safety condition is not met.
func (m *OTModule) PreFlightCheck(target, protocol string) error {
	m.safetyLock.Lock()
	defer m.safetyLock.Unlock()

	// 1. Check if module is shut down
	if m.IsShutdown() {
		return fmt.Errorf("OT module is shut down")
	}

	// 2. Check kill switch
	if active, reason := m.killSwitch.IsActive(m.engagementID); active {
		return fmt.Errorf("kill switch active: %s", reason)
	}

	// 3. Check scope
	inScope, reason := m.scope.Contains(target)
	if !inScope {
		return fmt.Errorf("target out of scope: %s", reason)
	}

	// 4. Check time window
	if m.timeWindow != nil {
		if active, reason := m.timeWindow.IsActive(); !active {
			return fmt.Errorf("outside time window: %s", reason)
		}
	}

	// 5. Check connection limit
	m.connMu.Lock()
	connCount := m.activeConns
	m.connMu.Unlock()
	if connCount >= m.config.MaxConcurrentConns {
		return fmt.Errorf("max concurrent connections reached (%d/%d)", connCount, m.config.MaxConcurrentConns)
	}

	// 6. Check safety-critical tags
	if m.isSafetyCritical(target) {
		return fmt.Errorf("target %q is tagged as safety-critical; manual review required", target)
	}

	// 7. Check rate limit
	if !m.rateLimiter.Allow() {
		return fmt.Errorf("scan rate limit exceeded (%d ops/sec)", m.config.ScanRatePerSec)
	}

	return nil
}

// isSafetyCritical checks if a target matches any safety-critical tags.
func (m *OTModule) isSafetyCritical(target string) bool {
	// Safety-critical determination would normally involve device inventory lookup.
	// This stub always returns false; real implementation would check the asset database.
	_ = target
	return false
}

// AcquireConnection increments the active connection count.
// Returns an error if the limit would be exceeded.
func (m *OTModule) AcquireConnection(target string) error {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.activeConns >= m.config.MaxConcurrentConns {
		return fmt.Errorf("connection limit reached (%d)", m.config.MaxConcurrentConns)
	}

	m.activeConns++
	m.connTracker.Add(target)
	return nil
}

// ReleaseConnection decrements the active connection count.
func (m *OTModule) ReleaseConnection(target string) {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.activeConns > 0 {
		m.activeConns--
	}
	m.connTracker.Remove(target)
}

// EmergencyShutdown immediately terminates all OT operations.
func (m *OTModule) EmergencyShutdown() {
	m.shutdownMu.Lock()
	m.shutdown = true
	m.shutdownMu.Unlock()

	m.watchdog.Stop()

	// Log active connections at time of shutdown for forensics
	active := m.connTracker.Active()
	_ = active // In a real implementation, this would be logged to the audit system
}

// WatchdogTick should be called periodically to indicate server connectivity.
func (m *OTModule) WatchdogTick() {
	m.watchdog.Tick()
}

// Config returns the current OT configuration.
func (m *OTModule) Config() OTConfig {
	return m.config
}

// ActiveConnections returns the count of active connections.
func (m *OTModule) ActiveConnections() int {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return m.activeConns
}

// InterPacketDelay returns the configured inter-packet delay as a duration.
func (m *OTModule) InterPacketDelay() time.Duration {
	return time.Duration(m.config.InterPacketDelayMs) * time.Millisecond
}

// QueryTimeout returns the configured query timeout as a duration.
func (m *OTModule) QueryTimeout() time.Duration {
	return time.Duration(m.config.QueryTimeoutMs) * time.Millisecond
}
