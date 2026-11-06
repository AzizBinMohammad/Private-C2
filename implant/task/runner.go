package task

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

const (
	// DefaultRunnerConcurrency bounds simultaneous task execution.
	DefaultRunnerConcurrency = 4
	// DefaultRunnerTimeout is used when a task does not carry a timeout.
	DefaultRunnerTimeout = 5 * time.Minute
	// DefaultMaxOutputBytes bounds a single result held in memory.
	DefaultMaxOutputBytes = 4 << 20 // 4 MiB
)

// RunnerConfig configures background task execution.
type RunnerConfig struct {
	Concurrency    int
	Timeout        time.Duration
	MaxOutputBytes int
	// SafetyCheck, when set, runs before the handler. A non-nil error refuses
	// the task and is reported as its failure.
	SafetyCheck func(ctx context.Context, task protocol.TaskWire) error
}

// Result is a completed background task.
type Result struct {
	TaskID    string
	Success   bool
	Output    string
	Error     string
	Truncated bool
	Bytes     int64
}

// Handler executes a single task.
type Handler func(ctx context.Context, task protocol.TaskWire) (string, error)

// Runner executes tasks asynchronously and buffers their results for the next
// check-in. It never blocks the beacon loop on a long-running task.
type Runner struct {
	handler Handler
	cfg     RunnerConfig
	sem     chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	results []Result
	pending map[string]struct{}
	active  int
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewRunner(handler Handler, cfg RunnerConfig) *Runner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultRunnerConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultRunnerTimeout
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = DefaultMaxOutputBytes
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{
		handler: handler,
		cfg:     cfg,
		sem:     make(chan struct{}, cfg.Concurrency),
		pending: make(map[string]struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Submit queues a task for execution. It returns false when the task has no
// ID, is already known, or the runner is closed.
func (r *Runner) Submit(task protocol.TaskWire) bool {
	if task.ID == "" {
		return false
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false
	}
	if _, exists := r.pending[task.ID]; exists {
		r.mu.Unlock()
		return false
	}
	r.pending[task.ID] = struct{}{}
	r.wg.Add(1)
	r.mu.Unlock()

	go func() {
		defer r.wg.Done()
		defer func() {
			r.mu.Lock()
			delete(r.pending, task.ID)
			r.mu.Unlock()
		}()
		r.execute(task)
	}()
	return true
}

func (r *Runner) execute(task protocol.TaskWire) {
	// Blocking acquire: tasks wait for a slot rather than being dropped.
	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	r.mu.Lock()
	r.active++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()

	timeout := r.cfg.Timeout
	if task.TimeoutMs > 0 {
		timeout = time.Duration(task.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()

	result := Result{TaskID: task.ID}
	if r.cfg.SafetyCheck != nil {
		if err := r.cfg.SafetyCheck(ctx, task); err != nil {
			result.Error = err.Error()
			r.record(result)
			return
		}
	}

	output, err := r.runHandler(ctx, task)
	if err != nil {
		result.Error = err.Error()
	} else {
		result.Success = true
	}
	result.Bytes = int64(len(output))
	if len(output) > r.cfg.MaxOutputBytes {
		output = output[:r.cfg.MaxOutputBytes]
		result.Truncated = true
	}
	result.Output = output
	r.record(result)
}

func (r *Runner) runHandler(ctx context.Context, task protocol.TaskWire) (out string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("task panicked: %v", recovered)
			out = ""
		}
	}()
	return r.handler(ctx, task)
}

func (r *Runner) record(result Result) {
	r.mu.Lock()
	r.results = append(r.results, result)
	r.mu.Unlock()
}

// Drain returns all completed results and clears the buffer.
func (r *Runner) Drain() []Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	results := r.results
	r.results = nil
	return results
}

// Active returns the number of tasks currently executing.
func (r *Runner) Active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

// Pending returns the number of tasks accepted but not yet completed.
func (r *Runner) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// Close stops accepting new tasks, cancels in-flight contexts, and waits for
// their goroutines to exit.
func (r *Runner) Close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
}
