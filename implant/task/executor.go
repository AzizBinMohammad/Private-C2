package task

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultMaxConcurrent is the default maximum number of concurrent tasks.
	DefaultMaxConcurrent = 5
	// DefaultTaskTimeout is the default timeout for a single task execution.
	DefaultTaskTimeout = 5 * time.Minute
)

// TaskRequest represents an incoming task to be executed.
type TaskRequest struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// TaskResponse represents the result of a task execution.
type TaskResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Success bool   `json:"success"`
	Output  []byte `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Executor dispatches incoming task requests to registered handlers,
// enforces timeouts, limits concurrent execution, and buffers results
// for beacon mode.
type Executor struct {
	mu            sync.Mutex
	registry      *Registry
	maxConcurrent int
	taskTimeout   time.Duration
	semaphore     chan struct{}
	results       chan *TaskResponse
	resultBuf     []*TaskResponse
	bufMu         sync.Mutex
}

// ExecutorConfig configures the task executor.
type ExecutorConfig struct {
	Registry      *Registry
	MaxConcurrent int
	TaskTimeout   time.Duration
	ResultBufSize int
}

// NewExecutor creates a new task executor.
func NewExecutor(cfg ExecutorConfig) *Executor {
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}

	taskTimeout := cfg.TaskTimeout
	if taskTimeout <= 0 {
		taskTimeout = DefaultTaskTimeout
	}

	resultBufSize := cfg.ResultBufSize
	if resultBufSize <= 0 {
		resultBufSize = 128
	}

	return &Executor{
		registry:      cfg.Registry,
		maxConcurrent: maxConcurrent,
		taskTimeout:   taskTimeout,
		semaphore:     make(chan struct{}, maxConcurrent),
		results:       make(chan *TaskResponse, resultBufSize),
	}
}

// Execute dispatches a task request synchronously and returns the response.
func (e *Executor) Execute(ctx context.Context, req *TaskRequest) *TaskResponse {
	if req == nil {
		return &TaskResponse{
			Success: false,
			Error:   "nil task request",
		}
	}

	resp := &TaskResponse{
		ID:   req.ID,
		Type: req.Type,
	}

	handler, ok := e.registry.Get(req.Type)
	if !ok {
		resp.Error = fmt.Sprintf("unknown task type: %s", req.Type)
		return resp
	}

	// Acquire semaphore to enforce concurrency limit.
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		resp.Error = "context cancelled while waiting for execution slot"
		return resp
	}

	// Create a timeout context for this task.
	taskCtx, cancel := context.WithTimeout(ctx, e.taskTimeout)
	defer cancel()

	// Execute in a goroutine with result channel for timeout enforcement.
	type result struct {
		output []byte
		err    error
	}
	resultCh := make(chan result, 1)

	go func() {
		output, err := handler(taskCtx, req.Payload)
		resultCh <- result{output: output, err: err}
	}()

	select {
	case r := <-resultCh:
		if r.err != nil {
			resp.Error = r.err.Error()
		} else {
			resp.Success = true
			resp.Output = r.output
		}
	case <-taskCtx.Done():
		resp.Error = fmt.Sprintf("task timed out after %s", e.taskTimeout)
	}

	return resp
}

// ExecuteAsync dispatches a task asynchronously. The result is buffered
// for later retrieval (useful for beacon mode).
func (e *Executor) ExecuteAsync(ctx context.Context, req *TaskRequest) {
	go func() {
		resp := e.Execute(ctx, req)
		e.bufMu.Lock()
		e.resultBuf = append(e.resultBuf, resp)
		e.bufMu.Unlock()

		// Also send to channel for streaming consumers.
		select {
		case e.results <- resp:
		default:
		}
	}()
}

// ExecuteBatch dispatches multiple task requests and returns all responses.
func (e *Executor) ExecuteBatch(ctx context.Context, requests []*TaskRequest) []*TaskResponse {
	responses := make([]*TaskResponse, len(requests))
	var wg sync.WaitGroup

	for i, req := range requests {
		wg.Add(1)
		go func(idx int, r *TaskRequest) {
			defer wg.Done()
			responses[idx] = e.Execute(ctx, r)
		}(i, req)
	}

	wg.Wait()
	return responses
}

// DrainResults returns all buffered results and clears the buffer.
// Used by beacon mode to collect results between check-ins.
func (e *Executor) DrainResults() []*TaskResponse {
	e.bufMu.Lock()
	defer e.bufMu.Unlock()

	results := e.resultBuf
	e.resultBuf = nil
	return results
}

// Results returns the channel for streaming task responses.
func (e *Executor) Results() <-chan *TaskResponse {
	return e.results
}

// PendingCount returns the number of tasks currently executing.
func (e *Executor) PendingCount() int {
	return len(e.semaphore)
}

// ParseRequest deserializes a task request from JSON bytes.
func ParseRequest(data []byte) (*TaskRequest, error) {
	var req TaskRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parsing task request: %w", err)
	}
	return &req, nil
}

// MarshalResponse serializes a task response to JSON bytes.
func MarshalResponse(resp *TaskResponse) ([]byte, error) {
	return json.Marshal(resp)
}
