package process

import (
	"context"
	"encoding/json"
	"fmt"
)

// Operation defines the process operation type.
type Operation string

const (
	OpPS      Operation = "ps"
	OpKill    Operation = "kill"
	OpSuspend Operation = "suspend"
	OpResume  Operation = "resume"
)

// Request represents a process operation request.
type Request struct {
	Op  Operation `json:"op"`
	PID int       `json:"pid,omitempty"` // for kill/suspend/resume
}

// ProcessInfo represents information about a running process.
type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	User    string `json:"user"`
	CmdLine string `json:"cmdline,omitempty"`
	MemRSS  int64  `json:"mem_rss,omitempty"` // resident set size in bytes
}

// Response represents the result of a process operation.
type Response struct {
	Output    string        `json:"output,omitempty"`
	Processes []ProcessInfo `json:"processes,omitempty"`
}

// Lister is the platform-specific interface for process operations.
type Lister interface {
	List(ctx context.Context) ([]ProcessInfo, error)
	Kill(ctx context.Context, pid int) error
	Suspend(ctx context.Context, pid int) error
	Resume(ctx context.Context, pid int) error
}

// Execute handles a process operation request using the platform-specific lister.
func Execute(ctx context.Context, payload []byte) ([]byte, error) {
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("parsing process request: %w", err)
	}

	lister := newPlatformLister()

	var resp *Response

	switch req.Op {
	case OpPS:
		procs, listErr := lister.List(ctx)
		if listErr != nil {
			return nil, listErr
		}
		resp = &Response{Processes: procs}

	case OpKill:
		if req.PID <= 0 {
			return nil, fmt.Errorf("invalid PID: %d", req.PID)
		}
		if killErr := lister.Kill(ctx, req.PID); killErr != nil {
			return nil, killErr
		}
		resp = &Response{Output: fmt.Sprintf("killed process %d", req.PID)}

	case OpSuspend:
		if req.PID <= 0 {
			return nil, fmt.Errorf("invalid PID: %d", req.PID)
		}
		if suspendErr := lister.Suspend(ctx, req.PID); suspendErr != nil {
			return nil, suspendErr
		}
		resp = &Response{Output: fmt.Sprintf("suspended process %d", req.PID)}

	case OpResume:
		if req.PID <= 0 {
			return nil, fmt.Errorf("invalid PID: %d", req.PID)
		}
		if resumeErr := lister.Resume(ctx, req.PID); resumeErr != nil {
			return nil, resumeErr
		}
		resp = &Response{Output: fmt.Sprintf("resumed process %d", req.PID)}

	default:
		return nil, fmt.Errorf("unknown process operation: %s", req.Op)
	}

	return json.Marshal(resp)
}
