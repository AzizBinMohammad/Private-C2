package shell

import (
	"context"
	"encoding/json"
	"fmt"
)

// Request represents a shell command execution request.
type Request struct {
	Command string `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// Response represents the result of a shell command execution.
type Response struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// Execute runs a shell command and returns the result.
// The actual execution is platform-specific and delegated to platformExecute.
func Execute(ctx context.Context, payload []byte) ([]byte, error) {
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("parsing shell request: %w", err)
	}

	if req.Command == "" {
		return nil, fmt.Errorf("empty command")
	}

	resp, err := platformExecute(ctx, req)
	if err != nil {
		return nil, err
	}

	return json.Marshal(resp)
}
