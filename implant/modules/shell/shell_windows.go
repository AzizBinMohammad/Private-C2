//go:build windows

package shell

import (
	"bytes"
	"context"
	"os/exec"
)

// platformExecute runs a command via cmd.exe /c on Windows.
func platformExecute(ctx context.Context, req Request) (*Response, error) {
	cmdStr := req.Command
	if len(req.Args) > 0 {
		for _, arg := range req.Args {
			cmdStr += " " + arg
		}
	}

	cmd := exec.CommandContext(ctx, "cmd.exe", "/c", cmdStr)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	resp := &Response{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			resp.ExitCode = exitErr.ExitCode()
		} else {
			resp.ExitCode = -1
			resp.Stderr = err.Error()
		}
	}

	return resp, nil
}
