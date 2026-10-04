//go:build windows

package logs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func NewClearer() LogClearer {
	return &windowsClearer{}
}

type windowsClearer struct{}

var windowsEventLogs = map[ClearTarget][]string{
	TargetSystem:      {"System"},
	TargetSecurity:    {"Security"},
	TargetApplication: {"Application"},
	TargetAll:         {"System", "Security", "Application", "Setup", "ForwardedEvents"},
}

func (w *windowsClearer) Clear(ctx context.Context, req ClearRequest) ([]ClearResult, error) {
	var results []ClearResult

	if req.Target == TargetCustom {
		result := w.clearCustomLog(ctx, req)
		return []ClearResult{result}, nil
	}

	logNames, ok := windowsEventLogs[req.Target]
	if !ok {
		return nil, fmt.Errorf("unknown target: %s", req.Target)
	}

	for _, logName := range logNames {
		result := w.clearEventLog(ctx, logName, req.DryRun)
		results = append(results, result)
	}

	return results, nil
}

func (w *windowsClearer) clearEventLog(ctx context.Context, logName string, dryRun bool) ClearResult {
	result := ClearResult{
		Target: logName,
		DryRun: dryRun,
	}

	countCmd := exec.CommandContext(ctx, "wevtutil", "gli", logName)
	countOut, err := countCmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("failed to query %s: %v", logName, err)
		return result
	}

	for _, line := range strings.Split(string(countOut), "\n") {
		if strings.Contains(line, "numberOfLogRecords") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Details = append(result.Details, fmt.Sprintf("records: %s", strings.TrimSpace(parts[1])))
			}
		}
	}

	if dryRun {
		result.Details = append(result.Details, "dry run — no logs cleared")
		return result
	}

	clearCmd := exec.CommandContext(ctx, "wevtutil", "cl", logName)
	if err := clearCmd.Run(); err != nil {
		result.Error = fmt.Sprintf("failed to clear %s: %v", logName, err)
		return result
	}

	result.Cleared = true
	result.Details = append(result.Details, "event log cleared")
	return result
}

func (w *windowsClearer) clearCustomLog(ctx context.Context, req ClearRequest) ClearResult {
	result := ClearResult{
		Target: req.LogPath,
		DryRun: req.DryRun,
	}

	info, err := os.Stat(req.LogPath)
	if err != nil {
		result.Error = fmt.Sprintf("cannot access: %v", err)
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("size: %d bytes", info.Size()))

	if req.DryRun {
		result.Details = append(result.Details, "dry run — file not modified")
		return result
	}

	if err := os.Truncate(req.LogPath, 0); err != nil {
		result.Error = fmt.Sprintf("failed to truncate: %v", err)
		return result
	}

	result.Cleared = true
	result.Details = append(result.Details, "file truncated")
	return result
}

func (w *windowsClearer) ListLogs(ctx context.Context) ([]LogInfo, error) {
	var logs []LogInfo

	for _, name := range windowsEventLogs[TargetAll] {
		info := LogInfo{Name: name, Path: name}

		cmd := exec.CommandContext(ctx, "wevtutil", "gli", name)
		out, err := cmd.Output()
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "fileSize") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &info.SizeBytes)
				}
			}
			if strings.Contains(line, "numberOfLogRecords") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &info.Entries)
				}
			}
		}
		info.Writable = true
		logs = append(logs, info)
	}

	evtxDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	entries, err := os.ReadDir(evtxDir)
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".evtx") {
				fi, _ := e.Info()
				if fi != nil {
					logs = append(logs, LogInfo{
						Name:      strings.TrimSuffix(e.Name(), ".evtx"),
						Path:      filepath.Join(evtxDir, e.Name()),
						SizeBytes: fi.Size(),
					})
				}
			}
		}
	}

	return logs, nil
}
