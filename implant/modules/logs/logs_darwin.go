//go:build darwin

package logs

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func NewClearer() LogClearer {
	return &darwinClearer{}
}

type darwinClearer struct{}

var darwinLogPaths = map[ClearTarget][]string{
	TargetSystem:      {"/var/log/system.log", "/var/log/install.log"},
	TargetSecurity:    {"/var/log/authd.log", "/var/log/opendirectoryd.log"},
	TargetApplication: {"/var/log/appfirewall.log"},
	TargetAll: {
		"/var/log/system.log", "/var/log/install.log",
		"/var/log/authd.log", "/var/log/opendirectoryd.log",
		"/var/log/appfirewall.log", "/var/log/wifi.log",
		"/var/log/asl",
	},
}

func (d *darwinClearer) Clear(ctx context.Context, req ClearRequest) ([]ClearResult, error) {
	var results []ClearResult

	if req.Target == TargetCustom {
		result := d.clearFile(ctx, req.LogPath, req.DryRun)
		return []ClearResult{result}, nil
	}

	paths, ok := darwinLogPaths[req.Target]
	if !ok {
		return nil, fmt.Errorf("unknown target: %s", req.Target)
	}

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		result := d.clearFile(ctx, path, req.DryRun)
		results = append(results, result)
	}

	if req.Target == TargetAll || req.Target == TargetSystem {
		r := d.clearUnifiedLog(ctx, req.DryRun)
		results = append(results, r)
	}

	return results, nil
}

func (d *darwinClearer) clearFile(_ context.Context, path string, dryRun bool) ClearResult {
	result := ClearResult{
		Target: path,
		DryRun: dryRun,
	}

	info, err := os.Stat(path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot access: %v", err)
		return result
	}

	if info.IsDir() {
		entries, _ := os.ReadDir(path)
		result.EntriesFound = len(entries)
		result.Details = append(result.Details, fmt.Sprintf("directory with %d files", len(entries)))

		if dryRun {
			result.Details = append(result.Details, "dry run — directory not modified")
			return result
		}

		for _, e := range entries {
			os.Remove(fmt.Sprintf("%s/%s", path, e.Name()))
		}
		result.Cleared = true
		result.Details = append(result.Details, "directory contents removed")
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("size: %d bytes", info.Size()))

	if dryRun {
		result.Details = append(result.Details, "dry run — file not modified")
		return result
	}

	if err := os.Truncate(path, 0); err != nil {
		result.Error = fmt.Sprintf("failed to truncate: %v", err)
		return result
	}

	result.Cleared = true
	result.Details = append(result.Details, "file truncated")
	return result
}

func (d *darwinClearer) clearUnifiedLog(ctx context.Context, dryRun bool) ClearResult {
	result := ClearResult{
		Target: "unified-log",
		DryRun: dryRun,
	}

	cmd := exec.CommandContext(ctx, "log", "stats")
	out, err := cmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("cannot query unified log: %v", err)
		return result
	}
	result.Details = append(result.Details, strings.TrimSpace(string(out)))

	if dryRun {
		result.Details = append(result.Details, "dry run — unified log not modified (requires sudo log erase)")
		return result
	}

	eraseCmd := exec.CommandContext(ctx, "log", "erase", "--all")
	if err := eraseCmd.Run(); err != nil {
		result.Error = fmt.Sprintf("failed to erase unified log (requires root): %v", err)
		return result
	}

	result.Cleared = true
	result.Details = append(result.Details, "unified log erased")
	return result
}

func (d *darwinClearer) ListLogs(_ context.Context) ([]LogInfo, error) {
	var logs []LogInfo

	for _, path := range darwinLogPaths[TargetAll] {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		writable := false
		if !info.IsDir() {
			if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
				f.Close()
				writable = true
			}
		}

		lineCount := 0
		if !info.IsDir() {
			if f, err := os.Open(path); err == nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					lineCount++
				}
				f.Close()
			}
		}

		logs = append(logs, LogInfo{
			Name:      path[strings.LastIndex(path, "/")+1:],
			Path:      path,
			SizeBytes: info.Size(),
			Entries:   lineCount,
			Writable:  writable,
		})
	}

	return logs, nil
}
