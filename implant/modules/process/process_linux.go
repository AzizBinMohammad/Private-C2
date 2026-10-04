//go:build linux

package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type linuxLister struct{}

func newPlatformLister() Lister {
	return &linuxLister{}
}

// List enumerates processes by reading the /proc filesystem.
func (l *linuxLister) List(_ context.Context) ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}

	var procs []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		proc := ProcessInfo{PID: pid}

		// Read /proc/<pid>/stat for process name and PPID.
		statPath := filepath.Join("/proc", entry.Name(), "stat")
		statData, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}

		statStr := string(statData)
		// The process name is in parentheses, so find the boundaries.
		nameStart := strings.IndexByte(statStr, '(')
		nameEnd := strings.LastIndexByte(statStr, ')')
		if nameStart >= 0 && nameEnd > nameStart {
			proc.Name = statStr[nameStart+1 : nameEnd]

			// Fields after the closing paren.
			remaining := strings.TrimSpace(statStr[nameEnd+1:])
			fields := strings.Fields(remaining)
			if len(fields) >= 2 {
				proc.PPID, _ = strconv.Atoi(fields[1])
			}
			// RSS is field 23 (0-indexed from after name) = fields[21].
			if len(fields) >= 22 {
				rss, _ := strconv.ParseInt(fields[21], 10, 64)
				pageSize := int64(os.Getpagesize())
				proc.MemRSS = rss * pageSize
			}
		}

		// Read /proc/<pid>/cmdline for the full command line.
		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		cmdlineData, err := os.ReadFile(cmdlinePath)
		if err == nil {
			proc.CmdLine = strings.ReplaceAll(string(cmdlineData), "\x00", " ")
			proc.CmdLine = strings.TrimSpace(proc.CmdLine)
		}

		// Read /proc/<pid>/status for the user (UID).
		statusPath := filepath.Join("/proc", entry.Name(), "status")
		statusData, err := os.ReadFile(statusPath)
		if err == nil {
			for _, line := range strings.Split(string(statusData), "\n") {
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						proc.User = fields[1]
					}
					break
				}
			}
		}

		procs = append(procs, proc)
	}

	return procs, nil
}

// Kill sends SIGKILL to the specified process.
func (l *linuxLister) Kill(_ context.Context, pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}

	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("killing process %d: %w", pid, err)
	}

	return nil
}
