//go:build !linux && !windows && !darwin

package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type defaultLister struct{}

func newPlatformLister() Lister {
	return &defaultLister{}
}

// List attempts to enumerate processes using the ps command as a fallback.
func (d *defaultLister) List(ctx context.Context) ([]ProcessInfo, error) {
	cmd := exec.CommandContext(ctx, "ps", "-eo", "pid,ppid,user,comm")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("process listing not fully supported on %s: %w", runtime.GOOS, err)
	}

	var procs []ProcessInfo
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		ppid, _ := strconv.Atoi(fields[1])

		procs = append(procs, ProcessInfo{
			PID:  pid,
			PPID: ppid,
			User: fields[2],
			Name: strings.Join(fields[3:], " "),
		})
	}

	return procs, nil
}

// Kill attempts to terminate a process.
func (d *defaultLister) Kill(_ context.Context, pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}
	return proc.Kill()
}

// Suspend is not implemented on this platform.
func (d *defaultLister) Suspend(_ context.Context, _ int) error {
	return fmt.Errorf("process suspend is not supported on %s", runtime.GOOS)
}

// Resume is not implemented on this platform.
func (d *defaultLister) Resume(_ context.Context, _ int) error {
	return fmt.Errorf("process resume is not supported on %s", runtime.GOOS)
}
