//go:build darwin

package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

type darwinLister struct{}

func newPlatformLister() Lister {
	return &darwinLister{}
}

// List enumerates processes on macOS using the ps command.
// TODO: Replace with direct sysctl calls (CTL_KERN, KERN_PROC) for
// better performance and stealth.
func (d *darwinLister) List(ctx context.Context) ([]ProcessInfo, error) {
	cmd := exec.CommandContext(ctx, "ps", "-eo", "pid,ppid,rss,user,comm")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running ps: %w", err)
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
		if len(fields) < 5 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		ppid, _ := strconv.Atoi(fields[1])
		rss, _ := strconv.ParseInt(fields[2], 10, 64)

		procs = append(procs, ProcessInfo{
			PID:    pid,
			PPID:   ppid,
			MemRSS: rss * 1024, // ps reports RSS in KB
			User:   fields[3],
			Name:   strings.Join(fields[4:], " "),
		})
	}

	return procs, nil
}

// Kill sends SIGKILL to the specified process.
func (d *darwinLister) Kill(_ context.Context, pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}

	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("killing process %d: %w", pid, err)
	}

	return nil
}

// Suspend stops the process with SIGSTOP.
func (d *darwinLister) Suspend(_ context.Context, pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("suspending process %d: %w", pid, err)
	}
	return nil
}

// Resume continues a stopped process with SIGCONT.
func (d *darwinLister) Resume(_ context.Context, pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGCONT); err != nil {
		return fmt.Errorf("resuming process %d: %w", pid, err)
	}
	return nil
}
