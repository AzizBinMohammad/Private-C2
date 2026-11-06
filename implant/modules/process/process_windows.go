//go:build windows

package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

var (
	modNtdll             = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProcess = modNtdll.NewProc("NtSuspendProcess")
	procNtResumeProcess  = modNtdll.NewProc("NtResumeProcess")
)

type windowsLister struct{}

func newPlatformLister() Lister {
	return &windowsLister{}
}

// List enumerates processes using tasklist on Windows.
// TODO: Replace with direct Windows API calls (CreateToolhelp32Snapshot,
// Process32First/Next) for better performance and stealth.
func (w *windowsLister) List(ctx context.Context) ([]ProcessInfo, error) {
	cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running tasklist: %w", err)
	}

	var procs []ProcessInfo
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// CSV format: "name","PID","Session Name","Session#","Mem Usage"
		fields := parseCSVLine(line)
		if len(fields) < 2 {
			continue
		}

		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		proc := ProcessInfo{
			PID:  pid,
			Name: fields[0],
		}

		if len(fields) >= 5 {
			memStr := strings.ReplaceAll(fields[4], ",", "")
			memStr = strings.ReplaceAll(memStr, " K", "")
			memStr = strings.TrimSpace(memStr)
			if mem, err := strconv.ParseInt(memStr, 10, 64); err == nil {
				proc.MemRSS = mem * 1024 // convert KB to bytes
			}
		}

		procs = append(procs, proc)
	}

	return procs, nil
}

// Kill terminates a process on Windows.
func (w *windowsLister) Kill(_ context.Context, pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}
	return proc.Kill()
}

// Suspend stops all threads in the process with NtSuspendProcess.
func (w *windowsLister) Suspend(_ context.Context, pid int) error {
	return ntProcessCall(procNtSuspendProcess, pid)
}

// Resume resumes all threads in the process with NtResumeProcess.
func (w *windowsLister) Resume(_ context.Context, pid int) error {
	return ntProcessCall(procNtResumeProcess, pid)
}

// ntProcessCall opens the target with PROCESS_SUSPEND_RESUME and invokes an
// ntdll process-state routine. NtSuspendProcess/NtResumeProcess return an
// NTSTATUS, where zero means success.
func ntProcessCall(proc *windows.LazyProc, pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("opening process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	status, _, _ := proc.Call(uintptr(h))
	if status != 0 {
		return fmt.Errorf("%s(pid %d) failed with NTSTATUS 0x%x", proc.Name, pid, status)
	}
	return nil
}

// parseCSVLine parses a simple CSV line, handling quoted fields.
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, current.String())
	return fields
}
