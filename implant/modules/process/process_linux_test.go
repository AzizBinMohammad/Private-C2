//go:build linux

package process

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSuspendResume starts a throwaway sleep process and verifies that the
// SIGSTOP/SIGCONT-backed operations change its /proc state.
func TestSuspendResume(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	lister := newPlatformLister()
	if err := lister.Suspend(context.Background(), pid); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	waitForState(t, pid, "T")

	if err := lister.Resume(context.Background(), pid); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	waitForState(t, pid, "S")
}

func TestExecuteRejectsInvalidPIDs(t *testing.T) {
	for _, op := range []Operation{OpKill, OpSuspend, OpResume} {
		req, err := json.Marshal(Request{Op: op, PID: 0})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Execute(context.Background(), req); err == nil {
			t.Errorf("%s with PID 0 unexpectedly succeeded", op)
		}
	}
}

func waitForState(t *testing.T, pid int, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			t.Fatalf("reading stat: %v", err)
		}
		s := string(data)
		if i := strings.LastIndexByte(s, ')'); i >= 0 {
			fields := strings.Fields(s[i+1:])
			if len(fields) > 0 && fields[0] == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d did not reach state %q", pid, want)
}
