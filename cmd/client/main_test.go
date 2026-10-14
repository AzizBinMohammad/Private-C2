package main

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIsTaskPending pins the task-polling contract.
//
// GET /api/tasks/{id} answers {"status":"pending"} while a task is queued and
// the bare result object (no "status") once it has finished. The console must
// treat only the explicit "pending" status as unfinished — treating it the
// other way round ("status == completed") made every task poll until timeout
// and discard its output.
func TestIsTaskPending(t *testing.T) {
	tests := []struct {
		name   string
		result TaskResult
		want   bool
	}{
		{
			name:   "queued task is pending",
			result: TaskResult{Status: "pending"},
			want:   true,
		},
		{
			name:   "completed task has no status field",
			result: TaskResult{TaskID: "t1", Success: true, Output: "ok"},
			want:   false,
		},
		{
			name:   "failed task has no status field",
			result: TaskResult{TaskID: "t2", Success: false, Error: "boom"},
			want:   false,
		},
		{
			name:   "completed task with empty output",
			result: TaskResult{TaskID: "t3", Success: true},
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTaskPending(&tc.result); got != tc.want {
				t.Errorf("isTaskPending(%+v) = %v, want %v", tc.result, got, tc.want)
			}
		})
	}
}

// TestUploadTaskArgs pins the wire format the implant's upload handler parses:
// "<base64-data>|<remote-path>".
func TestUploadTaskArgs(t *testing.T) {
	data := []byte("hello-from-cli-upload-test")
	got := uploadTaskArgs("/tmp/target.txt", data)

	parts := strings.SplitN(got, "|", 2)
	if len(parts) != 2 {
		t.Fatalf("uploadTaskArgs() = %q, want a single '|' separator", got)
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("payload segment is not valid base64: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("decoded payload = %q, want %q", decoded, data)
	}
	if parts[1] != "/tmp/target.txt" {
		t.Errorf("remote path = %q, want %q", parts[1], "/tmp/target.txt")
	}
}

// TestUploadTaskArgsEmptyFile guards the edge case where a zero-byte upload
// must still produce two segments, so the implant does not reject the task.
func TestUploadTaskArgsEmptyFile(t *testing.T) {
	got := uploadTaskArgs("/tmp/empty", nil)
	if got != "|/tmp/empty" {
		t.Errorf("uploadTaskArgs(empty) = %q, want %q", got, "|/tmp/empty")
	}
}

// TestTaskPollTimeoutFor pins which task types get the long poll window.
//
// A scan runs inline in the implant's beacon loop, so its result only returns
// on the checkin after it finishes -- far outside the 30s that suits every
// other task type. Only nmap may be widened; if this ever changes, the other
// commands silently start waiting five minutes before reporting a failure.
func TestTaskPollTimeoutFor(t *testing.T) {
	tests := []struct {
		taskType string
		want     time.Duration
	}{
		{"nmap", nmapPollTimeout},
		{"shell", taskPollTimeout},
		{"download", taskPollTimeout},
		{"screenshot", taskPollTimeout},
		{"", taskPollTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.taskType, func(t *testing.T) {
			if got := taskPollTimeoutFor(tc.taskType); got != tc.want {
				t.Errorf("taskPollTimeoutFor(%q) = %s, want %s", tc.taskType, got, tc.want)
			}
		})
	}

	if nmapPollTimeout <= taskPollTimeout {
		t.Errorf("nmapPollTimeout (%s) must exceed taskPollTimeout (%s)", nmapPollTimeout, taskPollTimeout)
	}
}

// TestRenderTaskResultPrintsOutputBeforeFailure pins the fix for output being
// discarded on a failed task.
//
// A scan killed at the implant's timeout reports failure but still carries the
// ports it found. Rendering only the error threw that away, which is the worst
// possible outcome: the scan cost minutes and returned nothing to show for it.
func TestRenderTaskResultPrintsOutputBeforeFailure(t *testing.T) {
	result := &TaskResult{
		TaskID:  "t1",
		Success: false,
		Output:  "80/tcp open  http\n",
		Error:   "nmap timed out after 3m0s",
	}

	out := captureStdout(t, func() { renderTaskResult(result) })

	if !strings.Contains(out, "80/tcp open  http") {
		t.Errorf("rendered %q, want the partial output included", out)
	}
	if !strings.Contains(out, "nmap timed out") {
		t.Errorf("rendered %q, want the error reported as well", out)
	}
}

// TestRenderTaskResultSuccess pins the unchanged success paths.
func TestRenderTaskResultSuccess(t *testing.T) {
	out := captureStdout(t, func() {
		renderTaskResult(&TaskResult{TaskID: "t2", Success: true, Output: "hello\n"})
	})
	if !strings.Contains(out, "hello") {
		t.Errorf("rendered %q, want the task output", out)
	}

	empty := captureStdout(t, func() {
		renderTaskResult(&TaskResult{TaskID: "t3", Success: true})
	})
	if !strings.Contains(empty, "no output") {
		t.Errorf("rendered %q, want the no-output notice", empty)
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = old
	return <-done
}
