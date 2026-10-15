package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
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
		{"scan", scanPollTimeout},
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
	// The structured scan must outlast the longest profile the implant offers
	// (6 minutes for "vulns"), or the console gives up on a scan still running.
	if scanPollTimeout <= 7*time.Minute {
		t.Errorf("scanPollTimeout (%s) must exceed the implant's longest scan profile (7m)", scanPollTimeout)
	}
}

func TestParseScanArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantTarget  string
		wantProfile string
		wantPorts   string
		wantErr     bool
	}{
		{name: "target only leaves the profile to the implant", args: []string{"10.0.0.5"}, wantTarget: "10.0.0.5"},
		{name: "long services flag", args: []string{"10.0.0.5", "--services"}, wantTarget: "10.0.0.5", wantProfile: "services"},
		{name: "short vulns flag before the target", args: []string{"-v", "10.0.0.5"}, wantTarget: "10.0.0.5", wantProfile: "vulns"},
		{name: "quick", args: []string{"10.0.0.5", "--quick"}, wantTarget: "10.0.0.5", wantProfile: "quick"},
		{name: "cidr target", args: []string{"10.0.0.0/24", "--quick"}, wantTarget: "10.0.0.0/24", wantProfile: "quick"},
		{name: "hostname target", args: []string{"web01.example.test"}, wantTarget: "web01.example.test"},

		{name: "ports long flag", args: []string{"10.0.0.5", "--ports", "80,443"}, wantTarget: "10.0.0.5", wantPorts: "80,443"},
		{name: "ports short flag before the target", args: []string{"-p", "1-1024", "10.0.0.5"}, wantTarget: "10.0.0.5", wantPorts: "1-1024"},
		{name: "ports with a profile", args: []string{"10.0.0.5", "--services", "--ports", "22,80"}, wantTarget: "10.0.0.5", wantProfile: "services", wantPorts: "22,80"},
		{name: "ports flag with no value", args: []string{"10.0.0.5", "--ports"}, wantErr: true},

		{name: "no target", args: []string{"--vulns"}, wantErr: true},
		{name: "empty", args: nil, wantErr: true},
		{name: "two targets", args: []string{"10.0.0.5", "10.0.0.6"}, wantErr: true},
		{name: "unknown option", args: []string{"10.0.0.5", "--yolo"}, wantErr: true},
		{name: "conflicting profiles", args: []string{"10.0.0.5", "--quick", "--vulns"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseScanArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseScanArgs(%v) error = nil, want a rejection", tc.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseScanArgs(%v) error = %v", tc.args, err)
			}
			if opts.Target != tc.wantTarget || opts.Profile != tc.wantProfile || opts.Ports != tc.wantPorts {
				t.Errorf("parseScanArgs(%v) = (%q, %q, %q), want (%q, %q, %q)",
					tc.args, opts.Target, opts.Profile, opts.Ports, tc.wantTarget, tc.wantProfile, tc.wantPorts)
			}
		})
	}
}

// TestFormatCVEs pins the cap. Without it a single version-match finding can
// print a hundred identifiers and bury every other finding on the screen.
func TestFormatCVEs(t *testing.T) {
	if got := formatCVEs(nil); got != "" {
		t.Errorf("formatCVEs(nil) = %q, want empty", got)
	}
	if got := formatCVEs([]string{"CVE-2024-1"}); got != "CVE-2024-1" {
		t.Errorf("formatCVEs(single) = %q", got)
	}

	many := make([]string, 20)
	for i := range many {
		many[i] = "CVE-2024-" + strconv.Itoa(1000+i)
	}
	got := formatCVEs(many)

	if n := strings.Count(got, "CVE-"); n != maxCVEsShown {
		t.Errorf("formatCVEs(20) printed %d identifiers, want the cap of %d", n, maxCVEsShown)
	}
	if !strings.Contains(got, "(+12 more)") {
		t.Errorf("formatCVEs(20) = %q, want it to say how many were omitted", got)
	}
}

func TestRenderScanResult_ShowsServicesAndFindings(t *testing.T) {
	scan := ScanResult{
		Target:  "10.0.0.5",
		Profile: "services",
		Elapsed: "12.34",
		Services: []ScanService{
			{Host: "10.0.0.5", Port: 443, Protocol: "tcp", State: "open", Name: "https", Product: "Apache httpd", Version: "2.4.49"},
			{Host: "10.0.0.5", Port: 22, Protocol: "tcp", State: "closed", Name: "ssh"},
		},
		Findings: []ScanFinding{
			{ScriptID: "ssl-heartbleed", Port: 443, Protocol: "tcp", Vulnerable: true,
				CVEs: []string{"CVE-2014-0160"}, Output: "State: VULNERABLE"},
			{ScriptID: "http-title", Port: 443, Protocol: "tcp"},
		},
	}
	payload, err := json.Marshal(scan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	out := captureStdout(t, func() {
		renderScanResult(&TaskResult{TaskID: "t1", Success: true, Output: string(payload)})
	})

	for _, want := range []string{
		"10.0.0.5", "443/tcp", "Apache httpd", "2.4.49",
		"22/tcp", "closed", // a checked-but-closed port is still reported
		"ssl-heartbleed", "CVE-2014-0160", "VULNERABLE",
		"http-title",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered scan is missing %q\n---\n%s", want, out)
		}
	}
}

// TestRenderScanResult_FailedScanStillShowsFindings pins the point of returning
// JSON alongside the error: a scan cut short at its deadline still found
// things, and throwing them away would make the scan worth nothing.
func TestRenderScanResult_FailedScanStillShowsFindings(t *testing.T) {
	scan := ScanResult{
		Target:   "10.0.0.5",
		Profile:  "vulns",
		Partial:  true,
		Notice:   "scan stopped after 6m0s: results are partial",
		Services: []ScanService{{Host: "10.0.0.5", Port: 443, Protocol: "tcp", State: "open", Name: "https"}},
	}
	payload, _ := json.Marshal(scan)

	out := captureStdout(t, func() {
		renderScanResult(&TaskResult{TaskID: "t1", Success: false, Error: "scan timed out after 6m0s", Output: string(payload)})
	})

	if !strings.Contains(out, "443/tcp") {
		t.Errorf("partial findings discarded:\n%s", out)
	}
	if !strings.Contains(out, "partial") {
		t.Errorf("truncation not flagged:\n%s", out)
	}
	if !strings.Contains(out, "timed out") {
		t.Errorf("failure not reported:\n%s", out)
	}
}

// TestRenderScanResult_NonJSONFallsBack guarantees a result that is not a
// structured scan is still shown rather than swallowed.
func TestRenderScanResult_NonJSONFallsBack(t *testing.T) {
	out := captureStdout(t, func() {
		renderScanResult(&TaskResult{TaskID: "t1", Success: true, Output: "plain text output"})
	})
	if !strings.Contains(out, "plain text output") {
		t.Errorf("unstructured output dropped:\n%s", out)
	}
}

// TestRenderScanResult_ShowsRawWhenUnstructured covers a scan whose XML could
// not be parsed: nmap's own text is all there is, and it must be shown rather
// than presented as a scan that found nothing.
func TestRenderScanResult_ShowsRawWhenUnstructured(t *testing.T) {
	scan := ScanResult{
		Target: "10.0.0.5",
		Raw:    "Starting Nmap 7.92 ( https://nmap.org )\nNmap done\n",
		Notice: "nmap output could not be parsed as XML; showing it raw",
	}
	payload, _ := json.Marshal(scan)

	out := captureStdout(t, func() {
		renderScanResult(&TaskResult{TaskID: "t1", Success: true, Output: string(payload)})
	})

	if !strings.Contains(out, "Starting Nmap 7.92") {
		t.Errorf("raw output dropped:\n%s", out)
	}
	if strings.Contains(out, "No ports reported") {
		t.Errorf("empty result shown instead of the raw output:\n%s", out)
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
