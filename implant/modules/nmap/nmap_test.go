package nmap

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// recordingRun captures how runNmap was invoked, so tests can assert on the
// argv that would reach the real process without starting one.
type recordingRun struct {
	calls int
	path  string
	argv  []string
}

func stubRun(rec *recordingRun, stdout, stderr string, err error) runFunc {
	return func(_ context.Context, path string, argv []string) ([]byte, []byte, error) {
		rec.calls++
		rec.path = path
		rec.argv = argv
		return []byte(stdout), []byte(stderr), err
	}
}

func lookupFound(path string) lookupFunc {
	return func(string) (string, error) { return path, nil }
}

func lookupMissing() lookupFunc {
	return func(string) (string, error) { return "", exec.ErrNotFound }
}

func TestAvailable_Found(t *testing.T) {
	path, err := availableWith(lookupFound("/usr/bin/nmap"))
	if err != nil {
		t.Fatalf("availableWith() error = %v, want nil", err)
	}
	if path != "/usr/bin/nmap" {
		t.Errorf("path = %q, want %q", path, "/usr/bin/nmap")
	}
}

func TestAvailable_NotFound(t *testing.T) {
	_, err := availableWith(lookupMissing())
	if err == nil {
		t.Fatal("availableWith() error = nil, want an error when nmap is absent")
	}
	// The operator has to be able to tell what is wrong and what to do about
	// it from the message alone -- this error is what the check surfaces.
	msg := err.Error()
	if !strings.Contains(msg, "nmap") {
		t.Errorf("error %q does not name nmap", msg)
	}
	if !strings.Contains(msg, "install") {
		t.Errorf("error %q is not actionable", msg)
	}
}

func TestAvailable_FallbackPath(t *testing.T) {
	// PATH lookup fails, as it does for an implant started from cron, but nmap
	// is installed. The absolute-path probe has to find it anyway.
	lookup := func(name string) (string, error) {
		if name == "nmap" {
			return "", exec.ErrNotFound
		}
		return name, nil
	}

	path, err := availableWith(lookup)
	if err != nil {
		t.Fatalf("availableWith() error = %v, want the fallback path to be found", err)
	}
	if path != fallbackPaths[0] {
		t.Errorf("path = %q, want %q", path, fallbackPaths[0])
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"options before target", "-sV 10.0.0.1", []string{"-sV", "10.0.0.1"}},
		{"collapses whitespace runs", "  -p 22,80   host ", []string{"-p", "22,80", "host"}},
		{"double quotes", `--script "default,safe" 10.0.0.1`, []string{"--script", "default,safe", "10.0.0.1"}},
		{"single quotes", `'10.0.0.1' -T4`, []string{"10.0.0.1", "-T4"}},
		{"quoted metacharacters stay one argument", `"10.0.0.1; rm -rf /"`, []string{"10.0.0.1; rm -rf /"}},
		{"empty", "", nil},
		{"whitespace only", "   \t ", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tokenize(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("tokenize(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("tokenize(%q)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestExecute_NoArgs_ReportsVersion(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "Nmap version 7.94", "", nil)

	out, err := executeWith(context.Background(), lookupFound("/usr/bin/nmap"), run, time.Second, "")
	if err != nil {
		t.Fatalf("executeWith() error = %v, want nil", err)
	}
	if rec.calls != 1 {
		t.Fatalf("run called %d times, want 1", rec.calls)
	}
	// No arguments is the availability probe, so it must invoke nmap rather
	// than erroring out on the missing target.
	if len(rec.argv) != 1 || rec.argv[0] != "--version" {
		t.Errorf("argv = %q, want [--version]", rec.argv)
	}
	if !strings.Contains(out, "Nmap version") {
		t.Errorf("output = %q, want the version banner", out)
	}
}

func TestExecute_ArgvIsNotShell(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "ok", "", nil)

	// A target containing shell metacharacters and spaces. Passed as separate
	// argv elements it is inert; passed through /bin/sh -c it would delete
	// directories.
	_, err := executeWith(context.Background(), lookupFound("/usr/bin/nmap"), run, time.Second,
		`-sV "10.0.0.1; rm -rf /tmp/x"`)
	if err != nil {
		t.Fatalf("executeWith() error = %v, want nil", err)
	}

	if rec.path == "/bin/sh" || rec.path == "sh" || rec.path == "cmd" || rec.path == "cmd.exe" {
		t.Fatalf("nmap was run through a shell: %q", rec.path)
	}
	for _, arg := range rec.argv {
		if arg == "-c" || arg == "/c" {
			t.Fatalf("argv %q contains a shell command flag", rec.argv)
		}
	}
	// The quoted target must arrive as exactly one argument, metacharacters
	// included and uninterpreted.
	wantTarget := "10.0.0.1; rm -rf /tmp/x"
	found := false
	for _, arg := range rec.argv {
		if arg == wantTarget {
			found = true
		}
	}
	if !found {
		t.Errorf("argv = %q, want it to contain %q as a single element", rec.argv, wantTarget)
	}
}

func TestExecute_MissingNmap(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "", "", nil)

	_, err := executeWith(context.Background(), lookupMissing(), run, time.Second, "10.0.0.1")
	if err == nil {
		t.Fatal("executeWith() error = nil, want an error when nmap is absent")
	}
	if rec.calls != 0 {
		t.Errorf("run called %d times, want 0 when nmap is missing", rec.calls)
	}
}

func TestExecute_NoTargetRejected(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "ok", "", nil)

	_, err := executeWith(context.Background(), lookupFound("/usr/bin/nmap"), run, time.Second, "-sV -T4")
	if err == nil {
		t.Fatal("executeWith() error = nil, want a no-target error")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("error = %q, want it to mention the missing target", err)
	}
	if rec.calls != 0 {
		t.Errorf("run called %d times, want 0 when no target was given", rec.calls)
	}
}

func TestExecute_InputFileIsATarget(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "ok", "", nil)

	// -iL takes the target list from a file, so its operand is the target.
	if _, err := executeWith(context.Background(), lookupFound("/usr/bin/nmap"), run, time.Second, "-iL list.txt"); err != nil {
		t.Fatalf("executeWith(-iL list.txt) error = %v, want nil", err)
	}
	if rec.calls != 1 {
		t.Errorf("run called %d times, want 1", rec.calls)
	}
}

func TestExecute_TimeoutKeepsPartialOutput(t *testing.T) {
	// Blocks until the deadline, then reports the ports found so far the way a
	// killed nmap would leave them in its stdout buffer.
	run := func(ctx context.Context, _ string, _ []string) ([]byte, []byte, error) {
		<-ctx.Done()
		return []byte("80/tcp open http\n"), nil, ctx.Err()
	}

	out, err := executeWith(context.Background(), lookupFound("/usr/bin/nmap"), run, 10*time.Millisecond, "10.0.0.1")
	if err == nil {
		t.Fatal("executeWith() error = nil, want a timeout error")
	}
	if !strings.Contains(out, "80/tcp open http") {
		t.Errorf("output = %q, want the partial ports to survive the timeout", out)
	}
	if !strings.Contains(out, "partial") {
		t.Errorf("output = %q, want a notice that the scan was cut short", out)
	}
}

func TestExecute_NonZeroExitSurfacesStderr(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "", "Failed to resolve \"nope.invalid\".\n", errors.New("exit status 1"))

	_, err := executeWith(context.Background(), lookupFound("/usr/bin/nmap"), run, time.Second, "nope.invalid")
	if err == nil {
		t.Fatal("executeWith() error = nil, want the run error surfaced")
	}
	// nmap's own diagnostic is far more useful than "exit status 1".
	if !strings.Contains(err.Error(), "Failed to resolve") {
		t.Errorf("error = %q, want it to carry nmap's stderr", err)
	}
}
