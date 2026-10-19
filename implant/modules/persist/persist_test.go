//go:build !windows

package persist

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactIDDeterministic(t *testing.T) {
	a := ArtifactID("shell", "svc")
	b := ArtifactID("shell", "svc")
	c := ArtifactID("cron", "svc")
	if a != b || a == c || len(a) != 16 {
		t.Fatalf("ArtifactID: %q %q %q", a, b, c)
	}
}

func TestValidate(t *testing.T) {
	valid := []Request{
		{Action: "add", Name: "svc-1", Command: "id"},
		{Action: "remove", Name: "svc_1"},
		{Action: "list"},
		{Action: "add", Name: "svc", Command: "id", Schedule: "*/5 * * * *"},
		{Action: "add", Name: "svc", Command: "id", Schedule: "@reboot"},
	}
	for _, req := range valid {
		if err := validate(&req); err != nil {
			t.Errorf("validate(%+v) = %v", req, err)
		}
	}

	invalid := []Request{
		{Action: "bogus", Name: "svc", Command: "id"},
		{Action: "add", Command: "id"},
		{Action: "add", Name: "bad name", Command: "id"},
		{Action: "add", Name: "svc", Command: ""},
		{Action: "add", Name: "svc", Command: "id", Schedule: "not a schedule"},
	}
	for _, req := range invalid {
		if err := validate(&req); err == nil {
			t.Errorf("validate(%+v) unexpectedly succeeded", req)
		}
	}
}

func TestShellPersistLifecycle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	profile := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(profile, []byte("export PATH=/usr/bin\n"), 0600); err != nil {
		t.Fatal(err)
	}

	add, err := Execute(context.Background(), "shell", Request{
		Action: "add", Name: "beacon", Command: "nohup /tmp/x >/dev/null 2>&1 &",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !add.Changed || add.ArtifactID == "" {
		t.Fatalf("unexpected add result: %+v", add)
	}
	content, _ := os.ReadFile(profile)
	if !strings.Contains(string(content), "# pc2-begin:"+add.ArtifactID) {
		t.Fatalf("profile lacks marker: %s", content)
	}

	list, err := Execute(context.Background(), "shell", Request{Action: "list"})
	if err != nil || !strings.Contains(list.Note, add.ArtifactID) {
		t.Fatalf("list = %+v, %v", list, err)
	}

	again, err := Execute(context.Background(), "shell", Request{Action: "add", Name: "beacon", Command: "id"})
	if err != nil || again.Changed {
		t.Fatalf("duplicate add changed the profile: %+v, %v", again, err)
	}

	remove, err := Execute(context.Background(), "shell", Request{Action: "remove", Name: "beacon"})
	if err != nil || !remove.Changed {
		t.Fatalf("remove = %+v, %v", remove, err)
	}
	content, _ = os.ReadFile(profile)
	if strings.Contains(string(content), "pc2-begin") || !strings.Contains(string(content), "export PATH") {
		t.Fatalf("unexpected profile after remove: %s", content)
	}
}

func TestShellPersistDryRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	profile := filepath.Join(home, ".profile")
	if err := os.WriteFile(profile, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := Execute(context.Background(), "shell", Request{
		Action: "add", Name: "dry", Command: "id", DryRun: true,
	})
	if err != nil || res.Changed {
		t.Fatalf("dry run = %+v, %v", res, err)
	}
	content, _ := os.ReadFile(profile)
	if len(content) != 0 {
		t.Fatalf("dry run wrote the profile: %q", content)
	}
}

func TestCronLineHelpers(t *testing.T) {
	marker := cronMarker("abc")
	current := "@daily /usr/bin/backup\n"
	added, changed := addCronLine(current, "@reboot /tmp/x "+marker, marker)
	if !changed || !strings.Contains(added, marker) {
		t.Fatalf("addCronLine = %q, %v", added, changed)
	}
	if _, changed := addCronLine(added, "@reboot /tmp/x "+marker, marker); changed {
		t.Fatal("duplicate cron line was added")
	}
	removed, changed := removeCronLines(added, marker)
	if !changed || strings.Contains(removed, marker) || !strings.Contains(removed, "/usr/bin/backup") {
		t.Fatalf("removeCronLines = %q, %v", removed, changed)
	}
}

func TestSystemdUnitEscapesSingleQuotes(t *testing.T) {
	unit := systemdUnit("abc", `/bin/sh -c 'echo it'"'"'s'`)
	if !strings.Contains(unit, `'\''`) {
		t.Fatalf("unit did not escape the command: %s", unit)
	}
	if !strings.Contains(unit, "# pc2-artifact:abc") {
		t.Fatalf("unit lacks the artifact marker: %s", unit)
	}
}
