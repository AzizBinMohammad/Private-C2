package lateral

import (
	"strings"
	"testing"
)

func TestParseSSHRequest(t *testing.T) {
	req, err := ParseSSHRequest(`{"target":"10.0.0.5","user":"alice","command":"id","port":2222}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.Port != 2222 || req.Target != "10.0.0.5" || req.User != "alice" {
		t.Fatalf("unexpected request: %+v", req)
	}

	req, err = ParseSSHRequest(`{"target":"h","user":"u","command":"id"}`)
	if err != nil || req.Port != defaultSSHPort {
		t.Fatalf("default port: %+v %v", req, err)
	}

	for _, bad := range []string{
		``,
		`not-json`,
		`{"user":"u","command":"id"}`,
		`{"target":"h","command":"id"}`,
		`{"target":"h","user":"u"}`,
		`{"target":"h","user":"u","command":"id","port":70000}`,
		`{"target":"h","user":"u","command":"id","key_path":"k","password":"p"}`,
	} {
		if _, err := ParseSSHRequest(bad); err == nil {
			t.Errorf("ParseSSHRequest(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestCommandFor(t *testing.T) {
	program, args, env, err := commandFor(SSHRequest{
		Target: "host", User: "u", Port: 22, KeyPath: "/tmp/key", Command: "id",
	})
	if err != nil || program != "ssh" || len(env) != 0 {
		t.Fatalf("key auth: %q %v %v %v", program, args, env, err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"-i /tmp/key", "BatchMode=yes", "u@host id"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ssh args %q missing %q", joined, want)
		}
	}
}

func TestCommandForPasswordRequiresSSHPass(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, _, _, err := commandFor(SSHRequest{
		Target: "host", User: "u", Port: 22, Password: "p", Command: "id",
	}); err == nil {
		t.Error("password auth unexpectedly succeeded without sshpass on PATH")
	}
}
