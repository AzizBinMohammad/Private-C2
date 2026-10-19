package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnumerateFindsSSHKeyAndEnv(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	ed25519 := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(ed25519, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rsa := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(rsa, []byte("-----BEGIN RSA PRIVATE KEY-----\nabc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	awsPath := filepath.Join(home, ".aws", "credentials")
	if err := os.WriteFile(awsPath, []byte("[default]\naws_access_key_id=x\n"), 0600); err != nil {
		t.Fatal(err)
	}

	report := Enumerate("alice", home, []string{
		"AWS_SECRET_ACCESS_KEY=s3cret",
		"PATH=/bin",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
	})

	byPath := make(map[string]Source)
	for _, s := range report.Sources {
		byPath[s.Path] = s
	}
	if src := byPath[rsa]; !src.Present || !src.Readable || !strings.Contains(src.Note, "unencrypted") {
		t.Errorf("id_rsa source = %+v", src)
	}
	if src := byPath[ed25519]; !src.Present || !strings.Contains(src.Note, "OpenSSH") {
		t.Errorf("id_ed25519 source = %+v", src)
	}
	if src := byPath[awsPath]; !src.Present || !src.Readable {
		t.Errorf("aws credentials source = %+v", src)
	}

	var sawAWSSecret, sawKeyFinding bool
	for _, f := range report.Findings {
		if f.Kind == "env" && f.Name == "AWS_SECRET_ACCESS_KEY" && f.Value == "s3cret" {
			sawAWSSecret = true
		}
		if f.Kind == "env" && f.Name == "SSH_AUTH_SOCK" {
			t.Error("SSH_AUTH_SOCK should be treated as noise")
		}
		if f.Kind == "env" && f.Name == "PATH" {
			t.Error("PATH should not match the sensitive-name filter")
		}
		if f.Kind == "ssh_key" && f.Name == rsa {
			sawKeyFinding = true
		}
	}
	if !sawAWSSecret {
		t.Errorf("AWS secret env finding missing: %+v", report.Findings)
	}
	if !sawKeyFinding {
		t.Errorf("unencrypted key finding missing: %+v", report.Findings)
	}
}

func TestEnumerateMissingHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "does-not-exist")
	report := Enumerate("nobody", home, nil)
	for _, s := range report.Sources {
		// System paths (/etc/shadow, /etc/sudoers) exist independently of the
		// supplied home, so only home-relative candidates are checked here.
		if strings.HasPrefix(s.Path, home) && s.Present {
			t.Errorf("unexpected present source: %+v", s)
		}
	}
	if len(report.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", report.Findings)
	}
}

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("value"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecret(path, 16)
	if err != nil || string(got) != "value" {
		t.Fatalf("ReadSecret = %q, %v", got, err)
	}

	if _, err := ReadSecret("", 16); err == nil {
		t.Error("empty path unexpectedly succeeded")
	}
	if _, err := ReadSecret(dir, 16); err == nil {
		t.Error("directory unexpectedly succeeded")
	}
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(big, 16); err == nil {
		t.Error("oversized file unexpectedly succeeded")
	}
}
