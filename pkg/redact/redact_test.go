package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsSecrets(t *testing.T) {
	in := strings.Join([]string{
		`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
		`password: hunter2`,
		`"token": "eyJhbGciOiJIUzI1NiJ9.payload.signature"`,
		`Authorization: Bearer abcdefghijklmnopqrstuvwxyz`,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----",
	}, "\n")
	out := Text(in)
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "hunter2", "eyJhbGciOiJIUzI1NiJ9", "abcdefghijklmnopqrstuvwxyz", "MIIEow"} {
		if strings.Contains(out, secret) {
			t.Errorf("output still contains %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "aws_access_key_id") {
		t.Errorf("redaction removed the field name instead of the value:\n%s", out)
	}
}

func TestTextPreservesNonSecrets(t *testing.T) {
	in := "target: 10.10.0.5\nrole: PLC\nhostname: plc-1"
	if got := Text(in); got != in {
		t.Fatalf("redaction changed non-secret text: %q", got)
	}
}

func TestBytesSkipsBinary(t *testing.T) {
	binary := []byte{0x00, 0x01, 0x02}
	out, changed := Bytes(binary)
	if changed || string(out) != string(binary) {
		t.Fatalf("binary data was modified")
	}
	out, changed = Bytes([]byte("password=secret"))
	if !changed || strings.Contains(string(out), "secret") {
		t.Fatalf("text was not redacted: %q %v", out, changed)
	}
}
