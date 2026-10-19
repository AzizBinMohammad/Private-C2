package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialEnumHandler(t *testing.T) {
	out, err := handleCredentialEnum(context.Background(), "")
	if err != nil {
		t.Fatalf("credential_enum: %v", err)
	}
	var report struct {
		User    string `json:"user"`
		Home    string `json:"home"`
		Sources []any  `json:"sources"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Home == "" {
		t.Fatalf("credential_enum did not report a home directory: %s", out)
	}
	if len(report.Sources) == 0 {
		t.Fatal("credential_enum returned no sources")
	}
}

func TestCredentialReadHandler(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(path, []byte("secret-value"), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := handleCredentialRead(context.Background(), path)
	if err != nil {
		t.Fatalf("credential_read: %v", err)
	}
	var resp struct {
		Path   string `json:"path"`
		Size   int    `json:"size"`
		SHA256 string `json:"sha256"`
		Data   string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if string(data) != "secret-value" || resp.Size != len(data) || resp.SHA256 == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	if _, err := handleCredentialRead(context.Background(), ""); err == nil {
		t.Error("empty path unexpectedly succeeded")
	}
	if _, err := handleCredentialRead(context.Background(), dir); err == nil {
		t.Error("directory unexpectedly succeeded")
	}
}
