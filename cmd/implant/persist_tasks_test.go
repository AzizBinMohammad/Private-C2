package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistShellHandler(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	profile := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(profile, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	handler := persistHandler("shell")
	out, err := handler(context.Background(), `{"action":"add","name":"svc","command":"/tmp/x &"}`)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	var added struct {
		Changed    bool   `json:"changed"`
		ArtifactID string `json:"artifact_id"`
	}
	if err := json.Unmarshal([]byte(out), &added); err != nil {
		t.Fatal(err)
	}
	if !added.Changed || added.ArtifactID == "" {
		t.Fatalf("unexpected add result: %s", out)
	}

	if _, err := handler(context.Background(), `{"action":"list"}`); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, err := handler(context.Background(), `{"action":"remove","name":"svc"}`); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := handler(context.Background(), `not-json`); err == nil {
		t.Error("invalid JSON unexpectedly succeeded")
	}
	if _, err := handler(context.Background(), `{"action":"add"}`); err == nil {
		t.Error("missing name unexpectedly succeeded")
	}
}

func TestPersistUnsupportedKind(t *testing.T) {
	if _, err := persistHandler("bogus")(context.Background(), `{"action":"list"}`); err == nil {
		t.Error("unsupported kind unexpectedly succeeded")
	}
}
