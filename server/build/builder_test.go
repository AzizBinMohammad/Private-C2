package build

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTransports(t *testing.T) {
	cases := []struct {
		raw    string
		list   []string
		host   string
		failed bool
	}{
		{"mtls@c2.example:4444", []string{"mtls"}, "c2.example:4444", false},
		{"mtls,https@c2.example:443", []string{"mtls", "https"}, "c2.example:443", false},
		{"dns@1.example.com", []string{"dns"}, "1.example.com", false},
		{"", nil, "", true},
	}
	for _, tc := range cases {
		list, host, err := ParseTransports(tc.raw)
		if tc.failed {
			if err == nil {
				t.Errorf("ParseTransports(%q) unexpectedly succeeded", tc.raw)
			}
			continue
		}
		if err != nil || host != tc.host || strings.Join(list, ",") != strings.Join(tc.list, ",") {
			t.Errorf("ParseTransports(%q) = (%v,%q,%v), want (%v,%q,nil)", tc.raw, list, host, err, tc.list, tc.host)
		}
	}
}

func TestConfigFromRequest(t *testing.T) {
	cfg, transport, err := configFromRequest(BuildRequest{
		Transports:   "mtls@c2.example:4444",
		IntervalMs:   1000,
		JitterPct:    10,
		EngagementID: "eng-1",
	})
	if err != nil {
		t.Fatalf("configFromRequest: %v", err)
	}
	if transport != "mtls" || cfg.ServerAddr != "c2.example:4444" || cfg.IntervalMs != 1000 {
		t.Fatalf("unexpected mtls config: %s %+v", transport, cfg)
	}

	cfg, transport, err = configFromRequest(BuildRequest{Transports: "https@c2.example:443"})
	if err != nil {
		t.Fatalf("configFromRequest https: %v", err)
	}
	if transport != "https" || cfg.HTTPSURL != "https://c2.example:443/api/c2" {
		t.Fatalf("unexpected https config: %s %+v", transport, cfg)
	}

	if _, _, err := configFromRequest(BuildRequest{Transports: "dns@c2.example"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("dns transport err = %v, want ErrInvalidRequest", err)
	}
}

func TestBuildRejectsUnsupportedFormat(t *testing.T) {
	_, err := Build(context.Background(), ".", BuildRequest{
		TargetOS:   "linux",
		TargetArch: "amd64",
		Format:     "dll",
		Transports: "mtls@127.0.0.1:4444",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Build(dll) err = %v, want ErrInvalidRequest", err)
	}
}

func TestBuildEmbedsConfigWithoutModifyingSource(t *testing.T) {
	root, err := FindProjectRoot()
	if err != nil {
		t.Fatalf("FindProjectRoot: %v", err)
	}
	sourcePath := filepath.Join(root, "cmd", "implant", "config_gen.go")
	before, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read source config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	artifact, err := Build(ctx, root, BuildRequest{
		TargetOS:     "linux",
		TargetArch:   "amd64",
		Format:       "exe",
		Transports:   "mtls@127.0.0.1:14444",
		EngagementID: "eng-embedded",
		IntervalMs:   1000,
		JitterPct:    5,
		CACertPEM:    []byte("test-ca"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(artifact.Binary) == 0 || artifact.SHA256 == "" || artifact.Transport != "mtls" {
		t.Fatalf("unexpected artifact: transport=%s bytes=%d sha=%s", artifact.Transport, len(artifact.Binary), artifact.SHA256)
	}
	if artifact.Config.EngagementID != "eng-embedded" || artifact.Config.ServerAddr != "127.0.0.1:14444" {
		t.Fatalf("embedded config = %+v", artifact.Config)
	}

	after, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read source config after build: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("build modified cmd/implant/config_gen.go")
	}
}
