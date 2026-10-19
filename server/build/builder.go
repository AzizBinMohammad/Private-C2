// Package build creates self-contained implant payloads. Configuration is
// injected with go build's -overlay flag, so the source tree is never modified.
package build

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

// BuildRequest describes one payload build.
type BuildRequest struct {
	TargetOS   string `json:"target_os"`
	TargetArch string `json:"target_arch"`
	Format     string `json:"format"`
	Transports string `json:"transports"` // e.g. "mtls,https@c2.example.com:443"
	Mode       string `json:"mode"`

	EngagementID string `json:"engagement_id"`

	CACertPEM     []byte `json:"-"`
	ClientCertPEM []byte `json:"-"`
	ClientKeyPEM  []byte `json:"-"`
	Insecure      bool   `json:"insecure"`

	IntervalMs int `json:"interval_ms"`
	JitterPct  int `json:"jitter_pct"`

	ScopeCIDRs   []string `json:"scope_cidrs"`
	ScopeHosts   []string `json:"scope_hosts"`
	ScopeDomains []string `json:"scope_domains"`

	KillDate       string `json:"kill_date"`
	WindowStart    string `json:"window_start"`
	WindowEnd      string `json:"window_end"`
	DataQuotaBytes int64  `json:"data_quota_bytes"`
	RemoteKillURL  string `json:"remote_kill_url"`
	SafeMode       bool   `json:"safe_mode"`
}

// Artifact is a successfully built payload.
type Artifact struct {
	Binary    []byte
	SHA256    string
	Transport string
	Config    protocol.ImplantConfig
}

var buildSlots = make(chan struct{}, 2)

// ErrInvalidRequest marks build failures caused by the caller's input rather
// than by the toolchain or filesystem.
var ErrInvalidRequest = errors.New("invalid build request")

// ParseTransports parses "mtls,https@host:port" into transport names and the
// last explicitly supplied host.
func ParseTransports(raw string) (transports []string, host string, err error) {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "@"); i >= 0 {
			name := strings.TrimSpace(part[:i])
			host = strings.TrimSpace(part[i+1:])
			if name != "" {
				transports = append(transports, name)
			}
			continue
		}
		transports = append(transports, part)
	}
	if len(transports) == 0 {
		return nil, "", fmt.Errorf("no transports specified")
	}
	return transports, host, nil
}

// FindProjectRoot walks up from the working directory and executable looking
// for go.work.
func FindProjectRoot() (string, error) {
	var starts []string
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	for _, start := range starts {
		for dir := start; ; dir = filepath.Dir(dir) {
			if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	return "", fmt.Errorf("project root with go.work not found")
}

// configFromRequest derives the embedded config and the selected carrier.
func configFromRequest(req BuildRequest) (protocol.ImplantConfig, string, error) {
	transports, host, err := ParseTransports(req.Transports)
	if err != nil {
		return protocol.ImplantConfig{}, "", fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if host == "" {
		return protocol.ImplantConfig{}, "", fmt.Errorf("%w: transports must include a server address, e.g. mtls@c2.example.com:4444", ErrInvalidRequest)
	}

	transport := ""
	for _, t := range transports {
		if t == "mtls" {
			transport = "mtls"
			break
		}
	}
	if transport == "" {
		for _, t := range transports {
			if t == "https" {
				transport = "https"
				break
			}
		}
	}
	if transport == "" {
		return protocol.ImplantConfig{}, "", fmt.Errorf("%w: only mtls and https transports are implemented", ErrInvalidRequest)
	}

	cfg := protocol.ImplantConfig{
		Transport:      transport,
		CACertPEM:      string(req.CACertPEM),
		ClientCertPEM:  string(req.ClientCertPEM),
		ClientKeyPEM:   string(req.ClientKeyPEM),
		Insecure:       req.Insecure,
		IntervalMs:     req.IntervalMs,
		JitterPct:      req.JitterPct,
		Mode:           req.Mode,
		EngagementID:   req.EngagementID,
		ScopeCIDRs:     req.ScopeCIDRs,
		ScopeHosts:     req.ScopeHosts,
		ScopeDomains:   req.ScopeDomains,
		KillDate:       req.KillDate,
		WindowStart:    req.WindowStart,
		WindowEnd:      req.WindowEnd,
		DataQuotaBytes: req.DataQuotaBytes,
		RemoteKillURL:  req.RemoteKillURL,
		SafeMode:       req.SafeMode,
	}
	if transport == "mtls" {
		cfg.ServerAddr = host
	} else {
		cfg.HTTPSURL = "https://" + host + "/api/c2"
	}
	return cfg, transport, nil
}

// Build compiles a self-contained implant. The caller owns ctx deadlines.
func Build(ctx context.Context, root string, req BuildRequest) (*Artifact, error) {
	format := req.Format
	if format == "" {
		format = "exe"
	}
	switch format {
	case "exe", "ps1", "sh":
	default:
		return nil, fmt.Errorf("%w: format %q is not supported (only exe, ps1, and sh are available without a cross-toolchain)", ErrInvalidRequest, format)
	}
	if req.TargetOS == "" {
		return nil, fmt.Errorf("%w: target_os is required", ErrInvalidRequest)
	}
	if req.TargetArch == "" {
		req.TargetArch = "amd64"
	}

	cfg, transport, err := configFromRequest(req)
	if err != nil {
		return nil, err
	}

	select {
	case buildSlots <- struct{}{}:
		defer func() { <-buildSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	tmp, err := os.MkdirTemp("", "pc2-build-*")
	if err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal implant config: %w", err)
	}
	generated := "package main\n\n// Generated by the payload builder.\nconst embeddedConfigJSON = " +
		strconv.Quote(string(configJSON)) + "\n"
	generatedPath := filepath.Join(tmp, "config_gen.go")
	if err := os.WriteFile(generatedPath, []byte(generated), 0600); err != nil {
		return nil, fmt.Errorf("write generated config: %w", err)
	}

	targetPath := filepath.Join(root, "cmd", "implant", "config_gen.go")
	overlay, err := json.Marshal(map[string]any{
		"Replace": map[string]string{targetPath: generatedPath},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal overlay: %w", err)
	}
	overlayPath := filepath.Join(tmp, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
		return nil, fmt.Errorf("write overlay: %w", err)
	}

	outPath := filepath.Join(tmp, "implant")
	if req.TargetOS == "windows" {
		outPath += ".exe"
	}
	cmd := exec.CommandContext(ctx, "go", "build",
		"-overlay", overlayPath,
		"-trimpath",
		"-ldflags=-s -w",
		"-o", outPath,
		"./cmd/implant",
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"GOOS="+req.TargetOS,
		"GOARCH="+req.TargetArch,
		"CGO_ENABLED=0",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go build failed: %s: %w", strings.TrimSpace(string(output)), err)
	}

	binary, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read built implant: %w", err)
	}
	sum := sha256.Sum256(binary)
	return &Artifact{
		Binary:    binary,
		SHA256:    hex.EncodeToString(sum[:]),
		Transport: transport,
		Config:    cfg,
	}, nil
}

// BuildSlots returns the configured concurrency limit (used by tests).
func BuildSlots() int { return cap(buildSlots) }
