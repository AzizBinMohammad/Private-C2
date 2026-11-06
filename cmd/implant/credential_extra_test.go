package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCredentialDPAPIValidation(t *testing.T) {
	cases := []string{``, `{}`, `{"data":"!!not-base64!!"}`}
	if runtime.GOOS != "windows" {
		cases = append(cases, `{"data":"`+base64.StdEncoding.EncodeToString([]byte("blob"))+`"}`)
	}
	for _, args := range cases {
		if _, err := handleCredentialDPAPI(context.Background(), args); err == nil {
			t.Errorf("handleCredentialDPAPI(%q) unexpectedly succeeded", args)
		}
	}
}

func TestCredentialKerberosCapturesCCache(t *testing.T) {
	dir := t.TempDir()
	ccache := filepath.Join(dir, "krb5cc_test")
	data := []byte("kerberos-cache-bytes")
	if err := os.WriteFile(ccache, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5CCNAME", "FILE:"+ccache)

	out, err := handleCredentialKerberos(context.Background(), "")
	if err != nil {
		t.Fatalf("kerberos: %v", err)
	}
	var result struct {
		Path   string `json:"ccache_path"`
		Size   int    `json:"ccache_size"`
		SHA256 string `json:"ccache_sha256"`
		Data   string `json:"ccache_data"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Path != ccache || result.Size != len(data) {
		t.Fatalf("unexpected result: %+v", result)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil || string(decoded) != string(data) {
		t.Fatalf("ccache data = %q, %v", decoded, err)
	}
	sum := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha mismatch: %s", result.SHA256)
	}
}

func TestCredentialKerberosWithoutCCache(t *testing.T) {
	t.Setenv("KRB5CCNAME", "")
	out, err := handleCredentialKerberos(context.Background(), "")
	if err != nil {
		t.Fatalf("kerberos: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result["klist"] == nil {
		t.Fatalf("result lacks the klist field: %s", out)
	}
}
