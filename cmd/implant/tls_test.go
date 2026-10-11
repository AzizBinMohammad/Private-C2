package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildTLSConfig_WithCA(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTestCA(t, dir)

	cfg, err := buildTLSConfig(caPath)
	if err != nil {
		t.Fatalf("buildTLSConfig with CA: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.3)", cfg.MinVersion, tls.VersionTLS13)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs should not be nil when CA provided")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false when CA provided")
	}
}

func TestBuildTLSConfig_NoCA(t *testing.T) {
	cfg, err := buildTLSConfig("")
	if err != nil {
		t.Fatalf("buildTLSConfig without CA: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.3)", cfg.MinVersion, tls.VersionTLS13)
	}
	if cfg.RootCAs != nil {
		t.Error("RootCAs should be nil when no CA provided")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when no CA provided")
	}
}

func TestBuildTLSConfig_InvalidCAPath(t *testing.T) {
	_, err := buildTLSConfig("/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent CA file")
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := buildTLSConfig(badCA)
	if err == nil {
		t.Fatal("expected error for unparseable CA PEM")
	}
}

func TestBuildTLSConfig_NoCertificates(t *testing.T) {
	cfg, err := buildTLSConfig("")
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("len(Certificates) = %d, want 0 (implant does not present client certs)", len(cfg.Certificates))
	}
}

func writeTestCA(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	return caPath
}
