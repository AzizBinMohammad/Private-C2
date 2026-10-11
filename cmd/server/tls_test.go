package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/tlsutil"
)

func TestServerTLSConfig_WithCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)

	cfg, err := tlsutil.ServerTLSConfig(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("ServerTLSConfig with cert+key: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert (no CA provided)", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs should be nil when no CA file provided")
	}
}

func TestServerTLSConfig_SelfSigned(t *testing.T) {
	cfg, err := tlsutil.ServerTLSConfig("", "", "")
	if err != nil {
		t.Fatalf("ServerTLSConfig self-signed: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}

	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "private-c2-server" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "private-c2-server")
	}
	if leaf.Issuer.CommonName != leaf.Subject.CommonName {
		t.Error("expected self-signed cert (issuer == subject)")
	}
}

func TestServerTLSConfig_WithCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)

	cfg, err := tlsutil.ServerTLSConfig(certPath, keyPath, certPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig with CA: %v", err)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs should not be nil when CA file provided")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert (CA loaded but mTLS not required)", cfg.ClientAuth)
	}
}

func TestServerTLSConfig_InvalidCertPath(t *testing.T) {
	_, err := tlsutil.ServerTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem", "")
	if err == nil {
		t.Fatal("expected error for nonexistent cert/key")
	}
}

func TestServerTLSConfig_InvalidCAPath(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)

	_, err := tlsutil.ServerTLSConfig(certPath, keyPath, "/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent CA file")
	}
}

func TestServerTLSConfig_InvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := tlsutil.ServerTLSConfig(certPath, keyPath, badCA)
	if err == nil {
		t.Fatal("expected error for unparseable CA PEM")
	}
}

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate returned")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "private-c2-server" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "private-c2-server")
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("cert should be valid for localhost: %v", err)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("missing KeyUsageDigitalSignature")
	}
	if len(leaf.ExtKeyUsage) == 0 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("missing ExtKeyUsageServerAuth")
	}
}

func writeTestCertKey(t *testing.T, dir string) (string, string) {
	t.Helper()

	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	certPath := filepath.Join(dir, "server.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyPath := filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}
