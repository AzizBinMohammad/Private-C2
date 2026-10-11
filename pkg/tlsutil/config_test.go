package tlsutil

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

// --- ServerTLSConfig tests ---

func TestServerTLSConfig_WithCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)

	cfg, err := ServerTLSConfig(certPath, keyPath, "")
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
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs should be nil when no CA file provided")
	}
}

func TestServerTLSConfig_SelfSigned(t *testing.T) {
	cfg, err := ServerTLSConfig("", "", "")
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
}

func TestServerTLSConfig_WithCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)

	cfg, err := ServerTLSConfig(certPath, keyPath, certPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig with CA: %v", err)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs should not be nil when CA file provided")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
}

func TestServerTLSConfig_InvalidCertPath(t *testing.T) {
	_, err := ServerTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem", "")
	if err == nil {
		t.Fatal("expected error for nonexistent cert/key")
	}
}

func TestServerTLSConfig_InvalidCAPath(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)

	_, err := ServerTLSConfig(certPath, keyPath, "/nonexistent/ca.pem")
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

	_, err := ServerTLSConfig(certPath, keyPath, badCA)
	if err == nil {
		t.Fatal("expected error for unparseable CA PEM")
	}
}

// --- ClientTLSConfig tests ---

func TestClientTLSConfig_WithCA(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTestCA(t, dir)

	cfg, err := ClientTLSConfig(caPath)
	if err != nil {
		t.Fatalf("ClientTLSConfig with CA: %v", err)
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

func TestClientTLSConfig_NoCA(t *testing.T) {
	cfg, err := ClientTLSConfig("")
	if err != nil {
		t.Fatalf("ClientTLSConfig without CA: %v", err)
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

func TestClientTLSConfig_InvalidCAPath(t *testing.T) {
	_, err := ClientTLSConfig("/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent CA file")
	}
}

func TestClientTLSConfig_InvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := ClientTLSConfig(badCA)
	if err == nil {
		t.Fatal("expected error for unparseable CA PEM")
	}
}

func TestClientTLSConfig_NoCertificates(t *testing.T) {
	cfg, err := ClientTLSConfig("")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("len(Certificates) = %d, want 0", len(cfg.Certificates))
	}
}

// --- GenerateSelfSigned tests ---

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := GenerateSelfSigned()
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

// --- test helpers ---

func writeTestCertKey(t *testing.T, dir string) (string, string) {
	t.Helper()

	cert, err := GenerateSelfSigned()
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
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
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
