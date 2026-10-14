package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	// Supplying a CA means "authenticate implants" — accepting any client
	// would let any host that can reach the port register as an implant.
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
}

// TestServerTLSConfig_NoCA_DoesNotRequireClientCert pins the deliberate
// counterpart: without a CA there is nothing to verify a client certificate
// against, so the listener must not be left claiming to require one.
func TestServerTLSConfig_NoCA_DoesNotRequireClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertKey(t, dir)

	cfg, err := ServerTLSConfig(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("ServerTLSConfig without CA: %v", err)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs should be nil when no CA file is provided")
	}
	if cfg.ClientAuth == tls.RequireAndVerifyClientCert {
		t.Error("ClientAuth must not require a client cert when no CA is configured")
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

	cfg, err := ClientTLSConfig(ClientOptions{CAPath: caPath})
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

// TestClientTLSConfig_NoCAIsAnError pins the fix for the silent
// InsecureSkipVerify fallback: an implant with no CA and no explicit
// --insecure must refuse to build a configuration rather than quietly accept
// any certificate.
func TestClientTLSConfig_NoCAIsAnError(t *testing.T) {
	_, err := ClientTLSConfig(ClientOptions{})
	if err == nil {
		t.Fatal("expected an error when neither CAPath nor Insecure is set")
	}
	if !strings.Contains(err.Error(), "insecure") {
		t.Errorf("error %q should mention the --insecure escape hatch", err)
	}
}

func TestClientTLSConfig_ExplicitInsecure(t *testing.T) {
	cfg, err := ClientTLSConfig(ClientOptions{Insecure: true})
	if err != nil {
		t.Fatalf("ClientTLSConfig with Insecure: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when Insecure is set")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.3)", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestClientTLSConfig_LoadsClientCertificate(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, keyPath := writeTestCAAndLeaf(t, dir, "implant", x509.ExtKeyUsageClientAuth)

	cfg, err := ClientTLSConfig(ClientOptions{CAPath: caPath, CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatalf("ClientTLSConfig with client cert: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
}

func TestClientTLSConfig_CertWithoutKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, _ := writeTestCAAndLeaf(t, dir, "implant", x509.ExtKeyUsageClientAuth)

	_, err := ClientTLSConfig(ClientOptions{CAPath: caPath, CertFile: certPath})
	if err == nil {
		t.Fatal("expected an error when only the certificate is provided")
	}
}

func TestClientTLSConfig_InvalidCAPath(t *testing.T) {
	_, err := ClientTLSConfig(ClientOptions{CAPath: "/nonexistent/ca.pem"})
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

	_, err := ClientTLSConfig(ClientOptions{CAPath: badCA})
	if err == nil {
		t.Fatal("expected error for unparseable CA PEM")
	}
}

func TestClientTLSConfig_NoCertificatesWhenNoneRequested(t *testing.T) {
	dir := t.TempDir()
	cfg, err := ClientTLSConfig(ClientOptions{CAPath: writeTestCA(t, dir)})
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("len(Certificates) = %d, want 0", len(cfg.Certificates))
	}
}

// --- mTLS handshake tests ---
//
// These are the tests that actually prove the listener enforces client
// authentication, rather than just asserting a struct field.

func TestMTLSHandshake_ValidClientCertSucceeds(t *testing.T) {
	dir := t.TempDir()
	caPath, serverCert, serverKey := writeTestCAAndLeaf(t, dir, "private-c2-server", x509.ExtKeyUsageServerAuth)
	_, clientCert, clientKey := writeTestCAAndLeaf(t, dir, "implant", x509.ExtKeyUsageClientAuth)

	serverCfg, err := ServerTLSConfig(serverCert, serverKey, caPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	clientCfg, err := ClientTLSConfig(ClientOptions{CAPath: caPath, CertFile: clientCert, KeyFile: clientKey})
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	ln := startTLSEcho(t, serverCfg)
	defer ln.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("handshake with a valid client certificate failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write after handshake: %v", err)
	}
}

func TestMTLSHandshake_MissingClientCertIsRejected(t *testing.T) {
	dir := t.TempDir()
	caPath, serverCert, serverKey := writeTestCAAndLeaf(t, dir, "private-c2-server", x509.ExtKeyUsageServerAuth)

	serverCfg, err := ServerTLSConfig(serverCert, serverKey, caPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	// Client trusts the server's CA but presents no client certificate.
	clientCfg, err := ClientTLSConfig(ClientOptions{CAPath: caPath})
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	ln := startTLSEcho(t, serverCfg)
	defer ln.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err == nil {
		// TLS 1.3 reports a missing client certificate on first read.
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("handshake succeeded without a client certificate; the listener is not enforcing mTLS")
	}
}

func TestMTLSHandshake_CertFromWrongCAIsRejected(t *testing.T) {
	dir := t.TempDir()
	caPath, serverCert, serverKey := writeTestCAAndLeaf(t, dir, "private-c2-server", x509.ExtKeyUsageServerAuth)

	// A client certificate signed by a different CA.
	otherDir := t.TempDir()
	_, rogueCert, rogueKey := writeTestCAAndLeaf(t, otherDir, "rogue", x509.ExtKeyUsageClientAuth)

	serverCfg, err := ServerTLSConfig(serverCert, serverKey, caPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	clientCfg, err := ClientTLSConfig(ClientOptions{CAPath: caPath, CertFile: rogueCert, KeyFile: rogueKey})
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	ln := startTLSEcho(t, serverCfg)
	defer ln.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("handshake succeeded with a certificate from an untrusted CA")
	}
}

// startTLSEcho starts a TLS listener that accepts connections in the
// background so handshake failures surface on the client side.
func startTLSEcho(t *testing.T, cfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln
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

// writeTestCAAndLeaf creates a CA and a leaf certificate signed by it, for the
// given extended key usage. It returns the CA path, the leaf certificate path
// and the leaf key path. Each call in the same directory writes its own files,
// suffixed by the common name.
func writeTestCAAndLeaf(t *testing.T, dir, cn string, eku x509.ExtKeyUsage) (caPath, certPath, keyPath string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	caPath = filepath.Join(dir, cn+"-ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, cn+"-cert.pem")
	writePEM(t, certPath, "CERTIFICATE", leafDER)

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, cn+"-key.pem")
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)

	return caPath, certPath, keyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
