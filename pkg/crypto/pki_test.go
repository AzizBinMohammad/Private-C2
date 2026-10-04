package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestNewCertificateAuthority(t *testing.T) {
	ca, caPEM, err := NewCertificateAuthority("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}

	if ca.Certificate == nil {
		t.Fatal("CA certificate should not be nil")
	}
	if ca.PrivateKey == nil {
		t.Fatal("CA private key should not be nil")
	}
	if len(caPEM) == 0 {
		t.Fatal("CA PEM should not be empty")
	}

	if !ca.Certificate.IsCA {
		t.Fatal("certificate should be a CA")
	}
	if ca.Certificate.Subject.CommonName != "Test CA" {
		t.Fatalf("expected CN %q, got %q", "Test CA", ca.Certificate.Subject.CommonName)
	}
}

func TestIssueCertificate(t *testing.T) {
	ca, _, err := NewCertificateAuthority("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}

	certPEM, keyPEM, err := ca.IssueCertificate("leaf.example.com", 12*time.Hour)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	if len(certPEM) == 0 {
		t.Fatal("leaf cert PEM should not be empty")
	}
	if len(keyPEM) == 0 {
		t.Fatal("leaf key PEM should not be empty")
	}

	// Parse the leaf certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode leaf cert PEM")
	}
	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if leafCert.Subject.CommonName != "leaf.example.com" {
		t.Fatalf("expected CN %q, got %q", "leaf.example.com", leafCert.Subject.CommonName)
	}
	if leafCert.IsCA {
		t.Fatal("leaf certificate should not be a CA")
	}
}

func TestLeafValidatesAgainstCAPool(t *testing.T) {
	ca, _, err := NewCertificateAuthority("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}

	certPEM, _, err := ca.IssueCertificate("leaf.example.com", 12*time.Hour)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	pool := ca.CertPool()

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	_, err = leafCert.Verify(opts)
	if err != nil {
		t.Fatalf("leaf cert should validate against CA pool: %v", err)
	}
}

func TestCertPoolUsable(t *testing.T) {
	ca, _, err := NewCertificateAuthority("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}

	pool := ca.CertPool()
	if pool == nil {
		t.Fatal("CertPool should not be nil")
	}

	// Verify that a cert from a different CA does not validate
	otherCA, _, err := NewCertificateAuthority("Other CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCertificateAuthority (other): %v", err)
	}

	otherCertPEM, _, err := otherCA.IssueCertificate("other.example.com", 12*time.Hour)
	if err != nil {
		t.Fatalf("IssueCertificate (other): %v", err)
	}

	block, _ := pem.Decode(otherCertPEM)
	otherCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	_, err = otherCert.Verify(x509.VerifyOptions{Roots: pool})
	if err == nil {
		t.Fatal("cert from other CA should not validate against original CA pool")
	}
}

func TestLeafCertTLSUsable(t *testing.T) {
	ca, _, err := NewCertificateAuthority("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}

	certPEM, keyPEM, err := ca.IssueCertificate("leaf.example.com", 12*time.Hour)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	// Verify the cert/key pair can be used for TLS
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("leaf cert/key pair should be usable for TLS: %v", err)
	}
}
