package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func ServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	var tlsCert tls.Certificate

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading cert/key: %w", err)
		}
		tlsCert = cert
		log.Printf("Loaded TLS certificate from %s", certFile)
	} else {
		log.Println("No --cert/--key provided, generating self-signed certificate")
		cert, err := GenerateSelfSigned()
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert: %w", err)
		}
		tlsCert = cert
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		cfg.ClientCAs = pool
		// Supplying a CA means "authenticate implants with a client
		// certificate". Without this, the listener accepts any TLS client —
		// any host able to reach the port could register as an implant.
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("Loaded CA certificate from %s (client certificate required)", caFile)
	} else {
		log.Println("No --ca provided: implants will NOT be authenticated by client certificate")
	}

	return cfg, nil
}

// ClientOptions configures a client-side (implant) TLS connection.
type ClientOptions struct {
	// CAPath is the PEM CA used to verify the server certificate. It is
	// required unless Insecure is set.
	CAPath string

	// CertFile and KeyFile are the PEM client certificate and key presented
	// to the server when the listener requires client authentication. Both
	// must be set together.
	CertFile string
	KeyFile  string

	// Insecure skips server certificate verification entirely. It is
	// development-only: without verification the implant cannot tell a real
	// C2 server from an impostor, and will hand its client certificate to
	// whoever answers the port.
	Insecure bool
}

// ClientTLSConfig builds the TLS configuration for an implant connecting to a
// C2 server.
func ClientTLSConfig(opts ClientOptions) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	switch {
	case opts.Insecure:
		log.Println("WARNING: --insecure set; server certificate verification is disabled")
		cfg.InsecureSkipVerify = true
	case opts.CAPath == "":
		return nil, fmt.Errorf("no CA certificate provided: pass --ca <ca.pem> to verify the server, or --insecure to disable verification explicitly")
	default:
		caPEM, err := os.ReadFile(opts.CAPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		cfg.RootCAs = pool
	}

	if (opts.CertFile == "") != (opts.KeyFile == "") {
		return nil, fmt.Errorf("client certificate and key must be provided together (got cert=%q key=%q)", opts.CertFile, opts.KeyFile)
	}
	if opts.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
		log.Printf("Loaded client certificate from %s", opts.CertFile)
	}

	return cfg, nil
}

// ClientTLSConfigFromPEM is the embedded-config variant of ClientTLSConfig.
// Payloads carry PEM material rather than paths on the target filesystem.
func ClientTLSConfigFromPEM(caPEM, certPEM, keyPEM []byte, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}

	switch {
	case insecure:
		log.Println("WARNING: embedded config disables server certificate verification")
		cfg.InsecureSkipVerify = true
	case len(caPEM) == 0:
		return nil, fmt.Errorf("embedded config has no CA certificate; refusing to connect unauthenticated")
	default:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse embedded CA certificate")
		}
		cfg.RootCAs = pool
	}

	if (len(certPEM) == 0) != (len(keyPEM) == 0) {
		return nil, fmt.Errorf("embedded client certificate and key must be provided together")
	}
	if len(certPEM) > 0 {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("loading embedded client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func GenerateSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "private-c2-server",
			Organization: []string{"Private-C2"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "private-c2-server"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
			net.IPv4zero,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	fp := sha256.Sum256(certDER)
	log.Printf("Self-signed certificate fingerprint (SHA-256): %x", fp)

	return tls.X509KeyPair(certPEM, keyPEM)
}
