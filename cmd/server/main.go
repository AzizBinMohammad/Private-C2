package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/azizbinmohammad/private-c2/server/api/httpapi"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/telemetry"
)

func main() {
	listenAddr := flag.String("listen", ":4444", "Implant TLS listener address")
	apiAddr := flag.String("api", "127.0.0.1:8080", "Operator HTTP API address")
	metricsAddr := flag.String("metrics-addr", ":9090", "Metrics/health listen address")
	certFile := flag.String("cert", "", "Server certificate PEM file")
	keyFile := flag.String("key", "", "Server private key PEM file")
	caFile := flag.String("ca", "", "CA certificate PEM for verifying implants (optional)")
	dbPath := flag.String("db", "pc2.db", "SQLite database path")
	flag.Parse()

	log.Println("Starting Private-C2 server")

	// --- Database ---
	dbCfg := store.DefaultConfig()
	dbCfg.Dialect = "sqlite"
	dbCfg.DSN = *dbPath

	db, err := store.Open(dbCfg)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	log.Println("Database connected")

	if err := store.Migrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	log.Println("Database migrated")

	// --- TLS configuration ---
	tlsConfig, err := buildTLSConfig(*certFile, *keyFile, *caFile)
	if err != nil {
		log.Fatalf("TLS setup failed: %v", err)
	}

	// --- Core C2 server ---
	implantServer := c2.NewImplantServer()

	// --- TLS listener for implants ---
	tlsListener, err := tls.Listen("tcp", *listenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *listenAddr, err)
	}
	log.Printf("Implant TLS listener on %s", *listenAddr)

	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				// Check if listener was closed (shutdown).
				select {
				case <-shutdownCh:
					return
				default:
				}
				log.Printf("Accept error: %v", err)
				continue
			}
			go implantServer.HandleConnection(conn)
		}
	}()

	// --- Operator HTTP API ---
	apiRouter := httpapi.NewRouter(implantServer, db)
	apiServer := &http.Server{
		Addr:    *apiAddr,
		Handler: apiRouter,
	}

	go func() {
		log.Printf("Operator HTTP API on %s", *apiAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server error: %v", err)
		}
	}()

	// --- Metrics/health server ---
	telemetry.Init()
	healthChecker := telemetry.NewHealthChecker()

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", telemetry.Handler())
	metricsMux.HandleFunc("/healthz", healthChecker.Handler())

	metricsServer := &http.Server{
		Addr:    *metricsAddr,
		Handler: metricsMux,
	}

	go func() {
		log.Printf("Metrics/health server on %s", *metricsAddr)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Metrics server error: %v", err)
		}
	}()

	// --- Graceful shutdown ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down", sig)

	close(shutdownCh)
	tlsListener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	apiServer.Shutdown(ctx)
	metricsServer.Shutdown(ctx)

	log.Println("Server stopped")
}

// shutdownCh signals the accept loop to stop.
var shutdownCh = make(chan struct{})

// buildTLSConfig constructs the TLS configuration. If certFile/keyFile are
// empty, a self-signed certificate is generated and its fingerprint printed.
func buildTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
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
		cert, err := generateSelfSigned()
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert: %w", err)
		}
		tlsCert = cert
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	// If a CA file is provided, add it to the config but do NOT require
	// client certs (server-side TLS only, no mTLS).
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
		// Still NoClientCert -- the CA is available for optional verification.
		cfg.ClientAuth = tls.NoClientCert
		log.Printf("Loaded CA certificate from %s (client auth not required)", caFile)
	}

	return cfg, nil
}

// generateSelfSigned creates an ephemeral self-signed TLS certificate and
// prints its SHA-256 fingerprint so operators can verify it.
func generateSelfSigned() (tls.Certificate, error) {
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

	// Print fingerprint.
	fp := sha256.Sum256(certDER)
	log.Printf("Self-signed certificate fingerprint (SHA-256): %x", fp)

	return tls.X509KeyPair(certPEM, keyPEM)
}
