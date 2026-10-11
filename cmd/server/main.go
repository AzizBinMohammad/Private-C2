package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/tlsutil"
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
	tlsConfig, err := tlsutil.ServerTLSConfig(*certFile, *keyFile, *caFile)
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

