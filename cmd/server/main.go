package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/tlsutil"
	"github.com/azizbinmohammad/private-c2/server/api/httpapi"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
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
	persistence := c2.NewGORMPersistence(
		repository.NewSessionRepository(db),
		repository.NewTaskRepository(db),
	)
	// Sessions marked active from a previous process cannot still be live.
	if err := persistence.MarkLiveSessionsDisconnected(context.Background()); err != nil {
		log.Printf("Failed to reconcile previous sessions: %v", err)
	}
	implantServer.SetPersistence(persistence)

	// --- TLS listener for implants ---
	//
	// Registered with the implant server rather than bound directly, so the
	// API reports the listener that is actually running and operators can stop
	// it. The listener is served on the port from --listen; StartListener
	// takes a bind address and a port separately.
	bindHost, bindPort, err := net.SplitHostPort(*listenAddr)
	if err != nil {
		log.Fatalf("Invalid --listen address %q: %v", *listenAddr, err)
	}
	port, err := strconv.Atoi(bindPort)
	if err != nil {
		log.Fatalf("Invalid port in --listen address %q: %v", *listenAddr, err)
	}
	defaultListener, err := implantServer.StartListener(c2.ListenerConfig{
		ID:        "default",
		Type:      c2.ListenerTypeMTLS,
		BindAddr:  bindHost,
		Port:      port,
		TLSConfig: tlsConfig,
	})
	if err != nil {
		log.Fatalf("Failed to start implant listener: %v", err)
	}
	log.Printf("Implant TLS listener on %s", net.JoinHostPort(defaultListener.BindAddr, strconv.Itoa(defaultListener.Port)))

	// --- Operator HTTP API ---
	apiRouter := httpapi.NewRouter(implantServer, db, tlsConfig)
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

	for _, ln := range implantServer.Listeners() {
		if err := implantServer.StopListener(ln.ID); err != nil {
			log.Printf("Stopping listener %s: %v", ln.ID, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	apiServer.Shutdown(ctx)
	metricsServer.Shutdown(ctx)

	log.Println("Server stopped")
}
