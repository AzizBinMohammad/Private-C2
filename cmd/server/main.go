package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/crypto"
	"github.com/azizbinmohammad/private-c2/server/api/middleware"
	"github.com/azizbinmohammad/private-c2/server/core"
	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
	"github.com/azizbinmohammad/private-c2/server/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	grpcAddr := flag.String("grpc-addr", ":31337", "gRPC listen address")
	metricsAddr := flag.String("metrics-addr", ":9090", "Metrics/health listen address")
	dbDialect := flag.String("db-dialect", "sqlite", "Database dialect (sqlite, postgres)")
	dbDSN := flag.String("db-dsn", "private-c2.db", "Database connection string")
	flag.Parse()

	log.Println("Starting Private-C2 server")

	dbCfg := store.DefaultConfig()
	dbCfg.Dialect = *dbDialect
	dbCfg.DSN = *dbDSN

	db, err := store.Open(dbCfg)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	log.Println("Database connected")

	if err := store.Migrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	log.Println("Database migrated")

	eventBus := core.NewEventBus()
	sessionMgr := core.NewSessionManager(eventBus, 30*time.Second, 2*time.Minute)

	operatorRepo := repository.NewOperatorRepository(db)
	_ = operatorRepo

	ca, _, err := crypto.NewCertificateAuthority("Private-C2 Root CA", 10*365*24*time.Hour)
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}

	serverCert, serverKey, err := ca.IssueCertificate("private-c2-server", 365*24*time.Hour)
	if err != nil {
		log.Fatalf("Failed to issue server certificate: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatalf("Failed to parse TLS key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.CertPool(),
		MinVersion:   tls.VersionTLS13,
	}

	rateLimiter := middleware.NewRateLimiter(100, 200)

	operatorLookup := func(ctx context.Context, cn string) (*middleware.OperatorInfo, error) {
		op, err := operatorRepo.GetByName(cn)
		if err != nil {
			return nil, err
		}
		return &middleware.OperatorInfo{
			ID:   op.ID,
			Name: op.Name,
			Role: op.Role,
		}, nil
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(
			middleware.AuthUnaryInterceptor(operatorLookup),
			middleware.RBACUnaryInterceptor(),
			middleware.RateLimitUnaryInterceptor(rateLimiter),
		),
		grpc.ChainStreamInterceptor(
			middleware.AuthStreamInterceptor(operatorLookup),
			middleware.RBACStreamInterceptor(),
			middleware.RateLimitStreamInterceptor(rateLimiter),
		),
	)

	_ = grpcServer

	telemetry.Init()
	healthChecker := telemetry.NewHealthChecker()

	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.Handler())
	mux.HandleFunc("/healthz", healthChecker.Handler())

	metricsServer := &http.Server{
		Addr:    *metricsAddr,
		Handler: mux,
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			sessionMgr.RunHealthCheck()
		}
	}()

	go func() {
		log.Printf("Metrics/health server listening on %s", *metricsAddr)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Metrics server error: %v", err)
		}
	}()

	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *grpcAddr, err)
	}

	go func() {
		log.Printf("gRPC server listening on %s", *grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server error: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down", sig)

	grpcServer.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	metricsServer.Shutdown(ctx)

	log.Println("Server stopped")
}
