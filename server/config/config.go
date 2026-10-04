package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// ServerConfig holds all runtime configuration for the Private-C2
// server. Values are populated from environment variables by Load(),
// falling back to sensible defaults suitable for local development.
type ServerConfig struct {
	// Network
	GRPCAddr    string // TCP address for the gRPC listener.
	MetricsAddr string // TCP address for the health/metrics HTTP server.

	// Database
	DBDialect string // "sqlite" or "postgres".
	DBDSN     string // Connection string / file path.

	// TLS
	CACertPath     string // PEM-encoded CA certificate.
	ServerCertPath string // PEM-encoded server certificate.
	ServerKeyPath  string // PEM-encoded server private key.

	// Rate limiting
	RateLimitRPS   float64 // Sustained requests per second.
	RateLimitBurst float64 // Burst size.

	// Session health thresholds
	SessionStaleThreshold time.Duration // Time before a session is considered stale.
	SessionLostThreshold  time.Duration // Time before a stale session is considered lost.

	// Logging / audit
	LogLevel      string // "debug", "info", "warn", "error".
	AuditFilePath string // Path to the append-only audit log file.
}

// Defaults returns a ServerConfig populated with development-mode
// defaults. These are the values used when the corresponding
// environment variable is not set.
func Defaults() ServerConfig {
	return ServerConfig{
		GRPCAddr:              ":31337",
		MetricsAddr:           ":9090",
		DBDialect:             "sqlite",
		DBDSN:                 "private-c2.db",
		CACertPath:            "certs/ca-cert.pem",
		ServerCertPath:        "certs/server-cert.pem",
		ServerKeyPath:         "certs/server-key.pem",
		RateLimitRPS:          100,
		RateLimitBurst:        200,
		SessionStaleThreshold: 30 * time.Second,
		SessionLostThreshold:  2 * time.Minute,
		LogLevel:              "info",
		AuditFilePath:         "audit.log",
	}
}

// Load reads configuration from the environment, falling back to
// Defaults() for any variable that is not set.
func Load() (ServerConfig, error) {
	cfg := Defaults()

	if v := os.Getenv("PC2_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	if v := os.Getenv("PC2_METRICS_ADDR"); v != "" {
		cfg.MetricsAddr = v
	}
	if v := os.Getenv("PC2_DB_DIALECT"); v != "" {
		cfg.DBDialect = v
	}
	if v := os.Getenv("PC2_DB_DSN"); v != "" {
		cfg.DBDSN = v
	}
	if v := os.Getenv("PC2_CA_CERT_PATH"); v != "" {
		cfg.CACertPath = v
	}
	if v := os.Getenv("PC2_SERVER_CERT_PATH"); v != "" {
		cfg.ServerCertPath = v
	}
	if v := os.Getenv("PC2_SERVER_KEY_PATH"); v != "" {
		cfg.ServerKeyPath = v
	}
	if v := os.Getenv("PC2_RATE_LIMIT_RPS"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return cfg, fmt.Errorf("PC2_RATE_LIMIT_RPS: %w", err)
		}
		cfg.RateLimitRPS = f
	}
	if v := os.Getenv("PC2_RATE_LIMIT_BURST"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return cfg, fmt.Errorf("PC2_RATE_LIMIT_BURST: %w", err)
		}
		cfg.RateLimitBurst = f
	}
	if v := os.Getenv("PC2_SESSION_STALE_THRESHOLD"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("PC2_SESSION_STALE_THRESHOLD: %w", err)
		}
		cfg.SessionStaleThreshold = d
	}
	if v := os.Getenv("PC2_SESSION_LOST_THRESHOLD"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("PC2_SESSION_LOST_THRESHOLD: %w", err)
		}
		cfg.SessionLostThreshold = d
	}
	if v := os.Getenv("PC2_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("PC2_AUDIT_FILE_PATH"); v != "" {
		cfg.AuditFilePath = v
	}

	return cfg, nil
}

// Validate performs semantic checks on the configuration and returns
// an error describing every issue found.
func (c *ServerConfig) Validate() error {
	var errs []string

	if c.GRPCAddr == "" {
		errs = append(errs, "GRPCAddr must not be empty")
	}
	if c.MetricsAddr == "" {
		errs = append(errs, "MetricsAddr must not be empty")
	}

	switch c.DBDialect {
	case "sqlite", "postgres":
		// ok
	default:
		errs = append(errs, fmt.Sprintf("unsupported DBDialect %q (want sqlite or postgres)", c.DBDialect))
	}

	if c.DBDSN == "" {
		errs = append(errs, "DBDSN must not be empty")
	}

	if c.RateLimitRPS <= 0 {
		errs = append(errs, "RateLimitRPS must be positive")
	}
	if c.RateLimitBurst <= 0 {
		errs = append(errs, "RateLimitBurst must be positive")
	}

	if c.SessionStaleThreshold <= 0 {
		errs = append(errs, "SessionStaleThreshold must be positive")
	}
	if c.SessionLostThreshold <= 0 {
		errs = append(errs, "SessionLostThreshold must be positive")
	}
	if c.SessionStaleThreshold >= c.SessionLostThreshold {
		errs = append(errs, "SessionStaleThreshold must be less than SessionLostThreshold")
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
		// ok
	default:
		errs = append(errs, fmt.Sprintf("unsupported LogLevel %q (want debug, info, warn or error)", c.LogLevel))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", joinErrors(errs))
	}
	return nil
}

func joinErrors(errs []string) string {
	result := ""
	for i, e := range errs {
		if i > 0 {
			result += "\n  - "
		}
		result += e
	}
	return result
}
