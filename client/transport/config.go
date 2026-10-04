package transport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the operator's connection configuration.
type Config struct {
	ServerAddr string `json:"server_addr"`
	CACertPath string `json:"ca_cert_path"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	Operator   string `json:"operator"`
	ConfigDir  string `json:"config_dir,omitempty"`
}

// DefaultConfigDir returns the default configuration directory.
func DefaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".pc2"
	}
	return filepath.Join(home, ".pc2")
}

// DefaultConfigPath returns the path to the default configuration file.
func DefaultConfigPath() string {
	return filepath.Join(DefaultConfigDir(), "config.json")
}

// LoadConfig reads the operator configuration from the given path.
// If path is empty, the default config path is used.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cfg.ConfigDir = filepath.Dir(path)
	return &cfg, nil
}

// Save writes the configuration to disk at the given path.
// If path is empty, the default config path is used.
func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultConfigPath()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// validate checks that required configuration fields are present.
func (c *Config) validate() error {
	if c.ServerAddr == "" {
		return fmt.Errorf("server_addr is required")
	}
	if c.CACertPath == "" {
		return fmt.Errorf("ca_cert_path is required")
	}
	if c.CertPath == "" {
		return fmt.Errorf("cert_path is required")
	}
	if c.KeyPath == "" {
		return fmt.Errorf("key_path is required")
	}
	if c.Operator == "" {
		return fmt.Errorf("operator name is required")
	}
	return nil
}

// GenerateConfig creates a new config file with the provided parameters.
func GenerateConfig(serverAddr, caCertPath, certPath, keyPath, operator, outputPath string) error {
	cfg := &Config{
		ServerAddr: serverAddr,
		CACertPath: caCertPath,
		CertPath:   certPath,
		KeyPath:    keyPath,
		Operator:   operator,
	}

	if err := cfg.validate(); err != nil {
		return err
	}

	return cfg.Save(outputPath)
}

// ResolvePath resolves a path relative to the config directory.
// If the path is absolute, it is returned as-is.
func (c *Config) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if c.ConfigDir == "" {
		return path
	}
	return filepath.Join(c.ConfigDir, path)
}
