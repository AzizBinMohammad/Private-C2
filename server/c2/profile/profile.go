package profile

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// C2Profile defines the communication profile used by listeners and implants
// to blend C2 traffic with normal network patterns.
type C2Profile struct {
	Name        string            `json:"name"`
	HTTPConfig  HTTPProfileConfig `json:"http_config"`
	DNSConfig   DNSProfileConfig  `json:"dns_config"`
	Jitter      JitterConfig      `json:"jitter"`
}

// HTTPProfileConfig defines the HTTP-layer malleable profile.
type HTTPProfileConfig struct {
	GetPaths      []string          `json:"get_paths"`
	PostPaths     []string          `json:"post_paths"`
	Headers       map[string]string `json:"headers"`
	UserAgents    []string          `json:"user_agents"`
	ServerHeaders map[string]string `json:"server_headers"`
	DataTransform string            `json:"data_transform"` // "base64", "hex", "raw"
}

// DNSProfileConfig defines the DNS-layer profile parameters.
type DNSProfileConfig struct {
	ParentDomain string   `json:"parent_domain"`
	RecordTypes  []string `json:"record_types"` // "TXT", "CNAME", "A", "AAAA"
	MaxTXTSize   int      `json:"max_txt_size"`
}

// JitterConfig controls timing randomization for callbacks.
type JitterConfig struct {
	BaseMs int     `json:"base_ms"`
	MaxPct float64 `json:"max_pct"` // 0.0-1.0
}

// DefaultProfile returns a sensible default C2 profile.
func DefaultProfile() *C2Profile {
	return &C2Profile{
		Name: "default",
		HTTPConfig: HTTPProfileConfig{
			GetPaths:  []string{"/api/v1/status", "/health", "/assets/logo.png"},
			PostPaths: []string{"/api/v1/report", "/api/v1/upload", "/submit"},
			Headers: map[string]string{
				"Accept":       "text/html,application/json",
				"Content-Type": "application/octet-stream",
			},
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
			},
			ServerHeaders: map[string]string{
				"Server":       "nginx/1.24.0",
				"X-Powered-By": "Express",
			},
			DataTransform: "base64",
		},
		DNSConfig: DNSProfileConfig{
			ParentDomain: "example.com",
			RecordTypes:  []string{"TXT", "A"},
			MaxTXTSize:   189,
		},
		Jitter: JitterConfig{
			BaseMs: 5000,
			MaxPct: 0.3,
		},
	}
}

// RandomGetPath returns a random GET path from the profile.
func (p *C2Profile) RandomGetPath() string {
	if len(p.HTTPConfig.GetPaths) == 0 {
		return "/"
	}
	return p.HTTPConfig.GetPaths[rand.Intn(len(p.HTTPConfig.GetPaths))]
}

// RandomPostPath returns a random POST path from the profile.
func (p *C2Profile) RandomPostPath() string {
	if len(p.HTTPConfig.PostPaths) == 0 {
		return "/"
	}
	return p.HTTPConfig.PostPaths[rand.Intn(len(p.HTTPConfig.PostPaths))]
}

// RandomUserAgent returns a random User-Agent string from the profile.
func (p *C2Profile) RandomUserAgent() string {
	if len(p.HTTPConfig.UserAgents) == 0 {
		return "Go-http-client/2.0"
	}
	return p.HTTPConfig.UserAgents[rand.Intn(len(p.HTTPConfig.UserAgents))]
}

// ComputeJitter returns a jittered duration based on the profile's base and max percentage.
func (p *C2Profile) ComputeJitter() time.Duration {
	base := time.Duration(p.Jitter.BaseMs) * time.Millisecond
	jitter := time.Duration(float64(base) * p.Jitter.MaxPct * rand.Float64())
	if rand.Intn(2) == 0 {
		return base + jitter
	}
	return base - jitter/2
}

// Marshal serializes the profile to JSON.
func (p *C2Profile) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

// Unmarshal deserializes a profile from JSON.
func Unmarshal(data []byte) (*C2Profile, error) {
	var p C2Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshalling C2 profile: %w", err)
	}
	return &p, nil
}

// Validate checks the profile for basic correctness.
func (p *C2Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	if p.Jitter.MaxPct < 0 || p.Jitter.MaxPct > 1.0 {
		return fmt.Errorf("jitter max percentage must be between 0.0 and 1.0")
	}
	if p.Jitter.BaseMs < 0 {
		return fmt.Errorf("jitter base must be non-negative")
	}
	if p.DNSConfig.MaxTXTSize < 0 || p.DNSConfig.MaxTXTSize > 255 {
		return fmt.Errorf("DNS TXT max size must be between 0 and 255")
	}
	return nil
}
