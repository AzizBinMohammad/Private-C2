package build

import (
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/platform"
)

// BuildConfig holds all parameters needed to produce an implant binary.
type BuildConfig struct {
	TargetOS     string        `json:"target_os"`
	TargetArch   string        `json:"target_arch"`
	Mode         string        `json:"mode"`          // session, beacon
	Transports   []string      `json:"transports"`    // mtls, https, dns, wireguard
	Features     []string      `json:"features"`      // shell, filesystem, process, network, screenshot
	Evasion      bool          `json:"evasion"`
	SafeMode     bool          `json:"safe_mode"`
	Debug        bool          `json:"debug"`
	C2Servers    []string      `json:"c2_servers"`
	Interval     time.Duration `json:"interval"`
	Jitter       float64       `json:"jitter"`
	KillDate     *time.Time    `json:"kill_date,omitempty"`
	ImplantID    string        `json:"implant_id"`
	OutputFormat string        `json:"output_format"` // exe, dll, shellcode, shared
}

// Validate checks the build configuration against the platform support matrix
// and returns all validation errors and warnings.
func (c *BuildConfig) Validate() error {
	if c.TargetOS == "" {
		return fmt.Errorf("target_os is required")
	}
	if c.TargetArch == "" {
		return fmt.Errorf("target_arch is required")
	}
	if c.Mode == "" {
		return fmt.Errorf("mode is required")
	}
	if len(c.C2Servers) == 0 {
		return fmt.Errorf("at least one C2 server address is required")
	}
	if c.OutputFormat == "" {
		c.OutputFormat = "exe"
	}

	validFormats := map[string]bool{"exe": true, "dll": true, "shellcode": true, "shared": true, "ps1": true, "sh": true}
	if !validFormats[c.OutputFormat] {
		return fmt.Errorf("unsupported output format %q: must be exe, dll, shellcode, shared, ps1, or sh", c.OutputFormat)
	}

	if c.Jitter < 0 || c.Jitter > 1.0 {
		return fmt.Errorf("jitter must be between 0 and 1.0, got %f", c.Jitter)
	}

	if c.KillDate != nil && c.KillDate.Before(time.Now()) {
		return fmt.Errorf("kill_date must be in the future")
	}

	result := platform.ValidatePayloadConfig(c.TargetOS, c.TargetArch, c.Mode, c.Transports, c.Features)
	if !result.Valid {
		if len(result.Errors) > 0 {
			return fmt.Errorf("platform validation failed: %s", result.Errors[0].Message)
		}
		return fmt.Errorf("platform validation failed for %s/%s", c.TargetOS, c.TargetArch)
	}

	return nil
}

// BuildTags returns the Go build tags derived from this configuration.
func (c *BuildConfig) BuildTags() []string {
	var tags []string

	for _, t := range c.Transports {
		tags = append(tags, "transport_"+t)
	}

	for _, f := range c.Features {
		tags = append(tags, "feature_"+f)
	}

	if c.Evasion {
		tags = append(tags, "evasion")
	}

	if c.SafeMode {
		tags = append(tags, "safemode")
	}

	if c.Debug {
		tags = append(tags, "debug")
	}

	return tags
}
