package core

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

// ---- regular expressions for validation ----

var (
	// uuidRE matches the canonical UUID format (8-4-4-4-12 hex digits).
	uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// nameRE allows alphanumeric characters, hyphens and underscores.
	nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
)

// MaxNameLength is the upper bound on names (operator names, engagement
// names, listener names, etc.).
const MaxNameLength = 128

// ---- ValidateID ----

// ValidateID checks that id is a well-formed UUID (v4 hex format).
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("id must not be empty")
	}
	if !uuidRE.MatchString(id) {
		return fmt.Errorf("id %q is not a valid UUID", id)
	}
	return nil
}

// ---- ValidateName ----

// ValidateName checks that name contains only alphanumeric characters,
// hyphens or underscores, starts with an alphanumeric character, and
// does not exceed MaxNameLength.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if len(name) > MaxNameLength {
		return fmt.Errorf("name exceeds maximum length of %d characters", MaxNameLength)
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("name %q contains invalid characters; allowed: a-z, A-Z, 0-9, hyphen, underscore (must start with alphanumeric)", name)
	}
	return nil
}

// ---- SanitizePath ----

// SanitizePath cleans a file path and rejects any path that attempts a
// directory traversal (contains ".." components) or is absolute. The
// returned path is the cleaned, relative form suitable for use as a
// suffix in a file-system sandbox.
func SanitizePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path must not be empty")
	}

	cleaned := filepath.Clean(p)

	// Reject absolute paths.
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute paths are not allowed: %q", p)
	}

	// Reject traversal attempts.
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal is not allowed: %q", p)
	}

	// Also reject if any component is ".." after cleaning (handles
	// cases like "a/../../b").
	for _, part := range strings.Split(cleaned, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("path traversal is not allowed: %q", p)
		}
	}

	return cleaned, nil
}

// ---- ValidateIP ----

// ValidateIP checks that addr is a valid IPv4 or IPv6 address.
func ValidateIP(addr string) error {
	if addr == "" {
		return fmt.Errorf("IP address must not be empty")
	}
	if net.ParseIP(addr) == nil {
		return fmt.Errorf("%q is not a valid IP address", addr)
	}
	return nil
}

// ---- ValidateCIDR ----

// ValidateCIDR checks that cidr is a valid CIDR notation string
// (e.g. "10.0.0.0/8" or "fd00::/64").
func ValidateCIDR(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("CIDR must not be empty")
	}
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return nil
}

// ---- ValidatePort ----

// ValidatePort checks that port is in the range 1-65535.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is out of valid range 1-65535", port)
	}
	return nil
}

// ---- ValidateTransport ----

// allowedTransports enumerates the transport names the framework
// supports.
var allowedTransports = map[string]bool{
	"mtls":  true,
	"https": true,
	"dns":   true,
	"smb":   true,
}

// ValidateTransport checks that transport is one of the supported
// transport protocol names.
func ValidateTransport(transport string) error {
	if transport == "" {
		return fmt.Errorf("transport must not be empty")
	}
	if !allowedTransports[strings.ToLower(transport)] {
		return fmt.Errorf("unsupported transport %q", transport)
	}
	return nil
}
