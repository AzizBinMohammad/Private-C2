// Package redact removes common secret shapes from text deliverables. It is
// intentionally conservative: it targets well-known credential formats and
// key/value secrets, not general identifiers that an engagement report needs.
package redact

import (
	"bytes"
	"regexp"
	"unicode/utf8"
)

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Private key blocks (PEM and OpenSSH).
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), "[REDACTED PRIVATE KEY]"},
	// AWS access key IDs.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "[REDACTED AWS ACCESS KEY]"},
	// Authorization headers, including the scheme, so the bearer rule below
	// does not leave a stray "Bearer" behind.
	{regexp.MustCompile(`(?i)(\bauthorization:\s*)(?:(?:bearer|basic)\s+)?\S+`), "${1}[REDACTED]"},
	// Bearer tokens without an Authorization header.
	{regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{16,}`), "${1}[REDACTED]"},
	// key=value / key: value secrets in text, JSON, and YAML. Group 1 is the
	// key and separator; group 2 is the value.
	{regexp.MustCompile(`(?i)("?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;]+)`), "${1}[REDACTED]"},
}

// Text applies every rule to s.
func Text(s string) string {
	for _, rule := range rules {
		s = rule.re.ReplaceAllString(s, rule.repl)
	}
	return s
}

// IsText reports whether data is valid UTF-8 without NUL bytes, which is a
// reasonable test for redactable task output and loot.
func IsText(data []byte) bool {
	return utf8.Valid(data) && !bytes.ContainsRune(data, 0)
}

// Bytes redacts data when it is text. Binary data is returned unchanged and
// the second return value reports that no redaction was applied.
func Bytes(data []byte) ([]byte, bool) {
	if !IsText(data) {
		return data, false
	}
	return []byte(Text(string(data))), true
}
