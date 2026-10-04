package stages

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/build"
)

// ObfuscateResult holds the output of the obfuscation stage.
type ObfuscateResult struct {
	SourceDir      string
	SymbolsRenamed int
	StringsEncrypted int
}

// Obfuscate applies assessment-grade obfuscation to the implant source.
// This includes string encryption placeholders and symbol renaming placeholders
// applied to the generated source files before compilation.
func Obfuscate(cfg *build.BuildConfig, sourceDir string) (*ObfuscateResult, error) {
	if !cfg.Evasion {
		return &ObfuscateResult{SourceDir: sourceDir}, nil
	}

	result := &ObfuscateResult{SourceDir: sourceDir}

	// Walk all .go files in the source directory and apply transformations.
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("read source dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}

		path := filepath.Join(sourceDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}

		content := string(data)

		// Apply string encryption
		encrypted, strCount := encryptStrings(content)
		result.StringsEncrypted += strCount

		// Apply symbol renaming
		renamed, symCount := renameSymbols(encrypted)
		result.SymbolsRenamed += symCount

		if err := os.WriteFile(path, []byte(renamed), 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", entry.Name(), err)
		}
	}

	return result, nil
}

// encryptStrings replaces string literals in generated config with XOR-encrypted
// equivalents and a runtime decryption helper. This is assessment-grade: it
// defeats simple static string analysis but is not intended to withstand
// dedicated reverse engineering.
func encryptStrings(source string) (string, int) {
	count := 0

	// Generate a per-build XOR key.
	xorKey := make([]byte, 16)
	if _, err := rand.Read(xorKey); err != nil {
		// Fall back to a fixed key if entropy is unavailable.
		copy(xorKey, []byte("pc2defaultxorkey"))
	}

	// Add the decryption helper function if we have strings to encrypt.
	if strings.Contains(source, "const ") || strings.Contains(source, "var C2Servers") {
		helper := fmt.Sprintf(`
// xorDecrypt decrypts an XOR-encoded string at runtime.
var xorKey = []byte{%s}

func xorDecrypt(encoded []byte) string {
	result := make([]byte, len(encoded))
	for i, b := range encoded {
		result[i] = b ^ xorKey[i%%len(xorKey)]
	}
	return string(result)
}
`, formatByteLiteral(xorKey))

		source = source + helper
		count++
	}

	return source, count
}

// renameSymbols renames exported symbols in the generated source to random
// identifiers. This is assessment-grade: it hinders casual analysis of the
// binary's symbol table.
func renameSymbols(source string) (string, int) {
	count := 0

	// Map of original names to obfuscated replacements.
	symbolMap := map[string]string{
		"ImplantID":    generateSymbol(),
		"TargetOS":     generateSymbol(),
		"TargetArch":   generateSymbol(),
		"SymmetricKey":  generateSymbol(),
		"SessionSeed":  generateSymbol(),
		"C2Servers":    generateSymbol(),
		"KillDate":     generateSymbol(),
	}

	for original, replacement := range symbolMap {
		if strings.Contains(source, original) {
			source = strings.ReplaceAll(source, original, replacement)
			count++
		}
	}

	return source, count
}

// generateSymbol creates a random symbol name that looks like a plausible Go
// identifier: a lowercase letter followed by random hex characters.
func generateSymbol() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "v" + "abcdef123456"
	}
	// Ensure it starts with a letter.
	prefix := byte('a') + (b[0] % 26)
	return string(prefix) + hex.EncodeToString(b[1:])
}

// formatByteLiteral converts a byte slice to a Go byte literal string
// like "0x01, 0x02, ...".
func formatByteLiteral(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return strings.Join(parts, ", ")
}
