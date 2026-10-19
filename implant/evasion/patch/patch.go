// Package patch applies narrowly scoped in-memory patches used by explicitly
// gated evasion tasks. Execution is Windows-only; other builds report
// ErrUnsupported.
package patch

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupported reports memory patching on a non-Windows build.
var ErrUnsupported = errors.New("memory patching requires Windows")

// Result describes the address and bytes changed by a patch.
type Result struct {
	Name    string `json:"name"`
	Module  string `json:"module"`
	Symbol  string `json:"symbol"`
	Address string `json:"address"`
	Old     string `json:"old_bytes"`
	New     string `json:"new_bytes"`
}

func formatAddress(addr uintptr) string { return fmt.Sprintf("0x%x", addr) }

func validateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("patch name is required")
	}
	return nil
}
