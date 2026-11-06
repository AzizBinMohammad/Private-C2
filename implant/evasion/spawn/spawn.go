// Package spawn creates processes with a spoofed parent. It is Windows-only
// and gated by the engagement's evasion capability.
package spawn

import "errors"

// ErrUnsupported reports spoofed process creation on a non-Windows build.
var ErrUnsupported = errors.New("parent-PID spoofing requires Windows")

// Result describes the created process.
type Result struct {
	PID       uint32 `json:"pid"`
	ParentPID uint32 `json:"parent_pid"`
	Command   string `json:"command"`
}
