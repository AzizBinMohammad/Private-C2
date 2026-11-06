//go:build !windows

package token

import (
	"errors"
	"testing"
)

func TestUnsupportedManager(t *testing.T) {
	m := NewManager()
	if _, err := m.List(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("List error = %v, want ErrUnsupported", err)
	}
	if _, err := m.Steal(1); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Steal error = %v, want ErrUnsupported", err)
	}
	if _, err := m.Make("u", "p", "", ""); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Make error = %v, want ErrUnsupported", err)
	}
	if _, err := m.Impersonate("t1"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Impersonate error = %v, want ErrUnsupported", err)
	}
	if _, err := m.Revert(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Revert error = %v, want ErrUnsupported", err)
	}
	if _, err := m.Privileges(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Privileges error = %v, want ErrUnsupported", err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("Close error = %v", err)
	}
}
