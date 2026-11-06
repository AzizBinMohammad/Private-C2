//go:build !windows

package patch

import (
	"errors"
	"testing"
)

func TestPatchUnsupported(t *testing.T) {
	if _, err := AMSI(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("AMSI error = %v", err)
	}
	if _, err := ETW(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ETW error = %v", err)
	}
}
