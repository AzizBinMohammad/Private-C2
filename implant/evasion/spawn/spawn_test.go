//go:build !windows

package spawn

import (
	"errors"
	"testing"
)

func TestSpoofParentUnsupported(t *testing.T) {
	if _, err := SpoofParent("cmd.exe", 4); !errors.Is(err, ErrUnsupported) {
		t.Errorf("SpoofParent error = %v", err)
	}
}
