//go:build !windows

package spawn

// SpoofParent is only available on Windows.
func SpoofParent(string, uint32) (Result, error) { return Result{}, ErrUnsupported }
