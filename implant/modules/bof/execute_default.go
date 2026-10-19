//go:build !windows

package bof

// Execute is only available on Windows.
func Execute([]byte, []byte) (Result, error) {
	return Result{}, ErrUnsupported
}
