//go:build !windows

package patch

// AMSI is only available on Windows.
func AMSI() (Result, error) { return Result{}, ErrUnsupported }

// ETW is only available on Windows.
func ETW() (Result, error) { return Result{}, ErrUnsupported }
