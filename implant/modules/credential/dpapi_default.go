//go:build !windows

package credential

import "errors"

// ErrDPAPIUnsupported is returned on non-Windows builds.
var ErrDPAPIUnsupported = errors.New("DPAPI decryption requires Windows")

// UnprotectDPAPI is only available on Windows.
func UnprotectDPAPI([]byte, []byte, bool) ([]byte, error) {
	return nil, ErrDPAPIUnsupported
}
