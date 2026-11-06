//go:build !windows

package main

import "os"

// processElevated reports whether the implant is running as root. On the BSDs
// and macOS this is the same effective-uid check as on Linux.
func processElevated() bool {
	return os.Geteuid() == 0
}
