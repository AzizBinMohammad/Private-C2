//go:build windows

package main

import "golang.org/x/sys/windows"

// processElevated reports whether the process token is elevated from a UAC
// perspective, which is what separates an administrator context from a
// filtered one.
func processElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
