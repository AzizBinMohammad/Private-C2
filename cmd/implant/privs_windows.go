//go:build windows

package main

// platformPrivileges returns the current process token's privileges on Windows.
func platformPrivileges() (any, error) {
	return tokenManager.Privileges()
}
