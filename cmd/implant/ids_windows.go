//go:build windows

package main

import "fmt"

func getuid() (int, error) {
	return 0, fmt.Errorf("numeric uid is not available on Windows; use whoami")
}

func getgid() (int, error) {
	return 0, fmt.Errorf("numeric gid is not available on Windows")
}
