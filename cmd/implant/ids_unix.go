//go:build !windows

package main

import "os"

func getuid() (int, error) { return os.Getuid(), nil }
func getgid() (int, error) { return os.Getgid(), nil }
