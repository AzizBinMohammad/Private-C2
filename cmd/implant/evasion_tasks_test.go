package main

import (
	"context"
	"runtime"
	"testing"
)

func TestPPIDSpoofValidation(t *testing.T) {
	for _, args := range []string{`not-json`, `{}`, `{"command":"cmd.exe"}`} {
		if _, err := handleEvasionPPIDSpoof(context.Background(), args); err == nil {
			t.Errorf("handleEvasionPPIDSpoof(%q) unexpectedly succeeded", args)
		}
	}
}

func TestEvasionWindowsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	for name, call := range map[string]func() (string, error){
		"amsi": func() (string, error) { return handleEvasionAMSI(context.Background(), "") },
		"etw":  func() (string, error) { return handleEvasionETW(context.Background(), "") },
		"ppid": func() (string, error) {
			return handleEvasionPPIDSpoof(context.Background(), `{"command":"cmd.exe","parent_pid":4}`)
		},
	} {
		if _, err := call(); err == nil {
			t.Errorf("%s unexpectedly succeeded on this platform", name)
		}
	}
}
