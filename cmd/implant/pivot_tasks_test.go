package main

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
)

func TestPivotSocksLifecycle(t *testing.T) {
	out, err := handlePivotSocks(context.Background(), `{"action":"start","listen":"127.0.0.1:0"}`)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	var started struct {
		Listen string `json:"listen"`
		Auth   bool   `json:"auth"`
	}
	if err := json.Unmarshal([]byte(out), &started); err != nil {
		t.Fatal(err)
	}
	if started.Listen == "" || started.Auth {
		t.Fatalf("unexpected start result: %s", out)
	}
	defer handlePivotSocks(context.Background(), `{"action":"stop","listen":"`+started.Listen+`"}`)

	status, err := handlePivotSocks(context.Background(), `{"action":"status"}`)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var listed struct {
		Listeners []string `json:"listeners"`
	}
	if err := json.Unmarshal([]byte(status), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Listeners) != 1 || listed.Listeners[0] != started.Listen {
		t.Fatalf("status = %s", status)
	}

	if _, err := handlePivotSocks(context.Background(),
		`{"action":"stop","listen":"`+started.Listen+`"}`); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestPivotArgsValidation(t *testing.T) {
	cases := []struct {
		handler taskHandler
		args    string
	}{
		{handlePivotSocks, `not-json`},
		{handlePivotSocks, `{"action":"bogus"}`},
		{handlePivotPortfwd, `not-json`},
		{handlePivotPortfwd, `{"action":"start","listen":"127.0.0.1:0"}`},
		{handlePivotPortfwd, `{"action":"stop"}`},
	}
	for _, tc := range cases {
		if _, err := tc.handler(context.Background(), tc.args); err == nil {
			t.Errorf("%q unexpectedly succeeded", tc.args)
		}
	}
}

func TestCredentialDumpWindowsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the unsupported path is not used on Windows")
	}
	if _, err := handleCredentialDump(context.Background(), "lsass"); err == nil {
		t.Error("credential_dump unexpectedly succeeded on this platform")
	}
	if _, err := handleCredentialDump(context.Background(), ""); err == nil {
		t.Error("empty dump kind unexpectedly succeeded")
	}
}

func TestLateralSSHHandlerValidation(t *testing.T) {
	if _, err := handleLateralSSH(context.Background(), `{}`); err == nil {
		t.Error("empty lateral_ssh request unexpectedly succeeded")
	}
	if _, err := handleLateralSSH(context.Background(), `not-json`); err == nil {
		t.Error("invalid lateral_ssh JSON unexpectedly succeeded")
	}
}

func TestWinRMAndWMIRequireWindows(t *testing.T) {
	valid := `{"target":"h","username":"u","password":"p","command":"id"}`
	if runtime.GOOS == "windows" {
		return
	}
	if _, err := handleLateralWinRM(context.Background(), valid); err == nil {
		t.Error("lateral_winrm unexpectedly succeeded on this platform")
	}
	if _, err := handleLateralWMI(context.Background(), valid); err == nil {
		t.Error("lateral_wmi unexpectedly succeeded on this platform")
	}
}

func TestNamedPipeHandlerValidation(t *testing.T) {
	for _, args := range []string{
		`not-json`,
		`{"action":"start"}`,
		`{"action":"start","pipe":"pc2"}`,
		`{"action":"stop"}`,
		`{"action":"bogus"}`,
	} {
		if _, err := handlePivotNamedpipe(context.Background(), args); err == nil {
			t.Errorf("handlePivotNamedpipe(%q) unexpectedly succeeded", args)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := handlePivotNamedpipe(context.Background(),
			`{"action":"start","pipe":"pc2","target":"127.0.0.1:445"}`); err == nil {
			t.Error("named-pipe start unexpectedly succeeded on this platform")
		}
	}
}
