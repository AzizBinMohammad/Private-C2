package lateral

import (
	"strings"
	"testing"
)

func TestParseWinRMRequest(t *testing.T) {
	req, err := ParseWinRMRequest(`{"target":"10.0.0.9","username":"CORP\\alice","password":"p","command":"whoami"}`)
	if err != nil {
		t.Fatal(err)
	}
	if req.Port != 5985 || req.Target != "10.0.0.9" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if _, err := ParseWMIRequest(`{"target":"h","username":"u","password":"p","command":"id","port":0}`); err != nil {
		t.Fatalf("wmi parse: %v", err)
	}
	for _, bad := range []string{
		``, `x`,
		`{"username":"u","password":"p","command":"c"}`,
		`{"target":"t","password":"p","command":"c"}`,
		`{"target":"t","username":"u","command":"c"}`,
		`{"target":"t","username":"u","password":"p"}`,
		`{"target":"t","username":"u","password":"p","command":"c","port":70000}`,
	} {
		if _, err := ParseWinRMRequest(bad); err == nil {
			t.Errorf("ParseWinRMRequest(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestWinRMScriptEscaping(t *testing.T) {
	script := WinRMScript(WinRMRequest{
		Target: "host", Username: `CORP\o'brien`, Password: "pa'ss",
		Command: "Get-Process | Where-Object { $_.Name -eq 'x' }", Port: 5986, UseSSL: true,
	})
	for _, want := range []string{
		`'CORP\o''brien'`, `'pa''ss'`, `-Port 5986`, `-UseSSL`,
		`[ScriptBlock]::Create('Get-Process | Where-Object { $_.Name -eq ''x'' }')`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
}

func TestWMIScript(t *testing.T) {
	script := WMIScript(WinRMRequest{
		Target: "host", Username: "u", Password: "p", Command: `cmd.exe /c whoami`,
	})
	if !strings.Contains(script, `-ArgumentList 'cmd.exe /c whoami'`) ||
		!strings.Contains(script, `-Class Win32_Process -Name Create`) {
		t.Fatalf("unexpected WMI script:\n%s", script)
	}
}
