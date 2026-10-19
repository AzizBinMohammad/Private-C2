package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestParseScriptArgs(t *testing.T) {
	if got, err := parseScriptArgs("whoami"); err != nil || got != "whoami" {
		t.Fatalf("raw: %q %v", got, err)
	}
	if got, err := parseScriptArgs(`{"script":"Get-Process"}`); err != nil || got != "Get-Process" {
		t.Fatalf("json script: %q %v", got, err)
	}
	if got, err := parseScriptArgs(`{"code":"print(1)"}`); err != nil || got != "print(1)" {
		t.Fatalf("json code: %q %v", got, err)
	}
	if _, err := parseScriptArgs("  "); err == nil {
		t.Error("empty script unexpectedly succeeded")
	}
}

func TestEncodeUTF16LE(t *testing.T) {
	got := encodeUTF16LE("Ab")
	if len(got) != 4 || got[0] != 'A' || got[1] != 0 || got[2] != 'b' || got[3] != 0 {
		t.Fatalf("encodeUTF16LE = %v", got)
	}
}

func TestAssemblyScriptEscaping(t *testing.T) {
	script := assemblyScript("QUJD", []string{"a", "it's"})
	if !strings.Contains(script, "[Convert]::FromBase64String('QUJD')") {
		t.Fatalf("missing payload: %s", script)
	}
	if !strings.Contains(script, "'it''s'") {
		t.Fatalf("single quote was not escaped: %s", script)
	}
	if !strings.Contains(script, "[string[]]@('a','it''s')") {
		t.Fatalf("arguments were not assembled: %s", script)
	}
}

func TestPowershellAndAssemblyRejectNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("these paths run on Windows")
	}
	if _, err := handlePowershell(context.Background(), "whoami"); err == nil {
		t.Error("powershell unexpectedly succeeded on this platform")
	}
	if _, err := handleExecuteAssembly(context.Background(),
		`{"assembly":"`+base64.StdEncoding.EncodeToString([]byte("MZ"))+`"}`); err == nil {
		t.Error("execute_assembly unexpectedly succeeded on this platform")
	}
}

func TestHandlePython(t *testing.T) {
	out, err := handlePython(context.Background(), "print(2+2)")
	if err != nil {
		t.Skipf("python is not available: %v", err)
	}
	var result scriptResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || strings.TrimSpace(result.Stdout) != "4" {
		t.Fatalf("python result = %+v", result)
	}
}
