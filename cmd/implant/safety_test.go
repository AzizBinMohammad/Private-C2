package main

import (
	"context"
	"testing"

	"github.com/azizbinmohammad/private-c2/implant/safety"
	"github.com/azizbinmohammad/private-c2/pkg/engagement"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func TestSplitList(t *testing.T) {
	got := splitList(" 10.0.0.0/8, example.com ,, ")
	if len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "example.com" {
		t.Fatalf("splitList = %#v", got)
	}
	if splitList("   ") != nil {
		t.Fatal("blank list should be nil")
	}
}

func TestBuildSafetyRejectsInvalidConfiguration(t *testing.T) {
	cases := []safetyConfig{
		{KillDate: "not-a-date"},
		{WindowStart: "2026-01-01T00:00:00Z"},
		{WindowEnd: "2026-01-01T00:00:00Z"},
		{WindowStart: "not-a-date", WindowEnd: "2026-01-01T00:00:00Z"},
		{CIDRs: "not-a-cidr"},
	}
	for i, cfg := range cases {
		if _, _, err := buildSafety(cfg); err == nil {
			t.Errorf("case %d: expected an error for %+v", i, cfg)
		}
	}
}

func TestBuildSafetyValidConfiguration(t *testing.T) {
	checker, allowlist, err := buildSafety(safetyConfig{
		EngagementID: "eng-1",
		CIDRs:        "10.0.0.0/8",
		Hosts:        "target.example",
		Domains:      "example.com",
		KillDate:     "2030-01-01T00:00:00Z",
		WindowStart:  "2020-01-01T00:00:00Z",
		WindowEnd:    "2030-01-01T00:00:00Z",
		DataQuota:    1024,
		SafeMode:     true,
	})
	if err != nil {
		t.Fatalf("buildSafety: %v", err)
	}
	if checker == nil || allowlist == nil || !allowlist.IsEnabled() {
		t.Fatalf("checker/allowlist not configured: %v %v", checker, allowlist)
	}
}

func TestTaskTarget(t *testing.T) {
	cases := []struct {
		task protocol.TaskWire
		want string
	}{
		{protocol.TaskWire{Type: protocol.TaskPortscan, Args: "10.0.0.5:22,80"}, "10.0.0.5"},
		{protocol.TaskWire{Type: protocol.TaskResolve, Args: "example.com"}, "example.com"},
		{protocol.TaskWire{Type: protocol.TaskScan, Args: `{"target":"10.0.0.9","profile":"quick"}`}, "10.0.0.9"},
		{protocol.TaskWire{Type: protocol.TaskNmap, Args: "-sV 10.0.0.7"}, "10.0.0.7"},
		{protocol.TaskWire{Type: protocol.TaskShell, Args: "whoami"}, ""},
	}
	for _, tc := range cases {
		if got := taskTarget(tc.task); got != tc.want {
			t.Errorf("taskTarget(%+v) = %q, want %q", tc.task, got, tc.want)
		}
	}
}

func TestCheckTaskSafety_Scope(t *testing.T) {
	scope, err := engagement.NewScope([]string{"10.0.0.0/8"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldSafety, oldAllow := agentSafety, agentAllowlist
	agentSafety = safety.NewSafetyChecker(safety.SafetyConfig{Scope: scope})
	agentAllowlist = nil
	defer func() { agentSafety, agentAllowlist = oldSafety, oldAllow }()

	inScope := protocol.TaskWire{Type: protocol.TaskPortscan, Args: "10.1.2.3:22"}
	if err := checkTaskSafety(context.Background(), inScope); err != nil {
		t.Fatalf("in-scope task refused: %v", err)
	}
	outOfScope := protocol.TaskWire{Type: protocol.TaskPortscan, Args: "192.168.1.1:22"}
	if err := checkTaskSafety(context.Background(), outOfScope); err == nil {
		t.Fatal("out-of-scope task was allowed")
	}
}

func TestCheckTaskSafety_Allowlist(t *testing.T) {
	oldSafety, oldAllow := agentSafety, agentAllowlist
	agentSafety = nil
	agentAllowlist = safety.NewCommandAllowlist()
	agentAllowlist.Enable()
	defer func() { agentSafety, agentAllowlist = oldSafety, oldAllow }()

	if err := checkTaskSafety(context.Background(), protocol.TaskWire{Type: protocol.TaskShell, Args: "whoami"}); err != nil {
		t.Fatalf("allowlisted command refused: %v", err)
	}
	if err := checkTaskSafety(context.Background(), protocol.TaskWire{Type: protocol.TaskShell, Args: "rm -rf /"}); err == nil {
		t.Fatal("non-allowlisted command was allowed")
	}
}
