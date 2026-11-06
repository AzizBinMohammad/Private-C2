package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func TestParseTargets(t *testing.T) {
	cases := []struct {
		args string
		want []string
	}{
		{`{"targets":["10.0.0.1","10.0.0.2"]}`, []string{"10.0.0.1", "10.0.0.2"}},
		{`["10.0.0.1","10.0.0.2"]`, []string{"10.0.0.1", "10.0.0.2"}},
		{"10.0.0.1, 10.0.0.2\n10.0.0.3", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"10.0.0.1", []string{"10.0.0.1"}},
		{"", nil},
	}
	for _, tc := range cases {
		if got := parseTargets(tc.args); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseTargets(%q) = %#v, want %#v", tc.args, got, tc.want)
		}
	}
}

func TestOTHandlersRequireScope(t *testing.T) {
	old := agentOT
	agentOT = nil
	defer func() { agentOT = old }()

	if _, err := handleOTDiscover(context.Background(), "10.0.0.1"); err == nil || !strings.Contains(err.Error(), "engagement scope") {
		t.Fatalf("ot_discover without scope error = %v", err)
	}
	if _, err := handleOTFingerprint(context.Background(), "10.0.0.1"); err == nil || !strings.Contains(err.Error(), "engagement scope") {
		t.Fatalf("ot_fingerprint without scope error = %v", err)
	}

	if err := checkTaskSafety(context.Background(), protocol.TaskWire{Type: protocol.TaskOTDiscover}); err == nil {
		t.Fatal("checkTaskSafety allowed OT without a scope")
	}
}

func TestOTHandlersRejectEmptyTarget(t *testing.T) {
	if _, err := handleOTFingerprint(context.Background(), "  "); err == nil {
		t.Fatal("ot_fingerprint accepted an empty target")
	}
	if _, err := handleOTPLCRead(context.Background(), `{}`); err == nil {
		t.Fatal("ot_plc_read accepted an empty target")
	}
}
