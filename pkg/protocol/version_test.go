package protocol

import (
	"encoding/json"
	"testing"
)

func TestNegotiate(t *testing.T) {
	cases := []struct {
		client int
		want   int
	}{
		{0, Version1},
		{-1, Version1},
		{Version1, Version1},
		{Version2, Version2},
		{99, CurrentVersion},
	}
	for _, tc := range cases {
		if got := Negotiate(tc.client); got != tc.want {
			t.Errorf("Negotiate(%d) = %d, want %d", tc.client, got, tc.want)
		}
	}
}

func TestHasCapability(t *testing.T) {
	caps := []string{CapabilityKill, CapabilityTaskStarted}
	if !HasCapability(caps, CapabilityKill) {
		t.Fatal("expected kill capability")
	}
	if HasCapability(caps, CapabilitySessionToken) {
		t.Fatal("did not expect session_token capability")
	}
	if HasCapability(nil, CapabilityKill) {
		t.Fatal("nil capabilities must not match")
	}
}

func TestImplementedTaskTypes(t *testing.T) {
	types := ImplementedTaskTypes()
	if len(types) != len(implementedTaskTypes) {
		t.Fatalf("got %d types, want %d", len(types), len(implementedTaskTypes))
	}
	for _, want := range []string{
		TaskShell, TaskScan, TaskPortscan, TaskResolve, TaskKill,
		TaskMkdir, TaskRm, TaskCp, TaskMv, TaskNetstat, TaskIfconfig,
		TaskWhoami, TaskOTDiscover, TaskOTFingerprint, TaskOTPLCRead,
		TaskCredentialEnum, TaskCredentialRead,
		TaskProcessInfo, TaskProcessSuspend, TaskProcessResume,
		TaskTokenList, TaskTokenSteal, TaskTokenMake, TaskTokenImpersonate,
		TaskTokenRevert, TaskGetprivs,
	} {
		if !IsImplementedTaskType(want) {
			t.Errorf("task type %q is not registered", want)
		}
	}
	if IsImplementedTaskType("does-not-exist") {
		t.Fatal("unknown task type unexpectedly registered")
	}

	// Callers must not be able to mutate the package registry.
	types[0] = "mutated"
	if ImplementedTaskTypes()[0] == "mutated" {
		t.Fatal("ImplementedTaskTypes returned the backing slice")
	}
}

func TestLegacyRegisterJSONStillDecodes(t *testing.T) {
	// A v1 implant sends only the original fields. The new fields must remain
	// zero-valued so the server can treat it as a legacy peer.
	raw := []byte(`{"type":"register","data":{"implant_id":"abc","hostname":"h","username":"u","os":"linux","arch":"amd64","pid":1,"process":"p","mode":"beacon"}}`)
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.Type != "register" {
		t.Fatalf("type = %q", msg.Type)
	}
	var reg RegisterData
	if err := json.Unmarshal(msg.Data, &reg); err != nil {
		t.Fatalf("unmarshal register: %v", err)
	}
	if reg.ProtocolVersion != 0 || reg.EngagementID != "" || len(reg.Capabilities) != 0 {
		t.Fatalf("legacy register gained v2 values: %+v", reg)
	}
	if reg.ImplantID != "abc" || reg.Hostname != "h" {
		t.Fatalf("legacy fields lost: %+v", reg)
	}
}

func TestV2RegisterRoundTrip(t *testing.T) {
	in := RegisterData{
		ImplantID:       "abc",
		Hostname:        "h",
		ProtocolVersion: Version2,
		Capabilities:    []string{CapabilityKill},
		EngagementID:    "eng-1",
		SleepMs:         5000,
		JitterPct:       20,
		Transports:      []string{"mtls", "https"},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out RegisterData
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ProtocolVersion != Version2 || out.EngagementID != "eng-1" ||
		len(out.Transports) != 2 || out.Capabilities[0] != CapabilityKill {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestCategoryFor(t *testing.T) {
	cases := map[string]TaskCategory{
		TaskShell:            CategoryGeneral,
		TaskOTDiscover:       CategoryOT,
		TaskOTFingerprint:    CategoryOT,
		TaskOTCredentials:    CategoryCredential,
		"credential_dump":    CategoryCredential,
		"lateral_psexec":     CategoryLateral,
		"persist_systemd":    CategoryPersistence,
		"evasion_sleep":      CategoryEvasion,
		TaskTokenList:        CategoryPrivilege,
		TaskTokenSteal:       CategoryPrivilege,
		TaskTokenImpersonate: CategoryPrivilege,
		TaskProcessSuspend:   CategoryPrivilege,
		TaskProcessResume:    CategoryPrivilege,
		TaskGetprivs:         CategoryPrivilege,
		TaskProcessInfo:      CategoryGeneral,
		TaskCredentialEnum:   CategoryCredential,
		TaskCredentialRead:   CategoryCredential,
	}
	for taskType, want := range cases {
		if got := CategoryFor(taskType); got != want {
			t.Errorf("CategoryFor(%q) = %q, want %q", taskType, got, want)
		}
	}
}

func TestUnknownJSONFieldsAreIgnored(t *testing.T) {
	raw := []byte(`{"session_id":"s","interval":5000,"future_field":"ignored"}`)
	var ack RegisterAckData
	if err := json.Unmarshal(raw, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.SessionID != "s" || ack.Interval != 5000 {
		t.Fatalf("known fields lost: %+v", ack)
	}
}
