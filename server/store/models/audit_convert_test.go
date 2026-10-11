package models

import (
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
)

func TestAuditEntryFromLib_RoundTrip(t *testing.T) {
	ts := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)

	lib := audit.Entry{
		ID:            "entry-001",
		Timestamp:     ts,
		OperatorID:    "op-1",
		EngagementID:  "eng-1",
		SessionID:     "sess-1",
		EventType:     audit.EventSessionInteract,
		Action:        "shell",
		Target:        "10.0.0.5",
		ResultSummary: "success",
		Metadata:      map[string]any{"cmd": "whoami", "exit_code": float64(0)},
		SourceIP:      "192.168.1.10",
		CorrelationID: "corr-1",
		PreviousHash:  "aabbccdd",
		EntryHash:     "11223344",
	}

	model := AuditEntryFromLib(lib)

	if model.ID != lib.ID {
		t.Errorf("ID: got %q, want %q", model.ID, lib.ID)
	}
	if !model.CreatedAt.Equal(lib.Timestamp) {
		t.Errorf("CreatedAt: got %v, want %v", model.CreatedAt, lib.Timestamp)
	}
	if model.OperatorID != lib.OperatorID {
		t.Errorf("OperatorID: got %q, want %q", model.OperatorID, lib.OperatorID)
	}
	if model.EngagementID != lib.EngagementID {
		t.Errorf("EngagementID: got %q, want %q", model.EngagementID, lib.EngagementID)
	}
	if model.SessionID != lib.SessionID {
		t.Errorf("SessionID: got %q, want %q", model.SessionID, lib.SessionID)
	}
	if model.EventType != string(lib.EventType) {
		t.Errorf("EventType: got %q, want %q", model.EventType, string(lib.EventType))
	}
	if model.Action != lib.Action {
		t.Errorf("Action: got %q, want %q", model.Action, lib.Action)
	}
	if model.Target != lib.Target {
		t.Errorf("Target: got %q, want %q", model.Target, lib.Target)
	}
	if model.ResultSummary != lib.ResultSummary {
		t.Errorf("ResultSummary: got %q, want %q", model.ResultSummary, lib.ResultSummary)
	}
	if model.SourceIP != lib.SourceIP {
		t.Errorf("SourceIP: got %q, want %q", model.SourceIP, lib.SourceIP)
	}
	if model.CorrelationID != lib.CorrelationID {
		t.Errorf("CorrelationID: got %q, want %q", model.CorrelationID, lib.CorrelationID)
	}
	if model.PreviousHash != lib.PreviousHash {
		t.Errorf("PreviousHash: got %q, want %q", model.PreviousHash, lib.PreviousHash)
	}
	if model.EntryHash != lib.EntryHash {
		t.Errorf("EntryHash: got %q, want %q", model.EntryHash, lib.EntryHash)
	}
	if model.Metadata != `{"cmd":"whoami","exit_code":0}` {
		t.Errorf("Metadata: got %q", model.Metadata)
	}

	back, err := AuditEntryToLib(model)
	if err != nil {
		t.Fatalf("AuditEntryToLib: %v", err)
	}
	if back.ID != lib.ID {
		t.Errorf("round-trip ID: got %q, want %q", back.ID, lib.ID)
	}
	if !back.Timestamp.Equal(lib.Timestamp) {
		t.Errorf("round-trip Timestamp: got %v, want %v", back.Timestamp, lib.Timestamp)
	}
	if back.EventType != lib.EventType {
		t.Errorf("round-trip EventType: got %q, want %q", back.EventType, lib.EventType)
	}
	if back.Action != lib.Action {
		t.Errorf("round-trip Action: got %q, want %q", back.Action, lib.Action)
	}
	if back.Metadata == nil {
		t.Fatal("round-trip Metadata is nil")
	}
	if back.Metadata["cmd"] != "whoami" {
		t.Errorf("round-trip Metadata[cmd]: got %v", back.Metadata["cmd"])
	}
	if back.Metadata["exit_code"] != float64(0) {
		t.Errorf("round-trip Metadata[exit_code]: got %v (type %T)", back.Metadata["exit_code"], back.Metadata["exit_code"])
	}
}

func TestMetadata_NilMap(t *testing.T) {
	lib := audit.Entry{
		ID:        "entry-nil",
		Timestamp: time.Now().UTC(),
		Metadata:  nil,
	}

	model := AuditEntryFromLib(lib)
	if model.Metadata != "" {
		t.Errorf("nil map should produce empty string, got %q", model.Metadata)
	}

	back, err := AuditEntryToLib(model)
	if err != nil {
		t.Fatalf("AuditEntryToLib: %v", err)
	}
	if back.Metadata != nil {
		t.Errorf("empty string should produce nil map, got %v", back.Metadata)
	}
}

func TestMetadata_EmptyMap(t *testing.T) {
	lib := audit.Entry{
		ID:        "entry-empty",
		Timestamp: time.Now().UTC(),
		Metadata:  map[string]any{},
	}

	model := AuditEntryFromLib(lib)
	if model.Metadata != "{}" {
		t.Errorf("empty map should produce %q, got %q", "{}", model.Metadata)
	}

	back, err := AuditEntryToLib(model)
	if err != nil {
		t.Fatalf("AuditEntryToLib: %v", err)
	}
	if back.Metadata == nil {
		t.Fatal("ToLib of \"{}\" should produce non-nil empty map, got nil")
	}
	if len(back.Metadata) != 0 {
		t.Errorf("ToLib of \"{}\" should produce empty map, got %v", back.Metadata)
	}
}

func TestMetadata_InvalidJSON(t *testing.T) {
	model := AuditEntry{
		ID:       "entry-bad",
		Metadata: "not valid json",
	}
	_, err := AuditEntryToLib(model)
	if err == nil {
		t.Fatal("expected error for invalid JSON metadata")
	}
}

func TestEventType_UnknownValue(t *testing.T) {
	unknown := "custom.unknown.event.type"

	lib := audit.Entry{
		ID:        "entry-unknown-evt",
		Timestamp: time.Now().UTC(),
		EventType: audit.EventType(unknown),
	}

	model := AuditEntryFromLib(lib)
	if model.EventType != unknown {
		t.Errorf("EventType: got %q, want %q", model.EventType, unknown)
	}

	back, err := AuditEntryToLib(model)
	if err != nil {
		t.Fatalf("AuditEntryToLib: %v", err)
	}
	if string(back.EventType) != unknown {
		t.Errorf("round-trip EventType: got %q, want %q", back.EventType, unknown)
	}
}
