package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleEntries() []Entry {
	return []Entry{
		{
			ID:            "entry-001",
			Timestamp:     time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			OperatorID:    "operator1",
			EngagementID:  "eng-001",
			SessionID:     "sess-001",
			EventType:     EventSessionInteract,
			Action:        "shell command",
			Target:        "10.0.0.5",
			ResultSummary: "command executed",
			SourceIP:      "192.168.1.10",
			PreviousHash:  "",
			EntryHash:     "abc123",
		},
		{
			ID:            "entry-002",
			Timestamp:     time.Date(2024, 1, 15, 10, 31, 0, 0, time.UTC),
			OperatorID:    "operator1",
			EngagementID:  "eng-001",
			SessionID:     "sess-001",
			EventType:     EventKillSwitch,
			Action:        "kill switch activated",
			Target:        "",
			ResultSummary: "engagement halted",
			SourceIP:      "192.168.1.10",
			PreviousHash:  "abc123",
			EntryHash:     "def456",
		},
	}
}

func TestExportJSON(t *testing.T) {
	entries := sampleEntries()
	var buf bytes.Buffer

	if err := Export(&buf, entries, FormatJSON); err != nil {
		t.Fatalf("Export JSON: %v", err)
	}

	// Validate that output is valid JSON
	var parsed []Entry
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid: %v\nOutput: %s", err, buf.String())
	}

	if len(parsed) != len(entries) {
		t.Fatalf("expected %d entries in JSON, got %d", len(entries), len(parsed))
	}

	if parsed[0].ID != "entry-001" {
		t.Errorf("first entry ID = %q, want %q", parsed[0].ID, "entry-001")
	}
}

func TestExportCEF(t *testing.T) {
	entries := sampleEntries()
	var buf bytes.Buffer

	if err := Export(&buf, entries, FormatCEF); err != nil {
		t.Fatalf("Export CEF: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != len(entries) {
		t.Fatalf("expected %d CEF lines, got %d", len(entries), len(lines))
	}

	// Each CEF line should start with "CEF:0|"
	for i, line := range lines {
		if !strings.HasPrefix(line, "CEF:0|") {
			t.Errorf("line %d should start with 'CEF:0|', got %q", i, line)
		}
	}

	// Check that the vendor/product fields are present
	if !strings.Contains(lines[0], "PrivateC2") {
		t.Error("CEF line should contain vendor name PrivateC2")
	}

	// Check that source IP is present
	if !strings.Contains(lines[0], "src=192.168.1.10") {
		t.Error("CEF line should contain source IP")
	}
}

func TestExportLEEF(t *testing.T) {
	entries := sampleEntries()
	var buf bytes.Buffer

	if err := Export(&buf, entries, FormatLEEF); err != nil {
		t.Fatalf("Export LEEF: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != len(entries) {
		t.Fatalf("expected %d LEEF lines, got %d", len(entries), len(lines))
	}

	// Each LEEF line should start with "LEEF:2.0|"
	for i, line := range lines {
		if !strings.HasPrefix(line, "LEEF:2.0|") {
			t.Errorf("line %d should start with 'LEEF:2.0|', got %q", i, line)
		}
	}

	if !strings.Contains(lines[0], "PrivateC2") {
		t.Error("LEEF line should contain vendor name PrivateC2")
	}
}

func TestExportUnsupportedFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Export(&buf, sampleEntries(), ExportFormat("xml"))
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestExportEmptyEntries(t *testing.T) {
	var buf bytes.Buffer

	if err := Export(&buf, []Entry{}, FormatJSON); err != nil {
		t.Fatalf("Export empty JSON: %v", err)
	}

	// Should produce valid JSON (an empty array)
	var parsed []Entry
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("empty JSON not valid: %v", err)
	}
}
