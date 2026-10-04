package audit

import (
	"sync"
	"testing"
)

// memWriter is a test Writer that stores entries in memory.
type memWriter struct {
	mu      sync.Mutex
	entries []Entry
}

func (w *memWriter) Write(entry Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = append(w.entries, entry)
	return nil
}

func (w *memWriter) getEntries() []Entry {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Entry, len(w.entries))
	copy(out, w.entries)
	return out
}

func TestHashChaining(t *testing.T) {
	mw := &memWriter{}
	logger := NewLogger(mw)

	for i := 0; i < 5; i++ {
		err := logger.Log("op1", "eng1", "sess1", EventSessionInteract, "action", "target", "ok", nil, "127.0.0.1", "")
		if err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	entries := mw.getEntries()
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}

	for i := 1; i < len(entries); i++ {
		if entries[i].PreviousHash != entries[i-1].EntryHash {
			t.Fatalf("entry %d PreviousHash (%s) != entry %d EntryHash (%s)",
				i, entries[i].PreviousHash, i-1, entries[i-1].EntryHash)
		}
	}
}

func TestFirstEntryEmptyPreviousHash(t *testing.T) {
	mw := &memWriter{}
	logger := NewLogger(mw)

	err := logger.Log("op1", "eng1", "", EventOperatorLogin, "login", "", "ok", nil, "10.0.0.1", "")
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries := mw.getEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].PreviousHash != "" {
		t.Fatalf("first entry PreviousHash should be empty, got %q", entries[0].PreviousHash)
	}

	if entries[0].EntryHash == "" {
		t.Fatal("first entry EntryHash should not be empty")
	}
}

func TestConcurrentWritesSerialized(t *testing.T) {
	mw := &memWriter{}
	logger := NewLogger(mw)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = logger.Log("op1", "eng1", "", EventSessionInteract, "action", "target", "ok", nil, "127.0.0.1", "")
		}()
	}

	wg.Wait()

	entries := mw.getEntries()
	if len(entries) != goroutines {
		t.Fatalf("expected %d entries, got %d", goroutines, len(entries))
	}

	// Verify chain integrity: even with concurrent writes, the mutex
	// should ensure proper hash chaining
	for i := 1; i < len(entries); i++ {
		if entries[i].PreviousHash != entries[i-1].EntryHash {
			t.Fatalf("chain broken at entry %d: PreviousHash=%s, previous EntryHash=%s",
				i, entries[i].PreviousHash, entries[i-1].EntryHash)
		}
	}
}

func TestEntryFieldsPopulated(t *testing.T) {
	mw := &memWriter{}
	logger := NewLogger(mw)

	meta := map[string]any{"key": "value"}
	err := logger.Log("operator", "engagement", "session", EventPayloadGenerate, "generate", "payload.exe", "success", meta, "192.168.1.1", "corr123")
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries := mw.getEntries()
	e := entries[0]

	if e.OperatorID != "operator" {
		t.Errorf("OperatorID = %q, want %q", e.OperatorID, "operator")
	}
	if e.EngagementID != "engagement" {
		t.Errorf("EngagementID = %q, want %q", e.EngagementID, "engagement")
	}
	if e.SessionID != "session" {
		t.Errorf("SessionID = %q, want %q", e.SessionID, "session")
	}
	if e.EventType != EventPayloadGenerate {
		t.Errorf("EventType = %q, want %q", e.EventType, EventPayloadGenerate)
	}
	if e.Action != "generate" {
		t.Errorf("Action = %q, want %q", e.Action, "generate")
	}
	if e.Target != "payload.exe" {
		t.Errorf("Target = %q, want %q", e.Target, "payload.exe")
	}
	if e.SourceIP != "192.168.1.1" {
		t.Errorf("SourceIP = %q, want %q", e.SourceIP, "192.168.1.1")
	}
	if e.CorrelationID != "corr123" {
		t.Errorf("CorrelationID = %q, want %q", e.CorrelationID, "corr123")
	}
	if e.ID == "" {
		t.Error("ID should be set")
	}
	if e.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}
