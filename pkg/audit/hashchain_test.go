package audit

import (
	"testing"
)

func TestRecomputeHash_MatchesStored(t *testing.T) {
	mw := &memWriter{}
	logger := NewLogger(mw)

	for i := 0; i < 3; i++ {
		if err := logger.Log("op1", "eng1", "", EventSessionInteract, "action", "target", "ok", nil, "127.0.0.1", ""); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	entries := mw.getEntries()
	for i, e := range entries {
		recomputed := computeHash(e)
		if recomputed != e.EntryHash {
			t.Errorf("entry %d: recomputed hash %q != stored hash %q", i, recomputed, e.EntryHash)
		}
	}
}

func TestTamperMiddleEntry_BreaksChain(t *testing.T) {
	mw := &memWriter{}
	logger := NewLogger(mw)

	for i := 0; i < 5; i++ {
		if err := logger.Log("op1", "eng1", "", EventSessionInteract, "action", "target", "ok", nil, "127.0.0.1", ""); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	entries := mw.getEntries()

	// Tamper with entry 2's action field.
	entries[2].Action = "TAMPERED"

	// Recomputing entry 2's hash should no longer match the stored hash.
	recomputed := computeHash(entries[2])
	if recomputed == entries[2].EntryHash {
		t.Fatal("tampered entry hash should differ from stored hash")
	}

	// Entry 3's PreviousHash still points to the original entry 2 hash,
	// which is correct, but entry 2's stored hash no longer matches its content.
	if entries[3].PreviousHash != entries[2].EntryHash {
		t.Fatal("entry 3 PreviousHash should still point to entry 2's original hash")
	}
}

func TestDeleteEntry_BreaksChain(t *testing.T) {
	mw := &memWriter{}
	logger := NewLogger(mw)

	for i := 0; i < 5; i++ {
		if err := logger.Log("op1", "eng1", "", EventSessionInteract, "action", "target", "ok", nil, "127.0.0.1", ""); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	entries := mw.getEntries()

	// Delete entry 2 (splice it out).
	shortened := append(entries[:2], entries[3:]...)

	// Entry at index 2 (originally entry 3) should have PreviousHash
	// pointing to entry 2 (now deleted), not entry 1.
	if shortened[2].PreviousHash == shortened[1].EntryHash {
		t.Fatal("after deleting entry 2, chain should be broken: entry 3's PreviousHash should not match entry 1's EntryHash")
	}
}

func TestEmptyLog_Valid(t *testing.T) {
	mw := &memWriter{}
	_ = NewLogger(mw)

	entries := mw.getEntries()
	if len(entries) != 0 {
		t.Fatalf("empty log should have 0 entries, got %d", len(entries))
	}
}

func TestMultipleWriters(t *testing.T) {
	mw1 := &memWriter{}
	mw2 := &memWriter{}
	logger := NewLogger(mw1, mw2)

	if err := logger.Log("op1", "eng1", "", EventOperatorLogin, "login", "", "ok", nil, "10.0.0.1", ""); err != nil {
		t.Fatalf("Log: %v", err)
	}

	if len(mw1.getEntries()) != 1 {
		t.Errorf("writer 1 got %d entries, want 1", len(mw1.getEntries()))
	}
	if len(mw2.getEntries()) != 1 {
		t.Errorf("writer 2 got %d entries, want 1", len(mw2.getEntries()))
	}

	// Both should have identical entries.
	if mw1.getEntries()[0].EntryHash != mw2.getEntries()[0].EntryHash {
		t.Error("both writers should receive the same entry")
	}
}
