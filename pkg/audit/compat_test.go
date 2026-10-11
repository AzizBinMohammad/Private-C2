package audit

import (
	"fmt"
	"testing"
	"time"
)

func TestHashAlgorithm_LibraryAndAPI_Match(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	entry := Entry{
		ID:           "test-entry-001",
		Timestamp:    ts,
		OperatorID:   "operator-1",
		EventType:    EventSessionInteract,
		Action:       "shell_exec",
		PreviousHash: "",
	}

	internalHash := computeHash(entry)
	exportedHash := ComputeHash(entry.ID, entry.Timestamp, entry.OperatorID, entry.EventType, entry.Action, entry.PreviousHash)

	if internalHash != exportedHash {
		t.Fatalf("internal computeHash and exported ComputeHash must produce identical results\n  internal: %s\n  exported: %s", internalHash, exportedHash)
	}
}

func TestHashAlgorithm_FieldSensitivity(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("changes_with_operator_id", func(t *testing.T) {
		h1 := ComputeHash("id", ts, "op1", EventSessionInteract, "action", "")
		h2 := ComputeHash("id", ts, "op2", EventSessionInteract, "action", "")
		if h1 == h2 {
			t.Fatal("hash must change when operator_id changes")
		}
	})

	t.Run("changes_with_event_type", func(t *testing.T) {
		h1 := ComputeHash("id", ts, "op1", EventSessionInteract, "action", "")
		h2 := ComputeHash("id", ts, "op1", EventOperatorLogin, "action", "")
		if h1 == h2 {
			t.Fatal("hash must change when event_type changes")
		}
	})

	t.Run("changes_with_action", func(t *testing.T) {
		h1 := ComputeHash("id", ts, "op1", EventSessionInteract, "action-a", "")
		h2 := ComputeHash("id", ts, "op1", EventSessionInteract, "action-b", "")
		if h1 == h2 {
			t.Fatal("hash must change when action changes")
		}
	})

	t.Run("changes_with_previous_hash", func(t *testing.T) {
		h1 := ComputeHash("id", ts, "op1", EventSessionInteract, "action", "")
		h2 := ComputeHash("id", ts, "op1", EventSessionInteract, "action", "abc123")
		if h1 == h2 {
			t.Fatal("hash must change when previous_hash changes")
		}
	})

	t.Run("chain_integrity", func(t *testing.T) {
		prev := ""
		hashes := make([]string, 3)
		for i := 0; i < 3; i++ {
			h := ComputeHash(
				fmt.Sprintf("entry-%d", i),
				ts.Add(time.Duration(i)*time.Minute),
				"op1",
				EventSessionInteract,
				fmt.Sprintf("action-%d", i),
				prev,
			)
			hashes[i] = h
			prev = h
		}

		for i, h := range hashes {
			if h == "" {
				t.Fatalf("hash %d is empty", i)
			}
			for j := i + 1; j < len(hashes); j++ {
				if h == hashes[j] {
					t.Fatalf("hash %d and %d collide: %s", i, j, h)
				}
			}
		}
	})
}
