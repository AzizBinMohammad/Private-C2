package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// apiComputeHash reproduces the hash algorithm used by the API verification
// endpoint in server/api/httpapi/audit.go (handleAuditDetail). It concatenates
// 4 raw byte fields: id + created_at (RFC3339Nano) + action + previous_hash.
func apiComputeHash(id string, createdAt time.Time, action, previousHash string) string {
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte(createdAt.Format(time.RFC3339Nano)))
	h.Write([]byte(action))
	h.Write([]byte(previousHash))
	return hex.EncodeToString(h.Sum(nil))
}

func TestHashAlgorithm_LibraryAndAPI_CurrentlyDiffer(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	entry := Entry{
		ID:           "test-entry-001",
		Timestamp:    ts,
		OperatorID:   "operator-1",
		EventType:    EventSessionInteract,
		Action:       "shell_exec",
		PreviousHash: "",
	}

	libraryHash := computeHash(entry)
	apiHash := apiComputeHash(entry.ID, entry.Timestamp, entry.Action, entry.PreviousHash)

	if libraryHash == apiHash {
		t.Fatal("expected library and API hashes to differ (documenting known issue #2), but they matched")
	}

	t.Logf("library hash: %s", libraryHash)
	t.Logf("API hash:     %s", apiHash)
	t.Log("confirmed: the two algorithms produce different hashes for the same entry fields")
}

func TestHashAlgorithm_DifferenceSources(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("differs_due_to_extra_fields", func(t *testing.T) {
		entry := Entry{
			ID:           "entry-1",
			Timestamp:    ts,
			OperatorID:   "",
			EventType:    "",
			Action:       "action",
			PreviousHash: "",
		}

		libraryHash := computeHash(entry)
		apiHash := apiComputeHash(entry.ID, entry.Timestamp, entry.Action, entry.PreviousHash)

		if libraryHash == apiHash {
			t.Fatal("even with empty operator_id and event_type, hashes differ due to JSON vs concatenation")
		}
	})

	t.Run("library_includes_operator_id_and_event_type", func(t *testing.T) {
		base := Entry{
			ID:           "entry-1",
			Timestamp:    ts,
			OperatorID:   "op1",
			EventType:    EventSessionInteract,
			Action:       "action",
			PreviousHash: "",
		}

		modified := base
		modified.OperatorID = "op2"

		hash1 := computeHash(base)
		hash2 := computeHash(modified)

		if hash1 == hash2 {
			t.Fatal("library hash should change when operator_id changes")
		}

		apiHash1 := apiComputeHash(base.ID, base.Timestamp, base.Action, base.PreviousHash)
		apiHash2 := apiComputeHash(modified.ID, modified.Timestamp, modified.Action, modified.PreviousHash)

		if apiHash1 != apiHash2 {
			t.Fatal("API hash should NOT change when operator_id changes (it doesn't include that field)")
		}
	})

	t.Run("chain_with_both_algorithms_diverges", func(t *testing.T) {
		prevLib := ""
		prevAPI := ""

		for i := 0; i < 3; i++ {
			entry := Entry{
				ID:           fmt.Sprintf("entry-%d", i),
				Timestamp:    ts.Add(time.Duration(i) * time.Minute),
				OperatorID:   "op1",
				EventType:    EventSessionInteract,
				Action:       fmt.Sprintf("action-%d", i),
				PreviousHash: prevLib,
			}
			prevLib = computeHash(entry)

			entry.PreviousHash = prevAPI
			prevAPI = apiComputeHash(entry.ID, entry.Timestamp, entry.Action, entry.PreviousHash)
		}

		if prevLib == prevAPI {
			t.Fatal("hash chains built with the two algorithms should diverge")
		}
	})
}
