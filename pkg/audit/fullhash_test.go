package audit

import (
	"testing"
	"time"
)

func TestComputeEntryHash_CoversAllFields(t *testing.T) {
	base := Entry{
		ID:            "id",
		Timestamp:     time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		OperatorID:    "op",
		EngagementID:  "eng",
		SessionID:     "sess",
		EventType:     EventSessionInteract,
		Action:        "task",
		Target:        "10.0.0.1",
		ResultSummary: "ok",
		Metadata:      map[string]any{"k": "v"},
		SourceIP:      "127.0.0.1",
		CorrelationID: "corr",
		PreviousHash:  "prev",
	}
	want := ComputeEntryHash(base)

	mutations := map[string]func(*Entry){
		"engagement":  func(e *Entry) { e.EngagementID = "other" },
		"session":     func(e *Entry) { e.SessionID = "other" },
		"target":      func(e *Entry) { e.Target = "10.0.0.2" },
		"summary":     func(e *Entry) { e.ResultSummary = "changed" },
		"metadata":    func(e *Entry) { e.Metadata = map[string]any{"k": "other"} },
		"source ip":   func(e *Entry) { e.SourceIP = "10.0.0.9" },
		"correlation": func(e *Entry) { e.CorrelationID = "other" },
	}
	for name, mutate := range mutations {
		changed := base
		mutate(&changed)
		if got := ComputeEntryHash(changed); got == want {
			t.Errorf("hash did not change when %s changed", name)
		}
	}
}
