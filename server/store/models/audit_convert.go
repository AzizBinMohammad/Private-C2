package models

import (
	"encoding/json"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
)

func AuditEntryFromLib(e audit.Entry) AuditEntry {
	var meta string
	if e.Metadata != nil {
		b, _ := json.Marshal(e.Metadata)
		meta = string(b)
	}
	return AuditEntry{
		ID:                e.ID,
		CreatedAt:         e.Timestamp,
		TimestampUnixNano: e.Timestamp.UTC().UnixNano(),
		OperatorID:        e.OperatorID,
		EngagementID:      e.EngagementID,
		SessionID:         e.SessionID,
		EventType:         string(e.EventType),
		Action:            e.Action,
		Target:            e.Target,
		ResultSummary:     e.ResultSummary,
		Metadata:          meta,
		SourceIP:          e.SourceIP,
		CorrelationID:     e.CorrelationID,
		PreviousHash:      e.PreviousHash,
		EntryHash:         e.EntryHash,
	}
}

func AuditEntryToLib(e AuditEntry) (audit.Entry, error) {
	var meta map[string]any
	if e.Metadata != "" {
		if err := json.Unmarshal([]byte(e.Metadata), &meta); err != nil {
			return audit.Entry{}, err
		}
	}
	timestamp := e.CreatedAt
	if e.TimestampUnixNano != 0 {
		timestamp = time.Unix(0, e.TimestampUnixNano).UTC()
	}
	return audit.Entry{
		ID:            e.ID,
		Timestamp:     timestamp,
		OperatorID:    e.OperatorID,
		EngagementID:  e.EngagementID,
		SessionID:     e.SessionID,
		EventType:     audit.EventType(e.EventType),
		Action:        e.Action,
		Target:        e.Target,
		ResultSummary: e.ResultSummary,
		Metadata:      meta,
		SourceIP:      e.SourceIP,
		CorrelationID: e.CorrelationID,
		PreviousHash:  e.PreviousHash,
		EntryHash:     e.EntryHash,
	}, nil
}
