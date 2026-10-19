package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
)

type EventType string

const (
	EventOperatorLogin    EventType = "operator.login"
	EventOperatorLogout   EventType = "operator.logout"
	EventPayloadGenerate  EventType = "payload.generate"
	EventPayloadRevoke    EventType = "payload.revoke"
	EventSessionInteract  EventType = "session.interact"
	EventSessionKill      EventType = "session.kill"
	EventListenerStart    EventType = "listener.start"
	EventListenerStop     EventType = "listener.stop"
	EventDataCollect      EventType = "data.collect"
	EventPivot            EventType = "pivot"
	EventPrivescAssess    EventType = "privesc.assess"
	EventConfigChange     EventType = "config.change"
	EventKillSwitch       EventType = "killswitch"
	EventScopeViolation   EventType = "scope.violation"
	EventEngagementCreate EventType = "engagement.create"
	EventOTImport         EventType = "ot.import"
	EventOTReport         EventType = "ot.report"
	EventPluginRun        EventType = "plugin.run"
)

type Entry struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	OperatorID    string         `json:"operator_id"`
	EngagementID  string         `json:"engagement_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	EventType     EventType      `json:"event_type"`
	Action        string         `json:"action"`
	Target        string         `json:"target,omitempty"`
	ResultSummary string         `json:"result_summary,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	SourceIP      string         `json:"source_ip,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	PreviousHash  string         `json:"previous_hash"`
	EntryHash     string         `json:"entry_hash"`
}

type Writer interface {
	Write(entry Entry) error
}

type Logger struct {
	mu           sync.Mutex
	writers      []Writer
	previousHash string
}

func NewLogger(writers ...Writer) *Logger {
	return &Logger{writers: writers}
}

// NewLoggerFromHead starts a logger at an existing chain head. Use this when
// reconnecting to a persisted chain; otherwise the first entry's PreviousHash
// will not match the stored head.
func NewLoggerFromHead(previousHash string, writers ...Writer) *Logger {
	return &Logger{writers: writers, previousHash: previousHash}
}

func (l *Logger) Log(operatorID, engagementID, sessionID string, eventType EventType, action, target, result string, metadata map[string]any, sourceIP, correlationID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := Entry{
		ID:            uuid.New().String(),
		Timestamp:     time.Now().UTC(),
		OperatorID:    operatorID,
		EngagementID:  engagementID,
		SessionID:     sessionID,
		EventType:     eventType,
		Action:        action,
		Target:        target,
		ResultSummary: result,
		Metadata:      metadata,
		SourceIP:      sourceIP,
		CorrelationID: correlationID,
		PreviousHash:  l.previousHash,
	}

	entry.EntryHash = computeHash(entry)
	l.previousHash = entry.EntryHash

	for _, w := range l.writers {
		if err := w.Write(entry); err != nil {
			return err
		}
	}

	return nil
}

// ComputeHash is the legacy field subset. New code should use
// ComputeEntryHash, which covers every field that can affect an audit entry.
func ComputeHash(id string, timestamp time.Time, operatorID string, eventType EventType, action, previousHash string) string {
	return ComputeEntryHash(Entry{
		ID:           id,
		Timestamp:    timestamp,
		OperatorID:   operatorID,
		EventType:    eventType,
		Action:       action,
		PreviousHash: previousHash,
	})
}

// ComputeEntryHash hashes every audit field. Tampering with engagement,
// session, target, metadata, source IP, or correlation ID now breaks the chain.
func ComputeEntryHash(entry Entry) string {
	metadata, _ := json.Marshal(entry.Metadata)
	data, _ := json.Marshal(struct {
		ID              string `json:"id"`
		TimestampUnixNs int64  `json:"timestamp_unix_ns"`
		OperatorID      string `json:"operator_id"`
		EngagementID    string `json:"engagement_id"`
		SessionID       string `json:"session_id"`
		EventType       string `json:"event_type"`
		Action          string `json:"action"`
		Target          string `json:"target"`
		ResultSummary   string `json:"result_summary"`
		Metadata        string `json:"metadata"`
		SourceIP        string `json:"source_ip"`
		CorrelationID   string `json:"correlation_id"`
		PreviousHash    string `json:"previous_hash"`
	}{
		ID:              entry.ID,
		TimestampUnixNs: entry.Timestamp.UTC().UnixNano(),
		OperatorID:      entry.OperatorID,
		EngagementID:    entry.EngagementID,
		SessionID:       entry.SessionID,
		EventType:       string(entry.EventType),
		Action:          entry.Action,
		Target:          entry.Target,
		ResultSummary:   entry.ResultSummary,
		Metadata:        string(metadata),
		SourceIP:        entry.SourceIP,
		CorrelationID:   entry.CorrelationID,
		PreviousHash:    entry.PreviousHash,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func computeHash(entry Entry) string {
	return ComputeEntryHash(entry)
}
