package protocol

import "encoding/json"

// Message is the wire protocol message wrapper.
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// RegisterData is the registration payload sent by the implant. All v2 fields
// are additive and omitted by legacy v1 implants.
type RegisterData struct {
	ImplantID string `json:"implant_id"`
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Mode      string `json:"mode"`
	// Elevated reports whether the implant holds admin/root-level rights on
	// the host. It is advisory metadata for the portal, not an authorization
	// signal: tasking is still gated by the engagement policy server-side.
	Elevated bool `json:"elevated,omitempty"`

	// v2 additions.
	ProtocolVersion int      `json:"protocol_version,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	EngagementID    string   `json:"engagement_id,omitempty"`
	SleepMs         int      `json:"sleep_ms,omitempty"`
	JitterPct       int      `json:"jitter_pct,omitempty"`
	Transports      []string `json:"transports,omitempty"`
}

// RegisterAckData is the registration acknowledgement sent to the implant.
type RegisterAckData struct {
	SessionID string `json:"session_id"`
	Interval  int    `json:"interval"`

	// v2 additions. Legacy implants ignore unknown JSON fields.
	ProtocolVersion int      `json:"protocol_version,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	HeartbeatMs     int      `json:"heartbeat_ms,omitempty"`
	MaxTasks        int      `json:"max_tasks,omitempty"`
	SessionToken    string   `json:"session_token,omitempty"`
	Kill            bool     `json:"kill,omitempty"`
	KillReason      string   `json:"kill_reason,omitempty"`
}

// CheckinData is the checkin payload (heartbeat/poll).
type CheckinData struct {
	SessionID string `json:"session_id"`

	// v2 additions: token for stateless carriers and task reconciliation.
	SessionToken   string   `json:"session_token,omitempty"`
	OutstandingIDs []string `json:"outstanding_task_ids,omitempty"`
	StartedIDs     []string `json:"started_task_ids,omitempty"`
	RunningIDs     []string `json:"running_task_ids,omitempty"`
}

// TaskingData is the tasking response sent to the implant.
type TaskingData struct {
	Tasks      []TaskWire `json:"tasks"`
	Kill       bool       `json:"kill,omitempty"`
	KillReason string     `json:"kill_reason,omitempty"`
}

// TaskWire is the on-wire representation of a task.
type TaskWire struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Args string `json:"args"`
	// TimeoutMs is a per-task execution budget (v2). Zero means server default.
	TimeoutMs int `json:"timeout_ms,omitempty"`
}

// TaskStartedData acknowledges that the implant has begun executing tasks. It
// distinguishes running work from tasking lost in transit (v2).
type TaskStartedData struct {
	TaskIDs []string `json:"task_ids"`
}

// ResultData is the result payload from the implant.
type ResultData struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Error     string `json:"error"`

	// v2 additions.
	SessionToken string `json:"session_token,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
	Bytes        int64  `json:"bytes,omitempty"`
}
