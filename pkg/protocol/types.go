package protocol

import "encoding/json"

// Message is the wire protocol message wrapper.
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// RegisterData is the registration payload sent by the implant.
type RegisterData struct {
	ImplantID string `json:"implant_id"`
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Mode      string `json:"mode"`
}

// RegisterAckData is the registration acknowledgement sent to the implant.
type RegisterAckData struct {
	SessionID string `json:"session_id"`
	Interval  int    `json:"interval"`
}

// CheckinData is the checkin payload (heartbeat/poll).
type CheckinData struct {
	SessionID string `json:"session_id"`
}

// TaskingData is the tasking response sent to the implant.
type TaskingData struct {
	Tasks []TaskWire `json:"tasks"`
}

// TaskWire is the on-wire representation of a task.
type TaskWire struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Args string `json:"args"`
}

// ResultData is the result payload from the implant.
type ResultData struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Error     string `json:"error"`
}
