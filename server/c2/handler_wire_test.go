package c2

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func TestWireRoundTrip_Message(t *testing.T) {
	inner, _ := json.Marshal(map[string]string{"key": "value"})
	original := protocol.Message{
		Type: "register",
		Data: json.RawMessage(inner),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, original.Type)
	}
	if string(decoded.Data) != string(original.Data) {
		t.Errorf("Data = %s, want %s", decoded.Data, original.Data)
	}
}

func TestWireRoundTrip_Message_NilData(t *testing.T) {
	original := protocol.Message{Type: "result_ack"}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, original.Type)
	}
	if string(decoded.Data) != "null" {
		t.Errorf("Data = %s, want null (nil RawMessage marshals to null)", decoded.Data)
	}
}

func TestWireRoundTrip_RegisterData(t *testing.T) {
	original := protocol.RegisterData{
		ImplantID: "abc123",
		Hostname:  "target-host",
		Username:  "admin",
		OS:        "linux",
		Arch:      "amd64",
		PID:       4321,
		Process:   "implant.exe",
		Mode:      "beacon",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.RegisterData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, original)
	}
}

func TestWireRoundTrip_RegisterData_ZeroValues(t *testing.T) {
	original := protocol.RegisterData{}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.RegisterData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, original)
	}
}

func TestWireRoundTrip_RegisterAckData(t *testing.T) {
	original := protocol.RegisterAckData{
		SessionID: "550e8400-e29b-41d4-a716-446655440000",
		Interval:  5000,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.RegisterAckData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, original)
	}
}

func TestWireRoundTrip_CheckinData(t *testing.T) {
	original := protocol.CheckinData{
		SessionID: "550e8400-e29b-41d4-a716-446655440000",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.CheckinData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, original)
	}
}

func TestWireRoundTrip_TaskingData_WithTasks(t *testing.T) {
	original := protocol.TaskingData{
		Tasks: []protocol.TaskWire{
			{ID: "task-1", Type: "shell", Args: "whoami"},
			{ID: "task-2", Type: "ls", Args: "/tmp"},
			{ID: "task-3", Type: "cat", Args: "/etc/hostname"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.TaskingData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Tasks) != len(original.Tasks) {
		t.Fatalf("task count = %d, want %d", len(decoded.Tasks), len(original.Tasks))
	}
	for i, got := range decoded.Tasks {
		want := original.Tasks[i]
		if got != want {
			t.Errorf("Tasks[%d] = %+v, want %+v", i, got, want)
		}
	}
}

func TestWireRoundTrip_TaskingData_Empty(t *testing.T) {
	original := protocol.TaskingData{Tasks: []protocol.TaskWire{}}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.TaskingData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Tasks) != 0 {
		t.Errorf("task count = %d, want 0", len(decoded.Tasks))
	}
}

func TestWireRoundTrip_TaskWire(t *testing.T) {
	original := protocol.TaskWire{
		ID:   "task-abc",
		Type: "shell",
		Args: "id && uname -a",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.TaskWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, original)
	}
}

func TestWireRoundTrip_ResultData(t *testing.T) {
	original := protocol.ResultData{
		SessionID: "550e8400-e29b-41d4-a716-446655440000",
		TaskID:    "task-xyz",
		Success:   true,
		Output:    "root\n",
		Error:     "",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.ResultData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, original)
	}
}

func TestWireRoundTrip_ResultData_Failure(t *testing.T) {
	original := protocol.ResultData{
		SessionID: "550e8400-e29b-41d4-a716-446655440000",
		TaskID:    "task-fail",
		Success:   false,
		Output:    "",
		Error:     "command not found: foobar",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded protocol.ResultData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, original)
	}
}

func TestWireJSONKeys_RegisterData(t *testing.T) {
	rd := protocol.RegisterData{
		ImplantID: "id1",
		Hostname:  "h",
		Username:  "u",
		OS:        "linux",
		Arch:      "amd64",
		PID:       1,
		Process:   "p",
		Mode:      "beacon",
	}

	data, _ := json.Marshal(rd)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	expected := []string{"implant_id", "hostname", "username", "os", "arch", "pid", "process", "mode"}
	for _, key := range expected {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON key %q", key)
		}
	}
	if len(raw) != len(expected) {
		t.Errorf("JSON has %d keys, want %d", len(raw), len(expected))
	}
}

func TestWireJSONKeys_ResultData(t *testing.T) {
	rd := protocol.ResultData{
		SessionID: "s",
		TaskID:    "t",
		Success:   false,
		Output:    "",
		Error:     "",
	}

	data, _ := json.Marshal(rd)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	expected := []string{"session_id", "task_id", "success", "output", "error"}
	for _, key := range expected {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON key %q", key)
		}
	}
	if len(raw) != len(expected) {
		t.Errorf("JSON has %d keys, want %d", len(raw), len(expected))
	}
}

func TestWireRoundTrip_NestedMessage_RegisterData(t *testing.T) {
	reg := protocol.RegisterData{
		ImplantID: "nested-test",
		Hostname:  "box1",
		Username:  "root",
		OS:        "linux",
		Arch:      "arm64",
		PID:       999,
		Process:   "agent",
		Mode:      "interactive",
	}

	regBytes, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("marshal register data: %v", err)
	}

	msg := protocol.Message{Type: "register", Data: json.RawMessage(regBytes)}
	wireBytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}

	var decodedMsg protocol.Message
	if err := json.Unmarshal(wireBytes, &decodedMsg); err != nil {
		t.Fatalf("unmarshal message: %v", err)
	}

	if decodedMsg.Type != "register" {
		t.Errorf("message type = %q, want %q", decodedMsg.Type, "register")
	}

	var decodedReg protocol.RegisterData
	if err := json.Unmarshal(decodedMsg.Data, &decodedReg); err != nil {
		t.Fatalf("unmarshal register data from message: %v", err)
	}

	if !reflect.DeepEqual(decodedReg, reg) {
		t.Errorf("nested round-trip mismatch:\n  got  %+v\n  want %+v", decodedReg, reg)
	}
}

func TestWireRoundTrip_NestedMessage_TaskingData(t *testing.T) {
	tasking := protocol.TaskingData{
		Tasks: []protocol.TaskWire{
			{ID: "t1", Type: "shell", Args: "whoami"},
		},
	}

	taskingBytes, _ := json.Marshal(tasking)
	msg := protocol.Message{Type: "tasking", Data: json.RawMessage(taskingBytes)}
	wireBytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decodedMsg protocol.Message
	if err := json.Unmarshal(wireBytes, &decodedMsg); err != nil {
		t.Fatalf("unmarshal message: %v", err)
	}

	var decodedTasking protocol.TaskingData
	if err := json.Unmarshal(decodedMsg.Data, &decodedTasking); err != nil {
		t.Fatalf("unmarshal tasking: %v", err)
	}

	if len(decodedTasking.Tasks) != 1 {
		t.Fatalf("task count = %d, want 1", len(decodedTasking.Tasks))
	}
	if decodedTasking.Tasks[0] != tasking.Tasks[0] {
		t.Errorf("task mismatch: got %+v, want %+v", decodedTasking.Tasks[0], tasking.Tasks[0])
	}
}

func TestWireRoundTrip_NestedMessage_ResultData(t *testing.T) {
	result := protocol.ResultData{
		SessionID: "sess-1",
		TaskID:    "task-1",
		Success:   true,
		Output:    "uid=0(root)",
		Error:     "",
	}

	resultBytes, _ := json.Marshal(result)
	msg := protocol.Message{Type: "result", Data: json.RawMessage(resultBytes)}
	wireBytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decodedMsg protocol.Message
	if err := json.Unmarshal(wireBytes, &decodedMsg); err != nil {
		t.Fatalf("unmarshal message: %v", err)
	}

	var decodedResult protocol.ResultData
	if err := json.Unmarshal(decodedMsg.Data, &decodedResult); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if decodedResult != result {
		t.Errorf("nested round-trip mismatch:\n  got  %+v\n  want %+v", decodedResult, result)
	}
}
