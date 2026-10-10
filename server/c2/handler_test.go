package c2

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

// sendMsg writes a framed JSON message to conn.
func sendMsg(t *testing.T, conn net.Conn, msgType string, data interface{}) {
	t.Helper()
	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	msg := protocol.Message{Type: msgType, Data: json.RawMessage(dataBytes)}
	frame, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	if err := envelope.WriteFrame(conn, frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

// recvMsg reads a framed JSON message from conn.
func recvMsg(t *testing.T, conn net.Conn) protocol.Message {
	t.Helper()
	frame, err := envelope.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var msg protocol.Message
	if err := json.Unmarshal(frame, &msg); err != nil {
		t.Fatalf("unmarshal message: %v", err)
	}
	return msg
}

func makeRegisterData() protocol.RegisterData {
	return protocol.RegisterData{
		ImplantID: "implant-001",
		Hostname:  "target-host",
		Username:  "testuser",
		OS:        "linux",
		Arch:      "amd64",
		PID:       1234,
		Process:   "test",
		Mode:      "beacon",
	}
}

// register performs a full registration handshake over conn and returns
// the session ID from the register_ack.
func register(t *testing.T, conn net.Conn) string {
	t.Helper()
	sendMsg(t, conn, "register", makeRegisterData())
	ack := recvMsg(t, conn)
	if ack.Type != "register_ack" {
		t.Fatalf("expected register_ack, got %q", ack.Type)
	}
	var ackData protocol.RegisterAckData
	if err := json.Unmarshal(ack.Data, &ackData); err != nil {
		t.Fatalf("unmarshal ack data: %v", err)
	}
	if ackData.SessionID == "" {
		t.Fatal("register_ack has empty session ID")
	}
	return ackData.SessionID
}

func TestRegistration_CreatesSession(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.HandleConnection(serverConn)
	}()

	sessionID := register(t, clientConn)

	// Verify session exists in server.
	sess := srv.GetSession(sessionID)
	if sess == nil {
		t.Fatalf("session %s not found after registration", sessionID)
	}
	if sess.Hostname != "target-host" {
		t.Errorf("hostname = %q, want %q", sess.Hostname, "target-host")
	}
	if sess.Username != "testuser" {
		t.Errorf("username = %q, want %q", sess.Username, "testuser")
	}
	if sess.OS != "linux" {
		t.Errorf("os = %q, want %q", sess.OS, "linux")
	}

	// Verify the session appears in ListSessions.
	sessions := srv.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("ListSessions returned %d sessions, want 1", len(sessions))
	}

	clientConn.Close()
	wg.Wait()
}

func TestRegistration_AckContainsValidUUID(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sendMsg(t, clientConn, "register", makeRegisterData())
	ack := recvMsg(t, clientConn)

	var ackData protocol.RegisterAckData
	if err := json.Unmarshal(ack.Data, &ackData); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}

	// UUID v4 format: 8-4-4-4-12 hex chars.
	if len(ackData.SessionID) != 36 {
		t.Errorf("session ID length = %d, want 36 (UUID format)", len(ackData.SessionID))
	}

	clientConn.Close()
}

func TestCheckin_UpdatesLastCheckin(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	sess := srv.GetSession(sessionID)
	firstCheckin := sess.LastCheckin

	time.Sleep(10 * time.Millisecond)

	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	_ = recvMsg(t, clientConn) // consume tasking response

	sess = srv.GetSession(sessionID)
	if !sess.LastCheckin.After(firstCheckin) {
		t.Errorf("LastCheckin was not updated: got %v, want after %v", sess.LastCheckin, firstCheckin)
	}

	clientConn.Close()
}

func TestCheckin_EmptyTaskQueue(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	resp := recvMsg(t, clientConn)

	if resp.Type != "tasking" {
		t.Fatalf("expected tasking, got %q", resp.Type)
	}

	var tasking protocol.TaskingData
	if err := json.Unmarshal(resp.Data, &tasking); err != nil {
		t.Fatalf("unmarshal tasking: %v", err)
	}
	if len(tasking.Tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(tasking.Tasks))
	}

	clientConn.Close()
}

func TestRegistration_BadJSON(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.HandleConnection(serverConn)
		close(done)
	}()

	// Send a frame that is not valid JSON.
	if err := envelope.WriteFrame(clientConn, []byte("not json{{")); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	<-done

	if len(srv.ListSessions()) != 0 {
		t.Error("server created a session from bad JSON")
	}
}

func TestRegistration_WrongMessageType(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.HandleConnection(serverConn)
		close(done)
	}()

	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: "bogus"})

	<-done

	if len(srv.ListSessions()) != 0 {
		t.Error("server created a session from non-register message")
	}
}

func TestRegistration_InvalidRegisterData(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.HandleConnection(serverConn)
		close(done)
	}()

	// Send a register message with data that can't unmarshal to RegisterData.
	dataBytes, _ := json.Marshal("a plain string, not an object")
	msg := protocol.Message{Type: "register", Data: json.RawMessage(dataBytes)}
	frame, _ := json.Marshal(msg)
	if err := envelope.WriteFrame(clientConn, frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	<-done

	if len(srv.ListSessions()) != 0 {
		t.Error("server created a session from invalid register data")
	}
}

func TestConnectionDrop_CleansUpSession(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		srv.HandleConnection(serverConn)
		close(done)
	}()

	sessionID := register(t, clientConn)

	if srv.GetSession(sessionID) == nil {
		t.Fatal("session should exist before disconnect")
	}

	clientConn.Close()
	<-done

	if srv.GetSession(sessionID) != nil {
		t.Error("session was not cleaned up after connection drop")
	}
	if len(srv.ListSessions()) != 0 {
		t.Errorf("ListSessions returned %d, want 0 after disconnect", len(srv.ListSessions()))
	}
}

// ── Flow 2: Task Queuing, Dispatch, and Result Collection ──

func TestQueueTask_ValidSession(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	taskID, err := srv.QueueTask(sessionID, "shell", "whoami")
	if err != nil {
		t.Fatalf("QueueTask failed: %v", err)
	}
	if taskID == "" {
		t.Fatal("QueueTask returned empty task ID")
	}

	clientConn.Close()
}

func TestQueueTask_NonexistentSession(t *testing.T) {
	srv := NewImplantServer()

	_, err := srv.QueueTask("nonexistent-session-id", "shell", "whoami")
	if err == nil {
		t.Fatal("QueueTask should fail for nonexistent session")
	}
}

func TestQueueTask_DispatchOnCheckin(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	taskID, err := srv.QueueTask(sessionID, "shell", "id")
	if err != nil {
		t.Fatalf("QueueTask: %v", err)
	}

	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	resp := recvMsg(t, clientConn)

	if resp.Type != "tasking" {
		t.Fatalf("expected tasking, got %q", resp.Type)
	}

	var tasking protocol.TaskingData
	if err := json.Unmarshal(resp.Data, &tasking); err != nil {
		t.Fatalf("unmarshal tasking: %v", err)
	}
	if len(tasking.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasking.Tasks))
	}
	if tasking.Tasks[0].ID != taskID {
		t.Errorf("task ID = %q, want %q", tasking.Tasks[0].ID, taskID)
	}
	if tasking.Tasks[0].Type != "shell" {
		t.Errorf("task type = %q, want %q", tasking.Tasks[0].Type, "shell")
	}
	if tasking.Tasks[0].Args != "id" {
		t.Errorf("task args = %q, want %q", tasking.Tasks[0].Args, "id")
	}

	// Second checkin should return empty.
	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	resp2 := recvMsg(t, clientConn)
	var tasking2 protocol.TaskingData
	if err := json.Unmarshal(resp2.Data, &tasking2); err != nil {
		t.Fatalf("unmarshal tasking2: %v", err)
	}
	if len(tasking2.Tasks) != 0 {
		t.Errorf("second checkin returned %d tasks, want 0", len(tasking2.Tasks))
	}

	clientConn.Close()
}

func TestMultipleTasksDispatchedInOneBatch(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	// Queue 3 tasks between checkins.
	for i := 0; i < 3; i++ {
		if _, err := srv.QueueTask(sessionID, "shell", fmt.Sprintf("cmd-%d", i)); err != nil {
			t.Fatalf("QueueTask %d: %v", i, err)
		}
	}

	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	resp := recvMsg(t, clientConn)

	var tasking protocol.TaskingData
	if err := json.Unmarshal(resp.Data, &tasking); err != nil {
		t.Fatalf("unmarshal tasking: %v", err)
	}
	if len(tasking.Tasks) != 3 {
		t.Errorf("expected 3 tasks, got %d", len(tasking.Tasks))
	}

	clientConn.Close()
}

func TestHandleResult_StoresResult(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	taskID, _ := srv.QueueTask(sessionID, "shell", "whoami")

	// Drain the task via checkin.
	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	_ = recvMsg(t, clientConn) // consume tasking

	// Send result.
	sendMsg(t, clientConn, "result", protocol.ResultData{
		SessionID: sessionID,
		TaskID:    taskID,
		Success:   true,
		Output:    "root",
	})
	ack := recvMsg(t, clientConn)
	if ack.Type != "result_ack" {
		t.Fatalf("expected result_ack, got %q", ack.Type)
	}

	result := srv.GetResult(taskID)
	if result == nil {
		t.Fatal("GetResult returned nil after result was submitted")
	}
	if result.Output != "root" {
		t.Errorf("result output = %q, want %q", result.Output, "root")
	}
	if !result.Success {
		t.Error("result.Success = false, want true")
	}

	clientConn.Close()
}

func TestGetResult_Nil_BeforeCompletion(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	taskID, _ := srv.QueueTask(sessionID, "shell", "whoami")

	if result := srv.GetResult(taskID); result != nil {
		t.Error("GetResult should return nil before task completes")
	}

	clientConn.Close()
}

func TestConcurrentQueueTask(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := srv.QueueTask(sessionID, "shell", fmt.Sprintf("cmd-%d", n))
			if err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent QueueTask error: %v", err)
	}

	// Drain and verify count.
	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	resp := recvMsg(t, clientConn)
	var tasking protocol.TaskingData
	if err := json.Unmarshal(resp.Data, &tasking); err != nil {
		t.Fatalf("unmarshal tasking: %v", err)
	}
	if len(tasking.Tasks) != goroutines {
		t.Errorf("expected %d tasks, got %d", goroutines, len(tasking.Tasks))
	}

	clientConn.Close()
}
