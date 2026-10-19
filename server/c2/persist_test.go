package c2

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

type fakePersistence struct {
	mu            sync.Mutex
	registered    int
	checkins      int
	disconnected  int
	queued        []*Task
	dispatched    [][]string
	completed     []*TaskResult
	pending       []*Task
	failQueue     bool
	markLostCalls int
}

func (f *fakePersistence) SessionRegistered(context.Context, *ImplantSession) error {
	f.mu.Lock()
	f.registered++
	f.mu.Unlock()
	return nil
}

func (f *fakePersistence) SessionCheckin(context.Context, string, time.Time) error {
	f.mu.Lock()
	f.checkins++
	f.mu.Unlock()
	return nil
}

func (f *fakePersistence) SessionDisconnected(context.Context, string, time.Time) error {
	f.mu.Lock()
	f.disconnected++
	f.mu.Unlock()
	return nil
}

func (f *fakePersistence) PendingTasks(context.Context, string) ([]*Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*Task(nil), f.pending...), nil
}

func (f *fakePersistence) TaskQueued(_ context.Context, task *Task) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failQueue {
		return errors.New("db unavailable")
	}
	f.queued = append(f.queued, task)
	return nil
}

func (f *fakePersistence) TaskDispatched(_ context.Context, ids []string, _ time.Time) error {
	f.mu.Lock()
	f.dispatched = append(f.dispatched, append([]string(nil), ids...))
	f.mu.Unlock()
	return nil
}

func (f *fakePersistence) TaskCompleted(_ context.Context, result *TaskResult) error {
	f.mu.Lock()
	f.completed = append(f.completed, result)
	f.mu.Unlock()
	return nil
}

func (f *fakePersistence) MarkLiveSessionsDisconnected(context.Context) error {
	f.mu.Lock()
	f.markLostCalls++
	f.mu.Unlock()
	return nil
}

func (f *fakePersistence) counts() (registered, checkins, disconnected, queued, dispatched, completed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registered, f.checkins, f.disconnected, len(f.queued), len(f.dispatched), len(f.completed)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestPersistenceLifecycleHooks(t *testing.T) {
	srv := NewImplantServer()
	fp := &fakePersistence{}
	srv.SetPersistence(fp)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go srv.HandleConnection(serverConn)

	sessionID := register(t, clientConn)
	taskID, err := srv.QueueTask(sessionID, protocol.TaskShell, "id")
	if err != nil {
		t.Fatalf("QueueTask: %v", err)
	}

	sendMsg(t, clientConn, "checkin", protocol.CheckinData{SessionID: sessionID})
	if msg := recvMsg(t, clientConn); msg.Type != "tasking" {
		t.Fatalf("expected tasking, got %q", msg.Type)
	}
	sendMsg(t, clientConn, "result", protocol.ResultData{
		SessionID: sessionID,
		TaskID:    taskID,
		Success:   true,
		Output:    "uid=0",
	})
	if msg := recvMsg(t, clientConn); msg.Type != "result_ack" {
		t.Fatalf("expected result_ack, got %q", msg.Type)
	}

	clientConn.Close()
	waitFor(t, "persistence hooks", func() bool {
		registered, _, disconnected, queued, dispatched, completed := fp.counts()
		return registered == 1 && disconnected == 1 && queued == 1 && dispatched == 1 && completed == 1
	})
}

func TestQueueTask_FailsClosedWhenPersistenceFails(t *testing.T) {
	srv := NewImplantServer()
	fp := &fakePersistence{failQueue: true}
	srv.SetPersistence(fp)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go srv.HandleConnection(serverConn)
	sessionID := register(t, clientConn)

	if _, err := srv.QueueTask(sessionID, protocol.TaskShell, "id"); err == nil {
		t.Fatal("QueueTask succeeded despite persistence failure")
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if got := len(srv.taskQueues[sessionID]); got != 0 {
		t.Fatalf("queue length = %d, want 0 after failed persistence", got)
	}
}

func TestRegister_RebindsPersistedTasks(t *testing.T) {
	srv := NewImplantServer()
	fp := &fakePersistence{
		pending: []*Task{{ID: "persisted-task", Type: protocol.TaskShell, Args: "id"}},
	}
	srv.SetPersistence(fp)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go srv.HandleConnection(serverConn)
	sessionID := register(t, clientConn)

	waitFor(t, "persisted task rebind", func() bool {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		return len(srv.taskQueues[sessionID]) == 1
	})

	srv.mu.RLock()
	queue := append([]*Task(nil), srv.taskQueues[sessionID]...)
	srv.mu.RUnlock()
	if queue[0].ID != "persisted-task" || queue[0].SessionID != sessionID {
		t.Fatalf("unexpected rebound task: %+v", queue[0])
	}
}
