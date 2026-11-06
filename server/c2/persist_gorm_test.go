package c2

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
	"gorm.io/gorm"
)

func testGORMDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := store.DefaultConfig()
	cfg.DSN = filepath.Join(t.TempDir(), "persist.db")
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestGORMPersistenceLifecycle(t *testing.T) {
	db := testGORMDB(t)
	sessions := repository.NewSessionRepository(db)
	tasks := repository.NewTaskRepository(db)
	p := NewGORMPersistence(sessions, tasks)
	ctx := context.Background()
	now := time.Now()

	session := &ImplantSession{
		ID:           "session-1",
		ImplantID:    "implant-1",
		Hostname:     "host",
		Username:     "user",
		OS:           "linux",
		Arch:         "amd64",
		RemoteAddr:   "127.0.0.1:1234",
		Transport:    "mtls",
		Mode:         "beacon",
		EngagementID: "eng-1",
		PID:          42,
		Process:      "implant",
		CreatedAt:    now,
		LastCheckin:  now,
	}
	if err := p.SessionRegistered(ctx, session); err != nil {
		t.Fatalf("SessionRegistered: %v", err)
	}

	var row models.Session
	if err := db.First(&row, "id = ?", session.ID).Error; err != nil {
		t.Fatalf("session row: %v", err)
	}
	if row.HealthStatus != "active" || row.ImplantID != "implant-1" || row.EngagementID != "eng-1" {
		t.Fatalf("unexpected session row: %+v", row)
	}

	later := now.Add(10 * time.Second)
	if err := p.SessionCheckin(ctx, session.ID, later); err != nil {
		t.Fatalf("SessionCheckin: %v", err)
	}
	if err := db.First(&row, "id = ?", session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !row.LastCheckin.Equal(later) {
		t.Fatalf("last_checkin = %v, want %v", row.LastCheckin, later)
	}

	task := &Task{
		ID:           "task-1",
		Type:         "shell",
		Args:         "id",
		SessionID:    session.ID,
		ImplantID:    "implant-1",
		EngagementID: "eng-1",
		CreatedAt:    now,
	}
	if err := p.TaskQueued(ctx, task); err != nil {
		t.Fatalf("TaskQueued: %v", err)
	}
	got, err := tasks.GetByID(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "queued" {
		t.Fatalf("task state = %q, want queued", got.State)
	}

	if err := p.TaskDispatched(ctx, []string{task.ID}, now); err != nil {
		t.Fatalf("TaskDispatched: %v", err)
	}
	got, _ = tasks.GetByID(task.ID)
	if got.State != "sent" || got.Attempts != 1 {
		t.Fatalf("dispatched task = %+v", got)
	}

	result := &TaskResult{
		TaskID:      task.ID,
		SessionID:   session.ID,
		Success:     true,
		Output:      "uid=0",
		CompletedAt: now.Add(2 * time.Second),
	}
	if err := p.TaskCompleted(ctx, result); err != nil {
		t.Fatalf("TaskCompleted: %v", err)
	}
	got, _ = tasks.GetByID(task.ID)
	if got.State != "completed" {
		t.Fatalf("completed task state = %q", got.State)
	}
	var resultRow models.TaskResult
	if err := db.First(&resultRow, "task_id = ?", task.ID).Error; err != nil {
		t.Fatalf("result row: %v", err)
	}
	if resultRow.Output != "uid=0" || !resultRow.Success {
		t.Fatalf("unexpected result row: %+v", resultRow)
	}

	if err := p.SessionDisconnected(ctx, session.ID, now.Add(3*time.Second)); err != nil {
		t.Fatalf("SessionDisconnected: %v", err)
	}
	if err := db.First(&row, "id = ?", session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if row.HealthStatus != "disconnected" {
		t.Fatalf("health = %q, want disconnected", row.HealthStatus)
	}
}

func TestGORMPersistence_PendingTasksAndReconcile(t *testing.T) {
	db := testGORMDB(t)
	sessions := repository.NewSessionRepository(db)
	tasks := repository.NewTaskRepository(db)
	p := NewGORMPersistence(sessions, tasks)
	ctx := context.Background()
	now := time.Now()

	if err := sessions.Create(&models.Session{Base: models.Base{ID: "live"}, HealthStatus: "active", LastCheckin: now}); err != nil {
		t.Fatal(err)
	}
	if err := tasks.Create(&models.Task{
		ID: "queued-1", ImplantID: "implant-9", SessionID: "old", Type: "shell", State: "queued", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tasks.Create(&models.Task{
		ID: "sent-1", ImplantID: "implant-9", SessionID: "old", Type: "shell", State: "sent", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	pending, err := p.PendingTasks(ctx, "implant-9")
	if err != nil {
		t.Fatalf("PendingTasks: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "queued-1" {
		t.Fatalf("PendingTasks = %+v, want only queued-1", pending)
	}

	if err := p.MarkLiveSessionsDisconnected(ctx); err != nil {
		t.Fatalf("MarkLiveSessionsDisconnected: %v", err)
	}
	var row models.Session
	if err := db.First(&row, "id = ?", "live").Error; err != nil {
		t.Fatal(err)
	}
	if row.HealthStatus != "disconnected" {
		t.Fatalf("health = %q, want disconnected", row.HealthStatus)
	}
}
