package repository

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := store.DefaultConfig()
	cfg.DSN = filepath.Join(t.TempDir(), "test.db")
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestTaskRepositoryLifecycle(t *testing.T) {
	repo := NewTaskRepository(testDB(t))

	task := &models.Task{
		ImplantID:    "implant-1",
		EngagementID: "eng-1",
		Type:         "shell",
		Args:         "id",
		State:        "queued",
	}
	if err := repo.Create(task); err != nil {
		t.Fatalf("create: %v", err)
	}
	if task.ID == "" {
		t.Fatal("task ID was not assigned")
	}

	got, err := repo.GetByID(task.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != "queued" || got.Type != "shell" {
		t.Fatalf("unexpected task: %+v", got)
	}

	if err := repo.MarkSent(task.ID, time.Now()); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	sent, _ := repo.GetByID(task.ID)
	if sent.State != "sent" || sent.SentAt == nil || sent.Attempts != 1 {
		t.Fatalf("unexpected sent task: %+v", sent)
	}

	result := &models.TaskResult{
		TaskID:       task.ID,
		SessionID:    "session-1",
		EngagementID: "eng-1",
		Success:      true,
		Output:       "uid=0",
		CompletedAt:  time.Now(),
	}
	if err := repo.Complete(result); err != nil {
		t.Fatalf("complete: %v", err)
	}
	done, _ := repo.GetByID(task.ID)
	if done.State != "completed" || done.CompletedAt == nil {
		t.Fatalf("unexpected completed task: %+v", done)
	}

	// Duplicate completion must not create a second result or fail.
	if err := repo.Complete(result); err != nil {
		t.Fatalf("duplicate complete: %v", err)
	}
	var count int64
	if err := testDBQuery(t, repo.db, &models.TaskResult{}, &count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("result rows = %d, want 1", count)
	}
}

func testDBQuery(t *testing.T, db *gorm.DB, model any, count *int64) error {
	t.Helper()
	return db.Model(model).Count(count).Error
}

func TestTaskRepository_ListByImplantReturnsQueuedOnly(t *testing.T) {
	repo := NewTaskRepository(testDB(t))
	for _, task := range []*models.Task{
		{ImplantID: "i1", Type: "shell", State: "queued"},
		{ImplantID: "i1", Type: "ls", State: "sent"},
		{ImplantID: "i2", Type: "ls", State: "queued"},
	} {
		if err := repo.Create(task); err != nil {
			t.Fatal(err)
		}
	}
	tasks, err := repo.ListByImplant("i1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].Type != "shell" {
		t.Fatalf("ListByImplant = %+v, want the queued shell task", tasks)
	}
}

func TestTaskRepository_ExpireBefore(t *testing.T) {
	repo := NewTaskRepository(testDB(t))
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	stale := &models.Task{ImplantID: "i1", Type: "shell", State: "sent", ExpiresAt: &past}
	fresh := &models.Task{ImplantID: "i1", Type: "shell", State: "sent", ExpiresAt: &future}
	for _, task := range []*models.Task{stale, fresh} {
		if err := repo.Create(task); err != nil {
			t.Fatal(err)
		}
	}
	n, err := repo.ExpireBefore(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expired %d tasks, want 1", n)
	}
	got, _ := repo.GetByID(stale.ID)
	if got.State != "expired" {
		t.Fatalf("stale task state = %q", got.State)
	}
	got, _ = repo.GetByID(fresh.ID)
	if got.State != "sent" {
		t.Fatalf("fresh task state = %q", got.State)
	}
}

func TestSessionRepository_MarkStaleOnlyMarksOldSessions(t *testing.T) {
	db := testDB(t)
	repo := NewSessionRepository(db)
	now := time.Now()

	old := &models.Session{Base: models.Base{ID: "old"}, HealthStatus: "active", LastCheckin: now.Add(-2 * time.Hour)}
	fresh := &models.Session{Base: models.Base{ID: "fresh"}, HealthStatus: "active", LastCheckin: now}
	lost := &models.Session{Base: models.Base{ID: "lost"}, HealthStatus: "lost", LastCheckin: now.Add(-2 * time.Hour)}
	for _, s := range []*models.Session{old, fresh, lost} {
		if err := repo.Create(s); err != nil {
			t.Fatal(err)
		}
	}

	if err := repo.MarkStale(now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	gotOld, _ := repo.GetByID("old")
	if gotOld.HealthStatus != "stale" {
		t.Errorf("old session health = %q, want stale", gotOld.HealthStatus)
	}
	gotFresh, _ := repo.GetByID("fresh")
	if gotFresh.HealthStatus != "active" {
		t.Errorf("fresh session health = %q, want active", gotFresh.HealthStatus)
	}
	gotLost, _ := repo.GetByID("lost")
	if gotLost.HealthStatus != "lost" {
		t.Errorf("lost session health = %q, want lost", gotLost.HealthStatus)
	}
}
