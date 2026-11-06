package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrTaskNotQueued is returned when a state transition is attempted on a task
// that is no longer in the expected state.
var ErrTaskNotQueued = errors.New("task is not queued")

// TaskRepository persists operator task intent and results.
type TaskRepository struct {
	db *gorm.DB
}

func NewTaskRepository(db *gorm.DB) *TaskRepository {
	return &TaskRepository{db: db}
}

func (r *TaskRepository) Create(task *models.Task) error {
	if err := r.db.Create(task).Error; err != nil {
		return fmt.Errorf("create task: %w", err)
	}
	return nil
}

func (r *TaskRepository) GetByID(id string) (*models.Task, error) {
	var task models.Task
	if err := r.db.First(&task, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("task %s: %w", id, err)
	}
	return &task, nil
}

// ListBySession returns the most recent tasks for a session.
func (r *TaskRepository) ListBySession(sessionID string, limit int) ([]models.Task, error) {
	if limit <= 0 {
		limit = 100
	}
	var tasks []models.Task
	if err := r.db.Where("session_id = ?", sessionID).
		Order("created_at DESC").Limit(limit).Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

// ListByImplant returns queued tasks that can be rebound to a new session for
// the same implant after a reconnect or server restart.
func (r *TaskRepository) ListByImplant(implantID string) ([]models.Task, error) {
	var tasks []models.Task
	if err := r.db.Where("implant_id = ? AND state = ?", implantID, "queued").
		Order("created_at ASC").Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

// MarkSent transitions a queued task to sent. It is a no-op error when the task
// has already been sent (for example, a duplicate dispatch).
func (r *TaskRepository) MarkSent(id string, sentAt time.Time) error {
	res := r.db.Model(&models.Task{}).
		Where("id = ? AND state = ?", id, "queued").
		Updates(map[string]any{
			"state":    "sent",
			"sent_at":  sentAt,
			"attempts": gorm.Expr("attempts + 1"),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrTaskNotQueued
	}
	return nil
}

func (r *TaskRepository) MarkStarted(id string, startedAt time.Time) error {
	res := r.db.Model(&models.Task{}).
		Where("id = ? AND state IN ?", id, []string{"queued", "sent"}).
		Updates(map[string]any{"state": "running", "started_at": startedAt})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrTaskNotQueued
	}
	return nil
}

// Complete stores a result and marks the task completed in one transaction.
// Inserting the result is idempotent on TaskID.
func (r *TaskRepository) Complete(result *models.TaskResult) error {
	if result == nil || result.TaskID == "" {
		return fmt.Errorf("complete task: missing result task ID")
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(result).Error; err != nil {
			return fmt.Errorf("store result: %w", err)
		}
		now := result.CompletedAt
		if now.IsZero() {
			now = time.Now()
		}
		if err := tx.Model(&models.Task{}).Where("id = ?", result.TaskID).
			Updates(map[string]any{"state": "completed", "completed_at": now}).Error; err != nil {
			return fmt.Errorf("mark task completed: %w", err)
		}
		return nil
	})
}

// ExpireBefore marks stale sent/running tasks as expired. It returns the
// number of rows changed.
func (r *TaskRepository) ExpireBefore(cutoff time.Time) (int64, error) {
	res := r.db.Model(&models.Task{}).
		Where("state IN ?", []string{"sent", "running"}).
		Where("expires_at IS NOT NULL AND expires_at < ?", cutoff).
		Update("state", "expired")
	return res.RowsAffected, res.Error
}

func (r *TaskRepository) Cancel(id string) error {
	res := r.db.Model(&models.Task{}).
		Where("id = ? AND state IN ?", id, []string{"queued", "sent", "running"}).
		Updates(map[string]any{"state": "cancelled", "completed_at": time.Now()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrTaskNotQueued
	}
	return nil
}
