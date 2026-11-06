package repository

import (
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type SessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(session *models.Session) error {
	return r.db.Create(session).Error
}

func (r *SessionRepository) GetByID(id string) (*models.Session, error) {
	var session models.Session
	if err := r.db.First(&session, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}
	return &session, nil
}

func (r *SessionRepository) List(engagementID string) ([]models.Session, error) {
	var sessions []models.Session
	query := r.db
	if engagementID != "" {
		query = query.Where("engagement_id = ?", engagementID)
	}
	if err := query.Find(&sessions).Error; err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *SessionRepository) Update(session *models.Session) error {
	return r.db.Save(session).Error
}

func (r *SessionRepository) Delete(id string) error {
	return r.db.Delete(&models.Session{}, "id = ?", id).Error
}

func (r *SessionRepository) Lock(id, operatorID string) error {
	result := r.db.Model(&models.Session{}).
		Where("id = ? AND (locked_by = '' OR locked_by = ?)", id, operatorID).
		Update("locked_by", operatorID)
	if result.RowsAffected == 0 {
		return fmt.Errorf("session %s is locked by another operator", id)
	}
	return result.Error
}

func (r *SessionRepository) Unlock(id, operatorID string) error {
	result := r.db.Model(&models.Session{}).
		Where("id = ? AND locked_by = ?", id, operatorID).
		Update("locked_by", "")
	if result.RowsAffected == 0 {
		return fmt.Errorf("session %s is not locked by operator %s", id, operatorID)
	}
	return result.Error
}

// Checkin updates the last-seen timestamp and marks the session active.
func (r *SessionRepository) Checkin(id string, at time.Time) error {
	return r.db.Model(&models.Session{}).Where("id = ?", id).
		Updates(map[string]any{"last_checkin": at, "health_status": "active"}).Error
}

// Disconnect marks a session as disconnected. It is intentionally not a
// delete: the history remains available to operators.
func (r *SessionRepository) Disconnect(id string, at time.Time) error {
	return r.db.Model(&models.Session{}).Where("id = ?", id).
		Updates(map[string]any{
			"health_status": "disconnected",
			"last_checkin":  at,
		}).Error
}

// MarkAllLiveDisconnected is called at server startup. Sessions that were
// active when the process stopped cannot still be live, and must not be shown
// as such after the restart.
func (r *SessionRepository) MarkAllLiveDisconnected() error {
	return r.db.Model(&models.Session{}).
		Where("health_status IN ?", []string{"active", "stale"}).
		Update("health_status", "disconnected").Error
}

func (r *SessionRepository) UpdateHealth(id, status string, latencyMs, jitterMs float64) error {
	return r.db.Model(&models.Session{}).Where("id = ?", id).
		Updates(map[string]any{
			"health_status": status,
			"latency_ms":    latencyMs,
			"jitter_ms":     jitterMs,
		}).Error
}

// MarkStale marks sessions whose last check-in predates before. The previous
// implementation had no predicate and marked every session stale, including
// sessions that were actively checking in.
func (r *SessionRepository) MarkStale(before time.Time) error {
	return r.db.Model(&models.Session{}).
		Where("health_status IN ?", []string{"active", "stale"}).
		Where("last_checkin < ?", before).
		Update("health_status", "stale").Error
}
