package repository

import (
	"fmt"

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

func (r *SessionRepository) UpdateHealth(id, status string, latencyMs, jitterMs float64) error {
	return r.db.Model(&models.Session{}).Where("id = ?", id).
		Updates(map[string]any{
			"health_status": status,
			"latency_ms":    latencyMs,
			"jitter_ms":     jitterMs,
		}).Error
}

func (r *SessionRepository) MarkStale() error {
	return r.db.Model(&models.Session{}).
		Where("health_status != ?", "lost").
		Update("health_status", "stale").Error
}
