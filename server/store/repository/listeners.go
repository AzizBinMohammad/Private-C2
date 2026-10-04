package repository

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type ListenerRepository struct {
	db *gorm.DB
}

func NewListenerRepository(db *gorm.DB) *ListenerRepository {
	return &ListenerRepository{db: db}
}

func (r *ListenerRepository) Create(listener *models.Listener) error {
	return r.db.Create(listener).Error
}

func (r *ListenerRepository) GetByID(id string) (*models.Listener, error) {
	var listener models.Listener
	if err := r.db.First(&listener, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("listener not found: %w", err)
	}
	return &listener, nil
}

func (r *ListenerRepository) List(engagementID string) ([]models.Listener, error) {
	var listeners []models.Listener
	query := r.db
	if engagementID != "" {
		query = query.Where("engagement_id = ?", engagementID)
	}
	if err := query.Find(&listeners).Error; err != nil {
		return nil, err
	}
	return listeners, nil
}

func (r *ListenerRepository) UpdateStatus(id, status string) error {
	return r.db.Model(&models.Listener{}).Where("id = ?", id).
		Update("status", status).Error
}

func (r *ListenerRepository) Delete(id string) error {
	return r.db.Delete(&models.Listener{}, "id = ?", id).Error
}

func (r *ListenerRepository) IncrementConnections(id string) error {
	return r.db.Model(&models.Listener{}).Where("id = ?", id).
		UpdateColumn("active_connections", gorm.Expr("active_connections + 1")).Error
}

func (r *ListenerRepository) DecrementConnections(id string) error {
	return r.db.Model(&models.Listener{}).Where("id = ?", id).
		UpdateColumn("active_connections", gorm.Expr("CASE WHEN active_connections > 0 THEN active_connections - 1 ELSE 0 END")).Error
}
