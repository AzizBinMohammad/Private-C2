package repository

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type EngagementRepository struct {
	db *gorm.DB
}

func NewEngagementRepository(db *gorm.DB) *EngagementRepository {
	return &EngagementRepository{db: db}
}

func (r *EngagementRepository) Create(engagement *models.Engagement) error {
	return r.db.Create(engagement).Error
}

func (r *EngagementRepository) GetByID(id string) (*models.Engagement, error) {
	var engagement models.Engagement
	if err := r.db.First(&engagement, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("engagement not found: %w", err)
	}
	return &engagement, nil
}

func (r *EngagementRepository) List() ([]models.Engagement, error) {
	var engagements []models.Engagement
	if err := r.db.Find(&engagements).Error; err != nil {
		return nil, err
	}
	return engagements, nil
}

func (r *EngagementRepository) Update(engagement *models.Engagement) error {
	return r.db.Save(engagement).Error
}

func (r *EngagementRepository) UpdateStatus(id, status string) error {
	return r.db.Model(&models.Engagement{}).
		Where("id = ?", id).
		Update("status", status).Error
}

func (r *EngagementRepository) Delete(id string) error {
	return r.db.Delete(&models.Engagement{}, "id = ?", id).Error
}

func (r *EngagementRepository) GetOperatorEngagements(operatorID string) ([]models.Engagement, error) {
	var operator models.Operator
	if err := r.db.Preload("Engagements").First(&operator, "id = ?", operatorID).Error; err != nil {
		return nil, fmt.Errorf("operator not found: %w", err)
	}
	return operator.Engagements, nil
}
