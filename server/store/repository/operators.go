package repository

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type OperatorRepository struct {
	db *gorm.DB
}

func NewOperatorRepository(db *gorm.DB) *OperatorRepository {
	return &OperatorRepository{db: db}
}

func (r *OperatorRepository) Create(operator *models.Operator) error {
	return r.db.Create(operator).Error
}

func (r *OperatorRepository) GetByID(id string) (*models.Operator, error) {
	var operator models.Operator
	if err := r.db.First(&operator, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("operator not found: %w", err)
	}
	return &operator, nil
}

func (r *OperatorRepository) GetByName(name string) (*models.Operator, error) {
	var operator models.Operator
	if err := r.db.First(&operator, "name = ?", name).Error; err != nil {
		return nil, fmt.Errorf("operator not found: %w", err)
	}
	return &operator, nil
}

func (r *OperatorRepository) List() ([]models.Operator, error) {
	var operators []models.Operator
	if err := r.db.Find(&operators).Error; err != nil {
		return nil, err
	}
	return operators, nil
}

func (r *OperatorRepository) Update(operator *models.Operator) error {
	return r.db.Save(operator).Error
}

func (r *OperatorRepository) Delete(id string) error {
	return r.db.Delete(&models.Operator{}, "id = ?", id).Error
}

func (r *OperatorRepository) UpdateLastActive(id, sourceIP string) error {
	return r.db.Model(&models.Operator{}).Where("id = ?", id).
		Updates(map[string]any{
			"source_ip": sourceIP,
		}).Error
}
