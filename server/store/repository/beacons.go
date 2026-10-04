package repository

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type BeaconRepository struct {
	db *gorm.DB
}

func NewBeaconRepository(db *gorm.DB) *BeaconRepository {
	return &BeaconRepository{db: db}
}

func (r *BeaconRepository) Create(beacon *models.Beacon) error {
	return r.db.Create(beacon).Error
}

func (r *BeaconRepository) GetByID(id string) (*models.Beacon, error) {
	var beacon models.Beacon
	if err := r.db.First(&beacon, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("beacon not found: %w", err)
	}
	return &beacon, nil
}

func (r *BeaconRepository) List(engagementID string) ([]models.Beacon, error) {
	var beacons []models.Beacon
	query := r.db
	if engagementID != "" {
		query = query.Where("engagement_id = ?", engagementID)
	}
	if err := query.Find(&beacons).Error; err != nil {
		return nil, err
	}
	return beacons, nil
}

func (r *BeaconRepository) Update(beacon *models.Beacon) error {
	return r.db.Save(beacon).Error
}

func (r *BeaconRepository) Delete(id string) error {
	return r.db.Delete(&models.Beacon{}, "id = ?", id).Error
}
