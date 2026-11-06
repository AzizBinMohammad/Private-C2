package repository

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

// LootRepository stores loot metadata. Blob bytes live on disk and are managed
// by the API handler, which keeps the database free of large payloads.
type LootRepository struct {
	db *gorm.DB
}

func NewLootRepository(db *gorm.DB) *LootRepository {
	return &LootRepository{db: db}
}

func (r *LootRepository) Create(artifact *models.LootArtifact) error {
	if err := r.db.Create(artifact).Error; err != nil {
		return fmt.Errorf("create loot artifact: %w", err)
	}
	return nil
}

func (r *LootRepository) Get(id string) (*models.LootArtifact, error) {
	var artifact models.LootArtifact
	if err := r.db.First(&artifact, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("loot artifact %s: %w", id, err)
	}
	return &artifact, nil
}

// List returns metadata newest first, optionally filtered by engagement/kind.
func (r *LootRepository) List(engagementID, kind string, limit int) ([]models.LootArtifact, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := r.db.Model(&models.LootArtifact{})
	if engagementID != "" {
		query = query.Where("engagement_id = ?", engagementID)
	}
	if kind != "" {
		query = query.Where("kind = ?", kind)
	}
	var artifacts []models.LootArtifact
	if err := query.Order("created_at DESC").Limit(limit).Find(&artifacts).Error; err != nil {
		return nil, err
	}
	return artifacts, nil
}

func (r *LootRepository) Delete(id string) error {
	res := r.db.Delete(&models.LootArtifact{}, "id = ?", id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
