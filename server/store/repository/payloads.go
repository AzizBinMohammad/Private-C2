package repository

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

// PayloadRepository provides CRUD operations for PayloadArtifact records.
type PayloadRepository struct {
	db *gorm.DB
}

// NewPayloadRepository creates a new PayloadRepository backed by the given database.
func NewPayloadRepository(db *gorm.DB) *PayloadRepository {
	return &PayloadRepository{db: db}
}

// Create inserts a new PayloadArtifact into the database.
func (r *PayloadRepository) Create(payload *models.PayloadArtifact) error {
	return r.db.Create(payload).Error
}

// GetByID retrieves a PayloadArtifact by its primary key.
func (r *PayloadRepository) GetByID(id string) (*models.PayloadArtifact, error) {
	var payload models.PayloadArtifact
	if err := r.db.First(&payload, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("payload not found: %w", err)
	}
	return &payload, nil
}

// GetBySHA256 retrieves a PayloadArtifact by its SHA-256 hash.
func (r *PayloadRepository) GetBySHA256(hash string) (*models.PayloadArtifact, error) {
	var payload models.PayloadArtifact
	if err := r.db.First(&payload, "sha256 = ?", hash).Error; err != nil {
		return nil, fmt.Errorf("payload with hash %s not found: %w", hash, err)
	}
	return &payload, nil
}

// ListByEngagement returns all PayloadArtifacts associated with an engagement.
// If engagementID is empty, all payloads are returned.
func (r *PayloadRepository) ListByEngagement(engagementID string) ([]models.PayloadArtifact, error) {
	var payloads []models.PayloadArtifact
	query := r.db
	if engagementID != "" {
		query = query.Where("engagement_id = ?", engagementID)
	}
	// Omit BinaryData from list queries for performance.
	if err := query.Select("id, created_at, updated_at, deleted_at, created_by, target_os, target_arch, mode, transports, format, sha256, file_size, implant_id, public_key, engagement_id, c2_profile_id, expiry, status").
		Find(&payloads).Error; err != nil {
		return nil, err
	}
	return payloads, nil
}

// ListByOperator returns all PayloadArtifacts created by a specific operator.
func (r *PayloadRepository) ListByOperator(operatorID string) ([]models.PayloadArtifact, error) {
	var payloads []models.PayloadArtifact
	if err := r.db.Where("created_by = ?", operatorID).
		Select("id, created_at, updated_at, deleted_at, created_by, target_os, target_arch, mode, transports, format, sha256, file_size, implant_id, public_key, engagement_id, c2_profile_id, expiry, status").
		Find(&payloads).Error; err != nil {
		return nil, err
	}
	return payloads, nil
}

// Delete soft-deletes a PayloadArtifact by its ID.
func (r *PayloadRepository) Delete(id string) error {
	return r.db.Delete(&models.PayloadArtifact{}, "id = ?", id).Error
}

// UpdateStatus changes the status of a PayloadArtifact (e.g., active -> revoked).
func (r *PayloadRepository) UpdateStatus(id, status string) error {
	result := r.db.Model(&models.PayloadArtifact{}).
		Where("id = ?", id).
		Update("status", status)
	if result.RowsAffected == 0 {
		return fmt.Errorf("payload %s not found", id)
	}
	return result.Error
}

// GetBinaryData retrieves only the binary data for a payload, used for download.
func (r *PayloadRepository) GetBinaryData(id string) ([]byte, error) {
	var payload models.PayloadArtifact
	if err := r.db.Select("binary_data").First(&payload, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("payload not found: %w", err)
	}
	if len(payload.BinaryData) == 0 {
		return nil, fmt.Errorf("no binary data for payload %s", id)
	}
	return payload.BinaryData, nil
}
