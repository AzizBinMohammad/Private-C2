package repository

import (
	"time"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Insert(entry *models.AuditEntry) error {
	return r.db.Create(entry).Error
}

type AuditFilter struct {
	OperatorID   string
	EngagementID string
	SessionID    string
	EventType    string
	StartTime    *time.Time
	EndTime      *time.Time
	Page         int
	PageSize     int
}

func (r *AuditRepository) Query(filter AuditFilter) ([]models.AuditEntry, int64, error) {
	query := r.db.Model(&models.AuditEntry{})

	if filter.OperatorID != "" {
		query = query.Where("operator_id = ?", filter.OperatorID)
	}
	if filter.EngagementID != "" {
		query = query.Where("engagement_id = ?", filter.EngagementID)
	}
	if filter.SessionID != "" {
		query = query.Where("session_id = ?", filter.SessionID)
	}
	if filter.EventType != "" {
		query = query.Where("event_type = ?", filter.EventType)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if filter.PageSize <= 0 {
		filter.PageSize = 50
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	offset := (filter.Page - 1) * filter.PageSize

	var entries []models.AuditEntry
	if err := query.Order("created_at DESC").Offset(offset).Limit(filter.PageSize).Find(&entries).Error; err != nil {
		return nil, 0, err
	}

	return entries, total, nil
}

func (r *AuditRepository) VerifyChain() (bool, error) {
	var entries []models.AuditEntry
	if err := r.db.Order("created_at ASC").Find(&entries).Error; err != nil {
		return false, err
	}

	prevHash := ""
	for _, entry := range entries {
		if entry.PreviousHash != prevHash {
			return false, nil
		}
		prevHash = entry.EntryHash
	}
	return true, nil
}
