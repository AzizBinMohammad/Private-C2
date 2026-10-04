package repository

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

// OTRepository provides data access for OT assessment records.
type OTRepository struct {
	db *gorm.DB
}

// NewOTRepository creates a new OT repository.
func NewOTRepository(db *gorm.DB) *OTRepository {
	return &OTRepository{db: db}
}

// AutoMigrate creates or updates OT tables.
func (r *OTRepository) AutoMigrate() error {
	return r.db.AutoMigrate(
		&models.OTAssetRecord{},
		&models.OTCredentialFinding{},
		&models.OTVulnFinding{},
		&models.OTSegmentationGap{},
		&models.OTComplianceFinding{},
		&models.OTTopologyEdge{},
		&models.OTCaptureSession{},
		&models.OTAssessmentReport{},
		&models.OTHMIFinding{},
		&models.OTWirelessFinding{},
	)
}

// --- OT Asset CRUD ---

func (r *OTRepository) CreateAsset(asset *models.OTAssetRecord) error {
	return r.db.Create(asset).Error
}

func (r *OTRepository) GetAssetByID(id string) (*models.OTAssetRecord, error) {
	var asset models.OTAssetRecord
	if err := r.db.First(&asset, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("OT asset not found: %w", err)
	}
	return &asset, nil
}

func (r *OTRepository) GetAssetByIP(engagementID, ip string) (*models.OTAssetRecord, error) {
	var asset models.OTAssetRecord
	if err := r.db.Where("engagement_id = ? AND ip = ?", engagementID, ip).First(&asset).Error; err != nil {
		return nil, fmt.Errorf("OT asset not found: %w", err)
	}
	return &asset, nil
}

func (r *OTRepository) ListAssets(engagementID string) ([]models.OTAssetRecord, error) {
	var assets []models.OTAssetRecord
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

func (r *OTRepository) UpdateAsset(asset *models.OTAssetRecord) error {
	return r.db.Save(asset).Error
}

func (r *OTRepository) DeleteAsset(id string) error {
	return r.db.Delete(&models.OTAssetRecord{}, "id = ?", id).Error
}

// --- Credential Findings ---

func (r *OTRepository) CreateCredentialFinding(finding *models.OTCredentialFinding) error {
	return r.db.Create(finding).Error
}

func (r *OTRepository) ListCredentialFindings(engagementID string) ([]models.OTCredentialFinding, error) {
	var findings []models.OTCredentialFinding
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}

// --- Vulnerability Findings ---

func (r *OTRepository) CreateVulnFinding(finding *models.OTVulnFinding) error {
	return r.db.Create(finding).Error
}

func (r *OTRepository) ListVulnFindings(engagementID string) ([]models.OTVulnFinding, error) {
	var findings []models.OTVulnFinding
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}

func (r *OTRepository) GetVulnFindingsBySeverity(engagementID, severity string) ([]models.OTVulnFinding, error) {
	var findings []models.OTVulnFinding
	if err := r.db.Where("engagement_id = ? AND severity = ?", engagementID, severity).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}

// --- Segmentation Gaps ---

func (r *OTRepository) CreateSegmentationGap(gap *models.OTSegmentationGap) error {
	return r.db.Create(gap).Error
}

func (r *OTRepository) ListSegmentationGaps(engagementID string) ([]models.OTSegmentationGap, error) {
	var gaps []models.OTSegmentationGap
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&gaps).Error; err != nil {
		return nil, err
	}
	return gaps, nil
}

// --- Compliance Findings ---

func (r *OTRepository) CreateComplianceFinding(finding *models.OTComplianceFinding) error {
	return r.db.Create(finding).Error
}

func (r *OTRepository) ListComplianceFindings(engagementID string) ([]models.OTComplianceFinding, error) {
	var findings []models.OTComplianceFinding
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}

func (r *OTRepository) ListComplianceByFramework(engagementID, framework string) ([]models.OTComplianceFinding, error) {
	var findings []models.OTComplianceFinding
	if err := r.db.Where("engagement_id = ? AND framework = ?", engagementID, framework).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}

// --- Topology Edges ---

func (r *OTRepository) CreateTopologyEdge(edge *models.OTTopologyEdge) error {
	return r.db.Create(edge).Error
}

func (r *OTRepository) ListTopologyEdges(engagementID string) ([]models.OTTopologyEdge, error) {
	var edges []models.OTTopologyEdge
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&edges).Error; err != nil {
		return nil, err
	}
	return edges, nil
}

// --- Capture Sessions ---

func (r *OTRepository) CreateCaptureSession(session *models.OTCaptureSession) error {
	return r.db.Create(session).Error
}

func (r *OTRepository) ListCaptureSessions(engagementID string) ([]models.OTCaptureSession, error) {
	var sessions []models.OTCaptureSession
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&sessions).Error; err != nil {
		return nil, err
	}
	return sessions, nil
}

// --- Assessment Reports ---

func (r *OTRepository) CreateReport(report *models.OTAssessmentReport) error {
	return r.db.Create(report).Error
}

func (r *OTRepository) GetReportByID(id string) (*models.OTAssessmentReport, error) {
	var report models.OTAssessmentReport
	if err := r.db.First(&report, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("OT report not found: %w", err)
	}
	return &report, nil
}

func (r *OTRepository) ListReports(engagementID string) ([]models.OTAssessmentReport, error) {
	var reports []models.OTAssessmentReport
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&reports).Error; err != nil {
		return nil, err
	}
	return reports, nil
}

// --- HMI Findings ---

func (r *OTRepository) CreateHMIFinding(finding *models.OTHMIFinding) error {
	return r.db.Create(finding).Error
}

func (r *OTRepository) ListHMIFindings(engagementID string) ([]models.OTHMIFinding, error) {
	var findings []models.OTHMIFinding
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}

// --- Wireless Findings ---

func (r *OTRepository) CreateWirelessFinding(finding *models.OTWirelessFinding) error {
	return r.db.Create(finding).Error
}

func (r *OTRepository) ListWirelessFindings(engagementID string) ([]models.OTWirelessFinding, error) {
	var findings []models.OTWirelessFinding
	if err := r.db.Where("engagement_id = ?", engagementID).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}

// --- Bulk Operations ---

func (r *OTRepository) BulkCreateAssets(assets []models.OTAssetRecord) error {
	return r.db.CreateInBatches(assets, 100).Error
}

func (r *OTRepository) BulkCreateVulnFindings(findings []models.OTVulnFinding) error {
	return r.db.CreateInBatches(findings, 100).Error
}

// --- Statistics ---

func (r *OTRepository) GetAssetCount(engagementID string) (int64, error) {
	var count int64
	if err := r.db.Model(&models.OTAssetRecord{}).Where("engagement_id = ?", engagementID).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *OTRepository) GetVulnCountBySeverity(engagementID string) (map[string]int64, error) {
	type result struct {
		Severity string
		Count    int64
	}
	var results []result
	if err := r.db.Model(&models.OTVulnFinding{}).
		Select("severity, count(*) as count").
		Where("engagement_id = ?", engagementID).
		Group("severity").
		Scan(&results).Error; err != nil {
		return nil, err
	}

	counts := make(map[string]int64)
	for _, r := range results {
		counts[r.Severity] = r.Count
	}
	return counts, nil
}
