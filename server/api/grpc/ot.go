package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/server/api/middleware"
	"github.com/azizbinmohammad/private-c2/server/core"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
)

// OT event types.
const (
	EventOTAssetDiscovered   core.EventType = "ot.asset.discovered"
	EventOTVulnFound         core.EventType = "ot.vuln.found"
	EventOTCredentialFound   core.EventType = "ot.credential.found"
	EventOTAssessmentStarted core.EventType = "ot.assessment.started"
	EventOTAssessmentEnded   core.EventType = "ot.assessment.ended"
	EventOTReportGenerated   core.EventType = "ot.report.generated"
	EventOTEmergencyStop     core.EventType = "ot.emergency.stop"
)

// OTServer handles OT assessment gRPC requests.
// This server is NOT registered with gRPC reflection to remain hidden.
type OTServer struct {
	repo     *repository.OTRepository
	eventBus *core.EventBus
}

// NewOTServer creates a new OT gRPC server.
func NewOTServer(repo *repository.OTRepository, eventBus *core.EventBus) *OTServer {
	return &OTServer{repo: repo, eventBus: eventBus}
}

// requireOTPermission checks that the caller has ot.assess permission.
func (s *OTServer) requireOTPermission(ctx context.Context) error {
	role := middleware.GetOperatorRole(ctx)
	if !middleware.HasPermission(role, middleware.PermOTAssess) {
		return fmt.Errorf("permission denied: ot.assess required")
	}
	return nil
}

// --- Asset Management ---

// CreateAsset records a discovered OT asset.
func (s *OTServer) CreateAsset(ctx context.Context, asset *models.OTAssetRecord) (*models.OTAssetRecord, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}

	asset.FirstSeen = time.Now()
	asset.LastSeen = time.Now()

	if err := s.repo.CreateAsset(asset); err != nil {
		return nil, fmt.Errorf("creating OT asset: %w", err)
	}

	s.eventBus.Publish(core.Event{
		Type:         EventOTAssetDiscovered,
		EngagementID: asset.EngagementID,
		OperatorID:   middleware.GetOperatorID(ctx),
		Data:         asset,
	})

	return asset, nil
}

// GetAsset retrieves an OT asset by ID.
func (s *OTServer) GetAsset(ctx context.Context, id string) (*models.OTAssetRecord, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.GetAssetByID(id)
}

// ListAssets retrieves all OT assets for an engagement.
func (s *OTServer) ListAssets(ctx context.Context, engagementID string) ([]models.OTAssetRecord, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListAssets(engagementID)
}

// --- Vulnerability Management ---

// RecordVulnFinding saves a vulnerability finding.
func (s *OTServer) RecordVulnFinding(ctx context.Context, finding *models.OTVulnFinding) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}

	if err := s.repo.CreateVulnFinding(finding); err != nil {
		return fmt.Errorf("recording vulnerability: %w", err)
	}

	s.eventBus.Publish(core.Event{
		Type:         EventOTVulnFound,
		EngagementID: finding.EngagementID,
		OperatorID:   middleware.GetOperatorID(ctx),
		Data:         finding,
	})

	return nil
}

// ListVulnFindings retrieves vulnerability findings for an engagement.
func (s *OTServer) ListVulnFindings(ctx context.Context, engagementID string) ([]models.OTVulnFinding, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListVulnFindings(engagementID)
}

// --- Credential Management ---

// RecordCredentialFinding saves a credential finding.
func (s *OTServer) RecordCredentialFinding(ctx context.Context, finding *models.OTCredentialFinding) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}

	if err := s.repo.CreateCredentialFinding(finding); err != nil {
		return fmt.Errorf("recording credential finding: %w", err)
	}

	s.eventBus.Publish(core.Event{
		Type:         EventOTCredentialFound,
		EngagementID: finding.EngagementID,
		OperatorID:   middleware.GetOperatorID(ctx),
		Data:         finding,
	})

	return nil
}

// ListCredentialFindings retrieves credential findings.
func (s *OTServer) ListCredentialFindings(ctx context.Context, engagementID string) ([]models.OTCredentialFinding, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListCredentialFindings(engagementID)
}

// --- Segmentation ---

// RecordSegmentationGap saves a segmentation gap.
func (s *OTServer) RecordSegmentationGap(ctx context.Context, gap *models.OTSegmentationGap) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}
	return s.repo.CreateSegmentationGap(gap)
}

// ListSegmentationGaps retrieves segmentation gaps.
func (s *OTServer) ListSegmentationGaps(ctx context.Context, engagementID string) ([]models.OTSegmentationGap, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListSegmentationGaps(engagementID)
}

// --- Compliance ---

// RecordComplianceFinding saves a compliance finding.
func (s *OTServer) RecordComplianceFinding(ctx context.Context, finding *models.OTComplianceFinding) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}
	return s.repo.CreateComplianceFinding(finding)
}

// ListComplianceFindings retrieves compliance findings.
func (s *OTServer) ListComplianceFindings(ctx context.Context, engagementID string) ([]models.OTComplianceFinding, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListComplianceFindings(engagementID)
}

// --- Topology ---

// RecordTopologyEdge saves a topology connection.
func (s *OTServer) RecordTopologyEdge(ctx context.Context, edge *models.OTTopologyEdge) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}
	return s.repo.CreateTopologyEdge(edge)
}

// ListTopologyEdges retrieves topology edges.
func (s *OTServer) ListTopologyEdges(ctx context.Context, engagementID string) ([]models.OTTopologyEdge, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListTopologyEdges(engagementID)
}

// --- Traffic Capture ---

// RecordCaptureSession saves traffic capture metadata.
func (s *OTServer) RecordCaptureSession(ctx context.Context, session *models.OTCaptureSession) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}
	return s.repo.CreateCaptureSession(session)
}

// --- Reports ---

// GenerateReport creates and stores an assessment report.
func (s *OTServer) GenerateReport(ctx context.Context, report *models.OTAssessmentReport) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}

	report.GeneratedAt = time.Now()
	report.GeneratedBy = middleware.GetOperatorID(ctx)

	if err := s.repo.CreateReport(report); err != nil {
		return fmt.Errorf("saving report: %w", err)
	}

	s.eventBus.Publish(core.Event{
		Type:         EventOTReportGenerated,
		EngagementID: report.EngagementID,
		OperatorID:   middleware.GetOperatorID(ctx),
		Data:         report,
	})

	return nil
}

// GetReport retrieves a report by ID.
func (s *OTServer) GetReport(ctx context.Context, id string) (*models.OTAssessmentReport, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.GetReportByID(id)
}

// ListReports retrieves reports for an engagement.
func (s *OTServer) ListReports(ctx context.Context, engagementID string) ([]models.OTAssessmentReport, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListReports(engagementID)
}

// --- HMI Findings ---

// RecordHMIFinding saves an HMI finding.
func (s *OTServer) RecordHMIFinding(ctx context.Context, finding *models.OTHMIFinding) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}
	return s.repo.CreateHMIFinding(finding)
}

// ListHMIFindings retrieves HMI findings.
func (s *OTServer) ListHMIFindings(ctx context.Context, engagementID string) ([]models.OTHMIFinding, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListHMIFindings(engagementID)
}

// --- Wireless Findings ---

// RecordWirelessFinding saves a wireless finding.
func (s *OTServer) RecordWirelessFinding(ctx context.Context, finding *models.OTWirelessFinding) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}
	return s.repo.CreateWirelessFinding(finding)
}

// ListWirelessFindings retrieves wireless findings.
func (s *OTServer) ListWirelessFindings(ctx context.Context, engagementID string) ([]models.OTWirelessFinding, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}
	return s.repo.ListWirelessFindings(engagementID)
}

// --- Statistics ---

// GetOTStats returns OT assessment statistics.
func (s *OTServer) GetOTStats(ctx context.Context, engagementID string) (map[string]any, error) {
	if err := s.requireOTPermission(ctx); err != nil {
		return nil, err
	}

	assetCount, _ := s.repo.GetAssetCount(engagementID)
	vulnCounts, _ := s.repo.GetVulnCountBySeverity(engagementID)

	return map[string]any{
		"asset_count":         assetCount,
		"vuln_counts":         vulnCounts,
	}, nil
}

// --- Emergency Stop ---

// EmergencyStop triggers an emergency stop for OT assessment.
func (s *OTServer) EmergencyStop(ctx context.Context, engagementID, reason string) error {
	if err := s.requireOTPermission(ctx); err != nil {
		return err
	}

	s.eventBus.Publish(core.Event{
		Type:         EventOTEmergencyStop,
		EngagementID: engagementID,
		OperatorID:   middleware.GetOperatorID(ctx),
		Data:         map[string]string{"reason": reason},
	})

	return nil
}
