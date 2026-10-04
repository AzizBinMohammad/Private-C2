package grpc

import (
	"context"
	"encoding/json"

	"github.com/azizbinmohammad/private-c2/pkg/engagement"
	"github.com/azizbinmohammad/private-c2/server/core"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type EngagementServer struct {
	repo     *repository.EngagementRepository
	eventBus *core.EventBus
}

func NewEngagementServer(repo *repository.EngagementRepository, eventBus *core.EventBus) *EngagementServer {
	return &EngagementServer{repo: repo, eventBus: eventBus}
}

type CreateEngagementRequest struct {
	Name                string
	Description         string
	AuthorizationRef    string
	ScopeCIDRs          []string
	ScopeHostnames      []string
	ScopeDomains        []string
	ExcludedTargets     []string
	DataCollectionLevel string
	ExfilLimitBytes     int64
	EmergencyContact    string
}

func (s *EngagementServer) Create(ctx context.Context, req CreateEngagementRequest) (*models.Engagement, error) {
	scopeConfig, _ := json.Marshal(map[string]any{
		"cidrs":     req.ScopeCIDRs,
		"hostnames": req.ScopeHostnames,
		"domains":   req.ScopeDomains,
		"excluded":  req.ExcludedTargets,
	})

	eng := &models.Engagement{
		Name:                req.Name,
		Description:         req.Description,
		AuthorizationRef:    req.AuthorizationRef,
		ScopeConfig:         string(scopeConfig),
		DataCollectionLevel: req.DataCollectionLevel,
		ExfilLimitBytes:     req.ExfilLimitBytes,
		EmergencyContact:    req.EmergencyContact,
	}

	if err := s.repo.Create(eng); err != nil {
		return nil, status.Errorf(codes.Internal, "creating engagement: %v", err)
	}

	s.eventBus.Publish(core.Event{
		Type:         core.EventEngagementStarted,
		EngagementID: eng.ID,
	})

	return eng, nil
}

func (s *EngagementServer) Get(ctx context.Context, id string) (*models.Engagement, error) {
	eng, err := s.repo.GetByID(id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "engagement not found: %v", err)
	}
	return eng, nil
}

func (s *EngagementServer) List(ctx context.Context) ([]models.Engagement, error) {
	return s.repo.List()
}

type CheckScopeRequest struct {
	EngagementID string
	TargetIP     string
	TargetHost   string
}

func (s *EngagementServer) CheckScope(ctx context.Context, req CheckScopeRequest) (bool, error) {
	eng, err := s.repo.GetByID(req.EngagementID)
	if err != nil {
		return false, status.Errorf(codes.NotFound, "engagement not found: %v", err)
	}

	var scopeConfig struct {
		CIDRs     []string `json:"cidrs"`
		Hostnames []string `json:"hostnames"`
		Domains   []string `json:"domains"`
		Excluded  []string `json:"excluded"`
	}
	if err := json.Unmarshal([]byte(eng.ScopeConfig), &scopeConfig); err != nil {
		return false, status.Errorf(codes.Internal, "invalid scope config: %v", err)
	}

	scope, err := engagement.NewScope(scopeConfig.CIDRs, scopeConfig.Hostnames, scopeConfig.Domains, scopeConfig.Excluded)
	if err != nil {
		return false, status.Errorf(codes.Internal, "building scope: %v", err)
	}

	target := req.TargetHost
	if req.TargetIP != "" {
		target = req.TargetIP
	}
	if target == "" {
		return false, status.Error(codes.InvalidArgument, "target IP or hostname required")
	}

	inScope, _ := scope.Contains(target)
	return inScope, nil
}
