package grpc

import (
	"context"

	"github.com/azizbinmohammad/private-c2/server/core"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type OperatorServer struct {
	sessions   *repository.SessionRepository
	sessionMgr *core.SessionManager
	eventBus   *core.EventBus
}

func NewOperatorServer(
	sessions *repository.SessionRepository,
	sessionMgr *core.SessionManager,
	eventBus *core.EventBus,
) *OperatorServer {
	return &OperatorServer{
		sessions:   sessions,
		sessionMgr: sessionMgr,
		eventBus:   eventBus,
	}
}

type ListSessionsRequest struct {
	EngagementID string
}

type SessionInfo struct {
	ID           string
	Hostname     string
	Username     string
	OS           string
	Arch         string
	Transport    string
	HealthStatus string
	LockedBy     string
}

func (s *OperatorServer) ListSessions(ctx context.Context, engagementID string) ([]SessionInfo, error) {
	dbSessions, err := s.sessions.List(engagementID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing sessions: %v", err)
	}

	result := make([]SessionInfo, len(dbSessions))
	for i, sess := range dbSessions {
		result[i] = SessionInfo{
			ID:           sess.ID,
			Hostname:     sess.Hostname,
			Username:     sess.Username,
			OS:           sess.OS,
			Arch:         sess.Arch,
			Transport:    sess.Transport,
			HealthStatus: sess.HealthStatus,
			LockedBy:     sess.LockedBy,
		}

		if live, ok := s.sessionMgr.Get(sess.ID); ok {
			result[i].HealthStatus = string(live.State)
		}
	}

	return result, nil
}

func (s *OperatorServer) GetSession(ctx context.Context, id string) (*SessionInfo, error) {
	sess, err := s.sessions.GetByID(id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "session not found: %v", err)
	}

	info := &SessionInfo{
		ID:           sess.ID,
		Hostname:     sess.Hostname,
		Username:     sess.Username,
		OS:           sess.OS,
		Arch:         sess.Arch,
		Transport:    sess.Transport,
		HealthStatus: sess.HealthStatus,
		LockedBy:     sess.LockedBy,
	}

	if live, ok := s.sessionMgr.Get(sess.ID); ok {
		info.HealthStatus = string(live.State)
	}

	return info, nil
}

func (s *OperatorServer) LockSession(ctx context.Context, sessionID, operatorID string) error {
	return s.sessions.Lock(sessionID, operatorID)
}

func (s *OperatorServer) UnlockSession(ctx context.Context, sessionID, operatorID string) error {
	return s.sessions.Unlock(sessionID, operatorID)
}
