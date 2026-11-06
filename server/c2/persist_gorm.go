package c2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
)

// GORMPersistence adapts the live C2 handler to the GORM repositories.
type GORMPersistence struct {
	sessions *repository.SessionRepository
	tasks    *repository.TaskRepository
}

func NewGORMPersistence(sessions *repository.SessionRepository, tasks *repository.TaskRepository) *GORMPersistence {
	return &GORMPersistence{sessions: sessions, tasks: tasks}
}

func (p *GORMPersistence) SessionRegistered(_ context.Context, session *ImplantSession) error {
	row := &models.Session{
		Base:         models.Base{ID: session.ID, CreatedAt: session.CreatedAt},
		Hostname:     session.Hostname,
		Username:     session.Username,
		OS:           session.OS,
		Arch:         session.Arch,
		RemoteAddr:   session.RemoteAddr,
		Transport:    session.Transport,
		Mode:         session.Mode,
		Elevated:     session.Elevated,
		HealthStatus: "active",
		EngagementID: session.EngagementID,
		LockedBy:     session.LockedBy,
		ImplantID:    session.ImplantID,
		PID:          session.PID,
		ProcessName:  session.Process,
		LastCheckin:  session.LastCheckin,
	}
	if err := p.sessions.Create(row); err != nil {
		return fmt.Errorf("persist session registration: %w", err)
	}
	return nil
}

func (p *GORMPersistence) SessionCheckin(_ context.Context, sessionID string, at time.Time) error {
	return p.sessions.Checkin(sessionID, at)
}

func (p *GORMPersistence) SessionDisconnected(_ context.Context, sessionID string, at time.Time) error {
	return p.sessions.Disconnect(sessionID, at)
}

func (p *GORMPersistence) PendingTasks(_ context.Context, implantID string) ([]*Task, error) {
	rows, err := p.tasks.ListByImplant(implantID)
	if err != nil {
		return nil, err
	}
	out := make([]*Task, 0, len(rows))
	for _, row := range rows {
		out = append(out, &Task{
			ID:           row.ID,
			Type:         row.Type,
			Args:         row.Args,
			SessionID:    row.SessionID,
			ImplantID:    row.ImplantID,
			EngagementID: row.EngagementID,
			TimeoutMs:    row.TimeoutMs,
			CreatedAt:    row.CreatedAt,
		})
	}
	return out, nil
}

func (p *GORMPersistence) TaskQueued(_ context.Context, task *Task) error {
	row := &models.Task{
		ID:           task.ID,
		CreatedAt:    task.CreatedAt,
		SessionID:    task.SessionID,
		ImplantID:    task.ImplantID,
		EngagementID: task.EngagementID,
		Type:         task.Type,
		Args:         task.Args,
		State:        "queued",
		TimeoutMs:    task.TimeoutMs,
	}
	if err := p.tasks.Create(row); err != nil {
		return fmt.Errorf("persist queued task: %w", err)
	}
	return nil
}

func (p *GORMPersistence) TaskDispatched(_ context.Context, taskIDs []string, at time.Time) error {
	for _, id := range taskIDs {
		if err := p.tasks.MarkSent(id, at); err != nil && !errors.Is(err, repository.ErrTaskNotQueued) {
			return err
		}
	}
	return nil
}

func (p *GORMPersistence) TaskCompleted(_ context.Context, result *TaskResult) error {
	row := &models.TaskResult{
		TaskID:      result.TaskID,
		SessionID:   result.SessionID,
		Success:     result.Success,
		Output:      result.Output,
		Error:       result.Error,
		Truncated:   result.Truncated,
		Bytes:       result.Bytes,
		CompletedAt: result.CompletedAt,
	}
	if err := p.tasks.Complete(row); err != nil {
		return fmt.Errorf("persist task result: %w", err)
	}
	return nil
}

func (p *GORMPersistence) MarkLiveSessionsDisconnected(context.Context) error {
	return p.sessions.MarkAllLiveDisconnected()
}
