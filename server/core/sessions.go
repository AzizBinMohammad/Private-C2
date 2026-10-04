package core

import (
	"sync"
	"time"
)

type SessionState string

const (
	StateConnecting   SessionState = "connecting"
	StateRegistering  SessionState = "registering"
	StateActive       SessionState = "active"
	StateStale        SessionState = "stale"
	StateLost         SessionState = "lost"
	StateDisconnected SessionState = "disconnected"
)

var validTransitions = map[SessionState][]SessionState{
	StateConnecting:   {StateRegistering, StateDisconnected},
	StateRegistering:  {StateActive, StateDisconnected},
	StateActive:       {StateStale, StateDisconnected},
	StateStale:        {StateActive, StateLost, StateDisconnected},
	StateLost:         {StateActive, StateDisconnected},
	StateDisconnected: {},
}

type LiveSession struct {
	ID           string
	State        SessionState
	LastCheckin   time.Time
	LockedBy     string
	EngagementID string
	mu           sync.RWMutex
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*LiveSession
	eventBus *EventBus

	staleThreshold time.Duration
	lostThreshold  time.Duration
}

func NewSessionManager(eventBus *EventBus, staleThreshold, lostThreshold time.Duration) *SessionManager {
	return &SessionManager{
		sessions:       make(map[string]*LiveSession),
		eventBus:       eventBus,
		staleThreshold: staleThreshold,
		lostThreshold:  lostThreshold,
	}
}

func (sm *SessionManager) Register(id, engagementID string) *LiveSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session := &LiveSession{
		ID:           id,
		State:        StateActive,
		LastCheckin:   time.Now(),
		EngagementID: engagementID,
	}
	sm.sessions[id] = session

	sm.eventBus.Publish(Event{
		Type:         EventSessionConnected,
		SessionID:    id,
		EngagementID: engagementID,
	})

	return session
}

func (sm *SessionManager) Checkin(id string) bool {
	sm.mu.RLock()
	session, ok := sm.sessions[id]
	sm.mu.RUnlock()
	if !ok {
		return false
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	oldState := session.State
	session.LastCheckin = time.Now()
	if session.State == StateStale || session.State == StateLost {
		session.State = StateActive
		sm.eventBus.Publish(Event{
			Type:      EventSessionHealthChange,
			SessionID: id,
			Data:      map[string]any{"from": oldState, "to": StateActive},
		})
	}
	return true
}

func (sm *SessionManager) Remove(id string) {
	sm.mu.Lock()
	session, ok := sm.sessions[id]
	if ok {
		delete(sm.sessions, id)
	}
	sm.mu.Unlock()

	if ok {
		session.mu.Lock()
		session.State = StateDisconnected
		session.mu.Unlock()

		sm.eventBus.Publish(Event{
			Type:      EventSessionDisconnected,
			SessionID: id,
		})
	}
}

func (sm *SessionManager) Get(id string) (*LiveSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	return s, ok
}

func (sm *SessionManager) ListAll() []*LiveSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*LiveSession, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		result = append(result, s)
	}
	return result
}

func (sm *SessionManager) TransitionCanBe(from, to SessionState) bool {
	targets, ok := validTransitions[from]
	if !ok {
		return false
	}
	for _, t := range targets {
		if t == to {
			return true
		}
	}
	return false
}

func (sm *SessionManager) RunHealthCheck() {
	sm.mu.RLock()
	sessions := make([]*LiveSession, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, s)
	}
	sm.mu.RUnlock()

	now := time.Now()
	for _, s := range sessions {
		s.mu.Lock()
		switch {
		case s.State == StateActive && now.Sub(s.LastCheckin) > sm.staleThreshold:
			s.State = StateStale
			sm.eventBus.Publish(Event{
				Type:      EventSessionHealthChange,
				SessionID: s.ID,
				Data:      map[string]any{"from": StateActive, "to": StateStale},
			})
		case s.State == StateStale && now.Sub(s.LastCheckin) > sm.lostThreshold:
			s.State = StateLost
			sm.eventBus.Publish(Event{
				Type:      EventSessionHealthChange,
				SessionID: s.ID,
				Data:      map[string]any{"from": StateStale, "to": StateLost},
			})
		}
		s.mu.Unlock()
	}
}
