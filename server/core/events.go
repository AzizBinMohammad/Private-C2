package core

import (
	"sync"
)

type EventType string

const (
	EventSessionConnected    EventType = "session.connected"
	EventSessionDisconnected EventType = "session.disconnected"
	EventSessionHealthChange EventType = "session.health_change"
	EventBeaconCheckin       EventType = "beacon.checkin"
	EventListenerStarted     EventType = "listener.started"
	EventListenerStopped     EventType = "listener.stopped"
	EventTaskQueued          EventType = "task.queued"
	EventTaskCompleted       EventType = "task.completed"
	EventTaskFailed          EventType = "task.failed"
	EventEngagementStarted   EventType = "engagement.started"
	EventEngagementEnded     EventType = "engagement.ended"
	EventKillSwitchActivated EventType = "killswitch.activated"
	EventOperatorJoined      EventType = "operator.joined"
	EventOperatorLeft        EventType = "operator.left"
)

type Event struct {
	Type         EventType
	EngagementID string
	SessionID    string
	OperatorID   string
	Data         any
}

type EventHandler func(Event)

type EventBus struct {
	mu       sync.RWMutex
	handlers map[EventType][]EventHandler
	allHandlers []EventHandler
}

func NewEventBus() *EventBus {
	return &EventBus{
		handlers: make(map[EventType][]EventHandler),
	}
}

func (eb *EventBus) Subscribe(eventType EventType, handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

func (eb *EventBus) SubscribeAll(handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.allHandlers = append(eb.allHandlers, handler)
}

func (eb *EventBus) Publish(event Event) {
	eb.mu.RLock()
	handlers := make([]EventHandler, 0, len(eb.handlers[event.Type])+len(eb.allHandlers))
	handlers = append(handlers, eb.handlers[event.Type]...)
	handlers = append(handlers, eb.allHandlers...)
	eb.mu.RUnlock()

	for _, h := range handlers {
		go h(event)
	}
}
