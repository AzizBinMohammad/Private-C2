package console

import (
	"fmt"
	"sync"
	"time"
)

// NotificationType identifies the kind of background event.
type NotificationType string

const (
	NotifySessionConnect    NotificationType = "session.connect"
	NotifySessionDisconnect NotificationType = "session.disconnect"
	NotifySessionHealthChange NotificationType = "session.health_change"
	NotifyBeaconCheckin     NotificationType = "beacon.checkin"
	NotifyBeaconMissed      NotificationType = "beacon.missed"
	NotifyListenerStarted   NotificationType = "listener.started"
	NotifyListenerStopped   NotificationType = "listener.stopped"
	NotifyTaskCompleted     NotificationType = "task.completed"
	NotifyTaskFailed        NotificationType = "task.failed"
	NotifyBuildCompleted    NotificationType = "build.completed"
	NotifyBuildFailed       NotificationType = "build.failed"
	NotifyKillSwitch        NotificationType = "killswitch.activated"
	NotifyOperatorJoined    NotificationType = "operator.joined"
	NotifyOperatorLeft      NotificationType = "operator.left"
)

// Notification represents a background event delivered to the console.
type Notification struct {
	Type         NotificationType
	Message      string
	EngagementID string
	SessionID    string
	Timestamp    time.Time
}

// NotificationHandler is a callback invoked when a notification arrives.
type NotificationHandler func(Notification)

// EventListener subscribes to background events from the server and delivers
// notifications to the console. This is a placeholder that demonstrates the
// event architecture; the actual server-side streaming will be connected
// when the gRPC dependency is added to the client module.
type EventListener struct {
	mu        sync.RWMutex
	handlers  map[NotificationType][]NotificationHandler
	allHandlers []NotificationHandler
	writer    *Writer
	stopCh    chan struct{}
	running   bool
}

// NewEventListener creates a new event listener.
func NewEventListener(writer *Writer) *EventListener {
	return &EventListener{
		handlers: make(map[NotificationType][]NotificationHandler),
		writer:   writer,
		stopCh:   make(chan struct{}),
	}
}

// Subscribe registers a handler for a specific notification type.
func (el *EventListener) Subscribe(notifType NotificationType, handler NotificationHandler) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.handlers[notifType] = append(el.handlers[notifType], handler)
}

// SubscribeAll registers a handler that receives all notification types.
func (el *EventListener) SubscribeAll(handler NotificationHandler) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.allHandlers = append(el.allHandlers, handler)
}

// Start begins listening for background events. In the full implementation
// this would open a server-streaming gRPC call. Here it starts a placeholder
// loop.
func (el *EventListener) Start() {
	el.mu.Lock()
	if el.running {
		el.mu.Unlock()
		return
	}
	el.running = true
	el.mu.Unlock()

	go el.listenLoop()
}

// Stop terminates the event listener.
func (el *EventListener) Stop() {
	el.mu.Lock()
	defer el.mu.Unlock()
	if !el.running {
		return
	}
	el.running = false
	close(el.stopCh)
}

// Deliver manually delivers a notification to all registered handlers.
// This can be used for locally generated events or testing.
func (el *EventListener) Deliver(notif Notification) {
	if notif.Timestamp.IsZero() {
		notif.Timestamp = time.Now()
	}

	el.mu.RLock()
	handlers := make([]NotificationHandler, 0, len(el.handlers[notif.Type])+len(el.allHandlers))
	handlers = append(handlers, el.handlers[notif.Type]...)
	handlers = append(handlers, el.allHandlers...)
	el.mu.RUnlock()

	for _, h := range handlers {
		h(notif)
	}
}

// listenLoop is the background goroutine that would receive server events.
// Placeholder: it simply waits for the stop signal.
func (el *EventListener) listenLoop() {
	// In the full implementation, this loop would:
	//   1. Open a server-streaming RPC: stream, err := client.EventStream(ctx, &req)
	//   2. For each event received from stream.Recv():
	//      - Convert server event to Notification
	//      - Call el.Deliver(notification)
	//   3. On disconnect, attempt reconnection with backoff.

	<-el.stopCh
}

// DefaultNotificationPrinter returns a handler that prints notifications
// to the console writer with appropriate color coding.
func DefaultNotificationPrinter(writer *Writer) NotificationHandler {
	return func(n Notification) {
		ts := n.Timestamp.Format("15:04:05")
		switch n.Type {
		case NotifySessionConnect:
			writer.Print("\n%s%s [EVENT]%s %s\n", ColorGreen, ts, ColorReset, n.Message)
		case NotifySessionDisconnect, NotifyBeaconMissed:
			writer.Print("\n%s%s [EVENT]%s %s\n", ColorRed, ts, ColorReset, n.Message)
		case NotifySessionHealthChange:
			writer.Print("\n%s%s [EVENT]%s %s\n", ColorYellow, ts, ColorReset, n.Message)
		case NotifyTaskCompleted, NotifyBuildCompleted:
			writer.Print("\n%s%s [EVENT]%s %s\n", ColorGreen, ts, ColorReset, n.Message)
		case NotifyTaskFailed, NotifyBuildFailed:
			writer.Print("\n%s%s [EVENT]%s %s\n", ColorRed, ts, ColorReset, n.Message)
		case NotifyKillSwitch:
			writer.Print("\n%s%s%s [KILLSWITCH]%s %s\n", ColorBold, ColorRed, ts, ColorReset, n.Message)
		default:
			writer.Print("\n%s%s [EVENT]%s %s\n", ColorDim, ts, ColorReset, n.Message)
		}
		// Reprint the prompt hint after an asynchronous notification.
		fmt.Print("> ")
	}
}
