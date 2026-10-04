package task

import (
	"context"
	"fmt"
	"sync"
)

// HandlerFunc is the signature for task handler functions.
// It receives a context and the task payload, and returns output bytes or an error.
type HandlerFunc func(ctx context.Context, req []byte) ([]byte, error)

// Built-in task type constants.
const (
	TypeShell      = "shell"
	TypeUpload     = "upload"
	TypeDownload   = "download"
	TypeLS         = "ls"
	TypePS         = "ps"
	TypeIfconfig   = "ifconfig"
	TypeScreenshot = "screenshot"
	TypeKill       = "kill"
	TypeCat        = "cat"
	TypeMkdir      = "mkdir"
	TypeRm         = "rm"
	TypeCp         = "cp"
	TypeMv         = "mv"
	TypePwd        = "pwd"
	TypeCd         = "cd"
	TypeNetstat    = "netstat"
	TypePortscan   = "portscan"
	TypeResolve    = "resolve"
)

// Registry maps task type strings to handler functions.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]HandlerFunc
}

// NewRegistry creates a new empty task registry.
func NewRegistry() *Registry {
	return &Registry{
		handlers: make(map[string]HandlerFunc),
	}
}

// Register adds a handler for the given task type.
// Returns an error if a handler is already registered for that type.
func (r *Registry) Register(taskType string, handler HandlerFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.handlers[taskType]; exists {
		return fmt.Errorf("handler already registered for task type %q", taskType)
	}
	r.handlers[taskType] = handler
	return nil
}

// MustRegister registers a handler and panics on error.
func (r *Registry) MustRegister(taskType string, handler HandlerFunc) {
	if err := r.Register(taskType, handler); err != nil {
		panic(err)
	}
}

// Replace registers or replaces a handler for the given task type.
func (r *Registry) Replace(taskType string, handler HandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[taskType] = handler
}

// Get retrieves the handler for the given task type.
func (r *Registry) Get(taskType string) (HandlerFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[taskType]
	return h, ok
}

// Remove unregisters a handler for the given task type.
func (r *Registry) Remove(taskType string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.handlers, taskType)
}

// Types returns a list of all registered task types.
func (r *Registry) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.handlers))
	for t := range r.handlers {
		types = append(types, t)
	}
	return types
}

// Count returns the number of registered handlers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.handlers)
}
