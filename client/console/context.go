package console

import (
	"fmt"
	"sync"
)

// Context holds the current console state: which engagement, session, or beacon
// the operator is interacting with, along with operator identity information.
type Context struct {
	mu sync.RWMutex

	// Operator identity
	OperatorName string
	OperatorID   string
	OperatorRole string

	// Active engagement
	EngagementID   string
	EngagementName string

	// Active session (mutually exclusive with active beacon)
	SessionID   string
	SessionName string

	// Active beacon (mutually exclusive with active session)
	BeaconID   string
	BeaconName string

	// Server connection info
	ServerAddr string
	Connected  bool
}

// NewContext creates a new console context with operator information.
func NewContext(operatorName, operatorID, serverAddr string) *Context {
	return &Context{
		OperatorName: operatorName,
		OperatorID:   operatorID,
		ServerAddr:   serverAddr,
	}
}

// SetEngagement updates the active engagement context.
func (c *Context) SetEngagement(id, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.EngagementID = id
	c.EngagementName = name
	// Clear session/beacon context when switching engagements.
	c.SessionID = ""
	c.SessionName = ""
	c.BeaconID = ""
	c.BeaconName = ""
}

// ClearEngagement removes the active engagement context.
func (c *Context) ClearEngagement() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.EngagementID = ""
	c.EngagementName = ""
	c.SessionID = ""
	c.SessionName = ""
	c.BeaconID = ""
	c.BeaconName = ""
}

// SetSession sets the active session for interaction.
func (c *Context) SetSession(id, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SessionID = id
	c.SessionName = name
	// Clear beacon when selecting a session.
	c.BeaconID = ""
	c.BeaconName = ""
}

// ClearSession removes the active session context.
func (c *Context) ClearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SessionID = ""
	c.SessionName = ""
}

// SetBeacon sets the active beacon for interaction.
func (c *Context) SetBeacon(id, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BeaconID = id
	c.BeaconName = name
	// Clear session when selecting a beacon.
	c.SessionID = ""
	c.SessionName = ""
}

// ClearBeacon removes the active beacon context.
func (c *Context) ClearBeacon() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BeaconID = ""
	c.BeaconName = ""
}

// HasEngagement returns true if an engagement is currently selected.
func (c *Context) HasEngagement() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.EngagementID != ""
}

// HasSession returns true if a session is currently selected.
func (c *Context) HasSession() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.SessionID != ""
}

// HasBeacon returns true if a beacon is currently selected.
func (c *Context) HasBeacon() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.BeaconID != ""
}

// Prompt generates the console prompt string reflecting the current context.
// Format: [engagement:name] [session:id] operator@pc2 >
func (c *Context) Prompt() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	prompt := ""

	if c.EngagementName != "" {
		prompt += fmt.Sprintf("[engagement:%s] ", c.EngagementName)
	}

	if c.SessionName != "" {
		prompt += fmt.Sprintf("[session:%s] ", c.SessionName)
	} else if c.BeaconName != "" {
		prompt += fmt.Sprintf("[beacon:%s] ", c.BeaconName)
	}

	prompt += fmt.Sprintf("%s@pc2 > ", c.OperatorName)

	return prompt
}

// InteractionTarget returns the type and ID of the current interaction target.
// Returns ("session", id), ("beacon", id), or ("", "") if none is selected.
func (c *Context) InteractionTarget() (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.SessionID != "" {
		return "session", c.SessionID
	}
	if c.BeaconID != "" {
		return "beacon", c.BeaconID
	}
	return "", ""
}
