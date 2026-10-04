package safety

import (
	"strings"
	"sync"
)

// DefaultAllowlist contains commands considered safe for simulation mode.
// These commands only gather information and do not modify the system.
var DefaultAllowlist = []string{
	"whoami",
	"hostname",
	"ipconfig",
	"ifconfig",
	"dir",
	"ls",
	"pwd",
	"ps",
	"id",
	"uname",
	"env",
	"set",
	"systeminfo",
	"ver",
	"cat /etc/hostname",
	"cat /etc/os-release",
}

// CommandAllowlist manages a list of allowed commands for safe simulation mode.
// When enabled, only commands matching the allowlist may execute.
type CommandAllowlist struct {
	mu       sync.RWMutex
	commands map[string]bool
	enabled  bool
}

// NewCommandAllowlist creates a new allowlist with the default safe commands.
func NewCommandAllowlist() *CommandAllowlist {
	al := &CommandAllowlist{
		commands: make(map[string]bool),
		enabled:  false,
	}
	for _, cmd := range DefaultAllowlist {
		al.commands[strings.ToLower(cmd)] = true
	}
	return al
}

// Enable activates allowlist enforcement.
func (al *CommandAllowlist) Enable() {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.enabled = true
}

// Disable deactivates allowlist enforcement.
func (al *CommandAllowlist) Disable() {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.enabled = false
}

// IsEnabled returns whether the allowlist is active.
func (al *CommandAllowlist) IsEnabled() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.enabled
}

// Add adds a command to the allowlist.
func (al *CommandAllowlist) Add(command string) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.commands[strings.ToLower(strings.TrimSpace(command))] = true
}

// Remove removes a command from the allowlist.
func (al *CommandAllowlist) Remove(command string) {
	al.mu.Lock()
	defer al.mu.Unlock()
	delete(al.commands, strings.ToLower(strings.TrimSpace(command)))
}

// IsAllowed checks whether a command is permitted.
// If the allowlist is disabled, all commands are allowed.
// When enabled, the command (or the first word of the command) must
// match an entry in the allowlist.
func (al *CommandAllowlist) IsAllowed(command string) (bool, string) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if !al.enabled {
		return true, ""
	}

	cmd := strings.ToLower(strings.TrimSpace(command))
	if cmd == "" {
		return false, "empty command"
	}

	// Check exact match first.
	if al.commands[cmd] {
		return true, ""
	}

	// Check if the base command (first word) is allowed.
	parts := strings.Fields(cmd)
	if len(parts) > 0 && al.commands[parts[0]] {
		return true, ""
	}

	return false, "command not in allowlist: " + parts[0]
}

// List returns all commands currently in the allowlist.
func (al *CommandAllowlist) List() []string {
	al.mu.RLock()
	defer al.mu.RUnlock()

	cmds := make([]string, 0, len(al.commands))
	for cmd := range al.commands {
		cmds = append(cmds, cmd)
	}
	return cmds
}

// Reset restores the allowlist to its default set of commands.
func (al *CommandAllowlist) Reset() {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.commands = make(map[string]bool)
	for _, cmd := range DefaultAllowlist {
		al.commands[strings.ToLower(cmd)] = true
	}
}
