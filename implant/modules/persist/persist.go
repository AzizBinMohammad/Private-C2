// Package persist implements gated persistence artifacts. Every artifact has a
// deterministic ID derived from its kind and name, so an operator can remove it
// later without guessing paths. Actions are explicit: add, remove, or list.
package persist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Request is the JSON argument object for every persist_* task.
type Request struct {
	Action   string `json:"action"` // add (default), remove, list
	Name     string `json:"name"`
	Command  string `json:"command,omitempty"`
	Schedule string `json:"schedule,omitempty"` // cron only; defaults to @reboot
	Scope    string `json:"scope,omitempty"`    // systemd only; user is the only supported scope
	DryRun   bool   `json:"dry_run,omitempty"`
}

// Result reports what changed and how to reference the artifact later.
type Result struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Action     string `json:"action"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Changed    bool   `json:"changed"`
	Note       string `json:"note,omitempty"`
}

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Execute validates the request and dispatches to the platform implementation.
func Execute(ctx context.Context, kind string, req Request) (Result, error) {
	if err := validate(&req); err != nil {
		return Result{}, err
	}
	home, _ := os.UserHomeDir()
	return executePlatform(ctx, kind, req, home)
}

func validate(req *Request) error {
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if req.Action == "" {
		req.Action = "add"
	}
	switch req.Action {
	case "add", "remove", "list":
	default:
		return fmt.Errorf("action must be add, remove, or list")
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Command = strings.TrimSpace(req.Command)
	req.Schedule = strings.TrimSpace(req.Schedule)

	if req.Action == "list" {
		return nil
	}
	if req.Name == "" {
		return fmt.Errorf("a name is required")
	}
	if !validName.MatchString(req.Name) {
		return fmt.Errorf("name must match [A-Za-z0-9._-]{1,64}")
	}
	if req.Action == "add" && req.Command == "" {
		return fmt.Errorf("a command is required to add persistence")
	}
	if req.Action == "add" && req.Schedule != "" {
		fields := strings.Fields(req.Schedule)
		if len(fields) != 5 && !strings.HasPrefix(req.Schedule, "@") {
			return fmt.Errorf("schedule must be a five-field cron expression or an @ keyword")
		}
	}
	return nil
}

// ArtifactID is deterministic for a kind/name pair.
func ArtifactID(kind, name string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + name))
	return hex.EncodeToString(sum[:8])
}

func resultFor(kind string, req Request, path string, changed bool, note string) Result {
	return Result{
		Kind:       kind,
		Name:       req.Name,
		Action:     req.Action,
		ArtifactID: ArtifactID(kind, req.Name),
		Path:       path,
		Changed:    changed,
		Note:       note,
	}
}
