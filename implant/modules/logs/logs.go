package logs

import (
	"context"
	"fmt"
	"runtime"
)

type ClearTarget string

const (
	TargetSystem      ClearTarget = "system"
	TargetSecurity    ClearTarget = "security"
	TargetApplication ClearTarget = "application"
	TargetAll         ClearTarget = "all"
	TargetCustom      ClearTarget = "custom"
)

type ClearRequest struct {
	Target   ClearTarget
	LogPath  string // for custom target
	Selective bool  // if true, remove only matching entries
	Pattern  string // regex for selective clearing
	DryRun   bool   // report what would be cleared without clearing
}

type ClearResult struct {
	Target       string
	EntriesFound int
	Cleared      bool
	DryRun       bool
	Details      []string
	Error        string
}

type LogClearer interface {
	Clear(ctx context.Context, req ClearRequest) ([]ClearResult, error)
	ListLogs(ctx context.Context) ([]LogInfo, error)
}

type LogInfo struct {
	Name     string
	Path     string
	SizeBytes int64
	Entries  int
	Writable bool
}

func newGenericClearer() LogClearer {
	return &genericClearer{}
}

type genericClearer struct{}

func (g *genericClearer) Clear(_ context.Context, req ClearRequest) ([]ClearResult, error) {
	return nil, fmt.Errorf("log clearing not supported on %s", runtime.GOOS)
}

func (g *genericClearer) ListLogs(_ context.Context) ([]LogInfo, error) {
	return nil, fmt.Errorf("log listing not supported on %s", runtime.GOOS)
}
