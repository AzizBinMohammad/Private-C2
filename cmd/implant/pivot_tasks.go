package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/azizbinmohammad/private-c2/implant/modules/pivot"
)

// pivotManager owns the SOCKS and port-forward listeners started by tasks.
// Listeners live until pivot_* stop is called or the implant exits.
type pivotManager struct {
	mu         sync.Mutex
	socks      map[string]*pivot.SOCKS5Server
	forwards   map[string]*pivot.PortForward
	namedpipes map[string]*pivot.NamedPipeProxy
}

var pivots = &pivotManager{
	socks:      make(map[string]*pivot.SOCKS5Server),
	forwards:   make(map[string]*pivot.PortForward),
	namedpipes: make(map[string]*pivot.NamedPipeProxy),
}

type socksRequest struct {
	Action   string `json:"action"`
	Listen   string `json:"listen"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type portfwdRequest struct {
	Action string `json:"action"`
	Listen string `json:"listen"`
	Target string `json:"target"`
}

// pivotScopeCheck enforces the engagement scope for each pivot destination.
func pivotScopeCheck(ctx context.Context, host string) error {
	if host == "" {
		return fmt.Errorf("empty pivot destination")
	}
	if agentSafety == nil {
		return nil
	}
	result := agentSafety.CheckWithTarget(ctx, host)
	if !result.Passed {
		return fmt.Errorf("%s", result.Reason)
	}
	return nil
}

func handlePivotSocks(ctx context.Context, args string) (string, error) {
	var req socksRequest
	if err := unmarshalArgs(args, &req); err != nil {
		return "", fmt.Errorf("pivot_socks args must be JSON: %w", err)
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "status"
	}

	switch action {
	case "start":
		listen := strings.TrimSpace(req.Listen)
		if listen == "" {
			listen = "127.0.0.1:0"
		}
		pivots.mu.Lock()
		if _, exists := pivots.socks[listen]; exists {
			pivots.mu.Unlock()
			return "", fmt.Errorf("a socks pivot is already listening on %s", listen)
		}
		pivots.mu.Unlock()

		server, err := pivot.StartSOCKS5(listen, req.Username, req.Password, pivotScopeCheck)
		if err != nil {
			return "", err
		}
		pivots.mu.Lock()
		pivots.socks[server.Addr()] = server
		pivots.mu.Unlock()
		return marshalJSON(map[string]any{
			"action": "start", "listen": server.Addr(), "auth": req.Username != "",
		})

	case "stop":
		listen := strings.TrimSpace(req.Listen)
		if listen == "" {
			return "", fmt.Errorf("pivot_socks stop requires the listen address")
		}
		pivots.mu.Lock()
		server, ok := pivots.socks[listen]
		delete(pivots.socks, listen)
		pivots.mu.Unlock()
		if !ok {
			return "", fmt.Errorf("no socks pivot is listening on %s", listen)
		}
		_ = server.Close()
		return marshalJSON(map[string]any{"action": "stop", "listen": listen})

	case "status", "list":
		pivots.mu.Lock()
		addrs := make([]string, 0, len(pivots.socks))
		for addr := range pivots.socks {
			addrs = append(addrs, addr)
		}
		pivots.mu.Unlock()
		sort.Strings(addrs)
		return marshalJSON(map[string]any{"action": "status", "listeners": addrs})

	default:
		return "", fmt.Errorf("unsupported pivot_socks action %q (want start, stop, or status)", action)
	}
}

func handlePivotPortfwd(ctx context.Context, args string) (string, error) {
	var req portfwdRequest
	if err := unmarshalArgs(args, &req); err != nil {
		return "", fmt.Errorf("pivot_portfwd args must be JSON: %w", err)
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "status"
	}

	switch action {
	case "start":
		listen := strings.TrimSpace(req.Listen)
		if listen == "" {
			return "", fmt.Errorf("pivot_portfwd start requires a listen address")
		}
		target := strings.TrimSpace(req.Target)
		if target == "" {
			return "", fmt.Errorf("pivot_portfwd start requires a target (host:port)")
		}
		if err := pivotScopeCheck(ctx, hostPart(target)); err != nil {
			return "", err
		}

		pivots.mu.Lock()
		if _, exists := pivots.forwards[listen]; exists {
			pivots.mu.Unlock()
			return "", fmt.Errorf("a port forward is already listening on %s", listen)
		}
		pivots.mu.Unlock()

		fwd, err := pivot.StartPortForward(listen, target, pivotScopeCheck)
		if err != nil {
			return "", err
		}
		pivots.mu.Lock()
		pivots.forwards[fwd.Addr()] = fwd
		pivots.mu.Unlock()
		return marshalJSON(map[string]any{
			"action": "start", "listen": fwd.Addr(), "target": target,
		})

	case "stop":
		listen := strings.TrimSpace(req.Listen)
		if listen == "" {
			return "", fmt.Errorf("pivot_portfwd stop requires the listen address")
		}
		pivots.mu.Lock()
		fwd, ok := pivots.forwards[listen]
		delete(pivots.forwards, listen)
		pivots.mu.Unlock()
		if !ok {
			return "", fmt.Errorf("no port forward is listening on %s", listen)
		}
		_ = fwd.Close()
		return marshalJSON(map[string]any{"action": "stop", "listen": listen})

	case "status", "list":
		pivots.mu.Lock()
		addrs := make([]string, 0, len(pivots.forwards))
		for addr := range pivots.forwards {
			addrs = append(addrs, addr)
		}
		pivots.mu.Unlock()
		sort.Strings(addrs)
		return marshalJSON(map[string]any{"action": "status", "listeners": addrs})

	default:
		return "", fmt.Errorf("unsupported pivot_portfwd action %q (want start, stop, or status)", action)
	}
}

type namedpipeRequest struct {
	Action string `json:"action"`
	Pipe   string `json:"pipe"`
	Target string `json:"target"`
}

func normalizePipeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if !strings.HasPrefix(name, `\\.\pipe\`) {
		return `\\.\pipe\` + strings.TrimPrefix(name, `\`)
	}
	return name
}

func handlePivotNamedpipe(ctx context.Context, args string) (string, error) {
	var req namedpipeRequest
	if err := unmarshalArgs(args, &req); err != nil {
		return "", fmt.Errorf("pivot_namedpipe args must be JSON: %w", err)
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "status"
	}
	pipe := normalizePipeName(req.Pipe)

	switch action {
	case "start":
		if pipe == "" {
			return "", fmt.Errorf("pivot_namedpipe start requires a pipe name")
		}
		target := strings.TrimSpace(req.Target)
		if target == "" {
			return "", fmt.Errorf("pivot_namedpipe start requires a target (host:port)")
		}
		if err := pivotScopeCheck(ctx, hostPart(target)); err != nil {
			return "", err
		}

		pivots.mu.Lock()
		if _, exists := pivots.namedpipes[pipe]; exists {
			pivots.mu.Unlock()
			return "", fmt.Errorf("a named-pipe pivot already exists for %s", pipe)
		}
		pivots.mu.Unlock()

		proxy, err := pivot.StartNamedPipeProxy(pipe, target, pivotScopeCheck)
		if err != nil {
			return "", err
		}
		pivots.mu.Lock()
		pivots.namedpipes[pipe] = proxy
		pivots.mu.Unlock()
		return marshalJSON(map[string]any{"action": "start", "pipe": pipe, "target": target})

	case "stop":
		if pipe == "" {
			return "", fmt.Errorf("pivot_namedpipe stop requires a pipe name")
		}
		pivots.mu.Lock()
		proxy, ok := pivots.namedpipes[pipe]
		delete(pivots.namedpipes, pipe)
		pivots.mu.Unlock()
		if !ok {
			return "", fmt.Errorf("no named-pipe pivot exists for %s", pipe)
		}
		_ = proxy.Close()
		return marshalJSON(map[string]any{"action": "stop", "pipe": pipe})

	case "status", "list":
		pivots.mu.Lock()
		pipes := make([]string, 0, len(pivots.namedpipes))
		for name := range pivots.namedpipes {
			pipes = append(pipes, name)
		}
		pivots.mu.Unlock()
		sort.Strings(pipes)
		return marshalJSON(map[string]any{"action": "status", "pipes": pipes})

	default:
		return "", fmt.Errorf("unsupported pivot_namedpipe action %q (want start, stop, or status)", action)
	}
}

func hostPart(target string) string {
	if i := strings.LastIndex(target, ":"); i > 0 {
		return target[:i]
	}
	return target
}
