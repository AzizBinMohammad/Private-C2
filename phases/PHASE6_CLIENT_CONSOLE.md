# Phase 6: Client Console & CLI

## Status: DONE

## What Was Built
- `client/transport/config.go` — Operator config with JSON serialization
- `client/transport/grpc.go` — gRPC client interface (stub pattern)
- `client/console/context.go` — Console context (engagement, session, beacon)
- `client/console/output.go` — Table formatting, ANSI colors, JSON mode
- `client/console/events.go` — Background event listener with 14 notification types
- `client/console/console.go` — Interactive REPL with bufio.Scanner
- `client/cli/commands/commands.go` — Command struct, registry, helpers
- `client/cli/commands/sessions.go` — sessions commands (list, interact, lock, unlock, kill)
- `client/cli/commands/beacons.go` — beacons commands (list, interact, watch)
- `client/cli/commands/listeners.go` — listeners commands (list, start, stop, profiles)
- `client/cli/commands/payloads.go` — generate/payloads commands
- `client/cli/commands/tasks.go` — shell, upload, download, ls, ps, etc.
- `client/cli/commands/engagement.go` — engagements commands (list, create, use, killswitch, scope)
- `client/cli/commands/audit.go` — audit commands (query, export, verify)
- `client/cli/commands/admin.go` — operators/server commands

## Objective
Build the operator-facing CLI client with interactive console, tab completion, command framework, and gRPC connection to the server.

## Tasks

### 6.1 Client Transport Layer
**File: `client/transport/grpc.go`**
- gRPC client connection to server with mTLS
- Client certificate loading from file or embedded
- Connection health monitoring with automatic reconnect
- Server discovery: direct address or config file

**File: `client/transport/config.go`**
- Operator config file format (YAML):
  ```yaml
  server: localhost:31337
  operator: operator-name
  ca_cert: /path/to/ca.pem
  client_cert: /path/to/operator.pem
  client_key: /path/to/operator-key.pem
  ```
- Config loading with defaults
- Config generation command (after operator registration)

### 6.2 Console Framework
**File: `client/console/console.go`**
- Interactive REPL using `github.com/desertbit/grumble` or `github.com/c-bata/go-prompt`
- Prompt showing current context: `[engagement:name] operator@pc2 > `
- Context switching: select active engagement, select active session
- Command history (persistent across sessions)
- Tab completion for commands, session IDs, file paths

**File: `client/console/context.go`**
- Console context management:
  - Active engagement (required for most commands)
  - Active session/beacon (for task commands)
  - Current operator info
- Context displayed in prompt, updated on switch

### 6.3 Command Framework
**File: `client/cli/commands/sessions.go`**
- `sessions` — List all sessions (table format: ID, hostname, user, OS, transport, health, locked_by)
- `sessions interact <id>` — Set active session
- `sessions lock <id>` — Lock session to this operator
- `sessions unlock <id>` — Release session lock
- `sessions kill <id>` — Terminate session

**File: `client/cli/commands/beacons.go`**
- `beacons` — List all beacons (table: ID, hostname, interval, last check-in, next check-in)
- `beacons interact <id>` — Set active beacon
- `beacons watch <id>` — Stream beacon check-ins

**File: `client/cli/commands/listeners.go`**
- `listeners` — List active listeners
- `listeners start <type> --bind <addr> --port <port>` — Start a new listener (mtls, https, dns, wireguard)
- `listeners stop <id>` — Stop a listener
- `listeners profiles` — List C2 profiles
- `listeners profiles use <name>` — Apply C2 profile to new listener

**File: `client/cli/commands/payloads.go`**
- `generate` — Interactive payload generation wizard
- `generate --os <os> --arch <arch> --mode <mode> --transport <transport>` — Non-interactive generation
- `payloads` — List generated payloads
- `payloads download <id>` — Download payload artifact
- `payloads revoke <id>` — Mark payload as revoked

**File: `client/cli/commands/tasks.go`**
- `shell <command>` — Execute shell command on active session
- `upload <local_path> <remote_path>` — Upload file to target
- `download <remote_path> [local_path]` — Download file from target
- `ls [path]` — List directory on target
- `ps` — List processes on target
- `kill <pid>` — Kill process on target
- `ifconfig` — List network interfaces on target
- `netstat` — List connections on target
- `screenshot` — Capture screenshot from target
- `portscan <target> <ports>` — Port scan (scope-checked)

**File: `client/cli/commands/engagement.go`**
- `engagements` — List engagements
- `engagements create` — Interactive engagement creation wizard
- `engagements use <id>` — Switch active engagement
- `engagements status` — Show current engagement details
- `engagements killswitch <id>` — Activate kill switch for engagement
- `engagements scope check <target>` — Check if target is in scope

**File: `client/cli/commands/audit.go`**
- `audit` — Query audit log (with filters)
- `audit export --format <json|cef|leef> --output <file>` — Export audit trail
- `audit verify` — Verify audit chain integrity

**File: `client/cli/commands/admin.go`**
- `operators` — List operators
- `operators add <name> --role <role>` — Add operator (generates cert)
- `operators remove <name>` — Remove operator
- `server status` — Server status and stats

### 6.4 Output Formatting
**File: `client/console/output.go`**
- Table formatting for list commands (aligned columns, truncation)
- JSON output mode (`--json` flag on any command)
- Color coding: healthy=green, stale=yellow, lost=red
- Progress bars for file transfers
- Streaming output for shell commands

### 6.5 Event Stream
**File: `client/console/events.go`**
- Background event listener: subscribe to server event stream via gRPC
- Real-time notifications in console:
  - New session connected
  - Session health change
  - Beacon check-in
  - Listener started/stopped
  - Kill switch activated
  - Task completed/failed
- Non-intrusive display: notifications above prompt line

### 6.6 Client Entry Point
**Update: `cmd/client/main.go`**
- CLI argument parsing with `cobra` or `flag`
- Subcommands: `connect`, `import-config`, `version`
- `connect` enters interactive console
- `import-config <file>` imports operator config

## Key Design Decisions
- Console is the primary interface — all server features accessible from CLI
- Every command requires an active engagement context (except admin commands)
- Session interaction commands only work with an active session selected
- Tab completion includes dynamic data from server (session IDs, engagement names)
- Event stream runs in background goroutine, non-blocking

## Dependencies
- Phase 1: Server gRPC API, models (DONE)
- Phase 3: Transport layer for connection
- Phase 5: Build pipeline for payload generation commands
- Phase 8: OT interface commands (hidden, loaded only with `ot.assess` permission)
- External: `github.com/desertbit/grumble` or `github.com/c-bata/go-prompt`, `github.com/olekukonko/tablewriter`, `github.com/spf13/cobra`

## OT Integration
The hidden OT console (`client/cli/commands/ot.go` from Phase 8) is NOT registered in the standard command tree. It is loaded dynamically only when:
1. The operator's role includes `ot.assess` permission
2. The active engagement has `ot_authorized: true`
3. The operator enters `ot-mode` with a valid dual-auth token
See `PHASE8_OT_INTERFACE.md` for the full OT command set.

## Verification
```bash
go build -o /tmp/pc2-client ./cmd/client/...
# Manual test: start server, connect client, list sessions
go test ./client/... -v
```
