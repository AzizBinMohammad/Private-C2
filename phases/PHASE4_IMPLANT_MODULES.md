# Phase 4: Implant Task Modules

## Status: NOT STARTED

## Objective
Implement the implant-side task execution engine and all core operational modules (shell, filesystem, process, network). All modules operate within engagement scope and respect kill switch state.

## Tasks

### 4.1 Task Execution Engine
**File: `implant/task/executor.go`**
- Task dispatcher: receive TaskRequest, route to correct module handler, return TaskResponse
- Timeout enforcement per task
- Concurrent task limit (configurable, default 5)
- Task result buffering for beacon mode (queue results until next check-in)

**File: `implant/task/registry.go`**
- Module registry: map task type string → handler function
- Handler signature: `func(ctx context.Context, req []byte) ([]byte, error)`
- Built-in task types: shell, upload, download, ls, ps, ifconfig, screenshot, kill

### 4.2 Shell Module
**File: `implant/modules/shell/shell.go`**
- Execute OS commands and return stdout + stderr
- Platform-specific: `cmd.exe /c` on Windows, `/bin/sh -c` on Unix
- Configurable timeout per command
- Interactive shell support (session mode only): PTY allocation on Unix, ConPTY on Windows

**File: `implant/modules/shell/shell_windows.go`**
- Windows-specific: CreateProcess, ConPTY for interactive
- Token manipulation for execution context

**File: `implant/modules/shell/shell_unix.go`**
- Unix-specific: exec with PTY via `os/exec` + `golang.org/x/term`

### 4.3 Filesystem Module
**File: `implant/modules/filesystem/filesystem.go`**
- `ls` — List directory contents with metadata (size, permissions, timestamps)
- `cat` — Read file contents (with size limit to prevent memory issues)
- `upload` — Receive file from server, write to disk (chunked for large files)
- `download` — Read file from disk, send to server (chunked, respects DataQuota)
- `rm` — Delete file
- `mkdir` — Create directory
- `cp` / `mv` — Copy/move files
- `pwd` — Current working directory
- `cd` — Change working directory (process-level)

**Safety constraints:**
- Download respects `pkg/engagement.DataQuota` — tracks bytes sent, blocks if limit exceeded
- All paths validated against engagement scope if path-based scoping is enabled

### 4.4 Process Module
**File: `implant/modules/process/process.go`**
- `ps` — List running processes with PID, PPID, name, user, memory, CPU
- `kill` — Terminate a process by PID
- `execute-assembly` — (Windows) Load and execute .NET assembly in memory (for authorized assessment)

**File: `implant/modules/process/process_windows.go`**
- Windows process enumeration via CreateToolhelp32Snapshot
- Process token information

**File: `implant/modules/process/process_linux.go`**
- Linux process enumeration via /proc filesystem

**File: `implant/modules/process/process_darwin.go`**
- macOS process enumeration via sysctl

### 4.5 Network Module
**File: `implant/modules/network/network.go`**
- `ifconfig` — List network interfaces with IPs, MACs, MTU
- `netstat` — List active connections (TCP/UDP) with local/remote addresses
- `portscan` — TCP connect scan of specified host:port ranges (assessment only, scope-checked)
- `resolve` — DNS resolution of hostnames

**Safety constraints:**
- Port scan MUST check engagement scope before scanning any target
- Rate-limited to avoid network disruption
- Scan results logged to audit trail

### 4.6 Screenshot Module (Assessment)
**File: `implant/modules/screenshot/screenshot.go`**
- Capture screen as PNG
- Platform-specific implementations
- Respects DataQuota for image size

### 4.7 Implant Safety Layer
**File: `implant/safety/safety.go`**
- Pre-execution checks before any task:
  1. Kill switch check (local + remote if configured)
  2. Kill date check (self-terminate if past expiry)
  3. Engagement time window check
  4. Scope validation for network-targeting tasks
  5. Data quota check for exfiltration tasks
- If any check fails: refuse task, return error to server, optionally self-terminate

**File: `implant/safety/allowlist.go`**
- Safe simulation mode: only allow commands from an explicit allowlist
- Default allowlist: `whoami`, `hostname`, `ipconfig`/`ifconfig`, `dir`/`ls`, `pwd`, `ps`
- Configurable at build time

### 4.8 Evasion Foundations
**File: `implant/evasion/syscalls/syscalls.go`**
- Interface for direct syscall invocation (bypasses userland hooks)
- Build-tag gated: only compiled when evasion features enabled

**File: `implant/evasion/syscalls/syscalls_windows.go`**
- Windows: direct NT syscall stubs for NtCreateFile, NtReadFile, NtWriteFile, NtClose
- Syscall number resolution at runtime

**NOTE:** This is the assessment-oriented evasion layer. It demonstrates detection gaps for defensive teams. It does NOT include weaponized exploit chains, credential theft mechanisms, or persistence mechanisms.

## Key Design Decisions
- Every module is a standalone package — can be excluded at build time via build tags
- All network-targeting modules validate scope BEFORE acting
- DataQuota is checked before any data leaves the implant
- Kill switch check runs at the start of every task cycle, not just per-task
- Modules return structured results (not raw strings) for proper server-side processing

## Dependencies
- Phase 1: `pkg/crypto`, `pkg/envelope`, `pkg/engagement` (DONE)
- Phase 2: `implant/runtime`, `implant/transport` interfaces
- Phase 3: At least one transport working for integration testing

## Verification
```bash
go build ./implant/...
go test ./implant/task/... -v
go test ./implant/modules/... -v
go test ./implant/safety/... -v
go vet ./implant/...
```
