# Phase 2 Status — 2026-10-19

Phase 2 adds post-exploitation under explicit engagement gates. Nothing in this
cut is enabled by default: an engagement must set the relevant `allow_*` flag,
and the implant must be built or launched with the matching flag. Every
sensitive task type is mapped to a capability in `pkg/protocol.CategoryFor`;
the server refuses it before queueing and the implant re-checks it before
execution.

## Delivered

### 2A — Capability gates, OT execution, identity, chunked transfer

- Engagement capability fields: `AllowPrivilegeEscalation`,
  `AllowCredentialAccess`, `AllowLateralMovement`, `AllowPersistence`,
  `AllowEvasion`, `AllowOTAssessment` (all default false).
- Server policy refuses sensitive categories with no engagement or a disabled
  capability, and checks the engagement status, time window, authorized
  technique list, and scope before queueing.
- Implant safety gate (`checkTaskSafety`) enforces the same categories and the
  command allowlist.
- The 17-protocol OT module is reachable through read-only task types:
  `ot_discover`, `ot_fingerprint`, `ot_vuln_scan`, `ot_hmi`,
  `ot_historian`, `ot_wireless`, `ot_serial`, `ot_plc_read`,
  `ot_credentials` (credential-gated).
- Identity tasks: `whoami`, `getuid`, `getgid`.
- Chunked, resumable transfer: `download_stat`, `download_chunk`,
  `upload_chunk`, with data-quota enforcement and SHA-256 verification.

### 2B — Process and token operations

- `process_info`: structured JSON process list (PID, PPID, name, user,
  command line, RSS).
- `process_suspend` / `process_resume`: SIGSTOP/SIGCONT on Linux and macOS,
  `NtSuspendProcess`/`NtResumeProcess` on Windows.
- Windows token module (`implant/modules/token`): `token_list`,
  `token_steal`, `token_make` (`LogonUser`, interactive/network),
  `token_impersonate`, `token_revert`, and `getprivs`.
- Impersonation is task-scoped: it runs on a locked OS thread, reads back the
  effective identity, and reverts before the task returns.

### 2C — Credential access

- `credential_enum`: read-only discovery of SSH keys (PEM encryption state),
  cloud/VCS/Docker/Kubernetes files, browser profile stores, shell histories,
  `/etc/shadow` and `/etc/sudoers` readability, Windows Credential
  Manager/DPAPI paths, and sensitive environment-variable values.
- `credential_read <path>`: reads one operator-named regular file
  (devices/FIFOs refused), applies the data quota, returns base64 + SHA-256.
- `credential_dump <lsass|sam|security|system>` (Windows): LSASS full-memory
  minidump via `MiniDumpWriteDump` with SeDebugPrivilege, and registry hives
  via `reg save`. Dumps are left on the target for chunked retrieval.
- Credential loot is refused by the loot API unless the engagement enables
  credential access.

### 2D — Lateral movement

- `lateral_ssh`: runs a command through the target's `ssh` client with
  key/agent auth, or password auth via `sshpass -e` (the password is passed in
  the environment, never on the command line). Targets are scope-checked on the
  server and again in the implant before execution.

### 2E — Pivoting and proxying

- `pivot_socks`: SOCKS5 proxy with optional RFC 1929 username/password auth,
  CONNECT only, and a per-connection scope check before every dial.
- `pivot_portfwd`: local TCP port forward; the destination host is
  scope-checked before every dial.
- Both support `start`, `stop`, and `status` actions. Listeners are owned by
  the implant and stop when it exits.

### 2F — Scripting

- `powershell`: `-EncodedCommand` execution with a bounded task timeout.
- `python`: `python3 -c` (falling back to `python`).
- `execute_assembly`: loads a base64 .NET assembly into a PowerShell process
  and invokes its entry point. This is a PowerShell-hosted equivalent, not an
  in-process CLR host; the base implant stays CGO-free.
- The command allowlist applies to `shell`, `powershell`, and `python`.

### 2G — Evasion

- `evasion_timestomp`: sets atime/mtime from an RFC3339 timestamp or a
  reference file.
- `evasion_cleanup`: dry-run by default; with `{"apply":true}` removes the
  fixed set of shell-history files and reports the environment variables
  unset in the implant process. It cannot delete arbitrary paths.

### 2H — Persistence

- Unix: `persist_shell` (marked block in a shell profile), `persist_systemd`
  (user unit, enabled through `systemctl --user`), `persist_cron` (marked
  crontab line, `@reboot` by default).
- Windows: `persist_registry` (HKCU Run value prefixed `pc2-`) and
  `persist_schtasks` (`ONLOGON`/`ONSTART` task prefixed `pc2-`).
- Every artifact has a deterministic ID derived from kind and name, supports
  `add`, `remove`, and `list`, and honors `dry_run`.
- Mutating persistence tasks are gated by `allow_persistence`.

### 2I — Loot store and exfiltration handling

- `LootArtifact` metadata model plus server-side blobs under `PC2_LOOT_DIR`
  (default `./loot`, mode 0700, 16 MiB per artifact).
- `POST /api/loot` accepts base64 data or promotes a completed task result
  (`task_id`); `GET /api/loot` filters by engagement/kind; `GET
  /api/loot/{id}`, `GET /api/loot/{id}/download`, and `DELETE /api/loot/{id}`.
- RBAC: `loot.read` for operators, observers, and OT operators; `loot.write`
  for operators. Credential-kind loot additionally requires the engagement's
  credential capability.
- Loot creation/deletion writes an audit entry (`data.collect`).

### Operator surfaces

- CLI: `psinfo`, `suspend`, `resume`, `getprivs`, `tokens`, `steal`,
  `maketoken`, `impersonate`, `revert`, `creds`, `credread`, `dump`,
  `assembly`, and `loot list|add|get|download|rm`.
- The web portal task dropdown offers every registered task type; the registry
  sync test enforces this.

## Verification

- `make test` — all modules, race detector.
- `make lint` — `go vet` (golangci-lint is not installed here).
- `make build` — server, client, builder.
- `make cross-compile` — linux/amd64, windows/amd64, darwin/arm64.
- `make e2e-smoke` — real server and implants over mTLS and HTTPS; an
  API-built no-flags payload; task round-trips; chunked download; structured
  `process_info`; denial of a privilege-gated task on an engagement-less
  session; and a loot create/download/delete round-trip.
- Unit tests cover capability mapping, process suspend/resume against a live
  child, the non-Windows token manager, credential discovery/read, lateral SSH
  argument building, SOCKS5 authentication and scope denial, port-forward
  relay, persistence add/list/remove and dry-run, timestomp, and loot RBAC and
  gate behavior.

## Known limits / not delivered

These are not claimed as complete:

- **BOF/COFF loader and Cobalt Strike Beacon API callbacks.** A correct COFF
  loader is Windows-specific, untestable in this environment, and larger than
  the rest of this cut; shipping an unverified loader would be worse than
  omitting it.
- **In-process CLR hosting.** `execute_assembly` uses PowerShell; it does not
  host the CLR in the implant, does not support in-memory patching, and leaves
  PowerShell process artifacts.
- **Windows sleep obfuscation, AMSI/ETW patching, call-stack spoofing.**
  Deliberately not implemented without a Windows lab to verify behavior and
  detection impact.
- **SMB/WinRM/WMI/PsExec lateral adapters and named-pipe pivots.** SSH and
  TCP SOCKS/port-forward are the supported paths in this cut.
- **DPAPI/browser credential decryption and Kerberos ticket extraction.**
- **OT finding persistence and report generation.** OT tasks execute
  read-only; their outputs are retrieved as task results, not yet stored in
  the OT finding tables.
- **Windows execution verification.** Every Windows path compiles under
  `GOOS=windows`; none has been run on a Windows lab host in this
  environment. Treat them as cross-compiled, not behaviorally verified.
