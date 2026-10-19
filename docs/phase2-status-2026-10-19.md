# Phase 2 Status — 2026-10-19

Phase 2 adds post-exploitation under explicit engagement gates. Nothing in this
cut is enabled by default: an engagement must set the relevant `allow_*` flag,
and the implant must be built or launched with the matching flag.

## Delivered in this cut

### 2A — Capability gates, OT execution, identity, chunked transfer

- Engagement capability fields: `AllowPrivilegeEscalation`,
  `AllowCredentialAccess`, `AllowLateralMovement`, `AllowPersistence`,
  `AllowEvasion`, `AllowOTAssessment` (all default false).
- Server policy (`server/api/httpapi/policy.go`) maps task types to categories
  and refuses sensitive categories when the engagement does not enable them.
  Sensitive tasks are also refused when a session has no engagement.
- Implant safety gate (`checkTaskSafety`) enforces the same categories from the
  embedded/build-time configuration.
- The existing 17-protocol OT module is now reachable through read-only task
  types: `ot_discover`, `ot_fingerprint`, `ot_vuln_scan`, `ot_hmi`,
  `ot_historian`, `ot_wireless`, `ot_serial`, `ot_plc_read`,
  `ot_credentials` (the last is credential-gated).
- Identity tasks: `whoami`, `getuid`, `getgid`.
- Chunked, resumable transfer: `download_stat`, `download_chunk`,
  `upload_chunk`, with data-quota enforcement and SHA-256 verification in the
  CLI download path.

### 2B — Process and token operations

- `process_info`: structured JSON process list (PID, PPID, name, user,
  command line, RSS).
- `process_suspend` / `process_resume`: SIGSTOP/SIGCONT on Linux and macOS,
  `NtSuspendProcess`/`NtResumeProcess` on Windows.
- Windows token module (`implant/modules/token`):
  - `token_list` — current identity plus stored tokens.
  - `token_steal <pid>` — duplicate a process token into the handle store.
  - `token_make` — `LogonUser` with `interactive` or `network` logon type.
  - `token_impersonate <id>` — impersonate on a locked thread, read back the
    effective identity, then revert (task-scoped).
  - `token_revert` — close and clear all stored token handles.
  - `getprivs` — token privileges on Windows; uid/gid/groups and Linux
    capability sets on Unix.
- CLI commands: `psinfo`, `suspend`, `resume`, `getprivs`, `tokens`, `steal`,
  `maketoken`, `impersonate`, `revert`.
- The web portal task dropdown now offers the new task types.

### 2C — Credential access, first cut

- `credential_enum` (credential-gated): read-only discovery of SSH keys
  (including whether a PEM key is encrypted), cloud/VCS/Docker/Kubernetes
  credential files, browser profile stores, shell histories, `/etc/shadow` and
  `/etc/sudoers` readability, Windows Credential Manager/DPAPI paths, and
  sensitive environment-variable values.
- `credential_read <path>` (credential-gated): reads one operator-named regular
  file (devices/FIFOs refused), applies the data quota, and returns base64 plus
  SHA-256. Larger files use `download_chunk`.
- Discovery never decrypts DPAPI/browser stores and never writes to disk.
- CLI commands: `creds`, `credread <path>`.
- Not in this cut: LSASS/SAM/LSA-secret dumping, Kerberos ticket extraction,
  DPAPI decryption, and a server-side credential vault.

## Verification

- `make test` (all modules, with `-race` where configured).
- `go build` / cross-compile for linux/amd64, windows/amd64, darwin/arm64.
- Unit tests: category mapping, process suspend/resume against a live child
  process, the non-Windows token manager, handler argument validation, and
  `process_info`/`getprivs` output.

## Not yet delivered (remaining Phase 2)

- Credential access beyond discovery/read: LSASS/SAM/LSA-secret dumping,
  Kerberos ticket extraction, DPAPI decryption, and a credential vault.
- Lateral movement (SMB/WinRM/WMI/PsExec-style/SSH) and pivot listeners.
- SOCKS5, port forwarding, named-pipe pivots.
- BOF/COFF loader and the plugin manifest system.
- .NET/CLR hosting, PowerShell import, Python operator modules.
- Windows evasion (sleep obfuscation, AMSI/ETW patches, call-stack spoofing).
- Persistence tasks with removable artifact IDs.
- Server-side persistence/reporting of OT findings and a loot store.
