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
  `AllowEvasion`, `AllowOTAssessment`, and `AllowCodeExecution` (all default
  false).
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
- `credential_dpapi` (Windows): decrypts an operator-supplied DPAPI blob
  (optional entropy, optional machine scope).
- `credential_kerberos`: lists tickets with `klist` and captures the local
  credential cache (`KRB5CCNAME` or `/tmp/krb5cc_<uid>`) as base64 + SHA-256.
- Credential loot is refused by the loot API unless the engagement enables
  credential access.

### 2D — Lateral movement

- `lateral_ssh`: runs a command through the target's `ssh` client with
  key/agent auth, or password auth via `sshpass -e` (the password is passed in
  the environment, never on the command line).
- `lateral_winrm`: PowerShell Remoting (`Invoke-Command`) with an in-memory
  PSCredential; optional SSL and port.
- `lateral_wmi`: `Invoke-WmiMethod Win32_Process Create` with in-memory
  credentials; returns the remote process ID.
- Targets are scope-checked on the server and again in the implant.

### 2E — Pivoting and proxying

- `pivot_socks`: SOCKS5 proxy with optional RFC 1929 username/password auth,
  CONNECT only, and a per-connection scope check before every dial.
- `pivot_portfwd`: local TCP port forward; the destination host is
  scope-checked before every dial.
- `pivot_namedpipe` (Windows): a named-pipe server that relays each client to
  a scope-checked TCP target.
- All support `start`, `stop`, and `status`. Listeners are owned by the
  implant and stop when it exits.

### 2F — Scripting and in-memory code

- `powershell`: `-EncodedCommand` execution with a bounded task timeout.
- `python`: `python3 -c` (falling back to `python`).
- `execute_assembly`: loads a base64 .NET assembly into a PowerShell process
  and invokes its entry point. This is a PowerShell-hosted equivalent, not an
  in-process CLR host; the base implant stays CGO-free.
- `inline_execute` (Windows, code-execution-gated): parses an AMD64 COFF/BOF,
  maps its sections into `VirtualAlloc` memory, applies ADDR64/ADDR32/ADDR32NB
  and REL32 relocations, resolves a Beacon API subset through
  `syscall.NewCallback`, and calls the `go` entry point with base64 args.
  - Implemented Beacon API: `BeaconOutput`, `BeaconError`, `BeaconDataParse`,
    `BeaconDataExtract`, `BeaconDataInt`, `BeaconDataShort`,
    `BeaconDataLength`, `BeaconIsAdmin`, `BeaconFormatAlloc`,
    `BeaconFormatAppend`, `BeaconFormatToString`, `BeaconFormatReset`,
    `BeaconFormatFree`, `BeaconRevertToken`, `BeaconGetSpawnTo`,
    `BeaconUseToken`.
  - Not implemented: `BeaconPrintf` (varargs), token use/injection helpers,
    i386 COFF, and deep-stack BOFs that exceed the Go syscall stack.
- The command allowlist applies to `shell`, `powershell`, and `python`.

### 2G — Evasion

- `evasion_timestomp`: sets atime/mtime from an RFC3339 timestamp or a
  reference file.
- `evasion_cleanup`: dry-run by default; with `{"apply":true}` removes the
  fixed set of shell-history files and reports the environment variables
  unset in the implant process. It cannot delete arbitrary paths.
- `evasion_amsi` (Windows): patches `amsi.dll!AmsiScanBuffer` to return
  `E_INVALIDARG`.
- `evasion_etw` (Windows): patches `ntdll.dll!EtwEventWrite` to return success.
- `evasion_ppid_spoof` (Windows): starts a process with
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` pointing at an operator-chosen PID.

### 2H — Persistence

- Unix: `persist_shell` (marked block in a shell profile), `persist_systemd`
  (user unit, enabled through `systemctl --user`), `persist_cron` (marked
  crontab line, `@reboot` by default).
- Windows: `persist_registry` (HKCU Run value prefixed `pc2-`) and
  `persist_schtasks` (`ONLOGON`/`ONSTART` task prefixed `pc2-`).
- Every artifact has a deterministic ID derived from kind and name, supports
  `add`, `remove`, and `list`, and honors `dry_run`.

### 2I — Loot store

- `LootArtifact` metadata plus AES-256-GCM-encrypted blobs under
  `PC2_LOOT_DIR` (default `./loot`, mode 0700, 16 MiB per artifact). The key
  comes from `PC2_LOOT_KEY`, `<loot-dir>/loot.key`, or a newly generated key.
  Legacy plaintext blobs remain readable.
- `POST /api/loot` accepts base64 data or promotes a completed task result;
  `GET /api/loot` filters by engagement/kind; download, delete, and
  `?redact=true` (text only) are supported.
- RBAC: `loot.read` and `loot.write`. Credential-kind loot additionally
  requires the engagement's credential capability.
- `pkg/redact` removes private-key blocks, AWS access keys, bearer tokens,
  authorization headers, and key/value secrets from deliverables.

### 2J — OT persistence and reporting

- `POST /api/ot/import` persists asset, fingerprint, vulnerability, credential,
  HMI, wireless, compliance, topology, and segmentation results, supplied
  inline or loaded from a completed task result. Imports require the
  engagement's OT assessment capability.
- Assets upsert by `(engagement_id, ip)` and merge only non-empty fields.
- `POST /api/ot/reports` generates a stored Markdown or JSON assessment report
  with severity counts, compliance rate, and risk score.
- RBAC: `ot.read` / `ot.write`; audit events `ot.import` and `ot.report`.

### 2K — Plugin manifests

- `PC2_PLUGIN_DIR` (default `./plugins`) holds `*.json` manifests that map
  operator commands to registered task types with an argument template.
- Manifests are validated (name, version, command uniqueness, registered task
  type, template syntax). Optional Ed25519 signatures are verified over the
  canonical manifest; `PC2_PLUGIN_REQUIRE_SIGNED=true` rejects unsigned ones.
- `GET /api/plugins`, `POST /api/plugins/reload`, and `POST /api/plugins/run`.
  Plugin runs go through the same engagement policy as direct tasking, so a
  plugin cannot bypass a capability gate.
- RBAC: `plugin.read` / `plugin.run`.

### Operator surfaces

- CLI: `psinfo`, `suspend`, `resume`, `getprivs`, `tokens`, `steal`,
  `maketoken`, `impersonate`, `revert`, `creds`, `credread`, `dump`, `dpapi`,
  `kerberos`, `assembly`, `bof`, `amsi`, `etw`, `ppid`, `namedpipe`,
  `winrm`, `wmi`, `plugins`, `pluginrun`, `otimport`, `otreports`, and
  `loot list|add|get|download|rm`.
- The web portal task dropdown offers every registered task type (enforced by
  a registry sync test) and has a Loot tab with download, redacted download,
  delete, and task-result promotion.

## Verification

- `make test` — all modules, race detector.
- `make lint` — `go vet` (golangci-lint is not installed here).
- `make build` — server, client, builder.
- `make cross-compile` — linux/amd64, windows/amd64, darwin/arm64.
- `make e2e-smoke` — real server and implants over mTLS and HTTPS; an
  API-built no-flags payload; task round-trips; chunked download; structured
  `process_info`; denial of a privilege-gated task on an engagement-less
  session; a loot create/download/delete round-trip; and an OT asset
  import + Markdown report.
- Unit tests cover capability mapping, process suspend/resume against a live
  child, the non-Windows token manager, credential discovery/read/DPAPI,
  Kerberos ccache capture, lateral SSH/WinRM argument building, SOCKS5
  authentication and scope denial, port-forward relay, persistence
  add/list/remove and dry-run, timestomp, loot encryption/legacy/redaction,
  RBAC and gates, plugin validation/signatures/policy bypass, OT import merge
  and report counts, COFF parsing/relocations, the Beacon data parser, format
  buffers, and AMSI/ETW/PPID error paths.

## Known limits / not delivered

These are not claimed as complete:

- **In-process CLR hosting.** `execute_assembly` uses PowerShell; it does not
  host the CLR in the implant. A pure-Go COM CLR host is deferred until it can
  be verified on the Windows lab host.
- **SMB/PsExec lateral movement and reverse port forwarding.** WinRM, WMI, SSH,
  SOCKS5, TCP port-forward, and named-pipe pivots are supported. SMB
  pass-the-hash and reverse forwarding need an NTLM/SMB client and a
  multiplexed C2 stream, respectively.
- **Sleep obfuscation, call-stack spoofing, module stomping.** AMSI/ETW
  patching and PPID spoofing are implemented; the remaining memory-evasion
  techniques need a Windows lab to verify their behavior and detection impact.
- **Browser credential decryption.** `credential_enum` locates browser stores
  and `credential_dpapi` decrypts DPAPI blobs, but the SQLite `logins` tables
  are not parsed/decrypted in-implant.
- **BOF limits.** AMD64 only, no `BeaconPrintf`, no i386, no injection/token
  Beacon helpers, and the Go syscall stack may be too small for unusually
  deep BOFs.
- **OT report exports.** Markdown and JSON only (no PDF/CSV).
- **Windows execution verification.** Every Windows path compiles under
  `GOOS=windows`; none has been run on a Windows lab host in this
  environment. Treat them as cross-compiled, not behaviorally verified.
