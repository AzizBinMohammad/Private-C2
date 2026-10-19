package protocol

import "strings"

// Task type names are the single source of truth shared by the server policy,
// the implant registry, and the operator surfaces. Keep this list in sync with
// the handlers registered by the implant; the portal test asserts the embedded
// HTML offers exactly these values.
const (
	TaskWhoami        = "whoami"
	TaskGetuid        = "getuid"
	TaskGetgid        = "getgid"
	TaskDownloadStat  = "download_stat"
	TaskDownloadChunk = "download_chunk"
	TaskUploadChunk   = "upload_chunk"

	TaskOTDiscover    = "ot_discover"
	TaskOTFingerprint = "ot_fingerprint"
	TaskOTVulnScan    = "ot_vuln_scan"
	TaskOTHMI         = "ot_hmi"
	TaskOTHistorian   = "ot_historian"
	TaskOTWireless    = "ot_wireless"
	TaskOTSerial      = "ot_serial"
	TaskOTPLCRead     = "ot_plc_read"
	TaskOTCredentials = "ot_credentials"

	TaskCredentialEnum = "credential_enum"
	TaskCredentialRead = "credential_read"
	TaskCredentialDump = "credential_dump"

	TaskLateralSSH   = "lateral_ssh"
	TaskPivotSocks   = "pivot_socks"
	TaskPivotPortfwd = "pivot_portfwd"

	TaskPowerShell      = "powershell"
	TaskPython          = "python"
	TaskExecuteAssembly = "execute_assembly"

	TaskEvasionTimestomp = "evasion_timestomp"
	TaskEvasionCleanup   = "evasion_cleanup"

	TaskPersistShell    = "persist_shell"
	TaskPersistSystemd  = "persist_systemd"
	TaskPersistCron     = "persist_cron"
	TaskPersistRegistry = "persist_registry"
	TaskPersistSchtasks = "persist_schtasks"

	TaskProcessInfo      = "process_info"
	TaskProcessSuspend   = "process_suspend"
	TaskProcessResume    = "process_resume"
	TaskTokenList        = "token_list"
	TaskTokenSteal       = "token_steal"
	TaskTokenMake        = "token_make"
	TaskTokenImpersonate = "token_impersonate"
	TaskTokenRevert      = "token_revert"
	TaskGetprivs         = "getprivs"

	TaskShell      = "shell"
	TaskUpload     = "upload"
	TaskDownload   = "download"
	TaskLS         = "ls"
	TaskPS         = "ps"
	TaskKill       = "kill"
	TaskIfconfig   = "ifconfig"
	TaskNetstat    = "netstat"
	TaskScreenshot = "screenshot"
	TaskNmap       = "nmap"
	TaskScan       = "scan"
	TaskCat        = "cat"
	TaskMkdir      = "mkdir"
	TaskRm         = "rm"
	TaskCp         = "cp"
	TaskMv         = "mv"
	TaskPwd        = "pwd"
	TaskCd         = "cd"
	TaskResolve    = "resolve"
	TaskPortscan   = "portscan"
)

// implementedTaskTypes is intentionally ordered for stable UI output.
var implementedTaskTypes = []string{
	TaskWhoami,
	TaskGetuid,
	TaskGetgid,
	TaskDownloadStat,
	TaskDownloadChunk,
	TaskUploadChunk,
	TaskOTDiscover,
	TaskOTFingerprint,
	TaskOTVulnScan,
	TaskOTHMI,
	TaskOTHistorian,
	TaskOTWireless,
	TaskOTSerial,
	TaskOTPLCRead,
	TaskOTCredentials,
	TaskCredentialEnum,
	TaskCredentialRead,
	TaskCredentialDump,
	TaskLateralSSH,
	TaskPivotSocks,
	TaskPivotPortfwd,
	TaskPowerShell,
	TaskPython,
	TaskExecuteAssembly,
	TaskEvasionTimestomp,
	TaskEvasionCleanup,
	TaskPersistShell,
	TaskPersistSystemd,
	TaskPersistCron,
	TaskPersistRegistry,
	TaskPersistSchtasks,
	TaskProcessInfo,
	TaskProcessSuspend,
	TaskProcessResume,
	TaskTokenList,
	TaskTokenSteal,
	TaskTokenMake,
	TaskTokenImpersonate,
	TaskTokenRevert,
	TaskGetprivs,
	TaskShell,
	TaskUpload,
	TaskDownload,
	TaskLS,
	TaskPS,
	TaskKill,
	TaskIfconfig,
	TaskNetstat,
	TaskScreenshot,
	TaskNmap,
	TaskScan,
	TaskCat,
	TaskMkdir,
	TaskRm,
	TaskCp,
	TaskMv,
	TaskPwd,
	TaskCd,
	TaskResolve,
	TaskPortscan,
}

var implementedTaskTypeSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(implementedTaskTypes))
	for _, t := range implementedTaskTypes {
		m[t] = struct{}{}
	}
	return m
}()

// ImplementedTaskTypes returns a copy of every task type the implant is
// expected to implement. Callers may mutate the returned slice safely.
func ImplementedTaskTypes() []string {
	out := make([]string, len(implementedTaskTypes))
	copy(out, implementedTaskTypes)
	return out
}

// IsImplementedTaskType reports whether taskType is in the shared registry.
func IsImplementedTaskType(taskType string) bool {
	_, ok := implementedTaskTypeSet[taskType]
	return ok
}

// TaskCategory groups task types for engagement-level capability gates.
type TaskCategory string

const (
	CategoryGeneral     TaskCategory = "general"
	CategoryPrivilege   TaskCategory = "privilege"
	CategoryCredential  TaskCategory = "credential"
	CategoryLateral     TaskCategory = "lateral"
	CategoryPersistence TaskCategory = "persistence"
	CategoryEvasion     TaskCategory = "evasion"
	CategoryOT          TaskCategory = "ot"
)

// CategoryFor maps a task type to the engagement capability it requires.
// Unknown task types are general; the registry check still rejects them.
func CategoryFor(taskType string) TaskCategory {
	switch {
	case taskType == TaskOTCredentials:
		return CategoryCredential
	case strings.HasPrefix(taskType, "ot_"):
		return CategoryOT
	case strings.HasPrefix(taskType, "credential_"), taskType == "hashdump", taskType == "lsass_dump":
		return CategoryCredential
	case strings.HasPrefix(taskType, "lateral_"), strings.HasPrefix(taskType, "pivot_"),
		taskType == "psexec", taskType == "winrm", taskType == "wmi":
		return CategoryLateral
	case strings.HasPrefix(taskType, "persist_"):
		return CategoryPersistence
	case strings.HasPrefix(taskType, "evasion_"), strings.HasPrefix(taskType, "syscall_"):
		return CategoryEvasion
	case taskType == TaskProcessSuspend, taskType == TaskProcessResume,
		taskType == TaskGetprivs,
		strings.HasPrefix(taskType, "token_"),
		strings.HasPrefix(taskType, "privesc_"):
		return CategoryPrivilege
	default:
		return CategoryGeneral
	}
}
