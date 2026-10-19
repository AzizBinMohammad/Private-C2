package protocol

// Task type names are the single source of truth shared by the server policy,
// the implant registry, and the operator surfaces. Keep this list in sync with
// the handlers registered by the implant; the portal test asserts the embedded
// HTML offers exactly these values.
const (
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
