package runtime

// SystemInfo holds cross-platform information about the host system.
type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Username     string `json:"username"`
	UserID       string `json:"user_id"`
	ProcessID    int    `json:"process_id"`
	ProcessName  string `json:"process_name"`
	InternalIPs  []string `json:"internal_ips"`
	Integrity    string `json:"integrity"` // "low", "medium", "high", "system"
}

// Collector defines the interface for gathering system information.
// Each platform provides its own implementation.
type Collector interface {
	Collect() (*SystemInfo, error)
}
