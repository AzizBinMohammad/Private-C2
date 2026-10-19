package protocol

// ImplantConfig is embedded into a built payload. Flags may override it for
// development, but a generated payload runs with no arguments.
type ImplantConfig struct {
	Transport string `json:"transport,omitempty"` // "mtls" or "https"

	ServerAddr string `json:"server_addr,omitempty"`
	HTTPSURL   string `json:"https_url,omitempty"`

	CACertPEM     string `json:"ca_cert_pem,omitempty"`
	ClientCertPEM string `json:"client_cert_pem,omitempty"`
	ClientKeyPEM  string `json:"client_key_pem,omitempty"`
	Insecure      bool   `json:"insecure,omitempty"`

	IntervalMs int    `json:"interval_ms,omitempty"`
	JitterPct  int    `json:"jitter_pct,omitempty"`
	Mode       string `json:"mode,omitempty"`

	EngagementID string `json:"engagement_id,omitempty"`

	ScopeCIDRs   []string `json:"scope_cidrs,omitempty"`
	ScopeHosts   []string `json:"scope_hosts,omitempty"`
	ScopeDomains []string `json:"scope_domains,omitempty"`

	KillDate       string `json:"kill_date,omitempty"`
	WindowStart    string `json:"window_start,omitempty"`
	WindowEnd      string `json:"window_end,omitempty"`
	DataQuotaBytes int64  `json:"data_quota_bytes,omitempty"`
	RemoteKillURL  string `json:"remote_kill_url,omitempty"`
	SafeMode       bool   `json:"safe_mode,omitempty"`
}
