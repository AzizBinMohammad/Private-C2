package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Base struct {
	ID        string         `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

func (b *Base) BeforeCreate(tx *gorm.DB) error {
	if b.ID == "" {
		b.ID = uuid.New().String()
	}
	return nil
}

type Operator struct {
	Base
	Name         string       `gorm:"uniqueIndex;not null" json:"name"`
	Role         string       `gorm:"not null;default:'operator'" json:"role"`
	CertPEM      []byte       `json:"-"`
	MFAEnabled   bool         `gorm:"default:false" json:"mfa_enabled"`
	MFASecret    string       `json:"-"`
	LastActiveAt *time.Time   `json:"last_active_at,omitempty"`
	SourceIP     string       `json:"source_ip,omitempty"`
	Engagements  []Engagement `gorm:"many2many:operator_engagements;" json:"engagements,omitempty"`
}

type Session struct {
	Base
	Hostname     string    `json:"hostname"`
	Username     string    `json:"username"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	RemoteAddr   string    `json:"remote_addr"`
	Transport    string    `json:"transport"`
	Mode         string    `json:"mode"`
	HealthStatus string    `gorm:"default:'healthy'" json:"health_status"`
	EngagementID string    `gorm:"index" json:"engagement_id"`
	LockedBy     string    `json:"locked_by,omitempty"`
	ImplantID    string    `gorm:"index" json:"implant_id"`
	PID          int       `json:"pid"`
	ProcessName  string    `json:"process_name"`
	Domain       string    `json:"domain"`
	Elevated     bool      `json:"elevated"`
	LastCheckin  time.Time `json:"last_checkin"`
	LatencyMs    float64   `json:"latency_ms"`
	JitterMs     float64   `json:"jitter_ms"`
}

type Beacon struct {
	Base
	Hostname     string    `json:"hostname"`
	Username     string    `json:"username"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	RemoteAddr   string    `json:"remote_addr"`
	Transport    string    `json:"transport"`
	EngagementID string    `gorm:"index" json:"engagement_id"`
	IntervalMs   int64     `json:"interval_ms"`
	JitterPct    int       `json:"jitter_pct"`
	ImplantID    string    `gorm:"index" json:"implant_id"`
	LastCheckin  time.Time `json:"last_checkin"`
	NextCheckin  time.Time `json:"next_checkin"`
}

// Task is durable operator intent. Unlike the live in-memory queue it
// survives disconnects and server restarts, and it is bound to the implant so
// a reconnecting agent can resume work.
type Task struct {
	ID           string     `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	SessionID    string     `gorm:"index" json:"session_id"`
	ImplantID    string     `gorm:"index;not null" json:"implant_id"`
	EngagementID string     `gorm:"index" json:"engagement_id"`
	Type         string     `gorm:"not null" json:"type"`
	Args         string     `gorm:"type:text" json:"args"`
	State        string     `gorm:"index;default:'queued'" json:"state"` // queued|sent|running|completed|failed|expired|cancelled
	CreatedBy    string     `json:"created_by"`
	Attempts     int        `gorm:"default:0" json:"attempts"`
	TimeoutMs    int        `json:"timeout_ms"`
	SentAt       *time.Time `json:"sent_at,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ExpiresAt    *time.Time `gorm:"index" json:"expires_at,omitempty"`
	Error        string     `gorm:"type:text" json:"error,omitempty"`
}

func (t *Task) BeforeCreate(_ *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

// TaskResult stores a completed task's output. It deliberately has no
// gorm.DeletedAt: TaskID is unique and a soft-deleted row would collide with a
// future insert for the same task.
type TaskResult struct {
	ID           string    `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	TaskID       string    `gorm:"uniqueIndex;not null" json:"task_id"`
	SessionID    string    `gorm:"index" json:"session_id"`
	EngagementID string    `gorm:"index" json:"engagement_id"`
	Success      bool      `json:"success"`
	Output       string    `gorm:"type:text" json:"output"`
	Error        string    `gorm:"type:text" json:"error,omitempty"`
	Truncated    bool      `json:"truncated,omitempty"`
	Bytes        int64     `json:"bytes,omitempty"`
	CompletedAt  time.Time `gorm:"index" json:"completed_at"`
}

func (r *TaskResult) BeforeCreate(_ *gorm.DB) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	return nil
}

type Listener struct {
	Base
	Type              string `gorm:"not null" json:"type"`
	BindAddr          string `gorm:"not null" json:"bind_addr"`
	Port              int    `gorm:"not null" json:"port"`
	EngagementID      string `gorm:"index" json:"engagement_id"`
	C2ProfileID       string `json:"c2_profile_id,omitempty"`
	Status            string `gorm:"default:'stopped'" json:"status"`
	ActiveConnections int    `json:"active_connections"`
}

type PayloadArtifact struct {
	Base
	CreatedBy    string     `json:"created_by"`
	TargetOS     string     `json:"target_os"`
	TargetArch   string     `json:"target_arch"`
	Mode         string     `json:"mode"`
	Transports   string     `json:"transports"` // JSON array
	Format       string     `json:"format"`
	SHA256       string     `gorm:"uniqueIndex" json:"sha256"`
	FileSize     int64      `json:"file_size"`
	ImplantID    string     `gorm:"index" json:"implant_id"`
	PublicKey    string     `json:"public_key"`
	EngagementID string     `gorm:"index" json:"engagement_id"`
	C2ProfileID  string     `json:"c2_profile_id,omitempty"`
	Expiry       *time.Time `json:"expiry,omitempty"`
	Status       string     `gorm:"default:'active'" json:"status"`
	BinaryData   []byte     `json:"-"`
}

type Engagement struct {
	Base
	Name                 string     `gorm:"not null" json:"name"`
	Description          string     `json:"description"`
	AuthorizationRef     string     `json:"authorization_ref"`
	Status               string     `gorm:"default:'planning'" json:"status"`
	ScopeConfig          string     `gorm:"type:text" json:"scope_config"` // JSON
	TimeWindowStart      *time.Time `json:"time_window_start,omitempty"`
	TimeWindowEnd        *time.Time `json:"time_window_end,omitempty"`
	AuthorizedTechniques string     `gorm:"type:text" json:"authorized_techniques"` // JSON array
	DataCollectionLevel  string     `json:"data_collection_level"`
	ExfilLimitBytes      int64      `json:"exfil_limit_bytes"`
	EmergencyContact     string     `json:"emergency_contact"`
	ProfileConfig        string     `gorm:"type:text" json:"profile_config"` // JSON
	CreatedBy            string     `json:"created_by"`
}

type AuditEntry struct {
	ID            string    `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt     time.Time `gorm:"index" json:"created_at"`
	OperatorID    string    `gorm:"index" json:"operator_id"`
	EngagementID  string    `gorm:"index" json:"engagement_id"`
	SessionID     string    `gorm:"index" json:"session_id"`
	EventType     string    `gorm:"index" json:"event_type"`
	Action        string    `json:"action"`
	Target        string    `json:"target"`
	ResultSummary string    `json:"result_summary"`
	Metadata      string    `gorm:"type:text" json:"metadata"` // JSON
	SourceIP      string    `json:"source_ip"`
	CorrelationID string    `gorm:"index" json:"correlation_id"`
	PreviousHash  string    `json:"previous_hash"`
	EntryHash     string    `json:"entry_hash"`
}

type C2Profile struct {
	Base
	Name        string `gorm:"uniqueIndex;not null" json:"name"`
	Description string `json:"description"`
	Config      string `gorm:"type:text;not null" json:"config"` // JSON
	Version     int    `gorm:"default:1" json:"version"`
}

type Role struct {
	Base
	Name        string `gorm:"uniqueIndex;not null" json:"name"`
	Description string `json:"description"`
	Permissions string `gorm:"type:text" json:"permissions"` // JSON
}
