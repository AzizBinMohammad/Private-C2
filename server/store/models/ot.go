package models

import (
	"time"

	"gorm.io/gorm"
)

// OTAssetRecord represents a discovered OT/ICS asset persisted to the database.
type OTAssetRecord struct {
	Base
	EngagementID    string         `gorm:"index;not null" json:"engagement_id"`
	IP              string         `gorm:"index" json:"ip"`
	MAC             string         `json:"mac,omitempty"`
	Hostname        string         `json:"hostname,omitempty"`
	Vendor          string         `json:"vendor,omitempty"`
	Model           string         `json:"model,omitempty"`
	Firmware        string         `json:"firmware,omitempty"`
	SerialNumber    string         `json:"serial_number,omitempty"`
	Role            string         `json:"role,omitempty"` // PLC, HMI, RTU, DCS, EWS, Historian, Gateway, IO, Sensor
	PurdueLevel     int            `json:"purdue_level"`
	Protocol        string         `json:"protocol,omitempty"`
	Protocols       string         `gorm:"type:text" json:"protocols,omitempty"` // JSON array
	SafetyRated     bool           `json:"safety_rated"`
	SILLevel        int            `json:"sil_level"`
	Description     string         `json:"description,omitempty"`
	OpenPorts       string         `gorm:"type:text" json:"open_ports,omitempty"` // JSON array
	Services        string         `gorm:"type:text" json:"services,omitempty"`   // JSON array
	Banners         string         `gorm:"type:text" json:"banners,omitempty"`    // JSON object
	DiscoveryMethod string         `json:"discovery_method,omitempty"`
	Confidence      float64        `json:"confidence"`
	Tags            string         `gorm:"type:text" json:"tags,omitempty"` // JSON array
	RawData         string         `gorm:"type:text" json:"raw_data,omitempty"` // JSON
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

func (OTAssetRecord) TableName() string { return "ot_assets" }

// OTCredentialFinding records a default credential finding.
type OTCredentialFinding struct {
	Base
	EngagementID string `gorm:"index;not null" json:"engagement_id"`
	AssetID      string `gorm:"index" json:"asset_id"`
	Target       string `json:"target"`
	Service      string `json:"service"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	IsDefault    bool   `json:"is_default"`
	Vendor       string `json:"vendor,omitempty"`
	Protocol     string `json:"protocol"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
	TestedAt     time.Time `json:"tested_at"`
}

func (OTCredentialFinding) TableName() string { return "ot_credential_findings" }

// OTVulnFinding records a vulnerability finding for an OT asset.
type OTVulnFinding struct {
	Base
	EngagementID    string  `gorm:"index;not null" json:"engagement_id"`
	AssetID         string  `gorm:"index" json:"asset_id"`
	Target          string  `json:"target"`
	CVEID           string  `gorm:"index" json:"cve_id"`
	Description     string  `gorm:"type:text" json:"description"`
	CVSS            float64 `json:"cvss"`
	Severity        string  `json:"severity"`
	AffectedVersion string  `json:"affected_version,omitempty"`
	FixedVersion    string  `json:"fixed_version,omitempty"`
	VendorAdvisory  string  `json:"vendor_advisory,omitempty"`
	ICSCERTAdvisory string  `json:"icscert_advisory,omitempty"`
	AttackVector    string  `json:"attack_vector,omitempty"`
	Mitigations     string  `gorm:"type:text" json:"mitigations,omitempty"` // JSON array
}

func (OTVulnFinding) TableName() string { return "ot_vuln_findings" }

// OTSegmentationGap records a network segmentation issue.
type OTSegmentationGap struct {
	Base
	EngagementID string `gorm:"index;not null" json:"engagement_id"`
	Description  string `gorm:"type:text" json:"description"`
	FromZone     string `json:"from_zone"`
	ToZone       string `json:"to_zone"`
	FromLevel    int    `json:"from_level"`
	ToLevel      int    `json:"to_level"`
	Protocol     string `json:"protocol,omitempty"`
	Severity     string `json:"severity"`
}

func (OTSegmentationGap) TableName() string { return "ot_segmentation_gaps" }

// OTComplianceFinding records a compliance gap.
type OTComplianceFinding struct {
	Base
	EngagementID string `gorm:"index;not null" json:"engagement_id"`
	Framework    string `json:"framework"` // IEC 62443, NIST 800-82, NERC CIP
	Requirement  string `json:"requirement"`
	Section      string `json:"section"`
	Description  string `gorm:"type:text" json:"description"`
	Status       string `json:"status"` // pass, fail, partial, not_assessed
	Severity     string `json:"severity"`
	Evidence     string `gorm:"type:text" json:"evidence,omitempty"`
	Remediation  string `gorm:"type:text" json:"remediation,omitempty"`
}

func (OTComplianceFinding) TableName() string { return "ot_compliance_findings" }

// OTTopologyEdge records a connection between two OT assets.
type OTTopologyEdge struct {
	Base
	EngagementID  string `gorm:"index;not null" json:"engagement_id"`
	SourceIP      string `gorm:"index" json:"source_ip"`
	TargetIP      string `gorm:"index" json:"target_ip"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port"`
	Encrypted     bool   `json:"encrypted"`
	Bidirectional bool   `json:"bidirectional"`
}

func (OTTopologyEdge) TableName() string { return "ot_topology_edges" }

// OTCaptureSession records an OT traffic capture session.
type OTCaptureSession struct {
	Base
	EngagementID      string    `gorm:"index;not null" json:"engagement_id"`
	StartTime         time.Time `json:"start_time"`
	EndTime           time.Time `json:"end_time"`
	TotalPackets      int       `json:"total_packets"`
	TotalBytes        int64     `json:"total_bytes"`
	ProtocolBreakdown string    `gorm:"type:text" json:"protocol_breakdown,omitempty"` // JSON
	CommMatrix        string    `gorm:"type:text" json:"comm_matrix,omitempty"`        // JSON
	AnomalyIndicators string    `gorm:"type:text" json:"anomaly_indicators,omitempty"` // JSON
}

func (OTCaptureSession) TableName() string { return "ot_capture_sessions" }

// OTAssessmentReport records a generated assessment report.
type OTAssessmentReport struct {
	Base
	EngagementID    string    `gorm:"index;not null" json:"engagement_id"`
	Title           string    `json:"title"`
	Format          string    `json:"format"` // json, markdown, csv, mitre_attack
	GeneratedAt     time.Time `json:"generated_at"`
	GeneratedBy     string    `json:"generated_by"`
	ReportData      string    `gorm:"type:text" json:"report_data"` // Full report content
	ExecutiveSummary string   `gorm:"type:text" json:"executive_summary,omitempty"`
	AssetCount      int       `json:"asset_count"`
	VulnCount       int       `json:"vuln_count"`
	ComplianceRate  float64   `json:"compliance_rate"`
	RiskScore       float64   `json:"risk_score"`
}

func (OTAssessmentReport) TableName() string { return "ot_assessment_reports" }

// OTHMIFinding records an HMI web interface security finding.
type OTHMIFinding struct {
	Base
	EngagementID string `gorm:"index;not null" json:"engagement_id"`
	AssetID      string `gorm:"index" json:"asset_id"`
	Target       string `json:"target"`
	URL          string `json:"url"`
	Title        string `json:"title"`
	Description  string `gorm:"type:text" json:"description"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	Remediation  string `gorm:"type:text" json:"remediation,omitempty"`
}

func (OTHMIFinding) TableName() string { return "ot_hmi_findings" }

// OTWirelessFinding records wireless presence findings in OT zones.
type OTWirelessFinding struct {
	Base
	EngagementID string `gorm:"index;not null" json:"engagement_id"`
	Protocol     string `json:"protocol"` // wifi, wirelesshart, isa100, zigbee, ble
	Evidence     string `gorm:"type:text" json:"evidence"`
	Gateway      string `json:"gateway,omitempty"`
	Severity     string `json:"severity"`
	Risk         string `gorm:"type:text" json:"risk,omitempty"`
	Remediation  string `gorm:"type:text" json:"remediation,omitempty"`
}

func (OTWirelessFinding) TableName() string { return "ot_wireless_findings" }
