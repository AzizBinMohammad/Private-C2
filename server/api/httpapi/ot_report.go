package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/store/models"
)

type otReportRequest struct {
	EngagementID string `json:"engagement_id"`
	Title        string `json:"title"`
	Format       string `json:"format"` // json or markdown
}

type otReportSummary struct {
	AssetCount        int     `json:"asset_count"`
	VulnCount         int     `json:"vuln_count"`
	CredentialCount   int     `json:"credential_count"`
	ComplianceCount   int     `json:"compliance_count"`
	SegmentationCount int     `json:"segmentation_count"`
	HMICount          int     `json:"hmi_count"`
	WirelessCount     int     `json:"wireless_count"`
	Critical          int     `json:"critical"`
	High              int     `json:"high"`
	Medium            int     `json:"medium"`
	Low               int     `json:"low"`
	Info              int     `json:"info"`
	ComplianceRate    float64 `json:"compliance_rate"`
	RiskScore         float64 `json:"risk_score"`
}

type otReportData struct {
	EngagementID string                       `json:"engagement_id"`
	GeneratedAt  time.Time                    `json:"generated_at"`
	Summary      otReportSummary              `json:"summary"`
	Assets       []models.OTAssetRecord       `json:"assets"`
	Vulns        []models.OTVulnFinding       `json:"vulnerabilities"`
	Credentials  []models.OTCredentialFinding `json:"credentials"`
	Compliance   []models.OTComplianceFinding `json:"compliance"`
	Segmentation []models.OTSegmentationGap   `json:"segmentation_gaps"`
	Topology     []models.OTTopologyEdge      `json:"topology"`
	HMI          []models.OTHMIFinding        `json:"hmi_findings"`
	Wireless     []models.OTWirelessFinding   `json:"wireless_findings"`
}

func (oth *otHandler) generateOTReport(w http.ResponseWriter, r *http.Request) {
	if oth.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "database unavailable"})
		return
	}
	var req otReportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}
	req.EngagementID = strings.TrimSpace(req.EngagementID)
	if req.EngagementID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "engagement_id is required"})
		return
	}
	var engagement models.Engagement
	if err := oth.db.First(&engagement, "id = ?", req.EngagementID).Error; err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
		return
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "json" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "format must be json or markdown"})
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "OT Assessment — " + engagement.Name
	}

	data, err := oth.collectOTReport(req.EngagementID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	data.GeneratedAt = time.Now().UTC()

	var rendered string
	if format == "json" {
		blob, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		rendered = string(blob)
	} else {
		rendered = renderOTMarkdown(title, data)
	}

	identity, _ := authz.FromContext(r.Context())
	operator := identity.OperatorID
	if operator == "" {
		operator = identity.Username
	}
	record := &models.OTAssessmentReport{
		EngagementID:     req.EngagementID,
		Title:            title,
		Format:           format,
		GeneratedAt:      data.GeneratedAt,
		GeneratedBy:      operator,
		ReportData:       rendered,
		ExecutiveSummary: executiveSummary(data.Summary),
		AssetCount:       data.Summary.AssetCount,
		VulnCount:        data.Summary.VulnCount,
		ComplianceRate:   data.Summary.ComplianceRate,
		RiskScore:        data.Summary.RiskScore,
	}
	if err := oth.db.Create(record).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	if oth.auditor != nil {
		_ = oth.auditor.Log(operator, req.EngagementID, "", audit.EventOTReport,
			"ot.report", record.ID, format,
			map[string]any{"assets": record.AssetCount, "vulns": record.VulnCount}, r.RemoteAddr, "")
	}
	writeJSON(w, http.StatusCreated, record)
}

func (oth *otHandler) collectOTReport(engagementID string) (otReportData, error) {
	data := otReportData{EngagementID: engagementID}
	queries := []struct {
		dest any
	}{{&data.Assets}, {&data.Vulns}, {&data.Credentials}, {&data.Compliance},
		{&data.Segmentation}, {&data.Topology}, {&data.HMI}, {&data.Wireless}}
	for _, q := range queries {
		if err := oth.db.Where("engagement_id = ?", engagementID).Find(q.dest).Error; err != nil {
			return data, err
		}
	}

	s := &data.Summary
	s.AssetCount = len(data.Assets)
	s.VulnCount = len(data.Vulns)
	s.CredentialCount = len(data.Credentials)
	s.ComplianceCount = len(data.Compliance)
	s.SegmentationCount = len(data.Segmentation)
	s.HMICount = len(data.HMI)
	s.WirelessCount = len(data.Wireless)

	bestRisk := 0.0
	note := func(severity string, cvss float64) {
		switch strings.ToLower(severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Info++
		}
		if weight := severityWeight(severity); weight > bestRisk {
			bestRisk = weight
		}
		if cvss > bestRisk {
			bestRisk = cvss
		}
	}
	for _, v := range data.Vulns {
		note(v.Severity, v.CVSS)
	}
	for _, c := range data.Credentials {
		note(c.Severity, 0)
	}
	for _, g := range data.Segmentation {
		note(g.Severity, 0)
	}
	for _, h := range data.HMI {
		note(h.Severity, 0)
	}
	for _, wl := range data.Wireless {
		note(wl.Severity, 0)
	}
	s.RiskScore = bestRisk

	assessed, passed := 0, 0
	for _, c := range data.Compliance {
		switch strings.ToLower(c.Status) {
		case "pass":
			assessed++
			passed++
		case "fail", "partial":
			assessed++
		}
	}
	if assessed > 0 {
		s.ComplianceRate = float64(passed) / float64(assessed) * 100
	}
	return data, nil
}

func severityWeight(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5
	case "high":
		return 8
	case "medium":
		return 5.5
	case "low":
		return 2.5
	case "info":
		return 0.5
	default:
		return 0
	}
}

func executiveSummary(s otReportSummary) string {
	return fmt.Sprintf("%d assets, %d vulnerabilities (%d critical, %d high), %d credential findings, %.1f%% compliance, risk score %.1f/10.",
		s.AssetCount, s.VulnCount, s.Critical, s.High, s.CredentialCount, s.ComplianceRate, s.RiskScore)
}

func renderOTMarkdown(title string, data otReportData) string {
	var b strings.Builder
	s := data.Summary
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "Engagement: `%s`\n\n", data.EngagementID)
	fmt.Fprintf(&b, "Generated: %s\n\n", data.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "## Executive summary\n\n%s\n\n", executiveSummary(s))

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Assets | %d |\n| Vulnerabilities | %d |\n| Credentials | %d |\n", s.AssetCount, s.VulnCount, s.CredentialCount)
	fmt.Fprintf(&b, "| Compliance findings | %d |\n| Segmentation gaps | %d |\n| HMI findings | %d |\n| Wireless findings | %d |\n", s.ComplianceCount, s.SegmentationCount, s.HMICount, s.WirelessCount)
	fmt.Fprintf(&b, "| Severity (critical/high/medium/low/info) | %d/%d/%d/%d/%d |\n", s.Critical, s.High, s.Medium, s.Low, s.Info)
	fmt.Fprintf(&b, "| Compliance rate | %.1f%% |\n| Risk score | %.1f/10 |\n\n", s.ComplianceRate, s.RiskScore)

	if len(data.Assets) > 0 {
		b.WriteString("## Assets\n\n| IP | Role | Vendor | Model | Purdue | Protocols |\n|---|---|---|---|---|---|\n")
		for _, a := range data.Assets {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %s |\n", a.IP, a.Role, a.Vendor, a.Model, a.PurdueLevel, a.Protocols)
		}
		b.WriteString("\n")
	}
	if len(data.Vulns) > 0 {
		b.WriteString("## Vulnerabilities\n\n| Target | CVE | Severity | CVSS | Description |\n|---|---|---|---|---|\n")
		for _, v := range data.Vulns {
			fmt.Fprintf(&b, "| %s | %s | %s | %.1f | %s |\n", v.Target, v.CVEID, v.Severity, v.CVSS, escapeTable(v.Description))
		}
		b.WriteString("\n")
	}
	if len(data.Credentials) > 0 {
		b.WriteString("## Credential findings\n\n| Target | Service | Username | Default | Severity |\n|---|---|---|---|---|\n")
		for _, c := range data.Credentials {
			fmt.Fprintf(&b, "| %s | %s | %s | %t | %s |\n", c.Target, c.Service, c.Username, c.IsDefault, c.Severity)
		}
		b.WriteString("\n")
	}
	if len(data.Compliance) > 0 {
		b.WriteString("## Compliance\n\n| Framework | Requirement | Status | Severity |\n|---|---|---|---|\n")
		for _, c := range data.Compliance {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.Framework, escapeTable(c.Requirement), c.Status, c.Severity)
		}
		b.WriteString("\n")
	}
	if len(data.Segmentation) > 0 {
		b.WriteString("## Segmentation gaps\n\n| From | To | Severity | Description |\n|---|---|---|---|\n")
		for _, g := range data.Segmentation {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", g.FromZone, g.ToZone, g.Severity, escapeTable(g.Description))
		}
		b.WriteString("\n")
	}
	if len(data.HMI) > 0 {
		b.WriteString("## HMI findings\n\n| Target | Title | Severity | Category |\n|---|---|---|---|\n")
		for _, h := range data.HMI {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", h.Target, escapeTable(h.Title), h.Severity, h.Category)
		}
		b.WriteString("\n")
	}
	if len(data.Wireless) > 0 {
		b.WriteString("## Wireless findings\n\n| Protocol | Severity | Evidence |\n|---|---|---|\n")
		for _, wl := range data.Wireless {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", wl.Protocol, wl.Severity, escapeTable(wl.Evidence))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func escapeTable(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
