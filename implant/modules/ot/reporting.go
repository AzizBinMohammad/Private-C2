package ot

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ReportFormat specifies the output format for a report.
type ReportFormat string

const (
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatMarkdown ReportFormat = "markdown"
	ReportFormatCSV      ReportFormat = "csv"
	ReportFormatATTCK    ReportFormat = "mitre_attack_navigator"
)

// AssessmentReport holds the complete OT assessment report data.
type AssessmentReport struct {
	Metadata       ReportMetadata       `json:"metadata"`
	ExecutiveSummary string             `json:"executive_summary"`
	Assets         []OTAsset            `json:"assets"`
	Vulnerabilities []*VulnScanResult   `json:"vulnerabilities,omitempty"`
	Compliance     *ComplianceReport    `json:"compliance,omitempty"`
	Segmentation   *SegmentationAnalysis `json:"segmentation,omitempty"`
	Topology       *NetworkTopology     `json:"topology,omitempty"`
	Credentials    []*CredentialTestResult `json:"credentials,omitempty"`
	Wireless       *WirelessAssessment  `json:"wireless,omitempty"`
	Historians     *HistorianAssessment `json:"historians,omitempty"`
	HMI            []*HMIAssessment     `json:"hmi,omitempty"`
	RiskMatrix     []RiskItem           `json:"risk_matrix"`
	Recommendations []Recommendation    `json:"recommendations"`
}

// ReportMetadata holds report metadata.
type ReportMetadata struct {
	Title        string    `json:"title"`
	EngagementID string    `json:"engagement_id"`
	AssessorID   string    `json:"assessor_id"`
	StartDate    time.Time `json:"start_date"`
	EndDate      time.Time `json:"end_date"`
	Scope        string    `json:"scope"`
	Classification string `json:"classification"`
	Version      string    `json:"version"`
}

// RiskItem represents an entry in the risk matrix.
type RiskItem struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Category    string  `json:"category"`
	Likelihood  string  `json:"likelihood"`  // "low", "medium", "high", "critical"
	Impact      string  `json:"impact"`      // "low", "medium", "high", "critical"
	RiskScore   float64 `json:"risk_score"`  // 0-10
	Mitigations []string `json:"mitigations"`
}

// Recommendation is a prioritized remediation recommendation.
type Recommendation struct {
	Priority    int    `json:"priority"` // 1 = highest
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Effort      string `json:"effort"` // "low", "medium", "high"
	Impact      string `json:"impact"` // "low", "medium", "high"
}

// MITREATTCKLayer represents a MITRE ATT&CK Navigator layer.
type MITREATTCKLayer struct {
	Name        string                 `json:"name"`
	Versions    MITREVersions          `json:"versions"`
	Domain      string                 `json:"domain"`
	Description string                 `json:"description"`
	Techniques  []MITRETechnique       `json:"techniques"`
	Gradient    MITREGradient          `json:"gradient"`
	LegendItems []MITRELegendItem      `json:"legendItems"`
}

// MITREVersions holds version info for the navigator layer.
type MITREVersions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

// MITRETechnique represents a technique in the layer.
type MITRETechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Comment     string `json:"comment"`
	Color       string `json:"color,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// MITREGradient defines the color gradient for scores.
type MITREGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

// MITRELegendItem defines a legend entry.
type MITRELegendItem struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

// ReportGenerator generates assessment reports.
type ReportGenerator struct {
	report *AssessmentReport
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(report *AssessmentReport) *ReportGenerator {
	return &ReportGenerator{report: report}
}

// Generate produces the report in the specified format.
func (rg *ReportGenerator) Generate(format ReportFormat) ([]byte, error) {
	switch format {
	case ReportFormatJSON:
		return rg.generateJSON()
	case ReportFormatMarkdown:
		return rg.generateMarkdown()
	case ReportFormatCSV:
		return rg.generateCSV()
	case ReportFormatATTCK:
		return rg.generateATTCKNavigator()
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// generateJSON produces a JSON report.
func (rg *ReportGenerator) generateJSON() ([]byte, error) {
	rg.buildExecutiveSummary()
	rg.buildRiskMatrix()
	rg.buildRecommendations()
	return json.MarshalIndent(rg.report, "", "  ")
}

// generateMarkdown produces a Markdown report.
func (rg *ReportGenerator) generateMarkdown() ([]byte, error) {
	rg.buildExecutiveSummary()
	rg.buildRiskMatrix()
	rg.buildRecommendations()

	var b strings.Builder

	// Header
	b.WriteString(fmt.Sprintf("# %s\n\n", rg.report.Metadata.Title))
	b.WriteString(fmt.Sprintf("**Engagement ID:** %s\n\n", rg.report.Metadata.EngagementID))
	b.WriteString(fmt.Sprintf("**Assessment Period:** %s to %s\n\n",
		rg.report.Metadata.StartDate.Format("2006-01-02"),
		rg.report.Metadata.EndDate.Format("2006-01-02")))
	b.WriteString(fmt.Sprintf("**Classification:** %s\n\n", rg.report.Metadata.Classification))
	b.WriteString("---\n\n")

	// Executive Summary
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(rg.report.ExecutiveSummary)
	b.WriteString("\n\n")

	// Asset Inventory
	b.WriteString("## Asset Inventory\n\n")
	b.WriteString(fmt.Sprintf("Total OT assets discovered: **%d**\n\n", len(rg.report.Assets)))
	b.WriteString("| IP | Vendor | Model | Role | Purdue Level |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, asset := range rg.report.Assets {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d |\n",
			asset.IP, asset.Vendor, asset.Model, asset.Role, asset.PurdueLevel))
	}
	b.WriteString("\n")

	// Risk Matrix
	b.WriteString("## Risk Matrix\n\n")
	b.WriteString("| ID | Title | Likelihood | Impact | Score |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, risk := range rg.report.RiskMatrix {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %.1f |\n",
			risk.ID, risk.Title, risk.Likelihood, risk.Impact, risk.RiskScore))
	}
	b.WriteString("\n")

	// Vulnerability Summary
	if len(rg.report.Vulnerabilities) > 0 {
		b.WriteString("## Vulnerability Summary\n\n")
		totalVulns := 0
		for _, vr := range rg.report.Vulnerabilities {
			totalVulns += len(vr.Vulnerabilities)
		}
		b.WriteString(fmt.Sprintf("Total vulnerabilities found: **%d** across %d assets\n\n",
			totalVulns, len(rg.report.Vulnerabilities)))
	}

	// Compliance
	if rg.report.Compliance != nil {
		b.WriteString("## Compliance Assessment\n\n")
		b.WriteString(fmt.Sprintf("Compliance Rate: **%.1f%%**\n\n", rg.report.Compliance.Summary.ComplianceRate))
		b.WriteString(fmt.Sprintf("- Passed: %d\n", rg.report.Compliance.Summary.Passed))
		b.WriteString(fmt.Sprintf("- Failed: %d\n", rg.report.Compliance.Summary.Failed))
		b.WriteString(fmt.Sprintf("- Partial: %d\n", rg.report.Compliance.Summary.Partial))
		b.WriteString(fmt.Sprintf("- Not Assessed: %d\n\n", rg.report.Compliance.Summary.NotAssessed))
	}

	// Segmentation
	if rg.report.Segmentation != nil {
		b.WriteString("## Network Segmentation\n\n")
		b.WriteString(fmt.Sprintf("Overall Score: **%.1f/100**\n\n", rg.report.Segmentation.OverallScore))
		if len(rg.report.Segmentation.Gaps) > 0 {
			b.WriteString("### Segmentation Gaps\n\n")
			for _, gap := range rg.report.Segmentation.Gaps {
				b.WriteString(fmt.Sprintf("- **[%s]** %s\n", strings.ToUpper(gap.Severity), gap.Description))
			}
			b.WriteString("\n")
		}
	}

	// Recommendations
	b.WriteString("## Recommendations\n\n")
	for _, rec := range rg.report.Recommendations {
		b.WriteString(fmt.Sprintf("### %d. %s\n\n", rec.Priority, rec.Title))
		b.WriteString(fmt.Sprintf("%s\n\n", rec.Description))
		b.WriteString(fmt.Sprintf("- **Effort:** %s | **Impact:** %s\n\n", rec.Effort, rec.Impact))
	}

	return []byte(b.String()), nil
}

// generateCSV produces a CSV findings export.
func (rg *ReportGenerator) generateCSV() ([]byte, error) {
	var b strings.Builder

	// Header
	b.WriteString("Category,Title,Severity,Target,Description,Remediation\n")

	// Vulnerability findings
	for _, vr := range rg.report.Vulnerabilities {
		for _, v := range vr.Vulnerabilities {
			b.WriteString(fmt.Sprintf("Vulnerability,%s,%s,%s,%s,%s\n",
				csvEscape(v.CVEID), v.Severity, vr.Target,
				csvEscape(v.Description), csvEscape(strings.Join(v.Mitigations, "; "))))
		}
		for _, p := range vr.InsecureProtos {
			b.WriteString(fmt.Sprintf("Insecure Protocol,%s,%s,%s,%s,%s\n",
				csvEscape(p.Protocol), p.Severity, vr.Target,
				csvEscape(p.Issue), csvEscape(p.Remediation)))
		}
	}

	// Compliance findings
	if rg.report.Compliance != nil {
		for _, f := range rg.report.Compliance.Findings {
			b.WriteString(fmt.Sprintf("Compliance,%s,%s,%s,%s,%s\n",
				csvEscape(f.Requirement), f.Severity, f.Section,
				csvEscape(f.Description), csvEscape(f.Remediation)))
		}
	}

	// Credential findings
	for _, cr := range rg.report.Credentials {
		for _, f := range cr.Findings {
			b.WriteString(fmt.Sprintf("Credential,%s,%s,%s,%s,Change default credentials\n",
				csvEscape(f.Description), f.Severity, cr.Target, csvEscape(f.Description)))
		}
	}

	return []byte(b.String()), nil
}

// generateATTCKNavigator creates a MITRE ATT&CK for ICS Navigator layer.
func (rg *ReportGenerator) generateATTCKNavigator() ([]byte, error) {
	layer := MITREATTCKLayer{
		Name:        rg.report.Metadata.Title + " - ATT&CK for ICS Coverage",
		Domain:      "ics-attack",
		Description: fmt.Sprintf("OT Assessment coverage for engagement %s", rg.report.Metadata.EngagementID),
		Versions: MITREVersions{
			Attack:    "14",
			Navigator: "4.9.1",
			Layer:     "4.5",
		},
		Gradient: MITREGradient{
			Colors:   []string{"#ffffff", "#66b1ff", "#ff6666"},
			MinValue: 0,
			MaxValue: 3,
		},
		LegendItems: []MITRELegendItem{
			{Label: "Not Assessed", Color: "#ffffff"},
			{Label: "Assessed - No Finding", Color: "#66b1ff"},
			{Label: "Assessed - Finding", Color: "#ff6666"},
		},
	}

	// Map assessment activities to ICS ATT&CK techniques
	techniques := []struct {
		id      string
		name    string
		assessed bool
		finding  bool
	}{
		{"T0800", "Activate Firmware Update Mode", false, false},
		{"T0801", "Monitor Process State", true, false},
		{"T0802", "Automated Collection", true, false},
		{"T0803", "Block Command Message", false, false},
		{"T0804", "Block Reporting Message", false, false},
		{"T0805", "Block Serial COM", false, false},
		{"T0806", "Brute Force I/O", false, false},
		{"T0807", "Command-Line Interface", true, false},
		{"T0808", "Control Device Identification", true, false},
		{"T0809", "Data Destruction", false, false},
		{"T0810", "Data Historian Compromise", rg.report.Historians != nil, false},
		{"T0811", "Data from Information Repositories", true, false},
		{"T0812", "Default Credentials", len(rg.report.Credentials) > 0, rg.hasCredentialFindings()},
		{"T0813", "Denial of Control", false, false},
		{"T0814", "Denial of Service", false, false},
		{"T0815", "Denial of View", false, false},
		{"T0817", "Drive-by Compromise", false, false},
		{"T0818", "Engineering Workstation Compromise", false, false},
		{"T0819", "Exploit Public-Facing Application", len(rg.report.HMI) > 0, rg.hasHMIFindings()},
		{"T0820", "Exploitation for Evasion", false, false},
		{"T0821", "Modify Controller Tasking", false, false},
		{"T0822", "External Remote Services", true, false},
		{"T0823", "Graphical User Interface", len(rg.report.HMI) > 0, false},
		{"T0826", "Loss of Availability", false, false},
		{"T0827", "Loss of Control", false, false},
		{"T0828", "Loss of Productivity and Revenue", false, false},
		{"T0829", "Loss of View", false, false},
		{"T0830", "Man in the Middle", false, false},
		{"T0831", "Manipulation of Control", false, false},
		{"T0832", "Manipulation of View", false, false},
		{"T0836", "Modify Parameter", false, false},
		{"T0838", "Modify Alarm Settings", false, false},
		{"T0839", "Module Firmware", false, false},
		{"T0840", "Network Connection Enumeration", true, true},
		{"T0842", "Network Sniffing", true, false},
		{"T0843", "Program Download", false, false},
		{"T0845", "Program Upload", false, false},
		{"T0846", "Remote System Discovery", true, true},
		{"T0847", "Replication Through Removable Media", false, false},
		{"T0848", "Rogue Master", false, false},
		{"T0849", "Masquerading", false, false},
		{"T0851", "Rootkit", false, false},
		{"T0852", "Screen Capture", false, false},
		{"T0853", "Scripting", false, false},
		{"T0855", "Unauthorized Command Message", false, false},
		{"T0856", "Spoof Reporting Message", false, false},
		{"T0857", "System Firmware", false, false},
		{"T0858", "Change Operating Mode", false, false},
		{"T0859", "Valid Accounts", len(rg.report.Credentials) > 0, rg.hasCredentialFindings()},
		{"T0860", "Wireless Compromise", rg.report.Wireless != nil, rg.hasWirelessFindings()},
		{"T0861", "Point & Tag Identification", true, false},
		{"T0862", "Supply Chain Compromise", false, false},
		{"T0863", "User Execution", false, false},
		{"T0866", "Exploitation of Remote Services", true, false},
		{"T0869", "Standard Application Layer Protocol", true, true},
		{"T0870", "Detect Operating Mode", true, false},
		{"T0871", "Execution through API", false, false},
		{"T0872", "Indicator Removal on Host", false, false},
		{"T0873", "Project File Infection", false, false},
		{"T0874", "Hooking", false, false},
		{"T0877", "I/O Image", false, false},
		{"T0878", "Alarm Suppression", false, false},
		{"T0879", "Damage to Property", false, false},
		{"T0880", "Loss of Safety", false, false},
		{"T0881", "Service Stop", false, false},
		{"T0882", "Theft of Operational Information", true, false},
		{"T0883", "Internet Accessible Device", true, false},
		{"T0884", "Connection Proxy", false, false},
		{"T0885", "Commonly Used Port", true, true},
		{"T0886", "Remote Services", true, false},
		{"T0887", "Wireless Sniffing", false, false},
		{"T0888", "Remote System Information Discovery", true, true},
		{"T0889", "Modify Program", false, false},
		{"T0890", "Exploitation for Privilege Escalation", false, false},
		{"T0891", "Hardcoded Credentials", len(rg.report.Credentials) > 0, rg.hasCredentialFindings()},
		{"T0893", "Data from Local System", true, false},
	}

	for _, t := range techniques {
		score := 0
		comment := "Not assessed in this engagement"
		if t.assessed {
			score = 1
			comment = "Assessed - no finding"
		}
		if t.finding {
			score = 3
			comment = "Assessed - finding identified"
		}

		layer.Techniques = append(layer.Techniques, MITRETechnique{
			TechniqueID: t.id,
			Score:       score,
			Comment:     comment,
			Enabled:     true,
		})
	}

	return json.MarshalIndent(layer, "", "  ")
}

// Helper methods for MITRE layer

func (rg *ReportGenerator) hasCredentialFindings() bool {
	for _, cr := range rg.report.Credentials {
		if len(cr.Findings) > 0 {
			return true
		}
	}
	return false
}

func (rg *ReportGenerator) hasHMIFindings() bool {
	for _, hmi := range rg.report.HMI {
		if len(hmi.Findings) > 0 {
			return true
		}
	}
	return false
}

func (rg *ReportGenerator) hasWirelessFindings() bool {
	return rg.report.Wireless != nil && len(rg.report.Wireless.Findings) > 0
}

// buildExecutiveSummary creates the executive summary text.
func (rg *ReportGenerator) buildExecutiveSummary() {
	var parts []string

	parts = append(parts, fmt.Sprintf("This OT/ICS security assessment identified %d operational technology assets.", len(rg.report.Assets)))

	// Vulnerability summary
	totalVulns := 0
	critVulns := 0
	for _, vr := range rg.report.Vulnerabilities {
		for _, v := range vr.Vulnerabilities {
			totalVulns++
			if v.Severity == "critical" {
				critVulns++
			}
		}
	}
	if totalVulns > 0 {
		parts = append(parts, fmt.Sprintf("Vulnerability correlation identified %d potential CVEs (%d critical).", totalVulns, critVulns))
	}

	// Compliance
	if rg.report.Compliance != nil {
		parts = append(parts, fmt.Sprintf("Compliance assessment achieved %.1f%% across %d checks.",
			rg.report.Compliance.Summary.ComplianceRate, rg.report.Compliance.Summary.TotalChecks))
	}

	// Segmentation
	if rg.report.Segmentation != nil {
		parts = append(parts, fmt.Sprintf("Network segmentation scored %.1f/100 with %d gaps identified.",
			rg.report.Segmentation.OverallScore, len(rg.report.Segmentation.Gaps)))
	}

	rg.report.ExecutiveSummary = strings.Join(parts, " ")
}

// buildRiskMatrix creates the risk matrix from all findings.
func (rg *ReportGenerator) buildRiskMatrix() {
	riskID := 1

	// From vulnerabilities
	for _, vr := range rg.report.Vulnerabilities {
		if vr.RiskScore > 5.0 {
			rg.report.RiskMatrix = append(rg.report.RiskMatrix, RiskItem{
				ID:         fmt.Sprintf("RISK-%03d", riskID),
				Title:      fmt.Sprintf("Vulnerabilities on %s (%s)", vr.Target, vr.Vendor),
				Category:   "vulnerability",
				Likelihood: scoreSeverity(vr.RiskScore),
				Impact:     "high",
				RiskScore:  vr.RiskScore,
			})
			riskID++
		}
	}

	// From segmentation gaps
	if rg.report.Segmentation != nil {
		for _, gap := range rg.report.Segmentation.Gaps {
			if gap.Severity == "critical" || gap.Severity == "high" {
				rg.report.RiskMatrix = append(rg.report.RiskMatrix, RiskItem{
					ID:         fmt.Sprintf("RISK-%03d", riskID),
					Title:      gap.Description,
					Category:   "segmentation",
					Likelihood: "medium",
					Impact:     gap.Severity,
					RiskScore:  8.0,
				})
				riskID++
			}
		}
	}
}

// buildRecommendations creates prioritized recommendations.
func (rg *ReportGenerator) buildRecommendations() {
	priority := 1

	// Critical segmentation gaps first
	if rg.report.Segmentation != nil {
		for _, gap := range rg.report.Segmentation.Gaps {
			if gap.Severity == "critical" {
				rg.report.Recommendations = append(rg.report.Recommendations, Recommendation{
					Priority:    priority,
					Title:       "Address Critical Segmentation Gap",
					Description: gap.Description,
					Category:    "segmentation",
					Effort:      "high",
					Impact:      "high",
				})
				priority++
			}
		}
	}

	// Critical vulnerabilities
	for _, vr := range rg.report.Vulnerabilities {
		for _, v := range vr.Vulnerabilities {
			if v.Severity == "critical" {
				rg.report.Recommendations = append(rg.report.Recommendations, Recommendation{
					Priority:    priority,
					Title:       fmt.Sprintf("Remediate %s on %s", v.CVEID, vr.Target),
					Description: v.Description,
					Category:    "vulnerability",
					Effort:      "medium",
					Impact:      "high",
				})
				priority++
			}
		}
	}

	// Default credentials
	for _, cr := range rg.report.Credentials {
		if len(cr.Findings) > 0 {
			rg.report.Recommendations = append(rg.report.Recommendations, Recommendation{
				Priority:    priority,
				Title:       fmt.Sprintf("Change Default Credentials on %s", cr.Target),
				Description: "Default vendor credentials were accepted",
				Category:    "credentials",
				Effort:      "low",
				Impact:      "high",
			})
			priority++
		}
	}
}

// scoreSeverity converts a numeric score to a severity label.
func scoreSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// csvEscape escapes a string for CSV output.
func csvEscape(s string) string {
	s = strings.ReplaceAll(s, "\"", "\"\"")
	if strings.ContainsAny(s, ",\"\n\r") {
		s = "\"" + s + "\""
	}
	return s
}
