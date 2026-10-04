package ot

import (
	"fmt"
	"strings"
	"time"
)

// ComplianceFramework identifies a compliance standard.
type ComplianceFramework string

const (
	FrameworkIEC62443  ComplianceFramework = "IEC 62443"
	FrameworkNIST80082 ComplianceFramework = "NIST SP 800-82"
	FrameworkNERCCIP   ComplianceFramework = "NERC CIP"
	FrameworkISA99     ComplianceFramework = "ISA/IEC 62443"
)

// ComplianceFinding represents a gap against a compliance requirement.
type ComplianceFinding struct {
	Framework   ComplianceFramework `json:"framework"`
	Requirement string              `json:"requirement"`
	Section     string              `json:"section"`
	Description string              `json:"description"`
	Status      string              `json:"status"` // "pass", "fail", "partial", "not_assessed"
	Severity    string              `json:"severity"`
	Evidence    string              `json:"evidence"`
	Remediation string              `json:"remediation"`
}

// ComplianceReport holds the complete compliance gap analysis.
type ComplianceReport struct {
	Frameworks  []ComplianceFramework `json:"frameworks"`
	AssessedAt  time.Time             `json:"assessed_at"`
	Findings    []ComplianceFinding   `json:"findings"`
	Summary     ComplianceSummary     `json:"summary"`
}

// ComplianceSummary provides an overview of compliance status.
type ComplianceSummary struct {
	TotalChecks    int     `json:"total_checks"`
	Passed         int     `json:"passed"`
	Failed         int     `json:"failed"`
	Partial        int     `json:"partial"`
	NotAssessed    int     `json:"not_assessed"`
	ComplianceRate float64 `json:"compliance_rate"` // 0-100
}

// ComplianceChecker performs compliance gap analysis.
type ComplianceChecker struct {
	module *OTModule
}

// NewComplianceChecker creates a new compliance checker.
func NewComplianceChecker(module *OTModule) *ComplianceChecker {
	return &ComplianceChecker{module: module}
}

// Assess performs a compliance gap analysis against selected frameworks.
func (cc *ComplianceChecker) Assess(
	assets []OTAsset,
	topology *NetworkTopology,
	vulnResults []*VulnScanResult,
	segResults *SegmentationAnalysis,
	frameworks []ComplianceFramework,
) *ComplianceReport {

	report := &ComplianceReport{
		Frameworks: frameworks,
		AssessedAt: time.Now(),
	}

	for _, fw := range frameworks {
		switch fw {
		case FrameworkIEC62443:
			report.Findings = append(report.Findings, cc.checkIEC62443(assets, topology, segResults)...)
		case FrameworkNIST80082:
			report.Findings = append(report.Findings, cc.checkNIST80082(assets, vulnResults, segResults)...)
		case FrameworkNERCCIP:
			report.Findings = append(report.Findings, cc.checkNERCCIP(assets, topology, segResults)...)
		}
	}

	// Calculate summary
	report.Summary = cc.calculateSummary(report.Findings)

	return report
}

// checkIEC62443 evaluates against IEC 62443 requirements.
func (cc *ComplianceChecker) checkIEC62443(assets []OTAsset, topology *NetworkTopology, seg *SegmentationAnalysis) []ComplianceFinding {
	var findings []ComplianceFinding

	// FR 1: Identification and Authentication Control
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkIEC62443,
		Requirement: "FR 1 - Identification and Authentication Control",
		Section:     "IEC 62443-3-3 SR 1.1",
		Description: "Human user identification and authentication",
		Status:      "not_assessed",
		Severity:    "high",
		Remediation: "Verify all OT devices require individual user authentication",
	})

	// FR 2: Use Control
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkIEC62443,
		Requirement: "FR 2 - Use Control",
		Section:     "IEC 62443-3-3 SR 2.1",
		Description: "Authorization enforcement on all interfaces",
		Status:      "not_assessed",
		Severity:    "high",
		Remediation: "Implement role-based access control on all OT systems",
	})

	// FR 3: System Integrity
	if len(assets) > 0 {
		hasOldFirmware := false
		for _, asset := range assets {
			if asset.Firmware != "" && containsOldVersion(asset.Firmware) {
				hasOldFirmware = true
				break
			}
		}
		status := "pass"
		if hasOldFirmware {
			status = "fail"
		}
		findings = append(findings, ComplianceFinding{
			Framework:   FrameworkIEC62443,
			Requirement: "FR 3 - System Integrity",
			Section:     "IEC 62443-3-3 SR 3.4",
			Description: "Software and information integrity - firmware currency",
			Status:      status,
			Severity:    "medium",
			Evidence:    fmt.Sprintf("Assessed %d assets for firmware currency", len(assets)),
			Remediation: "Update firmware on all OT devices to vendor-recommended versions",
		})
	}

	// FR 5: Restricted Data Flow (Zone segmentation)
	if seg != nil {
		status := "pass"
		severity := "info"
		if len(seg.Gaps) > 0 {
			status = "fail"
			severity = "critical"
		}
		findings = append(findings, ComplianceFinding{
			Framework:   FrameworkIEC62443,
			Requirement: "FR 5 - Restricted Data Flow",
			Section:     "IEC 62443-3-3 SR 5.1",
			Description: "Network segmentation between zones and conduits",
			Status:      status,
			Severity:    severity,
			Evidence:    fmt.Sprintf("%d segmentation gaps detected", len(seg.Gaps)),
			Remediation: "Implement proper zone segmentation per IEC 62443 zones and conduits model",
		})
	}

	// FR 7: Resource Availability
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkIEC62443,
		Requirement: "FR 7 - Resource Availability",
		Section:     "IEC 62443-3-3 SR 7.1",
		Description: "Denial of service protection",
		Status:      "not_assessed",
		Severity:    "medium",
		Remediation: "Verify network-level DoS protection is in place for critical OT zones",
	})

	return findings
}

// checkNIST80082 evaluates against NIST SP 800-82 recommendations.
func (cc *ComplianceChecker) checkNIST80082(assets []OTAsset, vulnResults []*VulnScanResult, seg *SegmentationAnalysis) []ComplianceFinding {
	var findings []ComplianceFinding

	// Section 5.1 - Network Segmentation
	if seg != nil {
		status := "pass"
		if len(seg.Gaps) > 0 {
			status = "fail"
		}
		findings = append(findings, ComplianceFinding{
			Framework:   FrameworkNIST80082,
			Requirement: "Network Segmentation",
			Section:     "NIST 800-82 Section 5.1",
			Description: "ICS network architecture should implement defense-in-depth with proper segmentation",
			Status:      status,
			Severity:    "high",
			Evidence:    fmt.Sprintf("%d segmentation gaps found", len(seg.Gaps)),
			Remediation: "Implement DMZ between corporate and ICS networks; segment by Purdue level",
		})

		// Check for DMZ
		hasDMZ := false
		if seg != nil {
			for _, zone := range seg.Zones {
				if zone.PurdueLevel == PurdueLevel35 {
					hasDMZ = true
					break
				}
			}
		}
		status = "pass"
		if !hasDMZ {
			status = "fail"
		}
		findings = append(findings, ComplianceFinding{
			Framework:   FrameworkNIST80082,
			Requirement: "DMZ Between IT and OT",
			Section:     "NIST 800-82 Section 5.1.2",
			Description: "A DMZ should separate corporate IT from the ICS network",
			Status:      status,
			Severity:    "critical",
			Remediation: "Establish a DMZ between Level 3 and Level 4 networks",
		})
	}

	// Section 6.2 - Patch Management
	patchStatus := "not_assessed"
	if len(vulnResults) > 0 {
		hasUnpatched := false
		for _, vr := range vulnResults {
			for _, v := range vr.Vulnerabilities {
				if v.FixedVer != "" {
					hasUnpatched = true
					break
				}
			}
		}
		if hasUnpatched {
			patchStatus = "fail"
		} else {
			patchStatus = "pass"
		}
	}
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkNIST80082,
		Requirement: "Patch Management",
		Section:     "NIST 800-82 Section 6.2.2",
		Description: "ICS patch management program should be in place",
		Status:      patchStatus,
		Severity:    "high",
		Remediation: "Establish ICS patch management process; test patches before deployment",
	})

	// Section 6.3 - Encryption
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkNIST80082,
		Requirement: "Communication Encryption",
		Section:     "NIST 800-82 Section 6.3",
		Description: "ICS communications should use encryption where feasible",
		Status:      "not_assessed",
		Severity:    "medium",
		Remediation: "Enable TLS/encryption on OT protocols where supported (OPC UA, Modbus/TCP Security)",
	})

	return findings
}

// checkNERCCIP evaluates against NERC CIP requirements (power sector).
func (cc *ComplianceChecker) checkNERCCIP(assets []OTAsset, topology *NetworkTopology, seg *SegmentationAnalysis) []ComplianceFinding {
	var findings []ComplianceFinding

	// CIP-002 - BES Cyber System Categorization
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkNERCCIP,
		Requirement: "BES Cyber System Categorization",
		Section:     "CIP-002-5.1",
		Description: "Identify and categorize BES Cyber Systems",
		Status:      "not_assessed",
		Severity:    "high",
		Evidence:    fmt.Sprintf("%d OT assets discovered for categorization review", len(assets)),
		Remediation: "Categorize all BES Cyber Systems as High, Medium, or Low impact",
	})

	// CIP-005 - Electronic Security Perimeter
	if seg != nil {
		status := "pass"
		if len(seg.Gaps) > 0 {
			status = "fail"
		}
		findings = append(findings, ComplianceFinding{
			Framework:   FrameworkNERCCIP,
			Requirement: "Electronic Security Perimeter",
			Section:     "CIP-005-7",
			Description: "Define and protect Electronic Security Perimeters",
			Status:      status,
			Severity:    "critical",
			Evidence:    fmt.Sprintf("Network segmentation analysis found %d gaps", len(seg.Gaps)),
			Remediation: "Ensure all BES Cyber Systems are within a defined ESP with proper access controls",
		})
	}

	// CIP-007 - System Security Management
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkNERCCIP,
		Requirement: "System Security Management",
		Section:     "CIP-007-6",
		Description: "Ports and services, patch management, malicious code prevention",
		Status:      "not_assessed",
		Severity:    "high",
		Remediation: "Disable unused ports/services, maintain patch management, deploy malware protection",
	})

	// CIP-010 - Configuration Change Management
	findings = append(findings, ComplianceFinding{
		Framework:   FrameworkNERCCIP,
		Requirement: "Configuration Change Management",
		Section:     "CIP-010-4",
		Description: "Baseline configurations and vulnerability assessments",
		Status:      "not_assessed",
		Severity:    "medium",
		Remediation: "Establish baseline configurations and conduct periodic vulnerability assessments",
	})

	return findings
}

// calculateSummary computes the compliance summary statistics.
func (cc *ComplianceChecker) calculateSummary(findings []ComplianceFinding) ComplianceSummary {
	summary := ComplianceSummary{
		TotalChecks: len(findings),
	}

	for _, f := range findings {
		switch f.Status {
		case "pass":
			summary.Passed++
		case "fail":
			summary.Failed++
		case "partial":
			summary.Partial++
		case "not_assessed":
			summary.NotAssessed++
		}
	}

	assessed := summary.TotalChecks - summary.NotAssessed
	if assessed > 0 {
		summary.ComplianceRate = float64(summary.Passed) / float64(assessed) * 100
	}

	return summary
}

// containsOldVersion heuristically checks if a firmware version looks outdated.
func containsOldVersion(firmware string) bool {
	lower := strings.ToLower(firmware)
	// Very basic heuristic: if version starts with v1. or v2. for modern systems
	oldPrefixes := []string{"v1.", "v2.", "1.0", "2.0", "fw 1.", "fw 2."}
	for _, prefix := range oldPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
