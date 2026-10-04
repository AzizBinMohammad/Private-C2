package ot

import (
	"fmt"
	"strings"
	"time"
)

// SAFETY: Vulnerability scanning is OFFLINE only.
// No active exploitation, no proof-of-concept execution.
// Correlates vendor/model/firmware against a local CVE database.

// VulnScanResult holds the results of a vulnerability scan.
type VulnScanResult struct {
	Target        string          `json:"target"`
	Vendor        string          `json:"vendor"`
	Model         string          `json:"model"`
	Firmware      string          `json:"firmware"`
	ScannedAt     time.Time       `json:"scanned_at"`
	Vulnerabilities []VulnFinding `json:"vulnerabilities"`
	InsecureProtos  []InsecureProtocol `json:"insecure_protocols"`
	RiskScore     float64         `json:"risk_score"` // 0-10
	Summary       string          `json:"summary"`
}

// VulnFinding represents a single vulnerability finding.
type VulnFinding struct {
	CVEID         string   `json:"cve_id"`
	Description   string   `json:"description"`
	CVSS          float64  `json:"cvss"`
	Severity      string   `json:"severity"` // "critical", "high", "medium", "low", "info"
	AffectedVer   string   `json:"affected_versions"`
	FixedVer      string   `json:"fixed_version,omitempty"`
	VendorAdvisory string  `json:"vendor_advisory,omitempty"`
	ICSCERTAdvisory string `json:"icscert_advisory,omitempty"`
	AttackVector  string   `json:"attack_vector"`
	References    []string `json:"references"`
	Mitigations   []string `json:"mitigations"`
}

// InsecureProtocol identifies an insecure protocol in use.
type InsecureProtocol struct {
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// VulnScanner performs offline CVE correlation.
type VulnScanner struct {
	module *OTModule
}

// NewVulnScanner creates a new vulnerability scanner.
func NewVulnScanner(module *OTModule) *VulnScanner {
	return &VulnScanner{module: module}
}

// ScanAsset performs an offline vulnerability assessment of an asset.
func (vs *VulnScanner) ScanAsset(asset OTAsset) *VulnScanResult {
	result := &VulnScanResult{
		Target:   asset.IP,
		Vendor:   asset.Vendor,
		Model:    asset.Model,
		Firmware: asset.Firmware,
		ScannedAt: time.Now(),
	}

	// Offline CVE correlation
	result.Vulnerabilities = vs.correlateCVEs(asset.Vendor, asset.Model, asset.Firmware)

	// Check for insecure protocols
	result.InsecureProtos = vs.checkInsecureProtocols(asset.Protocols, asset.OpenPorts)

	// Calculate risk score
	result.RiskScore = vs.calculateRiskScore(result)

	// Generate summary
	result.Summary = vs.generateSummary(result)

	return result
}

// correlateCVEs looks up CVEs for a vendor/model/firmware combination.
func (vs *VulnScanner) correlateCVEs(vendor, model, firmware string) []VulnFinding {
	var findings []VulnFinding

	vendor = strings.ToLower(vendor)
	model = strings.ToLower(model)

	// ICS-specific CVE database (offline, bundled)
	icsCVEs := getICSCVEDatabase()

	for _, cve := range icsCVEs {
		if matchesCVE(cve, vendor, model, firmware) {
			findings = append(findings, cve)
		}
	}

	return findings
}

// matchesCVE checks if a CVE applies to the given vendor/model/firmware.
func matchesCVE(cve VulnFinding, vendor, model, firmware string) bool {
	desc := strings.ToLower(cve.Description)
	affectedVer := strings.ToLower(cve.AffectedVer)

	// Check vendor match
	if !strings.Contains(desc, vendor) && !strings.Contains(affectedVer, vendor) {
		return false
	}

	// Check model match if available
	if model != "" && !strings.Contains(desc, model) && !strings.Contains(affectedVer, model) {
		return false
	}

	return true
}

// checkInsecureProtocols identifies protocols with known security issues.
func (vs *VulnScanner) checkInsecureProtocols(protocols []string, ports []int) []InsecureProtocol {
	var findings []InsecureProtocol

	insecure := map[string]InsecureProtocol{
		"modbus": {
			Protocol:    "Modbus TCP",
			Port:        502,
			Issue:       "No authentication or encryption; any network-accessible client can read/write registers",
			Severity:    "high",
			Remediation: "Segment Modbus traffic, use firewall rules, consider Modbus/TCP Security (TLS)",
		},
		"s7comm": {
			Protocol:    "S7Comm",
			Port:        102,
			Issue:       "Legacy protocol with weak or no authentication; password can be bypassed",
			Severity:    "high",
			Remediation: "Upgrade to S7CommPlus with TLS, restrict access via firewall",
		},
		"dnp3": {
			Protocol:    "DNP3",
			Port:        20000,
			Issue:       "DNP3 without Secure Authentication lacks integrity and authentication",
			Severity:    "medium",
			Remediation: "Enable DNP3 Secure Authentication (SA v5)",
		},
		"bacnet": {
			Protocol:    "BACnet/IP",
			Port:        47808,
			Issue:       "BACnet/IP has no built-in authentication or encryption",
			Severity:    "medium",
			Remediation: "Use BACnet/SC (Secure Connect) where supported, segment BACnet traffic",
		},
		"ethernetip": {
			Protocol:    "EtherNet/IP CIP",
			Port:        44818,
			Issue:       "CIP lacks authentication; any client can read object attributes",
			Severity:    "medium",
			Remediation: "Use CIP Security (EtherNet/IP with TLS), restrict with firewall rules",
		},
		"fins": {
			Protocol:    "Omron FINS",
			Port:        9600,
			Issue:       "FINS protocol has no authentication mechanism",
			Severity:    "high",
			Remediation: "Use Omron NX/NJ series with CIP Safety, segment network access",
		},
		"melsec": {
			Protocol:    "MELSEC SLMP",
			Port:        5007,
			Issue:       "SLMP/MC Protocol has no authentication for basic read operations",
			Severity:    "medium",
			Remediation: "Enable IP access control on Mitsubishi PLCs, use network segmentation",
		},
		"mqtt": {
			Protocol:    "MQTT",
			Port:        1883,
			Issue:       "MQTT without TLS exposes topic data in cleartext; anonymous access may be enabled",
			Severity:    "medium",
			Remediation: "Use MQTT over TLS (port 8883), require authentication, use ACLs",
		},
		"coap": {
			Protocol:    "CoAP",
			Port:        5683,
			Issue:       "CoAP without DTLS lacks encryption and authentication",
			Severity:    "medium",
			Remediation: "Use CoAPS (CoAP over DTLS, port 5684)",
		},
		"http": {
			Protocol:    "HTTP",
			Port:        80,
			Issue:       "Unencrypted HTTP exposes credentials and data; often used for HMI web interfaces",
			Severity:    "medium",
			Remediation: "Redirect to HTTPS, enforce TLS 1.2+",
		},
		"telnet": {
			Protocol:    "Telnet",
			Port:        23,
			Issue:       "Telnet transmits all data including credentials in cleartext",
			Severity:    "critical",
			Remediation: "Replace Telnet with SSH; disable Telnet service entirely",
		},
		"ftp": {
			Protocol:    "FTP",
			Port:        21,
			Issue:       "FTP transmits credentials and data in cleartext",
			Severity:    "high",
			Remediation: "Replace with SFTP or SCP; disable FTP service",
		},
	}

	for _, proto := range protocols {
		p := strings.ToLower(proto)
		if finding, ok := insecure[p]; ok {
			findings = append(findings, finding)
		}
	}

	// Check known insecure ports
	insecurePorts := map[int]string{
		23: "telnet", 21: "ftp", 69: "tftp", 80: "http",
	}
	for _, port := range ports {
		if proto, ok := insecurePorts[port]; ok {
			// Avoid duplicates
			found := false
			for _, f := range findings {
				if f.Port == port {
					found = true
					break
				}
			}
			if !found {
				if finding, ok := insecure[proto]; ok {
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// calculateRiskScore computes an overall risk score (0-10).
func (vs *VulnScanner) calculateRiskScore(result *VulnScanResult) float64 {
	score := 0.0

	// Max CVSS from vulnerabilities
	maxCVSS := 0.0
	for _, vuln := range result.Vulnerabilities {
		if vuln.CVSS > maxCVSS {
			maxCVSS = vuln.CVSS
		}
	}
	score += maxCVSS * 0.5

	// Insecure protocol penalty
	for _, proto := range result.InsecureProtos {
		switch proto.Severity {
		case "critical":
			score += 1.5
		case "high":
			score += 1.0
		case "medium":
			score += 0.5
		}
	}

	if score > 10.0 {
		score = 10.0
	}
	return score
}

// generateSummary creates a human-readable summary.
func (vs *VulnScanner) generateSummary(result *VulnScanResult) string {
	critCount, highCount, medCount := 0, 0, 0
	for _, v := range result.Vulnerabilities {
		switch v.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		}
	}

	return fmt.Sprintf("Risk Score: %.1f/10 | %d critical, %d high, %d medium CVEs | %d insecure protocols",
		result.RiskScore, critCount, highCount, medCount, len(result.InsecureProtos))
}

// getICSCVEDatabase returns a bundled ICS CVE database (sample entries).
func getICSCVEDatabase() []VulnFinding {
	return []VulnFinding{
		{
			CVEID:         "CVE-2019-13945",
			Description:   "Siemens S7-1200 CPU firmware allows bypass of access protection via replay attack",
			CVSS:          6.8,
			Severity:      "medium",
			AffectedVer:   "siemens s7-1200 firmware < v4.4",
			FixedVer:      "v4.4",
			VendorAdvisory: "SSA-232418",
			AttackVector:  "network",
			Mitigations:   []string{"Update firmware to v4.4+", "Use access protection with strong password"},
		},
		{
			CVEID:         "CVE-2019-10929",
			Description:   "Siemens S7-1200 and S7-1500 CPU families cryptographic vulnerability in challenge-response",
			CVSS:          5.9,
			Severity:      "medium",
			AffectedVer:   "siemens s7-1200 firmware < v4.4, siemens s7-1500 firmware < v2.6",
			FixedVer:      "v4.4 / v2.6",
			VendorAdvisory: "SSA-232418",
			AttackVector:  "network",
			Mitigations:   []string{"Update firmware", "Enable communication integrity in TIA Portal"},
		},
		{
			CVEID:           "CVE-2017-6034",
			Description:     "Schneider Electric Modicon M340 authentication bypass allows unauthorized access",
			CVSS:            9.8,
			Severity:        "critical",
			AffectedVer:     "schneider electric modicon m340",
			ICSCERTAdvisory: "ICSA-17-089-02",
			AttackVector:    "network",
			Mitigations:     []string{"Apply firmware update", "Restrict network access to PLC"},
		},
		{
			CVEID:           "CVE-2022-1159",
			Description:     "Rockwell Automation Studio 5000 Logix Designer allows unauthorized code modification",
			CVSS:            7.7,
			Severity:        "high",
			AffectedVer:     "rockwell automation studio 5000",
			ICSCERTAdvisory: "ICSA-22-090-05",
			AttackVector:    "local",
			Mitigations:     []string{"Apply vendor patch", "Use CIP Security", "Restrict engineering workstation access"},
		},
		{
			CVEID:         "CVE-2020-6994",
			Description:   "Rockwell ControlLogix and CompactLogix controllers improper input validation",
			CVSS:          8.6,
			Severity:      "high",
			AffectedVer:   "rockwell controllogix 5580 firmware < v32",
			FixedVer:      "v32",
			AttackVector:  "network",
			Mitigations:   []string{"Update firmware to v32+", "Apply network segmentation"},
		},
		{
			CVEID:           "CVE-2020-15791",
			Description:     "Siemens SIMATIC S7-300/400 CPU families memory protection bypass",
			CVSS:            6.5,
			Severity:        "medium",
			AffectedVer:     "siemens s7-300, siemens s7-400",
			ICSCERTAdvisory: "ICSA-20-252-02",
			AttackVector:    "network",
			Mitigations:     []string{"Restrict network access", "Use VPN for remote access"},
		},
		{
			CVEID:         "CVE-2021-22681",
			Description:   "Rockwell Automation Logix controllers authentication bypass via CIP",
			CVSS:          10.0,
			Severity:      "critical",
			AffectedVer:   "rockwell compactlogix, rockwell controllogix",
			AttackVector:  "network",
			Mitigations:   []string{"Apply CIP Security", "Restrict network access", "Use hardened switch/router"},
		},
		{
			CVEID:         "CVE-2022-22965",
			Description:   "Spring4Shell - affects OT systems running Java-based SCADA/HMI platforms",
			CVSS:          9.8,
			Severity:      "critical",
			AffectedVer:   "honeywell experion, ge ifix, schneider clearscada",
			FixedVer:      "Vendor-specific patches",
			AttackVector:  "network",
			Mitigations:   []string{"Apply vendor patches", "WAF rules", "Restrict web interface access"},
		},
	}
}
