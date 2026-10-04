package ot

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// SAFETY: Default credential testing uses ONE attempt per credential per service.
// No brute force, no dictionary attack, no account lockout risk.
// Only checks vendor-published default credentials.

// CredentialTestResult holds the result of a default credential check.
type CredentialTestResult struct {
	Target      string            `json:"target"`
	Service     string            `json:"service"`
	Port        int               `json:"port"`
	Findings    []CredentialFinding `json:"findings"`
	TestedAt    time.Time         `json:"tested_at"`
	TotalTested int               `json:"total_tested"`
}

// CredentialFinding represents a single credential test outcome.
type CredentialFinding struct {
	Username    string `json:"username"`
	IsDefault   bool   `json:"is_default"`
	Protocol    string `json:"protocol"`
	Service     string `json:"service"`
	Severity    string `json:"severity"` // "critical", "high", "medium"
	Vendor      string `json:"vendor"`
	Description string `json:"description"`
}

// DefaultCredential represents a vendor-published default credential pair.
type DefaultCredential struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// Password is intentionally NOT stored or logged.
	// Tests check only for authentication success with known defaults.
	IsBlank  bool   `json:"is_blank"` // True if default has no password
	Source   string `json:"source"`   // "vendor documentation", "ICS-CERT advisory", etc.
}

// CredentialChecker performs default credential assessment.
type CredentialChecker struct {
	module *OTModule
}

// NewCredentialChecker creates a new credential checker.
func NewCredentialChecker(module *OTModule) *CredentialChecker {
	return &CredentialChecker{module: module}
}

// CheckDefaults tests for vendor default credentials - ONE attempt per credential.
// This is NOT brute force. It only checks documented vendor defaults.
func (cc *CredentialChecker) CheckDefaults(ctx context.Context, target string, vendor string, services []string) (*CredentialTestResult, error) {
	if !cc.module.config.CredentialTestingOn {
		return nil, fmt.Errorf("credential testing is disabled in configuration")
	}

	if err := cc.module.PreFlightCheck(target, "credential-check"); err != nil {
		return nil, err
	}

	result := &CredentialTestResult{
		Target:   target,
		TestedAt: time.Now(),
	}

	creds := getDefaultCredentials(vendor)
	if len(creds) == 0 {
		return result, nil
	}

	for _, svc := range services {
		for _, cred := range creds {
			if !matchesService(svc, cred) {
				continue
			}

			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			result.TotalTested++

			// Single attempt only
			finding := cc.testSingleCredential(target, svc, cred)
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}

			// Rate limit between attempts
			cc.module.rateLimiter.Wait()
		}
	}

	return result, nil
}

// testSingleCredential performs ONE authentication attempt.
func (cc *CredentialChecker) testSingleCredential(target, service string, cred DefaultCredential) *CredentialFinding {
	timeout := time.Duration(cc.module.config.QueryTimeoutMs) * time.Millisecond

	switch service {
	case "http", "https":
		return cc.testHTTPAuth(target, cred, timeout)
	case "ftp":
		return cc.testFTPAuth(target, cred, timeout)
	case "telnet":
		return cc.testTelnetBanner(target, cred, timeout)
	case "snmp":
		return cc.testSNMPCommunity(target, cred, timeout)
	default:
		return nil
	}
}

// testHTTPAuth tests a single HTTP basic auth credential.
func (cc *CredentialChecker) testHTTPAuth(target string, cred DefaultCredential, timeout time.Duration) *CredentialFinding {
	// Implementation would do a single HTTP GET with Basic auth header
	// and check for 200 vs 401 response
	_ = target
	_ = cred
	_ = timeout
	return nil
}

// testFTPAuth tests a single FTP credential.
func (cc *CredentialChecker) testFTPAuth(target string, cred DefaultCredential, timeout time.Duration) *CredentialFinding {
	addr := fmt.Sprintf("%s:21", target)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Read banner
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	banner := string(buf[:n])
	if !strings.HasPrefix(banner, "220") {
		return nil
	}

	// Send USER
	_, _ = conn.Write([]byte(fmt.Sprintf("USER %s\r\n", cred.Username)))
	n, err = conn.Read(buf)
	if err != nil {
		return nil
	}

	resp := string(buf[:n])
	if strings.HasPrefix(resp, "230") {
		// No password required - default credential found
		_, _ = conn.Write([]byte("QUIT\r\n"))
		return &CredentialFinding{
			Username:    cred.Username,
			IsDefault:   true,
			Protocol:    "ftp",
			Service:     "ftp",
			Severity:    "critical",
			Vendor:      cred.Vendor,
			Description: fmt.Sprintf("FTP default credential accepted (user: %s, vendor: %s)", cred.Username, cred.Vendor),
		}
	}

	// Graceful disconnect
	_, _ = conn.Write([]byte("QUIT\r\n"))
	return nil
}

// testTelnetBanner only reads the telnet banner for default credential indicators.
func (cc *CredentialChecker) testTelnetBanner(target string, cred DefaultCredential, timeout time.Duration) *CredentialFinding {
	addr := fmt.Sprintf("%s:23", target)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	banner := strings.ToLower(string(buf[:n]))

	// Check if banner reveals default state
	if strings.Contains(banner, "default password") || strings.Contains(banner, "factory reset") {
		return &CredentialFinding{
			Username:    "",
			IsDefault:   true,
			Protocol:    "telnet",
			Service:     "telnet",
			Severity:    "high",
			Vendor:      cred.Vendor,
			Description: "Telnet banner indicates factory default configuration",
		}
	}

	return nil
}

// testSNMPCommunity tests for default SNMP community strings.
func (cc *CredentialChecker) testSNMPCommunity(target string, cred DefaultCredential, timeout time.Duration) *CredentialFinding {
	// Send a single SNMPv2c GET sysDescr.0 with the community string
	addr := fmt.Sprintf("%s:161", target)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SNMPv2c GET request for sysDescr.0 (1.3.6.1.2.1.1.1.0)
	community := cred.Username // SNMP uses community string
	pkt := buildSNMPGetRequest(community, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00})

	_, err = conn.Write(pkt)
	if err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	// Any valid SNMP response means the community string was accepted
	if n > 2 && buf[0] == 0x30 {
		return &CredentialFinding{
			Username:    community,
			IsDefault:   true,
			Protocol:    "snmp",
			Service:     "snmp",
			Severity:    "high",
			Vendor:      cred.Vendor,
			Description: fmt.Sprintf("Default SNMP community string '%s' accepted", community),
		}
	}

	return nil
}

// buildSNMPGetRequest constructs a minimal SNMPv2c GET request.
func buildSNMPGetRequest(community string, oid []byte) []byte {
	// Request ID
	reqID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}
	// Error status + index
	errFields := []byte{0x02, 0x01, 0x00, 0x02, 0x01, 0x00}

	// Variable binding: OID with null value
	oidEnc := append([]byte{0x06, byte(len(oid))}, oid...)
	nullVal := []byte{0x05, 0x00}
	varbind := append([]byte{0x30, byte(len(oidEnc) + len(nullVal))}, append(oidEnc, nullVal...)...)
	varbinds := append([]byte{0x30, byte(len(varbind))}, varbind...)

	// PDU
	pduPayload := append(reqID, append(errFields, varbinds...)...)
	pdu := append([]byte{0xa0, byte(len(pduPayload))}, pduPayload...)

	// Version (SNMPv2c = 1)
	version := []byte{0x02, 0x01, 0x01}
	// Community
	comm := append([]byte{0x04, byte(len(community))}, []byte(community)...)

	// Message
	msgPayload := append(version, append(comm, pdu...)...)
	msg := append([]byte{0x30, byte(len(msgPayload))}, msgPayload...)

	return msg
}

// matchesService checks if a credential applies to a service.
func matchesService(service string, cred DefaultCredential) bool {
	return strings.EqualFold(cred.Protocol, service)
}

// getDefaultCredentials returns known vendor default credentials.
// These are ONLY documented, vendor-published defaults.
func getDefaultCredentials(vendor string) []DefaultCredential {
	vendor = strings.ToLower(vendor)

	// Only vendor-documented default credentials from public sources
	allDefaults := map[string][]DefaultCredential{
		"siemens": {
			{Vendor: "Siemens", Product: "S7", Protocol: "http", Username: "admin", IsBlank: true, Source: "Siemens ProductCERT"},
			{Vendor: "Siemens", Product: "SCALANCE", Protocol: "snmp", Username: "public", Source: "Siemens documentation"},
			{Vendor: "Siemens", Product: "SCALANCE", Protocol: "http", Username: "admin", Source: "Siemens documentation"},
		},
		"schneider": {
			{Vendor: "Schneider Electric", Product: "M340", Protocol: "http", Username: "USER", Source: "Schneider Electric documentation"},
			{Vendor: "Schneider Electric", Product: "Quantum", Protocol: "ftp", Username: "USER", Source: "Schneider Electric documentation"},
		},
		"rockwell": {
			{Vendor: "Rockwell Automation", Product: "ControlLogix", Protocol: "http", Username: "admin", Source: "Rockwell documentation"},
			{Vendor: "Rockwell Automation", Product: "Stratix", Protocol: "snmp", Username: "public", Source: "Rockwell documentation"},
		},
		"abb": {
			{Vendor: "ABB", Product: "AC500", Protocol: "http", Username: "admin", Source: "ABB documentation"},
		},
		"honeywell": {
			{Vendor: "Honeywell", Product: "Experion", Protocol: "http", Username: "admin", Source: "Honeywell documentation"},
		},
		"ge": {
			{Vendor: "GE", Product: "PACSystems", Protocol: "snmp", Username: "public", Source: "GE documentation"},
		},
	}

	for key, creds := range allDefaults {
		if strings.Contains(vendor, key) {
			return creds
		}
	}

	return nil
}
