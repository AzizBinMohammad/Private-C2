package ot

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SAFETY: HMI assessment is READ-ONLY.
// Only HTTP GET requests. No injection, no form submission, no POST/PUT/DELETE.
// No attempt to modify process values or SCADA displays.

// HMIAssessment holds the complete HMI web interface assessment.
type HMIAssessment struct {
	Target          string         `json:"target"`
	Interfaces      []HMIInterface `json:"interfaces"`
	Findings        []HMIFinding   `json:"findings"`
	Recommendations []string       `json:"recommendations"`
}

// HMIInterface represents a detected HMI web interface.
type HMIInterface struct {
	URL          string            `json:"url"`
	Port         int               `json:"port"`
	Title        string            `json:"title,omitempty"`
	Server       string            `json:"server,omitempty"`
	TLS          bool              `json:"tls"`
	AuthRequired bool              `json:"auth_required"`
	AuthType     string            `json:"auth_type,omitempty"` // "basic", "form", "none"
	Vendor       string            `json:"vendor,omitempty"`
	Product      string            `json:"product,omitempty"`
	Version      string            `json:"version,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Technologies []string          `json:"technologies,omitempty"` // Detected frameworks
}

// HMIFinding is a security finding on an HMI interface.
type HMIFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // "critical", "high", "medium", "low", "info"
	Category    string `json:"category"` // "authentication", "encryption", "headers", "exposure"
	Remediation string `json:"remediation"`
	URL         string `json:"url,omitempty"`
}

// HMIAssessor performs HMI web interface assessment.
type HMIAssessor struct {
	module *OTModule
}

// NewHMIAssessor creates a new HMI assessor.
func NewHMIAssessor(module *OTModule) *HMIAssessor {
	return &HMIAssessor{module: module}
}

// Assess performs an HMI web interface assessment - READ ONLY, HTTP GET only.
func (ha *HMIAssessor) Assess(ctx context.Context, target string) (*HMIAssessment, error) {
	if err := ha.module.PreFlightCheck(target, "hmi-assess"); err != nil {
		return nil, err
	}

	result := &HMIAssessment{
		Target: target,
	}

	// Scan common HMI web ports
	ports := []struct {
		port   int
		scheme string
	}{
		{80, "http"},
		{443, "https"},
		{8080, "http"},
		{8443, "https"},
		{3000, "http"},  // Grafana
		{8088, "http"},  // Ignition
		{8043, "https"}, // Ignition SSL
		{81, "http"},    // Alternate HTTP
		{4443, "https"}, // Alternate HTTPS
	}

	for _, p := range ports {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		iface := ha.probeWebInterface(ctx, target, p.port, p.scheme)
		if iface != nil {
			result.Interfaces = append(result.Interfaces, *iface)
		}
	}

	// Analyze all interfaces for findings
	for _, iface := range result.Interfaces {
		findings := ha.analyzeInterface(iface)
		result.Findings = append(result.Findings, findings...)
	}

	result.Recommendations = ha.generateRecommendations(result)
	return result, nil
}

// probeWebInterface checks a single port for a web interface - GET only.
func (ha *HMIAssessor) probeWebInterface(ctx context.Context, target string, port int, scheme string) *HMIInterface {
	// First check if port is open
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(ha.module.config.QueryTimeoutMs)*time.Millisecond)
	if err != nil {
		return nil
	}
	conn.Close()

	client := &http.Client{
		Timeout: time.Duration(ha.module.config.QueryTimeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, target, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	iface := &HMIInterface{
		URL:     url,
		Port:    port,
		TLS:     scheme == "https",
		Headers: make(map[string]string),
	}

	// Collect security-relevant headers
	secHeaders := []string{"Server", "X-Powered-By", "X-Frame-Options",
		"Content-Security-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-XSS-Protection",
		"WWW-Authenticate", "Access-Control-Allow-Origin"}

	for _, h := range secHeaders {
		if v := resp.Header.Get(h); v != "" {
			iface.Headers[h] = v
		}
	}

	iface.Server = resp.Header.Get("Server")

	// Determine authentication
	if resp.StatusCode == 401 {
		iface.AuthRequired = true
		auth := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(strings.ToLower(auth), "basic") {
			iface.AuthType = "basic"
		} else if auth != "" {
			iface.AuthType = "digest"
		}
	} else if resp.StatusCode == 200 {
		bodyStr := string(body)
		if strings.Contains(strings.ToLower(bodyStr), "<form") &&
			(strings.Contains(strings.ToLower(bodyStr), "password") ||
				strings.Contains(strings.ToLower(bodyStr), "login")) {
			iface.AuthRequired = true
			iface.AuthType = "form"
		} else {
			iface.AuthRequired = false
			iface.AuthType = "none"
		}
	}

	// Detect title
	iface.Title = extractHTMLTitle(string(body))

	// Detect vendor/product
	ha.detectHMIProduct(string(body), iface)

	// Detect technologies
	iface.Technologies = ha.detectTechnologies(string(body), resp.Header)

	return iface
}

// analyzeInterface generates security findings for an HMI interface.
func (ha *HMIAssessor) analyzeInterface(iface HMIInterface) []HMIFinding {
	var findings []HMIFinding

	// No authentication
	if !iface.AuthRequired {
		findings = append(findings, HMIFinding{
			Title:       "HMI Web Interface Without Authentication",
			Description: fmt.Sprintf("HMI at %s requires no authentication to access", iface.URL),
			Severity:    "critical",
			Category:    "authentication",
			Remediation: "Enable authentication on the HMI web interface; use role-based access control",
			URL:         iface.URL,
		})
	}

	// Basic auth without TLS
	if iface.AuthType == "basic" && !iface.TLS {
		findings = append(findings, HMIFinding{
			Title:       "Basic Authentication Over HTTP",
			Description: fmt.Sprintf("HMI at %s uses Basic auth over unencrypted HTTP", iface.URL),
			Severity:    "high",
			Category:    "encryption",
			Remediation: "Enable HTTPS before using Basic authentication",
			URL:         iface.URL,
		})
	}

	// No TLS
	if !iface.TLS {
		findings = append(findings, HMIFinding{
			Title:       "Unencrypted HMI Web Interface",
			Description: fmt.Sprintf("HMI at %s uses HTTP without TLS encryption", iface.URL),
			Severity:    "high",
			Category:    "encryption",
			Remediation: "Enable HTTPS with TLS 1.2 or later; redirect HTTP to HTTPS",
			URL:         iface.URL,
		})
	}

	// Missing security headers
	if _, ok := iface.Headers["X-Frame-Options"]; !ok {
		findings = append(findings, HMIFinding{
			Title:       "Missing X-Frame-Options Header",
			Description: "HMI interface may be vulnerable to clickjacking",
			Severity:    "medium",
			Category:    "headers",
			Remediation: "Add X-Frame-Options: DENY or SAMEORIGIN header",
			URL:         iface.URL,
		})
	}

	if _, ok := iface.Headers["Content-Security-Policy"]; !ok {
		findings = append(findings, HMIFinding{
			Title:       "Missing Content-Security-Policy Header",
			Description: "No CSP header may allow cross-site scripting",
			Severity:    "medium",
			Category:    "headers",
			Remediation: "Implement Content-Security-Policy header",
			URL:         iface.URL,
		})
	}

	if iface.TLS {
		if _, ok := iface.Headers["Strict-Transport-Security"]; !ok {
			findings = append(findings, HMIFinding{
				Title:       "Missing HSTS Header",
				Description: "HTTPS without HSTS allows SSL stripping attacks",
				Severity:    "medium",
				Category:    "headers",
				Remediation: "Add Strict-Transport-Security header",
				URL:         iface.URL,
			})
		}
	}

	// Server version disclosure
	if iface.Server != "" {
		findings = append(findings, HMIFinding{
			Title:       "Server Version Disclosure",
			Description: fmt.Sprintf("Server header reveals: %s", iface.Server),
			Severity:    "low",
			Category:    "exposure",
			Remediation: "Remove or minimize server version information in HTTP headers",
			URL:         iface.URL,
		})
	}

	return findings
}

// detectHMIProduct identifies HMI vendor/product from page content.
func (ha *HMIAssessor) detectHMIProduct(body string, iface *HMIInterface) {
	lower := strings.ToLower(body)

	products := []struct {
		marker  string
		vendor  string
		product string
	}{
		{"wincc", "Siemens", "WinCC"},
		{"wonderware", "AVEVA", "Wonderware InTouch"},
		{"factorytalk", "Rockwell", "FactoryTalk View"},
		{"ignition", "Inductive Automation", "Ignition"},
		{"citect", "Schneider Electric", "CitectSCADA"},
		{"ge digital", "GE Digital", "iFIX"},
		{"vijeo", "Schneider Electric", "Vijeo Citect"},
		{"webaccess", "Advantech", "WebAccess"},
		{"magelis", "Schneider Electric", "Magelis HMI"},
		{"comfort panel", "Siemens", "Comfort Panel"},
	}

	for _, p := range products {
		if strings.Contains(lower, p.marker) {
			iface.Vendor = p.vendor
			iface.Product = p.product
			return
		}
	}
}

// detectTechnologies identifies web frameworks and technologies.
func (ha *HMIAssessor) detectTechnologies(body string, headers http.Header) []string {
	var techs []string

	lower := strings.ToLower(body)
	if strings.Contains(lower, "jquery") {
		techs = append(techs, "jQuery")
	}
	if strings.Contains(lower, "angular") {
		techs = append(techs, "Angular")
	}
	if strings.Contains(lower, "react") {
		techs = append(techs, "React")
	}
	if strings.Contains(lower, "silverlight") {
		techs = append(techs, "Silverlight (deprecated)")
	}
	if strings.Contains(lower, "activex") {
		techs = append(techs, "ActiveX (deprecated)")
	}
	if strings.Contains(lower, "java applet") || strings.Contains(lower, "<applet") {
		techs = append(techs, "Java Applet (deprecated)")
	}
	if strings.Contains(lower, "flash") || strings.Contains(lower, "swfobject") {
		techs = append(techs, "Flash (deprecated)")
	}

	// Deprecated technology findings are important for OT HMIs
	powered := headers.Get("X-Powered-By")
	if powered != "" {
		techs = append(techs, powered)
	}

	return techs
}

// extractHTMLTitle extracts the <title> content from HTML.
func extractHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := body[start : start+end]
	title = strings.TrimSpace(title)
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// generateRecommendations produces HMI-specific recommendations.
func (ha *HMIAssessor) generateRecommendations(result *HMIAssessment) []string {
	var recs []string

	critCount := 0
	for _, f := range result.Findings {
		if f.Severity == "critical" {
			critCount++
		}
	}

	if critCount > 0 {
		recs = append(recs, fmt.Sprintf("%d critical HMI findings require immediate attention", critCount))
	}

	// Check for deprecated technologies
	for _, iface := range result.Interfaces {
		for _, tech := range iface.Technologies {
			if strings.Contains(strings.ToLower(tech), "deprecated") {
				recs = append(recs, fmt.Sprintf("Deprecated technology '%s' found on %s - plan migration to modern web standards", tech, iface.URL))
			}
		}
	}

	return recs
}
