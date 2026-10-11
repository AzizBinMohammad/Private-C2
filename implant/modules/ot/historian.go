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

// SAFETY: Historian assessment is READ-ONLY.
// No data modification, no configuration changes, no process value writes.

// HistorianType identifies a historian/SCADA product.
type HistorianType string

const (
	HistorianOSIsoftPI  HistorianType = "osisoft_pi"
	HistorianWonderware HistorianType = "wonderware_historian"
	HistorianGEProfiler HistorianType = "ge_proficy"
	HistorianHoneywell  HistorianType = "honeywell_phd"
	HistorianIgnition   HistorianType = "ignition"
	HistorianSCADA      HistorianType = "generic_scada"
	HistorianUnknown    HistorianType = "unknown"
)

// HistorianInfo holds detected historian information.
type HistorianInfo struct {
	IP           string             `json:"ip"`
	Type         HistorianType      `json:"type"`
	Version      string             `json:"version,omitempty"`
	Vendor       string             `json:"vendor"`
	Product      string             `json:"product"`
	WebInterface bool               `json:"web_interface"`
	WebPorts     []int              `json:"web_ports,omitempty"`
	APIEndpoints []string           `json:"api_endpoints,omitempty"`
	AuthRequired bool               `json:"auth_required"`
	TLSEnabled   bool               `json:"tls_enabled"`
	OpenPorts    []int              `json:"open_ports"`
	Findings     []HistorianFinding `json:"findings"`
}

// HistorianFinding is a security finding related to a historian.
type HistorianFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// HistorianAssessment holds the overall historian assessment.
type HistorianAssessment struct {
	Historians      []HistorianInfo `json:"historians"`
	SCADAServers    []SCADAInfo     `json:"scada_servers"`
	Recommendations []string        `json:"recommendations"`
}

// SCADAInfo holds detected SCADA server information.
type SCADAInfo struct {
	IP      string `json:"ip"`
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	WebPort int    `json:"web_port,omitempty"`
	Version string `json:"version,omitempty"`
}

// HistorianDetector detects and assesses historian/SCADA systems.
type HistorianDetector struct {
	module *OTModule
}

// NewHistorianDetector creates a new historian detector.
func NewHistorianDetector(module *OTModule) *HistorianDetector {
	return &HistorianDetector{module: module}
}

// Assess performs historian/SCADA detection and assessment - READ ONLY.
func (hd *HistorianDetector) Assess(ctx context.Context, assets []OTAsset) (*HistorianAssessment, error) {
	if hd.module.IsShutdown() {
		return nil, fmt.Errorf("OT module is shut down")
	}

	result := &HistorianAssessment{}

	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Check if asset looks like a historian/SCADA
		if isHistorianCandidate(asset) {
			if err := hd.module.PreFlightCheck(asset.IP, "historian-detect"); err != nil {
				continue
			}

			info := hd.detectHistorian(ctx, asset)
			if info != nil {
				result.Historians = append(result.Historians, *info)
			}
		}

		if isSCADACandidate(asset) {
			scada := hd.detectSCADA(ctx, asset)
			if scada != nil {
				result.SCADAServers = append(result.SCADAServers, *scada)
			}
		}
	}

	result.Recommendations = hd.generateRecommendations(result)
	return result, nil
}

// detectHistorian identifies and assesses a historian server.
func (hd *HistorianDetector) detectHistorian(ctx context.Context, asset OTAsset) *HistorianInfo {
	info := &HistorianInfo{
		IP:     asset.IP,
		Vendor: asset.Vendor,
		Type:   HistorianUnknown,
	}

	// Check known historian ports
	historianPorts := map[int]string{
		5450:  "osisoft_pi_af",   // PI AF Server
		5457:  "osisoft_pi_data", // PI Data Archive
		5459:  "osisoft_pi_web",  // PI Web API
		443:   "https",
		80:    "http",
		8088:  "ignition",     // Ignition Gateway
		8043:  "ignition_ssl", // Ignition Gateway SSL
		1433:  "mssql",        // Wonderware uses SQL Server
		39320: "ge_proficy",   // Proficy Historian
	}

	timeout := time.Duration(hd.module.config.QueryTimeoutMs) * time.Millisecond

	for port, svc := range historianPorts {
		addr := net.JoinHostPort(asset.IP, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		conn.Close()
		info.OpenPorts = append(info.OpenPorts, port)

		switch svc {
		case "osisoft_pi_af", "osisoft_pi_data", "osisoft_pi_web":
			info.Type = HistorianOSIsoftPI
			info.Vendor = "OSIsoft / AVEVA"
			info.Product = "PI System"
		case "ignition", "ignition_ssl":
			info.Type = HistorianIgnition
			info.Vendor = "Inductive Automation"
			info.Product = "Ignition"
		case "ge_proficy":
			info.Type = HistorianGEProfiler
			info.Vendor = "GE Digital"
			info.Product = "Proficy Historian"
		}
	}

	// Check web interfaces - READ ONLY (HTTP GET only)
	hd.checkWebInterface(ctx, info)

	return info
}

// checkWebInterface performs READ-ONLY HTTP checks on historian web UIs.
func (hd *HistorianDetector) checkWebInterface(ctx context.Context, info *HistorianInfo) {
	client := &http.Client{
		Timeout: time.Duration(hd.module.config.QueryTimeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	webPorts := []int{80, 443, 8080, 8088, 8043, 5459}
	for _, port := range webPorts {
		scheme := "http"
		if port == 443 || port == 8043 || port == 5459 {
			scheme = "https"
		}

		url := fmt.Sprintf("%s://%s:%d/", scheme, info.IP, port)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := string(body)
		info.WebInterface = true
		info.WebPorts = append(info.WebPorts, port)

		// Check for authentication
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			info.AuthRequired = true
		} else if resp.StatusCode == 200 {
			// No auth required - finding
			info.Findings = append(info.Findings, HistorianFinding{
				Title:       "Unauthenticated Web Access",
				Description: fmt.Sprintf("Historian web interface on port %d accessible without authentication", port),
				Severity:    "high",
				Remediation: "Enable authentication on the historian web interface",
			})
		}

		// TLS check
		if scheme == "https" {
			info.TLSEnabled = true
		} else if scheme == "http" && resp.StatusCode == 200 {
			info.Findings = append(info.Findings, HistorianFinding{
				Title:       "Unencrypted Web Interface",
				Description: fmt.Sprintf("Historian web interface on port %d uses HTTP without TLS", port),
				Severity:    "medium",
				Remediation: "Enable HTTPS and redirect HTTP to HTTPS",
			})
		}

		// Product detection from page content
		hd.detectProductFromWeb(bodyStr, resp, info)
	}
}

// detectProductFromWeb identifies historian product from web page content.
func (hd *HistorianDetector) detectProductFromWeb(body string, resp *http.Response, info *HistorianInfo) {
	server := resp.Header.Get("Server")
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "pi web api") || strings.Contains(bodyLower, "osisoft") {
		info.Type = HistorianOSIsoftPI
		info.Product = "PI Web API"
		info.Vendor = "OSIsoft / AVEVA"
	} else if strings.Contains(bodyLower, "ignition") || strings.Contains(bodyLower, "inductive automation") {
		info.Type = HistorianIgnition
		info.Product = "Ignition"
		info.Vendor = "Inductive Automation"
	} else if strings.Contains(bodyLower, "wonderware") || strings.Contains(bodyLower, "archestra") {
		info.Type = HistorianWonderware
		info.Product = "Wonderware Historian"
		info.Vendor = "AVEVA / Schneider Electric"
	} else if strings.Contains(bodyLower, "proficy") || strings.Contains(server, "GE") {
		info.Type = HistorianGEProfiler
		info.Product = "Proficy Historian"
		info.Vendor = "GE Digital"
	}
}

// detectSCADA checks for SCADA server presence.
func (hd *HistorianDetector) detectSCADA(ctx context.Context, asset OTAsset) *SCADAInfo {
	info := &SCADAInfo{
		IP:     asset.IP,
		Vendor: asset.Vendor,
	}

	// Common SCADA web ports
	client := &http.Client{
		Timeout: time.Duration(hd.module.config.QueryTimeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, port := range []int{80, 443, 8080} {
		scheme := "http"
		if port == 443 {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s:%d/", scheme, asset.IP, port)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyLower := strings.ToLower(string(body))
		if strings.Contains(bodyLower, "scada") || strings.Contains(bodyLower, "clearscada") ||
			strings.Contains(bodyLower, "wincc") || strings.Contains(bodyLower, "citect") {
			info.Product = "SCADA Server"
			info.WebPort = port
			return info
		}
	}

	return nil
}

// isHistorianCandidate checks if an asset might be a historian.
func isHistorianCandidate(asset OTAsset) bool {
	role := strings.ToLower(asset.Role)
	if role == "historian" || role == "data server" {
		return true
	}
	model := strings.ToLower(asset.Model)
	return strings.Contains(model, "historian") || strings.Contains(model, "pi ") ||
		strings.Contains(model, "ignition") || strings.Contains(model, "proficy")
}

// isSCADACandidate checks if an asset might be a SCADA server.
func isSCADACandidate(asset OTAsset) bool {
	role := strings.ToLower(asset.Role)
	if role == "scada" || role == "hmi" {
		return true
	}
	model := strings.ToLower(asset.Model)
	return strings.Contains(model, "scada") || strings.Contains(model, "wincc") ||
		strings.Contains(model, "clearscada")
}

// generateRecommendations produces historian-specific recommendations.
func (hd *HistorianDetector) generateRecommendations(result *HistorianAssessment) []string {
	var recs []string

	for _, hist := range result.Historians {
		if !hist.AuthRequired {
			recs = append(recs, fmt.Sprintf("Enable authentication on historian at %s (%s)", hist.IP, hist.Product))
		}
		if !hist.TLSEnabled && hist.WebInterface {
			recs = append(recs, fmt.Sprintf("Enable TLS on historian web interface at %s", hist.IP))
		}
		for _, f := range hist.Findings {
			if f.Severity == "high" || f.Severity == "critical" {
				recs = append(recs, f.Remediation)
			}
		}
	}

	return recs
}
