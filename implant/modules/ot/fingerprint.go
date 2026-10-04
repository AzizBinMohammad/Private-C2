package ot

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// FingerprintSource identifies where a fingerprint data point came from.
type FingerprintSource string

const (
	FPSourceMAC      FingerprintSource = "mac_oui"
	FPSourceBanner   FingerprintSource = "banner"
	FPSourceProtocol FingerprintSource = "protocol"
	FPSourceHTTP     FingerprintSource = "http"
	FPSourceSNMP     FingerprintSource = "snmp"
	FPSourceTLS      FingerprintSource = "tls"
	FPSourceLLDP     FingerprintSource = "lldp"
	FPSourceDNS      FingerprintSource = "dns"
)

// FingerprintResult holds the combined fingerprint for a device.
type FingerprintResult struct {
	IP           string             `json:"ip"`
	Vendor       string             `json:"vendor"`
	Model        string             `json:"model"`
	Firmware     string             `json:"firmware"`
	DeviceType   string             `json:"device_type"`
	Confidence   float64            `json:"confidence"`
	Sources      []FingerprintEntry `json:"sources"`
	CVEs         []CVEReference     `json:"cves,omitempty"`
	Tags         []string           `json:"tags"`
}

// FingerprintEntry is a single data point contributing to a fingerprint.
type FingerprintEntry struct {
	Source     FingerprintSource `json:"source"`
	Field     string            `json:"field"`
	Value     string            `json:"value"`
	Confidence float64          `json:"confidence"`
}

// CVEReference is a cross-reference to a known vulnerability.
type CVEReference struct {
	CVEID       string  `json:"cve_id"`
	Description string  `json:"description"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	AffectsFrom string  `json:"affects_from,omitempty"`
	AffectsTo   string  `json:"affects_to,omitempty"`
	Published   string  `json:"published,omitempty"`
}

// Fingerprinter performs multi-source device fingerprinting.
type Fingerprinter struct {
	module *OTModule
}

// NewFingerprinter creates a new fingerprinter.
func NewFingerprinter(module *OTModule) *Fingerprinter {
	return &Fingerprinter{module: module}
}

// Fingerprint performs a comprehensive device fingerprint - READ ONLY.
func (f *Fingerprinter) Fingerprint(ctx context.Context, target string) (*FingerprintResult, error) {
	if err := f.module.PreFlightCheck(target, "fingerprint"); err != nil {
		return nil, err
	}

	result := &FingerprintResult{
		IP: target,
	}

	// MAC OUI lookup
	f.fingerprintMAC(target, result)

	// HTTP headers
	f.fingerprintHTTP(ctx, target, result)

	// TLS certificate
	f.fingerprintTLS(ctx, target, result)

	// Calculate overall confidence
	result.Confidence = f.calculateConfidence(result)

	// Determine vendor and model from best sources
	f.consolidateIdentity(result)

	// Cross-reference CVEs
	result.CVEs = f.lookupCVEs(result.Vendor, result.Model, result.Firmware)

	return result, nil
}

// fingerprintMAC attempts to resolve MAC address and look up OUI.
func (f *Fingerprinter) fingerprintMAC(target string, result *FingerprintResult) {
	// ARP resolution is platform-dependent; record any known MAC
	vendor := lookupOUI("") // Would use actual MAC
	if vendor != "" {
		result.Sources = append(result.Sources, FingerprintEntry{
			Source:     FPSourceMAC,
			Field:      "vendor",
			Value:      vendor,
			Confidence: 0.6,
		})
	}
}

// fingerprintHTTP checks HTTP/HTTPS for device info - READ ONLY.
func (f *Fingerprinter) fingerprintHTTP(ctx context.Context, target string, result *FingerprintResult) {
	client := &http.Client{
		Timeout: time.Duration(f.module.config.QueryTimeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, port := range []int{80, 443, 8080, 8443} {
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s:%d/", scheme, target, port)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Server header
		server := resp.Header.Get("Server")
		if server != "" {
			result.Sources = append(result.Sources, FingerprintEntry{
				Source:     FPSourceHTTP,
				Field:      "server",
				Value:      server,
				Confidence: 0.7,
			})
		}

		// X-Powered-By
		powered := resp.Header.Get("X-Powered-By")
		if powered != "" {
			result.Sources = append(result.Sources, FingerprintEntry{
				Source:     FPSourceHTTP,
				Field:      "powered_by",
				Value:      powered,
				Confidence: 0.5,
			})
		}

		// WWW-Authenticate
		auth := resp.Header.Get("WWW-Authenticate")
		if auth != "" {
			result.Sources = append(result.Sources, FingerprintEntry{
				Source:     FPSourceHTTP,
				Field:      "www_authenticate",
				Value:      auth,
				Confidence: 0.6,
			})
		}
	}
}

// fingerprintTLS checks TLS certificates for device info - READ ONLY.
func (f *Fingerprinter) fingerprintTLS(ctx context.Context, target string, result *FingerprintResult) {
	for _, port := range []int{443, 8443, 4843, 502} {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", addr, time.Second*3)
		if err != nil {
			continue
		}
		conn.Close()

		// In a full implementation, we would perform a TLS handshake,
		// extract the certificate, and parse Subject, Issuer, SANs.
		_ = addr
	}
}

// calculateConfidence computes overall fingerprint confidence from sources.
func (f *Fingerprinter) calculateConfidence(result *FingerprintResult) float64 {
	if len(result.Sources) == 0 {
		return 0
	}

	// Weighted average of source confidences
	var totalWeight, weightedSum float64
	for _, src := range result.Sources {
		weight := 1.0
		switch src.Source {
		case FPSourceProtocol:
			weight = 2.0
		case FPSourceHTTP:
			weight = 1.5
		case FPSourceMAC:
			weight = 1.0
		case FPSourceTLS:
			weight = 1.8
		}
		totalWeight += weight
		weightedSum += src.Confidence * weight
	}

	return weightedSum / totalWeight
}

// consolidateIdentity determines the best vendor/model/firmware from all sources.
func (f *Fingerprinter) consolidateIdentity(result *FingerprintResult) {
	// Use highest confidence source for each field
	vendorConf := 0.0
	modelConf := 0.0
	fwConf := 0.0

	for _, src := range result.Sources {
		switch src.Field {
		case "vendor":
			if src.Confidence > vendorConf {
				result.Vendor = src.Value
				vendorConf = src.Confidence
			}
		case "model", "product_name":
			if src.Confidence > modelConf {
				result.Model = src.Value
				modelConf = src.Confidence
			}
		case "firmware", "version":
			if src.Confidence > fwConf {
				result.Firmware = src.Value
				fwConf = src.Confidence
			}
		}
	}

	// Determine device type from vendor/model
	result.DeviceType = inferDeviceType(result.Vendor, result.Model)
}

// lookupCVEs cross-references vendor/model/firmware against known CVEs.
func (f *Fingerprinter) lookupCVEs(vendor, model, firmware string) []CVEReference {
	// This is an offline lookup against a local database.
	// In production, this would query a bundled CVE database.
	var cves []CVEReference

	vendor = strings.ToLower(vendor)
	model = strings.ToLower(model)

	// Known ICS CVEs by vendor (sample entries for demonstration)
	knownCVEs := map[string][]CVEReference{
		"siemens": {
			{CVEID: "CVE-2019-13945", Description: "S7-1200 CPU allows bypass of access protection", CVSS: 6.8, Severity: "medium"},
			{CVEID: "CVE-2019-10929", Description: "S7-1200/1500 cryptographic flaw in challenge-response", CVSS: 5.9, Severity: "medium"},
		},
		"schneider": {
			{CVEID: "CVE-2017-6034", Description: "Modicon M340 authentication bypass", CVSS: 9.8, Severity: "critical"},
		},
		"rockwell": {
			{CVEID: "CVE-2022-1159", Description: "Studio 5000 Logix Designer code modification", CVSS: 7.7, Severity: "high"},
		},
	}

	for key, entries := range knownCVEs {
		if strings.Contains(vendor, key) {
			cves = append(cves, entries...)
		}
	}

	return cves
}

// inferDeviceType guesses the device role from vendor and model info.
func inferDeviceType(vendor, model string) string {
	combined := strings.ToLower(vendor + " " + model)

	if strings.Contains(combined, "plc") || strings.Contains(combined, "s7-") ||
		strings.Contains(combined, "compactlogix") || strings.Contains(combined, "controllogix") {
		return "PLC"
	}
	if strings.Contains(combined, "hmi") || strings.Contains(combined, "panel") {
		return "HMI"
	}
	if strings.Contains(combined, "rtu") {
		return "RTU"
	}
	if strings.Contains(combined, "switch") || strings.Contains(combined, "scalance") {
		return "Network Switch"
	}
	if strings.Contains(combined, "gateway") {
		return "Gateway"
	}
	if strings.Contains(combined, "historian") || strings.Contains(combined, "pi ") {
		return "Historian"
	}
	if strings.Contains(combined, "relay") || strings.Contains(combined, "ied") {
		return "Protection Relay/IED"
	}

	return "Unknown"
}
