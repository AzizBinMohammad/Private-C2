package ot

import (
	"context"
	"fmt"
	"net"
	"time"
)

// WirelessProtocol identifies an industrial wireless technology.
type WirelessProtocol string

const (
	WirelessWiFi         WirelessProtocol = "wifi"
	WirelessHART         WirelessProtocol = "wirelesshart"
	WirelessISA100       WirelessProtocol = "isa100.11a"
	WirelessZigbee       WirelessProtocol = "zigbee"
	WirelessBLE          WirelessProtocol = "ble"
	WirelessLTE          WirelessProtocol = "lte_private"
	WirelessLoRa         WirelessProtocol = "lora"
)

// WirelessFinding represents a detected wireless presence.
type WirelessFinding struct {
	Protocol    WirelessProtocol `json:"protocol"`
	Evidence    string           `json:"evidence"`
	Gateway     string           `json:"gateway,omitempty"`
	SSID        string           `json:"ssid,omitempty"`
	Encryption  string           `json:"encryption,omitempty"`
	Channel     int              `json:"channel,omitempty"`
	Signal      int              `json:"signal_dbm,omitempty"`
	Severity    string           `json:"severity"`
	Risk        string           `json:"risk"`
	Remediation string           `json:"remediation"`
}

// WirelessAssessment holds the complete wireless assessment result.
type WirelessAssessment struct {
	Findings       []WirelessFinding `json:"findings"`
	WiFiAPs        []WiFiAP          `json:"wifi_aps,omitempty"`
	IndustrialWL   []IndustrialWireless `json:"industrial_wireless,omitempty"`
	Recommendations []string          `json:"recommendations"`
}

// WiFiAP represents a detected WiFi access point.
type WiFiAP struct {
	SSID       string `json:"ssid"`
	BSSID      string `json:"bssid"`
	Channel    int    `json:"channel"`
	Encryption string `json:"encryption"` // "open", "wep", "wpa", "wpa2", "wpa3"
	Signal     int    `json:"signal_dbm"`
	InOTZone   bool   `json:"in_ot_zone"`
}

// IndustrialWireless represents an industrial wireless network component.
type IndustrialWireless struct {
	Protocol WirelessProtocol `json:"protocol"`
	Gateway  string           `json:"gateway"`
	Vendor   string           `json:"vendor"`
	Model    string           `json:"model,omitempty"`
	Nodes    int              `json:"nodes,omitempty"`
}

// WirelessScanner detects wireless in OT environments.
type WirelessScanner struct {
	module *OTModule
}

// NewWirelessScanner creates a new wireless scanner.
func NewWirelessScanner(module *OTModule) *WirelessScanner {
	return &WirelessScanner{module: module}
}

// Assess performs wireless detection in the OT environment - READ ONLY.
// This detects wireless gateways by their wired-side network presence,
// NOT by RF scanning (which requires specialized hardware).
func (ws *WirelessScanner) Assess(ctx context.Context, assets []OTAsset) (*WirelessAssessment, error) {
	if ws.module.IsShutdown() {
		return nil, fmt.Errorf("OT module is shut down")
	}

	result := &WirelessAssessment{}

	// Detect WirelessHART gateways
	ws.detectWirelessHART(ctx, assets, result)

	// Detect ISA100.11a gateways
	ws.detectISA100(ctx, assets, result)

	// Detect WiFi APs visible on the wired side
	ws.detectWiFiAPs(ctx, assets, result)

	// Detect Zigbee coordinators/gateways
	ws.detectZigbee(ctx, assets, result)

	// Detect BLE gateways
	ws.detectBLE(ctx, assets, result)

	// Generate recommendations
	result.Recommendations = ws.generateRecommendations(result)

	return result, nil
}

// detectWirelessHART checks for WirelessHART gateway devices on the network.
func (ws *WirelessScanner) detectWirelessHART(ctx context.Context, assets []OTAsset, result *WirelessAssessment) {
	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// WirelessHART gateways typically have HART-IP on port 5094
		// and are from vendors like Emerson, ABB, Pepperl+Fuchs
		vendor := asset.Vendor
		isHARTVendor := containsAnyCI(vendor, []string{"emerson", "abb", "pepperl", "honeywell", "endress"})

		for _, svc := range asset.Services {
			if svc == "hart-ip" || containsAnyCI(asset.Model, []string{"wireless", "hart", "1420", "swg"}) {
				result.IndustrialWL = append(result.IndustrialWL, IndustrialWireless{
					Protocol: WirelessHART,
					Gateway:  asset.IP,
					Vendor:   asset.Vendor,
					Model:    asset.Model,
				})

				severity := "medium"
				if !isHARTVendor {
					severity = "high"
				}

				result.Findings = append(result.Findings, WirelessFinding{
					Protocol:    WirelessHART,
					Evidence:    fmt.Sprintf("WirelessHART gateway detected at %s (%s %s)", asset.IP, asset.Vendor, asset.Model),
					Gateway:     asset.IP,
					Severity:    severity,
					Risk:        "WirelessHART uses AES-128 encryption but gateway wired interface should be segmented",
					Remediation: "Ensure WirelessHART gateway is on a dedicated VLAN with firewall rules",
				})
				break
			}
		}
	}
}

// detectISA100 checks for ISA100.11a devices.
func (ws *WirelessScanner) detectISA100(ctx context.Context, assets []OTAsset, result *WirelessAssessment) {
	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if containsAnyCI(asset.Model, []string{"isa100", "isa 100", "oneWireless"}) ||
			containsAnyCI(asset.Vendor, []string{"yokogawa"}) && containsAnyCI(asset.Model, []string{"yfgw"}) {
			result.IndustrialWL = append(result.IndustrialWL, IndustrialWireless{
				Protocol: WirelessISA100,
				Gateway:  asset.IP,
				Vendor:   asset.Vendor,
				Model:    asset.Model,
			})

			result.Findings = append(result.Findings, WirelessFinding{
				Protocol:    WirelessISA100,
				Evidence:    fmt.Sprintf("ISA100.11a gateway detected at %s (%s %s)", asset.IP, asset.Vendor, asset.Model),
				Gateway:     asset.IP,
				Severity:    "medium",
				Risk:        "ISA100.11a gateway provides wireless access to field devices",
				Remediation: "Verify gateway security configuration and network segmentation",
			})
		}
	}
}

// detectWiFiAPs looks for WiFi access points on the wired network.
func (ws *WirelessScanner) detectWiFiAPs(ctx context.Context, assets []OTAsset, result *WirelessAssessment) {
	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		isAP := containsAnyCI(asset.Model, []string{"access point", "wap", "ap ", "aironet", "aruba"}) ||
			containsAnyCI(asset.Vendor, []string{"cisco", "aruba", "ubiquiti", "ruckus"}) &&
				containsAnyCI(asset.Role, []string{"gateway"})

		if isAP {
			ap := WiFiAP{
				BSSID:  asset.MAC,
				Signal: 0,
			}

			// Check for web management interface to determine encryption type
			for _, port := range asset.OpenPorts {
				if port == 80 || port == 443 {
					ap.InOTZone = true
					break
				}
			}

			result.WiFiAPs = append(result.WiFiAPs, ap)

			result.Findings = append(result.Findings, WirelessFinding{
				Protocol:    WirelessWiFi,
				Evidence:    fmt.Sprintf("WiFi access point detected at %s (%s %s)", asset.IP, asset.Vendor, asset.Model),
				Severity:    "high",
				Risk:        "WiFi in OT zone provides wireless attack surface",
				Remediation: "Remove unnecessary WiFi APs from OT zones; use WPA3-Enterprise with RADIUS",
			})
		}
	}
}

// detectZigbee checks for Zigbee coordinators/gateways.
func (ws *WirelessScanner) detectZigbee(ctx context.Context, assets []OTAsset, result *WirelessAssessment) {
	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if containsAnyCI(asset.Model, []string{"zigbee", "zb ", "coordinator"}) {
			result.Findings = append(result.Findings, WirelessFinding{
				Protocol:    WirelessZigbee,
				Evidence:    fmt.Sprintf("Zigbee gateway detected at %s", asset.IP),
				Gateway:     asset.IP,
				Severity:    "medium",
				Risk:        "Zigbee has known vulnerabilities in key exchange",
				Remediation: "Verify Zigbee network uses link-layer encryption, segment gateway",
			})
		}
	}
}

// detectBLE checks for BLE gateway devices.
func (ws *WirelessScanner) detectBLE(ctx context.Context, assets []OTAsset, result *WirelessAssessment) {
	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if containsAnyCI(asset.Model, []string{"ble gateway", "bluetooth", "beacon"}) {
			result.Findings = append(result.Findings, WirelessFinding{
				Protocol:    WirelessBLE,
				Evidence:    fmt.Sprintf("BLE gateway detected at %s", asset.IP),
				Gateway:     asset.IP,
				Severity:    "low",
				Risk:        "BLE in OT environment may expose asset tracking or sensor data",
				Remediation: "Verify BLE gateway segmentation and data sensitivity",
			})
		}
	}
}

// generateRecommendations produces wireless-specific recommendations.
func (ws *WirelessScanner) generateRecommendations(result *WirelessAssessment) []string {
	var recs []string

	if len(result.WiFiAPs) > 0 {
		recs = append(recs, "WiFi detected in OT zone - conduct wireless site survey to identify coverage and rogue APs")
		recs = append(recs, "Implement wireless IDS/IPS for OT wireless networks")
	}

	if len(result.IndustrialWL) > 0 {
		recs = append(recs, "Industrial wireless gateways should be on dedicated VLANs with strict firewall rules")
		recs = append(recs, "Verify firmware versions of all wireless gateway devices")
	}

	for _, f := range result.Findings {
		if f.Severity == "high" || f.Severity == "critical" {
			recs = append(recs, f.Remediation)
		}
	}

	return recs
}

// containsAnyCI checks if s contains any of the substrings (case-insensitive).
func containsAnyCI(s string, subs []string) bool {
	lower := lowerStr(s)
	for _, sub := range subs {
		if netContains(lower, lowerStr(sub)) {
			return true
		}
	}
	return false
}

func lowerStr(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func netContains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// CheckWirelessPort checks if a known wireless management port is open - READ ONLY.
func (ws *WirelessScanner) CheckWirelessPort(target string, port int) bool {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, time.Duration(ws.module.config.QueryTimeoutMs)*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
