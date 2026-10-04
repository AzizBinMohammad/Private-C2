package ot

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// SAFETY: Serial port and fieldbus enumeration is READ-ONLY.
// No configuration changes, no protocol writes, no baud rate changes.

// SerialPortInfo describes a serial port or serial-to-Ethernet converter.
type SerialPortInfo struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Type       string `json:"type"` // "serial_server", "terminal_server", "protocol_converter"
	Vendor     string `json:"vendor,omitempty"`
	Model      string `json:"model,omitempty"`
	NumPorts   int    `json:"num_ports,omitempty"`
	Protocol   string `json:"protocol,omitempty"` // Serial protocol bridged
	BaudRate   int    `json:"baud_rate,omitempty"`
	Banner     string `json:"banner,omitempty"`
}

// FieldbusInfo describes a detected fieldbus network.
type FieldbusInfo struct {
	Type       string `json:"type"` // "modbus_rtu", "profibus", "devicenet", "foundation_fieldbus", "asi"
	Gateway    string `json:"gateway,omitempty"`
	Protocol   string `json:"bridge_protocol,omitempty"`
	DeviceCount int   `json:"device_count,omitempty"`
	Evidence   string `json:"evidence"`
}

// SerialAssessment holds the serial/fieldbus enumeration results.
type SerialAssessment struct {
	SerialPorts  []SerialPortInfo   `json:"serial_ports"`
	Fieldbuses   []FieldbusInfo     `json:"fieldbuses"`
	Findings     []SerialFinding    `json:"findings"`
	Recommendations []string        `json:"recommendations"`
}

// SerialFinding is a security finding related to serial infrastructure.
type SerialFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// SerialScanner enumerates serial and fieldbus infrastructure.
type SerialScanner struct {
	module *OTModule
}

// NewSerialScanner creates a new serial scanner.
func NewSerialScanner(module *OTModule) *SerialScanner {
	return &SerialScanner{module: module}
}

// Enumerate detects serial-to-Ethernet converters and fieldbus gateways - READ ONLY.
func (ss *SerialScanner) Enumerate(ctx context.Context, assets []OTAsset) (*SerialAssessment, error) {
	if ss.module.IsShutdown() {
		return nil, fmt.Errorf("OT module is shut down")
	}

	result := &SerialAssessment{}

	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Detect serial servers
		ss.detectSerialServer(ctx, asset, result)

		// Detect fieldbus gateways
		ss.detectFieldbusGateway(asset, result)
	}

	// Check for exposed serial ports on common converter ports
	ss.scanSerialConverterPorts(ctx, assets, result)

	result.Recommendations = ss.generateRecommendations(result)
	return result, nil
}

// detectSerialServer identifies serial-to-Ethernet converter devices.
func (ss *SerialScanner) detectSerialServer(ctx context.Context, asset OTAsset, result *SerialAssessment) {
	// Common serial server vendors and models
	serialVendors := []struct {
		vendor  string
		models  []string
	}{
		{"moxa", []string{"nport", "mgate", "mb3"}},
		{"digi", []string{"portserver", "connect"}},
		{"lantronix", []string{"uds", "ets", "xport"}},
		{"advantech", []string{"eki", "adam"}},
		{"perle", []string{"iolan", "trueport"}},
		{"comtrol", []string{"rocketlinx", "devicemaster"}},
	}

	vendorLower := strings.ToLower(asset.Vendor)
	modelLower := strings.ToLower(asset.Model)

	for _, sv := range serialVendors {
		if strings.Contains(vendorLower, sv.vendor) {
			for _, m := range sv.models {
				if strings.Contains(modelLower, m) {
					info := SerialPortInfo{
						IP:     asset.IP,
						Type:   "serial_server",
						Vendor: asset.Vendor,
						Model:  asset.Model,
					}
					result.SerialPorts = append(result.SerialPorts, info)

					// Finding for exposed serial port
					result.Findings = append(result.Findings, SerialFinding{
						Title:       "Serial-to-Ethernet Converter Detected",
						Description: fmt.Sprintf("Serial server %s %s at %s bridges serial protocols to TCP/IP", asset.Vendor, asset.Model, asset.IP),
						Severity:    "medium",
						Remediation: "Ensure serial converter management interface is authenticated and network-segmented",
					})
					return
				}
			}
		}
	}
}

// detectFieldbusGateway identifies fieldbus protocol gateways.
func (ss *SerialScanner) detectFieldbusGateway(asset OTAsset, result *SerialAssessment) {
	// Detect fieldbus gateways from protocol/model info
	modelLower := strings.ToLower(asset.Model)
	vendorLower := strings.ToLower(asset.Vendor)

	if strings.Contains(modelLower, "profibus") ||
		(strings.Contains(vendorLower, "siemens") && strings.Contains(modelLower, "ie/pb")) {
		result.Fieldbuses = append(result.Fieldbuses, FieldbusInfo{
			Type:     "profibus",
			Gateway:  asset.IP,
			Evidence: fmt.Sprintf("PROFIBUS gateway detected: %s %s at %s", asset.Vendor, asset.Model, asset.IP),
		})
	}

	if strings.Contains(modelLower, "devicenet") {
		result.Fieldbuses = append(result.Fieldbuses, FieldbusInfo{
			Type:     "devicenet",
			Gateway:  asset.IP,
			Evidence: fmt.Sprintf("DeviceNet gateway detected: %s %s at %s", asset.Vendor, asset.Model, asset.IP),
		})
	}

	if strings.Contains(modelLower, "foundation fieldbus") || strings.Contains(modelLower, "ff ") {
		result.Fieldbuses = append(result.Fieldbuses, FieldbusInfo{
			Type:     "foundation_fieldbus",
			Gateway:  asset.IP,
			Evidence: fmt.Sprintf("Foundation Fieldbus gateway detected at %s", asset.IP),
		})
	}

	if strings.Contains(modelLower, "modbus rtu") || strings.Contains(modelLower, "mgate") {
		result.Fieldbuses = append(result.Fieldbuses, FieldbusInfo{
			Type:     "modbus_rtu",
			Gateway:  asset.IP,
			Protocol: "modbus_tcp_to_rtu",
			Evidence: fmt.Sprintf("Modbus TCP-to-RTU gateway at %s", asset.IP),
		})
	}
}

// scanSerialConverterPorts checks common serial converter TCP ports.
func (ss *SerialScanner) scanSerialConverterPorts(ctx context.Context, assets []OTAsset, result *SerialAssessment) {
	// Common serial-over-TCP ports
	serialPorts := []int{
		4001, 4002, 4003, 4004, // Moxa NPort defaults
		3001, 3002, 3003,       // Digi PortServer
		10001, 10002,           // Lantronix
		8000, 8001,             // Generic
		7001, 7002,             // Perle IOLAN
	}

	timeout := time.Duration(ss.module.config.QueryTimeoutMs) * time.Millisecond

	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := ss.module.PreFlightCheck(asset.IP, "serial-scan"); err != nil {
			continue
		}

		for _, port := range serialPorts {
			addr := fmt.Sprintf("%s:%d", asset.IP, port)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				continue
			}

			// Read any banner
			_ = conn.SetReadDeadline(time.Now().Add(time.Second * 2))
			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			conn.Close()

			banner := ""
			if n > 0 {
				banner = sanitizeSerialBanner(buf[:n])
			}

			info := SerialPortInfo{
				IP:     asset.IP,
				Port:   port,
				Type:   "serial_server",
				Banner: banner,
			}
			result.SerialPorts = append(result.SerialPorts, info)

			result.Findings = append(result.Findings, SerialFinding{
				Title:       "Exposed Serial-over-TCP Port",
				Description: fmt.Sprintf("TCP port %d open at %s - likely serial-to-TCP bridge", port, asset.IP),
				Severity:    "high",
				Remediation: "Restrict access to serial bridge ports via firewall; require authentication if supported",
			})

			ss.module.rateLimiter.Wait()
		}
	}
}

// sanitizeSerialBanner cleans up raw serial data for display.
func sanitizeSerialBanner(data []byte) string {
	var cleaned []byte
	for _, b := range data {
		if b >= 32 && b < 127 {
			cleaned = append(cleaned, b)
		} else {
			cleaned = append(cleaned, '.')
		}
	}
	s := string(cleaned)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// generateRecommendations produces serial-specific recommendations.
func (ss *SerialScanner) generateRecommendations(result *SerialAssessment) []string {
	var recs []string

	if len(result.SerialPorts) > 0 {
		recs = append(recs, "Serial-to-Ethernet converters should be on isolated network segments")
		recs = append(recs, "Enable authentication on serial converter management interfaces")
		recs = append(recs, "Disable unused serial ports on converter devices")
	}

	if len(result.Fieldbuses) > 0 {
		recs = append(recs, "Fieldbus gateways bridge air-gapped networks to IP - verify segmentation")
		recs = append(recs, "Document all fieldbus-to-IP bridge points for the network diagram")
	}

	return recs
}
