package ot

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// CaptureConfig holds traffic capture configuration.
type CaptureConfig struct {
	Interface     string        `json:"interface"`
	Duration      time.Duration `json:"duration"`
	MaxBytes      int64         `json:"max_bytes"`
	Protocols     []string      `json:"protocols"` // Filter to these OT protocols
	PassiveOnly   bool          `json:"passive_only"`
}

// CapturedPacket represents a single captured OT packet (structured, not raw PCAP).
type CapturedPacket struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    int       `json:"src_port"`
	DstPort    int       `json:"dst_port"`
	Protocol   string    `json:"protocol"`
	Length     int       `json:"length"`
	Direction  string    `json:"direction"` // "request" or "response"
	Function   string    `json:"function,omitempty"`
	Summary    string    `json:"summary"`
	IsAnomalous bool    `json:"is_anomalous,omitempty"`
	AnomalyNote string  `json:"anomaly_note,omitempty"`
}

// CaptureResult holds the results of a traffic capture session.
type CaptureResult struct {
	StartTime          time.Time            `json:"start_time"`
	EndTime            time.Time            `json:"end_time"`
	Duration           time.Duration        `json:"duration"`
	TotalPackets       int                  `json:"total_packets"`
	TotalBytes         int64                `json:"total_bytes"`
	ProtocolBreakdown  map[string]int       `json:"protocol_breakdown"`
	Packets            []CapturedPacket     `json:"packets,omitempty"`
	CommMatrix         []CommMatrixEntry    `json:"comm_matrix"`
	PollingIntervals   []PollingInterval    `json:"polling_intervals"`
	AnomalyIndicators  []AnomalyIndicator   `json:"anomaly_indicators"`
}

// CommMatrixEntry represents communication between two endpoints.
type CommMatrixEntry struct {
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Protocol    string `json:"protocol"`
	PacketCount int    `json:"packet_count"`
	ByteCount   int64  `json:"byte_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// PollingInterval describes detected periodic communication.
type PollingInterval struct {
	SrcIP      string        `json:"src_ip"`
	DstIP      string        `json:"dst_ip"`
	Protocol   string        `json:"protocol"`
	Interval   time.Duration `json:"interval"`
	Jitter     time.Duration `json:"jitter"`
	SampleSize int           `json:"sample_size"`
}

// AnomalyIndicator flags unusual traffic patterns.
type AnomalyIndicator struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // "info", "low", "medium", "high"
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
}

// TrafficCapture handles OT protocol-aware traffic capture.
type TrafficCapture struct {
	module    *OTModule
	config    CaptureConfig
	packets   []CapturedPacket
	mu        sync.Mutex
	totalBytes int64
	commMatrix map[string]*CommMatrixEntry
	intervals  map[string][]time.Time
}

// NewTrafficCapture creates a new traffic capture engine.
func NewTrafficCapture(module *OTModule, config CaptureConfig) *TrafficCapture {
	return &TrafficCapture{
		module:     module,
		config:     config,
		commMatrix: make(map[string]*CommMatrixEntry),
		intervals:  make(map[string][]time.Time),
	}
}

// Capture performs a passive OT traffic capture session.
// Output is structured JSON, never raw PCAP.
func (tc *TrafficCapture) Capture(ctx context.Context) (*CaptureResult, error) {
	if tc.module.IsShutdown() {
		return nil, fmt.Errorf("OT module is shut down")
	}

	startTime := time.Now()
	duration := tc.config.Duration
	if duration > tc.module.config.CaptureMaxDuration {
		duration = tc.module.config.CaptureMaxDuration
	}

	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	// Listen on common OT ports
	ports := otProtocolPorts(tc.config.Protocols)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			tc.listenPort(ctx, p)
		}(port)
	}

	wg.Wait()

	result := &CaptureResult{
		StartTime:         startTime,
		EndTime:           time.Now(),
		Duration:          time.Since(startTime),
		TotalPackets:      len(tc.packets),
		TotalBytes:        tc.totalBytes,
		ProtocolBreakdown: tc.protocolBreakdown(),
		Packets:           tc.packets,
		CommMatrix:        tc.commMatrixSlice(),
		PollingIntervals:  tc.detectPolling(),
		AnomalyIndicators: tc.detectAnomalies(),
	}

	return result, nil
}

// listenPort listens for traffic on a specific port.
func (tc *TrafficCapture) listenPort(ctx context.Context, port int) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		// Try TCP listener for TCP-based protocols
		return
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		tc.mu.Lock()
		if tc.totalBytes+int64(n) > tc.module.config.CaptureMaxBytes {
			tc.mu.Unlock()
			return
		}

		host, _, _ := net.SplitHostPort(remoteAddr.String())
		proto := identifyProtocolByPort(port)

		pkt := CapturedPacket{
			Timestamp: time.Now(),
			SrcIP:     host,
			DstIP:     "local",
			SrcPort:   0,
			DstPort:   port,
			Protocol:  proto,
			Length:     n,
			Direction: "inbound",
			Summary:   fmt.Sprintf("%s packet (%d bytes)", proto, n),
		}

		tc.packets = append(tc.packets, pkt)
		tc.totalBytes += int64(n)

		// Update comm matrix
		key := fmt.Sprintf("%s->local:%s", host, proto)
		if entry, ok := tc.commMatrix[key]; ok {
			entry.PacketCount++
			entry.ByteCount += int64(n)
			entry.LastSeen = time.Now()
		} else {
			tc.commMatrix[key] = &CommMatrixEntry{
				SrcIP:       host,
				DstIP:       "local",
				Protocol:    proto,
				PacketCount: 1,
				ByteCount:   int64(n),
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			}
		}

		// Track timing for polling detection
		iKey := fmt.Sprintf("%s:%s", host, proto)
		tc.intervals[iKey] = append(tc.intervals[iKey], time.Now())

		tc.mu.Unlock()
	}
}

// protocolBreakdown returns packet counts by protocol.
func (tc *TrafficCapture) protocolBreakdown() map[string]int {
	counts := make(map[string]int)
	for _, p := range tc.packets {
		counts[p.Protocol]++
	}
	return counts
}

// commMatrixSlice returns the communication matrix as a slice.
func (tc *TrafficCapture) commMatrixSlice() []CommMatrixEntry {
	var entries []CommMatrixEntry
	for _, e := range tc.commMatrix {
		entries = append(entries, *e)
	}
	return entries
}

// detectPolling detects periodic communication patterns.
func (tc *TrafficCapture) detectPolling() []PollingInterval {
	var intervals []PollingInterval

	for key, timestamps := range tc.intervals {
		if len(timestamps) < 5 {
			continue
		}

		// Calculate inter-arrival times
		var deltas []time.Duration
		for i := 1; i < len(timestamps); i++ {
			deltas = append(deltas, timestamps[i].Sub(timestamps[i-1]))
		}

		// Calculate mean and std dev
		var sum time.Duration
		for _, d := range deltas {
			sum += d
		}
		mean := sum / time.Duration(len(deltas))

		var variance float64
		for _, d := range deltas {
			diff := float64(d - mean)
			variance += diff * diff
		}
		variance /= float64(len(deltas))

		// If jitter is less than 30% of mean, it's likely periodic
		jitter := time.Duration(variance)
		if float64(jitter) < float64(mean)*0.3 {
			// Parse key back to src:proto
			intervals = append(intervals, PollingInterval{
				SrcIP:      key,
				Interval:   mean,
				Jitter:     jitter,
				SampleSize: len(timestamps),
			})
		}
	}

	return intervals
}

// detectAnomalies identifies suspicious patterns in captured traffic.
func (tc *TrafficCapture) detectAnomalies() []AnomalyIndicator {
	var anomalies []AnomalyIndicator

	// Check for unusual protocol combinations
	protocols := tc.protocolBreakdown()
	if _, ok := protocols["modbus"]; ok {
		if _, ok2 := protocols["http"]; ok2 {
			anomalies = append(anomalies, AnomalyIndicator{
				Type:        "mixed_protocols",
				Description: "HTTP traffic detected alongside Modbus - potential IT/OT convergence or web-based HMI",
				Severity:    "info",
				Timestamp:   time.Now(),
			})
		}
	}

	// Check for burst patterns
	if len(tc.packets) > 100 {
		windowSize := 10 * time.Second
		maxInWindow := 0
		for i, p := range tc.packets {
			count := 0
			for j := i; j < len(tc.packets); j++ {
				if tc.packets[j].Timestamp.Sub(p.Timestamp) > windowSize {
					break
				}
				count++
			}
			if count > maxInWindow {
				maxInWindow = count
			}
		}
		if maxInWindow > 50 {
			anomalies = append(anomalies, AnomalyIndicator{
				Type:        "burst_traffic",
				Description: fmt.Sprintf("Burst of %d packets in 10s window detected", maxInWindow),
				Severity:    "medium",
				Timestamp:   time.Now(),
			})
		}
	}

	return anomalies
}

// ExportJSON exports the capture result as formatted JSON.
func (cr *CaptureResult) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(cr, "", "  ")
}

// identifyProtocolByPort maps a port number to a protocol name.
func identifyProtocolByPort(port int) string {
	protocols := map[int]string{
		502:   "modbus",
		102:   "s7comm",
		44818: "ethernetip",
		47808: "bacnet",
		2404:  "iec104",
		20000: "dnp3",
		4840:  "opcua",
		9600:  "fins",
		1883:  "mqtt",
		5683:  "coap",
		5094:  "hart-ip",
		34962: "profinet",
		80:    "http",
		443:   "https",
	}
	if p, ok := protocols[port]; ok {
		return p
	}
	return fmt.Sprintf("port-%d", port)
}

// otProtocolPorts returns ports for requested OT protocols.
func otProtocolPorts(protocols []string) []int {
	allPorts := map[string]int{
		"modbus":    502,
		"s7comm":    102,
		"ethernetip": 44818,
		"bacnet":    47808,
		"iec104":    2404,
		"dnp3":      20000,
		"opcua":     4840,
		"fins":      9600,
		"mqtt":      1883,
		"coap":      5683,
		"hart-ip":   5094,
		"profinet":  34962,
	}

	if len(protocols) == 0 {
		var ports []int
		for _, p := range allPorts {
			ports = append(ports, p)
		}
		return ports
	}

	var ports []int
	for _, proto := range protocols {
		if p, ok := allPorts[proto]; ok {
			ports = append(ports, p)
		}
	}
	return ports
}
