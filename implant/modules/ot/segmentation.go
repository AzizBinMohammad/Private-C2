package ot

import (
	"context"
	"fmt"
	"net"
	"time"
)

// SegmentationAnalysis holds the results of a network segmentation assessment.
type SegmentationAnalysis struct {
	Zones           []ZoneInfo         `json:"zones"`
	CrossZoneFlows  []CrossZoneFlow    `json:"cross_zone_flows"`
	Gaps            []SegmentationGap  `json:"gaps"`
	FirewallRules   []InferredFirewall `json:"inferred_firewalls"`
	VLANs           []VLANInfo         `json:"vlans"`
	Recommendations []string           `json:"recommendations"`
	OverallScore    float64            `json:"overall_score"` // 0-100
}

// ZoneInfo describes a discovered network zone.
type ZoneInfo struct {
	Name        string      `json:"name"`
	PurdueLevel PurdueLevel `json:"purdue_level"`
	Subnet      string      `json:"subnet"`
	VLAN        int         `json:"vlan,omitempty"`
	DeviceCount int         `json:"device_count"`
	HasFirewall bool        `json:"has_firewall"`
	HasIDS      bool        `json:"has_ids"`
	HasDMZ      bool        `json:"has_dmz"`
}

// CrossZoneFlow represents traffic observed between zones.
type CrossZoneFlow struct {
	FromZone   string `json:"from_zone"`
	ToZone     string `json:"to_zone"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	Encrypted  bool   `json:"encrypted"`
	Authorized bool   `json:"authorized"` // Expected by policy
	Risk       string `json:"risk"`       // "low", "medium", "high", "critical"
}

// InferredFirewall represents a firewall boundary inferred from reachability.
type InferredFirewall struct {
	BetweenZones [2]string `json:"between_zones"`
	Evidence     string    `json:"evidence"`
	Type         string    `json:"type"` // "firewall", "router_acl", "vlan", "none_detected"
	Confidence   float64   `json:"confidence"`
}

// VLANInfo holds detected VLAN information.
type VLANInfo struct {
	ID          int      `json:"id"`
	Name        string   `json:"name,omitempty"`
	Subnet      string   `json:"subnet,omitempty"`
	PurdueLevel PurdueLevel `json:"purdue_level"`
	Devices     []string `json:"devices"`
}

// SegmentationAnalyzer performs Purdue model segmentation analysis.
type SegmentationAnalyzer struct {
	module  *OTModule
	assets  []OTAsset
	topo    *NetworkTopology
}

// NewSegmentationAnalyzer creates a new segmentation analyzer.
func NewSegmentationAnalyzer(module *OTModule, assets []OTAsset, topo *NetworkTopology) *SegmentationAnalyzer {
	return &SegmentationAnalyzer{
		module: module,
		assets: assets,
		topo:   topo,
	}
}

// Analyze performs the segmentation analysis - READ ONLY, passive checks.
func (sa *SegmentationAnalyzer) Analyze(ctx context.Context) (*SegmentationAnalysis, error) {
	if sa.module.IsShutdown() {
		return nil, fmt.Errorf("OT module is shut down")
	}

	result := &SegmentationAnalysis{}

	// Build zone inventory from topology
	result.Zones = sa.buildZoneInventory()

	// Detect VLANs from IP addressing
	result.VLANs = sa.detectVLANs()

	// Check cross-zone reachability (passive, from observed traffic)
	result.CrossZoneFlows = sa.analyzeCrossZoneFlows()

	// Infer firewall presence from reachability patterns
	result.FirewallRules = sa.inferFirewalls(ctx)

	// Identify segmentation gaps
	result.Gaps = sa.identifyGaps(result)

	// Generate recommendations
	result.Recommendations = sa.generateRecommendations(result)

	// Calculate overall score
	result.OverallScore = sa.calculateScore(result)

	return result, nil
}

// buildZoneInventory creates zone info from discovered assets.
func (sa *SegmentationAnalyzer) buildZoneInventory() []ZoneInfo {
	zoneMap := make(map[PurdueLevel]*ZoneInfo)

	for _, asset := range sa.assets {
		level := inferPurdueLevel(asset)
		if z, ok := zoneMap[level]; ok {
			z.DeviceCount++
		} else {
			zoneMap[level] = &ZoneInfo{
				Name:        purdueLabel(level),
				PurdueLevel: level,
				DeviceCount: 1,
			}
		}
	}

	var zones []ZoneInfo
	for _, z := range zoneMap {
		zones = append(zones, *z)
	}
	return zones
}

// detectVLANs infers VLAN boundaries from IP addressing patterns.
func (sa *SegmentationAnalyzer) detectVLANs() []VLANInfo {
	// Group assets by /24 subnet
	subnets := make(map[string][]string)
	for _, asset := range sa.assets {
		ip := net.ParseIP(asset.IP)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		subnet := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		subnets[subnet] = append(subnets[subnet], asset.IP)
	}

	var vlans []VLANInfo
	vlanID := 1
	for subnet, devices := range subnets {
		vlans = append(vlans, VLANInfo{
			ID:      vlanID,
			Subnet:  subnet,
			Devices: devices,
		})
		vlanID++
	}

	return vlans
}

// analyzeCrossZoneFlows examines traffic crossing zone boundaries.
func (sa *SegmentationAnalyzer) analyzeCrossZoneFlows() []CrossZoneFlow {
	var flows []CrossZoneFlow

	if sa.topo == nil {
		return flows
	}

	assetLevel := make(map[string]PurdueLevel)
	for _, asset := range sa.assets {
		assetLevel[asset.IP] = inferPurdueLevel(asset)
	}

	for _, edge := range sa.topo.Edges {
		srcLevel, srcOK := assetLevel[edge.SourceID]
		dstLevel, dstOK := assetLevel[edge.TargetID]
		if !srcOK || !dstOK {
			continue
		}

		if srcLevel != dstLevel {
			risk := "low"
			levelDiff := int(srcLevel) - int(dstLevel)
			if levelDiff < 0 {
				levelDiff = -levelDiff
			}
			if levelDiff > 1 {
				risk = "high"
			}
			if levelDiff > 2 {
				risk = "critical"
			}
			if !edge.Encrypted {
				if risk == "low" {
					risk = "medium"
				}
			}

			flows = append(flows, CrossZoneFlow{
				FromZone:  purdueLabel(srcLevel),
				ToZone:    purdueLabel(dstLevel),
				Protocol:  edge.Protocol,
				Port:      edge.Port,
				Encrypted: edge.Encrypted,
				Risk:      risk,
			})
		}
	}

	return flows
}

// inferFirewalls tries to detect firewall boundaries from reachability.
func (sa *SegmentationAnalyzer) inferFirewalls(ctx context.Context) []InferredFirewall {
	var firewalls []InferredFirewall

	// Check for TTL differences between zones (simple hop count inference)
	// This is passive analysis only - no active probing

	levels := []PurdueLevel{PurdueLevel0, PurdueLevel1, PurdueLevel2, PurdueLevel3, PurdueLevel4, PurdueLevel5}
	for i := 0; i < len(levels)-1; i++ {
		select {
		case <-ctx.Done():
			return firewalls
		default:
		}

		// Between adjacent levels, check if we can infer a boundary
		fw := InferredFirewall{
			BetweenZones: [2]string{purdueLabel(levels[i]), purdueLabel(levels[i+1])},
			Type:         "none_detected",
			Confidence:   0.3,
			Evidence:     "No boundary device detected between zones",
		}

		// If we see subnet changes between levels, infer at least routing separation
		if sa.subnetsDiffer(levels[i], levels[i+1]) {
			fw.Type = "router_acl"
			fw.Confidence = 0.5
			fw.Evidence = "Different subnets detected between zones, implying routing boundary"
		}

		firewalls = append(firewalls, fw)
	}

	return firewalls
}

// subnetsDiffer checks if assets at two Purdue levels are on different subnets.
func (sa *SegmentationAnalyzer) subnetsDiffer(l1, l2 PurdueLevel) bool {
	subnets1 := make(map[string]bool)
	subnets2 := make(map[string]bool)

	for _, asset := range sa.assets {
		level := inferPurdueLevel(asset)
		ip := net.ParseIP(asset.IP)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		subnet := fmt.Sprintf("%d.%d.%d", ip4[0], ip4[1], ip4[2])

		if level == l1 {
			subnets1[subnet] = true
		}
		if level == l2 {
			subnets2[subnet] = true
		}
	}

	// Check for overlap
	for s := range subnets1 {
		if subnets2[s] {
			return false // Same subnet in both levels
		}
	}
	return len(subnets1) > 0 && len(subnets2) > 0
}

// identifyGaps finds segmentation weaknesses.
func (sa *SegmentationAnalyzer) identifyGaps(result *SegmentationAnalysis) []SegmentationGap {
	var gaps []SegmentationGap

	// Check for missing DMZ
	hasDMZ := false
	for _, z := range result.Zones {
		if z.PurdueLevel == PurdueLevel35 {
			hasDMZ = true
			break
		}
	}
	if !hasDMZ {
		hasLevel3 := false
		hasLevel4 := false
		for _, z := range result.Zones {
			if z.PurdueLevel == PurdueLevel3 {
				hasLevel3 = true
			}
			if z.PurdueLevel == PurdueLevel4 {
				hasLevel4 = true
			}
		}
		if hasLevel3 && hasLevel4 {
			gaps = append(gaps, SegmentationGap{
				Description: "No DMZ (Level 3.5) detected between OT (Level 3) and IT (Level 4) networks",
				FromZone:    "Level 3 - Site Operations",
				ToZone:      "Level 4 - Site Business",
				FromLevel:   PurdueLevel3,
				ToLevel:     PurdueLevel4,
				Severity:    "critical",
			})
		}
	}

	// High-risk cross-zone flows
	for _, flow := range result.CrossZoneFlows {
		if flow.Risk == "critical" || flow.Risk == "high" {
			gaps = append(gaps, SegmentationGap{
				Description: fmt.Sprintf("High-risk %s traffic from %s to %s (port %d, encrypted=%v)",
					flow.Protocol, flow.FromZone, flow.ToZone, flow.Port, flow.Encrypted),
				FromZone: flow.FromZone,
				ToZone:   flow.ToZone,
				Protocol: flow.Protocol,
				Severity: flow.Risk,
			})
		}
	}

	return gaps
}

// generateRecommendations produces actionable recommendations.
func (sa *SegmentationAnalyzer) generateRecommendations(result *SegmentationAnalysis) []string {
	var recs []string

	for _, gap := range result.Gaps {
		switch gap.Severity {
		case "critical":
			recs = append(recs, fmt.Sprintf("[CRITICAL] %s", gap.Description))
		case "high":
			recs = append(recs, fmt.Sprintf("[HIGH] Address: %s", gap.Description))
		}
	}

	// Check for unencrypted cross-zone flows
	for _, flow := range result.CrossZoneFlows {
		if !flow.Encrypted {
			recs = append(recs, fmt.Sprintf("Enable encryption for %s traffic between %s and %s",
				flow.Protocol, flow.FromZone, flow.ToZone))
		}
	}

	return recs
}

// calculateScore calculates overall segmentation score (0-100, higher is better).
func (sa *SegmentationAnalyzer) calculateScore(result *SegmentationAnalysis) float64 {
	score := 100.0

	for _, gap := range result.Gaps {
		switch gap.Severity {
		case "critical":
			score -= 20
		case "high":
			score -= 10
		case "medium":
			score -= 5
		case "low":
			score -= 2
		}
	}

	// Penalty for missing firewalls
	for _, fw := range result.FirewallRules {
		if fw.Type == "none_detected" {
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}
	return score
}

// purdueLabel returns a human-readable Purdue level label.
func purdueLabel(level PurdueLevel) string {
	labels := map[PurdueLevel]string{
		PurdueLevel0:  "Level 0 - Physical Process",
		PurdueLevel1:  "Level 1 - Basic Control",
		PurdueLevel2:  "Level 2 - Area Supervisory",
		PurdueLevel3:  "Level 3 - Site Operations",
		PurdueLevel35: "Level 3.5 - DMZ",
		PurdueLevel4:  "Level 4 - Site Business",
		PurdueLevel5:  "Level 5 - Enterprise",
	}
	if l, ok := labels[level]; ok {
		return l
	}
	return fmt.Sprintf("Level %d", level)
}

// SegmentationTestResult holds results from a reachability probe.
type SegmentationTestResult struct {
	SrcIP       string        `json:"src_ip"`
	DstIP       string        `json:"dst_ip"`
	Port        int           `json:"port"`
	Reachable   bool          `json:"reachable"`
	Latency     time.Duration `json:"latency"`
	TTL         int           `json:"ttl,omitempty"`
}

// TestReachability performs a single TCP connect test - READ ONLY.
func (sa *SegmentationAnalyzer) TestReachability(ctx context.Context, target string, port int) (*SegmentationTestResult, error) {
	if err := sa.module.PreFlightCheck(target, "reachability"); err != nil {
		return nil, err
	}

	result := &SegmentationTestResult{
		DstIP: target,
		Port:  port,
	}

	start := time.Now()
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, time.Duration(sa.module.config.QueryTimeoutMs)*time.Millisecond)
	result.Latency = time.Since(start)

	if err != nil {
		result.Reachable = false
		return result, nil
	}
	conn.Close()
	result.Reachable = true

	return result, nil
}
