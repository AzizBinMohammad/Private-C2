package ot

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PurdueLevel represents a level in the Purdue Enterprise Reference Architecture.
type PurdueLevel int

const (
	PurdueLevel0 PurdueLevel = 0 // Physical Process
	PurdueLevel1 PurdueLevel = 1 // Basic Control (PLCs, RTUs)
	PurdueLevel2 PurdueLevel = 2 // Area Supervisory (HMI, SCADA)
	PurdueLevel3 PurdueLevel = 3 // Site Operations (Historian, MES)
	PurdueLevel35 PurdueLevel = 35 // DMZ
	PurdueLevel4 PurdueLevel = 4 // Site Business (ERP)
	PurdueLevel5 PurdueLevel = 5 // Enterprise Network
)

// TopologyNode represents a node in the OT network topology.
type TopologyNode struct {
	ID           string      `json:"id"`
	IP           string      `json:"ip"`
	Hostname     string      `json:"hostname,omitempty"`
	Vendor       string      `json:"vendor,omitempty"`
	Model        string      `json:"model,omitempty"`
	DeviceType   string      `json:"device_type"`
	PurdueLevel  PurdueLevel `json:"purdue_level"`
	Zone         string      `json:"zone"`
	VLAN         int         `json:"vlan,omitempty"`
	Protocols    []string    `json:"protocols"`
	Interfaces   int         `json:"interfaces,omitempty"`
	IsDualHomed  bool        `json:"is_dual_homed"`
	IsGateway    bool        `json:"is_gateway"`
}

// TopologyEdge represents a connection between two nodes.
type TopologyEdge struct {
	SourceID   string `json:"source_id"`
	TargetID   string `json:"target_id"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	Encrypted  bool   `json:"encrypted"`
	Bidirectional bool `json:"bidirectional"`
}

// NetworkTopology represents the complete OT network topology.
type NetworkTopology struct {
	Nodes           []TopologyNode      `json:"nodes"`
	Edges           []TopologyEdge      `json:"edges"`
	SegmentationGaps []SegmentationGap  `json:"segmentation_gaps"`
	Zones           []NetworkZone       `json:"zones"`
}

// NetworkZone represents a network security zone.
type NetworkZone struct {
	Name        string      `json:"name"`
	PurdueLevel PurdueLevel `json:"purdue_level"`
	Subnet      string      `json:"subnet,omitempty"`
	VLAN        int         `json:"vlan,omitempty"`
	DeviceCount int         `json:"device_count"`
	Devices     []string    `json:"devices"` // Node IDs
}

// SegmentationGap identifies a missing boundary between zones.
type SegmentationGap struct {
	Description string      `json:"description"`
	FromZone    string      `json:"from_zone"`
	ToZone      string      `json:"to_zone"`
	FromLevel   PurdueLevel `json:"from_level"`
	ToLevel     PurdueLevel `json:"to_level"`
	Protocol    string      `json:"protocol,omitempty"`
	Severity    string      `json:"severity"` // "low", "medium", "high", "critical"
}

// TopologyMapper builds a Purdue model network topology.
type TopologyMapper struct {
	module   *OTModule
	nodes    map[string]*TopologyNode
	edges    []TopologyEdge
}

// NewTopologyMapper creates a new topology mapper.
func NewTopologyMapper(module *OTModule) *TopologyMapper {
	return &TopologyMapper{
		module: module,
		nodes:  make(map[string]*TopologyNode),
	}
}

// AddAsset adds a discovered asset to the topology.
func (tm *TopologyMapper) AddAsset(asset OTAsset) {
	node := &TopologyNode{
		ID:          asset.IP,
		IP:          asset.IP,
		Hostname:    asset.Hostname,
		Vendor:      asset.Vendor,
		Model:       asset.Model,
		DeviceType:  asset.Role,
		PurdueLevel: inferPurdueLevel(asset),
		Protocols:   asset.Protocols,
	}
	tm.nodes[asset.IP] = node
}

// AddConnection records a connection between two assets.
func (tm *TopologyMapper) AddConnection(srcIP, dstIP, protocol string, port int, encrypted bool) {
	edge := TopologyEdge{
		SourceID:  srcIP,
		TargetID:  dstIP,
		Protocol:  protocol,
		Port:      port,
		Encrypted: encrypted,
	}
	tm.edges = append(tm.edges, edge)
}

// Build constructs the complete topology.
func (tm *TopologyMapper) Build() *NetworkTopology {
	topo := &NetworkTopology{
		Edges: tm.edges,
	}

	for _, n := range tm.nodes {
		topo.Nodes = append(topo.Nodes, *n)
	}

	// Build zones from Purdue levels
	topo.Zones = tm.buildZones()

	// Detect segmentation gaps
	topo.SegmentationGaps = tm.detectSegmentationGaps()

	return topo
}

// buildZones groups devices into network zones by Purdue level.
func (tm *TopologyMapper) buildZones() []NetworkZone {
	levelDevices := make(map[PurdueLevel][]string)
	for _, node := range tm.nodes {
		levelDevices[node.PurdueLevel] = append(levelDevices[node.PurdueLevel], node.ID)
	}

	levelNames := map[PurdueLevel]string{
		PurdueLevel0:  "Level 0 - Physical Process",
		PurdueLevel1:  "Level 1 - Basic Control",
		PurdueLevel2:  "Level 2 - Area Supervisory",
		PurdueLevel3:  "Level 3 - Site Operations",
		PurdueLevel35: "Level 3.5 - DMZ",
		PurdueLevel4:  "Level 4 - Site Business",
		PurdueLevel5:  "Level 5 - Enterprise",
	}

	var zones []NetworkZone
	for level, devices := range levelDevices {
		zones = append(zones, NetworkZone{
			Name:        levelNames[level],
			PurdueLevel: level,
			DeviceCount: len(devices),
			Devices:     devices,
		})
	}

	return zones
}

// detectSegmentationGaps finds connections that cross Purdue level boundaries without proper segmentation.
func (tm *TopologyMapper) detectSegmentationGaps() []SegmentationGap {
	var gaps []SegmentationGap

	for _, edge := range tm.edges {
		srcNode, srcOK := tm.nodes[edge.SourceID]
		dstNode, dstOK := tm.nodes[edge.TargetID]
		if !srcOK || !dstOK {
			continue
		}

		levelDiff := int(srcNode.PurdueLevel) - int(dstNode.PurdueLevel)
		if levelDiff < 0 {
			levelDiff = -levelDiff
		}

		// Direct connection spanning more than 1 Purdue level
		if levelDiff > 1 {
			severity := "medium"
			if levelDiff > 2 {
				severity = "critical"
			}

			gaps = append(gaps, SegmentationGap{
				Description: fmt.Sprintf("Direct %s connection from Level %d to Level %d (crosses %d levels)",
					edge.Protocol, srcNode.PurdueLevel, dstNode.PurdueLevel, levelDiff),
				FromZone:  fmt.Sprintf("Level %d", srcNode.PurdueLevel),
				ToZone:    fmt.Sprintf("Level %d", dstNode.PurdueLevel),
				FromLevel: srcNode.PurdueLevel,
				ToLevel:   dstNode.PurdueLevel,
				Protocol:  edge.Protocol,
				Severity:  severity,
			})
		}

		// Unencrypted connections crossing any boundary
		if !edge.Encrypted && levelDiff > 0 {
			gaps = append(gaps, SegmentationGap{
				Description: fmt.Sprintf("Unencrypted %s traffic between Level %d and Level %d",
					edge.Protocol, srcNode.PurdueLevel, dstNode.PurdueLevel),
				FromZone:  fmt.Sprintf("Level %d", srcNode.PurdueLevel),
				ToZone:    fmt.Sprintf("Level %d", dstNode.PurdueLevel),
				FromLevel: srcNode.PurdueLevel,
				ToLevel:   dstNode.PurdueLevel,
				Protocol:  edge.Protocol,
				Severity:  "low",
			})
		}
	}

	return gaps
}

// ExportJSON exports the topology as JSON.
func (nt *NetworkTopology) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(nt, "", "  ")
}

// ExportDOT exports the topology as a GraphViz DOT file.
func (nt *NetworkTopology) ExportDOT() string {
	var b strings.Builder
	b.WriteString("digraph OT_Topology {\n")
	b.WriteString("  rankdir=TB;\n")
	b.WriteString("  node [shape=box, style=filled];\n\n")

	// Subgraphs for Purdue levels
	levelColors := map[PurdueLevel]string{
		PurdueLevel0: "#FF6B6B",
		PurdueLevel1: "#FFA07A",
		PurdueLevel2: "#FFD700",
		PurdueLevel3: "#90EE90",
		PurdueLevel35: "#ADD8E6",
		PurdueLevel4: "#87CEEB",
		PurdueLevel5: "#DDA0DD",
	}

	for _, zone := range nt.Zones {
		b.WriteString(fmt.Sprintf("  subgraph cluster_%d {\n", zone.PurdueLevel))
		b.WriteString(fmt.Sprintf("    label=%q;\n", zone.Name))
		color := levelColors[zone.PurdueLevel]
		if color == "" {
			color = "#FFFFFF"
		}
		b.WriteString(fmt.Sprintf("    color=%q;\n", color))
		b.WriteString("    style=filled;\n")

		for _, devID := range zone.Devices {
			b.WriteString(fmt.Sprintf("    %q;\n", devID))
		}
		b.WriteString("  }\n\n")
	}

	// Edges
	for _, edge := range nt.Edges {
		style := "solid"
		if !edge.Encrypted {
			style = "dashed"
		}
		b.WriteString(fmt.Sprintf("  %q -> %q [label=%q, style=%s];\n",
			edge.SourceID, edge.TargetID, edge.Protocol, style))
	}

	b.WriteString("}\n")
	return b.String()
}

// inferPurdueLevel determines the Purdue level based on device characteristics.
func inferPurdueLevel(asset OTAsset) PurdueLevel {
	if asset.PurdueLevel > 0 && asset.PurdueLevel <= 5 {
		return PurdueLevel(asset.PurdueLevel)
	}

	role := strings.ToLower(asset.Role)
	switch {
	case role == "sensor" || role == "actuator" || role == "io":
		return PurdueLevel0
	case role == "plc" || role == "rtu" || role == "dcs":
		return PurdueLevel1
	case role == "hmi" || role == "scada" || role == "ews":
		return PurdueLevel2
	case role == "historian" || role == "mes" || role == "oms":
		return PurdueLevel3
	case role == "erp" || role == "business":
		return PurdueLevel4
	case role == "gateway" || role == "firewall" || role == "dmz":
		return PurdueLevel35
	default:
		return PurdueLevel2 // Default to Level 2
	}
}
