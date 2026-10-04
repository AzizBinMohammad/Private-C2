package ot

import (
	"context"
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/implant/modules/ot/protocols"
)

// SAFETY: PLC logic assessment is READ-ONLY.
// Only reads block lists and tag metadata.
// No program download, no upload, no modification, no run/stop control.

// PLCLogicInfo holds read-only PLC program metadata.
type PLCLogicInfo struct {
	Target      string          `json:"target"`
	Protocol    string          `json:"protocol"`
	CPUInfo     *PLCCPUInfo     `json:"cpu_info,omitempty"`
	Blocks      []PLCBlock      `json:"blocks,omitempty"`
	Tags        []PLCTag        `json:"tags,omitempty"`
	ProjectInfo *PLCProjectInfo `json:"project_info,omitempty"`
	Findings    []PLCFinding    `json:"findings,omitempty"`
}

// PLCCPUInfo holds CPU identification data.
type PLCCPUInfo struct {
	Vendor     string `json:"vendor"`
	Model      string `json:"model"`
	Firmware   string `json:"firmware"`
	SerialNum  string `json:"serial_num,omitempty"`
	RunState   string `json:"run_state,omitempty"` // "run", "stop", "unknown"
	Protection string `json:"protection,omitempty"`
}

// PLCBlock represents a program block in a PLC.
type PLCBlock struct {
	Number   int    `json:"number"`
	Type     string `json:"type"` // "OB", "FB", "FC", "DB", "SFB", "SFC", "SDB"
	Name     string `json:"name,omitempty"`
	Language string `json:"language,omitempty"` // "LAD", "FBD", "STL", "SCL", "Graph"
	Size     int    `json:"size,omitempty"`
	Modified string `json:"modified,omitempty"`
}

// PLCTag represents a tag/variable in a PLC program.
type PLCTag struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	DataType string `json:"data_type"`
	Comment  string `json:"comment,omitempty"`
	Scope    string `json:"scope,omitempty"` // "global", "local"
	ReadOnly bool   `json:"read_only"`
}

// PLCProjectInfo holds PLC project metadata.
type PLCProjectInfo struct {
	ProjectName string `json:"project_name,omitempty"`
	Author      string `json:"author,omitempty"`
	Created     string `json:"created,omitempty"`
	Modified    string `json:"modified,omitempty"`
	Version     string `json:"version,omitempty"`
}

// PLCFinding is a security finding related to PLC program.
type PLCFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// PLCLogicReader reads PLC program metadata - READ ONLY.
type PLCLogicReader struct {
	module *OTModule
}

// NewPLCLogicReader creates a new PLC logic reader.
func NewPLCLogicReader(module *OTModule) *PLCLogicReader {
	return &PLCLogicReader{module: module}
}

// ReadS7Metadata reads Siemens S7 PLC program metadata - READ ONLY.
func (plr *PLCLogicReader) ReadS7Metadata(ctx context.Context, target string, port int) (*PLCLogicInfo, error) {
	if err := plr.module.PreFlightCheck(target, "s7comm"); err != nil {
		return nil, err
	}

	if err := plr.module.AcquireConnection(target); err != nil {
		return nil, err
	}
	defer plr.module.ReleaseConnection(target)

	config := protocols.ConnConfig{
		Timeout:         plr.module.QueryTimeout(),
		InterPacketDelay: plr.module.InterPacketDelay(),
	}

	client := protocols.NewS7Client(config)
	if err := client.Connect(ctx, target, port); err != nil {
		return nil, fmt.Errorf("S7 connect failed: %w", err)
	}
	defer client.Close()

	info := &PLCLogicInfo{
		Target:   target,
		Protocol: "s7comm",
	}

	// Read CPU info via SZL
	cpuInfo, err := client.ReadCPUInfo()
	if err == nil {
		info.CPUInfo = &PLCCPUInfo{
			Vendor:   "Siemens",
			Model:    cpuInfo.ModuleType,
			Firmware: cpuInfo.ASName,
		}
	}

	// Read block list via SZL 0x0011 (block types available)
	szlBlocks, err := client.ReadSZL(0x0011, 0x0000)
	if err == nil && len(szlBlocks) > 0 {
		info.Blocks = parseS7BlockList(szlBlocks)
	}


	// Security assessment
	info.Findings = plr.assessS7Security(info)

	return info, nil
}

// parseS7BlockList extracts block info from SZL 0x0011 response entries.
func parseS7BlockList(entries []protocols.S7SZLEntry) []PLCBlock {
	var blocks []PLCBlock

	blockTypes := map[byte]string{
		0x08: "OB",
		0x0A: "DB",
		0x0B: "SDB",
		0x0C: "FC",
		0x0D: "SFC",
		0x0E: "FB",
		0x0F: "SFB",
	}

	for _, entry := range entries {
		if len(entry.Raw) >= 4 {
			blockType := entry.Raw[0]
			if typeName, ok := blockTypes[blockType]; ok {
				count := int(entry.Raw[2])<<8 | int(entry.Raw[3])
				for j := 0; j < count; j++ {
					blocks = append(blocks, PLCBlock{
						Number: j,
						Type:   typeName,
					})
				}
			}
		}
	}

	return blocks
}

// assessS7Security checks for PLC security issues.
func (plr *PLCLogicReader) assessS7Security(info *PLCLogicInfo) []PLCFinding {
	var findings []PLCFinding

	// Check if CPU protection is enabled
	if info.CPUInfo != nil && info.CPUInfo.Protection == "" {
		findings = append(findings, PLCFinding{
			Title:       "No CPU Access Protection",
			Description: "S7 CPU has no access protection level configured",
			Severity:    "high",
			Remediation: "Configure access protection levels in TIA Portal (read/write/full protection)",
		})
	}

	// Check for large number of data blocks (potential info exposure)
	dbCount := 0
	for _, block := range info.Blocks {
		if block.Type == "DB" {
			dbCount++
		}
	}
	if dbCount > 100 {
		findings = append(findings, PLCFinding{
			Title:       "Large Number of Data Blocks",
			Description: fmt.Sprintf("PLC contains %d data blocks which may expose process data", dbCount),
			Severity:    "info",
			Remediation: "Review data block access permissions and enable know-how protection",
		})
	}

	return findings
}

// ReadModbusRegisters reads Modbus register metadata - READ ONLY.
func (plr *PLCLogicReader) ReadModbusRegisters(ctx context.Context, target string, port int, unitID byte) (*PLCLogicInfo, error) {
	if err := plr.module.PreFlightCheck(target, "modbus"); err != nil {
		return nil, err
	}

	if err := plr.module.AcquireConnection(target); err != nil {
		return nil, err
	}
	defer plr.module.ReleaseConnection(target)

	config := protocols.ConnConfig{
		Timeout:         plr.module.QueryTimeout(),
		InterPacketDelay: plr.module.InterPacketDelay(),
	}

	client := protocols.NewModbusClient(config)
	if err := client.Connect(ctx, target, port); err != nil {
		return nil, fmt.Errorf("Modbus connect failed: %w", err)
	}
	defer client.Close()

	info := &PLCLogicInfo{
		Target:   target,
		Protocol: "modbus",
	}

	// Read device identification (FC 43/14)
	devInfo, err := client.ReadDeviceIdentification(0x01, 0x00)
	if err == nil {
		info.CPUInfo = &PLCCPUInfo{
			Vendor: devInfo.VendorName,
			Model:  devInfo.ProductName,
		}
	}

	// Map register ranges (read-only probing)
	var tags []PLCTag

	// Probe holding registers in blocks to find populated ranges
	for startReg := uint16(0); startReg < 1000; startReg += 100 {
		regs, err := client.ReadHoldingRegisters(unitID, startReg, 1)
		if err == nil && regs != nil && len(regs.RawValues) > 0 {
			tags = append(tags, PLCTag{
				Name:     fmt.Sprintf("HR%d", startReg),
				Address:  fmt.Sprintf("4%05d", startReg),
				DataType: "uint16",
				Scope:    "global",
				ReadOnly: false,
			})
		}

		time.Sleep(plr.module.InterPacketDelay())
	}

	info.Tags = tags
	return info, nil
}

// ReadEtherNetIPTags reads EtherNet/IP CIP tag list - READ ONLY.
func (plr *PLCLogicReader) ReadEtherNetIPTags(ctx context.Context, target string, port int) (*PLCLogicInfo, error) {
	if err := plr.module.PreFlightCheck(target, "ethernetip"); err != nil {
		return nil, err
	}

	if err := plr.module.AcquireConnection(target); err != nil {
		return nil, err
	}
	defer plr.module.ReleaseConnection(target)

	config := protocols.ConnConfig{
		Timeout:         plr.module.QueryTimeout(),
		InterPacketDelay: plr.module.InterPacketDelay(),
	}

	client := protocols.NewEtherNetIPClient(config)
	if err := client.Connect(ctx, target, port); err != nil {
		return nil, fmt.Errorf("EtherNet/IP connect failed: %w", err)
	}
	defer client.Close()

	info := &PLCLogicInfo{
		Target:   target,
		Protocol: "ethernetip",
	}

	// Get identity
	identity, err := client.ListIdentity()
	if err == nil {
		info.CPUInfo = &PLCCPUInfo{
			Vendor: identity.VendorName,
			Model:  identity.ProductName,
		}
	}

	return info, nil
}
