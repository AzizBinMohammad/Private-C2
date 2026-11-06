package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/azizbinmohammad/private-c2/implant/modules/ot"
)

func otPreflight(target, protocolName string) (func(), error) {
	if agentOT == nil {
		return nil, fmt.Errorf("OT assessment requires an engagement scope (configure --scope-cidrs/--scope-hosts)")
	}
	if err := agentOT.PreFlightCheck(target, protocolName); err != nil {
		return nil, err
	}
	if err := agentOT.AcquireConnection(target); err != nil {
		return nil, err
	}
	return func() { agentOT.ReleaseConnection(target) }, nil
}

func marshalOT(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseTargets accepts a JSON {"targets":[...]} object, a JSON array, or a
// comma/space separated string.
func parseTargets(args string) []string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	var obj struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal([]byte(args), &obj); err == nil && len(obj.Targets) > 0 {
		return obj.Targets
	}
	var list []string
	if err := json.Unmarshal([]byte(args), &list); err == nil && len(list) > 0 {
		return list
	}
	parts := strings.FieldsFunc(args, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func handleOTDiscover(ctx context.Context, args string) (string, error) {
	if agentOT == nil {
		return "", fmt.Errorf("OT assessment requires an engagement scope")
	}
	var req struct {
		Targets []string `json:"targets"`
		Passive bool     `json:"passive"`
		Iface   string   `json:"iface"`
	}
	_ = json.Unmarshal([]byte(args), &req)
	if len(req.Targets) == 0 {
		req.Targets = parseTargets(args)
	}

	cfg := ot.DefaultDiscoveryConfig()
	cfg.Passive = req.Passive
	cfg.Active = !req.Passive
	discovery := ot.NewDiscovery(agentOT, cfg)

	if req.Passive {
		assets, err := discovery.PassiveDiscover(ctx, req.Iface)
		if err != nil {
			return "", err
		}
		return marshalOT(assets)
	}
	if len(req.Targets) == 0 {
		return "", fmt.Errorf("ot_discover requires targets")
	}
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for _, target := range req.Targets {
		release, err := otPreflight(target, "discovery")
		if err != nil {
			return "", err
		}
		releases = append(releases, release)
	}
	assets, err := discovery.ActiveDiscover(ctx, req.Targets)
	if err != nil {
		return "", err
	}
	return marshalOT(assets)
}

func handleOTFingerprint(ctx context.Context, args string) (string, error) {
	target := strings.TrimSpace(args)
	if target == "" {
		return "", fmt.Errorf("ot_fingerprint requires a target")
	}
	release, err := otPreflight(target, "fingerprint")
	if err != nil {
		return "", err
	}
	defer release()
	result, err := ot.NewFingerprinter(agentOT).Fingerprint(ctx, target)
	if err != nil {
		return "", err
	}
	return marshalOT(result)
}

func handleOTVulnScan(ctx context.Context, args string) (string, error) {
	target := strings.TrimSpace(args)
	if target == "" {
		return "", fmt.Errorf("ot_vuln_scan requires a target")
	}
	release, err := otPreflight(target, "vuln-scan")
	if err != nil {
		return "", err
	}
	defer release()
	return marshalOT(ot.NewVulnScanner(agentOT).ScanAsset(ot.OTAsset{IP: target}))
}

func handleOTHMI(ctx context.Context, args string) (string, error) {
	target := strings.TrimSpace(args)
	if target == "" {
		return "", fmt.Errorf("ot_hmi requires a target")
	}
	release, err := otPreflight(target, "hmi")
	if err != nil {
		return "", err
	}
	defer release()
	result, err := ot.NewHMIAssessor(agentOT).Assess(ctx, target)
	if err != nil {
		return "", err
	}
	return marshalOT(result)
}

func otAssets(targets []string) []ot.OTAsset {
	assets := make([]ot.OTAsset, 0, len(targets))
	for _, target := range targets {
		assets = append(assets, ot.OTAsset{IP: target})
	}
	return assets
}

func handleOTHistorian(ctx context.Context, args string) (string, error) {
	targets := parseTargets(args)
	if len(targets) == 0 {
		return "", fmt.Errorf("ot_historian requires targets")
	}
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for _, target := range targets {
		release, err := otPreflight(target, "historian")
		if err != nil {
			return "", err
		}
		releases = append(releases, release)
	}
	result, err := ot.NewHistorianDetector(agentOT).Assess(ctx, otAssets(targets))
	if err != nil {
		return "", err
	}
	return marshalOT(result)
}

func handleOTWireless(ctx context.Context, args string) (string, error) {
	targets := parseTargets(args)
	if len(targets) == 0 {
		return "", fmt.Errorf("ot_wireless requires targets")
	}
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for _, target := range targets {
		release, err := otPreflight(target, "wireless")
		if err != nil {
			return "", err
		}
		releases = append(releases, release)
	}
	result, err := ot.NewWirelessScanner(agentOT).Assess(ctx, otAssets(targets))
	if err != nil {
		return "", err
	}
	return marshalOT(result)
}

func handleOTSerial(ctx context.Context, args string) (string, error) {
	targets := parseTargets(args)
	if len(targets) == 0 {
		return "", fmt.Errorf("ot_serial requires targets")
	}
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for _, target := range targets {
		release, err := otPreflight(target, "serial")
		if err != nil {
			return "", err
		}
		releases = append(releases, release)
	}
	result, err := ot.NewSerialScanner(agentOT).Enumerate(ctx, otAssets(targets))
	if err != nil {
		return "", err
	}
	return marshalOT(result)
}

func handleOTPLCRead(ctx context.Context, args string) (string, error) {
	var req struct {
		Target   string `json:"target"`
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		UnitID   int    `json:"unit_id"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		req.Target = strings.TrimSpace(args)
	}
	if req.Target == "" {
		return "", fmt.Errorf("ot_plc_read requires a target")
	}
	if req.Protocol == "" {
		req.Protocol = "s7"
	}
	release, err := otPreflight(req.Target, "plc-read")
	if err != nil {
		return "", err
	}
	defer release()

	reader := ot.NewPLCLogicReader(agentOT)
	var result *ot.PLCLogicInfo
	switch strings.ToLower(req.Protocol) {
	case "s7", "s7comm":
		if req.Port == 0 {
			req.Port = 102
		}
		result, err = reader.ReadS7Metadata(ctx, req.Target, req.Port)
	case "modbus":
		if req.Port == 0 {
			req.Port = 502
		}
		result, err = reader.ReadModbusRegisters(ctx, req.Target, req.Port, byte(req.UnitID))
	case "ethernetip", "enip":
		if req.Port == 0 {
			req.Port = 44818
		}
		result, err = reader.ReadEtherNetIPTags(ctx, req.Target, req.Port)
	default:
		return "", fmt.Errorf("unsupported PLC protocol %q", req.Protocol)
	}
	if err != nil {
		return "", err
	}
	return marshalOT(result)
}

func handleOTCredentials(ctx context.Context, args string) (string, error) {
	var req struct {
		Target   string   `json:"target"`
		Vendor   string   `json:"vendor"`
		Services []string `json:"services"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		req.Target = strings.TrimSpace(args)
	}
	if req.Target == "" {
		return "", fmt.Errorf("ot_credentials requires a target")
	}
	release, err := otPreflight(req.Target, "credential-check")
	if err != nil {
		return "", err
	}
	defer release()
	result, err := ot.NewCredentialChecker(agentOT).CheckDefaults(ctx, req.Target, req.Vendor, req.Services)
	if err != nil {
		return "", err
	}
	return marshalOT(result)
}
