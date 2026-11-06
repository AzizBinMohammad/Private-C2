package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/store/models"
)

// otImportRequest accepts either explicit items or a completed OT task whose
// output is parsed according to Type. The engagement is resolved from the task
// when it is not supplied.
type otImportRequest struct {
	EngagementID string          `json:"engagement_id"`
	SessionID    string          `json:"session_id"`
	TaskID       string          `json:"task_id"`
	Type         string          `json:"type"`
	Items        json.RawMessage `json:"items,omitempty"`
}

type otImportResult struct {
	Type       string `json:"type"`
	Created    int    `json:"created"`
	Updated    int    `json:"updated"`
	Skipped    int    `json:"skipped"`
	Engagement string `json:"engagement_id"`
}

func (oth *otHandler) handleOTImport(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}
	if oth.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "database unavailable"})
		return
	}

	var req otImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "type is required"})
		return
	}

	raw := req.Items
	if len(raw) == 0 {
		if req.TaskID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "provide items or a task_id"})
			return
		}
		var row models.TaskResult
		res := oth.db.Where("task_id = ?", req.TaskID).Limit(1).Find(&row)
		if res.Error != nil || res.RowsAffected == 0 {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "task result not found"})
			return
		}
		if !row.Success {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "task did not succeed"})
			return
		}
		raw = json.RawMessage(row.Output)
		if req.EngagementID == "" {
			req.EngagementID = row.EngagementID
		}
		if req.SessionID == "" {
			req.SessionID = row.SessionID
		}
	}

	if req.EngagementID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "engagement_id is required"})
		return
	}
	var engagement models.Engagement
	if err := oth.db.First(&engagement, "id = ?", req.EngagementID).Error; err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
		return
	}
	if !engagement.AllowOTAssessment {
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "OT assessment is not enabled for this engagement"})
		return
	}

	result, err := oth.importOT(req.EngagementID, req.Type, raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	result.Engagement = req.EngagementID

	if oth.auditor != nil {
		identity, _ := authz.FromContext(r.Context())
		operator := identity.OperatorID
		if operator == "" {
			operator = identity.Username
		}
		_ = oth.auditor.Log(operator, req.EngagementID, req.SessionID, audit.EventOTImport,
			"ot.import", req.Type, fmt.Sprintf("created=%d updated=%d", result.Created, result.Updated),
			map[string]any{"task_id": req.TaskID}, r.RemoteAddr, "")
	}
	writeJSON(w, http.StatusOK, result)
}

func (oth *otHandler) importOT(engagementID, kind string, raw json.RawMessage) (otImportResult, error) {
	switch kind {
	case "asset":
		return oth.importAssets(engagementID, raw)
	case "fingerprint":
		return oth.importFingerprint(engagementID, raw)
	case "vuln":
		return oth.importVulns(engagementID, raw)
	case "credential":
		return oth.importCredentials(engagementID, raw)
	case "hmi":
		return oth.importHMI(engagementID, raw)
	case "wireless":
		return oth.importWireless(engagementID, raw)
	case "compliance":
		return oth.importCompliance(engagementID, raw)
	case "topology":
		return oth.importTopology(engagementID, raw)
	case "segmentation":
		return oth.importSegmentation(engagementID, raw)
	default:
		return otImportResult{}, fmt.Errorf("unsupported OT import type %q", kind)
	}
}

// ---- shared mapping ----

type otAssetInput struct {
	IP              string            `json:"ip"`
	MAC             string            `json:"mac"`
	Hostname        string            `json:"hostname"`
	Vendor          string            `json:"vendor"`
	Model           string            `json:"model"`
	Firmware        string            `json:"firmware"`
	SerialNumber    string            `json:"serial_number"`
	Role            string            `json:"role"`
	Protocol        string            `json:"protocol"`
	Protocols       []string          `json:"protocols"`
	PurdueLevel     int               `json:"purdue_level"`
	SILLevel        int               `json:"sil_level"`
	SafetyRated     bool              `json:"safety_rated"`
	Description     string            `json:"description"`
	OpenPorts       []int             `json:"open_ports"`
	Services        []string          `json:"services"`
	Banners         map[string]string `json:"banners"`
	DiscoveryMethod string            `json:"discovery_method"`
	Confidence      float64           `json:"confidence"`
	Tags            []string          `json:"tags"`
	RawData         map[string]any    `json:"raw_data"`
	FirstSeen       time.Time         `json:"first_seen"`
	LastSeen        time.Time         `json:"last_seen"`
}

func jsonText(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(data)
	if s == "null" || s == "[]" || s == "{}" {
		return ""
	}
	return s
}

func (oth *otHandler) upsertAsset(engagementID string, in otAssetInput) (bool, error) {
	if strings.TrimSpace(in.IP) == "" {
		return false, nil
	}
	now := time.Now()
	if in.FirstSeen.IsZero() {
		in.FirstSeen = now
	}
	if in.LastSeen.IsZero() {
		in.LastSeen = now
	}

	var existing models.OTAssetRecord
	res := oth.db.Where("engagement_id = ? AND ip = ?", engagementID, in.IP).Limit(1).Find(&existing)
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 1 {
		// Merge only fields the new observation actually carries, so a
		// topology import cannot erase fingerprint data (and vice versa).
		updates := map[string]any{}
		setStr := func(key, value string) {
			if value != "" {
				updates[key] = value
			}
		}
		setStr("mac", in.MAC)
		setStr("hostname", in.Hostname)
		setStr("vendor", in.Vendor)
		setStr("model", in.Model)
		setStr("firmware", in.Firmware)
		setStr("serial_number", in.SerialNumber)
		setStr("role", in.Role)
		setStr("protocol", in.Protocol)
		setStr("description", in.Description)
		setStr("discovery_method", in.DiscoveryMethod)
		if in.PurdueLevel != 0 {
			updates["purdue_level"] = in.PurdueLevel
		}
		if in.SILLevel != 0 {
			updates["sil_level"] = in.SILLevel
		}
		if in.SafetyRated {
			updates["safety_rated"] = true
		}
		if in.Confidence != 0 {
			updates["confidence"] = in.Confidence
		}
		if v := jsonText(in.Protocols); v != "" {
			updates["protocols"] = v
		}
		if v := jsonText(in.OpenPorts); v != "" {
			updates["open_ports"] = v
		}
		if v := jsonText(in.Services); v != "" {
			updates["services"] = v
		}
		if v := jsonText(in.Banners); v != "" {
			updates["banners"] = v
		}
		if v := jsonText(in.Tags); v != "" {
			updates["tags"] = v
		}
		if v := jsonText(in.RawData); v != "" {
			updates["raw_data"] = v
		}
		if !in.LastSeen.IsZero() {
			updates["last_seen"] = in.LastSeen
		}
		if len(updates) > 0 {
			if err := oth.db.Model(&models.OTAssetRecord{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
				return false, err
			}
		}
		return false, nil
	}
	record := &models.OTAssetRecord{
		EngagementID:    engagementID,
		IP:              in.IP,
		MAC:             in.MAC,
		Hostname:        in.Hostname,
		Vendor:          in.Vendor,
		Model:           in.Model,
		Firmware:        in.Firmware,
		SerialNumber:    in.SerialNumber,
		Role:            in.Role,
		PurdueLevel:     in.PurdueLevel,
		Protocol:        in.Protocol,
		Protocols:       jsonText(in.Protocols),
		SafetyRated:     in.SafetyRated,
		SILLevel:        in.SILLevel,
		Description:     in.Description,
		OpenPorts:       jsonText(in.OpenPorts),
		Services:        jsonText(in.Services),
		Banners:         jsonText(in.Banners),
		DiscoveryMethod: in.DiscoveryMethod,
		Confidence:      in.Confidence,
		Tags:            jsonText(in.Tags),
		RawData:         jsonText(in.RawData),
		FirstSeen:       in.FirstSeen,
		LastSeen:        in.LastSeen,
	}
	if err := oth.db.Create(record).Error; err != nil {
		return false, err
	}
	return true, nil
}

func decodeOTArray(raw json.RawMessage, key string, out any) error {
	if err := json.Unmarshal(raw, out); err == nil {
		return nil
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return err
	}
	inner, ok := wrapper[key]
	if !ok {
		return fmt.Errorf("expected a JSON array or an object with %q", key)
	}
	return json.Unmarshal(inner, out)
}

// ---- type importers ----

func (oth *otHandler) importAssets(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var items []otAssetInput
	if err := decodeOTArray(raw, "assets", &items); err != nil {
		return otImportResult{}, err
	}
	result := otImportResult{Type: "asset"}
	for _, item := range items {
		created, err := oth.upsertAsset(engagementID, item)
		if err != nil {
			return otImportResult{}, err
		}
		if created {
			result.Created++
		} else if item.IP != "" {
			result.Updated++
		} else {
			result.Skipped++
		}
	}
	return result, nil
}

type otFingerprintInput struct {
	IP         string   `json:"ip"`
	Vendor     string   `json:"vendor"`
	Model      string   `json:"model"`
	Firmware   string   `json:"firmware"`
	DeviceType string   `json:"device_type"`
	Confidence float64  `json:"confidence"`
	Tags       []string `json:"tags"`
	CVEs       []struct {
		CVEID       string  `json:"cve_id"`
		Description string  `json:"description"`
		CVSS        float64 `json:"cvss"`
		Severity    string  `json:"severity"`
	} `json:"cves"`
}

func (oth *otHandler) importFingerprint(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var in otFingerprintInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return otImportResult{}, err
	}
	if in.IP == "" {
		return otImportResult{}, fmt.Errorf("fingerprint result has no ip")
	}
	created, err := oth.upsertAsset(engagementID, otAssetInput{
		IP:         in.IP,
		Vendor:     in.Vendor,
		Model:      in.Model,
		Firmware:   in.Firmware,
		Role:       in.DeviceType,
		Confidence: in.Confidence,
		Tags:       in.Tags,
	})
	if err != nil {
		return otImportResult{}, err
	}
	result := otImportResult{Type: "fingerprint"}
	if created {
		result.Created++
	} else {
		result.Updated++
	}
	for _, cve := range in.CVEs {
		record := models.OTVulnFinding{
			EngagementID:   engagementID,
			Target:         in.IP,
			CVEID:          cve.CVEID,
			Description:    cve.Description,
			CVSS:           cve.CVSS,
			Severity:       cve.Severity,
			VendorAdvisory: "fingerprint correlation",
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	return result, nil
}

type otVulnScanInput struct {
	Target          string `json:"target"`
	Vulnerabilities []struct {
		CVEID           string   `json:"cve_id"`
		Description     string   `json:"description"`
		CVSS            float64  `json:"cvss"`
		Severity        string   `json:"severity"`
		AffectedVer     string   `json:"affected_versions"`
		FixedVer        string   `json:"fixed_version"`
		VendorAdvisory  string   `json:"vendor_advisory"`
		ICSCERTAdvisory string   `json:"icscert_advisory"`
		AttackVector    string   `json:"attack_vector"`
		Mitigations     []string `json:"mitigations"`
	} `json:"vulnerabilities"`
	InsecureProtos []struct {
		Protocol    string `json:"protocol"`
		Port        int    `json:"port"`
		Issue       string `json:"issue"`
		Severity    string `json:"severity"`
		Remediation string `json:"remediation"`
	} `json:"insecure_protocols"`
}

func (oth *otHandler) importVulns(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var in otVulnScanInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return otImportResult{}, err
	}
	result := otImportResult{Type: "vuln"}
	for _, v := range in.Vulnerabilities {
		record := models.OTVulnFinding{
			EngagementID:    engagementID,
			Target:          in.Target,
			CVEID:           v.CVEID,
			Description:     v.Description,
			CVSS:            v.CVSS,
			Severity:        v.Severity,
			AffectedVersion: v.AffectedVer,
			FixedVersion:    v.FixedVer,
			VendorAdvisory:  v.VendorAdvisory,
			ICSCERTAdvisory: v.ICSCERTAdvisory,
			AttackVector:    v.AttackVector,
			Mitigations:     jsonText(v.Mitigations),
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	for _, p := range in.InsecureProtos {
		record := models.OTVulnFinding{
			EngagementID: engagementID,
			Target:       in.Target,
			Description:  fmt.Sprintf("insecure protocol %s on port %d: %s", p.Protocol, p.Port, p.Issue),
			Severity:     p.Severity,
			Mitigations:  jsonText([]string{p.Remediation}),
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	return result, nil
}

type otCredentialInput struct {
	Target   string    `json:"target"`
	Service  string    `json:"service"`
	Port     int       `json:"port"`
	TestedAt time.Time `json:"tested_at"`
	Findings []struct {
		Username    string `json:"username"`
		IsDefault   bool   `json:"is_default"`
		Protocol    string `json:"protocol"`
		Service     string `json:"service"`
		Severity    string `json:"severity"`
		Vendor      string `json:"vendor"`
		Description string `json:"description"`
	} `json:"findings"`
}

func (oth *otHandler) importCredentials(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var in otCredentialInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return otImportResult{}, err
	}
	testedAt := in.TestedAt
	if testedAt.IsZero() {
		testedAt = time.Now()
	}
	result := otImportResult{Type: "credential"}
	for _, f := range in.Findings {
		service := f.Service
		if service == "" {
			service = in.Service
		}
		record := models.OTCredentialFinding{
			EngagementID: engagementID,
			Target:       in.Target,
			Service:      service,
			Port:         in.Port,
			Username:     f.Username,
			IsDefault:    f.IsDefault,
			Vendor:       f.Vendor,
			Protocol:     f.Protocol,
			Severity:     f.Severity,
			Description:  f.Description,
			TestedAt:     testedAt,
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	return result, nil
}

type otHMIInput struct {
	Target   string `json:"target"`
	Findings []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Category    string `json:"category"`
		Remediation string `json:"remediation"`
		URL         string `json:"url"`
	} `json:"findings"`
}

func (oth *otHandler) importHMI(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var in otHMIInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return otImportResult{}, err
	}
	result := otImportResult{Type: "hmi"}
	for _, f := range in.Findings {
		record := models.OTHMIFinding{
			EngagementID: engagementID,
			Target:       in.Target,
			URL:          f.URL,
			Title:        f.Title,
			Description:  f.Description,
			Severity:     f.Severity,
			Category:     f.Category,
			Remediation:  f.Remediation,
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	return result, nil
}

type otWirelessInput struct {
	Findings []struct {
		Protocol    string `json:"protocol"`
		Evidence    string `json:"evidence"`
		Gateway     string `json:"gateway"`
		Severity    string `json:"severity"`
		Risk        string `json:"risk"`
		Remediation string `json:"remediation"`
	} `json:"findings"`
}

func (oth *otHandler) importWireless(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var in otWirelessInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return otImportResult{}, err
	}
	result := otImportResult{Type: "wireless"}
	for _, f := range in.Findings {
		record := models.OTWirelessFinding{
			EngagementID: engagementID,
			Protocol:     f.Protocol,
			Evidence:     f.Evidence,
			Gateway:      f.Gateway,
			Severity:     f.Severity,
			Risk:         f.Risk,
			Remediation:  f.Remediation,
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	return result, nil
}

type otComplianceInput struct {
	Findings []struct {
		Framework   string `json:"framework"`
		Requirement string `json:"requirement"`
		Section     string `json:"section"`
		Description string `json:"description"`
		Status      string `json:"status"`
		Severity    string `json:"severity"`
		Evidence    string `json:"evidence"`
		Remediation string `json:"remediation"`
	} `json:"findings"`
}

func (oth *otHandler) importCompliance(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var in otComplianceInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return otImportResult{}, err
	}
	result := otImportResult{Type: "compliance"}
	for _, f := range in.Findings {
		record := models.OTComplianceFinding{
			EngagementID: engagementID,
			Framework:    f.Framework,
			Requirement:  f.Requirement,
			Section:      f.Section,
			Description:  f.Description,
			Status:       f.Status,
			Severity:     f.Severity,
			Evidence:     f.Evidence,
			Remediation:  f.Remediation,
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	return result, nil
}

type otTopologyInput struct {
	Nodes []struct {
		ID          string   `json:"id"`
		IP          string   `json:"ip"`
		Hostname    string   `json:"hostname"`
		Vendor      string   `json:"vendor"`
		Model       string   `json:"model"`
		DeviceType  string   `json:"device_type"`
		PurdueLevel int      `json:"purdue_level"`
		Protocols   []string `json:"protocols"`
	} `json:"nodes"`
	Edges []struct {
		SourceID      string `json:"source_id"`
		TargetID      string `json:"target_id"`
		Protocol      string `json:"protocol"`
		Port          int    `json:"port"`
		Encrypted     bool   `json:"encrypted"`
		Bidirectional bool   `json:"bidirectional"`
	} `json:"edges"`
	SegmentationGaps []struct {
		Description string `json:"description"`
		FromZone    string `json:"from_zone"`
		ToZone      string `json:"to_zone"`
		FromLevel   int    `json:"from_level"`
		ToLevel     int    `json:"to_level"`
		Protocol    string `json:"protocol"`
		Severity    string `json:"severity"`
	} `json:"segmentation_gaps"`
}

func (oth *otHandler) importTopology(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var in otTopologyInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return otImportResult{}, err
	}
	result := otImportResult{Type: "topology"}
	for _, n := range in.Nodes {
		created, err := oth.upsertAsset(engagementID, otAssetInput{
			IP:          n.IP,
			Hostname:    n.Hostname,
			Vendor:      n.Vendor,
			Model:       n.Model,
			Role:        n.DeviceType,
			PurdueLevel: n.PurdueLevel,
			Protocols:   n.Protocols,
		})
		if err != nil {
			return otImportResult{}, err
		}
		if created {
			result.Created++
		} else {
			result.Updated++
		}
	}
	for _, e := range in.Edges {
		record := models.OTTopologyEdge{
			EngagementID:  engagementID,
			SourceIP:      e.SourceID,
			TargetIP:      e.TargetID,
			Protocol:      e.Protocol,
			Port:          e.Port,
			Encrypted:     e.Encrypted,
			Bidirectional: e.Bidirectional,
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return otImportResult{}, err
		}
		result.Created++
	}
	gaps := make([]otSegmentationGapInput, 0, len(in.SegmentationGaps))
	for _, g := range in.SegmentationGaps {
		gaps = append(gaps, otSegmentationGapInput{
			Description: g.Description,
			FromZone:    g.FromZone,
			ToZone:      g.ToZone,
			FromLevel:   g.FromLevel,
			ToLevel:     g.ToLevel,
			Protocol:    g.Protocol,
			Severity:    g.Severity,
		})
	}
	created, err := oth.importSegmentationItems(engagementID, gaps)
	if err != nil {
		return otImportResult{}, err
	}
	result.Created += created
	return result, nil
}

type otSegmentationGapInput struct {
	Description string `json:"description"`
	FromZone    string `json:"from_zone"`
	ToZone      string `json:"to_zone"`
	FromLevel   int    `json:"from_level"`
	ToLevel     int    `json:"to_level"`
	Protocol    string `json:"protocol"`
	Severity    string `json:"severity"`
}

func (oth *otHandler) importSegmentation(engagementID string, raw json.RawMessage) (otImportResult, error) {
	var gaps []otSegmentationGapInput
	if err := decodeOTArray(raw, "segmentation_gaps", &gaps); err != nil {
		return otImportResult{}, err
	}
	created, err := oth.importSegmentationItems(engagementID, gaps)
	if err != nil {
		return otImportResult{}, err
	}
	return otImportResult{Type: "segmentation", Created: created}, nil
}

func (oth *otHandler) importSegmentationItems(engagementID string, gaps []otSegmentationGapInput) (int, error) {
	created := 0
	for _, g := range gaps {
		record := models.OTSegmentationGap{
			EngagementID: engagementID,
			Description:  g.Description,
			FromZone:     g.FromZone,
			ToZone:       g.ToZone,
			FromLevel:    g.FromLevel,
			ToLevel:      g.ToLevel,
			Protocol:     g.Protocol,
			Severity:     g.Severity,
		}
		if err := oth.db.Create(&record).Error; err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}
