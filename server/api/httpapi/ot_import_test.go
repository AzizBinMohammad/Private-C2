package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/azizbinmohammad/private-c2/server/store/models"
)

func otPost(t *testing.T, router http.Handler, token, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return lootRequest(t, router, http.MethodPost, path, token, body)
}

func TestOTImportAndReport(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	engagement := &models.Engagement{Name: "ot-eng", Status: "active", AuthorizationRef: "auth-ot"}
	if err := db.Create(engagement).Error; err != nil {
		t.Fatal(err)
	}

	assetItems := []map[string]any{{
		"ip": "10.10.0.5", "vendor": "Siemens", "model": "S7-1200",
		"role": "PLC", "purdue_level": 1, "protocols": []string{"s7"},
		"open_ports": []int{102}, "confidence": 0.9,
	}}
	importBody := map[string]any{
		"engagement_id": engagement.ID, "type": "asset", "items": assetItems,
	}
	denied := otPost(t, router, token, "/api/ot/import", importBody)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("import without OT gate = %d %s", denied.Code, denied.Body.String())
	}

	if err := db.Model(engagement).Update("allow_ot_assessment", true).Error; err != nil {
		t.Fatal(err)
	}
	created := otPost(t, router, token, "/api/ot/import", importBody)
	if created.Code != http.StatusOK {
		t.Fatalf("asset import = %d %s", created.Code, created.Body.String())
	}
	var importResult struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &importResult); err != nil {
		t.Fatal(err)
	}
	if importResult.Created != 1 {
		t.Fatalf("asset import result = %+v", importResult)
	}

	// Re-importing the same IP merges rather than duplicating, and preserves
	// fields the new observation does not carry.
	updateBody := map[string]any{
		"engagement_id": engagement.ID, "type": "asset",
		"items": []map[string]any{{"ip": "10.10.0.5", "hostname": "plc-1"}},
	}
	updated := otPost(t, router, token, "/api/ot/import", updateBody)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"updated":1`) {
		t.Fatalf("asset merge = %d %s", updated.Code, updated.Body.String())
	}
	var stored models.OTAssetRecord
	if err := db.Where("engagement_id = ? AND ip = ?", engagement.ID, "10.10.0.5").First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Hostname != "plc-1" || stored.Vendor != "Siemens" || stored.Protocols == "" {
		t.Fatalf("asset merge lost data: %+v", stored)
	}

	vulnBody := map[string]any{
		"engagement_id": engagement.ID, "type": "vuln",
		"items": map[string]any{
			"target": "10.10.0.5",
			"vulnerabilities": []map[string]any{{
				"cve_id": "CVE-2020-0001", "description": "test vuln",
				"cvss": 9.8, "severity": "critical",
			}},
			"insecure_protocols": []map[string]any{{
				"protocol": "http", "port": 80, "issue": "cleartext", "severity": "high",
			}},
		},
	}
	if w := otPost(t, router, token, "/api/ot/import", vulnBody); w.Code != http.StatusOK {
		t.Fatalf("vuln import = %d %s", w.Code, w.Body.String())
	}

	credBody := map[string]any{
		"engagement_id": engagement.ID, "type": "credential",
		"items": map[string]any{
			"target": "10.10.0.5", "service": "http", "port": 80,
			"findings": []map[string]any{{
				"username": "admin", "is_default": true, "protocol": "http",
				"severity": "critical", "description": "default admin",
			}},
		},
	}
	if w := otPost(t, router, token, "/api/ot/import", credBody); w.Code != http.StatusOK {
		t.Fatalf("credential import = %d %s", w.Code, w.Body.String())
	}

	complianceBody := map[string]any{
		"engagement_id": engagement.ID, "type": "compliance",
		"items": map[string]any{"findings": []map[string]any{
			{"framework": "IEC 62443", "requirement": "R1", "status": "pass", "severity": "info"},
			{"framework": "IEC 62443", "requirement": "R2", "status": "fail", "severity": "high"},
		}},
	}
	if w := otPost(t, router, token, "/api/ot/import", complianceBody); w.Code != http.StatusOK {
		t.Fatalf("compliance import = %d %s", w.Code, w.Body.String())
	}

	report := otPost(t, router, token, "/api/ot/reports", map[string]any{
		"engagement_id": engagement.ID, "title": "Test Report", "format": "markdown",
	})
	if report.Code != http.StatusCreated {
		t.Fatalf("report = %d %s", report.Code, report.Body.String())
	}
	var record models.OTAssessmentReport
	if err := json.Unmarshal(report.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.AssetCount != 1 || record.VulnCount != 2 {
		t.Fatalf("report counts = assets %d vulns %d", record.AssetCount, record.VulnCount)
	}
	if record.RiskScore < 9 {
		t.Fatalf("risk score = %f", record.RiskScore)
	}
	if record.ComplianceRate != 50 {
		t.Fatalf("compliance rate = %f", record.ComplianceRate)
	}
	for _, want := range []string{"# Test Report", "## Assets", "## Vulnerabilities", "## Credential findings", "## Compliance"} {
		if !strings.Contains(record.ReportData, want) {
			t.Errorf("report missing %q", want)
		}
	}

	// A JSON report is also supported and every imported finding is included.
	jsonReport := otPost(t, router, token, "/api/ot/reports", map[string]any{
		"engagement_id": engagement.ID, "format": "json",
	})
	if jsonReport.Code != http.StatusCreated {
		t.Fatalf("json report = %d %s", jsonReport.Code, jsonReport.Body.String())
	}
	var jsonRecord models.OTAssessmentReport
	if err := json.Unmarshal(jsonReport.Body.Bytes(), &jsonRecord); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonRecord.ReportData, `"credentials"`) || !strings.Contains(jsonRecord.ReportData, "CVE-2020-0001") {
		t.Fatalf("json report data missing findings")
	}

	list := lootRequest(t, router, http.MethodGet, "/api/ot/reports", token, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), record.ID) {
		t.Fatalf("report list = %d %s", list.Code, list.Body.String())
	}
}

func TestOTImportFromTaskResult(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	engagement := &models.Engagement{
		Name: "ot-task-eng", Status: "active", AuthorizationRef: "auth-ot",
		AllowOTAssessment: true,
	}
	if err := db.Create(engagement).Error; err != nil {
		t.Fatal(err)
	}
	result := &models.TaskResult{
		TaskID: "ot-task-1", SessionID: "session-ot", EngagementID: engagement.ID,
		Success: true,
		Output:  `[{"ip":"10.10.0.6","vendor":"Schneider","role":"RTU","protocols":["modbus"]}]`,
	}
	if err := db.Create(result).Error; err != nil {
		t.Fatal(err)
	}

	w := otPost(t, router, token, "/api/ot/import", map[string]any{
		"type": "asset", "task_id": "ot-task-1",
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"created":1`) {
		t.Fatalf("task import = %d %s", w.Code, w.Body.String())
	}
	var asset models.OTAssetRecord
	if err := db.Where("engagement_id = ? AND ip = ?", engagement.ID, "10.10.0.6").First(&asset).Error; err != nil {
		t.Fatal(err)
	}
	if asset.Vendor != "Schneider" || asset.EngagementID != engagement.ID {
		t.Fatalf("task asset = %+v", asset)
	}
}
