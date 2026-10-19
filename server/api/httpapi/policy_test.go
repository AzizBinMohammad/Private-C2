package httpapi

import (
	"errors"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
)

func TestAuthorizeTask_EngagementPolicy(t *testing.T) {
	_, _, db := setupTestRouter(t)
	sh := &sessionHandler{db: db}

	start := time.Now().Add(-time.Hour)
	end := time.Now().Add(time.Hour)
	eng := &models.Engagement{
		Name:                 "policy engagement",
		Status:               "active",
		ScopeConfig:          `{"cidrs":["10.0.0.0/8"],"hostnames":["target.example"],"domains":["example.com"]}`,
		AuthorizedTechniques: `["portscan","shell","resolve"]`,
		TimeWindowStart:      &start,
		TimeWindowEnd:        &end,
	}
	if err := db.Create(eng).Error; err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	sess := &c2.ImplantSession{EngagementID: eng.ID}

	cases := []struct {
		name     string
		taskType string
		args     string
		allow    bool
	}{
		{"in-scope CIDR", "portscan", "10.1.2.3:22,80", true},
		{"out-of-scope CIDR", "portscan", "192.168.1.1:22", false},
		{"in-scope hostname", "resolve", "target.example", true},
		{"in-scope domain", "resolve", "app.example.com", true},
		{"out-of-scope hostname", "resolve", "evil.example.net", false},
		{"unauthorized technique", "ls", "/tmp", false},
		{"authorized shell", "shell", "whoami", true},
	}
	for _, tc := range cases {
		err := sh.authorizeTask(sess, tc.taskType, tc.args)
		if tc.allow && err != nil {
			t.Errorf("%s: unexpectedly denied: %v", tc.name, err)
		}
		if !tc.allow && !errors.Is(err, errPolicyDenied) {
			t.Errorf("%s: err = %v, want policy denial", tc.name, err)
		}
	}
}

func TestAuthorizeTask_CapabilityGates(t *testing.T) {
	_, _, db := setupTestRouter(t)
	sh := &sessionHandler{db: db}

	eng := &models.Engagement{Name: "gated", Status: "active"}
	if err := db.Create(eng).Error; err != nil {
		t.Fatal(err)
	}
	sess := &c2.ImplantSession{EngagementID: eng.ID}

	// Sensitive categories are denied until the explicit gate is enabled.
	if err := sh.authorizeTask(sess, protocol.TaskOTDiscover, "10.0.0.5"); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("ot_discover without gate = %v, want denial", err)
	}
	if err := sh.authorizeTask(sess, protocol.TaskOTCredentials, "10.0.0.5"); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("ot_credentials without gate = %v, want denial", err)
	}
	if err := sh.authorizeTask(sess, "credential_dump", ""); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("credential_dump without gate = %v, want denial", err)
	}
	if err := sh.authorizeTask(sess, protocol.TaskInlineExecute, ""); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("inline_execute without gate = %v, want denial", err)
	}

	if err := db.Model(eng).Updates(map[string]any{
		"allow_ot_assessment":     true,
		"allow_credential_access": true,
		"allow_code_execution":    true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := sh.authorizeTask(sess, protocol.TaskOTDiscover, "10.0.0.5"); err != nil {
		t.Fatalf("ot_discover with gate denied: %v", err)
	}
	if err := sh.authorizeTask(sess, protocol.TaskOTCredentials, "10.0.0.5"); err != nil {
		t.Fatalf("ot_credentials with gate denied: %v", err)
	}
	if err := sh.authorizeTask(sess, protocol.TaskInlineExecute, ""); err != nil {
		t.Fatalf("inline_execute with gate denied: %v", err)
	}
}

func TestAuthorizeTask_UnscopedSensitiveDenied(t *testing.T) {
	_, _, db := setupTestRouter(t)
	sh := &sessionHandler{db: db}
	if err := sh.authorizeTask(&c2.ImplantSession{}, protocol.TaskOTDiscover, "10.0.0.5"); !errors.Is(err, errPolicyDenied) {
		t.Fatalf("unscoped OT task = %v, want denial", err)
	}
}

func TestAuthorizeTask_KilledOrOutsideWindow(t *testing.T) {
	_, _, db := setupTestRouter(t)
	sh := &sessionHandler{db: db}

	past := time.Now().Add(-2 * time.Hour)
	expired := &models.Engagement{
		Name:            "expired",
		Status:          "active",
		TimeWindowStart: &past,
		TimeWindowEnd:   &past,
	}
	if err := db.Create(expired).Error; err != nil {
		t.Fatal(err)
	}
	killed := &models.Engagement{Name: "killed", Status: "killed", KillSwitchActive: true}
	if err := db.Create(killed).Error; err != nil {
		t.Fatal(err)
	}

	if err := sh.authorizeTask(&c2.ImplantSession{EngagementID: expired.ID}, "shell", "id"); !errors.Is(err, errPolicyDenied) {
		t.Errorf("expired engagement err = %v, want policy denial", err)
	}
	if err := sh.authorizeTask(&c2.ImplantSession{EngagementID: killed.ID}, "shell", "id"); !errors.Is(err, errPolicyDenied) {
		t.Errorf("killed engagement err = %v, want policy denial", err)
	}
	if err := sh.authorizeTask(&c2.ImplantSession{EngagementID: "missing"}, "shell", "id"); !errors.Is(err, errPolicyDenied) {
		t.Errorf("missing engagement err = %v, want policy denial", err)
	}
}

func TestAuthorizeTask_UnscopedDevelopmentMode(t *testing.T) {
	_, _, db := setupTestRouter(t)
	sh := &sessionHandler{db: db}
	if err := sh.authorizeTask(&c2.ImplantSession{}, "shell", "id"); err != nil {
		t.Fatalf("unscoped development task denied: %v", err)
	}
}

func TestTechniqueAllowed(t *testing.T) {
	if !techniqueAllowed("", "shell") {
		t.Fatal("empty allowlist should allow")
	}
	if !techniqueAllowed(`[]`, "shell") {
		t.Fatal("empty JSON allowlist should allow")
	}
	if !techniqueAllowed(`["shell","*"]`, "shell") {
		t.Fatal("listed technique denied")
	}
	if techniqueAllowed(`["shell"]`, "ls") {
		t.Fatal("unlisted technique allowed")
	}
	if techniqueAllowed(`{bad`, "shell") {
		t.Fatal("malformed allowlist should deny")
	}
}
