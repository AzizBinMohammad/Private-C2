package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/engagement"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/azizbinmohammad/private-c2/pkg/taskargs"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
)

var errPolicyDenied = errors.New("task denied by engagement policy")

// authorizeTask applies engagement-level policy before a task is persisted or
// queued. It is a server-side check in addition to the implant's SafetyChecker.
func (sh *sessionHandler) authorizeTask(sess *c2.ImplantSession, taskType, args string) error {
	category := protocol.CategoryFor(taskType)
	if sess == nil || sess.EngagementID == "" {
		// Unscoped development mode is limited to non-sensitive task types.
		// Sensitive categories require an engagement with an explicit gate.
		if category != protocol.CategoryGeneral {
			return fmt.Errorf("%w: %s tasks require an engagement", errPolicyDenied, category)
		}
		return nil
	}
	if sh.db == nil {
		return fmt.Errorf("%w: database unavailable", errPolicyDenied)
	}

	var eng models.Engagement
	if err := sh.db.First(&eng, "id = ?", sess.EngagementID).Error; err != nil {
		return fmt.Errorf("%w: engagement not found", errPolicyDenied)
	}
	if eng.Status == "killed" || eng.Status == "closed" || eng.KillSwitchActive {
		return fmt.Errorf("%w: engagement is not active", errPolicyDenied)
	}
	if !capabilityAllowed(eng, category) {
		return fmt.Errorf("%w: capability %q is not enabled for this engagement", errPolicyDenied, category)
	}

	now := time.Now()
	if (eng.TimeWindowStart != nil && now.Before(*eng.TimeWindowStart)) ||
		(eng.TimeWindowEnd != nil && now.After(*eng.TimeWindowEnd)) {
		return fmt.Errorf("%w: outside the engagement time window", errPolicyDenied)
	}

	if !techniqueAllowed(eng.AuthorizedTechniques, taskType) {
		return fmt.Errorf("%w: task type %q is not authorized", errPolicyDenied, taskType)
	}

	target := taskargs.Target(taskType, args)
	if target == "" {
		return nil
	}
	scope, err := scopeFromConfig(eng.ScopeConfig)
	if err != nil {
		return fmt.Errorf("%w: invalid scope configuration", errPolicyDenied)
	}
	if scope == nil {
		// No scope configured: leave enforcement to the implant's explicit
		// scope flags. An empty scope must not silently authorize everything
		// in production; the engagement editor should require one.
		return nil
	}
	if inScope, reason := scope.Contains(target); !inScope {
		return fmt.Errorf("%w: %s", errPolicyDenied, reason)
	}
	return nil
}

func capabilityAllowed(eng models.Engagement, category protocol.TaskCategory) bool {
	switch category {
	case protocol.CategoryGeneral:
		return true
	case protocol.CategoryPrivilege:
		return eng.AllowPrivilegeEscalation
	case protocol.CategoryCredential:
		return eng.AllowCredentialAccess
	case protocol.CategoryLateral:
		return eng.AllowLateralMovement
	case protocol.CategoryPersistence:
		return eng.AllowPersistence
	case protocol.CategoryEvasion:
		return eng.AllowEvasion
	case protocol.CategoryOT:
		return eng.AllowOTAssessment
	case protocol.CategoryExecution:
		return eng.AllowCodeExecution
	default:
		return false
	}
}

func techniqueAllowed(raw, taskType string) bool {
	if raw == "" {
		return true
	}
	var techniques []string
	if err := json.Unmarshal([]byte(raw), &techniques); err != nil {
		return false
	}
	if len(techniques) == 0 {
		return true
	}
	for _, technique := range techniques {
		if technique == taskType || technique == "*" {
			return true
		}
	}
	return false
}

func scopeFromConfig(raw string) (*engagement.Scope, error) {
	if raw == "" {
		return nil, nil
	}
	var cfg struct {
		CIDRs     []string `json:"cidrs"`
		Hostnames []string `json:"hostnames"`
		Hosts     []string `json:"hosts"`
		Targets   []string `json:"targets"`
		Domains   []string `json:"domains"`
		Excluded  []string `json:"excluded"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}
	hosts := append(append([]string{}, cfg.Hostnames...), cfg.Hosts...)
	hosts = append(hosts, cfg.Targets...)
	return engagement.NewScope(cfg.CIDRs, hosts, cfg.Domains, cfg.Excluded)
}
