package safety

import (
	"context"
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/engagement"
)

// SafetyChecker performs pre-execution checks to ensure all safety
// constraints are met before a task runs. It validates the kill switch,
// kill date, time window, scope, and data quota.
type SafetyChecker struct {
	killSwitch     *engagement.KillSwitch
	engagementID   string
	killDate       time.Time
	timeWindow     *engagement.TimeWindow
	scope          *engagement.Scope
	dataQuota      *engagement.DataQuota
	remoteKillURL  string
}

// SafetyConfig configures the safety checker.
type SafetyConfig struct {
	KillSwitch    *engagement.KillSwitch
	EngagementID  string
	KillDate      time.Time
	TimeWindow    *engagement.TimeWindow
	Scope         *engagement.Scope
	DataQuota     *engagement.DataQuota
	RemoteKillURL string
}

// CheckResult represents the result of a safety check.
type CheckResult struct {
	Passed  bool
	Reason  string
	Fatal   bool // if true, the implant should terminate
}

// NewSafetyChecker creates a new safety checker.
func NewSafetyChecker(cfg SafetyConfig) *SafetyChecker {
	return &SafetyChecker{
		killSwitch:    cfg.KillSwitch,
		engagementID:  cfg.EngagementID,
		killDate:      cfg.KillDate,
		timeWindow:    cfg.TimeWindow,
		scope:         cfg.Scope,
		dataQuota:     cfg.DataQuota,
		remoteKillURL: cfg.RemoteKillURL,
	}
}

// Check performs all safety checks. Returns a CheckResult indicating
// whether the task should proceed.
func (sc *SafetyChecker) Check(ctx context.Context) CheckResult {
	// Check kill date first -- this is fatal.
	if result := sc.checkKillDate(); !result.Passed {
		return result
	}

	// Check local kill switch.
	if result := sc.checkKillSwitch(); !result.Passed {
		return result
	}

	// Check remote kill switch.
	if result := sc.checkRemoteKillSwitch(ctx); !result.Passed {
		return result
	}

	// Check time window.
	if result := sc.checkTimeWindow(); !result.Passed {
		return result
	}

	return CheckResult{Passed: true}
}

// CheckWithTarget performs all checks plus scope validation for a specific target.
func (sc *SafetyChecker) CheckWithTarget(ctx context.Context, target string) CheckResult {
	result := sc.Check(ctx)
	if !result.Passed {
		return result
	}

	// Check scope.
	if target != "" {
		if scopeResult := sc.checkScope(target); !scopeResult.Passed {
			return scopeResult
		}
	}

	return CheckResult{Passed: true}
}

// CheckDataQuota validates that the given amount of data can be consumed.
func (sc *SafetyChecker) CheckDataQuota(bytes int64) CheckResult {
	if sc.dataQuota == nil {
		return CheckResult{Passed: true}
	}

	if err := sc.dataQuota.Consume(bytes); err != nil {
		return CheckResult{
			Passed: false,
			Reason: fmt.Sprintf("data quota check failed: %s", err.Error()),
			Fatal:  false,
		}
	}

	return CheckResult{Passed: true}
}

// DataQuotaRemaining returns the remaining data quota in bytes, or -1 if unlimited.
func (sc *SafetyChecker) DataQuotaRemaining() int64 {
	if sc.dataQuota == nil {
		return -1
	}
	return sc.dataQuota.Remaining()
}

// checkKillDate verifies the engagement has not expired.
func (sc *SafetyChecker) checkKillDate() CheckResult {
	if sc.killDate.IsZero() {
		return CheckResult{Passed: true}
	}

	if time.Now().After(sc.killDate) {
		return CheckResult{
			Passed: false,
			Reason: fmt.Sprintf("kill date reached: %s", sc.killDate.Format(time.RFC3339)),
			Fatal:  true,
		}
	}

	return CheckResult{Passed: true}
}

// checkKillSwitch checks if the local kill switch has been activated.
func (sc *SafetyChecker) checkKillSwitch() CheckResult {
	if sc.killSwitch == nil {
		return CheckResult{Passed: true}
	}

	active, reason := sc.killSwitch.IsActive(sc.engagementID)
	if active {
		return CheckResult{
			Passed: false,
			Reason: fmt.Sprintf("kill switch activated: %s", reason),
			Fatal:  true,
		}
	}

	return CheckResult{Passed: true}
}

// checkRemoteKillSwitch checks the remote kill switch endpoint.
func (sc *SafetyChecker) checkRemoteKillSwitch(ctx context.Context) CheckResult {
	if sc.remoteKillURL == "" {
		return CheckResult{Passed: true}
	}

	killed, err := engagement.CheckRemoteKillSwitch(ctx, sc.remoteKillURL)
	if err != nil {
		// Fail-closed: if we can't reach the kill switch, stop.
		return CheckResult{
			Passed: false,
			Reason: fmt.Sprintf("remote kill switch check failed (fail-closed): %s", err.Error()),
			Fatal:  true,
		}
	}

	if killed {
		return CheckResult{
			Passed: false,
			Reason: "remote kill switch is active",
			Fatal:  true,
		}
	}

	return CheckResult{Passed: true}
}

// checkTimeWindow verifies the operation is within the allowed time window.
func (sc *SafetyChecker) checkTimeWindow() CheckResult {
	if sc.timeWindow == nil {
		return CheckResult{Passed: true}
	}

	active, reason := sc.timeWindow.IsActive()
	if !active {
		return CheckResult{
			Passed: false,
			Reason: fmt.Sprintf("outside time window: %s", reason),
			Fatal:  false, // not fatal: will retry on next check-in
		}
	}

	return CheckResult{Passed: true}
}

// checkScope verifies the target is within the engagement scope.
func (sc *SafetyChecker) checkScope(target string) CheckResult {
	if sc.scope == nil {
		return CheckResult{Passed: true}
	}

	inScope, reason := sc.scope.Contains(target)
	if !inScope {
		return CheckResult{
			Passed: false,
			Reason: fmt.Sprintf("out of scope: %s", reason),
			Fatal:  false,
		}
	}

	return CheckResult{Passed: true}
}
