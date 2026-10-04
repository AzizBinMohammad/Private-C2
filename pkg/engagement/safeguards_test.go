package engagement

import (
	"testing"
	"time"
)

func TestKillSwitchActivateDeactivate(t *testing.T) {
	ks := NewKillSwitch()

	active, reason := ks.IsActive("eng-001")
	if active {
		t.Fatal("kill switch should not be active initially")
	}
	if reason != "" {
		t.Fatalf("expected empty reason, got %q", reason)
	}

	ks.Activate("eng-001", "emergency stop")

	active, reason = ks.IsActive("eng-001")
	if !active {
		t.Fatal("kill switch should be active after Activate")
	}
	if reason != "emergency stop" {
		t.Fatalf("expected reason %q, got %q", "emergency stop", reason)
	}

	ks.Deactivate("eng-001")

	active, _ = ks.IsActive("eng-001")
	if active {
		t.Fatal("kill switch should not be active after Deactivate")
	}
}

func TestKillSwitchMultipleEngagements(t *testing.T) {
	ks := NewKillSwitch()

	ks.Activate("eng-001", "reason1")
	ks.Activate("eng-002", "reason2")

	active1, _ := ks.IsActive("eng-001")
	active2, _ := ks.IsActive("eng-002")
	active3, _ := ks.IsActive("eng-003")

	if !active1 {
		t.Fatal("eng-001 should be active")
	}
	if !active2 {
		t.Fatal("eng-002 should be active")
	}
	if active3 {
		t.Fatal("eng-003 should not be active")
	}
}

func TestDataQuotaWithinLimit(t *testing.T) {
	dq := NewDataQuota(1000)

	if err := dq.Consume(500); err != nil {
		t.Fatalf("Consume within limit: %v", err)
	}

	remaining := dq.Remaining()
	if remaining != 500 {
		t.Fatalf("expected 500 remaining, got %d", remaining)
	}
}

func TestDataQuotaExceedsLimit(t *testing.T) {
	dq := NewDataQuota(1000)

	if err := dq.Consume(500); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	err := dq.Consume(600)
	if err == nil {
		t.Fatal("expected error when exceeding quota")
	}

	// Remaining should still be 500 since the second consume was rejected
	remaining := dq.Remaining()
	if remaining != 500 {
		t.Fatalf("expected 500 remaining after rejected consume, got %d", remaining)
	}
}

func TestDataQuotaRemaining(t *testing.T) {
	dq := NewDataQuota(1000)

	if r := dq.Remaining(); r != 1000 {
		t.Fatalf("expected 1000 remaining initially, got %d", r)
	}

	_ = dq.Consume(300)
	if r := dq.Remaining(); r != 700 {
		t.Fatalf("expected 700 remaining, got %d", r)
	}

	_ = dq.Consume(700)
	if r := dq.Remaining(); r != 0 {
		t.Fatalf("expected 0 remaining, got %d", r)
	}
}

func TestDataQuotaUnlimited(t *testing.T) {
	dq := NewDataQuota(0)

	// With zero limit, Remaining returns -1 (unlimited)
	if r := dq.Remaining(); r != -1 {
		t.Fatalf("expected -1 for unlimited quota, got %d", r)
	}

	// Should be able to consume any amount
	if err := dq.Consume(1 << 30); err != nil {
		t.Fatalf("unlimited quota should accept any amount: %v", err)
	}
}

func TestTimeWindowActive(t *testing.T) {
	tw := &TimeWindow{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now().Add(1 * time.Hour),
	}

	active, reason := tw.IsActive()
	if !active {
		t.Fatalf("time window should be active, reason: %s", reason)
	}
}

func TestTimeWindowNotStarted(t *testing.T) {
	tw := &TimeWindow{
		Start: time.Now().Add(1 * time.Hour),
		End:   time.Now().Add(2 * time.Hour),
	}

	active, reason := tw.IsActive()
	if active {
		t.Fatal("time window should not be active before start")
	}
	if reason == "" {
		t.Fatal("expected reason for inactive window")
	}
}

func TestTimeWindowEnded(t *testing.T) {
	tw := &TimeWindow{
		Start: time.Now().Add(-2 * time.Hour),
		End:   time.Now().Add(-1 * time.Hour),
	}

	active, reason := tw.IsActive()
	if active {
		t.Fatal("time window should not be active after end")
	}
	if reason == "" {
		t.Fatal("expected reason for ended window")
	}
}
