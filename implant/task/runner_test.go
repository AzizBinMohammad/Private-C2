package task

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func waitForResults(t *testing.T, r *Runner, want int) []Result {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	collected := make([]Result, 0, want)
	for time.Now().Before(deadline) {
		collected = append(collected, r.Drain()...)
		if len(collected) >= want {
			return collected[:want]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d result(s), got %d", want, len(collected))
	return nil
}

func TestRunner_SubmitDoesNotBlockOnLongTask(t *testing.T) {
	release := make(chan struct{})
	r := NewRunner(func(ctx context.Context, task protocol.TaskWire) (string, error) {
		<-release
		return "done", nil
	}, RunnerConfig{Concurrency: 1})

	start := time.Now()
	if !r.Submit(protocol.TaskWire{ID: "t1", Type: "shell", Args: "sleep"}) {
		t.Fatal("Submit returned false")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Submit blocked for %v", elapsed)
	}
	close(release)
	results := waitForResults(t, r, 1)
	if !results[0].Success || results[0].Output != "done" {
		t.Fatalf("unexpected result: %+v", results[0])
	}
	r.Close()
}

func TestRunner_DuplicateIDNotRerun(t *testing.T) {
	var calls int32
	r := NewRunner(func(ctx context.Context, task protocol.TaskWire) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "ok", nil
	}, RunnerConfig{Concurrency: 2})

	if !r.Submit(protocol.TaskWire{ID: "same"}) {
		t.Fatal("first Submit returned false")
	}
	if r.Submit(protocol.TaskWire{ID: "same"}) {
		t.Fatal("duplicate Submit was accepted")
	}
	waitForResults(t, r, 1)
	r.Close()
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("handler calls = %d, want 1", got)
	}
}

func TestRunner_Timeout(t *testing.T) {
	r := NewRunner(func(ctx context.Context, task protocol.TaskWire) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}, RunnerConfig{Concurrency: 1, Timeout: time.Second})

	if !r.Submit(protocol.TaskWire{ID: "timeout", TimeoutMs: 20}) {
		t.Fatal("Submit returned false")
	}
	results := waitForResults(t, r, 1)
	if results[0].Success || !strings.Contains(results[0].Error, "deadline exceeded") {
		t.Fatalf("unexpected timeout result: %+v", results[0])
	}
	r.Close()
}

func TestRunner_PanicRecovered(t *testing.T) {
	r := NewRunner(func(ctx context.Context, task protocol.TaskWire) (string, error) {
		panic("boom")
	}, RunnerConfig{Concurrency: 1})

	if !r.Submit(protocol.TaskWire{ID: "panic"}) {
		t.Fatal("Submit returned false")
	}
	results := waitForResults(t, r, 1)
	if results[0].Success || !strings.Contains(results[0].Error, "panicked") {
		t.Fatalf("unexpected panic result: %+v", results[0])
	}
	r.Close()
}

func TestRunner_ConcurrencyLimit(t *testing.T) {
	var active, maxActive int32
	r := NewRunner(func(ctx context.Context, task protocol.TaskWire) (string, error) {
		n := atomic.AddInt32(&active, 1)
		for {
			m := atomic.LoadInt32(&maxActive)
			if n <= m || atomic.CompareAndSwapInt32(&maxActive, m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return "ok", nil
	}, RunnerConfig{Concurrency: 2})

	for i := 0; i < 6; i++ {
		r.Submit(protocol.TaskWire{ID: string(rune('a' + i))})
	}
	waitForResults(t, r, 6)
	r.Close()
	if got := atomic.LoadInt32(&maxActive); got > 2 {
		t.Fatalf("max concurrent tasks = %d, want <= 2", got)
	}
}

func TestRunner_OutputTruncated(t *testing.T) {
	r := NewRunner(func(ctx context.Context, task protocol.TaskWire) (string, error) {
		return strings.Repeat("x", 100), nil
	}, RunnerConfig{Concurrency: 1, MaxOutputBytes: 10})

	r.Submit(protocol.TaskWire{ID: "big"})
	results := waitForResults(t, r, 1)
	if !results[0].Truncated || len(results[0].Output) != 10 {
		t.Fatalf("unexpected truncation result: %+v", results[0])
	}
	r.Close()
}

func TestRunner_SafetyCheckRefusesTask(t *testing.T) {
	var called int32
	r := NewRunner(func(ctx context.Context, task protocol.TaskWire) (string, error) {
		atomic.AddInt32(&called, 1)
		return "should not run", nil
	}, RunnerConfig{
		Concurrency: 1,
		SafetyCheck: func(ctx context.Context, task protocol.TaskWire) error {
			return context.Canceled
		},
	})

	r.Submit(protocol.TaskWire{ID: "denied"})
	results := waitForResults(t, r, 1)
	if results[0].Success || results[0].Error == "" {
		t.Fatalf("unexpected safety result: %+v", results[0])
	}
	r.Close()
	if got := atomic.LoadInt32(&called); got != 0 {
		t.Fatalf("handler ran despite safety refusal: %d calls", got)
	}
}
