package engagement

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type KillSwitch struct {
	mu       sync.RWMutex
	active   map[string]bool
	reasons  map[string]string
}

func NewKillSwitch() *KillSwitch {
	return &KillSwitch{
		active:  make(map[string]bool),
		reasons: make(map[string]string),
	}
}

func (ks *KillSwitch) Activate(engagementID, reason string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.active[engagementID] = true
	ks.reasons[engagementID] = reason
}

func (ks *KillSwitch) IsActive(engagementID string) (bool, string) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.active[engagementID] {
		return true, ks.reasons[engagementID]
	}
	return false, ""
}

func (ks *KillSwitch) Deactivate(engagementID string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	delete(ks.active, engagementID)
	delete(ks.reasons, engagementID)
}

func CheckRemoteKillSwitch(ctx context.Context, url string) (bool, error) {
	if url == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("creating kill switch request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return true, nil // fail-closed: if we can't reach the kill switch, stop
	}
	defer resp.Body.Close()

	return resp.StatusCode != http.StatusOK, nil
}

type DataQuota struct {
	mu        sync.Mutex
	limit     int64
	consumed  int64
}

func NewDataQuota(limitBytes int64) *DataQuota {
	return &DataQuota{limit: limitBytes}
}

func (dq *DataQuota) Consume(bytes int64) error {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if dq.limit > 0 && dq.consumed+bytes > dq.limit {
		return fmt.Errorf("data collection quota exceeded: %d/%d bytes", dq.consumed+bytes, dq.limit)
	}
	dq.consumed += bytes
	return nil
}

func (dq *DataQuota) Remaining() int64 {
	dq.mu.Lock()
	defer dq.mu.Unlock()
	if dq.limit <= 0 {
		return -1
	}
	return dq.limit - dq.consumed
}
