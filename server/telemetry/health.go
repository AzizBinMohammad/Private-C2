package telemetry

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

type HealthStatus struct {
	Status    string    `json:"status"`
	Uptime    string    `json:"uptime"`
	GoVersion string    `json:"go_version"`
	NumCPU    int       `json:"num_cpu"`
	Goroutines int     `json:"goroutines"`
	MemAlloc  uint64    `json:"mem_alloc_bytes"`
	Timestamp time.Time `json:"timestamp"`
}

type HealthChecker struct {
	startTime time.Time
}

func NewHealthChecker() *HealthChecker {
	return &HealthChecker{startTime: time.Now()}
}

func (hc *HealthChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		status := HealthStatus{
			Status:     "healthy",
			Uptime:     time.Since(hc.startTime).String(),
			GoVersion:  runtime.Version(),
			NumCPU:     runtime.NumCPU(),
			Goroutines: runtime.NumGoroutine(),
			MemAlloc:   memStats.Alloc,
			Timestamp:  time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}
}
