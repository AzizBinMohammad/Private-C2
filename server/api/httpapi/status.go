package httpapi

import (
	"net/http"
	"runtime"
	"time"

	"github.com/azizbinmohammad/private-c2/server/c2"
)

// serverStartTime records when the server started for uptime calculation.
var serverStartTime = time.Now()

type statusHandler struct {
	implantServer *c2.ImplantServer
}

func (st *statusHandler) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	activeSessions := len(st.implantServer.ListSessions())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":         "0.1.0",
		"uptime_seconds":  int(time.Since(serverStartTime).Seconds()),
		"active_sessions": activeSessions,
		"go_version":      runtime.Version(),
		"goroutines":      runtime.NumGoroutine(),
		"memory_alloc":    memStats.Alloc,
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
	})
}
