package httpapi

import (
	"fmt"
	"net/http"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
)

// auditMiddleware records every authenticated API request after it completes.
// It is a safety net in addition to the explicit task/kill-switch events.
func auditMiddleware(auditor *audit.Logger, next http.Handler) http.Handler {
	if auditor == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			return
		}
		identity, _ := authz.FromContext(r.Context())
		operator := identity.OperatorID
		if operator == "" {
			operator = identity.Username
		}
		_ = auditor.Log(
			operator, "", "",
			audit.EventType("api.request"),
			r.Method+" "+r.URL.Path,
			r.URL.Path,
			fmt.Sprintf("status=%d", rec.status),
			nil,
			r.RemoteAddr,
			"",
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

// Flush forwards to the underlying writer for streaming responses.
func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
