package httpapi

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/azizbinmohammad/private-c2/server/c2"
	"gorm.io/gorm"
)

//go:embed webui
var webUIFS embed.FS

type TaskRequest struct {
	Type string `json:"type"`
	Args string `json:"args"`
}

type TaskResponse struct {
	TaskID string `json:"task_id"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type PendingResponse struct {
	Status string `json:"status"`
}

var newAuthManagerFn = NewAuthManager

// NewRouter builds the operator API router. listenerTLSConfig is used when an
// operator starts a new implant listener through POST /api/listeners; pass nil
// to disable listener creation.
func NewRouter(implantServer *c2.ImplantServer, db *gorm.DB, listenerTLSConfig *tls.Config) http.Handler {
	auth := newAuthManagerFn()

	mux := http.NewServeMux()

	// ── Public: login + static UI ──
	mux.HandleFunc("/api/auth/login", auth.LoginHandler())

	webUI, _ := fs.Sub(webUIFS, "webui")
	fileServer := http.FileServer(http.FS(webUI))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})

	// ── Protected API routes ──
	api := http.NewServeMux()

	// ───────────────── Sessions ─────────────────

	sh := &sessionHandler{implantServer: implantServer}
	api.HandleFunc("/api/sessions", sh.handleSessions)
	api.HandleFunc("/api/sessions/", sh.handleSessionDetail)
	api.HandleFunc("/api/tasks/", sh.handleTaskResult)

	// ───────────────── Beacons ─────────────────

	// Beacons are read from the beacons table *and* from live sessions: the
	// table has no writer in the running server, so reading it alone left the
	// portal's panel empty. See the comment on beaconHandler.
	bh := &beaconHandler{db: db, implantServer: implantServer}
	api.HandleFunc("/api/beacons", bh.handleBeacons)

	// ───────────────── Listeners ─────────────────

	lh := &listenerHandler{db: db, implantServer: implantServer, tlsConfig: listenerTLSConfig}
	api.HandleFunc("/api/listeners", lh.handleListeners)
	api.HandleFunc("/api/listeners/", lh.handleListenerDetail)

	// ───────────────── Engagements ─────────────────

	eh := &engagementHandler{db: db}
	api.HandleFunc("/api/engagements", eh.handleEngagements)
	api.HandleFunc("/api/engagements/", eh.handleEngagementDetail)

	// ───────────────── Payloads ─────────────────

	ph := &payloadHandler{db: db}
	api.HandleFunc("/api/payloads", ph.handlePayloads)
	api.HandleFunc("/api/payloads/", ph.handlePayloadDetail)

	// ───────────────── Operators ─────────────────

	oh := &operatorHandler{db: db, auth: auth}
	api.HandleFunc("/api/operators", oh.handleOperators)
	api.HandleFunc("/api/operators/", oh.handleOperatorDetail)

	// ───────────────── Server Status ─────────────────

	st := &statusHandler{implantServer: implantServer}
	api.HandleFunc("/api/server/status", st.handleServerStatus)

	// ───────────────── Audit ─────────────────

	ah := &auditHandler{db: db}
	api.HandleFunc("/api/audit", ah.handleAuditList)
	api.HandleFunc("/api/audit/", ah.handleAuditDetail)

	// ───────────────── OT/ICS ─────────────────

	oth := &otHandler{db: db}
	api.HandleFunc("/api/ot/assets", oth.handleOTAssets)
	api.HandleFunc("/api/ot/vulns", oth.handleOTVulns)
	api.HandleFunc("/api/ot/credentials", oth.handleOTCredentials)
	api.HandleFunc("/api/ot/compliance", oth.handleOTCompliance)
	api.HandleFunc("/api/ot/topology", oth.handleOTTopology)
	api.HandleFunc("/api/ot/reports", oth.handleOTReports)

	// ── Wire protected routes through auth middleware ──
	mux.Handle("/api/sessions", auth.Middleware(api))
	mux.Handle("/api/sessions/", auth.Middleware(api))
	mux.Handle("/api/tasks/", auth.Middleware(api))
	mux.Handle("/api/beacons", auth.Middleware(api))
	mux.Handle("/api/listeners", auth.Middleware(api))
	mux.Handle("/api/listeners/", auth.Middleware(api))
	mux.Handle("/api/engagements", auth.Middleware(api))
	mux.Handle("/api/engagements/", auth.Middleware(api))
	mux.Handle("/api/payloads", auth.Middleware(api))
	mux.Handle("/api/payloads/", auth.Middleware(api))
	mux.Handle("/api/operators", auth.Middleware(api))
	mux.Handle("/api/operators/", auth.Middleware(api))
	mux.Handle("/api/server/", auth.Middleware(api))
	mux.Handle("/api/audit", auth.Middleware(api))
	mux.Handle("/api/audit/", auth.Middleware(api))
	mux.Handle("/api/ot/", auth.Middleware(api))

	return mux
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
