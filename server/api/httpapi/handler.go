package httpapi

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/auditwriter"
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
	if err := auth.LoadFromDB(db); err != nil {
		// The in-memory admin remains usable; operators created earlier are
		// missing until the database is reachable again.
		log.Printf("[api] failed to load operators: %v", err)
	}

	var auditor *audit.Logger
	if db != nil {
		if writer, err := auditwriter.New(db); err != nil {
			log.Printf("[api] audit writer unavailable: %v", err)
		} else {
			auditor = audit.NewLoggerFromHead(writer.Head(), writer)
		}
	}
	auth.SetAuditLogger(auditor)

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
	api.HandleFunc("/api/auth/logout", auth.LogoutHandler())

	// ───────────────── Sessions ─────────────────

	sh := &sessionHandler{implantServer: implantServer, db: db, auditor: auditor}
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

	eh := &engagementHandler{db: db, implantServer: implantServer, auditor: auditor}
	api.HandleFunc("/api/engagements", eh.handleEngagements)
	api.HandleFunc("/api/engagements/", eh.handleEngagementDetail)

	// ───────────────── Payloads ─────────────────

	ph := &payloadHandler{db: db, auditor: auditor}
	api.HandleFunc("/api/payloads", ph.handlePayloads)
	api.HandleFunc("/api/payloads/", ph.handlePayloadDetail)

	// ───────────────── Operators ─────────────────

	oh := &operatorHandler{db: db, auth: auth}
	api.HandleFunc("/api/operators", oh.handleOperators)
	api.HandleFunc("/api/operators/", oh.handleOperatorDetail)

	// ───────────────── Plugins ─────────────────

	pl := newPluginHandler(sh, auditor)
	api.HandleFunc("/api/plugins", pl.handlePlugins)
	api.HandleFunc("/api/plugins/", pl.handlePluginAction)

	// ───────────────── Loot ─────────────────

	lootH := newLootHandler(db, auditor)
	api.HandleFunc("/api/loot", lootH.handleLoot)
	api.HandleFunc("/api/loot/", lootH.handleLootDetail)

	// ───────────────── Server Status ─────────────────

	st := &statusHandler{implantServer: implantServer}
	api.HandleFunc("/api/server/status", st.handleServerStatus)

	// ───────────────── Audit ─────────────────

	ah := &auditHandler{db: db}
	api.HandleFunc("/api/audit", ah.handleAuditList)
	api.HandleFunc("/api/audit/", ah.handleAuditDetail)

	// ───────────────── OT/ICS ─────────────────

	oth := &otHandler{db: db, auditor: auditor}
	api.HandleFunc("/api/ot/import", oth.handleOTImport)
	api.HandleFunc("/api/ot/assets", oth.handleOTAssets)
	api.HandleFunc("/api/ot/vulns", oth.handleOTVulns)
	api.HandleFunc("/api/ot/credentials", oth.handleOTCredentials)
	api.HandleFunc("/api/ot/compliance", oth.handleOTCompliance)
	api.HandleFunc("/api/ot/topology", oth.handleOTTopology)
	api.HandleFunc("/api/ot/reports", oth.handleOTReports)

	// ── Wire protected routes through authentication + authorization ──
	protected := auth.Middleware(auditMiddleware(auditor, authz.Middleware(api)))
	mux.Handle("/api/sessions", protected)
	mux.Handle("/api/sessions/", protected)
	mux.Handle("/api/tasks/", protected)
	mux.Handle("/api/beacons", protected)
	mux.Handle("/api/listeners", protected)
	mux.Handle("/api/listeners/", protected)
	mux.Handle("/api/engagements", protected)
	mux.Handle("/api/engagements/", protected)
	mux.Handle("/api/payloads", protected)
	mux.Handle("/api/payloads/", protected)
	mux.Handle("/api/operators", protected)
	mux.Handle("/api/operators/", protected)
	mux.Handle("/api/plugins", protected)
	mux.Handle("/api/plugins/", protected)
	mux.Handle("/api/loot", protected)
	mux.Handle("/api/loot/", protected)
	mux.Handle("/api/server/", protected)
	mux.Handle("/api/audit", protected)
	mux.Handle("/api/audit/", protected)
	mux.Handle("/api/ot/", protected)
	mux.Handle("/api/auth/logout", protected)

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
