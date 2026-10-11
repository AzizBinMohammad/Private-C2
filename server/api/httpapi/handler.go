package httpapi

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
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

func NewRouter(implantServer *c2.ImplantServer, db *gorm.DB) http.Handler {
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

	sh := &sessionHandler{implantServer: implantServer, db: db}
	api.HandleFunc("/api/sessions", sh.handleSessions)
	api.HandleFunc("/api/sessions/", sh.handleSessionDetail)
	api.HandleFunc("/api/tasks/", sh.handleTaskResult)

	// ───────────────── Beacons ─────────────────

	bh := &beaconHandler{db: db}
	api.HandleFunc("/api/beacons", bh.handleBeacons)

	// ───────────────── Listeners ─────────────────

	lh := &listenerHandler{db: db}
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

	api.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/audit" {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}

		query := db.Model(&models.AuditEntry{})

		if v := r.URL.Query().Get("operator_id"); v != "" {
			query = query.Where("operator_id = ?", v)
		}
		if v := r.URL.Query().Get("session_id"); v != "" {
			query = query.Where("session_id = ?", v)
		}
		if v := r.URL.Query().Get("event_type"); v != "" {
			query = query.Where("event_type = ?", v)
		}

		page := 1
		limit := 50
		if v := r.URL.Query().Get("page"); v != "" {
			if p, err := strconv.Atoi(v); err == nil && p > 0 {
				page = p
			}
		}
		if v := r.URL.Query().Get("limit"); v != "" {
			if l, err := strconv.Atoi(v); err == nil && l > 0 && l <= 1000 {
				limit = l
			}
		}

		var entries []models.AuditEntry
		offset := (page - 1) * limit
		if err := query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&entries).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	})

	api.HandleFunc("/api/audit/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/audit/")
		if path == "verify" {
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			// Verify audit hash chain integrity
			var entries []models.AuditEntry
			if err := db.Order("created_at ASC").Find(&entries).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			if len(entries) == 0 {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"valid":   true,
					"entries": 0,
					"message": "no audit entries",
				})
				return
			}

			valid := true
			brokenAt := -1
			prevHash := ""
			for i, entry := range entries {
				if i > 0 && entry.PreviousHash != prevHash {
					valid = false
					brokenAt = i
					break
				}
				// Recompute hash: sha256(id + created_at + action + previous_hash)
				h := sha256.New()
				h.Write([]byte(entry.ID))
				h.Write([]byte(entry.CreatedAt.Format(time.RFC3339Nano)))
				h.Write([]byte(entry.Action))
				h.Write([]byte(entry.PreviousHash))
				prevHash = hex.EncodeToString(h.Sum(nil))
				if entry.EntryHash != prevHash {
					valid = false
					brokenAt = i
					break
				}
			}

			result := map[string]interface{}{
				"valid":   valid,
				"entries": len(entries),
			}
			if !valid {
				result["broken_at_index"] = brokenAt
				result["message"] = fmt.Sprintf("chain broken at entry index %d", brokenAt)
			}
			writeJSON(w, http.StatusOK, result)
			return
		}

		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
	})

	// ───────────────── OT/ICS endpoints (real DB queries) ─────────────────

	api.HandleFunc("/api/ot/assets", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var records []models.OTAssetRecord
		if err := db.Find(&records).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, records)
	})

	api.HandleFunc("/api/ot/vulns", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var records []models.OTVulnFinding
		if err := db.Find(&records).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, records)
	})

	api.HandleFunc("/api/ot/credentials", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var records []models.OTCredentialFinding
		if err := db.Find(&records).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, records)
	})

	api.HandleFunc("/api/ot/compliance", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var records []models.OTComplianceFinding
		if err := db.Find(&records).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, records)
	})

	api.HandleFunc("/api/ot/topology", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var records []models.OTTopologyEdge
		if err := db.Find(&records).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, records)
	})

	api.HandleFunc("/api/ot/reports", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var records []models.OTAssessmentReport
		if err := db.Find(&records).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, records)
	})

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
