package httpapi

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

//go:embed webui
var webUIFS embed.FS

// serverStartTime records when the server started for uptime calculation.
var serverStartTime = time.Now()

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

func NewRouter(implantServer *c2.ImplantServer, db *gorm.DB) http.Handler {
	auth := NewAuthManager()

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

	api.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/sessions" {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		sessions := implantServer.ListSessions()
		writeJSON(w, http.StatusOK, sessions)
	})

	api.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
		parts := strings.SplitN(path, "/", 2)
		sessionID := parts[0]

		if sessionID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing session ID"})
			return
		}

		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				sess := implantServer.GetSession(sessionID)
				if sess == nil {
					writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "session not found"})
					return
				}
				writeJSON(w, http.StatusOK, sess)
			case http.MethodDelete:
				// Kill/remove session from DB
				if err := db.Where("id = ?", sessionID).Delete(&models.Session{}).Error; err != nil {
					writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
			default:
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			}
			return
		}

		subpath := parts[1]
		switch subpath {
		case "task":
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			var req TaskRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
				return
			}
			if req.Type == "" {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "task type is required"})
				return
			}
			taskID, err := implantServer.QueueTask(sessionID, req.Type, req.Args)
			if err != nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, TaskResponse{TaskID: taskID})

		case "lock":
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			var body struct {
				Operator string `json:"operator"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON"})
				return
			}
			if body.Operator == "" {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "operator is required"})
				return
			}
			res := db.Model(&models.Session{}).Where("id = ?", sessionID).Update("locked_by", body.Operator)
			if res.Error != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
				return
			}
			if res.RowsAffected == 0 {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "session not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "locked", "locked_by": body.Operator})

		case "unlock":
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			res := db.Model(&models.Session{}).Where("id = ?", sessionID).Update("locked_by", "")
			if res.Error != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
				return
			}
			if res.RowsAffected == 0 {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "session not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})

		default:
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
		}
	})

	api.HandleFunc("/api/tasks/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		taskID := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
		if taskID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing task ID"})
			return
		}
		result := implantServer.GetResult(taskID)
		if result == nil {
			writeJSON(w, http.StatusOK, PendingResponse{Status: "pending"})
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	// ───────────────── Beacons ─────────────────

	api.HandleFunc("/api/beacons", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var beacons []models.Beacon
		if err := db.Find(&beacons).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, beacons)
	})

	// ───────────────── Listeners ─────────────────

	api.HandleFunc("/api/listeners", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/listeners" {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			var listeners []models.Listener
			if err := db.Find(&listeners).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, listeners)
		case http.MethodPost:
			var listener models.Listener
			if err := json.NewDecoder(r.Body).Decode(&listener); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
				return
			}
			if listener.Type == "" || listener.BindAddr == "" || listener.Port == 0 {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "type, bind_addr, and port are required"})
				return
			}
			listener.Status = "running"
			if err := db.Create(&listener).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, listener)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		}
	})

	api.HandleFunc("/api/listeners/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/listeners/")

		if path == "profiles" {
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			var profiles []models.C2Profile
			if err := db.Find(&profiles).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, profiles)
			return
		}

		// DELETE /api/listeners/{id}
		listenerID := path
		if listenerID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing listener ID"})
			return
		}
		if r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		res := db.Where("id = ?", listenerID).Delete(&models.Listener{})
		if res.Error != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
			return
		}
		if res.RowsAffected == 0 {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "listener not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	// ───────────────── Engagements ─────────────────

	api.HandleFunc("/api/engagements", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/engagements" {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			var engagements []models.Engagement
			if err := db.Find(&engagements).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, engagements)
		case http.MethodPost:
			var eng models.Engagement
			if err := json.NewDecoder(r.Body).Decode(&eng); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
				return
			}
			if eng.Name == "" {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name is required"})
				return
			}
			if err := db.Create(&eng).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, eng)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		}
	})

	api.HandleFunc("/api/engagements/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/engagements/")
		parts := strings.SplitN(path, "/", 2)
		engID := parts[0]

		if engID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing engagement ID"})
			return
		}

		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				var eng models.Engagement
				if err := db.First(&eng, "id = ?", engID).Error; err != nil {
					writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
					return
				}
				writeJSON(w, http.StatusOK, eng)
			case http.MethodPut:
				var eng models.Engagement
				if err := db.First(&eng, "id = ?", engID).Error; err != nil {
					writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
					return
				}
				var updates models.Engagement
				if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
					writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
					return
				}
				if err := db.Model(&eng).Updates(updates).Error; err != nil {
					writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
					return
				}
				// Reload to return the full updated record
				db.First(&eng, "id = ?", engID)
				writeJSON(w, http.StatusOK, eng)
			default:
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			}
			return
		}

		subpath := parts[1]
		switch subpath {
		case "killswitch":
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			res := db.Model(&models.Engagement{}).Where("id = ?", engID).Update("status", "killed")
			if res.Error != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
				return
			}
			if res.RowsAffected == 0 {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "killed"})

		case "scope-check":
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			var body struct {
				Target string `json:"target"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON"})
				return
			}
			if body.Target == "" {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "target is required"})
				return
			}
			var eng models.Engagement
			if err := db.First(&eng, "id = ?", engID).Error; err != nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
				return
			}
			// Check if target appears in the scope config
			inScope := strings.Contains(eng.ScopeConfig, body.Target)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"target":   body.Target,
				"in_scope": inScope,
			})

		default:
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
		}
	})

	// ───────────────── Payloads ─────────────────

	api.HandleFunc("/api/payloads", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/payloads" {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var payloads []models.PayloadArtifact
		if err := db.Find(&payloads).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, payloads)
	})

	api.HandleFunc("/api/payloads/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/payloads/")

		if path == "generate" {
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			var payload models.PayloadArtifact
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
				return
			}
			if payload.TargetOS == "" {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "target_os is required"})
				return
			}

			arch := payload.TargetArch
			if arch == "" || arch == "auto" {
				arch = "amd64"
			}

			archMap := map[string][]string{
				"windows": {"amd64", "arm64", "386"},
				"linux":   {"amd64", "arm64", "386", "mips", "mipsle", "riscv64"},
				"darwin":  {"amd64", "arm64"},
				"freebsd": {"amd64", "arm64"},
				"ios":     {"arm64"},
				"android": {"arm64", "arm"},
			}

			if arch == "multi" {
				arches, ok := archMap[payload.TargetOS]
				if !ok {
					arches = []string{"amd64"}
				}
				var created []models.PayloadArtifact
				for _, a := range arches {
					p, err := buildImplant(db, payload, payload.TargetOS, a)
					if err != nil {
						writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: fmt.Sprintf("%s/%s: %v", payload.TargetOS, a, err)})
						return
					}
					created = append(created, *p)
				}
				writeJSON(w, http.StatusCreated, created)
				return
			}

			p, err := buildImplant(db, payload, payload.TargetOS, arch)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, p)
			return
		}

		if path == "download" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "specify payload ID: /api/payloads/{id}/download"})
			return
		}

		parts := strings.SplitN(path, "/", 2)
		payloadID := parts[0]

		if payloadID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing payload ID"})
			return
		}

		if len(parts) == 1 {
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			var payload models.PayloadArtifact
			if err := db.First(&payload, "id = ?", payloadID).Error; err != nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "payload not found"})
				return
			}
			writeJSON(w, http.StatusOK, payload)
			return
		}

		if parts[1] == "download" {
				if r.Method != http.MethodGet {
					writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
					return
				}
				var payload models.PayloadArtifact
				if err := db.First(&payload, "id = ?", payloadID).Error; err != nil {
					writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "payload not found"})
					return
				}
				if payload.Status == "revoked" {
					writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "payload has been revoked"})
					return
				}
				if len(payload.BinaryData) == 0 {
					writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "no binary data available"})
					return
				}
				ext := ""
				switch payload.TargetOS {
				case "windows":
					switch payload.Format {
					case "dll":
						ext = ".dll"
					case "shellcode":
						ext = ".bin"
					default:
						ext = ".exe"
					}
				default:
					if payload.Format == "shared" {
						ext = ".so"
					}
				}
				filename := fmt.Sprintf("implant-%s-%s%s", payload.TargetOS, payload.TargetArch, ext)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
				w.Header().Set("Content-Length", strconv.Itoa(len(payload.BinaryData)))
				w.Write(payload.BinaryData)
				return
			}

			if parts[1] == "revoke" {
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			res := db.Model(&models.PayloadArtifact{}).Where("id = ?", payloadID).Update("status", "revoked")
			if res.Error != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
				return
			}
			if res.RowsAffected == 0 {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "payload not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
			return
		}

		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
	})

	// ───────────────── Operators ─────────────────

	api.HandleFunc("/api/operators", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/operators" {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			var operators []models.Operator
			if err := db.Find(&operators).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, operators)
		case http.MethodPost:
			var body struct {
				Name     string `json:"name"`
				Role     string `json:"role"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
				return
			}
			if body.Name == "" || body.Password == "" {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name and password are required"})
				return
			}
			if body.Role == "" {
				body.Role = "operator"
			}
			// Hash the password and store it in CertPEM field as bcrypt hash
			hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to hash password"})
				return
			}
			op := models.Operator{
				Name:    body.Name,
				Role:    body.Role,
				CertPEM: hash,
			}
			if err := db.Create(&op).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			// Also register the operator in the auth system
			auth.SetPassword(body.Name, body.Password)
			writeJSON(w, http.StatusCreated, op)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		}
	})

	api.HandleFunc("/api/operators/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		opID := strings.TrimPrefix(r.URL.Path, "/api/operators/")
		if opID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing operator ID"})
			return
		}
		if r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		res := db.Where("id = ?", opID).Delete(&models.Operator{})
		if res.Error != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
			return
		}
		if res.RowsAffected == 0 {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "operator not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	// ───────────────── Server Status ─────────────────

	api.HandleFunc("/api/server/status", func(w http.ResponseWriter, r *http.Request) {
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

		activeSessions := len(implantServer.ListSessions())

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
	})

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

func buildImplant(db *gorm.DB, base models.PayloadArtifact, goos, goarch string) (*models.PayloadArtifact, error) {
	tmpDir, err := os.MkdirTemp("", "pc2-build-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	outPath := filepath.Join(tmpDir, "implant"+ext)

	// Find project root (where go.work lives)
	exePath, _ := os.Executable()
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(exePath)))
	// Fallback: look for go.work by walking up from cwd
	if _, err := os.Stat(filepath.Join(projectRoot, "go.work")); err != nil {
		cwd, _ := os.Getwd()
		for d := cwd; d != "/"; d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, "go.work")); err == nil {
				projectRoot = d
				break
			}
		}
	}

	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-trimpath", "-o", outPath, "./cmd/implant/...")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("build failed: %s: %w", string(output), err)
	}

	binData, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}

	hash := sha256.Sum256(binData)

	payload := base
	payload.ID = ""
	payload.TargetOS = goos
	payload.TargetArch = goarch
	payload.Status = "active"
	payload.SHA256 = hex.EncodeToString(hash[:])
	payload.FileSize = int64(len(binData))
	payload.BinaryData = binData

	if err := db.Create(&payload).Error; err != nil {
		return nil, fmt.Errorf("save payload: %w", err)
	}

	return &payload, nil
}
