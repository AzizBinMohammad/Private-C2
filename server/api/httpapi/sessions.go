package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/pkg/taskargs"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
	"gorm.io/gorm"
)

// sessionHandler serves live implant sessions. Sessions are held in memory
// (docs/decisions.md), so this handler needs no database access.
type sessionHandler struct {
	implantServer *c2.ImplantServer
	db            *gorm.DB
	auditor       *audit.Logger
}

func (sh *sessionHandler) handleSessions(w http.ResponseWriter, r *http.Request) {
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
	sessions := sh.implantServer.ListSessions()
	writeJSON(w, http.StatusOK, sessions)
}

func (sh *sessionHandler) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	if path == "history" {
		sh.handleSessionHistory(w, r)
		return
	}
	parts := strings.SplitN(path, "/", 2)
	sessionID := parts[0]

	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing session ID"})
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			sess := sh.implantServer.GetSession(sessionID)
			if sess == nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "session not found"})
				return
			}
			writeJSON(w, http.StatusOK, sess)
		case http.MethodDelete:
			// Live sessions exist only in memory (see docs/decisions.md), so
			// this must close the connection rather than delete a database row
			// that was never written. Previously it reported success
			// regardless, so the portal said "Session killed" while the
			// implant kept beaconing.
			if err := sh.implantServer.CloseSession(sessionID); err != nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
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
		sess := sh.implantServer.GetSession(sessionID)
		if sess == nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "session not found"})
			return
		}
		if err := sh.authorizeTask(sess, req.Type, req.Args); err != nil {
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: err.Error()})
			return
		}

		taskID, err := sh.implantServer.QueueTask(sessionID, req.Type, req.Args)
		if err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, c2.ErrSessionNotFound):
				status = http.StatusNotFound
			case errors.Is(err, c2.ErrUnsupportedTaskType), errors.Is(err, c2.ErrTaskQueueFull):
				status = http.StatusBadRequest
			case errors.Is(err, c2.ErrEngagementKilled):
				status = http.StatusForbidden
			}
			writeJSON(w, status, ErrorResponse{Error: err.Error()})
			return
		}
		if sh.auditor != nil {
			identity, _ := authz.FromContext(r.Context())
			operator := identity.OperatorID
			if operator == "" {
				operator = identity.Username
			}
			_ = sh.auditor.Log(operator, sess.EngagementID, sessionID,
				audit.EventSessionInteract, "task."+req.Type,
				taskargs.Target(req.Type, req.Args), "queued",
				map[string]any{"task_id": taskID}, r.RemoteAddr, "")
		}
		writeJSON(w, http.StatusCreated, TaskResponse{TaskID: taskID})

	case "tasks":
		sh.handleSessionTasks(w, r, sessionID)

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
		// Locks are held in memory alongside the session they protect; a lock
		// on a disconnected session would be meaningless.
		if err := sh.implantServer.LockSession(sessionID, body.Operator); err != nil {
			if errors.Is(err, c2.ErrSessionNotFound) {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "locked", "locked_by": body.Operator})

	case "unlock":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		if err := sh.implantServer.UnlockSession(sessionID); err != nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})

	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
	}
}

func (sh *sessionHandler) handleTaskResult(w http.ResponseWriter, r *http.Request) {
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
	result := sh.implantServer.GetResult(taskID)
	if result == nil && sh.db != nil {
		// Find (rather than First) avoids GORM logging a "record not found"
		// error on every poll while a task is still running.
		var row models.TaskResult
		res := sh.db.Where("task_id = ?", taskID).Limit(1).Find(&row)
		if res.Error == nil && res.RowsAffected == 1 {
			writeJSON(w, http.StatusOK, c2.TaskResult{
				TaskID:      row.TaskID,
				SessionID:   row.SessionID,
				Success:     row.Success,
				Output:      row.Output,
				Error:       row.Error,
				Truncated:   row.Truncated,
				Bytes:       row.Bytes,
				CompletedAt: row.CompletedAt,
			})
			return
		}
	}
	if result == nil {
		writeJSON(w, http.StatusOK, PendingResponse{Status: "pending"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (sh *sessionHandler) handleSessionHistory(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}
	if sh.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "database unavailable"})
		return
	}

	engagementID := r.URL.Query().Get("engagement_id")
	limit := parseLimit(r.URL.Query().Get("limit"), 100)
	rows, err := repository.NewSessionRepository(sh.db).List(engagementID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	writeJSON(w, http.StatusOK, rows)
}

func (sh *sessionHandler) handleSessionTasks(w http.ResponseWriter, r *http.Request, sessionID string) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}
	if sh.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "database unavailable"})
		return
	}

	limit := parseLimit(r.URL.Query().Get("limit"), 100)
	rows, err := repository.NewTaskRepository(sh.db).ListBySession(sessionID, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func parseLimit(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > 1000 {
		return 1000
	}
	return n
}
