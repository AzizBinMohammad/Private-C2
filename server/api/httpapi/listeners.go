package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type listenerHandler struct {
	db *gorm.DB
}

func (lh *listenerHandler) handleListeners(w http.ResponseWriter, r *http.Request) {
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
		if err := lh.db.Find(&listeners).Error; err != nil {
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
		if err := lh.db.Create(&listener).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, listener)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
	}
}

func (lh *listenerHandler) handleListenerDetail(w http.ResponseWriter, r *http.Request) {
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
		if err := lh.db.Find(&profiles).Error; err != nil {
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
	res := lh.db.Where("id = ?", listenerID).Delete(&models.Listener{})
	if res.Error != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "listener not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
