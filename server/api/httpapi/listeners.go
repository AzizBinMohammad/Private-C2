package httpapi

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

// listenerHandler starts and stops real listeners.
//
// Listener status used to be a database column that no socket backed: creating
// one stored status "running" and returned 201 without binding anything, so the
// portal showed an active listener that could not accept a connection. Status
// and connection counts now come from the running listener itself; the database
// row is kept as the record of what was configured.
type listenerHandler struct {
	db            *gorm.DB
	implantServer *c2.ImplantServer
	tlsConfig     *tls.Config
}

// createListenerRequest is the body accepted by POST /api/listeners.
//
// Port is a pointer so an omitted port can be rejected while an explicit 0
// means "let the OS choose a free port".
type createListenerRequest struct {
	Type         string `json:"type"`
	BindAddr     string `json:"bind_addr"`
	Port         *int   `json:"port"`
	EngagementID string `json:"engagement_id"`
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
		lh.listListeners(w)
	case http.MethodPost:
		lh.createListener(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
	}
}

// listListeners returns the configured listeners, with status and connection
// counts taken from the running processes rather than from the stored row.
func (lh *listenerHandler) listListeners(w http.ResponseWriter) {
	var stored []models.Listener
	if err := lh.db.Find(&stored).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	live := make(map[string]c2.ListenerInfo)
	for _, info := range lh.implantServer.Listeners() {
		live[info.ID] = info
	}

	out := make([]c2.ListenerInfo, 0, len(stored)+len(live))
	for _, rec := range stored {
		info := c2.ListenerInfo{
			ID:           rec.ID,
			Type:         rec.Type,
			BindAddr:     rec.BindAddr,
			Port:         rec.Port,
			EngagementID: rec.EngagementID,
			Status:       "stopped",
		}
		if running, ok := live[rec.ID]; ok {
			info.Status = running.Status
			info.ActiveConnections = running.ActiveConnections
			delete(live, rec.ID)
		}
		out = append(out, info)
	}

	// Listeners started outside the API (such as the one cmd/server binds at
	// startup) have no stored row; report them too rather than hiding live
	// state.
	for _, info := range live {
		out = append(out, info)
	}

	writeJSON(w, http.StatusOK, out)
}

func (lh *listenerHandler) createListener(w http.ResponseWriter, r *http.Request) {
	var req createListenerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}
	if req.Type == "" || req.Port == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "type and port are required"})
		return
	}
	if req.BindAddr == "" {
		req.BindAddr = "0.0.0.0"
	}

	info, err := lh.implantServer.StartListener(c2.ListenerConfig{
		Type:         req.Type,
		BindAddr:     req.BindAddr,
		Port:         *req.Port,
		EngagementID: req.EngagementID,
		TLSConfig:    lh.tlsConfig,
	})
	if err != nil {
		// Distinguish "you asked for something unimplemented" from "the bind
		// failed"; both are the client's to fix, so both are 400.
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	record := models.Listener{
		Type:         info.Type,
		BindAddr:     info.BindAddr,
		Port:         info.Port,
		EngagementID: info.EngagementID,
		Status:       info.Status,
	}
	record.ID = info.ID
	if err := lh.db.Create(&record).Error; err != nil {
		// The listener is bound; do not leave it running without a record.
		if stopErr := lh.implantServer.StopListener(info.ID); stopErr != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "storing listener: " + err.Error() + "; also failed to stop it: " + stopErr.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "storing listener: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, info)
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

	listenerID := path
	if listenerID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing listener ID"})
		return
	}
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	// Stop first: a stored row whose socket is still bound would be worse than
	// either failing alone.
	stopErr := lh.implantServer.StopListener(listenerID)
	if stopErr != nil && !errors.Is(stopErr, c2.ErrListenerNotFound) {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: stopErr.Error()})
		return
	}

	res := lh.db.Where("id = ?", listenerID).Delete(&models.Listener{})
	if res.Error != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 && errors.Is(stopErr, c2.ErrListenerNotFound) {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "listener not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}
