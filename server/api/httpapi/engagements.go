package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/engagement"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type engagementHandler struct {
	db            *gorm.DB
	implantServer *c2.ImplantServer
}

func (eh *engagementHandler) handleEngagements(w http.ResponseWriter, r *http.Request) {
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
		if err := eh.db.Find(&engagements).Error; err != nil {
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
		if err := eh.db.Create(&eng).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, eng)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
	}
}

func (eh *engagementHandler) handleEngagementDetail(w http.ResponseWriter, r *http.Request) {
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
			if err := eh.db.First(&eng, "id = ?", engID).Error; err != nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
				return
			}
			writeJSON(w, http.StatusOK, eng)
		case http.MethodPut:
			var eng models.Engagement
			if err := eh.db.First(&eng, "id = ?", engID).Error; err != nil {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
				return
			}
			var updates models.Engagement
			if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
				return
			}
			if err := eh.db.Model(&eng).Updates(updates).Error; err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}
			// Reload to return the full updated record
			eh.db.First(&eng, "id = ?", engID)
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
		reason := "operator activated kill switch"
		now := time.Now()
		res := eh.db.Model(&models.Engagement{}).Where("id = ?", engID).Updates(map[string]any{
			"status":             "killed",
			"kill_switch_active": true,
			"killed_at":          &now,
			"kill_reason":        reason,
		})
		if res.Error != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
			return
		}
		if res.RowsAffected == 0 {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
			return
		}
		closed := 0
		if eh.implantServer != nil {
			closed = eh.implantServer.KillEngagement(engID, reason)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":          "killed",
			"sessions_closed": closed,
		})

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
		if err := eh.db.First(&eng, "id = ?", engID).Error; err != nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
			return
		}

		if eng.ScopeConfig == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"target":   body.Target,
				"in_scope": false,
				"reason":   "no scope configured",
			})
			return
		}

		var scopeCfg struct {
			CIDRs     []string `json:"cidrs"`
			Hostnames []string `json:"hostnames"`
			Hosts     []string `json:"hosts"`
			Targets   []string `json:"targets"`
			Domains   []string `json:"domains"`
			Excluded  []string `json:"excluded"`
		}
		if err := json.Unmarshal([]byte(eng.ScopeConfig), &scopeCfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "invalid scope config: " + err.Error()})
			return
		}

		allHosts := append(scopeCfg.Hostnames, scopeCfg.Hosts...)
		allHosts = append(allHosts, scopeCfg.Targets...)

		scope, err := engagement.NewScope(scopeCfg.CIDRs, allHosts, scopeCfg.Domains, scopeCfg.Excluded)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "invalid scope config: " + err.Error()})
			return
		}

		inScope, reason := scope.Contains(body.Target)
		resp := map[string]interface{}{
			"target":   body.Target,
			"in_scope": inScope,
		}
		if reason != "" {
			resp["reason"] = reason
		}
		writeJSON(w, http.StatusOK, resp)

	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
	}
}
