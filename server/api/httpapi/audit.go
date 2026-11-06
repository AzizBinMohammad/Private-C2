package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type auditHandler struct {
	db *gorm.DB
}

func (ah *auditHandler) handleAuditList(w http.ResponseWriter, r *http.Request) {
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

	query := ah.db.Model(&models.AuditEntry{})

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
}

func (ah *auditHandler) handleAuditDetail(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/audit/")
	if path == "export" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		format := audit.ExportFormat(r.URL.Query().Get("format"))
		if format == "" {
			format = audit.FormatJSON
		}
		var rows []models.AuditEntry
		if err := ah.db.Order("created_at ASC").Limit(100000).Find(&rows).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		entries := make([]audit.Entry, 0, len(rows))
		for _, row := range rows {
			entry, err := models.AuditEntryToLib(row)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "invalid audit row: " + err.Error()})
				return
			}
			entries = append(entries, entry)
		}

		ext := string(format)
		contentType := "application/json"
		switch format {
		case audit.FormatCEF, audit.FormatLEEF:
			contentType = "text/plain"
		case audit.FormatJSON:
		default:
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "unsupported export format: " + string(format)})
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"audit.%s\"", ext))
		if err := audit.Export(w, entries, format); err != nil {
			// Headers are already written; log the failure in the response body
			// is not possible. The caller still receives the partial export.
			return
		}
		return
	}

	if path == "verify" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		// Verify audit hash chain integrity
		var entries []models.AuditEntry
		if err := ah.db.Order("created_at ASC").Find(&entries).Error; err != nil {
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
		for i, row := range entries {
			if i > 0 && row.PreviousHash != prevHash {
				valid = false
				brokenAt = i
				break
			}
			entry, err := models.AuditEntryToLib(row)
			if err != nil {
				valid = false
				brokenAt = i
				break
			}
			prevHash = audit.ComputeEntryHash(entry)
			if row.EntryHash != prevHash {
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
}
