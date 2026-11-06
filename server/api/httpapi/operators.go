package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type operatorHandler struct {
	db   *gorm.DB
	auth *AuthManager
}

func (oh *operatorHandler) handleOperators(w http.ResponseWriter, r *http.Request) {
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
		if err := oh.db.Find(&operators).Error; err != nil {
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
		if !authz.KnownRole(body.Role) {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "unknown role: " + body.Role})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to hash password"})
			return
		}
		op := models.Operator{
			Name:         body.Name,
			Role:         body.Role,
			PasswordHash: hash,
		}
		if err := oh.db.Create(&op).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		oh.auth.SetUser(body.Name, hash, body.Role, op.ID)
		writeJSON(w, http.StatusCreated, op)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
	}
}

func (oh *operatorHandler) handleOperatorDetail(w http.ResponseWriter, r *http.Request) {
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
	var op models.Operator
	if err := oh.db.Unscoped().First(&op, "id = ?", opID).Error; err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "operator not found"})
		return
	}
	// Hard delete so the unique name can be reused and no soft-deleted row is
	// left behind; auth credentials and tokens are revoked below.
	if err := oh.db.Unscoped().Delete(&op).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	oh.auth.RemoveUser(op.Name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
