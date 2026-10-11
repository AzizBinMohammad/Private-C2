package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

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
		if err := oh.db.Create(&op).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		// Also register the operator in the auth system
		oh.auth.SetPassword(body.Name, body.Password)
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
	res := oh.db.Where("id = ?", opID).Delete(&models.Operator{})
	if res.Error != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "operator not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
