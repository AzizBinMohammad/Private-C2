package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"golang.org/x/crypto/bcrypt"
)

func createTestOperator(t *testing.T, router http.Handler, adminToken, name, role, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"name": name, "role": role, "password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/operators", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create operator %s: %d %s", name, w.Code, w.Body.String())
	}
	var op models.Operator
	if err := json.Unmarshal(w.Body.Bytes(), &op); err != nil {
		t.Fatalf("decode operator: %v", err)
	}
	return op.ID
}

func loginToken(t *testing.T, router http.Handler, username, password string) (string, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return "", w.Code
	}
	var resp LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	return resp.Token, w.Code
}

func request(t *testing.T, router http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBuffer(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRBAC_ObserverIsReadOnly(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	admin := getAuthToken(t, router)
	createTestOperator(t, router, admin, "observer1", "observer", "password1")

	token, status := loginToken(t, router, "observer1", "password1")
	if status != http.StatusOK {
		t.Fatalf("observer login = %d", status)
	}

	if w := request(t, router, http.MethodGet, "/api/sessions", token, nil); w.Code != http.StatusOK {
		t.Fatalf("observer GET sessions = %d: %s", w.Code, w.Body.String())
	}
	if w := request(t, router, http.MethodGet, "/api/audit", token, nil); w.Code != http.StatusOK {
		t.Fatalf("observer GET audit = %d: %s", w.Code, w.Body.String())
	}
	if w := request(t, router, http.MethodPost, "/api/sessions/missing/task", token, []byte(`{"type":"shell","args":"id"}`)); w.Code != http.StatusForbidden {
		t.Fatalf("observer task = %d, want 403: %s", w.Code, w.Body.String())
	}
	if w := request(t, router, http.MethodGet, "/api/operators", token, nil); w.Code != http.StatusForbidden {
		t.Fatalf("observer operators = %d, want 403", w.Code)
	}
	if w := request(t, router, http.MethodPost, "/api/payloads/generate", token, []byte(`{"target_os":"linux"}`)); w.Code != http.StatusForbidden {
		t.Fatalf("observer payload build = %d, want 403", w.Code)
	}
}

func TestRBAC_BuilderCannotTask(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	admin := getAuthToken(t, router)
	createTestOperator(t, router, admin, "builder1", "builder", "password1")

	token, status := loginToken(t, router, "builder1", "password1")
	if status != http.StatusOK {
		t.Fatalf("builder login = %d", status)
	}

	// The permission gate passes, so the handler validates the body (400)
	// rather than returning 403.
	w := request(t, router, http.MethodPost, "/api/payloads/generate", token, []byte(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("builder payload generate = %d, want 400: %s", w.Code, w.Body.String())
	}
	if w := request(t, router, http.MethodPost, "/api/sessions/missing/task", token, []byte(`{"type":"shell","args":"id"}`)); w.Code != http.StatusForbidden {
		t.Fatalf("builder task = %d, want 403", w.Code)
	}
}

func TestAuth_LogoutRevokesToken(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	if w := request(t, router, http.MethodPost, "/api/auth/logout", token, nil); w.Code != http.StatusOK {
		t.Fatalf("logout = %d: %s", w.Code, w.Body.String())
	}
	if w := request(t, router, http.MethodGet, "/api/sessions", token, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("token still valid after logout: %d", w.Code)
	}
}

func TestAuth_DeleteOperatorRevokesCredentials(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	admin := getAuthToken(t, router)
	opID := createTestOperator(t, router, admin, "todelete", "operator", "password1")

	opToken, status := loginToken(t, router, "todelete", "password1")
	if status != http.StatusOK {
		t.Fatalf("operator login = %d", status)
	}

	if w := request(t, router, http.MethodDelete, "/api/operators/"+opID, admin, nil); w.Code != http.StatusOK {
		t.Fatalf("delete operator = %d: %s", w.Code, w.Body.String())
	}
	if w := request(t, router, http.MethodGet, "/api/sessions", opToken, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("deleted operator token still valid: %d", w.Code)
	}
	if _, status := loginToken(t, router, "todelete", "password1"); status != http.StatusUnauthorized {
		t.Fatalf("deleted operator can still log in: %d", status)
	}
}

func TestAuth_HydratesOperatorFromDatabase(t *testing.T) {
	router, srv, db := setupTestRouter(t)
	_ = router

	hash, err := bcrypt.GenerateFromPassword([]byte("dbpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	op := &models.Operator{Name: "dbuser", Role: "observer", PasswordHash: hash}
	if err := db.Create(op).Error; err != nil {
		t.Fatalf("create operator: %v", err)
	}

	// A new router (and therefore a new in-memory auth manager) must load the
	// operator from the database.
	newRouter := NewRouter(srv, db, testListenerTLSConfig(t))
	if _, status := loginToken(t, newRouter, "dbuser", "dbpassword"); status != http.StatusOK {
		t.Fatalf("DB-backed operator login = %d", status)
	}
}

func TestCreateOperator_UnknownRoleRejected(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	admin := getAuthToken(t, router)

	body := []byte(`{"name":"badrole","password":"password1","role":"superuser"}`)
	if w := request(t, router, http.MethodPost, "/api/operators", admin, body); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown role = %d, want 400: %s", w.Code, w.Body.String())
	}
}
