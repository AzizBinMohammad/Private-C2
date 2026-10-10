package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestRouter(t *testing.T) (http.Handler, *c2.ImplantServer, *gorm.DB) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := store.Open(store.Config{
		Dialect:  "sqlite",
		DSN:      dbPath,
		LogLevel: logger.Silent,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	srv := c2.NewImplantServer()
	router := NewRouter(srv, db)
	return router, srv, db
}

// getAuthToken logs in as admin/admin and returns the bearer token.
func getAuthToken(t *testing.T, router http.Handler) string {
	t.Helper()
	body := `{"username":"admin","password":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	var resp LoginResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return resp.Token
}

// registerImplant connects an implant via net.Pipe so the session appears
// in the ImplantServer. Returns the session ID and a cleanup function.
func registerImplant(t *testing.T, srv *c2.ImplantServer) (string, func()) {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.HandleConnection(serverConn)
	}()

	// Send register.
	regData, _ := json.Marshal(protocol.RegisterData{
		ImplantID: "test-implant",
		Hostname:  "test-host",
		Username:  "testuser",
		OS:        "linux",
		Arch:      "amd64",
		PID:       9999,
		Process:   "test",
		Mode:      "beacon",
	})
	msg := protocol.Message{Type: "register", Data: json.RawMessage(regData)}
	frame, _ := json.Marshal(msg)
	if err := envelope.WriteFrame(clientConn, frame); err != nil {
		t.Fatalf("write register: %v", err)
	}

	// Read ack.
	ackFrame, err := envelope.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	var ackMsg protocol.Message
	json.Unmarshal(ackFrame, &ackMsg)
	var ack protocol.RegisterAckData
	json.Unmarshal(ackMsg.Data, &ack)

	cleanup := func() {
		clientConn.Close()
		wg.Wait()
	}

	return ack.SessionID, cleanup
}

// ── Flow 2: HTTP API Task Endpoints ──

func TestHTTP_PostTask_CreatesTask(t *testing.T) {
	router, srv, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	sessionID, cleanup := registerImplant(t, srv)
	defer cleanup()

	body := `{"type":"shell","args":"whoami"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sessionID+"/task", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp TaskResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TaskID == "" {
		t.Error("response has empty task_id")
	}
}

func TestHTTP_PostTask_MissingType(t *testing.T) {
	router, srv, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	sessionID, cleanup := registerImplant(t, srv)
	defer cleanup()

	body := `{"args":"whoami"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sessionID+"/task", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_PostTask_NonexistentSession(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"type":"shell","args":"whoami"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/fake-session/task", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_GetResult_Pending(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/tasks/nonexistent-task-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp PendingResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "pending" {
		t.Errorf("status = %q, want %q", resp.Status, "pending")
	}
}

func TestHTTP_GetSessions(t *testing.T) {
	router, srv, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	sessionID, cleanup := registerImplant(t, srv)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var sessions []json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	_ = sessionID // used only to verify registration
}

// ── Flow 3: Authentication + Token Validation ──

func TestAuth_ValidCredentials(t *testing.T) {
	am := NewAuthManager()
	if !am.authenticate("admin", "admin") {
		t.Error("valid admin/admin credentials rejected")
	}
}

func TestAuth_InvalidPassword(t *testing.T) {
	am := NewAuthManager()
	if am.authenticate("admin", "wrong") {
		t.Error("invalid password accepted")
	}
}

func TestAuth_NonexistentUser(t *testing.T) {
	am := NewAuthManager()
	if am.authenticate("nobody", "admin") {
		t.Error("nonexistent user accepted")
	}
}

func TestAuth_SetPassword(t *testing.T) {
	am := NewAuthManager()
	if err := am.SetPassword("newuser", "secret123"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !am.authenticate("newuser", "secret123") {
		t.Error("new credentials rejected")
	}
	if am.authenticate("newuser", "wrong") {
		t.Error("wrong password accepted for new user")
	}
}

func TestAuth_SetPassword_OverridesOld(t *testing.T) {
	am := NewAuthManager()
	am.SetPassword("admin", "newpass")
	if am.authenticate("admin", "admin") {
		t.Error("old password still works")
	}
	if !am.authenticate("admin", "newpass") {
		t.Error("new password rejected")
	}
}

func TestAuth_TokenFormat(t *testing.T) {
	am := NewAuthManager()
	tok := am.issueToken("admin")
	if len(tok) != 64 {
		t.Errorf("token length = %d, want 64 hex chars", len(tok))
	}
}

func TestAuth_ValidateToken(t *testing.T) {
	am := NewAuthManager()
	tok := am.issueToken("admin")
	user, ok := am.validateToken(tok)
	if !ok {
		t.Fatal("valid token rejected")
	}
	if user != "admin" {
		t.Errorf("username = %q, want %q", user, "admin")
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	am := NewAuthManager()
	_, ok := am.validateToken("bogus-token")
	if ok {
		t.Error("bogus token accepted")
	}
}

func TestAuth_ExpiredToken(t *testing.T) {
	am := NewAuthManager()
	tok := am.issueToken("admin")

	// Manually expire the token by setting expiresAt in the past.
	am.mu.Lock()
	am.tokens[tok].expiresAt = time.Now().Add(-1 * time.Hour)
	am.mu.Unlock()

	_, ok := am.validateToken(tok)
	if ok {
		t.Error("expired token accepted")
	}
}

func TestAuth_LoginHandler_Success(t *testing.T) {
	am := NewAuthManager()
	handler := am.LoginHandler()

	body := `{"username":"admin","password":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp LoginResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("empty token in response")
	}
}

func TestAuth_LoginHandler_BadPassword(t *testing.T) {
	am := NewAuthManager()
	handler := am.LoginHandler()

	body := `{"username":"admin","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuth_LoginHandler_EmptyFields(t *testing.T) {
	am := NewAuthManager()
	handler := am.LoginHandler()

	for _, body := range []string{
		`{"username":"","password":"admin"}`,
		`{"username":"admin","password":""}`,
		`{"username":"","password":""}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s: expected 400, got %d", body, w.Code)
		}
	}
}

func TestAuth_Middleware_ValidToken(t *testing.T) {
	am := NewAuthManager()
	tok := am.issueToken("admin")

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	am.Middleware(inner).ServeHTTP(w, req)

	if !called {
		t.Error("inner handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuth_Middleware_MissingHeader(t *testing.T) {
	am := NewAuthManager()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	am.Middleware(inner).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuth_Middleware_MalformedHeader(t *testing.T) {
	am := NewAuthManager()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	for _, hdr := range []string{"Basic abc", "Token abc", "bearer abc"} {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", hdr)
		w := httptest.NewRecorder()
		am.Middleware(inner).ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("header=%q: expected 401, got %d", hdr, w.Code)
		}
	}
}

func TestAuth_Middleware_ExpiredToken(t *testing.T) {
	am := NewAuthManager()
	tok := am.issueToken("admin")

	am.mu.Lock()
	am.tokens[tok].expiresAt = time.Now().Add(-1 * time.Hour)
	am.mu.Unlock()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	am.Middleware(inner).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuth_ConcurrentLogins(t *testing.T) {
	am := NewAuthManager()
	handler := am.LoginHandler()

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan string, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := `{"username":"admin","password":"admin"}`
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				errs <- w.Body.String()
			}
		}()
	}

	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent login failed: %s", e)
	}
}

func TestHTTP_ProtectedEndpoint_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthed request, got %d", w.Code)
	}
}

// ── Flow 4: Scope Enforcement (HTTP API) ──

func TestHTTP_ScopeCheck_InScope(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	// Create an engagement with scope config.
	eng := models.Engagement{
		Name:        "Test Engagement",
		ScopeConfig: `{"cidrs":["10.0.0.0/24"],"hosts":["server1.internal"]}`,
	}
	db.Create(&eng)

	body := `{"target":"10.0.0.0/24"}`
	req := httptest.NewRequest(http.MethodPost, "/api/engagements/"+eng.ID+"/scope-check", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["in_scope"] != true {
		t.Errorf("target in scope config should be in_scope=true, got %v", result["in_scope"])
	}
}

func TestHTTP_ScopeCheck_OutOfScope(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{
		Name:        "Test Engagement",
		ScopeConfig: `{"cidrs":["10.0.0.0/24"]}`,
	}
	db.Create(&eng)

	body := `{"target":"192.168.1.1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/engagements/"+eng.ID+"/scope-check", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["in_scope"] != false {
		t.Errorf("target not in scope config should be in_scope=false, got %v", result["in_scope"])
	}
}

func TestHTTP_ScopeCheck_MissingTarget(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{
		Name:        "Test Engagement",
		ScopeConfig: `{"cidrs":["10.0.0.0/24"]}`,
	}
	db.Create(&eng)

	body := `{"target":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/engagements/"+eng.ID+"/scope-check", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty target, got %d", w.Code)
	}
}

func TestHTTP_ScopeCheck_EngagementNotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"target":"10.0.0.1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/engagements/nonexistent/scope-check", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ── Flow 5: Audit Log Hash Chain Verification (API endpoint) ──

func TestHTTP_AuditVerify_EmptyLog(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["valid"] != true {
		t.Errorf("empty log should be valid, got %v", result["valid"])
	}
	if result["entries"].(float64) != 0 {
		t.Errorf("expected 0 entries, got %v", result["entries"])
	}
}

func TestHTTP_AuditVerify_ValidChain(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	// Insert entries using the handler.go hash algorithm:
	// sha256(id + created_at_RFC3339Nano + action + previous_hash)
	insertAuditChain(t, db, 5)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["valid"] != true {
		t.Errorf("valid chain should pass verification, got %v (message: %v)", result["valid"], result["message"])
	}
}

func TestHTTP_AuditVerify_BrokenChain(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	insertAuditChain(t, db, 5)

	// Tamper with entry 3 by changing its action.
	var entries []models.AuditEntry
	db.Order("created_at ASC").Find(&entries)
	db.Model(&entries[2]).Update("action", "TAMPERED")

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["valid"] != false {
		t.Error("tampered chain should fail verification")
	}
}

func TestHTTP_AuditVerify_SingleEntry(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	insertAuditChain(t, db, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["valid"] != true {
		t.Errorf("single-entry log should be valid, got %v", result["valid"])
	}
}

// insertAuditChain inserts n audit entries using the handler.go hash algorithm
// (sha256(id + created_at_RFC3339Nano + action + previous_hash)).
func insertAuditChain(t *testing.T, db *gorm.DB, n int) {
	t.Helper()
	prevHash := ""
	base := time.Now().Add(-time.Duration(n) * time.Minute)

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("audit-%03d", i)
		createdAt := base.Add(time.Duration(i) * time.Minute)
		action := fmt.Sprintf("action-%d", i)

		h := sha256.New()
		h.Write([]byte(id))
		h.Write([]byte(createdAt.Format(time.RFC3339Nano)))
		h.Write([]byte(action))
		h.Write([]byte(prevHash))
		entryHash := hex.EncodeToString(h.Sum(nil))

		entry := models.AuditEntry{
			ID:           id,
			CreatedAt:    createdAt,
			OperatorID:   "test-op",
			EventType:    "test",
			Action:       action,
			PreviousHash: prevHash,
			EntryHash:    entryHash,
		}
		if err := db.Create(&entry).Error; err != nil {
			t.Fatalf("insert audit entry %d: %v", i, err)
		}
		prevHash = entryHash
	}
}

func TestHTTP_GetSession_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
