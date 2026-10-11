package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/pkg/envelope"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func init() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	newAuthManagerFn = func() *AuthManager {
		return &AuthManager{
			users:  map[string][]byte{"admin": hash},
			tokens: make(map[string]*tokenEntry),
		}
	}
}

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

func insertAuditChain(t *testing.T, db *gorm.DB, n int) {
	t.Helper()
	prevHash := ""
	base := time.Now().Add(-time.Duration(n) * time.Minute)

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("audit-%03d", i)
		createdAt := base.Add(time.Duration(i) * time.Minute)
		action := fmt.Sprintf("action-%d", i)
		operatorID := "test-op"
		eventType := "test"

		entryHash := audit.ComputeHash(id, createdAt, operatorID, audit.EventType(eventType), action, prevHash)

		entry := models.AuditEntry{
			ID:           id,
			CreatedAt:    createdAt,
			OperatorID:   operatorID,
			EventType:    eventType,
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

// ── Beacon Endpoints ──

func TestHTTP_ListBeacons_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/beacons", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var beacons []models.Beacon
	if err := json.NewDecoder(w.Body).Decode(&beacons); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(beacons) != 0 {
		t.Errorf("expected 0 beacons, got %d", len(beacons))
	}
}

func TestHTTP_ListBeacons_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.Beacon{Hostname: "plc-01", OS: "linux", Arch: "amd64"})
	db.Create(&models.Beacon{Hostname: "hmi-02", OS: "windows", Arch: "amd64"})

	req := httptest.NewRequest(http.MethodGet, "/api/beacons", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var beacons []models.Beacon
	json.NewDecoder(w.Body).Decode(&beacons)
	if len(beacons) != 2 {
		t.Errorf("expected 2 beacons, got %d", len(beacons))
	}
}

func TestHTTP_ListBeacons_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/beacons", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_ListBeacons_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/beacons", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── Listener Endpoints ──

func TestHTTP_ListListeners_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/listeners", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var listeners []models.Listener
	json.NewDecoder(w.Body).Decode(&listeners)
	if len(listeners) != 0 {
		t.Errorf("expected 0 listeners, got %d", len(listeners))
	}
}

func TestHTTP_CreateListener_Success(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"type":"https","bind_addr":"0.0.0.0","port":4444}`
	req := httptest.NewRequest(http.MethodPost, "/api/listeners", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var listener models.Listener
	json.NewDecoder(w.Body).Decode(&listener)
	if listener.ID == "" {
		t.Error("listener ID should be set")
	}
	if listener.Status != "running" {
		t.Errorf("status = %q, want %q", listener.Status, "running")
	}
	if listener.Type != "https" {
		t.Errorf("type = %q, want %q", listener.Type, "https")
	}
}

func TestHTTP_CreateListener_MissingFields(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	for _, body := range []string{
		`{"type":"","bind_addr":"0.0.0.0","port":4444}`,
		`{"type":"https","bind_addr":"","port":4444}`,
		`{"type":"https","bind_addr":"0.0.0.0","port":0}`,
		`{"type":"https","bind_addr":"0.0.0.0"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/listeners", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s: expected 400, got %d", body, w.Code)
		}
	}
}

func TestHTTP_CreateListener_InvalidJSON(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/listeners", bytes.NewBufferString(`{invalid`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_CreateThenListListeners(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"type":"dns","bind_addr":"0.0.0.0","port":5353}`
	req := httptest.NewRequest(http.MethodPost, "/api/listeners", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/listeners", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var listeners []models.Listener
	json.NewDecoder(w.Body).Decode(&listeners)
	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(listeners))
	}
	if listeners[0].Type != "dns" {
		t.Errorf("type = %q, want %q", listeners[0].Type, "dns")
	}
}

func TestHTTP_DeleteListener_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	l := models.Listener{Type: "https", BindAddr: "0.0.0.0", Port: 4444, Status: "running"}
	db.Create(&l)

	req := httptest.NewRequest(http.MethodDelete, "/api/listeners/"+l.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify it's gone.
	req = httptest.NewRequest(http.MethodGet, "/api/listeners", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var remaining []models.Listener
	json.NewDecoder(w.Body).Decode(&remaining)
	if len(remaining) != 0 {
		t.Errorf("expected 0 listeners after delete, got %d", len(remaining))
	}
}

func TestHTTP_DeleteListener_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodDelete, "/api/listeners/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_DeleteListener_MethodNotAllowed(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	l := models.Listener{Type: "https", BindAddr: "0.0.0.0", Port: 4444, Status: "running"}
	db.Create(&l)

	req := httptest.NewRequest(http.MethodPut, "/api/listeners/"+l.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_ListProfiles_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/listeners/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var profiles []models.C2Profile
	json.NewDecoder(w.Body).Decode(&profiles)
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(profiles))
	}
}

func TestHTTP_ListProfiles_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.C2Profile{Name: "default", Config: `{"jitter":0.2}`, Version: 1})

	req := httptest.NewRequest(http.MethodGet, "/api/listeners/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var profiles []models.C2Profile
	json.NewDecoder(w.Body).Decode(&profiles)
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].Name != "default" {
		t.Errorf("name = %q, want %q", profiles[0].Name, "default")
	}
}

func TestHTTP_ListProfiles_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/listeners/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── Engagement Endpoints ──

func TestHTTP_ListEngagements_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/engagements", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var engagements []models.Engagement
	json.NewDecoder(w.Body).Decode(&engagements)
	if len(engagements) != 0 {
		t.Errorf("expected 0 engagements, got %d", len(engagements))
	}
}

func TestHTTP_CreateEngagement_Success(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"name":"Red Team Q4","description":"Quarterly assessment","scope_config":"{\"cidrs\":[\"10.0.0.0/8\"]}"}`
	req := httptest.NewRequest(http.MethodPost, "/api/engagements", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var eng models.Engagement
	json.NewDecoder(w.Body).Decode(&eng)
	if eng.ID == "" {
		t.Error("engagement ID should be set")
	}
	if eng.Name != "Red Team Q4" {
		t.Errorf("name = %q, want %q", eng.Name, "Red Team Q4")
	}
}

func TestHTTP_CreateEngagement_MissingName(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"description":"no name given"}`
	req := httptest.NewRequest(http.MethodPost, "/api/engagements", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_CreateEngagement_InvalidJSON(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/engagements", bytes.NewBufferString(`not json`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_GetEngagement_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{Name: "Pentest Alpha", Description: "Initial access assessment"}
	db.Create(&eng)

	req := httptest.NewRequest(http.MethodGet, "/api/engagements/"+eng.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got models.Engagement
	json.NewDecoder(w.Body).Decode(&got)
	if got.Name != "Pentest Alpha" {
		t.Errorf("name = %q, want %q", got.Name, "Pentest Alpha")
	}
}

func TestHTTP_GetEngagement_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/engagements/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_UpdateEngagement_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{Name: "Original Name", Description: "Original desc"}
	db.Create(&eng)

	body := `{"description":"Updated description"}`
	req := httptest.NewRequest(http.MethodPut, "/api/engagements/"+eng.ID, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var updated models.Engagement
	json.NewDecoder(w.Body).Decode(&updated)
	if updated.Description != "Updated description" {
		t.Errorf("description = %q, want %q", updated.Description, "Updated description")
	}
	if updated.Name != "Original Name" {
		t.Errorf("name should remain %q, got %q", "Original Name", updated.Name)
	}
}

func TestHTTP_UpdateEngagement_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"description":"nope"}`
	req := httptest.NewRequest(http.MethodPut, "/api/engagements/nonexistent", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_UpdateEngagement_InvalidJSON(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{Name: "Test Eng"}
	db.Create(&eng)

	req := httptest.NewRequest(http.MethodPut, "/api/engagements/"+eng.ID, bytes.NewBufferString(`{bad`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_KillswitchEngagement_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{Name: "Active Engagement", Status: "active"}
	db.Create(&eng)

	req := httptest.NewRequest(http.MethodPost, "/api/engagements/"+eng.ID+"/killswitch", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "killed" {
		t.Errorf("status = %q, want %q", result["status"], "killed")
	}

	// Verify the DB was updated.
	var reloaded models.Engagement
	db.First(&reloaded, "id = ?", eng.ID)
	if reloaded.Status != "killed" {
		t.Errorf("db status = %q, want %q", reloaded.Status, "killed")
	}
}

func TestHTTP_KillswitchEngagement_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/engagements/nonexistent/killswitch", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_KillswitchEngagement_MethodNotAllowed(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{Name: "Test", Status: "active"}
	db.Create(&eng)

	req := httptest.NewRequest(http.MethodGet, "/api/engagements/"+eng.ID+"/killswitch", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_EngagementSubpath_NotFound(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	eng := models.Engagement{Name: "Test"}
	db.Create(&eng)

	req := httptest.NewRequest(http.MethodGet, "/api/engagements/"+eng.ID+"/bogus", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_Engagements_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodDelete, "/api/engagements", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Engagements_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/engagements", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHTTP_CreateThenGetEngagement(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"name":"Full Flow Engagement","scope_config":"{\"cidrs\":[\"192.168.0.0/16\"]}"}`
	req := httptest.NewRequest(http.MethodPost, "/api/engagements", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}
	var created models.Engagement
	json.NewDecoder(w.Body).Decode(&created)

	req = httptest.NewRequest(http.MethodGet, "/api/engagements/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", w.Code)
	}
	var fetched models.Engagement
	json.NewDecoder(w.Body).Decode(&fetched)
	if fetched.Name != "Full Flow Engagement" {
		t.Errorf("name = %q, want %q", fetched.Name, "Full Flow Engagement")
	}
}

// ── Payload Endpoints ──

func TestHTTP_ListPayloads_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var payloads []models.PayloadArtifact
	json.NewDecoder(w.Body).Decode(&payloads)
	if len(payloads) != 0 {
		t.Errorf("expected 0 payloads, got %d", len(payloads))
	}
}

func TestHTTP_ListPayloads_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.PayloadArtifact{TargetOS: "linux", TargetArch: "amd64", SHA256: "aaa"})
	db.Create(&models.PayloadArtifact{TargetOS: "windows", TargetArch: "amd64", SHA256: "bbb"})

	req := httptest.NewRequest(http.MethodGet, "/api/payloads", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var payloads []models.PayloadArtifact
	json.NewDecoder(w.Body).Decode(&payloads)
	if len(payloads) != 2 {
		t.Errorf("expected 2 payloads, got %d", len(payloads))
	}
}

func TestHTTP_ListPayloads_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/payloads", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_GetPayload_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	p := models.PayloadArtifact{TargetOS: "linux", TargetArch: "amd64", SHA256: "abc123", Status: "active"}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/"+p.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got models.PayloadArtifact
	json.NewDecoder(w.Body).Decode(&got)
	if got.TargetOS != "linux" {
		t.Errorf("target_os = %q, want %q", got.TargetOS, "linux")
	}
}

func TestHTTP_GetPayload_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_DownloadPayload_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	binary := []byte("MZ fake binary content")
	p := models.PayloadArtifact{
		TargetOS:   "windows",
		TargetArch: "amd64",
		SHA256:     "dl-test-hash",
		Status:     "active",
		BinaryData: binary,
	}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/"+p.ID+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Error("missing Content-Disposition header")
	}
	if w.Body.Len() != len(binary) {
		t.Errorf("body length = %d, want %d", w.Body.Len(), len(binary))
	}
}

func TestHTTP_DownloadPayload_WindowsDLL(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	p := models.PayloadArtifact{
		TargetOS:   "windows",
		TargetArch: "amd64",
		Format:     "dll",
		SHA256:     "dll-hash",
		Status:     "active",
		BinaryData: []byte("fake dll"),
	}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/"+p.ID+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	cd := w.Header().Get("Content-Disposition")
	if !bytes.Contains([]byte(cd), []byte(".dll")) {
		t.Errorf("Content-Disposition should contain .dll, got %q", cd)
	}
}

func TestHTTP_DownloadPayload_Revoked(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	secret := []byte("should not be served")
	p := models.PayloadArtifact{
		TargetOS:   "linux",
		TargetArch: "amd64",
		SHA256:     "revoked-hash",
		Status:     "revoked",
		BinaryData: secret,
	}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/"+p.ID+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for revoked payload, got %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), secret) {
		t.Error("response body must not contain the revoked payload's binary data")
	}
}

func TestHTTP_DownloadPayload_NoBinary(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	p := models.PayloadArtifact{
		TargetOS:   "linux",
		TargetArch: "amd64",
		SHA256:     "no-binary-hash",
		Status:     "active",
	}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/"+p.ID+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for empty binary, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "application/octet-stream" {
		t.Error("Content-Type should not be application/octet-stream when no binary exists")
	}
}

func TestHTTP_DownloadPayload_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/nonexistent/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_RevokePayload_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	p := models.PayloadArtifact{
		TargetOS:   "linux",
		TargetArch: "amd64",
		SHA256:     "revoke-test-hash",
		Status:     "active",
	}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodPost, "/api/payloads/"+p.ID+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "revoked" {
		t.Errorf("status = %q, want %q", result["status"], "revoked")
	}

	// Verify DB update.
	var reloaded models.PayloadArtifact
	db.First(&reloaded, "id = ?", p.ID)
	if reloaded.Status != "revoked" {
		t.Errorf("db status = %q, want %q", reloaded.Status, "revoked")
	}
}

func TestHTTP_RevokePayload_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/payloads/nonexistent/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_RevokePayload_MethodNotAllowed(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	p := models.PayloadArtifact{TargetOS: "linux", TargetArch: "amd64", SHA256: "revoke-method", Status: "active"}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/"+p.ID+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_GeneratePayload_MissingTargetOS(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"target_arch":"amd64"}`
	req := httptest.NewRequest(http.MethodPost, "/api/payloads/generate", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing target_os, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHTTP_GeneratePayload_InvalidJSON(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/payloads/generate", bytes.NewBufferString(`{bad`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_GeneratePayload_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/generate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Payloads_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHTTP_PayloadSubpath_NotFound(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	p := models.PayloadArtifact{TargetOS: "linux", TargetArch: "amd64", SHA256: "subpath-hash", Status: "active"}
	db.Create(&p)

	req := httptest.NewRequest(http.MethodGet, "/api/payloads/"+p.ID+"/bogus", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ── Operator Endpoints ──

func TestHTTP_ListOperators_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/operators", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var operators []models.Operator
	json.NewDecoder(w.Body).Decode(&operators)
	// Default admin is auth-only (in-memory), not a DB Operator record.
	if len(operators) != 0 {
		t.Errorf("expected 0 operators, got %d", len(operators))
	}
}

func TestHTTP_CreateThenListOperators(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"name":"listme","password":"pass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/operators", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/operators", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	var operators []models.Operator
	json.NewDecoder(w.Body).Decode(&operators)
	if len(operators) != 1 {
		t.Errorf("expected 1 operator, got %d", len(operators))
	}
}

func TestHTTP_CreateOperator_Success(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"name":"redteam1","password":"s3cret!","role":"operator"}`
	req := httptest.NewRequest(http.MethodPost, "/api/operators", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var op models.Operator
	json.NewDecoder(w.Body).Decode(&op)
	if op.ID == "" {
		t.Error("operator ID should be set")
	}
	if op.Name != "redteam1" {
		t.Errorf("name = %q, want %q", op.Name, "redteam1")
	}
	if op.Role != "operator" {
		t.Errorf("role = %q, want %q", op.Role, "operator")
	}
}

func TestHTTP_CreateOperator_DefaultRole(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"name":"norole","password":"pass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/operators", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var op models.Operator
	json.NewDecoder(w.Body).Decode(&op)
	if op.Role != "operator" {
		t.Errorf("role = %q, want default %q", op.Role, "operator")
	}
}

func TestHTTP_CreateOperator_MissingFields(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	for _, body := range []string{
		`{"name":"","password":"pass123"}`,
		`{"name":"user1","password":""}`,
		`{"name":"","password":""}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/operators", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s: expected 400, got %d", body, w.Code)
		}
	}
}

func TestHTTP_CreateOperator_InvalidJSON(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/operators", bytes.NewBufferString(`{nope`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_CreateOperator_CanLogin(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	body := `{"name":"logintest","password":"mypass"}`
	req := httptest.NewRequest(http.MethodPost, "/api/operators", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}

	// Verify the new operator can log in.
	loginBody := `{"username":"logintest","password":"mypass"}`
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHTTP_DeleteOperator_Success(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	op := models.Operator{Name: "todelete", Role: "operator"}
	db.Create(&op)

	req := httptest.NewRequest(http.MethodDelete, "/api/operators/"+op.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "deleted" {
		t.Errorf("status = %q, want %q", result["status"], "deleted")
	}
}

func TestHTTP_DeleteOperator_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodDelete, "/api/operators/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_DeleteOperator_MethodNotAllowed(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	op := models.Operator{Name: "noput", Role: "operator"}
	db.Create(&op)

	req := httptest.NewRequest(http.MethodPut, "/api/operators/"+op.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Operators_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodDelete, "/api/operators", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Operators_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/operators", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── Server Status Endpoint ──

func TestHTTP_ServerStatus_Success(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/server/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var status map[string]interface{}
	json.NewDecoder(w.Body).Decode(&status)

	for _, key := range []string{"version", "uptime_seconds", "active_sessions", "go_version", "goroutines", "memory_alloc", "os", "arch"} {
		if _, ok := status[key]; !ok {
			t.Errorf("missing key %q in status response", key)
		}
	}
}

func TestHTTP_ServerStatus_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/server/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_ServerStatus_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/server/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── Audit Listing Endpoint ──

func TestHTTP_ListAudit_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var entries []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestHTTP_ListAudit_ReturnsEntries(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	insertAuditChain(t, db, 3)

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestHTTP_ListAudit_FilterByOperatorID(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	insertAuditChain(t, db, 3)
	// Insert an entry with a different operator.
	db.Create(&models.AuditEntry{
		ID:         "other-op-entry",
		CreatedAt:  time.Now(),
		OperatorID: "other-op",
		EventType:  "test",
		Action:     "other-action",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/audit?operator_id=other-op", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry for other-op, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].OperatorID != "other-op" {
		t.Errorf("operator_id = %q, want %q", entries[0].OperatorID, "other-op")
	}
}

func TestHTTP_ListAudit_FilterByEventType(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	insertAuditChain(t, db, 2)
	db.Create(&models.AuditEntry{
		ID:         "special-event",
		CreatedAt:  time.Now(),
		OperatorID: "test-op",
		EventType:  "killswitch",
		Action:     "killed engagement",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/audit?event_type=killswitch", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 killswitch entry, got %d", len(entries))
	}
}

func TestHTTP_ListAudit_FilterBySessionID(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.AuditEntry{
		ID:         "sess-entry-1",
		CreatedAt:  time.Now(),
		OperatorID: "op1",
		SessionID:  "sess-abc",
		EventType:  "task",
		Action:     "ran shell",
	})
	db.Create(&models.AuditEntry{
		ID:         "sess-entry-2",
		CreatedAt:  time.Now(),
		OperatorID: "op1",
		SessionID:  "sess-xyz",
		EventType:  "task",
		Action:     "ran ps",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/audit?session_id=sess-abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry for sess-abc, got %d", len(entries))
	}
}

func TestHTTP_ListAudit_Pagination(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	insertAuditChain(t, db, 5)

	// Page 1, limit 2.
	req := httptest.NewRequest(http.MethodGet, "/api/audit?page=1&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var page1 []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&page1)
	if len(page1) != 2 {
		t.Errorf("page 1: expected 2 entries, got %d", len(page1))
	}

	// Page 2, limit 2.
	req = httptest.NewRequest(http.MethodGet, "/api/audit?page=2&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var page2 []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&page2)
	if len(page2) != 2 {
		t.Errorf("page 2: expected 2 entries, got %d", len(page2))
	}

	// Page 3, limit 2 — should get the remaining 1 entry.
	req = httptest.NewRequest(http.MethodGet, "/api/audit?page=3&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var page3 []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&page3)
	if len(page3) != 1 {
		t.Errorf("page 3: expected 1 entry, got %d", len(page3))
	}

	// Pages should not overlap.
	seen := make(map[string]bool)
	for _, e := range page1 {
		seen[e.ID] = true
	}
	for _, e := range page2 {
		if seen[e.ID] {
			t.Errorf("entry %s appears on both page 1 and page 2", e.ID)
		}
		seen[e.ID] = true
	}
	for _, e := range page3 {
		if seen[e.ID] {
			t.Errorf("entry %s appears on page 3 and a previous page", e.ID)
		}
	}
}

func TestHTTP_ListAudit_PaginationDefaults(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	// Insert more than the default limit (50) to verify the cap.
	insertAuditChain(t, db, 55)

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []models.AuditEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 50 {
		t.Errorf("expected default limit of 50, got %d", len(entries))
	}
}

func TestHTTP_ListAudit_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_ListAudit_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── OT/ICS Endpoints ──

func TestHTTP_OT_Assets_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/ot/assets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var records []models.OTAssetRecord
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestHTTP_OT_Assets_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.OTAssetRecord{EngagementID: "eng-1", IP: "10.0.0.1", Vendor: "Siemens"})
	db.Create(&models.OTAssetRecord{EngagementID: "eng-1", IP: "10.0.0.2", Vendor: "Rockwell"})

	req := httptest.NewRequest(http.MethodGet, "/api/ot/assets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTAssetRecord
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 2 {
		t.Errorf("expected 2 records, got %d", len(records))
	}
}

func TestHTTP_OT_Assets_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/ot/assets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_OT_Vulns_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/ot/vulns", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTVulnFinding
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestHTTP_OT_Vulns_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.OTVulnFinding{EngagementID: "eng-1", CVEID: "CVE-2024-0001", Severity: "critical", CVSS: 9.8})

	req := httptest.NewRequest(http.MethodGet, "/api/ot/vulns", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTVulnFinding
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].CVEID != "CVE-2024-0001" {
		t.Errorf("cve_id = %q, want %q", records[0].CVEID, "CVE-2024-0001")
	}
}

func TestHTTP_OT_Vulns_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/ot/vulns", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_OT_Credentials_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/ot/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTCredentialFinding
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestHTTP_OT_Credentials_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.OTCredentialFinding{EngagementID: "eng-1", Target: "10.0.0.5", Service: "modbus", Port: 502, Username: "admin", IsDefault: true})

	req := httptest.NewRequest(http.MethodGet, "/api/ot/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTCredentialFinding
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Service != "modbus" {
		t.Errorf("service = %q, want %q", records[0].Service, "modbus")
	}
}

func TestHTTP_OT_Credentials_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/ot/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_OT_Compliance_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/ot/compliance", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTComplianceFinding
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestHTTP_OT_Compliance_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.OTComplianceFinding{EngagementID: "eng-1", Framework: "IEC 62443", Requirement: "SR 1.1", Status: "fail", Severity: "high"})

	req := httptest.NewRequest(http.MethodGet, "/api/ot/compliance", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTComplianceFinding
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Framework != "IEC 62443" {
		t.Errorf("framework = %q, want %q", records[0].Framework, "IEC 62443")
	}
}

func TestHTTP_OT_Compliance_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/ot/compliance", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_OT_Topology_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/ot/topology", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTTopologyEdge
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestHTTP_OT_Topology_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.OTTopologyEdge{EngagementID: "eng-1", SourceIP: "10.0.0.1", TargetIP: "10.0.0.2", Protocol: "modbus", Port: 502})

	req := httptest.NewRequest(http.MethodGet, "/api/ot/topology", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTTopologyEdge
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Protocol != "modbus" {
		t.Errorf("protocol = %q, want %q", records[0].Protocol, "modbus")
	}
}

func TestHTTP_OT_Topology_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/ot/topology", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_OT_Reports_Empty(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/ot/reports", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTAssessmentReport
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestHTTP_OT_Reports_WithData(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	db.Create(&models.OTAssessmentReport{EngagementID: "eng-1", Title: "Q4 OT Assessment", Format: "json", GeneratedAt: time.Now(), GeneratedBy: "admin"})

	req := httptest.NewRequest(http.MethodGet, "/api/ot/reports", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []models.OTAssessmentReport
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Title != "Q4 OT Assessment" {
		t.Errorf("title = %q, want %q", records[0].Title, "Q4 OT Assessment")
	}
}

func TestHTTP_OT_Reports_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	req := httptest.NewRequest(http.MethodPost, "/api/ot/reports", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_OT_NoAuth(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	for _, path := range []string{
		"/api/ot/assets",
		"/api/ot/vulns",
		"/api/ot/credentials",
		"/api/ot/compliance",
		"/api/ot/topology",
		"/api/ot/reports",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", path, w.Code)
		}
	}
}
