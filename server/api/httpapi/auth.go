package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthManager struct {
	mu          sync.RWMutex
	users       map[string][]byte // username -> bcrypt hash
	roles       map[string]string
	operatorIDs map[string]string
	tokens      map[string]*tokenEntry
	auditor     *audit.Logger
}

type tokenEntry struct {
	username   string
	role       string
	operatorID string
	expiresAt  time.Time
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func NewAuthManager() *AuthManager {
	am := &AuthManager{
		users:       make(map[string][]byte),
		roles:       make(map[string]string),
		operatorIDs: make(map[string]string),
		tokens:      make(map[string]*tokenEntry),
	}
	am.ensureDefaultUser()
	return am
}

// SetAuditLogger installs the audit sink used for login/logout events.
func (am *AuthManager) SetAuditLogger(logger *audit.Logger) {
	am.auditor = logger
}

// auditAuthEvents can be disabled by tests that assert on audit counts.
var auditAuthEvents = true

func (am *AuthManager) logAuth(operator string, event audit.EventType, action, result, sourceIP string) {
	if am.auditor == nil || !auditAuthEvents {
		return
	}
	_ = am.auditor.Log(operator, "", "", event, action, "", result, nil, sourceIP, "")
}

func (am *AuthManager) ensureDefaultUser() {
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	am.mu.Lock()
	am.users["admin"] = hash
	am.roles["admin"] = "admin"
	am.mu.Unlock()
}

// LoadFromDB hydrates the in-memory auth store from the operators table. The
// server previously relied on operators created in this process, so accounts
// created before a restart could no longer log in.
func (am *AuthManager) LoadFromDB(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	var operators []models.Operator
	if err := db.Find(&operators).Error; err != nil {
		return err
	}
	for _, op := range operators {
		hash := op.PasswordHash
		if len(hash) == 0 {
			// Legacy rows stored the bcrypt hash in CertPEM.
			hash = op.CertPEM
		}
		if len(hash) == 0 {
			continue
		}
		role := op.Role
		if role == "" {
			role = "operator"
		}
		am.SetUser(op.Name, hash, role, op.ID)
	}
	return nil
}

func (am *AuthManager) SetPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	am.mu.Lock()
	am.users[username] = hash
	if am.roles[username] == "" {
		am.roles[username] = "operator"
	}
	am.mu.Unlock()
	return nil
}

// SetUser installs a pre-hashed password and its role/operator identity.
func (am *AuthManager) SetUser(username string, hash []byte, role, operatorID string) {
	am.mu.Lock()
	am.users[username] = append([]byte(nil), hash...)
	if role == "" {
		role = "operator"
	}
	am.roles[username] = role
	am.operatorIDs[username] = operatorID
	am.mu.Unlock()
}

// RemoveUser removes a credential and every token issued to it.
func (am *AuthManager) RemoveUser(username string) {
	am.mu.Lock()
	delete(am.users, username)
	delete(am.roles, username)
	delete(am.operatorIDs, username)
	for token, entry := range am.tokens {
		if entry.username == username {
			delete(am.tokens, token)
		}
	}
	am.mu.Unlock()
}

// RevokeTokens invalidates every token for a username.
func (am *AuthManager) RevokeTokens(username string) {
	am.mu.Lock()
	for token, entry := range am.tokens {
		if entry.username == username {
			delete(am.tokens, token)
		}
	}
	am.mu.Unlock()
}

func (am *AuthManager) authenticate(username, password string) bool {
	_, _, ok := am.authenticateIdentity(username, password)
	return ok
}

func (am *AuthManager) authenticateIdentity(username, password string) (role, operatorID string, ok bool) {
	am.mu.RLock()
	hash, known := am.users[username]
	role = am.roles[username]
	operatorID = am.operatorIDs[username]
	am.mu.RUnlock()
	if !known {
		return "", "", false
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
		return "", "", false
	}
	return role, operatorID, true
}

func (am *AuthManager) issueToken(username string) string {
	am.mu.RLock()
	role := am.roles[username]
	operatorID := am.operatorIDs[username]
	am.mu.RUnlock()
	return am.issueTokenFor(username, role, operatorID)
}

func (am *AuthManager) issueTokenFor(username, role, operatorID string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b)

	am.mu.Lock()
	am.pruneExpiredLocked()
	am.tokens[tok] = &tokenEntry{
		username:   username,
		role:       role,
		operatorID: operatorID,
		expiresAt:  time.Now().Add(12 * time.Hour),
	}
	am.mu.Unlock()
	return tok
}

func (am *AuthManager) validateToken(tok string) (string, bool) {
	identity, ok := am.validateTokenIdentity(tok)
	return identity.Username, ok
}

func (am *AuthManager) validateTokenIdentity(tok string) (authz.Identity, bool) {
	am.mu.RLock()
	entry, ok := am.tokens[tok]
	var identity authz.Identity
	if ok {
		identity = authz.Identity{
			Username:   entry.username,
			Role:       entry.role,
			OperatorID: entry.operatorID,
		}
	}
	am.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return authz.Identity{}, false
	}
	return identity, true
}

func (am *AuthManager) pruneExpiredLocked() {
	now := time.Now()
	for token, entry := range am.tokens {
		if now.After(entry.expiresAt) {
			delete(am.tokens, token)
		}
	}
}

func (am *AuthManager) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request"})
			return
		}

		if req.Username == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "username and password required"})
			return
		}

		role, operatorID, ok := am.authenticateIdentity(req.Username, req.Password)
		if !ok {
			_ = subtle.ConstantTimeCompare([]byte("a"), []byte("b"))
			am.logAuth(req.Username, audit.EventOperatorLogin, "login", "failure", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid credentials"})
			return
		}

		tok := am.issueTokenFor(req.Username, role, operatorID)
		if tok == "" {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to issue token"})
			return
		}
		am.logAuth(req.Username, audit.EventOperatorLogin, "login", "success", r.RemoteAddr)
		writeJSON(w, http.StatusOK, LoginResponse{Token: tok})
	}
}

// LogoutHandler revokes the bearer token used for the request.
func (am *AuthManager) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		tok := bearerToken(r)
		identity, _ := am.validateTokenIdentity(tok)
		am.mu.Lock()
		delete(am.tokens, tok)
		am.mu.Unlock()
		if identity.Username != "" {
			am.logAuth(identity.Username, audit.EventOperatorLogout, "logout", "success", r.RemoteAddr)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
	}
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func (am *AuthManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		tok := bearerToken(r)
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}

		identity, ok := am.validateTokenIdentity(tok)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid or expired token"})
			return
		}

		next.ServeHTTP(w, r.WithContext(authz.WithIdentity(r.Context(), identity)))
	})
}
