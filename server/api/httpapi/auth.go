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

	"golang.org/x/crypto/bcrypt"
)

type AuthManager struct {
	mu       sync.RWMutex
	users    map[string][]byte // username -> bcrypt hash
	tokens   map[string]*tokenEntry
}

type tokenEntry struct {
	username  string
	expiresAt time.Time
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
		users:  make(map[string][]byte),
		tokens: make(map[string]*tokenEntry),
	}
	am.ensureDefaultUser()
	return am
}

func (am *AuthManager) ensureDefaultUser() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	am.users["admin"] = hash
}

func (am *AuthManager) SetPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	am.mu.Lock()
	am.users[username] = hash
	am.mu.Unlock()
	return nil
}

func (am *AuthManager) authenticate(username, password string) bool {
	am.mu.RLock()
	hash, ok := am.users[username]
	am.mu.RUnlock()
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

func (am *AuthManager) issueToken(username string) string {
	b := make([]byte, 32)
	rand.Read(b)
	tok := hex.EncodeToString(b)

	am.mu.Lock()
	am.tokens[tok] = &tokenEntry{
		username:  username,
		expiresAt: time.Now().Add(12 * time.Hour),
	}
	am.mu.Unlock()
	return tok
}

func (am *AuthManager) validateToken(tok string) (string, bool) {
	am.mu.RLock()
	entry, ok := am.tokens[tok]
	am.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.username, true
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

		if !am.authenticate(req.Username, req.Password) {
			// constant-time comparison already handled by bcrypt
			_ = subtle.ConstantTimeCompare([]byte("a"), []byte("b"))
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid credentials"})
			return
		}

		tok := am.issueToken(req.Username)
		writeJSON(w, http.StatusOK, LoginResponse{Token: tok})
	}
}

func (am *AuthManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}

		tok := strings.TrimPrefix(auth, "Bearer ")
		if _, ok := am.validateToken(tok); !ok {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid or expired token"})
			return
		}

		next.ServeHTTP(w, r)
	})
}
