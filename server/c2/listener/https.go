package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/server/c2/profile"
)

// HTTPSListener implements an HTTP/2 server with TLS, configurable URL paths,
// session key encryption, cookie-based session tracking, and C2 profile support.
type HTTPSListener struct {
	BaseListener
	server     *http.Server
	tlsConfig  *tls.Config
	profile    *profile.C2Profile
	sessions   map[string]time.Time // sessionID -> last seen
	sessionsMu sync.RWMutex
	cancelFunc context.CancelFunc
}

// HTTPSConfig holds the configuration for an HTTPS listener.
type HTTPSConfig struct {
	ID            string
	BindAddr      string
	EngagementID  string
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	CACertPEM     []byte // optional: for client cert validation
	Profile       *profile.C2Profile
}

// NewHTTPSListener creates a new HTTPS listener.
func NewHTTPSListener(cfg HTTPSConfig) (*HTTPSListener, error) {
	cert, err := tls.X509KeyPair(cfg.ServerCertPEM, cfg.ServerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	if len(cfg.CACertPEM) > 0 {
		caPool := x509.NewCertPool()
		if caPool.AppendCertsFromPEM(cfg.CACertPEM) {
			tlsConfig.ClientCAs = caPool
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	p := cfg.Profile
	if p == nil {
		p = profile.DefaultProfile()
	}

	return &HTTPSListener{
		BaseListener: NewBaseListener(cfg.ID, "https", cfg.BindAddr, cfg.EngagementID),
		tlsConfig:    tlsConfig,
		profile:      p,
		sessions:     make(map[string]time.Time),
	}, nil
}

// Start begins serving HTTPS connections.
func (h *HTTPSListener) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Register GET paths for polling/check-in.
	for _, path := range h.profile.HTTPConfig.GetPaths {
		mux.HandleFunc(path, h.handleGet)
	}

	// Register POST paths for data submission.
	for _, path := range h.profile.HTTPConfig.PostPaths {
		mux.HandleFunc(path, h.handlePost)
	}

	// Catch-all for unmatched paths returns a plausible 404.
	mux.HandleFunc("/", h.handleDefault)

	h.server = &http.Server{
		Addr:      h.bindAddr,
		Handler:   h.wrapHeaders(mux),
		TLSConfig: h.tlsConfig,
		// HTTP/2 is automatically enabled when using TLS with Go's net/http.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, cancel := context.WithCancel(ctx)
	h.cancelFunc = cancel
	h.SetActive(true)

	log.Printf("[https] listener %s started on %s", h.id, h.bindAddr)

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		h.server.Shutdown(shutdownCtx)
	}()

	err := h.server.ListenAndServeTLS("", "")
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Stop shuts down the HTTPS listener.
func (h *HTTPSListener) Stop() error {
	h.SetActive(false)
	if h.cancelFunc != nil {
		h.cancelFunc()
	}
	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return h.server.Shutdown(ctx)
	}
	return nil
}

// ID returns the listener's unique identifier.
func (h *HTTPSListener) ID() string { return h.id }

// Type returns the listener type.
func (h *HTTPSListener) Type() string { return h.listenerType }

// Addr returns the listener's bind address.
func (h *HTTPSListener) Addr() string { return h.bindAddr }

// wrapHeaders returns middleware that applies C2 profile server headers.
func (h *HTTPSListener) wrapHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range h.profile.HTTPConfig.ServerHeaders {
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

// extractSessionID extracts the session ID from the request cookie or header.
func (h *HTTPSListener) extractSessionID(r *http.Request) string {
	if cookie, err := r.Cookie("SESSIONID"); err == nil {
		return cookie.Value
	}
	if sid := r.Header.Get("X-Session-ID"); sid != "" {
		return sid
	}
	return ""
}

// trackSession records session activity.
func (h *HTTPSListener) trackSession(sessionID string) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	h.sessions[sessionID] = time.Now()
}

// handleGet processes GET requests (polling/check-in).
func (h *HTTPSListener) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.handleDefault(w, r)
		return
	}

	sessionID := h.extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	h.trackSession(sessionID)

	// Invoke data handler with nil body to indicate a check-in/poll.
	response, err := h.OnData(sessionID, nil)
	if err != nil {
		// Return empty 200 as if normal web traffic.
		w.WriteHeader(http.StatusOK)
		return
	}

	if response != nil {
		encoded := base64.StdEncoding.EncodeToString(response)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(encoded))
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// handlePost processes POST requests (data submission).
func (h *HTTPSListener) handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.handleDefault(w, r)
		return
	}

	sessionID := h.extractSessionID(r)

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10 MB limit
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode based on data transform profile.
	var data []byte
	switch h.profile.HTTPConfig.DataTransform {
	case "base64":
		data, err = base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			data = body // fall back to raw
		}
	default:
		data = body
	}

	if sessionID == "" && len(data) > 0 {
		// New session registration: the session ID is part of the payload.
		sessionID = r.RemoteAddr
	}

	if sessionID != "" {
		h.trackSession(sessionID)
		h.OnSession(sessionID, h.engagementID, map[string]string{
			"remote_addr": r.RemoteAddr,
			"transport":   "https",
			"user_agent":  r.UserAgent(),
		})
	}

	response, err := h.OnData(sessionID, data)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Set session cookie for subsequent requests.
	if sessionID != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "SESSIONID",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}

	if response != nil {
		encoded := base64.StdEncoding.EncodeToString(response)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(encoded))
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// handleDefault returns a plausible default response for unmatched paths.
func (h *HTTPSListener) handleDefault(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("<html><body><h1>404 Not Found</h1></body></html>"))
}

// ActiveSessions returns the count of sessions seen within the given duration.
func (h *HTTPSListener) ActiveSessions(within time.Duration) int {
	h.sessionsMu.RLock()
	defer h.sessionsMu.RUnlock()
	count := 0
	cutoff := time.Now().Add(-within)
	for _, lastSeen := range h.sessions {
		if lastSeen.After(cutoff) {
			count++
		}
	}
	return count
}
