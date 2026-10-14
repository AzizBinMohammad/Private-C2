package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer returns a server that behaves like the Private-C2 auth
// middleware: /api/auth/login is public, everything else needs a bearer token.
func newTestServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	loginCalls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		if creds.Username != "admin" || creds.Password != "admin" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
	})

	protected := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		switch r.URL.Path {
		case "/api/sessions":
			json.NewEncoder(w).Encode([]map[string]string{{"id": "abc123", "hostname": "host1"}})
		case "/api/echo":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			json.NewEncoder(w).Encode(body)
		case "/api/notfound":
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "nope"})
		default:
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}
	}
	for _, p := range []string{"/api/sessions", "/api/echo", "/api/notfound", "/api/other"} {
		mux.HandleFunc(p, protected)
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &loginCalls
}

func TestLoginStoresToken(t *testing.T) {
	srv, calls := newTestServer(t)
	c := New(srv.URL)

	if c.Token() != "" {
		t.Fatalf("token before login = %q, want empty", c.Token())
	}
	if err := c.Login("admin", "admin"); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if c.Token() != "test-token" {
		t.Errorf("token after login = %q, want %q", c.Token(), "test-token")
	}
	if *calls != 1 {
		t.Errorf("login calls = %d, want 1", *calls)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)

	err := c.Login("admin", "wrong")
	if err == nil {
		t.Fatal("Login() with bad password returned nil error")
	}
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(%v) = false, want true", err)
	}
	if c.Token() != "" {
		t.Errorf("token set after failed login = %q, want empty", c.Token())
	}
}

// TestGetWithoutLoginIsUnauthorized pins the behaviour that caused the
// original CLI defect: an unauthenticated request must surface the 401.
func TestGetWithoutLoginIsUnauthorized(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL)

	var sessions []map[string]string
	err := c.Get("/api/sessions", &sessions)
	if err == nil {
		t.Fatal("Get() without login returned nil error")
	}
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(%v) = false, want true", err)
	}
}

func TestGetSendsBearerToken(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL, WithToken("test-token"))

	var sessions []map[string]string
	if err := c.Get("/api/sessions", &sessions); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(sessions) != 1 || sessions[0]["hostname"] != "host1" {
		t.Errorf("sessions = %v, want one entry with hostname host1", sessions)
	}
}

func TestPostEncodesJSONBody(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL, WithToken("test-token"))

	var out map[string]string
	if err := c.Post("/api/echo", map[string]string{"type": "shell", "args": "whoami"}, &out); err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if out["type"] != "shell" || out["args"] != "whoami" {
		t.Errorf("echoed body = %v, want type=shell args=whoami", out)
	}
}

func TestStatusErrorCarriesCodeAndBody(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL, WithToken("test-token"))

	err := c.Get("/api/notfound", nil)
	if err == nil {
		t.Fatal("Get() on missing route returned nil error")
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a *StatusError", err)
	}
	if se.Code != http.StatusNotFound {
		t.Errorf("Code = %d, want %d", se.Code, http.StatusNotFound)
	}
	if se.Body != `{"error":"nope"}` {
		t.Errorf("Body = %q, want the server error JSON", se.Body)
	}
}

func TestNilOutDiscardsBody(t *testing.T) {
	srv, _ := newTestServer(t)
	c := New(srv.URL, WithToken("test-token"))

	if err := c.Delete("/api/other", nil); err != nil {
		t.Fatalf("Delete() with nil out error = %v", err)
	}
}

func TestBaseURLTrailingSlashNormalised(t *testing.T) {
	c := New("http://127.0.0.1:8080/")
	if c.BaseURL() != "http://127.0.0.1:8080" {
		t.Errorf("BaseURL() = %q, want no trailing slash", c.BaseURL())
	}
}
