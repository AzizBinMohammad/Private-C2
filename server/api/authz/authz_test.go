package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPermissionFor(t *testing.T) {
	cases := []struct {
		method string
		path   string
		perm   string
		ok     bool
	}{
		{http.MethodGet, "/api/sessions", PermSessionRead, true},
		{http.MethodGet, "/api/sessions/history", PermSessionRead, true},
		{http.MethodGet, "/api/sessions/abc/tasks", PermSessionRead, true},
		{http.MethodPost, "/api/sessions/abc/task", PermTaskExecute, true},
		{http.MethodDelete, "/api/sessions/abc", PermSessionWrite, true},
		{http.MethodPost, "/api/sessions/abc/lock", PermSessionWrite, true},
		{http.MethodGet, "/api/tasks/abc", PermTaskRead, true},
		{http.MethodGet, "/api/beacons", PermBeaconRead, true},
		{http.MethodGet, "/api/listeners", PermListenerRead, true},
		{http.MethodPost, "/api/listeners", PermListenerWrite, true},
		{http.MethodGet, "/api/engagements", PermEngagementRead, true},
		{http.MethodPost, "/api/engagements/abc/scope-check", PermEngagementRead, true},
		{http.MethodPost, "/api/engagements/abc/killswitch", PermEngagementManage, true},
		{http.MethodGet, "/api/payloads", PermPayloadRead, true},
		{http.MethodPost, "/api/payloads/generate", PermPayloadBuild, true},
		{http.MethodGet, "/api/operators", PermAdminManage, true},
		{http.MethodGet, "/api/audit", PermAuditRead, true},
		{http.MethodGet, "/api/server/status", PermServerRead, true},
		{http.MethodGet, "/api/ot/assets", PermOTRead, true},
		{http.MethodGet, "/api/unknown", "", false},
	}
	for _, tc := range cases {
		perm, ok := PermissionFor(tc.method, tc.path)
		if perm != tc.perm || ok != tc.ok {
			t.Errorf("PermissionFor(%s,%s) = (%q,%v), want (%q,%v)", tc.method, tc.path, perm, ok, tc.perm, tc.ok)
		}
	}
}

func TestRoleMatrix(t *testing.T) {
	cases := []struct {
		role string
		perm string
		want bool
	}{
		{"admin", PermAdminManage, true},
		{"admin", PermOTRead, true},
		{"operator", PermTaskExecute, true},
		{"operator", PermAdminManage, false},
		{"operator", PermPayloadBuild, false},
		{"builder", PermPayloadBuild, true},
		{"builder", PermTaskExecute, false},
		{"observer", PermSessionRead, true},
		{"observer", PermTaskExecute, false},
		{"ot-operator", PermOTRead, true},
		{"ot-operator", PermTaskExecute, false},
		{"unknown", PermSessionRead, false},
		{"", PermAuthenticated, false},
		{"observer", PermAuthenticated, true},
	}
	for _, tc := range cases {
		if got := Allowed(tc.role, tc.perm); got != tc.want {
			t.Errorf("Allowed(%q,%q) = %v, want %v", tc.role, tc.perm, got, tc.want)
		}
	}
}

func TestMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	ctx := WithIdentity(context.Background(), Identity{Username: "obs", Role: "observer"})
	w := httptest.NewRecorder()
	Middleware(next).ServeHTTP(w, req.WithContext(ctx))
	if w.Code != http.StatusNoContent {
		t.Fatalf("observer GET sessions = %d, want 204", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/sessions/abc/task", nil)
	w = httptest.NewRecorder()
	Middleware(next).ServeHTTP(w, req.WithContext(ctx))
	if w.Code != http.StatusForbidden {
		t.Fatalf("observer task = %d, want 403", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	w = httptest.NewRecorder()
	Middleware(next).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("anonymous = %d, want 403", w.Code)
	}
}
