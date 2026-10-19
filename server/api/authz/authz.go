// Package authz defines the HTTP permission model shared by the REST API and
// middleware. It is deliberately independent of gRPC.
package authz

import (
	"context"
	"net/http"
	"strings"
)

// Identity is the authenticated operator placed in the request context by the
// auth middleware.
type Identity struct {
	Username   string
	Role       string
	OperatorID string
}

type contextKey struct{}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(contextKey{}).(Identity)
	return identity, ok
}

const (
	PermAuthenticated    = "authenticated"
	PermSessionRead      = "session.read"
	PermSessionWrite     = "session.write"
	PermTaskRead         = "task.read"
	PermTaskExecute      = "task.execute"
	PermBeaconRead       = "beacon.read"
	PermListenerRead     = "listener.read"
	PermListenerWrite    = "listener.write"
	PermEngagementRead   = "engagement.read"
	PermEngagementManage = "engagement.manage"
	PermPayloadRead      = "payload.read"
	PermPayloadBuild     = "payload.build"
	PermAuditRead        = "audit.read"
	PermAdminManage      = "admin.manage"
	PermServerRead       = "server.read"
	PermOTRead           = "ot.read"
	PermLootRead         = "loot.read"
	PermLootWrite        = "loot.write"
)

var rolePermissions = map[string]map[string]bool{
	"admin": {"*": true},
	"operator": {
		PermAuthenticated:  true,
		PermSessionRead:    true,
		PermSessionWrite:   true,
		PermTaskRead:       true,
		PermTaskExecute:    true,
		PermBeaconRead:     true,
		PermEngagementRead: true,
		PermListenerRead:   true,
		PermPayloadRead:    true,
		PermAuditRead:      true,
		PermServerRead:     true,
		PermOTRead:         true,
		PermLootRead:       true,
		PermLootWrite:      true,
	},
	"builder": {
		PermAuthenticated: true,
		PermPayloadBuild:  true,
		PermPayloadRead:   true,
		PermServerRead:    true,
	},
	"observer": {
		PermAuthenticated:  true,
		PermSessionRead:    true,
		PermTaskRead:       true,
		PermBeaconRead:     true,
		PermEngagementRead: true,
		PermListenerRead:   true,
		PermPayloadRead:    true,
		PermAuditRead:      true,
		PermServerRead:     true,
		PermOTRead:         true,
		PermLootRead:       true,
	},
	"ot-operator": {
		PermAuthenticated: true,
		PermOTRead:        true,
		PermSessionRead:   true,
		PermTaskRead:      true,
		PermServerRead:    true,
		PermLootRead:      true,
	},
}

// KnownRole reports whether role is part of the supported role set.
func KnownRole(role string) bool {
	_, ok := rolePermissions[role]
	return ok
}

// Allowed reports whether role may perform permission. Unknown roles and
// permissions are denied.
func Allowed(role, permission string) bool {
	if role == "" {
		return false
	}
	if permission == PermAuthenticated {
		return true
	}
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return perms["*"] || perms[permission]
}

// PermissionFor maps an API method/path to the permission it requires. The
// second return value is false for an unregistered protected route, which the
// middleware treats as a denial.
func PermissionFor(method, path string) (string, bool) {
	switch {
	case path == "/api/auth/logout":
		return PermAuthenticated, true
	case path == "/api/server/status":
		return PermServerRead, true
	case path == "/api/beacons":
		return PermBeaconRead, true
	case path == "/api/operators" || strings.HasPrefix(path, "/api/operators/"):
		return PermAdminManage, true
	case path == "/api/audit" || strings.HasPrefix(path, "/api/audit/"):
		return PermAuditRead, true
	case strings.HasPrefix(path, "/api/ot/"):
		return PermOTRead, true
	case path == "/api/loot" || strings.HasPrefix(path, "/api/loot/"):
		if method == http.MethodGet {
			return PermLootRead, true
		}
		return PermLootWrite, true
	case path == "/api/listeners" || strings.HasPrefix(path, "/api/listeners/"):
		if method == http.MethodGet {
			return PermListenerRead, true
		}
		return PermListenerWrite, true
	case path == "/api/engagements" || strings.HasPrefix(path, "/api/engagements/"):
		if method == http.MethodGet {
			return PermEngagementRead, true
		}
		if method == http.MethodPost && strings.HasSuffix(path, "/scope-check") {
			return PermEngagementRead, true
		}
		return PermEngagementManage, true
	case path == "/api/payloads" || strings.HasPrefix(path, "/api/payloads/"):
		if method == http.MethodGet {
			return PermPayloadRead, true
		}
		return PermPayloadBuild, true
	case strings.HasPrefix(path, "/api/tasks/"):
		return PermTaskRead, true
	case path == "/api/sessions" || path == "/api/sessions/history" ||
		strings.HasPrefix(path, "/api/sessions/"):
		if method == http.MethodPost && strings.HasSuffix(path, "/task") {
			return PermTaskExecute, true
		}
		if method == http.MethodGet {
			return PermSessionRead, true
		}
		return PermSessionWrite, true
	}
	return "", false
}

// Middleware enforces the permission table. It must run after authentication
// has placed an Identity in the request context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		identity, ok := FromContext(r.Context())
		if !ok || identity.Role == "" {
			forbidden(w)
			return
		}
		permission, ok := PermissionFor(r.Method, r.URL.Path)
		if !ok || !Allowed(identity.Role, permission) {
			forbidden(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden"}`))
}
