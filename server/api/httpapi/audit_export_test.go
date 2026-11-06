package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/store/models"
)

func TestHTTP_AuditExport_Formats(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)
	insertAuditChain(t, db, 2)

	for _, tc := range []struct {
		format      string
		contentType string
		contains    string
	}{
		{"json", "application/json", `"entry_hash"`},
		{"cef", "text/plain", "CEF:0|PrivateC2"},
		{"leef", "text/plain", "LEEF:2.0|PrivateC2"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/audit/export?format="+tc.format, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s export = %d: %s", tc.format, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, tc.contentType) {
			t.Errorf("%s content type = %q, want prefix %q", tc.format, got, tc.contentType)
		}
		if !strings.Contains(w.Body.String(), tc.contains) {
			t.Errorf("%s export missing %q: %s", tc.format, tc.contains, w.Body.String())
		}
	}
}

func TestHTTP_AuditExport_UnsupportedFormat(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)
	insertAuditChain(t, db, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/export?format=xml", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported format = %d, want 400", w.Code)
	}
}

func TestAuth_LoginWritesAuditEntry(t *testing.T) {
	old := auditAuthEvents
	auditAuthEvents = true
	defer func() { auditAuthEvents = old }()

	router, _, db := setupTestRouter(t)
	_ = getAuthToken(t, router)

	var entries []models.AuditEntry
	if err := db.Where("event_type = ?", "operator.login").Find(&entries).Error; err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("login audit entries = %d, want 1", len(entries))
	}
	if entries[0].OperatorID != "admin" || entries[0].ResultSummary != "success" {
		t.Fatalf("unexpected login entry: %+v", entries[0])
	}

	// The entry must round-trip through the canonical hash.
	lib, err := models.AuditEntryToLib(entries[0])
	if err != nil {
		t.Fatalf("convert entry: %v", err)
	}
	if got := audit.ComputeEntryHash(lib); got != entries[0].EntryHash {
		t.Fatalf("stored hash mismatch: %s != %s", got, entries[0].EntryHash)
	}
}
