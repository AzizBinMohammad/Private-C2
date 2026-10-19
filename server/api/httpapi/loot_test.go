package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/azizbinmohammad/private-c2/server/store/models"
)

func lootRequest(t *testing.T, router http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestLootLifecycle(t *testing.T) {
	lootDir := t.TempDir()
	t.Setenv("PC2_LOOT_DIR", lootDir)

	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	engagement := &models.Engagement{Name: "loot-eng", Status: "active", AuthorizationRef: "auth-1"}
	if err := db.Create(engagement).Error; err != nil {
		t.Fatal(err)
	}

	secret := []byte("credential material")
	create := lootRequest(t, router, http.MethodPost, "/api/loot", token, map[string]any{
		"engagement_id": engagement.ID,
		"kind":          "file",
		"name":          "notes.txt",
		"note":          "from test",
		"data":          base64.StdEncoding.EncodeToString(secret),
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", create.Code, create.Body.String())
	}
	var artifact models.LootArtifact
	if err := json.Unmarshal(create.Body.Bytes(), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.ID == "" || artifact.SHA256 == "" || artifact.Size != int64(len(secret)) {
		t.Fatalf("unexpected artifact: %+v", artifact)
	}
	if entries, _ := os.ReadDir(lootDir); len(entries) != 1 {
		t.Fatalf("loot directory has %d files, want 1", len(entries))
	}

	list := lootRequest(t, router, http.MethodGet, "/api/loot?engagement_id="+engagement.ID, token, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list = %d %s", list.Code, list.Body.String())
	}
	var artifacts []models.LootArtifact
	if err := json.Unmarshal(list.Body.Bytes(), &artifacts); err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].ID != artifact.ID {
		t.Fatalf("list = %+v", artifacts)
	}

	download := lootRequest(t, router, http.MethodGet, "/api/loot/"+artifact.ID+"/download", token, nil)
	if download.Code != http.StatusOK || !bytes.Equal(download.Body.Bytes(), secret) {
		t.Fatalf("download = %d %q", download.Code, download.Body.String())
	}

	del := lootRequest(t, router, http.MethodDelete, "/api/loot/"+artifact.ID, token, nil)
	if del.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", del.Code, del.Body.String())
	}
	if entries, _ := os.ReadDir(lootDir); len(entries) != 0 {
		t.Fatalf("loot directory has %d files after delete", len(entries))
	}
	missing := lootRequest(t, router, http.MethodGet, "/api/loot/"+artifact.ID, token, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d", missing.Code)
	}
}

func TestLootCredentialGate(t *testing.T) {
	t.Setenv("PC2_LOOT_DIR", t.TempDir())
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	engagement := &models.Engagement{Name: "gated", Status: "active", AuthorizationRef: "auth-1"}
	if err := db.Create(engagement).Error; err != nil {
		t.Fatal(err)
	}

	body := map[string]any{
		"engagement_id": engagement.ID,
		"kind":          "credential",
		"name":          "creds.txt",
		"data":          base64.StdEncoding.EncodeToString([]byte("secret")),
	}
	denied := lootRequest(t, router, http.MethodPost, "/api/loot", token, body)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("credential loot without gate = %d %s", denied.Code, denied.Body.String())
	}

	if err := db.Model(engagement).Update("allow_credential_access", true).Error; err != nil {
		t.Fatal(err)
	}
	allowed := lootRequest(t, router, http.MethodPost, "/api/loot", token, body)
	if allowed.Code != http.StatusCreated {
		t.Fatalf("credential loot with gate = %d %s", allowed.Code, allowed.Body.String())
	}
}

func TestLootRequiresAuth(t *testing.T) {
	t.Setenv("PC2_LOOT_DIR", t.TempDir())
	router, _, _ := setupTestRouter(t)
	w := lootRequest(t, router, http.MethodGet, "/api/loot", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated loot list = %d", w.Code)
	}
}

func TestLootPromoteTaskOutput(t *testing.T) {
	t.Setenv("PC2_LOOT_DIR", t.TempDir())
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	engagement := &models.Engagement{Name: "promote", Status: "active", AuthorizationRef: "auth-1"}
	if err := db.Create(engagement).Error; err != nil {
		t.Fatal(err)
	}
	result := &models.TaskResult{
		TaskID:       "task-123",
		SessionID:    "session-1",
		EngagementID: engagement.ID,
		Success:      true,
		Output:       `{"user":"alice"}`,
	}
	if err := db.Create(result).Error; err != nil {
		t.Fatal(err)
	}

	w := lootRequest(t, router, http.MethodPost, "/api/loot", token, map[string]any{
		"task_id": "task-123",
		"kind":    "task",
		"name":    "enum-output",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("promote = %d %s", w.Code, w.Body.String())
	}
	var artifact models.LootArtifact
	if err := json.Unmarshal(w.Body.Bytes(), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.EngagementID != engagement.ID || artifact.SessionID != "session-1" || artifact.Size == 0 {
		t.Fatalf("promoted artifact = %+v", artifact)
	}
}
