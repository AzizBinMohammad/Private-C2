package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azizbinmohammad/private-c2/server/store/models"
)

func lootBlobs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var blobs []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bin") {
			blobs = append(blobs, e.Name())
		}
	}
	return blobs
}

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
	if blobs := lootBlobs(t, lootDir); len(blobs) != 1 {
		t.Fatalf("loot directory has %d blobs, want 1", len(blobs))
	} else {
		raw, err := os.ReadFile(filepath.Join(lootDir, blobs[0]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(raw, []byte(lootMagic)) {
			t.Fatalf("loot blob is not encrypted")
		}
		if bytes.Contains(raw, secret) {
			t.Fatalf("loot blob contains plaintext")
		}
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
	if blobs := lootBlobs(t, lootDir); len(blobs) != 0 {
		t.Fatalf("loot directory has %d blobs after delete", len(blobs))
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

func TestLootLegacyPlaintextAndRedaction(t *testing.T) {
	lootDir := t.TempDir()
	t.Setenv("PC2_LOOT_DIR", lootDir)
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)

	engagement := &models.Engagement{Name: "legacy", Status: "active", AuthorizationRef: "auth-1"}
	if err := db.Create(engagement).Error; err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(lootDir, 0700); err != nil {
		t.Fatal(err)
	}

	textPath := filepath.Join(lootDir, "legacy-text.bin")
	text := []byte("target: plc-1\npassword=hunter2\n")
	if err := os.WriteFile(textPath, text, 0600); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.LootArtifact{
		Base: models.Base{ID: "legacy-text"}, EngagementID: engagement.ID,
		Kind: "file", Name: "legacy.txt", Path: textPath,
	}).Error; err != nil {
		t.Fatal(err)
	}

	raw := lootRequest(t, router, http.MethodGet, "/api/loot/legacy-text/download", token, nil)
	if raw.Code != http.StatusOK || !bytes.Equal(raw.Body.Bytes(), text) {
		t.Fatalf("legacy download = %d %q", raw.Code, raw.Body.String())
	}
	redacted := lootRequest(t, router, http.MethodGet, "/api/loot/legacy-text/download?redact=true", token, nil)
	if redacted.Code != http.StatusOK || strings.Contains(redacted.Body.String(), "hunter2") {
		t.Fatalf("redacted download = %d %q", redacted.Code, redacted.Body.String())
	}
	if !strings.Contains(redacted.Body.String(), "target: plc-1") {
		t.Fatalf("redaction removed non-secret context: %q", redacted.Body.String())
	}

	binaryPath := filepath.Join(lootDir, "legacy-binary.bin")
	if err := os.WriteFile(binaryPath, []byte{0x00, 0x01, 0x02}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.LootArtifact{
		Base: models.Base{ID: "legacy-binary"}, EngagementID: engagement.ID,
		Kind: "file", Name: "payload.bin", Path: binaryPath,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if w := lootRequest(t, router, http.MethodGet, "/api/loot/legacy-binary/download?redact=true", token, nil); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("binary redaction = %d %s", w.Code, w.Body.String())
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
