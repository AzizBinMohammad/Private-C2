package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/crypto"
)

func writePluginManifest(t *testing.T, dir string, manifest PluginManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifest.Name+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPluginsListAndRun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PC2_PLUGIN_DIR", dir)
	writePluginManifest(t, dir, PluginManifest{
		Name:    "recon",
		Version: "1.0.0",
		Commands: []PluginCommand{
			{Name: "pwd", TaskType: "pwd", ArgsTemplate: ""},
			{Name: "list", TaskType: "ls", ArgsTemplate: "{{.path}}",
				Arguments: []PluginArgument{{Name: "path", Required: true}}},
		},
	})

	router, srv, _ := setupTestRouter(t)
	token := getAuthToken(t, router)
	sessionID, cleanup := registerImplant(t, srv)
	defer cleanup()

	list := lootRequest(t, router, http.MethodGet, "/api/plugins", token, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list = %d %s", list.Code, list.Body.String())
	}
	var listed struct {
		Plugins []PluginManifest `json:"plugins"`
		Errors  []string         `json:"errors"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Errors) != 0 || len(listed.Plugins) != 1 || listed.Plugins[0].Name != "recon" {
		t.Fatalf("unexpected plugin list: %+v", listed)
	}

	run := lootRequest(t, router, http.MethodPost, "/api/plugins/run", token, map[string]any{
		"plugin": "recon", "command": "pwd", "session_id": sessionID,
	})
	if run.Code != http.StatusCreated || !strings.Contains(run.Body.String(), "task_id") {
		t.Fatalf("run pwd = %d %s", run.Code, run.Body.String())
	}

	missingArg := lootRequest(t, router, http.MethodPost, "/api/plugins/run", token, map[string]any{
		"plugin": "recon", "command": "list", "session_id": sessionID,
	})
	if missingArg.Code != http.StatusBadRequest {
		t.Fatalf("missing argument = %d %s", missingArg.Code, missingArg.Body.String())
	}

	withArg := lootRequest(t, router, http.MethodPost, "/api/plugins/run", token, map[string]any{
		"plugin": "recon", "command": "list", "session_id": sessionID,
		"arguments": map[string]string{"path": "/tmp"},
	})
	if withArg.Code != http.StatusCreated {
		t.Fatalf("run list = %d %s", withArg.Code, withArg.Body.String())
	}

	unknown := lootRequest(t, router, http.MethodPost, "/api/plugins/run", token, map[string]any{
		"plugin": "nope", "command": "pwd", "session_id": sessionID,
	})
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown plugin = %d", unknown.Code)
	}
}

func TestPluginsCannotBypassPolicy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PC2_PLUGIN_DIR", dir)
	writePluginManifest(t, dir, PluginManifest{
		Name:    "exec",
		Version: "1.0.0",
		Commands: []PluginCommand{
			{Name: "bof", TaskType: "inline_execute", ArgsTemplate: ""},
		},
	})

	router, srv, _ := setupTestRouter(t)
	token := getAuthToken(t, router)
	sessionID, cleanup := registerImplant(t, srv)
	defer cleanup()

	// The session has no engagement, so a code-execution task must be denied
	// by the same policy that governs direct tasking.
	run := lootRequest(t, router, http.MethodPost, "/api/plugins/run", token, map[string]any{
		"plugin": "exec", "command": "bof", "session_id": sessionID,
	})
	if run.Code != http.StatusForbidden {
		t.Fatalf("gated plugin run = %d %s", run.Code, run.Body.String())
	}
}

func TestPluginSignatures(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PC2_PLUGIN_DIR", dir)
	t.Setenv("PC2_PLUGIN_REQUIRE_SIGNED", "true")

	keyPair, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	manifest := PluginManifest{
		Name: "signed", Version: "1.0.0",
		Commands: []PluginCommand{{Name: "pwd", TaskType: "pwd"}},
	}
	message, err := canonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(crypto.Sign(keyPair.PrivateKey, message))
	manifest.PublicKey = base64.StdEncoding.EncodeToString(keyPair.PublicKey)
	if len(keyPair.PublicKey) != ed25519.PublicKeySize {
		t.Fatal("unexpected public key size")
	}
	writePluginManifest(t, dir, manifest)

	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)
	list := lootRequest(t, router, http.MethodGet, "/api/plugins", token, nil)
	var listed struct {
		Plugins []PluginManifest `json:"plugins"`
		Errors  []string         `json:"errors"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Errors) != 0 || len(listed.Plugins) != 1 {
		t.Fatalf("signed plugin rejected: %+v", listed)
	}

	// Tampering with a signed field must invalidate it.
	manifest.Version = "2.0.0"
	writePluginManifest(t, dir, manifest)
	list = lootRequest(t, router, http.MethodGet, "/api/plugins", token, nil)
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Plugins) != 0 || len(listed.Errors) == 0 ||
		!strings.Contains(strings.Join(listed.Errors, " "), "signature") {
		t.Fatalf("tampered plugin was accepted: %+v", listed)
	}
}

func TestPluginRejectsUnregisteredTaskType(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PC2_PLUGIN_DIR", dir)
	writePluginManifest(t, dir, PluginManifest{
		Name: "bad", Version: "1",
		Commands: []PluginCommand{{Name: "x", TaskType: "not-a-task"}},
	})

	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)
	list := lootRequest(t, router, http.MethodGet, "/api/plugins", token, nil)
	var listed struct {
		Plugins []PluginManifest `json:"plugins"`
		Errors  []string         `json:"errors"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Plugins) != 0 || len(listed.Errors) == 0 {
		t.Fatalf("invalid plugin was accepted: %+v", listed)
	}
}
