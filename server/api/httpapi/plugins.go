package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/pkg/crypto"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
)

// PluginArgument documents one argument a plugin command accepts.
type PluginArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
}

// PluginCommand maps an operator-facing command to a registered task type and
// an argument template.
type PluginCommand struct {
	Name         string           `json:"name"`
	TaskType     string           `json:"task_type"`
	Description  string           `json:"description,omitempty"`
	ArgsTemplate string           `json:"args_template"`
	Arguments    []PluginArgument `json:"arguments,omitempty"`
}

// PluginManifest is the on-disk extension format. Unsigned manifests are
// accepted unless PC2_PLUGIN_REQUIRE_SIGNED=true.
type PluginManifest struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description,omitempty"`
	Author      string          `json:"author,omitempty"`
	Requires    []string        `json:"requires,omitempty"`
	Commands    []PluginCommand `json:"commands"`
	Signature   string          `json:"signature,omitempty"`
	PublicKey   string          `json:"public_key,omitempty"`
}

var pluginNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type pluginHandler struct {
	sh      *sessionHandler
	dir     string
	auditor *audit.Logger
}

func newPluginHandler(sh *sessionHandler, auditor *audit.Logger) *pluginHandler {
	dir := os.Getenv("PC2_PLUGIN_DIR")
	if dir == "" {
		dir = "plugins"
	}
	return &pluginHandler{sh: sh, dir: dir, auditor: auditor}
}

func (ph *pluginHandler) handlePlugins(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}
	manifests, errs := ph.loadPlugins()
	writeJSON(w, http.StatusOK, map[string]any{
		"plugins": manifests,
		"errors":  errs,
	})
}

func (ph *pluginHandler) handlePluginAction(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/plugins/")
	switch action {
	case "reload":
		manifests, errs := ph.loadPlugins()
		writeJSON(w, http.StatusOK, map[string]any{"plugins": manifests, "errors": errs})
	case "run":
		ph.runPlugin(w, r)
	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
	}
}

type pluginRunRequest struct {
	Plugin    string            `json:"plugin"`
	Command   string            `json:"command"`
	SessionID string            `json:"session_id"`
	Arguments map[string]string `json:"arguments"`
}

func (ph *pluginHandler) runPlugin(w http.ResponseWriter, r *http.Request) {
	var req pluginRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}
	if req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "session_id is required"})
		return
	}
	manifests, _ := ph.loadPlugins()
	manifest, command, err := findPluginCommand(manifests, req.Plugin, req.Command)
	if err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	for _, arg := range command.Arguments {
		if arg.Required && strings.TrimSpace(req.Arguments[arg.Name]) == "" {
			writeJSON(w, http.StatusBadRequest,
				ErrorResponse{Error: fmt.Sprintf("argument %q is required", arg.Name)})
			return
		}
	}
	allowed := map[string]bool{}
	for _, arg := range command.Arguments {
		allowed[arg.Name] = true
	}
	for name := range req.Arguments {
		if len(command.Arguments) > 0 && !allowed[name] {
			writeJSON(w, http.StatusBadRequest,
				ErrorResponse{Error: fmt.Sprintf("unknown argument %q", name)})
			return
		}
	}

	tmpl, err := template.New("args").Option("missingkey=error").Parse(command.ArgsTemplate)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "invalid args template"})
		return
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, req.Arguments); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "rendering args: " + err.Error()})
		return
	}

	if ph.auditor != nil {
		identity := identityFrom(r)
		operator := identity.OperatorID
		if operator == "" {
			operator = identity.Username
		}
		_ = ph.auditor.Log(operator, "", req.SessionID, audit.EventPluginRun,
			"plugin.run", manifest.Name+"/"+command.Name, command.TaskType,
			map[string]any{"arguments": req.Arguments}, r.RemoteAddr, "")
	}
	// submitTask applies the same engagement policy as direct tasking; a
	// plugin cannot bypass a capability gate.
	ph.sh.submitTask(w, r, req.SessionID, command.TaskType, rendered.String())
}

// loadPlugins reads every manifest in the plugin directory. Individual errors
// are returned instead of hiding the other manifests.
func (ph *pluginHandler) loadPlugins() ([]PluginManifest, []string) {
	requireSigned := strings.EqualFold(os.Getenv("PC2_PLUGIN_REQUIRE_SIGNED"), "true")
	files, globErr := filepath.Glob(filepath.Join(ph.dir, "*.json"))
	if globErr != nil {
		return nil, []string{globErr.Error()}
	}

	var manifests []PluginManifest
	var errs []string
	seen := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(file), err))
			continue
		}
		var manifest PluginManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(file), err))
			continue
		}
		if err := validateManifest(manifest, requireSigned); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(file), err))
			continue
		}
		if seen[manifest.Name] {
			errs = append(errs, fmt.Sprintf("%s: duplicate plugin name %q", filepath.Base(file), manifest.Name))
			continue
		}
		seen[manifest.Name] = true
		manifests = append(manifests, manifest)
	}

	for _, manifest := range manifests {
		for _, required := range manifest.Requires {
			if !seen[required] {
				errs = append(errs, fmt.Sprintf("%s: missing dependency %q", manifest.Name, required))
			}
		}
	}
	return manifests, errs
}

func validateManifest(m PluginManifest, requireSigned bool) error {
	if !pluginNameRE.MatchString(m.Name) {
		return fmt.Errorf("invalid plugin name")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("version is required")
	}
	if len(m.Commands) == 0 {
		return fmt.Errorf("at least one command is required")
	}
	commands := map[string]bool{}
	for _, command := range m.Commands {
		if !pluginNameRE.MatchString(command.Name) {
			return fmt.Errorf("invalid command name %q", command.Name)
		}
		if commands[command.Name] {
			return fmt.Errorf("duplicate command %q", command.Name)
		}
		commands[command.Name] = true
		if !protocol.IsImplementedTaskType(command.TaskType) {
			return fmt.Errorf("command %q uses unregistered task type %q", command.Name, command.TaskType)
		}
		if _, err := template.New("args").Option("missingkey=error").Parse(command.ArgsTemplate); err != nil {
			return fmt.Errorf("command %q has an invalid args template: %w", command.Name, err)
		}
	}

	if m.Signature == "" && m.PublicKey == "" {
		if requireSigned {
			return fmt.Errorf("manifest must be signed")
		}
		return nil
	}
	if m.Signature == "" || m.PublicKey == "" {
		return fmt.Errorf("signature and public_key must be supplied together")
	}
	pub, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	message, err := canonicalManifest(m)
	if err != nil {
		return err
	}
	if err := crypto.Verify(ed25519.PublicKey(pub), message, sig); err != nil {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func canonicalManifest(m PluginManifest) ([]byte, error) {
	m.Signature = ""
	m.PublicKey = ""
	return json.Marshal(m)
}

func findPluginCommand(manifests []PluginManifest, pluginName, commandName string) (*PluginManifest, *PluginCommand, error) {
	for i := range manifests {
		if manifests[i].Name != pluginName {
			continue
		}
		for j := range manifests[i].Commands {
			if manifests[i].Commands[j].Name == commandName {
				return &manifests[i], &manifests[i].Commands[j], nil
			}
		}
		return nil, nil, fmt.Errorf("plugin %q has no command %q", pluginName, commandName)
	}
	return nil, nil, fmt.Errorf("plugin %q not found", pluginName)
}

func identityFrom(r *http.Request) authz.Identity {
	identity, _ := authz.FromContext(r.Context())
	return identity
}
