package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"github.com/azizbinmohammad/private-c2/server/store/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const maxLootBytes = 16 << 20

var lootKinds = map[string]bool{
	"credential": true,
	"file":       true,
	"screenshot": true,
	"ot_finding": true,
	"task":       true,
	"other":      true,
}

// lootHandler stores engagement-scoped artifacts on the server. Blob bytes are
// written under PC2_LOOT_DIR (default ./loot); the database holds metadata.
type lootHandler struct {
	db      *gorm.DB
	dir     string
	auditor *audit.Logger
}

func newLootHandler(db *gorm.DB, auditor *audit.Logger) *lootHandler {
	dir := os.Getenv("PC2_LOOT_DIR")
	if dir == "" {
		dir = "loot"
	}
	return &lootHandler{db: db, dir: dir, auditor: auditor}
}

type lootCreateRequest struct {
	EngagementID string `json:"engagement_id"`
	SessionID    string `json:"session_id"`
	TaskID       string `json:"task_id"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Note         string `json:"note"`
	Data         string `json:"data"` // base64; when empty and task_id is set, the task output is used
}

func (lh *lootHandler) handleLoot(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.Method {
	case http.MethodGet:
		lh.list(w, r)
	case http.MethodPost:
		lh.create(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
	}
}

func (lh *lootHandler) list(w http.ResponseWriter, r *http.Request) {
	repo := repository.NewLootRepository(lh.db)
	artifacts, err := repo.List(r.URL.Query().Get("engagement_id"), r.URL.Query().Get("kind"), 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, artifacts)
}

func (lh *lootHandler) create(w http.ResponseWriter, r *http.Request) {
	if lh.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "database unavailable"})
		return
	}

	var req lootCreateRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLootBytes+4096))
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	var data []byte
	if req.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "data must be base64"})
			return
		}
		data = decoded
	} else if req.TaskID != "" {
		var row models.TaskResult
		res := lh.db.Where("task_id = ?", req.TaskID).Limit(1).Find(&row)
		if res.Error != nil || res.RowsAffected == 0 {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "task result not found"})
			return
		}
		data = []byte(row.Output)
		if req.EngagementID == "" {
			req.EngagementID = row.EngagementID
		}
		if req.SessionID == "" {
			req.SessionID = row.SessionID
		}
		if req.Kind == "" {
			req.Kind = "task"
		}
		if req.Name == "" {
			req.Name = "task-" + req.TaskID
		}
	} else {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "provide data or a task_id"})
		return
	}

	if len(data) == 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "loot is empty"})
		return
	}
	if len(data) > maxLootBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, ErrorResponse{Error: "loot exceeds 16 MiB"})
		return
	}

	req.EngagementID = strings.TrimSpace(req.EngagementID)
	if req.EngagementID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "engagement_id is required"})
		return
	}
	var engagement models.Engagement
	if err := lh.db.First(&engagement, "id = ?", req.EngagementID).Error; err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "engagement not found"})
		return
	}

	if req.Kind == "" {
		req.Kind = "other"
	}
	if !lootKinds[req.Kind] {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "unsupported loot kind"})
		return
	}
	if req.Kind == "credential" && !engagement.AllowCredentialAccess {
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "credential access is not enabled for this engagement"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name is required"})
		return
	}

	id := uuid.New().String()
	if err := os.MkdirAll(lh.dir, 0700); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "cannot create loot directory"})
		return
	}
	path := filepath.Join(lh.dir, id+".bin")
	if err := writeFileAtomic(path, data); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "cannot store loot"})
		return
	}

	sum := sha256.Sum256(data)
	identity, _ := authz.FromContext(r.Context())
	operator := identity.OperatorID
	if operator == "" {
		operator = identity.Username
	}
	artifact := &models.LootArtifact{
		Base:         models.Base{ID: id},
		EngagementID: req.EngagementID,
		SessionID:    req.SessionID,
		TaskID:       req.TaskID,
		Operator:     operator,
		Kind:         req.Kind,
		Name:         req.Name,
		SHA256:       hex.EncodeToString(sum[:]),
		Size:         int64(len(data)),
		Path:         path,
		Note:         req.Note,
	}
	if err := repository.NewLootRepository(lh.db).Create(artifact); err != nil {
		_ = os.Remove(path)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	if lh.auditor != nil {
		_ = lh.auditor.Log(operator, req.EngagementID, req.SessionID, audit.EventDataCollect,
			"loot.create", id, req.Kind, map[string]any{"name": req.Name, "sha256": artifact.SHA256},
			r.RemoteAddr, "")
	}
	writeJSON(w, http.StatusCreated, artifact)
}

func (lh *lootHandler) handleLootDetail(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if lh.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "database unavailable"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/loot/")
	if rest == "" || strings.Contains(rest, "..") {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing loot ID"})
		return
	}

	id := rest
	download := false
	if strings.HasSuffix(rest, "/download") {
		id = strings.TrimSuffix(rest, "/download")
		download = true
	}
	if strings.Contains(id, "/") {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid loot ID"})
		return
	}

	repo := repository.NewLootRepository(lh.db)
	artifact, err := repo.Get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "loot not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		if download {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition",
				fmt.Sprintf("attachment; filename=%q", safeFilename(artifact.Name)))
			http.ServeFile(w, r, artifact.Path)
			return
		}
		writeJSON(w, http.StatusOK, artifact)

	case http.MethodDelete:
		if err := repo.Delete(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		_ = os.Remove(artifact.Path)
		if lh.auditor != nil {
			identity, _ := authz.FromContext(r.Context())
			operator := identity.OperatorID
			if operator == "" {
				operator = identity.Username
			}
			_ = lh.auditor.Log(operator, artifact.EngagementID, artifact.SessionID,
				audit.EventDataCollect, "loot.delete", id, artifact.Kind, nil, r.RemoteAddr, "")
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// safeFilename strips path separators and quotes from an operator-supplied
// name before it is used in Content-Disposition.
func safeFilename(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, `\`, "_")
	name = strings.ReplaceAll(name, `"`, "_")
	if name == "" {
		return "loot.bin"
	}
	return name
}
