package filesystem

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/azizbinmohammad/private-c2/pkg/engagement"
)

// Operation defines the filesystem operation type.
type Operation string

const (
	OpLS       Operation = "ls"
	OpCat      Operation = "cat"
	OpUpload   Operation = "upload"
	OpDownload Operation = "download"
	OpRm       Operation = "rm"
	OpMkdir    Operation = "mkdir"
	OpCp       Operation = "cp"
	OpMv       Operation = "mv"
	OpPwd      Operation = "pwd"
	OpCd       Operation = "cd"
)

// Request represents a filesystem operation request.
type Request struct {
	Op       Operation `json:"op"`
	Path     string    `json:"path"`
	DestPath string    `json:"dest_path,omitempty"` // for cp, mv
	Data     []byte    `json:"data,omitempty"`       // for upload
}

// FileInfo represents information about a single file.
type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

// Response represents the result of a filesystem operation.
type Response struct {
	Output string     `json:"output,omitempty"`
	Files  []FileInfo `json:"files,omitempty"`
	Data   []byte     `json:"data,omitempty"`
}

// Module provides filesystem operations with data quota enforcement.
type Module struct {
	quota *engagement.DataQuota
}

// NewModule creates a new filesystem module with optional data quota.
func NewModule(quota *engagement.DataQuota) *Module {
	return &Module{quota: quota}
}

// Execute handles a filesystem operation request.
func (m *Module) Execute(ctx context.Context, payload []byte) ([]byte, error) {
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("parsing filesystem request: %w", err)
	}

	var resp *Response
	var err error

	switch req.Op {
	case OpLS:
		resp, err = m.ls(req.Path)
	case OpCat:
		resp, err = m.cat(req.Path)
	case OpUpload:
		resp, err = m.upload(req.Path, req.Data)
	case OpDownload:
		resp, err = m.download(req.Path)
	case OpRm:
		resp, err = m.rm(req.Path)
	case OpMkdir:
		resp, err = m.mkdir(req.Path)
	case OpCp:
		resp, err = m.cp(req.Path, req.DestPath)
	case OpMv:
		resp, err = m.mv(req.Path, req.DestPath)
	case OpPwd:
		resp, err = m.pwd()
	case OpCd:
		resp, err = m.cd(req.Path)
	default:
		return nil, fmt.Errorf("unknown filesystem operation: %s", req.Op)
	}

	if err != nil {
		return nil, err
	}

	return json.Marshal(resp)
}

func (m *Module) ls(path string) (*Response, error) {
	if path == "" {
		path = "."
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("listing directory %s: %w", path, err)
	}

	files := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			IsDir:   entry.IsDir(),
		})
	}

	return &Response{Files: files}, nil
}

func (m *Module) cat(path string) (*Response, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}

	return &Response{Output: string(data)}, nil
}

func (m *Module) upload(path string, data []byte) (*Response, error) {
	if data == nil {
		return nil, fmt.Errorf("no data provided for upload")
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return nil, fmt.Errorf("writing file %s: %w", path, err)
	}

	return &Response{Output: fmt.Sprintf("uploaded %d bytes to %s", len(data), path)}, nil
}

func (m *Module) download(path string) (*Response, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	// Check data quota before reading.
	if m.quota != nil {
		if err := m.quota.Consume(info.Size()); err != nil {
			return nil, fmt.Errorf("data quota exceeded for %s (%d bytes): %w", path, info.Size(), err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}

	return &Response{Data: data}, nil
}

func (m *Module) rm(path string) (*Response, error) {
	err := os.RemoveAll(path)
	if err != nil {
		return nil, fmt.Errorf("removing %s: %w", path, err)
	}
	return &Response{Output: fmt.Sprintf("removed %s", path)}, nil
}

func (m *Module) mkdir(path string) (*Response, error) {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return nil, fmt.Errorf("creating directory %s: %w", path, err)
	}
	return &Response{Output: fmt.Sprintf("created directory %s", path)}, nil
}

func (m *Module) cp(src, dst string) (*Response, error) {
	if dst == "" {
		return nil, fmt.Errorf("destination path required for cp")
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("opening source %s: %w", src, err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat source %s: %w", src, err)
	}

	// If destination is a directory, use the source filename.
	dstInfo, err := os.Stat(dst)
	if err == nil && dstInfo.IsDir() {
		dst = filepath.Join(dst, filepath.Base(src))
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return nil, fmt.Errorf("creating destination %s: %w", dst, err)
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return nil, fmt.Errorf("copying %s to %s: %w", src, dst, err)
	}

	return &Response{Output: fmt.Sprintf("copied %d bytes from %s to %s", n, src, dst)}, nil
}

func (m *Module) mv(src, dst string) (*Response, error) {
	if dst == "" {
		return nil, fmt.Errorf("destination path required for mv")
	}

	err := os.Rename(src, dst)
	if err != nil {
		return nil, fmt.Errorf("moving %s to %s: %w", src, dst, err)
	}

	return &Response{Output: fmt.Sprintf("moved %s to %s", src, dst)}, nil
}

func (m *Module) pwd() (*Response, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("getting working directory: %w", err)
	}
	return &Response{Output: dir}, nil
}

func (m *Module) cd(path string) (*Response, error) {
	err := os.Chdir(path)
	if err != nil {
		return nil, fmt.Errorf("changing directory to %s: %w", path, err)
	}

	newDir, _ := os.Getwd()
	return &Response{Output: newDir}, nil
}
