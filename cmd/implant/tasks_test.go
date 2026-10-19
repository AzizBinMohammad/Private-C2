package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/azizbinmohammad/private-c2/implant/safety"
	"github.com/azizbinmohammad/private-c2/pkg/engagement"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func TestTaskHandlersMatchProtocolRegistry(t *testing.T) {
	for _, taskType := range protocol.ImplementedTaskTypes() {
		if _, ok := taskHandlers[taskType]; !ok {
			t.Errorf("protocol advertises %q but the implant has no handler", taskType)
		}
	}
	for taskType := range taskHandlers {
		if !protocol.IsImplementedTaskType(taskType) {
			t.Errorf("implant registers %q but the protocol registry does not list it", taskType)
		}
	}
}

func TestHandleTaskUnknownType(t *testing.T) {
	if _, err := handleTask(context.Background(), protocol.TaskWire{Type: "not-a-task"}); err == nil {
		t.Fatal("expected an error for an unknown task type")
	}
}

func TestSplitPair(t *testing.T) {
	cases := []struct {
		args string
		src  string
		dst  string
		ok   bool
	}{
		{"a|b", "a", "b", true},
		{"a b", "a", "b", true},
		{"only-one", "", "", false},
		{"|b", "", "", false},
		{"a|", "", "", false},
	}
	for _, tc := range cases {
		src, dst, err := splitPair(tc.args)
		if tc.ok {
			if err != nil || src != tc.src || dst != tc.dst {
				t.Errorf("splitPair(%q) = (%q,%q,%v), want (%q,%q,nil)", tc.args, src, dst, err, tc.src, tc.dst)
			}
		} else if err == nil {
			t.Errorf("splitPair(%q) unexpectedly succeeded", tc.args)
		}
	}
}

func TestParsePortscanArgs(t *testing.T) {
	cases := []struct {
		args   string
		target string
		ports  []int
		ok     bool
	}{
		{"10.0.0.1", "10.0.0.1", nil, true},
		{"10.0.0.1:22,80,443", "10.0.0.1", []int{22, 80, 443}, true},
		{"host.example:8080", "host.example", []int{8080}, true},
		{"", "", nil, false},
		{"host:notaport", "host:notaport", nil, true}, // colon suffix is not a port list
	}
	for _, tc := range cases {
		target, ports, err := parsePortscanArgs(tc.args)
		if tc.ok {
			if err != nil || target != tc.target || !reflect.DeepEqual(ports, tc.ports) {
				t.Errorf("parsePortscanArgs(%q) = (%q,%v,%v), want (%q,%v,nil)", tc.args, target, ports, err, tc.target, tc.ports)
			}
		} else if err == nil {
			t.Errorf("parsePortscanArgs(%q) unexpectedly succeeded", tc.args)
		}
	}
}

func TestFilesystemHandlers(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	if _, err := handleMkdir(ctx, filepath.Join(dir, "sub")); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := filepath.Join(dir, "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.txt")
	if _, err := handleCp(ctx, src+"|"+dst); err != nil {
		t.Fatalf("cp: %v", err)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "hello" {
		t.Fatalf("copied content = %q, err = %v", got, err)
	}
	moved := filepath.Join(dir, "moved.txt")
	if _, err := handleMv(ctx, dst+"|"+moved); err != nil {
		t.Fatalf("mv: %v", err)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatalf("moved file missing: %v", err)
	}
	if _, err := handleRm(ctx, moved); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if _, err := os.Stat(moved); !os.IsNotExist(err) {
		t.Fatalf("file still exists after rm: %v", err)
	}
}

func TestUploadDownloadHandlers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upload.bin")
	payload := base64.StdEncoding.EncodeToString([]byte("payload"))

	if _, err := handleUpload(context.Background(), payload+"|"+path); err != nil {
		t.Fatalf("upload: %v", err)
	}
	got, err := handleDownload(context.Background(), path)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decode download: %v", err)
	}
	if string(decoded) != "payload" {
		t.Fatalf("download = %q, want payload", decoded)
	}
}

func TestChunkedDownload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	content := make([]byte, 2*1024*1024+123)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	statJSON, err := handleDownloadStat(context.Background(), path)
	if err != nil {
		t.Fatalf("download_stat: %v", err)
	}
	var stat struct {
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(statJSON), &stat); err != nil {
		t.Fatalf("decode stat: %v", err)
	}
	if stat.Size != int64(len(content)) || stat.SHA256 == "" {
		t.Fatalf("unexpected stat: %+v", stat)
	}

	var assembled []byte
	const chunkSize = 1 << 20
	for offset := int64(0); offset < int64(len(content)); offset += chunkSize {
		args, _ := json.Marshal(map[string]any{"path": path, "offset": offset, "length": chunkSize})
		out, err := handleDownloadChunk(context.Background(), string(args))
		if err != nil {
			t.Fatalf("download_chunk at %d: %v", offset, err)
		}
		var chunk struct {
			Data   string `json:"data"`
			Offset int64  `json:"offset"`
			Length int    `json:"length"`
			EOF    bool   `json:"eof"`
		}
		if err := json.Unmarshal([]byte(out), &chunk); err != nil {
			t.Fatalf("decode chunk: %v", err)
		}
		data, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			t.Fatal(err)
		}
		assembled = append(assembled, data...)
		if chunk.EOF && offset+int64(chunk.Length) >= int64(len(content)) {
			break
		}
	}
	if !reflect.DeepEqual(assembled, content) {
		t.Fatalf("assembled %d bytes, want %d", len(assembled), len(content))
	}
}

func TestChunkedUpload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uploaded.bin")

	first, _ := json.Marshal(map[string]any{
		"path": path, "offset": 0, "data": base64.StdEncoding.EncodeToString([]byte("hello ")), "truncate": true,
	})
	if _, err := handleUploadChunk(context.Background(), string(first)); err != nil {
		t.Fatalf("first upload_chunk: %v", err)
	}
	second, _ := json.Marshal(map[string]any{
		"path": path, "offset": 6, "data": base64.StdEncoding.EncodeToString([]byte("world")),
	})
	if _, err := handleUploadChunk(context.Background(), string(second)); err != nil {
		t.Fatalf("second upload_chunk: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("uploaded content = %q", got)
	}
}

func TestChunkedDownload_DataQuota(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quota.bin")
	if err := os.WriteFile(path, make([]byte, 1024), 0644); err != nil {
		t.Fatal(err)
	}

	old := agentSafety
	agentSafety = safety.NewSafetyChecker(safety.SafetyConfig{DataQuota: engagement.NewDataQuota(10)})
	defer func() { agentSafety = old }()

	args, _ := json.Marshal(map[string]any{"path": path, "offset": 0, "length": 100})
	if _, err := handleDownloadChunk(context.Background(), string(args)); err == nil {
		t.Fatal("download_chunk ignored the data quota")
	}
}

func TestHandleKillRejectsInvalidPID(t *testing.T) {
	for _, args := range []string{"", "abc", "0", "-1"} {
		if _, err := handleKill(context.Background(), args); err == nil {
			t.Errorf("handleKill(%q) unexpectedly succeeded", args)
		}
	}
}
