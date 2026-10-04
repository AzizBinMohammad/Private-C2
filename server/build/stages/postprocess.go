package stages

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/azizbinmohammad/private-c2/server/build"
)

// PostProcessResult holds the output of the post-processing stage.
type PostProcessResult struct {
	OutputPath string
	SHA256     string
	FileSize   int64
}

// PostProcess applies output format transformations to the compiled binary.
// Supported transformations:
//   - exe: default, no transformation needed
//   - dll: wraps binary as a DLL export stub
//   - shellcode: converts binary to position-independent shellcode
//   - shared: wraps binary as a shared library stub
func PostProcess(cfg *build.BuildConfig, compiledPath string, workDir string) (*PostProcessResult, error) {
	var outputPath string
	var err error

	switch cfg.OutputFormat {
	case "exe", "":
		outputPath = compiledPath
	case "dll":
		outputPath, err = transformDLL(compiledPath, workDir, cfg.TargetOS)
	case "shellcode":
		outputPath, err = transformShellcode(compiledPath, workDir)
	case "shared":
		outputPath, err = transformShared(compiledPath, workDir, cfg.TargetOS)
	default:
		return nil, fmt.Errorf("unsupported output format: %s", cfg.OutputFormat)
	}

	if err != nil {
		return nil, fmt.Errorf("post-process %s: %w", cfg.OutputFormat, err)
	}

	hash, size, err := hashAndSize(outputPath)
	if err != nil {
		return nil, fmt.Errorf("hash output: %w", err)
	}

	return &PostProcessResult{
		OutputPath: outputPath,
		SHA256:     hash,
		FileSize:   size,
	}, nil
}

// transformDLL wraps the compiled binary as a DLL export stub.
// This writes a PE DLL header stub prepended to the binary payload.
func transformDLL(inputPath, workDir, targetOS string) (string, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}

	ext := ".dll"
	if targetOS != "windows" {
		ext = ".so"
	}

	// DLL stub header: a minimal placeholder that marks this as a DLL artifact.
	// In a production build, this would contain a proper PE header with DllMain
	// or an ELF shared object prologue.
	stub := []byte("PC2DLL\x00\x00")

	outputPath := filepath.Join(workDir, "implant"+ext)
	if err := os.WriteFile(outputPath, append(stub, data...), 0o700); err != nil {
		return "", fmt.Errorf("write dll: %w", err)
	}

	return outputPath, nil
}

// transformShellcode converts the binary into a position-independent shellcode
// format. In a production build this would perform PE-to-shellcode conversion
// (sRDI-style) or ELF flat binary extraction. Here we wrap the binary with a
// shellcode container header.
func transformShellcode(inputPath, workDir string) (string, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}

	// Shellcode container: marker + length prefix + payload.
	header := []byte("PC2SC\x00\x00\x00")
	size := uint32(len(data))
	header = append(header,
		byte(size>>24), byte(size>>16), byte(size>>8), byte(size),
	)

	outputPath := filepath.Join(workDir, "implant.bin")
	if err := os.WriteFile(outputPath, append(header, data...), 0o700); err != nil {
		return "", fmt.Errorf("write shellcode: %w", err)
	}

	return outputPath, nil
}

// transformShared wraps the binary as a platform-appropriate shared library
// stub.
func transformShared(inputPath, workDir, targetOS string) (string, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}

	ext := ".so"
	if targetOS == "windows" {
		ext = ".dll"
	} else if targetOS == "darwin" {
		ext = ".dylib"
	}

	// Shared library stub header.
	stub := []byte("PC2SO\x00\x00\x00")

	outputPath := filepath.Join(workDir, "implant"+ext)
	if err := os.WriteFile(outputPath, append(stub, data...), 0o700); err != nil {
		return "", fmt.Errorf("write shared: %w", err)
	}

	return outputPath, nil
}

// hashAndSize computes the SHA-256 hash and file size of the given file.
func hashAndSize(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// SignBinary applies a code signature to the binary. This is a placeholder
// that records the signing operation; a production implementation would use
// an HSM-backed code signing key.
func SignBinary(binaryPath string) error {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read binary for signing: %w", err)
	}

	// Compute signature over the binary content.
	h := sha256.Sum256(data)
	sig := []byte("PC2SIG:")
	sig = append(sig, []byte(hex.EncodeToString(h[:]))...)
	sig = append(sig, '\n')

	sigPath := binaryPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}

	return nil
}
