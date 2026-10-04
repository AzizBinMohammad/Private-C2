package stages

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/azizbinmohammad/private-c2/server/build"
)

// CompileResult holds the output of the compile stage.
type CompileResult struct {
	OutputPath string
	Duration   time.Duration
}

// DefaultCompileTimeout is the maximum time allowed for a single compilation.
const DefaultCompileTimeout = 10 * time.Minute

// Compile cross-compiles the implant source using `go build` with the
// appropriate GOOS, GOARCH, and build tags. Debug symbols are stripped
// for non-debug builds.
func Compile(ctx context.Context, cfg *build.BuildConfig, configResult *ConfigureResult, workDir string) (*CompileResult, error) {
	start := time.Now()

	outputName := buildOutputName(cfg)
	outputPath := filepath.Join(workDir, outputName)

	args := buildCompileArgs(cfg, configResult, outputPath)
	env := buildCompileEnv(cfg)

	compileCtx, cancel := context.WithTimeout(ctx, DefaultCompileTimeout)
	defer cancel()

	cmd := exec.CommandContext(compileCtx, "go", args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = configResult.SourceDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		if compileCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("compilation timed out after %s", DefaultCompileTimeout)
		}
		return nil, fmt.Errorf("compilation failed: %w\noutput: %s", err, string(output))
	}

	return &CompileResult{
		OutputPath: outputPath,
		Duration:   time.Since(start),
	}, nil
}

// buildCompileArgs constructs the `go build` argument list.
func buildCompileArgs(cfg *build.BuildConfig, configResult *ConfigureResult, outputPath string) []string {
	args := []string{"build"}

	// Build tags
	if len(configResult.BuildTags) > 0 {
		args = append(args, "-tags", strings.Join(configResult.BuildTags, ","))
	}

	// Strip debug info for release builds
	if !cfg.Debug {
		args = append(args, "-ldflags", "-s -w")
		args = append(args, "-trimpath")
	}

	args = append(args, "-o", outputPath)
	args = append(args, ".")

	return args
}

// buildCompileEnv returns the environment variables for cross-compilation.
func buildCompileEnv(cfg *build.BuildConfig) []string {
	env := []string{
		fmt.Sprintf("GOOS=%s", cfg.TargetOS),
		fmt.Sprintf("GOARCH=%s", cfg.TargetArch),
		"CGO_ENABLED=0",
	}
	return env
}

// buildOutputName returns the output binary name based on platform and format.
func buildOutputName(cfg *build.BuildConfig) string {
	name := "implant"

	switch cfg.OutputFormat {
	case "dll":
		if cfg.TargetOS == "windows" {
			return name + ".dll"
		}
		return name + ".so"
	case "shared":
		if cfg.TargetOS == "windows" {
			return name + ".dll"
		}
		if cfg.TargetOS == "darwin" {
			return name + ".dylib"
		}
		return name + ".so"
	case "shellcode":
		return name + ".bin"
	default:
		if cfg.TargetOS == "windows" {
			return name + ".exe"
		}
		return name
	}
}
