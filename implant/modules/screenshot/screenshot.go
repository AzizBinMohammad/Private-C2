package screenshot

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"os/exec"
	"runtime"
)

type Request struct {
	Display int    `json:"display,omitempty"`
	Format  string `json:"format,omitempty"`
	Quality int    `json:"quality,omitempty"`
}

type Response struct {
	Data   []byte `json:"data"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Format string `json:"format"`
}

func Execute(ctx context.Context, payload []byte) ([]byte, error) {
	var req Request
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fmt.Errorf("parsing screenshot request: %w", err)
		}
	}

	if req.Format == "" {
		req.Format = "png"
	}

	resp, err := captureScreen(ctx, req)
	if err != nil {
		return nil, err
	}

	return json.Marshal(resp)
}

func captureScreen(ctx context.Context, req Request) (*Response, error) {
	switch runtime.GOOS {
	case "linux":
		return captureLinux(ctx, req)
	case "windows":
		return nil, fmt.Errorf("screenshot capture on Windows requires GDI/DXGI support (not yet implemented)")
	case "darwin":
		return nil, fmt.Errorf("screenshot capture on macOS requires CGWindowListCreateImage (not yet implemented)")
	default:
		return nil, fmt.Errorf("screenshot capture not supported on %s", runtime.GOOS)
	}
}

func captureLinux(ctx context.Context, req Request) (*Response, error) {
	tmpFile, err := os.CreateTemp("", ".sc-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpBase := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpBase)

	ext := ".png"
	if req.Format == "jpeg" {
		ext = ".jpg"
	}
	outPath := tmpBase + ext
	defer os.Remove(outPath)

	type tool struct {
		name string
		fn   func() error
	}

	tools := []tool{
		{"import", func() error {
			cmd := exec.CommandContext(ctx, "import", "-window", "root", outPath)
			return cmd.Run()
		}},
		{"scrot", func() error {
			cmd := exec.CommandContext(ctx, "scrot", outPath)
			return cmd.Run()
		}},
		{"xwd", func() error {
			xwdPath := tmpBase + ".xwd"
			defer os.Remove(xwdPath)
			cmd := exec.CommandContext(ctx, "xwd", "-root", "-out", xwdPath)
			if err := cmd.Run(); err != nil {
				return err
			}
			return exec.CommandContext(ctx, "convert", xwdPath, outPath).Run()
		}},
		{"gnome-screenshot", func() error {
			cmd := exec.CommandContext(ctx, "gnome-screenshot", "-f", outPath)
			return cmd.Run()
		}},
	}

	var lastErr error
	for _, t := range tools {
		if _, err := exec.LookPath(t.name); err != nil {
			continue
		}
		if err := t.fn(); err != nil {
			lastErr = fmt.Errorf("%s: %w", t.name, err)
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return nil, lastErr
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read screenshot: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no screenshot tool available (tried: import, scrot, xwd, gnome-screenshot)")
	}

	width, height := 0, 0
	if f, err := os.Open(outPath); err == nil {
		if cfg, _, err := image.DecodeConfig(f); err == nil {
			width = cfg.Width
			height = cfg.Height
		}
		f.Close()
	}

	return &Response{
		Data:   data,
		Width:  width,
		Height: height,
		Format: req.Format,
	}, nil
}
