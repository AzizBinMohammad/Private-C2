package screenshot

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
)

// Request represents a screenshot capture request.
type Request struct {
	Display int    `json:"display,omitempty"` // display/monitor number (0 = primary)
	Format  string `json:"format,omitempty"`  // "png" (default) or "jpeg"
	Quality int    `json:"quality,omitempty"` // JPEG quality 1-100
}

// Response represents a screenshot capture result.
type Response struct {
	Data   []byte `json:"data"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Format string `json:"format"`
}

// Execute captures a screenshot of the screen.
// This is a platform-specific stub that returns appropriate errors
// on platforms where screenshot capture is not implemented.
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

// captureScreen is the platform-specific screenshot implementation.
// TODO: Implement platform-specific capture:
//   - Linux: use X11 (XGetImage) or Wayland (wlr-screencopy) or xdg-desktop-portal
//   - Windows: use GDI (BitBlt) or DXGI desktop duplication
//   - macOS: use CGWindowListCreateImage
func captureScreen(_ context.Context, req Request) (*Response, error) {
	switch runtime.GOOS {
	case "linux":
		return nil, fmt.Errorf("screenshot capture on Linux requires X11 or Wayland support (not yet implemented)")
	case "windows":
		return nil, fmt.Errorf("screenshot capture on Windows requires GDI/DXGI support (not yet implemented)")
	case "darwin":
		return nil, fmt.Errorf("screenshot capture on macOS requires CGWindowListCreateImage (not yet implemented)")
	default:
		return nil, fmt.Errorf("screenshot capture not supported on %s", runtime.GOOS)
	}
}
