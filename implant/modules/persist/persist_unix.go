//go:build !windows

package persist

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func executePlatform(ctx context.Context, kind string, req Request, home string) (Result, error) {
	switch kind {
	case "shell":
		return shellPersist(req, home)
	case "systemd":
		if runtime.GOOS != "linux" {
			return Result{}, fmt.Errorf("systemd persistence is Linux-only")
		}
		return systemdPersist(ctx, req, home)
	case "cron":
		return cronPersist(ctx, req)
	default:
		return Result{}, fmt.Errorf("persistence kind %q is not supported on %s", kind, runtime.GOOS)
	}
}

// ---- shell profile ----

func shellProfile(home string) string {
	candidates := []string{".bashrc", ".zshrc", ".profile"}
	for _, name := range candidates {
		path := filepath.Join(home, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return filepath.Join(home, ".profile")
}

func shellBegin(id string) string { return "# pc2-begin:" + id }
func shellEnd(id string) string   { return "# pc2-end:" + id }

func shellBlock(id, command string) string {
	return shellBegin(id) + "\n" + command + "\n" + shellEnd(id) + "\n"
}

func stripShellBlock(content, id string) (string, bool) {
	begin, end := shellBegin(id), shellEnd(id)
	lines := strings.SplitAfter(content, "\n")
	var out strings.Builder
	skipping, changed := false, false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == begin:
			skipping, changed = true, true
			continue
		case skipping && trimmed == end:
			skipping = false
			continue
		case skipping:
			continue
		default:
			out.WriteString(line)
		}
	}
	return out.String(), changed
}

func shellPersist(req Request, home string) (Result, error) {
	path := shellProfile(home)
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return Result{}, err
	}
	content := string(data)
	id := ArtifactID("shell", req.Name)

	switch req.Action {
	case "list":
		var found []string
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "# pc2-begin:") {
				found = append(found, strings.TrimPrefix(strings.TrimSpace(line), "# pc2-begin:"))
			}
		}
		return Result{Kind: "shell", Action: "list", Path: path, Note: strings.Join(found, ",")}, nil

	case "remove":
		updated, changed := stripShellBlock(content, id)
		if !changed {
			return resultFor("shell", req, path, false, "no matching shell block"), nil
		}
		if req.DryRun {
			return resultFor("shell", req, path, false, "dry run: block would be removed"), nil
		}
		if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
			return Result{}, err
		}
		return resultFor("shell", req, path, true, ""), nil

	default:
		if strings.Contains(content, shellBegin(id)) {
			return resultFor("shell", req, path, false, "artifact already present"), nil
		}
		if req.DryRun {
			return resultFor("shell", req, path, false, "dry run: block would be appended"), nil
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return Result{}, err
		}
		defer f.Close()
		block := shellBlock(id, req.Command)
		if content != "" && !strings.HasSuffix(content, "\n") {
			block = "\n" + block
		}
		if _, err := f.WriteString(block); err != nil {
			return Result{}, err
		}
		return resultFor("shell", req, path, true, ""), nil
	}
}

// ---- systemd user unit ----

func systemdUnitPath(home, name string) string {
	return filepath.Join(home, ".config", "systemd", "user", name+".service")
}

func systemdUnit(id, command string) string {
	escaped := strings.ReplaceAll(command, "'", `'\''`)
	return fmt.Sprintf(`[Unit]
Description=pc2 %s
# pc2-artifact:%s

[Service]
Type=simple
ExecStart=/bin/sh -c '%s'
Restart=on-failure

[Install]
WantedBy=default.target
`, id, id, escaped)
}

func runSystemctl(ctx context.Context, args ...string) string {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return "systemctl is not available on this target"
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, append([]string{"--user"}, args...)...).CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		if trimmed == "" {
			return fmt.Sprintf("systemctl %s: %v", strings.Join(args, " "), err)
		}
		return fmt.Sprintf("systemctl %s: %v: %s", strings.Join(args, " "), err, trimmed)
	}
	return ""
}

func systemdPersist(ctx context.Context, req Request, home string) (Result, error) {
	if req.Scope != "" && req.Scope != "user" {
		return Result{}, fmt.Errorf("only user-scope systemd units are supported")
	}
	path := systemdUnitPath(home, req.Name)
	id := ArtifactID("systemd", req.Name)

	switch req.Action {
	case "list":
		entries, _ := os.ReadDir(filepath.Dir(path))
		var found []string
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(filepath.Dir(path), e.Name()))
			if err == nil && strings.Contains(string(data), "# pc2-artifact:") {
				found = append(found, strings.TrimSuffix(e.Name(), ".service"))
			}
		}
		return Result{Kind: "systemd", Action: "list", Path: filepath.Dir(path), Note: strings.Join(found, ",")}, nil

	case "remove":
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return resultFor("systemd", req, path, false, "unit does not exist"), nil
		}
		if req.DryRun {
			return resultFor("systemd", req, path, false, "dry run: unit would be disabled and removed"), nil
		}
		note := runSystemctl(ctx, "disable", "--now", req.Name+".service")
		if err := os.Remove(path); err != nil {
			return Result{}, err
		}
		if reload := runSystemctl(ctx, "daemon-reload"); reload != "" {
			note = strings.TrimSpace(note + "; " + reload)
		}
		return resultFor("systemd", req, path, true, note), nil

	default:
		if req.DryRun {
			return resultFor("systemd", req, path, false, "dry run: unit would be written and enabled"), nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(path, []byte(systemdUnit(id, req.Command)), 0644); err != nil {
			return Result{}, err
		}
		note := runSystemctl(ctx, "daemon-reload")
		if enable := runSystemctl(ctx, "enable", "--now", req.Name+".service"); enable != "" {
			if note != "" {
				note += "; "
			}
			note += enable
		}
		return resultFor("systemd", req, path, true, note), nil
	}
}

// ---- crontab ----

func cronMarker(id string) string { return "# pc2-artifact:" + id }

func addCronLine(current, line, marker string) (string, bool) {
	for _, existing := range strings.Split(current, "\n") {
		if strings.Contains(existing, marker) {
			return current, false
		}
	}
	if current != "" && !strings.HasSuffix(current, "\n") {
		current += "\n"
	}
	return current + line + "\n", true
}

func removeCronLines(current, marker string) (string, bool) {
	var kept []string
	changed := false
	for _, line := range strings.Split(current, "\n") {
		if strings.Contains(line, marker) {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n"), changed
}

func readCrontab(ctx context.Context) (string, error) {
	path, err := exec.LookPath("crontab")
	if err != nil {
		return "", fmt.Errorf("crontab is not installed on the target")
	}
	out, err := exec.CommandContext(ctx, path, "-l").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && strings.Contains(string(exitErr.Stderr), "no crontab") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %w", err)
	}
	return string(out), nil
}

func writeCrontab(ctx context.Context, content string) error {
	path, err := exec.LookPath("crontab")
	if err != nil {
		return fmt.Errorf("crontab is not installed on the target")
	}
	cmd := exec.CommandContext(ctx, path, "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("crontab -: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cronPersist(ctx context.Context, req Request) (Result, error) {
	current, err := readCrontab(ctx)
	if err != nil {
		return Result{}, err
	}
	id := ArtifactID("cron", req.Name)
	marker := cronMarker(id)

	if req.Action == "list" {
		var found []string
		for _, line := range strings.Split(current, "\n") {
			if i := strings.Index(line, "# pc2-artifact:"); i >= 0 {
				found = append(found, strings.TrimSpace(line[i+len("# pc2-artifact:"):]))
			}
		}
		return Result{Kind: "cron", Action: "list", Note: strings.Join(found, ",")}, nil
	}

	schedule := req.Schedule
	if schedule == "" {
		schedule = "@reboot"
	}
	line := schedule + " " + req.Command + " " + marker

	updated, changed := addCronLine(current, line, marker)
	if req.Action == "remove" {
		updated, changed = removeCronLines(current, marker)
	}
	if !changed {
		return resultFor("cron", req, "", false, "no change required"), nil
	}
	if req.DryRun {
		return resultFor("cron", req, "", false, "dry run: crontab would change"), nil
	}
	if err := writeCrontab(ctx, updated); err != nil {
		return Result{}, err
	}
	return resultFor("cron", req, "", true, ""), nil
}
