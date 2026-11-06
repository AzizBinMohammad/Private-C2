//go:build windows

package persist

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

func executePlatform(ctx context.Context, kind string, req Request, home string) (Result, error) {
	switch kind {
	case "registry":
		return registryPersist(ctx, req)
	case "schtasks":
		return schtasksPersist(ctx, req)
	default:
		return Result{}, fmt.Errorf("persistence kind %q is not supported on Windows", kind)
	}
}

func registryPersist(ctx context.Context, req Request) (Result, error) {
	valueName := "pc2-" + req.Name
	id := ArtifactID("registry", req.Name)

	switch req.Action {
	case "list":
		out, err := exec.CommandContext(ctx, "reg.exe", "query", runKey).Output()
		if err != nil {
			return resultFor("registry", req, runKey, false, "no Run key entries"), nil
		}
		var found []string
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasPrefix(fields[0], "pc2-") {
				found = append(found, strings.TrimPrefix(fields[0], "pc2-"))
			}
		}
		return Result{Kind: "registry", Action: "list", Path: runKey, Note: strings.Join(found, ",")}, nil

	case "remove":
		if req.DryRun {
			return resultFor("registry", req, runKey, false, "dry run: value would be deleted"), nil
		}
		out, err := exec.CommandContext(ctx, "reg.exe", "delete", runKey, "/v", valueName, "/f").CombinedOutput()
		if err != nil {
			return resultFor("registry", req, runKey, false,
				"value not found or could not be deleted: "+strings.TrimSpace(string(out))), nil
		}
		return resultFor("registry", req, runKey, true, ""), nil

	default:
		if req.DryRun {
			return resultFor("registry", req, runKey, false, "dry run: value would be created"), nil
		}
		out, err := exec.CommandContext(ctx, "reg.exe", "add", runKey,
			"/v", valueName, "/t", "REG_SZ", "/d", req.Command, "/f").CombinedOutput()
		if err != nil {
			return Result{}, fmt.Errorf("reg add: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return resultFor("registry", req, runKey, true, id), nil
	}
}

func schtasksPersist(ctx context.Context, req Request) (Result, error) {
	taskName := "pc2-" + req.Name
	id := ArtifactID("schtasks", req.Name)

	switch req.Action {
	case "list":
		out, err := exec.CommandContext(ctx, "schtasks.exe", "/Query", "/TN", taskName).Output()
		note := ""
		if err == nil {
			note = strings.TrimSpace(string(out))
		}
		return Result{Kind: "schtasks", Action: "list", Path: taskName, Note: note}, nil

	case "remove":
		if req.DryRun {
			return resultFor("schtasks", req, taskName, false, "dry run: task would be deleted"), nil
		}
		out, err := exec.CommandContext(ctx, "schtasks.exe", "/Delete", "/TN", taskName, "/F").CombinedOutput()
		if err != nil {
			return resultFor("schtasks", req, taskName, false,
				"task not found or could not be deleted: "+strings.TrimSpace(string(out))), nil
		}
		return resultFor("schtasks", req, taskName, true, ""), nil

	default:
		schedule := "ONLOGON"
		if req.Schedule != "" {
			candidate := strings.ToUpper(strings.TrimSpace(req.Schedule))
			switch candidate {
			case "ONLOGON", "ONSTART":
				schedule = candidate
			}
		}
		if req.DryRun {
			return resultFor("schtasks", req, taskName, false, "dry run: task would be created"), nil
		}
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, "schtasks.exe", "/Create", "/SC", schedule,
			"/TN", taskName, "/TR", req.Command, "/F")
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return Result{}, fmt.Errorf("schtasks create: %v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return resultFor("schtasks", req, taskName, true, id), nil
	}
}
