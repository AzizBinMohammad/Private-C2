package commands

import (
	"fmt"
	"strings"

	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "shell",
		Description: "Execute a shell command on the target",
		Usage:       "shell <command>",
		Handler:     shellHandler,
	})

	Register(&Command{
		Name:        "upload",
		Description: "Upload a file to the target",
		Usage:       "upload <local-path> <remote-path>",
		Handler:     uploadHandler,
	})

	Register(&Command{
		Name:        "download",
		Description: "Download a file from the target",
		Usage:       "download <remote-path> [local-path]",
		Handler:     downloadHandler,
	})

	Register(&Command{
		Name:        "ls",
		Description: "List files in a directory on the target",
		Usage:       "ls [path]",
		Handler:     lsHandler,
	})

	Register(&Command{
		Name:        "ps",
		Description: "List processes on the target",
		Usage:       "ps",
		Handler:     psHandler,
	})

	Register(&Command{
		Name:        "kill",
		Description: "Kill a process on the target by PID",
		Usage:       "kill <pid>",
		Handler:     killHandler,
	})

	Register(&Command{
		Name:        "ifconfig",
		Description: "List network interfaces on the target",
		Usage:       "ifconfig",
		Handler:     ifconfigHandler,
	})

	Register(&Command{
		Name:        "netstat",
		Description: "Show network connections on the target",
		Usage:       "netstat",
		Handler:     netstatHandler,
	})

	Register(&Command{
		Name:        "screenshot",
		Description: "Capture a screenshot on the target",
		Usage:       "screenshot [--output <path>]",
		Handler:     screenshotHandler,
	})

	Register(&Command{
		Name:        "portscan",
		Description: "Scan ports on a target host",
		Usage:       "portscan <host> <ports>",
		Handler:     portscanHandler,
	})
}

func shellHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "shell <command>"); err != nil {
		return err
	}

	command := strings.Join(args, " ")
	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Executing on %s %s: %s", kind, id[:8], command)

	// Stub: Would call gRPC TaskService.SubmitTask with a shell task type.
	// For sessions, the result comes back synchronously.
	// For beacons, the task is queued for the next check-in.
	if kind == "beacon" {
		w.Info("Task queued for next beacon check-in")
	} else {
		w.Info("(awaiting result...)")
	}

	return nil
}

func uploadHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 2, "upload <local-path> <remote-path>"); err != nil {
		return err
	}

	localPath := args[0]
	remotePath := args[1]
	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Uploading %s to %s:%s", localPath, id[:8], remotePath)

	// Stub: Would read local file and call gRPC TaskService.UploadFile.
	if kind == "beacon" {
		w.Info("Upload task queued for next beacon check-in")
	} else {
		w.Success("Upload complete (stub)")
	}

	return nil
}

func downloadHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "download <remote-path> [local-path]"); err != nil {
		return err
	}

	remotePath := args[0]
	localPath := remotePath
	if len(args) > 1 {
		localPath = args[1]
	}

	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Downloading %s:%s to %s", id[:8], remotePath, localPath)

	// Stub: Would call gRPC TaskService.DownloadFile.
	if kind == "beacon" {
		w.Info("Download task queued for next beacon check-in")
	} else {
		w.Success("Download complete (stub)")
	}

	return nil
}

func lsHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}

	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Listing %s on %s %s", path, kind, id[:8])

	// Stub: Would call gRPC TaskService.SubmitTask with a directory listing task.
	table := console.NewTable(w, "Permissions", "Size", "Modified", "Name")
	table.AddRow("(awaiting result...)")
	table.Render()

	return nil
}

func psHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Listing processes on %s %s", kind, id[:8])

	// Stub: Would call gRPC TaskService.ListProcesses.
	table := console.NewTable(w, "PID", "PPID", "User", "Name", "Path")
	table.AddRow("(awaiting result...)")
	table.Render()

	return nil
}

func killHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "kill <pid>"); err != nil {
		return err
	}

	pid := args[0]
	w := console.NewWriter()
	_, id := ctx.InteractionTarget()

	w.Info("Killing process %s on %s", pid, id[:8])

	// Stub: Would call gRPC TaskService.SubmitTask with a kill task.
	w.Success("Process %s terminated (stub)", pid)

	return nil
}

func ifconfigHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Listing network interfaces on %s %s", kind, id[:8])

	// Stub: Would call gRPC TaskService.SubmitTask with a network info task.
	table := console.NewTable(w, "Interface", "IP Address", "MAC", "Status")
	table.AddRow("(awaiting result...)")
	table.Render()

	return nil
}

func netstatHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Listing network connections on %s %s", kind, id[:8])

	// Stub: Would call gRPC TaskService.SubmitTask with a netstat task.
	table := console.NewTable(w, "Proto", "Local Address", "Remote Address", "State", "PID")
	table.AddRow("(awaiting result...)")
	table.Render()

	return nil
}

func screenshotHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}

	outputPath := "screenshot.png"
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--output" {
			outputPath = args[i+1]
			break
		}
	}

	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Capturing screenshot on %s %s", kind, id[:8])

	// Stub: Would call gRPC TaskService.SubmitTask with a screenshot task.
	if kind == "beacon" {
		w.Info("Screenshot task queued for next beacon check-in")
	} else {
		w.Success("Screenshot saved to %s (stub)", outputPath)
	}

	return nil
}

func portscanHandler(ctx *console.Context, args []string) error {
	if err := requireTarget(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 2, "portscan <host> <ports>"); err != nil {
		return err
	}

	host := args[0]
	ports := args[1]
	w := console.NewWriter()
	kind, id := ctx.InteractionTarget()

	w.Info("Scanning %s ports %s via %s %s", host, ports, kind, id[:8])

	// Stub: Would call gRPC TaskService.SubmitTask with a portscan task.
	// Scope check would be performed server-side before execution.
	fmt.Println("(awaiting scan results...)")

	return nil
}
