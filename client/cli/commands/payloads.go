package commands

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "generate",
		Description: "Generate a new implant payload",
		Usage:       "generate --os <os> --arch <arch> --mode <mode> --transport <transport> [options]",
		Handler:     generateHandler,
	})

	Register(&Command{
		Name:        "payloads",
		Description: "List and manage generated payloads",
		Usage:       "payloads [download|revoke] [id]",
		Handler:     payloadsListHandler,
		SubCommands: []*Command{
			{
				Name:        "download",
				Description: "Download a payload artifact",
				Usage:       "payloads download <payload-id> [--output <path>]",
				Handler:     payloadsDownloadHandler,
			},
			{
				Name:        "revoke",
				Description: "Revoke a payload (mark as inactive)",
				Usage:       "payloads revoke <payload-id>",
				Handler:     payloadsRevokeHandler,
			},
		},
	})
}

func generateHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()

	// Parse generation flags.
	opts := parseGenerateOpts(args)

	if opts.os == "" || opts.arch == "" {
		w.Error("Required: --os and --arch")
		w.Info("Usage: generate --os <os> --arch <arch> --mode <mode> --transport <transport>")
		w.Info("  --os         Target OS: windows, linux, darwin")
		w.Info("  --arch       Target arch: amd64, arm64, 386")
		w.Info("  --mode       Implant mode: session, beacon (default: session)")
		w.Info("  --transport  Transport: mtls, https, dns, wireguard (default: mtls)")
		w.Info("  --format     Output format: exe, dll, shellcode, shared (default: exe)")
		w.Info("  --evasion    Enable evasion features")
		w.Info("  --debug      Include debug symbols")
		return nil
	}

	w.Info("Generating payload:")
	w.Info("  OS:        %s", opts.os)
	w.Info("  Arch:      %s", opts.arch)
	w.Info("  Mode:      %s", opts.mode)
	w.Info("  Transport: %s", opts.transport)
	w.Info("  Format:    %s", opts.format)
	if opts.evasion {
		w.Info("  Evasion:   enabled")
	}

	// Stub: Would call gRPC PayloadService.GeneratePayload, which queues
	// a build job and returns the job ID.
	w.Success("Build job submitted (stub)")
	w.Info("Use 'payloads' to check build status")

	return nil
}

type generateOpts struct {
	os        string
	arch      string
	mode      string
	transport string
	format    string
	evasion   bool
	debug     bool
}

func parseGenerateOpts(args []string) generateOpts {
	opts := generateOpts{
		mode:      "session",
		transport: "mtls",
		format:    "exe",
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--os":
			if i+1 < len(args) {
				opts.os = args[i+1]
				i++
			}
		case "--arch":
			if i+1 < len(args) {
				opts.arch = args[i+1]
				i++
			}
		case "--mode":
			if i+1 < len(args) {
				opts.mode = args[i+1]
				i++
			}
		case "--transport":
			if i+1 < len(args) {
				opts.transport = args[i+1]
				i++
			}
		case "--format":
			if i+1 < len(args) {
				opts.format = args[i+1]
				i++
			}
		case "--evasion":
			opts.evasion = true
		case "--debug":
			opts.debug = true
		}
	}

	return opts
}

func payloadsListHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	w.Info("Listing payloads for engagement %s...", ctx.EngagementName)

	// Stub: Would call gRPC PayloadService.ListPayloads.
	table := console.NewTable(w, "ID", "OS/Arch", "Mode", "Format", "SHA256", "Size", "Status", "Created")
	table.AddRow("(no payloads)")
	table.Render()

	return nil
}

func payloadsDownloadHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "payloads download <payload-id> [--output <path>]"); err != nil {
		return err
	}

	payloadID := args[0]
	outputPath := ""

	for i := 1; i < len(args)-1; i++ {
		if args[i] == "--output" {
			outputPath = args[i+1]
			break
		}
	}

	w := console.NewWriter()

	if outputPath == "" {
		outputPath = fmt.Sprintf("payload-%s", payloadID[:8])
	}

	// Stub: Would call gRPC PayloadService.DownloadPayload and write to disk.
	w.Success("Payload %s downloaded to %s (stub)", payloadID, outputPath)

	return nil
}

func payloadsRevokeHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "payloads revoke <payload-id>"); err != nil {
		return err
	}

	payloadID := args[0]
	w := console.NewWriter()

	// Stub: Would call gRPC PayloadService.RevokePayload.
	w.Warn("Payload %s revoked", payloadID)

	return nil
}
