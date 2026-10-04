package commands

import (
	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "operators",
		Description: "Manage operators (admin only)",
		Usage:       "operators [list|add|remove]",
		Handler:     operatorsListHandler,
		SubCommands: []*Command{
			{
				Name:        "list",
				Description: "List all operators",
				Usage:       "operators list",
				Handler:     operatorsListHandler,
			},
			{
				Name:        "add",
				Description: "Add a new operator",
				Usage:       "operators add <name> --role <role>",
				Handler:     operatorsAddHandler,
			},
			{
				Name:        "remove",
				Description: "Remove an operator",
				Usage:       "operators remove <operator-id>",
				Handler:     operatorsRemoveHandler,
			},
		},
	})

	Register(&Command{
		Name:        "server",
		Description: "Server administration",
		Usage:       "server status",
		Handler:     serverStatusHandler,
		SubCommands: []*Command{
			{
				Name:        "status",
				Description: "Show server status and health",
				Usage:       "server status",
				Handler:     serverStatusHandler,
			},
		},
	})
}

func operatorsListHandler(ctx *console.Context, args []string) error {
	w := console.NewWriter()
	w.Info("Listing operators...")

	// Stub: Would call gRPC AdminService.ListOperators.
	table := console.NewTable(w, "ID", "Name", "Role", "MFA", "Last Active", "Source IP")
	table.AddRow("(no operators listed)")
	table.Render()

	return nil
}

func operatorsAddHandler(ctx *console.Context, args []string) error {
	if err := requireArg(args, 1, "operators add <name> --role <role>"); err != nil {
		return err
	}

	name := args[0]
	role := "operator"

	for i := 1; i < len(args)-1; i++ {
		if args[i] == "--role" {
			role = args[i+1]
			break
		}
	}

	w := console.NewWriter()
	w.Info("Adding operator: %s (role: %s)", name, console.ColorizeRole(role))

	// Stub: Would call gRPC AdminService.AddOperator.
	// In the full implementation, this generates a client certificate and
	// returns the operator config file.
	w.Success("Operator %s added with role %s (stub)", name, role)
	w.Info("Client certificate and config file would be generated here")

	return nil
}

func operatorsRemoveHandler(ctx *console.Context, args []string) error {
	if err := requireArg(args, 1, "operators remove <operator-id>"); err != nil {
		return err
	}

	operatorID := args[0]
	w := console.NewWriter()

	// Stub: Would call gRPC AdminService.RemoveOperator.
	w.Warn("Operator %s removed (stub)", operatorID)
	w.Info("Client certificate revoked")

	return nil
}

func serverStatusHandler(ctx *console.Context, args []string) error {
	w := console.NewWriter()
	w.Info("Server Status")
	w.Print("\n")

	// Stub: Would call gRPC AdminService.ServerStatus.
	w.Print("  Server:      %s\n", ctx.ServerAddr)
	w.Print("  Connection:  %s\n", console.ColorizeStatus("connected"))
	w.Print("  Version:     %s\n", "(query pending)")
	w.Print("  Uptime:      %s\n", "(query pending)")
	w.Print("\n")

	w.Print("  %sResources:%s\n", console.ColorBold, console.ColorReset)
	w.Print("    Active Sessions:    %s\n", "(query pending)")
	w.Print("    Active Beacons:     %s\n", "(query pending)")
	w.Print("    Active Listeners:   %s\n", "(query pending)")
	w.Print("    Build Queue:        %s\n", "(query pending)")
	w.Print("    Connected Operators: %s\n", "(query pending)")
	w.Print("\n")

	w.Print("  %sHealth:%s\n", console.ColorBold, console.ColorReset)
	w.Print("    CPU:    %s\n", "(query pending)")
	w.Print("    Memory: %s\n", "(query pending)")
	w.Print("    Disk:   %s\n", "(query pending)")

	return nil
}
