package commands

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "engagements",
		Description: "Manage engagements",
		Usage:       "engagements [list|create|use|status|killswitch|scope] [args]",
		Handler:     engagementsListHandler,
		SubCommands: []*Command{
			{
				Name:        "list",
				Description: "List all engagements",
				Usage:       "engagements list",
				Handler:     engagementsListHandler,
			},
			{
				Name:        "create",
				Description: "Create a new engagement",
				Usage:       "engagements create <name> [--description <desc>] [--auth-ref <ref>]",
				Handler:     engagementsCreateHandler,
			},
			{
				Name:        "use",
				Description: "Switch to an engagement",
				Usage:       "engagements use <engagement-id>",
				Handler:     engagementsUseHandler,
			},
			{
				Name:        "status",
				Description: "Show current engagement status",
				Usage:       "engagements status",
				Handler:     engagementsStatusHandler,
			},
			{
				Name:        "killswitch",
				Description: "Activate the engagement kill switch",
				Usage:       "engagements killswitch [--confirm]",
				Handler:     engagementsKillSwitchHandler,
			},
			{
				Name:        "scope",
				Description: "Check if a target is within engagement scope",
				Usage:       "engagements scope check <target>",
				Handler:     engagementsScopeHandler,
				SubCommands: []*Command{
					{
						Name:        "check",
						Description: "Check if a target is in scope",
						Usage:       "engagements scope check <target>",
						Handler:     engagementsScopeCheckHandler,
					},
				},
			},
		},
	})
}

func engagementsListHandler(ctx *console.Context, args []string) error {
	w := console.NewWriter()
	w.Info("Listing engagements...")

	// Stub: Would call gRPC EngagementService.ListEngagements.
	table := console.NewTable(w, "ID", "Name", "Status", "Start", "End", "Created By")
	table.AddRow("(no engagements)")
	table.Render()

	return nil
}

func engagementsCreateHandler(ctx *console.Context, args []string) error {
	if err := requireArg(args, 1, "engagements create <name>"); err != nil {
		return err
	}

	name := args[0]
	description := ""
	authRef := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "--description":
			description = args[i+1]
			i++
		case "--auth-ref":
			authRef = args[i+1]
			i++
		}
	}

	w := console.NewWriter()
	w.Info("Creating engagement: %s", name)
	if description != "" {
		w.Info("  Description: %s", description)
	}
	if authRef != "" {
		w.Info("  Authorization: %s", authRef)
	}

	// Stub: Would call gRPC EngagementService.CreateEngagement.
	w.Success("Engagement created (stub)")

	return nil
}

func engagementsUseHandler(ctx *console.Context, args []string) error {
	if err := requireArg(args, 1, "engagements use <engagement-id>"); err != nil {
		return err
	}

	engagementID := args[0]
	w := console.NewWriter()

	// Stub: Would call gRPC EngagementService.GetEngagement to verify it exists
	// and retrieve its name.
	engagementName := engagementID[:8]
	ctx.SetEngagement(engagementID, engagementName)

	w.Success("Switched to engagement: %s (%s)", engagementName, engagementID)

	return nil
}

func engagementsStatusHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	w.Info("Engagement Status")
	w.Print("  ID:     %s\n", ctx.EngagementID)
	w.Print("  Name:   %s\n", ctx.EngagementName)

	// Stub: Would call gRPC EngagementService.GetEngagement for full details.
	w.Print("  Status: %s\n", console.ColorizeStatus("active"))
	w.Print("\n")

	// Summary counts
	w.Print("  Active Sessions:  %s\n", "(query pending)")
	w.Print("  Active Beacons:   %s\n", "(query pending)")
	w.Print("  Active Listeners: %s\n", "(query pending)")
	w.Print("  Payloads:         %s\n", "(query pending)")

	return nil
}

func engagementsKillSwitchHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()

	// Check for --confirm flag
	confirmed := false
	for _, arg := range args {
		if arg == "--confirm" {
			confirmed = true
		}
	}

	if !confirmed {
		w.Warn("KILL SWITCH will immediately:")
		w.Warn("  - Terminate all active sessions")
		w.Warn("  - Signal all beacons to self-destruct")
		w.Warn("  - Stop all listeners")
		w.Warn("  - Revoke all active payloads")
		w.Warn("")
		w.Warn("This action cannot be undone.")
		fmt.Println()
		w.Error("Run 'engagements killswitch --confirm' to proceed")
		return nil
	}

	// Stub: Would call gRPC EngagementService.ActivateKillSwitch.
	w.Warn("Kill switch activated for engagement %s", ctx.EngagementName)
	w.Info("All sessions and beacons signaled for termination")

	return nil
}

func engagementsScopeHandler(ctx *console.Context, args []string) error {
	return fmt.Errorf("usage: engagements scope check <target>")
}

func engagementsScopeCheckHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "engagements scope check <target>"); err != nil {
		return err
	}

	target := args[0]
	w := console.NewWriter()

	w.Info("Checking scope for target: %s", target)

	// Stub: Would call gRPC EngagementService.CheckScope.
	w.Info("(scope check result pending - stub)")

	return nil
}
