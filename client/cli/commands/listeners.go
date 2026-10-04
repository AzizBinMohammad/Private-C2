package commands

import (
	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "listeners",
		Description: "Manage C2 listeners",
		Usage:       "listeners [start|stop|profiles]",
		Handler:     listenersListHandler,
		SubCommands: []*Command{
			{
				Name:        "start",
				Description: "Start a new listener",
				Usage:       "listeners start <type> --bind <addr> --port <port> [--profile <name>]",
				Handler:     listenersStartHandler,
			},
			{
				Name:        "stop",
				Description: "Stop a running listener",
				Usage:       "listeners stop <listener-id>",
				Handler:     listenersStopHandler,
			},
			{
				Name:        "profiles",
				Description: "List available C2 communication profiles",
				Usage:       "listeners profiles",
				Handler:     listenersProfilesHandler,
			},
		},
	})
}

func listenersListHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	w.Info("Listing listeners for engagement %s...", ctx.EngagementName)

	// Stub: Would call gRPC ListenerService.ListListeners.
	table := console.NewTable(w, "ID", "Type", "Bind Address", "Port", "Status", "Active Conns", "Profile")
	table.AddRow("(no active listeners)")
	table.Render()

	return nil
}

func listenersStartHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "listeners start <type> [options]"); err != nil {
		return err
	}

	listenerType := args[0]
	w := console.NewWriter()

	// Parse optional flags.
	bindAddr := "0.0.0.0"
	port := "443"
	profile := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "--bind":
			bindAddr = args[i+1]
			i++
		case "--port":
			port = args[i+1]
			i++
		case "--profile":
			profile = args[i+1]
			i++
		}
	}

	w.Info("Starting %s listener on %s:%s", listenerType, bindAddr, port)
	if profile != "" {
		w.Info("Using profile: %s", profile)
	}

	// Stub: Would call gRPC ListenerService.StartListener.
	w.Success("Listener started (stub)")

	return nil
}

func listenersStopHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "listeners stop <listener-id>"); err != nil {
		return err
	}

	listenerID := args[0]
	w := console.NewWriter()

	// Stub: Would call gRPC ListenerService.StopListener.
	w.Success("Listener %s stopped", listenerID)

	return nil
}

func listenersProfilesHandler(ctx *console.Context, args []string) error {
	w := console.NewWriter()
	w.Info("Available C2 profiles:")

	// Stub: Would call gRPC to list C2 profiles.
	table := console.NewTable(w, "Name", "Description", "Version")
	table.AddRow("default", "Standard HTTPS profile", "1")
	table.AddRow("cdn", "CDN-fronted HTTPS profile", "1")
	table.AddRow("dns-txt", "DNS TXT record exfiltration", "1")
	table.Render()

	return nil
}
