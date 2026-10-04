package commands

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "beacons",
		Description: "List and manage active beacons",
		Usage:       "beacons [interact|watch] [id]",
		Handler:     beaconsListHandler,
		SubCommands: []*Command{
			{
				Name:        "interact",
				Description: "Interact with a beacon (queue tasks for next check-in)",
				Usage:       "beacons interact <beacon-id>",
				Handler:     beaconsInteractHandler,
			},
			{
				Name:        "watch",
				Description: "Watch a beacon for real-time check-in updates",
				Usage:       "beacons watch <beacon-id>",
				Handler:     beaconsWatchHandler,
			},
		},
	})
}

func beaconsListHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	w.Info("Listing beacons for engagement %s...", ctx.EngagementName)

	// Stub: Would call gRPC BeaconService.ListBeacons.
	table := console.NewTable(w, "ID", "Hostname", "User", "OS/Arch", "Transport", "Interval", "Last Checkin", "Next Checkin")
	table.AddRow("(no active beacons)")
	table.Render()

	return nil
}

func beaconsInteractHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "beacons interact <beacon-id>"); err != nil {
		return err
	}

	beaconID := args[0]

	// Stub: Would verify beacon exists via gRPC.
	ctx.SetBeacon(beaconID, beaconID[:8])

	w := console.NewWriter()
	w.Success("Interacting with beacon %s", beaconID)
	w.Info("Tasks will be queued and executed on next check-in")
	w.Info("Use 'background' to return to engagement context")

	return nil
}

func beaconsWatchHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "beacons watch <beacon-id>"); err != nil {
		return err
	}

	beaconID := args[0]
	w := console.NewWriter()
	w.Info("Watching beacon %s for check-in events...", beaconID)
	w.Info("Press Ctrl+C to stop watching")

	// Stub: In the full implementation, this would subscribe to the server's
	// event stream filtered to this beacon's check-in events.
	fmt.Println("(waiting for check-ins...)")

	return nil
}
