package commands

import (
	"fmt"

	"github.com/azizbinmohammad/private-c2/client/console"
)

func init() {
	Register(&Command{
		Name:        "sessions",
		Description: "List and manage active sessions",
		Usage:       "sessions [interact|lock|unlock|kill] [id]",
		Handler:     sessionsListHandler,
		SubCommands: []*Command{
			{
				Name:        "interact",
				Description: "Interact with a session",
				Usage:       "sessions interact <session-id>",
				Handler:     sessionsInteractHandler,
			},
			{
				Name:        "lock",
				Description: "Lock a session to prevent other operators from using it",
				Usage:       "sessions lock <session-id>",
				Handler:     sessionsLockHandler,
			},
			{
				Name:        "unlock",
				Description: "Unlock a previously locked session",
				Usage:       "sessions unlock <session-id>",
				Handler:     sessionsUnlockHandler,
			},
			{
				Name:        "kill",
				Description: "Terminate a session",
				Usage:       "sessions kill <session-id>",
				Handler:     sessionsKillHandler,
			},
		},
	})
}

func sessionsListHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}

	w := console.NewWriter()
	w.Info("Listing sessions for engagement %s...", ctx.EngagementName)

	// Stub: In the full implementation this would call the gRPC SessionService.
	// For now, display a placeholder table.
	table := console.NewTable(w, "ID", "Hostname", "User", "OS/Arch", "Transport", "Health", "Locked By")
	table.AddRow("(no active sessions)")
	table.Render()

	return nil
}

func sessionsInteractHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "sessions interact <session-id>"); err != nil {
		return err
	}

	sessionID := args[0]

	// Stub: In the full implementation, this would verify the session exists
	// via gRPC and retrieve its details.
	ctx.SetSession(sessionID, sessionID[:8])

	w := console.NewWriter()
	w.Success("Interacting with session %s", sessionID)
	w.Info("Use 'background' to return to engagement context")

	return nil
}

func sessionsLockHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "sessions lock <session-id>"); err != nil {
		return err
	}

	sessionID := args[0]
	w := console.NewWriter()

	// Stub: Would call gRPC to lock the session.
	w.Success("Session %s locked by %s", sessionID, ctx.OperatorName)

	return nil
}

func sessionsUnlockHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "sessions unlock <session-id>"); err != nil {
		return err
	}

	sessionID := args[0]
	w := console.NewWriter()

	// Stub: Would call gRPC to unlock the session.
	w.Success("Session %s unlocked", sessionID)

	return nil
}

func sessionsKillHandler(ctx *console.Context, args []string) error {
	if err := requireEngagement(ctx); err != nil {
		return err
	}
	if err := requireArg(args, 1, "sessions kill <session-id>"); err != nil {
		return err
	}

	sessionID := args[0]
	w := console.NewWriter()

	// Confirmation prompt
	fmt.Printf("Are you sure you want to kill session %s? [y/N] ", sessionID)
	// In the full implementation, this would read stdin for confirmation.

	// Stub: Would call gRPC to terminate the session.
	w.Warn("Session %s terminated", sessionID)

	if ctx.SessionID == sessionID {
		ctx.ClearSession()
	}

	return nil
}
