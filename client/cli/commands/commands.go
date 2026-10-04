package commands

import (
	"fmt"
	"strings"

	"github.com/azizbinmohammad/private-c2/client/console"
)

// Command represents a CLI command with optional subcommands.
type Command struct {
	Name        string
	Description string
	Usage       string
	Handler     func(ctx *console.Context, args []string) error
	SubCommands []*Command
}

// Execute runs the command or dispatches to a subcommand.
func (c *Command) Execute(ctx *console.Context, args []string) error {
	// If there are subcommands and the first arg matches one, dispatch.
	if len(args) > 0 && len(c.SubCommands) > 0 {
		for _, sub := range c.SubCommands {
			if sub.Name == args[0] {
				return sub.Execute(ctx, args[1:])
			}
		}
	}

	// Run the command's own handler.
	if c.Handler != nil {
		return c.Handler(ctx, args)
	}

	// No handler and no matching subcommand: show usage.
	return c.PrintUsage()
}

// PrintUsage displays the command's help text.
func (c *Command) PrintUsage() error {
	fmt.Printf("Usage: %s\n", c.Usage)
	fmt.Printf("  %s\n\n", c.Description)

	if len(c.SubCommands) > 0 {
		fmt.Println("Subcommands:")
		for _, sub := range c.SubCommands {
			fmt.Printf("  %-20s %s\n", sub.Name, sub.Description)
		}
		fmt.Println()
	}
	return nil
}

// registry holds all registered top-level commands.
var registry []*Command

// Register adds a command to the global registry.
func Register(cmd *Command) {
	registry = append(registry, cmd)
}

// All returns all registered commands.
func All() []*Command {
	return registry
}

// RegisterAll registers all commands with the given console.
func RegisterAll(c *console.Console) {
	for _, cmd := range registry {
		// Capture cmd in closure.
		command := cmd
		c.RegisterCommand(command.Name, func(ctx *console.Context, args []string) error {
			return command.Execute(ctx, args)
		})
	}
}

// requireEngagement checks that an engagement is selected and returns an
// error if not.
func requireEngagement(ctx *console.Context) error {
	if !ctx.HasEngagement() {
		return fmt.Errorf("no active engagement: use 'engagements use <id>' first")
	}
	return nil
}

// requireSession checks that a session is selected and returns an error if not.
func requireSession(ctx *console.Context) error {
	if !ctx.HasSession() {
		return fmt.Errorf("no active session: use 'sessions interact <id>' first")
	}
	return nil
}

// requireTarget checks that either a session or beacon is selected.
func requireTarget(ctx *console.Context) error {
	kind, _ := ctx.InteractionTarget()
	if kind == "" {
		return fmt.Errorf("no active session or beacon: use 'sessions interact' or 'beacons interact' first")
	}
	return nil
}

// requireArg checks that at least n arguments are provided.
func requireArg(args []string, n int, usage string) error {
	if len(args) < n {
		return fmt.Errorf("missing argument(s): %s", usage)
	}
	return nil
}

// joinArgs joins args from index start onwards into a single string.
func joinArgs(args []string, start int) string {
	if start >= len(args) {
		return ""
	}
	return strings.Join(args[start:], " ")
}
