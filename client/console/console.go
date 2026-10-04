package console

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// CommandHandler is a function that executes a console command.
type CommandHandler func(ctx *Context, args []string) error

// Console is the interactive REPL for operator interaction with the C2 framework.
type Console struct {
	ctx      *Context
	writer   *Writer
	events   *EventListener
	commands map[string]CommandHandler
	scanner  *bufio.Scanner
	history  []string
	input    io.Reader
	running  bool
}

// New creates a new interactive console.
func New(ctx *Context) *Console {
	writer := NewWriter()
	return &Console{
		ctx:      ctx,
		writer:   writer,
		events:   NewEventListener(writer),
		commands: make(map[string]CommandHandler),
		input:    os.Stdin,
		history:  make([]string, 0, 256),
	}
}

// Writer returns the console's output writer.
func (c *Console) Writer() *Writer {
	return c.writer
}

// Events returns the console's event listener.
func (c *Console) Events() *EventListener {
	return c.events
}

// Context returns the console's context.
func (c *Console) Context() *Context {
	return c.ctx
}

// RegisterCommand adds a command handler to the console.
func (c *Console) RegisterCommand(name string, handler CommandHandler) {
	c.commands[name] = handler
}

// SetInput changes the input source (useful for testing).
func (c *Console) SetInput(r io.Reader) {
	c.input = r
}

// Run starts the interactive REPL loop.
func (c *Console) Run() error {
	c.running = true
	c.scanner = bufio.NewScanner(c.input)

	c.printBanner()
	c.events.Start()

	for c.running {
		fmt.Print(c.ctx.Prompt())

		if !c.scanner.Scan() {
			break
		}

		line := strings.TrimSpace(c.scanner.Text())
		if line == "" {
			continue
		}

		c.history = append(c.history, line)

		if err := c.dispatch(line); err != nil {
			c.writer.Error("%v", err)
		}
	}

	c.events.Stop()
	return c.scanner.Err()
}

// Stop terminates the REPL loop.
func (c *Console) Stop() {
	c.running = false
}

// dispatch parses and executes a command line.
func (c *Console) dispatch(line string) error {
	args := splitArgs(line)
	if len(args) == 0 {
		return nil
	}

	cmd := args[0]
	cmdArgs := args[1:]

	// Built-in commands.
	switch cmd {
	case "exit", "quit":
		c.writer.Info("Goodbye.")
		c.Stop()
		return nil
	case "help":
		c.printHelp()
		return nil
	case "history":
		c.printHistory()
		return nil
	case "clear":
		fmt.Print("\033[2J\033[H")
		return nil
	case "background", "bg":
		c.ctx.ClearSession()
		c.ctx.ClearBeacon()
		c.writer.Info("Returned to engagement context")
		return nil
	case "output":
		return c.handleOutputMode(cmdArgs)
	}

	// Look up registered commands.
	handler, ok := c.commands[cmd]
	if !ok {
		return fmt.Errorf("unknown command: %s (type 'help' for available commands)", cmd)
	}

	return handler(c.ctx, cmdArgs)
}

// splitArgs splits a command line into arguments, respecting quoted strings.
func splitArgs(line string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]

		if inQuote {
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
			}
			continue
		}

		if ch == '"' || ch == '\'' {
			inQuote = true
			quoteChar = ch
			continue
		}

		if ch == ' ' || ch == '\t' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteByte(ch)
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// printBanner displays the startup banner.
func (c *Console) printBanner() {
	fmt.Fprintf(c.writer.out, "%s", ColorCyan)
	fmt.Fprintln(c.writer.out, "  ____       _            _           ____ ____  ")
	fmt.Fprintln(c.writer.out, " |  _ \\ _ __(_)_   ____ _| |_ ___    / ___|___ \\ ")
	fmt.Fprintln(c.writer.out, " | |_) | '__| \\ \\ / / _` | __/ _ \\  | |     __) |")
	fmt.Fprintln(c.writer.out, " |  __/| |  | |\\ V / (_| | ||  __/  | |___ / __/ ")
	fmt.Fprintln(c.writer.out, " |_|   |_|  |_| \\_/ \\__,_|\\__\\___|   \\____|_____|")
	fmt.Fprintf(c.writer.out, "%s", ColorReset)
	fmt.Fprintln(c.writer.out)
	c.writer.Info("Operator: %s | Server: %s", c.ctx.OperatorName, c.ctx.ServerAddr)
	c.writer.Info("Type 'help' for available commands")
	fmt.Fprintln(c.writer.out)
}

// printHelp displays the list of available commands.
func (c *Console) printHelp() {
	c.writer.Println()
	c.writer.Print("%sBuilt-in Commands:%s\n", ColorBold, ColorReset)
	c.writer.Print("  %-20s %s\n", "help", "Show this help message")
	c.writer.Print("  %-20s %s\n", "history", "Show command history")
	c.writer.Print("  %-20s %s\n", "clear", "Clear the screen")
	c.writer.Print("  %-20s %s\n", "background", "Return to engagement context")
	c.writer.Print("  %-20s %s\n", "output [text|json]", "Switch output mode")
	c.writer.Print("  %-20s %s\n", "exit", "Exit the console")
	c.writer.Println()

	if len(c.commands) > 0 {
		c.writer.Print("%sRegistered Commands:%s\n", ColorBold, ColorReset)
		for name := range c.commands {
			c.writer.Print("  %s\n", name)
		}
		c.writer.Println()
	}
}

// printHistory displays the command history.
func (c *Console) printHistory() {
	for i, cmd := range c.history {
		c.writer.Print("  %4d  %s\n", i+1, cmd)
	}
}

// handleOutputMode switches between text and JSON output.
func (c *Console) handleOutputMode(args []string) error {
	if len(args) == 0 {
		if c.writer.mode == OutputJSON {
			c.writer.Info("Output mode: json")
		} else {
			c.writer.Info("Output mode: text")
		}
		return nil
	}

	switch args[0] {
	case "text":
		c.writer.SetMode(OutputText)
		c.writer.Info("Output mode set to text")
	case "json":
		c.writer.SetMode(OutputJSON)
		c.writer.Info("Output mode set to json")
	default:
		return fmt.Errorf("unknown output mode: %s (use 'text' or 'json')", args[0])
	}
	return nil
}
