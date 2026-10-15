package nmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Profile selects how hard a scan looks at the target.
type Profile string

const (
	// ProfileQuick scans the most common ports with no version detection. It
	// answers "is anything listening" and nothing more.
	ProfileQuick Profile = "quick"

	// ProfileServices adds nmap's service and version detection. This is the
	// default: it answers "what is running here" without probing for
	// weaknesses.
	ProfileServices Profile = "services"

	// ProfileVulns adds nmap's NSE "vuln" script set. Those scripts actively
	// probe for known vulnerabilities and can crash or wedge the service they
	// test, so this tier is opt-in and never the default.
	ProfileVulns Profile = "vulns"
)

// ParseProfile resolves a profile name, treating empty as the default.
func ParseProfile(name string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", string(ProfileServices):
		return ProfileServices, nil
	case string(ProfileQuick):
		return ProfileQuick, nil
	case string(ProfileVulns):
		return ProfileVulns, nil
	default:
		return "", fmt.Errorf("unknown scan profile %q (want quick, services or vulns)", name)
	}
}

// flags returns the nmap arguments this profile contributes.
func (p Profile) flags() []string {
	switch p {
	case ProfileQuick:
		return []string{"-T4", "-F"}
	case ProfileVulns:
		// Two separate arguments rather than one "--script vuln" string: nmap
		// accepts either, and this way nothing downstream depends on splitting
		// an argument on whitespace.
		//
		// --script-timeout is what makes this profile finish, and it is the only
		// bound that works. Left unbounded, the vuln category runs for many
		// minutes -- measured at over eight on one host, still going. Sizing the
		// bound wrongly is worse than not having one: nmap's own --host-timeout
		// does not shorten the scan, it abandons the host and returns an empty
		// result with exit=success, which reads to an operator as "scanned
		// clean" when nothing was scanned at all. A per-script timeout instead
		// lets the sweep complete on its own and emit a closed document.
		//
		// No -F here, unlike the other profiles: the script phase dominates the
		// runtime, not the port count (measured at 129s over the default port set
		// against 134s over the top 100), so narrowing the ports buys nothing and
		// would skip the port the vulnerability lives on.
		return []string{"-sV", "-T4", "--script", "vuln", "--script-timeout", "30s"}
	default:
		return []string{"-sV", "-T4"}
	}
}

// Timeout bounds how long this profile may run.
//
// Per-profile because the tiers differ by an order of magnitude: a quick scan
// of common ports is seconds, while a vuln script sweep of a slow host can run
// for minutes. This also bounds how long the implant's serial beacon loop stops
// checking in, which is the reason it is not simply very large.
func (p Profile) Timeout() time.Duration {
	switch p {
	case ProfileQuick:
		return 2 * time.Minute
	case ProfileVulns:
		// Slightly longer than the profile's own --host-timeout (4m), because
		// nmap's script phase continues after the host scan gives up: measured
		// at around 6m10s end to end. nmap ending the scan itself is what keeps
		// the XML parseable, so this deadline should rarely be the one that
		// fires.
		return 7 * time.Minute
	default:
		return DefaultTimeout
	}
}

// Request is the payload the "scan" task carries in its Args. Target, profile
// and ports travel as JSON rather than as a space-separated string so none can
// be confused with another, or with an nmap option.
type Request struct {
	Target  string `json:"target"`
	Profile string `json:"profile,omitempty"`

	// Ports restricts the scan to a specific set, in nmap's -p syntax
	// ("80,443" or "1-1024"). Empty uses the profile's own port selection.
	Ports string `json:"ports,omitempty"`
}

// portSpecPattern accepts nmap's -p syntax: single ports, hyphen ranges, and
// comma-separated combinations of the two.
var portSpecPattern = regexp.MustCompile(`^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`)

// validatePorts rejects a port list nmap could not use, so the operator gets a
// clear message instead of nmap's usage dump.
func validatePorts(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	if !portSpecPattern.MatchString(spec) {
		return fmt.Errorf("scan: invalid port list %q (want e.g. \"80,443\" or \"1-1024\")", spec)
	}
	return nil
}

// dropFlag removes every occurrence of flag from flags.
func dropFlag(flags []string, flag string) []string {
	kept := flags[:0:0]
	for _, f := range flags {
		if f != flag {
			kept = append(kept, f)
		}
	}
	return kept
}

// HostSummary is one host nmap reported on.
type HostSummary struct {
	Address  string `json:"address"`
	Hostname string `json:"hostname,omitempty"`
	State    string `json:"state"`
}

// Service is one port nmap reported, with whatever version detail the profile
// asked for. Ports that were scanned and found closed are included with
// State "closed" rather than dropped, so the absence of a service is visible
// instead of looking like it was never checked.
type Service struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`
	CPE       string `json:"cpe,omitempty"`
}

// Finding is one NSE script result.
//
// There is no Severity field: nmap's XML carries none, and inventing a ranking
// would present a guess as an assessment. Vulnerable records what the script's
// own output asserted, and CVEs lists the identifiers it actually named.
type Finding struct {
	Host       string   `json:"host"`
	Port       int      `json:"port,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`
	ScriptID   string   `json:"script_id"`
	Vulnerable bool     `json:"vulnerable"`
	CVEs       []string `json:"cves,omitempty"`
	Output     string   `json:"output,omitempty"`
}

// Result is what a scan returns.
type Result struct {
	Target   string        `json:"target"`
	Profile  string        `json:"profile"`
	Ports    string        `json:"ports,omitempty"`
	Scanner  string        `json:"scanner,omitempty"`
	Args     string        `json:"args,omitempty"`
	Elapsed  string        `json:"elapsed,omitempty"`
	Hosts    []HostSummary `json:"hosts"`
	Services []Service     `json:"services"`
	Findings []Finding     `json:"findings"`

	// Partial is set when the scan did not run to completion, so a truncated
	// result is never mistaken for a clean one.
	Partial bool `json:"partial"`

	// Notice explains Partial, or that the output could not be structured.
	Notice string `json:"notice,omitempty"`

	// Raw carries nmap's own output when it could not be parsed as XML, most
	// likely because the scan was killed at the deadline mid-document. Without
	// it a timed-out scan would return nothing at all.
	Raw string `json:"raw,omitempty"`
}

// Scan runs nmap against the requested target and returns structured results.
//
// It mirrors the Execute signature the other implant modules use: JSON payload
// in, JSON payload out. A non-nil error alongside a populated result is the
// expected shape for a scan that was cut short -- the caller gets both the
// failure and whatever the scan had already found.
func Scan(ctx context.Context, payload []byte) ([]byte, error) {
	return scanWith(ctx, exec.LookPath, runNmap, payload)
}

// scanWith is the testable seam around Scan: it decodes the request, performs
// the scan, and encodes the result.
func scanWith(ctx context.Context, lookup lookupFunc, run runFunc, payload []byte) ([]byte, error) {
	var req Request
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fmt.Errorf("parsing scan request: %w", err)
		}
	}

	res, err := scanRequest(ctx, lookup, run, req)
	if res == nil {
		return nil, err
	}

	// Marshal even when err is non-nil: the partial result is the useful half
	// of a timed-out scan.
	out, mErr := json.Marshal(res)
	if mErr != nil {
		return nil, fmt.Errorf("encoding scan result: %w", mErr)
	}
	return out, err
}

// scanRequest validates a request, runs nmap, and turns its XML into a Result.
func scanRequest(ctx context.Context, lookup lookupFunc, run runFunc, req Request) (*Result, error) {
	target := strings.TrimSpace(req.Target)
	if target == "" {
		return nil, errors.New("scan: no target given")
	}
	// A target is never an option. Rejecting a leading dash keeps the target
	// from reaching nmap's flag parser at all, which is what makes the
	// separate-argv design hold all the way to the invocation.
	if strings.HasPrefix(target, "-") {
		return nil, fmt.Errorf("scan: target %q looks like an option", target)
	}

	profile, err := ParseProfile(req.Profile)
	if err != nil {
		return nil, err
	}

	if err := validatePorts(req.Ports); err != nil {
		return nil, err
	}

	path, err := availableWith(lookup)
	if err != nil {
		return nil, err
	}

	flags := profile.flags()
	if ports := strings.TrimSpace(req.Ports); ports != "" {
		// An explicit list replaces the profile's own port selection, so the
		// quick profile's -F ("top 100") is dropped: passing both would leave
		// which one wins up to nmap's flag ordering.
		flags = dropFlag(flags, "-F")
		flags = append(flags, "-p", ports)
	}

	// -oX - writes the XML to stdout, so nothing is written to the target's
	// disk: a scan artefact left in /tmp is a forensic trace for no gain.
	argv := append(flags, "-oX", "-", target)

	ctx, cancel := context.WithTimeout(ctx, profile.Timeout())
	defer cancel()

	stdout, stderr, runErr := run(ctx, path, argv)
	timedOut := ctx.Err() != nil

	res := &Result{
		Target:   target,
		Profile:  string(profile),
		Ports:    strings.TrimSpace(req.Ports),
		Hosts:    []HostSummary{},
		Services: []Service{},
		Findings: []Finding{},
	}

	// parseXML decodes tolerantly, so an incomplete document still yields the
	// services and findings that arrived before the truncation.
	parsed, parseErr := parseXML(stdout, target, string(profile))
	if parsed != nil {
		parsed.Ports = res.Ports
		res = parsed
	}
	sortResult(res)

	// If nothing at all was decoded, nmap's own text is the only content there
	// is. That is the case where a raw fallback is genuinely the best answer.
	if parseErr != nil && len(res.Services) == 0 && len(res.Findings) == 0 && len(res.Hosts) == 0 {
		if strings.TrimSpace(string(stdout)) != "" {
			res.Raw = string(stdout)
		}
	}

	switch {
	case timedOut:
		res.Partial = true
		res.Notice = fmt.Sprintf("scan stopped after %s; results are partial", profile.Timeout())
		return res, fmt.Errorf("scan timed out after %s", profile.Timeout())

	case runErr != nil:
		detail := strings.TrimSpace(string(stderr))
		if detail == "" {
			detail = runErr.Error()
		}
		res.Notice = "nmap exited with an error; results may be incomplete"
		return res, fmt.Errorf("scan: %s", detail)

	case parseErr != nil:
		res.Partial = true
		if res.Raw != "" {
			res.Notice = "nmap's output could not be parsed; showing it raw"
		} else {
			res.Notice = "scan results are incomplete: nmap's output was cut short"
		}
		if res.Raw == "" && len(res.Services) == 0 && len(res.Findings) == 0 {
			return res, fmt.Errorf("scan: nmap produced no usable output: %w", parseErr)
		}
		return res, nil
	}

	return res, nil
}

// sortResult orders services by port and puts confirmed findings first, since
// neither nmap's XML order nor its script order is meaningful to a reader.
func sortResult(res *Result) {
	sort.SliceStable(res.Services, func(i, j int) bool {
		if res.Services[i].Host != res.Services[j].Host {
			return res.Services[i].Host < res.Services[j].Host
		}
		return res.Services[i].Port < res.Services[j].Port
	})

	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].Vulnerable != res.Findings[j].Vulnerable {
			return res.Findings[i].Vulnerable
		}
		return res.Findings[i].ScriptID < res.Findings[j].ScriptID
	})
}
