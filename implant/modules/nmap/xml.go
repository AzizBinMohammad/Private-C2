package nmap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// This file reads nmap's XML output with a streaming decoder rather than
// decoding into a struct tree with xml.Unmarshal.
//
// The reason is truncation. A scan killed at its deadline stops mid-document,
// and xml.Unmarshal rejects the whole thing: a six-minute vulnerability scan
// that had already found three open ports and a vulnerable service would
// return nothing at all. Decoding token by token keeps everything that arrived
// before the truncation, so a partial scan returns partial findings.
//
// The element shapes below were taken from real nmap 7.92 output rather than
// the DTD, since nmap adds attributes over time and the decoder simply skips
// what it does not recognise.

// parseXML turns nmap's XML output into the package's result types.
//
// A non-nil error means the document was incomplete -- the returned Result
// still holds whatever was decoded before that point, so callers must not
// discard it.
func parseXML(data []byte, target, profile string) (*Result, error) {
	res := &Result{
		Target:   target,
		Profile:  profile,
		Hosts:    []HostSummary{},
		Services: []Service{},
		Findings: []Finding{},
	}

	dec := xml.NewDecoder(bytes.NewReader(data))

	var (
		// nmap always opens <nmaprun> and, if it ran to completion, closes it.
		// Tracking both is what distinguishes three cases a streaming decoder
		// would otherwise blur together: real output that finished, real output
		// that was cut short, and input that was never nmap XML at all. Relying
		// on the decoder's own error would miss a truncation that happens to
		// land on a token boundary, which would present a half-scan as complete.
		sawRun    bool
		closedRun bool

		host         HostSummary
		inHost       bool
		inHostScript bool
		// prescript/postscript hold scan-level probes, not findings about the
		// target: a broadcast script that discovers other hosts on the LAN says
		// nothing about the host being scanned, so its results are skipped.
		inScanScript bool
		cur          *Service
		curPort      int
		curProto     string
	)

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A syntax error means the document was cut short -- overwhelmingly
			// the common cause, since a scan killed at its deadline stops
			// mid-write. Everything decoded so far is still returned, and the
			// wording matches the no-closing-tag case below so callers see one
			// consistent reason.
			return res, fmt.Errorf("nmap XML is incomplete: %w", err)
		}

		switch el := tok.(type) {
		case xml.StartElement:
			switch el.Name.Local {
			case "nmaprun":
				sawRun = true
				res.Scanner = attr(el, "scanner")
				res.Args = attr(el, "args")
			case "prescript", "postscript":
				inScanScript = true
			case "hostscript":
				inHostScript = true
			case "host":
				inHost = true
				host = HostSummary{}
			case "status":
				if inHost {
					host.State = attr(el, "state")
				}
			case "address":
				if inHost && host.Address == "" {
					host.Address = attr(el, "addr")
				}
			case "hostname":
				if inHost && host.Hostname == "" {
					host.Hostname = attr(el, "name")
				}
			case "port":
				curPort, _ = strconv.Atoi(attr(el, "portid"))
				curProto = attr(el, "protocol")
				cur = &Service{Host: host.Address, Port: curPort, Protocol: curProto}
			case "state":
				if cur != nil {
					cur.State = attr(el, "state")
				}
			case "service":
				if cur != nil {
					cur.Name = attr(el, "name")
					cur.Product = attr(el, "product")
					cur.Version = attr(el, "version")
					cur.ExtraInfo = attr(el, "extrainfo")
				}
			case "cpe":
				if cur != nil && cur.CPE == "" {
					var cpe string
					// DecodeElement consumes through the matching end tag, which
					// also handles the element's character data.
					if derr := dec.DecodeElement(&cpe, &el); derr == nil {
						cur.CPE = strings.TrimSpace(cpe)
					}
				}
			case "script":
				if !inScanScript {
					res.Findings = append(res.Findings, newFinding(host.Address, curProto, portFor(cur, inHostScript), el))
				}
			case "finished":
				res.Elapsed = attr(el, "elapsed")
			}

		case xml.EndElement:
			switch el.Name.Local {
			case "prescript", "postscript":
				inScanScript = false
			case "hostscript":
				inHostScript = false
			case "ports":
				// Past the port list, so any later <script> belongs to the host
				// and must not inherit the last port's identity.
				curPort, curProto = 0, ""
			case "port":
				if cur != nil {
					res.Services = append(res.Services, *cur)
					cur = nil
				}
			case "nmaprun":
				closedRun = true
			case "host":
				res.Hosts = append(res.Hosts, host)
				inHost = false
			}
		}
	}

	switch {
	case !sawRun:
		// Not nmap XML. Without this, arbitrary text decodes to an empty
		// document with no error, and a failed scan reads as a clean one that
		// found nothing.
		return res, errors.New("output is not nmap XML: no <nmaprun> element")
	case !closedRun:
		return res, errors.New("nmap XML is incomplete: no closing </nmaprun>")
	}
	return res, nil
}

// portFor decides which port a script result belongs to. A host-level script
// (one inside <hostscript>) is attributed to the host, not to whichever port
// happened to be parsed last.
func portFor(cur *Service, inHostScript bool) int {
	if inHostScript || cur == nil {
		return 0
	}
	return cur.Port
}

// newFinding classifies one NSE script result.
//
// nmap's XML carries no severity, and nmap has never emitted one -- the colour
// a human sees on a terminal comes from the script's own output text. Rather
// than invent a ranking, this records what the output actually states: whether
// the script reported the target as vulnerable, and which CVE identifiers
// appear in it. Uncertain output stays "not vulnerable" instead of being
// upgraded to a finding.
func newFinding(host, protocol string, port int, el xml.StartElement) Finding {
	output := strings.TrimSpace(attr(el, "output"))
	return Finding{
		Host:       host,
		Port:       port,
		Protocol:   protocol,
		ScriptID:   attr(el, "id"),
		Vulnerable: statesVulnerable(output),
		CVEs:       uniqueCVEs(output),
		Output:     output,
	}
}

// uniqueCVEs returns the CVE identifiers named in a script's output, in
// first-seen order with duplicates removed.
//
// Deduplication is not cosmetic. NSE output repeats an identifier once per
// affected package, version or table row, so a single `vulners` result against
// an Apache version can name the same CVE a dozen times -- a real scan of
// scanme.nmap.org produced over 200 entries for well under 100 distinct CVEs.
func uniqueCVEs(output string) []string {
	matches := cvePattern.FindAllString(output, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(matches))
	unique := make([]string, 0, len(matches))
	for _, id := range matches {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	return unique
}

// statesVulnerable reports whether a script's output asserts the target is
// vulnerable. nmap's NSE convention is a "VULNERABLE" line, with scripts that
// checked and found nothing printing "NOT VULNERABLE" -- so the negative form
// has to be excluded explicitly rather than by absence of the word.
func statesVulnerable(output string) bool {
	upper := strings.ToUpper(output)
	if strings.Contains(upper, "NOT VULNERABLE") {
		return false
	}
	return strings.Contains(upper, "VULNERABLE")
}

func attr(el xml.StartElement, name string) string {
	for _, a := range el.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// cvePattern matches CVE identifiers as they appear in NSE output.
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
