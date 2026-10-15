package nmap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// realScanXML is captured verbatim from `nmap -sV -T4 -p 22,8080,9090,631 -oX -
// 127.0.0.1` on nmap 7.92, trimmed to the elements this package reads. Using
// real output rather than a hand-written sample is deliberate: it is what keeps
// the struct tags honest about <hosthint>, the attribute names, and the CPE
// nesting.
const realScanXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -T4 -p 22,8080,9090,631 -oX - 127.0.0.1" start="1792020467" version="7.92" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="4" services="22,631,8080,9090"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1792020468" endtime="1792020504"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="22"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="631"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ipp" product="CUPS" version="2.4" method="probed" conf="10"><cpe>cpe:/a:apple:cups:2.4</cpe></service></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Golang net/http server" extrainfo="Go-IPFS json-rpc or InfluxDB API" method="probed" conf="10"><cpe>cpe:/a:protocol_labs:go-ipfs</cpe></service></port>
<port protocol="tcp" portid="9090"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Golang net/http server" extrainfo="Go-IPFS json-rpc or InfluxDB API" method="probed" conf="10"><cpe>cpe:/a:protocol_labs:go-ipfs</cpe></service></port>
</ports>
<times srtt="128" rttvar="1621" to="100000"/>
</host>
<runstats><finished time="1792020504" timestr="Thu Oct 15 02:28:24 2026" elapsed="37.07" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>`

// scriptXML is the shape nmap emits for NSE scripts, again taken from real
// output (`--script banner,http-title,http-headers` on nmap 7.92) and extended
// with the VULNERABLE / NOT VULNERABLE wording the `vuln` scripts use, plus a
// hostscript block.
const scriptXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -T4 --script vuln -oX - 127.0.0.1" version="7.92">
<host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="web01.example.test" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="7.4"/><script id="ssh-auth-methods" output="Supported authentication methods: publickey,password"><elem>publickey</elem>
</script>
</port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Apache httpd" version="2.4.49"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service><script id="ssl-heartbleed" output="&#xa;  VULNERABLE:&#xa;  The Heartbleed Bug&#xa;    State: VULNERABLE&#xa;    IDs:  CVE:CVE-2014-0160&#xa;"><table key="state"><elem key="State">VULNERABLE</elem>
</table>
</script>
<script id="http-csrf" output="Couldn&apos;t find any CSRF vulnerabilities."/>
</port>
</ports>
<hostscript><script id="smb-vuln-ms17-010" output="&#xa;  VULNERABLE:&#xa;  Remote Code Execution vulnerability in Microsoft SMBv1&#xa;    IDs:  CVE:CVE-2017-0143  CVE:CVE-2017-0144&#xa;"/></hostscript>
</host>
<runstats><finished elapsed="12.34" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>`

func TestParseXML_RealOutput(t *testing.T) {
	res, err := parseXML([]byte(realScanXML), "127.0.0.1", "services")
	if err != nil {
		t.Fatalf("parseXML() error = %v", err)
	}

	// <hosthint> is a different element from <host> and must not be counted,
	// or every host would appear twice.
	if len(res.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1 (hosthint must be ignored)", len(res.Hosts))
	}
	if got := res.Hosts[0]; got.Address != "127.0.0.1" || got.Hostname != "localhost" || got.State != "up" {
		t.Errorf("host = %+v, want 127.0.0.1/localhost/up", got)
	}

	if len(res.Services) != 4 {
		t.Fatalf("services = %d, want 4", len(res.Services))
	}

	byPort := map[int]Service{}
	for _, s := range res.Services {
		byPort[s.Port] = s
	}

	// A closed port is reported rather than dropped, so "checked and nothing
	// there" is distinguishable from "never checked".
	if got := byPort[22]; got.State != "closed" || got.Name != "ssh" {
		t.Errorf("port 22 = %+v, want a closed ssh entry", got)
	}
	if got := byPort[631]; got.State != "open" || got.Product != "CUPS" || got.Version != "2.4" {
		t.Errorf("port 631 = %+v, want open CUPS 2.4", got)
	}
	if got := byPort[8080]; got.CPE != "cpe:/a:protocol_labs:go-ipfs" {
		t.Errorf("port 8080 CPE = %q, want the nested cpe element", got.CPE)
	}
	if got := byPort[8080]; got.ExtraInfo == "" {
		t.Errorf("port 8080 = %+v, want extrainfo captured", got)
	}

	if res.Elapsed != "37.07" {
		t.Errorf("elapsed = %q, want 37.07", res.Elapsed)
	}
	if res.Args == "" || res.Scanner != "nmap" {
		t.Errorf("run attributes lost: scanner=%q args=%q", res.Scanner, res.Args)
	}
}

func TestParseXML_ScriptClassification(t *testing.T) {
	res, err := parseXML([]byte(scriptXML), "10.0.0.5", "vulns")
	if err != nil {
		t.Fatalf("parseXML() error = %v", err)
	}

	byID := map[string]Finding{}
	for _, f := range res.Findings {
		byID[f.ScriptID] = f
	}
	if len(byID) != 4 {
		t.Fatalf("findings = %d (%v), want 4", len(byID), res.Findings)
	}

	hb := byID["ssl-heartbleed"]
	if !hb.Vulnerable {
		t.Errorf("ssl-heartbleed Vulnerable = false, want true")
	}
	if len(hb.CVEs) != 1 || hb.CVEs[0] != "CVE-2014-0160" {
		t.Errorf("ssl-heartbleed CVEs = %v, want [CVE-2014-0160]", hb.CVEs)
	}
	if hb.Port != 443 || hb.Protocol != "tcp" {
		t.Errorf("ssl-heartbleed at %s/%d, want tcp/443", hb.Protocol, hb.Port)
	}

	// A host-level script has no port; it must not be attributed to one.
	smb := byID["smb-vuln-ms17-010"]
	if !smb.Vulnerable || smb.Port != 0 {
		t.Errorf("smb-vuln-ms17-010 = %+v, want vulnerable with no port", smb)
	}
	if len(smb.CVEs) != 2 {
		t.Errorf("smb-vuln-ms17-010 CVEs = %v, want 2 identifiers", smb.CVEs)
	}

	// The negative form must not be read as a finding by loose word matching.
	csrf := byID["http-csrf"]
	if csrf.Vulnerable {
		t.Errorf("http-csrf marked vulnerable from output %q", csrf.Output)
	}
	if auth := byID["ssh-auth-methods"]; auth.Vulnerable {
		t.Errorf("ssh-auth-methods marked vulnerable; it is enumeration only")
	}
}

func TestStatesVulnerable(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"explicit vulnerable", "State: VULNERABLE\n  IDs: CVE:CVE-2014-0160", true},
		{"negative form", "State: NOT VULNERABLE", false},
		{"lowercase", "vulnerable", true},
		{"enumeration only", "Supported authentication methods: publickey", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := statesVulnerable(tc.output); got != tc.want {
				t.Errorf("statesVulnerable(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}

// TestUniqueCVEs pins deduplication. A real scan of scanme.nmap.org produced
// 200+ entries for well under 100 distinct CVEs, because NSE repeats each
// identifier once per affected version or table row.
func TestUniqueCVEs(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []string
	}{
		{"none", "State: NOT VULNERABLE", nil},
		{
			name:   "duplicates collapsed, first-seen order kept",
			output: "CVE-2024-38476 CVE-2024-38474 CVE-2024-38476 CVE-2024-38474 CVE-2022-31813",
			want:   []string{"CVE-2024-38476", "CVE-2024-38474", "CVE-2022-31813"},
		},
		{
			name:   "repeated across lines and columns",
			output: "cpe:/a:apache:http_server:2.4.7\n\tCVE-2021-44790\t9.8\thttps://x\n\tCVE-2021-44790\t9.8\thttps://x",
			want:   []string{"CVE-2021-44790"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := uniqueCVEs(tc.output)
			if len(got) != len(tc.want) {
				t.Fatalf("uniqueCVEs() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("uniqueCVEs()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		in      string
		want    Profile
		wantErr bool
	}{
		{"", ProfileServices, false},
		{"services", ProfileServices, false},
		{"Services", ProfileServices, false},
		{" quick ", ProfileQuick, false},
		{"vulns", ProfileVulns, false},
		{"nmap-fast", "", true},
	}
	for _, tc := range tests {
		got, err := ParseProfile(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseProfile(%q) error = nil, want an error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseProfile(%q) error = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseProfile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProfileFlags(t *testing.T) {
	if !containsAll(ProfileVulns.flags(), "-sV", "--script", "vuln") {
		t.Errorf("vulns flags = %v, want the vuln script set", ProfileVulns.flags())
	}

	// --script and its argument must be separate elements, never one string
	// that something later splits on whitespace.
	for _, f := range ProfileVulns.flags() {
		if strings.ContainsAny(f, " \t") {
			t.Errorf("flag %q contains whitespace; flags must be single elements", f)
		}
	}

	if containsAny(ProfileServices.flags(), "vuln") {
		t.Errorf("the default profile must not run vuln scripts: %v", ProfileServices.flags())
	}
	if containsAny(ProfileQuick.flags(), "-sV") {
		t.Errorf("quick must skip version detection: %v", ProfileQuick.flags())
	}
}

func TestProfileTimeout(t *testing.T) {
	// Per-profile timeouts only make sense if the tiers actually differ, and
	// the default must not exceed the raw nmap bound.
	if ProfileQuick.Timeout() >= ProfileServices.Timeout() {
		t.Errorf("quick (%s) must be shorter than services (%s)", ProfileQuick.Timeout(), ProfileServices.Timeout())
	}
	if ProfileServices.Timeout() >= ProfileVulns.Timeout() {
		t.Errorf("services (%s) must be shorter than vulns (%s)", ProfileServices.Timeout(), ProfileVulns.Timeout())
	}
	if ProfileServices.Timeout() != DefaultTimeout {
		t.Errorf("services timeout = %s, want DefaultTimeout (%s)", ProfileServices.Timeout(), DefaultTimeout)
	}
}

func TestScan_RejectsBadRequests(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "", "", nil)

	for _, req := range []Request{
		{Target: ""},
		{Target: "   "},
		{Target: "-sV"}, // an option, not a target
		{Target: "10.0.0.1", Profile: "turbo"},
	} {
		payload, _ := json.Marshal(req)
		if _, err := scanWith(context.Background(), lookupFound("/usr/bin/nmap"), run, payload); err == nil {
			t.Errorf("scanWith(%+v) error = nil, want a rejection", req)
		}
	}
	if rec.calls != 0 {
		t.Errorf("nmap invoked %d times for rejected requests, want 0", rec.calls)
	}
}

func TestScan_MissingNmap(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "", "", nil)

	payload, _ := json.Marshal(Request{Target: "10.0.0.1"})
	_, err := scanWith(context.Background(), lookupMissing(), run, payload)
	if err == nil {
		t.Fatal("scanWith() error = nil, want a missing-nmap error")
	}
	if rec.calls != 0 {
		t.Errorf("nmap invoked %d times with nmap absent, want 0", rec.calls)
	}
}

func TestScan_BuildsSafeArgv(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, realScanXML, "", nil)

	payload, _ := json.Marshal(Request{Target: "10.0.0.5"})
	if _, err := scanWith(context.Background(), lookupFound("/usr/bin/nmap"), run, payload); err != nil {
		t.Fatalf("scanWith() error = %v", err)
	}

	if rec.path == "/bin/sh" || rec.path == "sh" || rec.path == "cmd" {
		t.Fatalf("nmap ran through a shell: %q", rec.path)
	}
	if !containsAll(rec.argv, "-oX", "-") {
		t.Errorf("argv = %v, want XML on stdout (-oX -)", rec.argv)
	}
	if last := rec.argv[len(rec.argv)-1]; last != "10.0.0.5" {
		t.Errorf("argv = %v, want the target last", rec.argv)
	}
	// The path is passed through as resolved; the profile's own flags precede
	// the output flag so nothing can be read as an operand.
	if rec.argv[0] != "-sV" {
		t.Errorf("argv = %v, want the profile flags first", rec.argv)
	}
}

func TestScan_StructuredResult(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, scriptXML, "", nil)

	payload, err := json.Marshal(Request{Target: "10.0.0.5", Profile: "vulns"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	out, err := scanWith(context.Background(), lookupFound("/usr/bin/nmap"), run, payload)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	var res Result
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if res.Target != "10.0.0.5" || res.Profile != "vulns" {
		t.Errorf("target/profile = %q/%q, want 10.0.0.5/vulns", res.Target, res.Profile)
	}
	if res.Partial {
		t.Errorf("Partial = true on a completed scan")
	}
	if len(res.Services) != 2 {
		t.Errorf("services = %d, want 2", len(res.Services))
	}

	// Vulnerable findings sort ahead of enumeration noise.
	if len(res.Findings) == 0 {
		t.Fatalf("no findings parsed from the fixture")
	}
	if !res.Findings[0].Vulnerable {
		t.Errorf("first finding = %+v, want a vulnerable one first", res.Findings[0])
	}
}

func TestScan_TimeoutKeepsWhatWasFound(t *testing.T) {
	// A scan killed mid-document: truncated XML plus the ports found so far.
	run := func(ctx context.Context, _ string, _ []string) ([]byte, []byte, error) {
		<-ctx.Done()
		return []byte(realScanXML[:len(realScanXML)/2]), nil, ctx.Err()
	}

	payload, _ := json.Marshal(Request{Target: "127.0.0.1", Profile: "quick"})

	// A parent context that expires first wins: scanRequest derives its timeout
	// from the profile, and context.WithTimeout keeps the earlier of the two.
	// Without this the test would sit through the profile's real deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	out, err := scanWith(ctx, lookupFound("/usr/bin/nmap"), run, payload)

	// The caller must get both the failure and the partial data.
	if err == nil {
		t.Fatal("Scan() error = nil, want a timeout error")
	}
	var res Result
	if uerr := json.Unmarshal(out, &res); uerr != nil {
		t.Fatalf("partial result is not valid JSON: %v", uerr)
	}
	if !res.Partial {
		t.Error("Partial = false, want true: a truncated scan must not look clean")
	}
	if res.Notice == "" {
		t.Error("Notice is empty, want an explanation of the truncation")
	}
	// The tolerant decoder is the point: a scan killed mid-document must still
	// return the ports that arrived before the truncation, not an empty result
	// and not a wall of raw XML.
	if len(res.Services) == 0 {
		t.Error("no services decoded from the truncated document; the ports found before the deadline were lost")
	}
}

// TestParseXML_NotNmapOutput guards the failure that motivated the explicit
// completeness check: plain text decodes to an empty document without error, so
// without it a scan that produced nothing usable would read as a clean scan
// that found nothing.
func TestParseXML_NotNmapOutput(t *testing.T) {
	for _, in := range []string{
		"Starting Nmap 7.92 ( https://nmap.org )\nNmap done\n",
		"",
		"<html><body>not nmap</body></html>",
	} {
		res, err := parseXML([]byte(in), "127.0.0.1", "services")
		if err == nil {
			t.Errorf("parseXML(%q) error = nil, want a rejected document", in)
		}
		if res == nil {
			t.Errorf("parseXML(%q) returned no result; partial data must survive", in)
		}
	}
}

// TestParseXML_IncompleteDocument pins that a document nmap did not finish is
// reported as incomplete rather than silently accepted.
func TestParseXML_IncompleteDocument(t *testing.T) {
	// realScanXML without its closing </nmaprun>, i.e. a scan killed mid-write.
	truncated := strings.TrimSuffix(strings.TrimSpace(realScanXML), "</nmaprun>")

	res, err := parseXML([]byte(truncated), "127.0.0.1", "services")
	if err == nil {
		t.Fatal("parseXML() error = nil for an incomplete document")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error = %v, want it to say the document is incomplete", err)
	}
	// Everything before the truncation is still usable.
	if len(res.Services) != 4 {
		t.Errorf("services = %d, want the 4 decoded before truncation", len(res.Services))
	}
}

func TestScan_UnparseableOutputIsKeptRaw(t *testing.T) {
	rec := &recordingRun{}
	// nmap exits 0 but prints something that is not XML.
	run := stubRun(rec, "Starting Nmap 7.92\nNmap done\n", "", nil)

	payload, _ := json.Marshal(Request{Target: "127.0.0.1"})
	out, err := scanWith(context.Background(), lookupFound("/usr/bin/nmap"), run, payload)
	if err != nil {
		t.Fatalf("Scan() error = %v, want the raw output kept without an error", err)
	}

	var res Result
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if res.Raw == "" || res.Notice == "" {
		t.Errorf("result = %+v, want Raw and Notice populated", res)
	}
}

func TestScan_NoOutputAtAllIsAnError(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "", "", nil)

	payload, _ := json.Marshal(Request{Target: "127.0.0.1"})
	if _, err := scanWith(context.Background(), lookupFound("/usr/bin/nmap"), run, payload); err == nil {
		t.Fatal("Scan() error = nil, want an error when nmap produced nothing")
	}
}

func TestValidatePorts(t *testing.T) {
	tests := []struct {
		spec    string
		wantErr bool
	}{
		{"", false},
		{"80", false},
		{"80,443", false},
		{"1-1024", false},
		{"22,80,443,8000-8100", false},
		{" 80,443 ", false},
		{"80,", true},
		{"http", true},
		{"80; rm -rf /", true},
		{"-sV", true},
		{"80 443", true},
	}

	for _, tc := range tests {
		err := validatePorts(tc.spec)
		if tc.wantErr && err == nil {
			t.Errorf("validatePorts(%q) error = nil, want a rejection", tc.spec)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validatePorts(%q) error = %v", tc.spec, err)
		}
	}
}

// TestScan_PortsOverrideProfile pins that an explicit port list reaches nmap as
// -p and that the quick profile's -F is dropped rather than left to compete with
// it for which port set wins.
func TestScan_PortsOverrideProfile(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, realScanXML, "", nil)

	payload, _ := json.Marshal(Request{Target: "10.0.0.5", Profile: "quick", Ports: "80,443"})
	out, err := scanWith(context.Background(), lookupFound("/usr/bin/nmap"), run, payload)
	if err != nil {
		t.Fatalf("scanWith() error = %v", err)
	}

	if !containsAll(rec.argv, "-p", "80,443") {
		t.Errorf("argv = %v, want the explicit port list as -p", rec.argv)
	}
	if containsAny(rec.argv, "-F") {
		t.Errorf("argv = %v, want -F dropped when ports are given", rec.argv)
	}

	var res Result
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Ports != "80,443" {
		t.Errorf("Result.Ports = %q, want the selection echoed back", res.Ports)
	}
}

func TestScan_RejectsBadPortSpec(t *testing.T) {
	rec := &recordingRun{}
	run := stubRun(rec, "", "", nil)

	for _, spec := range []string{"80,", "http", "80; rm -rf /"} {
		payload, _ := json.Marshal(Request{Target: "10.0.0.5", Ports: spec})
		if _, err := scanWith(context.Background(), lookupFound("/usr/bin/nmap"), run, payload); err == nil {
			t.Errorf("scanWith(ports=%q) error = nil, want a rejection", spec)
		}
	}
	if rec.calls != 0 {
		t.Errorf("nmap invoked %d times for rejected port lists, want 0", rec.calls)
	}
}

func TestSortResult(t *testing.T) {
	res := &Result{
		Services: []Service{{Port: 443}, {Port: 22}, {Port: 8080}},
		Findings: []Finding{
			{ScriptID: "http-title"},
			{ScriptID: "ssl-heartbleed", Vulnerable: true},
			{ScriptID: "banner"},
		},
	}
	sortResult(res)

	if res.Services[0].Port != 22 || res.Services[2].Port != 8080 {
		t.Errorf("services = %+v, want port order", res.Services)
	}
	if !res.Findings[0].Vulnerable {
		t.Errorf("findings = %+v, want the vulnerable one first", res.Findings)
	}
}

// --- small helpers -------------------------------------------------------

func containsAll(hay []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, h := range hay {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func containsAny(hay []string, want string) bool {
	for _, h := range hay {
		if strings.Contains(h, want) {
			return true
		}
	}
	return false
}

// guard against the test file drifting from the type it exercises
var _ = time.Second
