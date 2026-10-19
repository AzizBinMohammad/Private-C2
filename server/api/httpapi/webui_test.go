package httpapi

import (
	"regexp"
	"strings"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

// TestPortalTaskTypesMatchProtocol guards against the portal drifting from the
// implant registry. The dropdown previously offered task types no handler
// implemented and omitted scan.
func TestPortalTaskTypesMatchProtocol(t *testing.T) {
	raw, err := webUIFS.ReadFile("webui/index.html")
	if err != nil {
		t.Fatalf("read embedded portal: %v", err)
	}
	html := string(raw)

	start := strings.Index(html, `<select id="cmd-type">`)
	if start < 0 {
		t.Fatal("cmd-type select not found")
	}
	end := strings.Index(html[start:], "</select>")
	if end < 0 {
		t.Fatal("cmd-type select is not closed")
	}
	block := html[start : start+end]

	re := regexp.MustCompile(`<option value="([^"]+)">`)
	matches := re.FindAllStringSubmatch(block, -1)
	got := make(map[string]bool, len(matches))
	for _, m := range matches {
		got[m[1]] = true
	}

	for _, want := range protocol.ImplementedTaskTypes() {
		if !got[want] {
			t.Errorf("portal is missing task type %q", want)
		}
	}
	for taskType := range got {
		if !protocol.IsImplementedTaskType(taskType) {
			t.Errorf("portal offers unregistered task type %q", taskType)
		}
	}
}
