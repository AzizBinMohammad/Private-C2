package platform

import (
	"testing"
)

func TestAllSixOSPresent(t *testing.T) {
	expected := []string{"windows", "linux", "darwin", "freebsd", "ios", "android"}
	oses := SupportedOperatingSystems()

	osSet := make(map[string]bool)
	for _, os := range oses {
		osSet[os] = true
	}

	for _, want := range expected {
		if !osSet[want] {
			t.Errorf("expected OS %q to be supported, but it was not found", want)
		}
	}

	if len(oses) != len(expected) {
		t.Errorf("expected %d operating systems, got %d", len(expected), len(oses))
	}
}

func TestKnownCapabilitiesCorrect(t *testing.T) {
	// Windows amd64 should have specific transports
	caps, ok := GetCapabilities("windows", "amd64")
	if !ok {
		t.Fatal("windows/amd64 should be supported")
	}

	transportSet := make(map[string]bool)
	for _, tr := range caps.Transports {
		transportSet[tr] = true
	}

	expectedTransports := []string{"mtls", "https", "http", "dns", "wireguard"}
	for _, tr := range expectedTransports {
		if !transportSet[tr] {
			t.Errorf("windows/amd64 should support transport %q", tr)
		}
	}

	// ios should only support beacon mode
	iosCaps, ok := GetCapabilities("ios", "arm64")
	if !ok {
		t.Fatal("ios/arm64 should be supported")
	}

	if len(iosCaps.ImplantModes) != 1 || iosCaps.ImplantModes[0] != "beacon" {
		t.Errorf("ios/arm64 should only support beacon mode, got %v", iosCaps.ImplantModes)
	}
}

func TestUnknownPlatformReturnsFalse(t *testing.T) {
	_, ok := GetCapabilities("plan9", "amd64")
	if ok {
		t.Error("plan9/amd64 should not be supported")
	}

	_, ok = GetCapabilities("linux", "sparc")
	if ok {
		t.Error("linux/sparc should not be supported")
	}
}

func TestSupportedArchitectures(t *testing.T) {
	arches := SupportedArchitectures("linux")
	if arches == nil {
		t.Fatal("linux should have supported architectures")
	}

	archSet := make(map[string]bool)
	for _, a := range arches {
		archSet[a] = true
	}

	if !archSet["amd64"] {
		t.Error("linux should support amd64")
	}
	if !archSet["arm64"] {
		t.Error("linux should support arm64")
	}
}

func TestSupportedArchitecturesUnknownOS(t *testing.T) {
	arches := SupportedArchitectures("plan9")
	if arches != nil {
		t.Errorf("unknown OS should return nil, got %v", arches)
	}
}
