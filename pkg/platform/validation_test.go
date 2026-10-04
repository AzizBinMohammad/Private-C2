package platform

import (
	"testing"
)

func TestValidConfigPasses(t *testing.T) {
	result := ValidatePayloadConfig("linux", "amd64", "session",
		[]string{"mtls", "https"}, []string{"shell", "filesystem"})

	if !result.Valid {
		t.Fatalf("expected valid config, got errors: %v", result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %d", len(result.Errors))
	}
}

func TestUnsupportedOSFails(t *testing.T) {
	result := ValidatePayloadConfig("plan9", "amd64", "session",
		[]string{"mtls"}, []string{"shell"})

	if result.Valid {
		t.Fatal("unsupported OS should not be valid")
	}

	found := false
	for _, e := range result.Errors {
		if e.Code == "UNSUPPORTED_PLATFORM" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected UNSUPPORTED_PLATFORM error code")
	}
}

func TestIncompatibleTransport(t *testing.T) {
	// ios/arm64 does not support mtls
	result := ValidatePayloadConfig("ios", "arm64", "beacon",
		[]string{"mtls"}, []string{"shell"})

	if result.Valid {
		t.Fatal("incompatible transport should not be valid")
	}

	found := false
	for _, e := range result.Errors {
		if e.Code == "UNSUPPORTED_TRANSPORT" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected UNSUPPORTED_TRANSPORT error code")
	}
}

func TestUnsupportedModeError(t *testing.T) {
	// ios/arm64 only supports beacon, not session
	result := ValidatePayloadConfig("ios", "arm64", "session",
		[]string{"https"}, []string{"shell"})

	if result.Valid {
		t.Fatal("unsupported mode should not be valid")
	}

	found := false
	for _, e := range result.Errors {
		if e.Code == "UNSUPPORTED_MODE" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected UNSUPPORTED_MODE error code")
	}
}

func TestFeatureWarning(t *testing.T) {
	// linux/amd64 does not have "registry" feature
	result := ValidatePayloadConfig("linux", "amd64", "session",
		[]string{"mtls"}, []string{"shell", "registry"})

	if !result.Valid {
		t.Fatal("missing feature should produce warning, not error")
	}

	if len(result.Warnings) == 0 {
		t.Fatal("expected at least one warning for unavailable feature")
	}

	found := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected non-empty warning message")
	}
}

func TestMultipleErrors(t *testing.T) {
	// ios/arm64: session mode unsupported + mtls transport unsupported
	result := ValidatePayloadConfig("ios", "arm64", "session",
		[]string{"mtls"}, nil)

	if result.Valid {
		t.Fatal("expected invalid config")
	}

	if len(result.Errors) < 2 {
		t.Fatalf("expected at least 2 errors, got %d", len(result.Errors))
	}
}
