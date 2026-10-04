package engagement

import (
	"testing"
)

func TestIPInCIDRMatches(t *testing.T) {
	scope, err := NewScope(
		[]string{"10.0.0.0/24"},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	ok, reason := scope.Contains("10.0.0.50")
	if !ok {
		t.Fatalf("10.0.0.50 should be in scope, reason: %s", reason)
	}
}

func TestIPOutsideCIDRRejected(t *testing.T) {
	scope, err := NewScope(
		[]string{"10.0.0.0/24"},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	ok, reason := scope.Contains("192.168.1.1")
	if ok {
		t.Fatal("192.168.1.1 should not be in 10.0.0.0/24 scope")
	}
	if reason == "" {
		t.Fatal("expected a reason for out-of-scope target")
	}
}

func TestHostnameMatch(t *testing.T) {
	scope, err := NewScope(
		nil,
		[]string{"server1.internal", "server2.internal"},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	ok, _ := scope.Contains("server1.internal")
	if !ok {
		t.Fatal("server1.internal should match by hostname")
	}

	// Case-insensitive match
	ok, _ = scope.Contains("SERVER1.INTERNAL")
	if !ok {
		t.Fatal("hostname matching should be case-insensitive")
	}

	ok, _ = scope.Contains("server3.internal")
	if ok {
		t.Fatal("server3.internal should not match")
	}
}

func TestDomainSuffixMatch(t *testing.T) {
	scope, err := NewScope(
		nil, nil,
		[]string{"example.com"},
		nil,
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	// Subdomain should match
	ok, _ := scope.Contains("www.example.com")
	if !ok {
		t.Fatal("www.example.com should match domain example.com")
	}

	// Deep subdomain should match
	ok, _ = scope.Contains("deep.sub.example.com")
	if !ok {
		t.Fatal("deep.sub.example.com should match domain example.com")
	}

	// Exact domain should match
	ok, _ = scope.Contains("example.com")
	if !ok {
		t.Fatal("example.com should match itself")
	}

	// Different domain should not match
	ok, _ = scope.Contains("notexample.com")
	if ok {
		t.Fatal("notexample.com should not match example.com domain")
	}
}

func TestExcludedTargetRejected(t *testing.T) {
	scope, err := NewScope(
		[]string{"10.0.0.0/24"},
		nil, nil,
		[]string{"10.0.0.1"},
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	// Excluded IP should be rejected even if it falls within CIDR
	ok, reason := scope.Contains("10.0.0.1")
	if ok {
		t.Fatal("excluded target should be rejected")
	}
	if reason == "" {
		t.Fatal("expected a reason for excluded target")
	}

	// Non-excluded IP in CIDR should still work
	ok, _ = scope.Contains("10.0.0.2")
	if !ok {
		t.Fatal("non-excluded IP in CIDR should be in scope")
	}
}

func TestInvalidCIDRError(t *testing.T) {
	_, err := NewScope(
		[]string{"invalid-cidr"},
		nil, nil, nil,
	)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestEmptyScope(t *testing.T) {
	scope, err := NewScope(nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	ok, _ := scope.Contains("10.0.0.1")
	if ok {
		t.Fatal("empty scope should not contain any target")
	}
}
