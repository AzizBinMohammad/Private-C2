//go:build integration

package integration_test

import (
	"testing"
)

// TestSessionLifecycle exercises the full interactive-session lifecycle:
//
//  1. Start the server with TLS and an in-memory database.
//  2. Start a listener on a free port.
//  3. Launch an implant in session mode and wait for registration.
//  4. Verify the session appears in the session manager as Active.
//  5. Send a no-op task and verify the response round-trip.
//  6. Simulate a network interruption; verify the session transitions
//     to Stale and then Lost.
//  7. Resume the implant connection; verify the session transitions
//     back to Active.
//  8. Cleanly disconnect the implant; verify the session is marked
//     Disconnected and removed from the session manager.
//  9. Verify matching audit-log entries were recorded for every
//     state transition.
func TestSessionLifecycle(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestSessionLocking verifies that only one operator may lock a session
// at a time and that lock/unlock events are audited.
func TestSessionLocking(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestSessionReconnection verifies that an implant that disconnects
// and reconnects is matched to the same server-side session record
// when its implant ID is unchanged.
func TestSessionReconnection(t *testing.T) {
	t.Skip("requires full server/implant stack")
}
