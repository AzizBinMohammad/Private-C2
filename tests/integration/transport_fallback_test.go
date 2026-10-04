//go:build integration

package integration_test

import (
	"testing"
)

// TestTransportFallback verifies that an implant configured with
// multiple transports falls back correctly when the primary fails:
//
//  1. Start the server with mTLS and HTTPS listeners.
//  2. Build an implant with transports [mtls, https] in order.
//  3. Launch the implant; verify it connects over mTLS.
//  4. Shut down the mTLS listener.
//  5. Wait for the implant to fail over to HTTPS.
//  6. Verify the session remains active with the same session ID.
//  7. Restart the mTLS listener; verify the implant falls back to
//     the primary transport on the next reconnect cycle.
//  8. Verify transport-change events are recorded in the audit log.
func TestTransportFallback(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestTransportAllDown verifies that the implant enters a back-off
// loop when every configured transport is unavailable and reconnects
// once any transport comes back up.
func TestTransportAllDown(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestTransportDNSOnly verifies session establishment over the DNS
// transport alone (the slowest path).
func TestTransportDNSOnly(t *testing.T) {
	t.Skip("requires full server/implant stack")
}
