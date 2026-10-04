//go:build integration

package integration_test

import (
	"testing"
)

// TestBeaconLifecycle exercises the full beacon-mode lifecycle:
//
//  1. Start the server with TLS and an in-memory database.
//  2. Start a listener.
//  3. Launch an implant in beacon mode with a short interval.
//  4. Wait for the first check-in; verify the beacon is registered.
//  5. Queue a task for the beacon.
//  6. Wait for the next check-in; verify the task result arrives.
//  7. Verify check-in timestamps and jitter are within the configured
//     tolerance.
//  8. Tear down the beacon cleanly.
//  9. Verify audit entries for all beacon events.
func TestBeaconLifecycle(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestBeaconJitter validates that the actual check-in interval varies
// within the configured jitter percentage.
func TestBeaconJitter(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestBeaconMissedCheckins verifies that if a beacon misses several
// consecutive check-in windows the server marks it appropriately.
func TestBeaconMissedCheckins(t *testing.T) {
	t.Skip("requires full server/implant stack")
}
