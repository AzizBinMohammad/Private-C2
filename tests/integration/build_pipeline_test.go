//go:build integration

package integration_test

import (
	"testing"
)

// TestBuildPipeline exercises the payload build pipeline end-to-end:
//
//  1. Start the server.
//  2. Create an engagement with an operator.
//  3. Request a build for linux/amd64, session mode, mTLS transport.
//  4. Verify the builder produces a binary artefact.
//  5. Verify the SHA256 hash is recorded in the PayloadArtifact table.
//  6. Verify the generated binary has the expected implant ID and
//     embedded public key.
//  7. Verify the build event appears in the audit log.
func TestBuildPipeline(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestBuildPipelineCrossCompile verifies that builds for each
// supported GOOS/GOARCH combination produce valid artefacts.
func TestBuildPipelineCrossCompile(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestBuildPipelineBeaconMode verifies that a beacon-mode build
// embeds the correct interval and jitter configuration.
func TestBuildPipelineBeaconMode(t *testing.T) {
	t.Skip("requires full server/implant stack")
}

// TestBuildPipelineDuplicateHash verifies that submitting the same
// build configuration twice does not create a duplicate artefact
// record.
func TestBuildPipelineDuplicateHash(t *testing.T) {
	t.Skip("requires full server/implant stack")
}
