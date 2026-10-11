//go:build linux

package api

import "testing"

// The product boundary is intentionally Linux-only: verified warm residency
// requires the real mincore+mlock backend. The Windows verifier cross-builds
// this package and executes this test through WSL.
func TestControllerResidencySignedNodeBoundary(t *testing.T) {
	runControllerResidencySignedNodeBoundary(t)
}
