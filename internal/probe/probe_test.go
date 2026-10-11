package probe

import (
	"testing"
	"time"
)

func TestProductionCheckpointProofRequiresEveryBoundary(t *testing.T) {
	partial := ProductionCheckpointVerification{SlotAssigned: true, PausedAtBoundary: true, SnapshotSaved: true, BackendStopConfirmed: true, SnapshotRestored: true, NodeID: "node", TargetID: "target", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextLimit: 4096, SlotID: 0, Generation: 1, NewFence: 2, EvidenceID: "evidence", Signature: "signed", Digest: "sha256:evidence"}
	if partial.Proof().Complete() {
		t.Fatal("incomplete production proof advertised")
	}
	complete := partial
	complete.KVReused = true
	complete.OldFence = 1
	complete.SavedTokens = 2
	complete.ReusedTokens = 1
	complete.SnapshotBytes = 1
	complete.SnapshotDigest = "sha256:snapshot"
	complete.Nonce = "nonce"
	complete.ExpiresAt = time.Now().Add(time.Hour)
	complete.Digest = "proof"
	proof := complete.Proof()
	if !proof.Complete() || proof.ProbeOnly {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestProductionCheckpointProofRejectsProbeOnlyWithAllBoundaries(t *testing.T) {
	proof := ProductionCheckpointVerification{SlotAssigned: true, PausedAtBoundary: true, SnapshotSaved: true, BackendStopConfirmed: true, SnapshotRestored: true, KVReused: true, NodeID: "node", TargetID: "target", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextLimit: 4096, SlotID: 0, Generation: 1, OldFence: 1, NewFence: 2, SavedTokens: 2, ReusedTokens: 1, SnapshotBytes: 1, SnapshotDigest: "sha256:snapshot", EvidenceID: "evidence", Signature: "signed", Nonce: "nonce", ExpiresAt: time.Now().Add(time.Hour)}.Proof()
	proof.ProbeOnly = true
	if proof.Complete() {
		t.Fatal("probe-only proof with complete-looking evidence was accepted")
	}
}
