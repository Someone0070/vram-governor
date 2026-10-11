package runtime

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCheckpointProofCannotBeProbeOnly(t *testing.T) {
	p := CheckpointCapabilityProof{ProofVersion: CheckpointCapabilityProofVersion, ModelAlias: "alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64), Verified: true, ProbeOnly: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true, BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true, NodeID: "n", TargetID: "t", ModelFingerprint: "m", RuntimeIdentity: "r", ProfileFingerprint: "p", ContextLimit: 1, SlotID: 0, Generation: 1, NewFence: 1, EvidenceID: "e", Signature: "s", Digest: "d"}
	if p.Complete() || p.ComponentsComplete() {
		t.Fatal("probe-only proof was complete")
	}
	p.ProbeOnly = false
	p.OldFence = 1
	p.NewFence = 2
	p.SavedTokens = 2
	p.ReusedTokens = 1
	p.SnapshotBytes = 1
	p.SnapshotDigest = "sha256:snapshot"
	p.Nonce = "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef"
	p.ExpiresAt = time.Now().Add(time.Hour)
	if !p.Complete() {
		t.Fatal("complete production proof rejected")
	}
}

func TestCheckpointProofV2CanonicalDigestAndMutations(t *testing.T) {
	p := CheckpointCapabilityProof{
		ProofVersion: CheckpointCapabilityProofVersion, ModelAlias: "approved-model-alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true,
		BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true,
		ProvenAt: time.Now().UTC(),
		NodeID:   "n", TargetID: "t", ModelFingerprint: "catalog-fingerprint", RuntimeIdentity: "r", ProfileFingerprint: "p",
		ContextLimit: 4096, SlotID: 0, Generation: 1, OldFence: 1, NewFence: 2,
		SavedTokens: 2, ReusedTokens: 1, EvidenceID: "e", Signature: "s", SnapshotDigest: "sha256:snapshot",
		SnapshotBytes: 1, AcceleratorID: "n-gpu0", ExpiresAt: time.Now().UTC().Add(time.Hour),
		Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef",
	}
	p.Digest = CheckpointProofDigest(p)
	if !p.Complete() || !p.ComponentsComplete() || !strings.HasPrefix(p.Digest, "sha256:") {
		t.Fatalf("synthetic v2 proof fixture is incomplete: %+v", p)
	}
	mutations := map[string]func(*CheckpointCapabilityProof){
		"proof version": func(v *CheckpointCapabilityProof) { v.ProofVersion = "v1" },
		"model alias":   func(v *CheckpointCapabilityProof) { v.ModelAlias = "different-alias" },
		"local binding": func(v *CheckpointCapabilityProof) { v.LocalCheckpointBinding = "sha256:" + strings.Repeat("b", 64) },
		"durable epoch": func(v *CheckpointCapabilityProof) { v.Nonce = "legacy-nonce" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			if reflect.DeepEqual(changed, p) {
				t.Fatal("mutant did not change proof")
			}
			if CheckpointProofDigest(changed) == p.Digest {
				t.Fatal("canonical digest did not bind mutated v2 material")
			}
			if name == "proof version" || name == "durable epoch" {
				if changed.Complete() || changed.ComponentsComplete() {
					t.Fatal("invalid v2 identity still satisfied a proof predicate")
				}
			}
		})
	}
}

func TestCheckpointProofV2PositiveControl(t *testing.T) {
	p := CheckpointCapabilityProof{
		ProofVersion: CheckpointCapabilityProofVersion, ModelAlias: "synthetic-approved-alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true,
		BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true,
		ProvenAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		NodeID: "synthetic-node", TargetID: "synthetic-target", ModelFingerprint: "catalog-fingerprint",
		RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextLimit: 4096,
		SlotID: 0, Generation: 1, OldFence: 1, NewFence: 2, SavedTokens: 2, ReusedTokens: 1,
		EvidenceID: "synthetic-evidence", Signature: "synthetic-signature", Digest: "sha256:placeholder",
		SnapshotDigest: "sha256:snapshot", SnapshotBytes: 8, AcceleratorID: "synthetic-node-gpu0",
		Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef",
	}
	p.Digest = CheckpointProofDigest(p)
	if !p.Complete() || !p.ComponentsComplete() {
		t.Fatalf("synthetic signed-validator positive control is incomplete: %+v", p)
	}
}
