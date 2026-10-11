package workloads

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/runtime"
	"vram-governor/internal/store"
)

type checkpointFakeRuntime struct {
	calls      []string
	assignErr  error
	pauseErr   error
	saveErr    error
	stopErr    error
	releaseErr error
	reloadErr  error
	restoreErr error
	reuse      int
	reuseErr   error
	resumeErr  error
}

func (f *checkpointFakeRuntime) mark(v string) { f.calls = append(f.calls, v) }
func (f *checkpointFakeRuntime) AssignSlot(_ context.Context, l SlotLease) (SlotLease, error) {
	f.mark("assign")
	if f.assignErr != nil {
		return SlotLease{}, f.assignErr
	}
	l.SlotID = 2
	return l, nil
}
func (f *checkpointFakeRuntime) PauseAtTokenBoundary(_ context.Context, _ SlotLease) (PartialOutput, error) {
	f.mark("pause")
	if f.pauseErr != nil {
		return PartialOutput{}, f.pauseErr
	}
	return PartialOutput{Prefix: []byte("partial"), TokenCount: 7}, nil
}
func (f *checkpointFakeRuntime) SaveKV(_ context.Context, _ SlotLease) (KVSnapshot, error) {
	f.mark("save")
	if f.saveErr != nil {
		return KVSnapshot{}, f.saveErr
	}
	return KVSnapshot{Bytes: []byte("kv-bytes"), Tokens: 7, RuntimeDigest: "runtime-digest"}, nil
}
func (f *checkpointFakeRuntime) ConfirmBackendStopped(context.Context, SlotLease) error {
	f.mark("stopped")
	return f.stopErr
}
func (f *checkpointFakeRuntime) ReleaseSlot(context.Context, SlotLease) error {
	f.mark("release")
	return f.releaseErr
}
func (f *checkpointFakeRuntime) Reload(context.Context, SlotLease) error {
	f.mark("reload")
	return f.reloadErr
}
func (f *checkpointFakeRuntime) RestoreKV(context.Context, SlotLease, KVSnapshot) error {
	f.mark("restore")
	return f.restoreErr
}
func (f *checkpointFakeRuntime) VerifyKVReuse(context.Context, SlotLease, int) (int, error) {
	f.mark("reuse")
	return f.reuse, f.reuseErr
}
func (f *checkpointFakeRuntime) Resume(context.Context, SlotLease, PartialOutput) error {
	f.mark("resume")
	return f.resumeErr
}

func testCheckpointCommand() (CheckpointCommand, SlotLease) {
	c := CheckpointCommand{ID: "cmd-1", IdempotencyKey: "key-1", OwnerID: "owner-a", WorkloadID: "work-a", WorkloadRevision: 1, Generation: 4, RuntimeIdentity: "llama-build-a", ModelFingerprint: "model-a", ProfileFingerprint: "profile-a", ContextLimit: 4096, Fence: 9, Signature: "signed"}
	l := SlotLease{TargetID: "target-a", AcceleratorID: "gpu-a", SlotID: 1, OwnerID: c.OwnerID, WorkloadID: c.WorkloadID, Generation: c.Generation, Fence: c.Fence, RuntimeIdentity: c.RuntimeIdentity, ModelFingerprint: c.ModelFingerprint, ProfileFingerprint: c.ProfileFingerprint, ContextLimit: c.ContextLimit}
	return c, l
}

func TestCheckpointCommandRequiresWorkloadRevision(t *testing.T) {
	command, _ := testCheckpointCommand()
	command.WorkloadRevision = 0
	if err := command.valid(); err == nil {
		t.Fatal("checkpoint command without workload revision was accepted")
	}
}

func testLiveProof() runtime.CheckpointCapabilityProof {
	p := runtime.CheckpointCapabilityProof{ProofVersion: runtime.CheckpointCapabilityProofVersion, ModelAlias: "model-a-alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64), Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true, BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true, ProvenAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour), NodeID: "node", TargetID: "target-a", ModelFingerprint: "model-a", RuntimeIdentity: "llama-build-a", ProfileFingerprint: "profile-a", ContextLimit: 4096, SlotID: 2, Generation: 4, OldFence: 8, NewFence: 9, SavedTokens: 7, ReusedTokens: 6, SnapshotBytes: 1, SnapshotDigest: "sha256:snapshot", Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef", EvidenceID: "evidence-1", Signature: "signed-evidence", Digest: "sha256:evidence"}
	return p
}

func TestProductionCheckpointOrderAndKVReuse(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir(), 1<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	fake := &checkpointFakeRuntime{reuse: 0}
	proof := testLiveProof()
	coordinator := NewCheckpointCoordinator(fake, store, proof)
	command, lease := testCheckpointCommand()
	name, err := coordinator.Checkpoint(context.Background(), command, lease)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fake.calls, []string{"assign", "pause", "save", "stopped", "release"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("checkpoint order=%v want %v", got, want)
	}
	fake.calls = nil
	command.Fence++
	lease.Fence++
	if err := coordinator.Restore(context.Background(), command, lease, name); err != nil {
		t.Fatal(err)
	}
	if got, want := fake.calls, []string{"assign", "reload", "restore", "resume", "reuse"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("restore order=%v want %v", got, want)
	}
}

func TestCheckpointDoesNotAdvertiseProbeOnlyAndPreservesOriginalOnSaveFault(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir(), 1<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	fake := &checkpointFakeRuntime{saveErr: errors.New("save fault")}
	coordinator := NewCheckpointCoordinator(fake, store, ProbeCapabilityProof())
	command, lease := testCheckpointCommand()
	if !coordinator.Ready() {
		t.Fatal("store/recovery readiness should not depend on the global proof")
	}
	if coordinator.ReadyForTarget(Target{ID: "target-a"}, "", "", 0, 0) {
		t.Fatal("probe-only result advertised production checkpointability")
	}
	if _, err := coordinator.Checkpoint(context.Background(), command, lease); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("err=%v", err)
	}
	coordinator.Proof = testLiveProof()
	if _, err := coordinator.Checkpoint(context.Background(), command, lease); err == nil {
		t.Fatal("save fault was hidden")
	}
	if got, want := fake.calls, []string{"assign", "pause", "save", "resume"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fault cleanup=%v want %v", got, want)
	}
}

func TestCheckpointFaultMatrixEveryLifecycleBoundary(t *testing.T) {
	faults := []struct {
		name      string
		configure func(*checkpointFakeRuntime)
		want      []string
	}{
		{"assign", func(f *checkpointFakeRuntime) { f.assignErr = errors.New("assign") }, []string{"assign"}},
		{"pause", func(f *checkpointFakeRuntime) { f.pauseErr = errors.New("pause") }, []string{"assign", "pause", "resume"}},
		{"save", func(f *checkpointFakeRuntime) { f.saveErr = errors.New("save") }, []string{"assign", "pause", "save", "resume"}},
		{"stop", func(f *checkpointFakeRuntime) { f.stopErr = errors.New("stop") }, []string{"assign", "pause", "save", "stopped", "resume"}},
		{"release", func(f *checkpointFakeRuntime) { f.releaseErr = errors.New("release") }, []string{"assign", "pause", "save", "stopped", "release", "resume"}},
	}
	for _, tc := range faults {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewSnapshotStore(t.TempDir(), 1<<20, 4)
			if err != nil {
				t.Fatal(err)
			}
			fake := &checkpointFakeRuntime{}
			tc.configure(fake)
			coordinator := NewCheckpointCoordinator(fake, store, testLiveProof())
			command, lease := testCheckpointCommand()
			if _, err := coordinator.Checkpoint(context.Background(), command, lease); err == nil {
				t.Fatal("fault was hidden")
			}
			if !reflect.DeepEqual(fake.calls, tc.want) {
				t.Fatalf("calls=%v want %v", fake.calls, tc.want)
			}
		})
	}
	restoreFaults := []struct {
		name      string
		configure func(*checkpointFakeRuntime)
		want      string
	}{
		{"reload", func(f *checkpointFakeRuntime) { f.reloadErr = errors.New("reload") }, "reload"},
		{"restore", func(f *checkpointFakeRuntime) { f.restoreErr = errors.New("restore") }, "restore"},
		{"reuse", func(f *checkpointFakeRuntime) { f.reuseErr = errors.New("reuse") }, "reuse"},
		{"resume", func(f *checkpointFakeRuntime) { f.resumeErr = errors.New("resume") }, "resume"},
	}
	for _, tc := range restoreFaults {
		t.Run("restore_"+tc.name, func(t *testing.T) {
			store, err := NewSnapshotStore(t.TempDir(), 1<<20, 4)
			if err != nil {
				t.Fatal(err)
			}
			producer := &checkpointFakeRuntime{}
			coordinator := NewCheckpointCoordinator(producer, store, testLiveProof())
			command, lease := testCheckpointCommand()
			name, err := coordinator.Checkpoint(context.Background(), command, lease)
			if err != nil {
				t.Fatal(err)
			}
			consumer := &checkpointFakeRuntime{reuse: 0}
			tc.configure(consumer)
			coordinator.Runtime = consumer
			command.Fence++
			lease.Fence++
			if err := coordinator.Restore(context.Background(), command, lease, name); err == nil {
				t.Fatal("restore fault was hidden")
			}
			if len(consumer.calls) == 0 || consumer.calls[len(consumer.calls)-1] != "release" {
				t.Fatalf("fault=%s calls=%v did not release", tc.name, consumer.calls)
			}
		})
	}
}

func TestSnapshotStoreRejectsTraversalSymlinkAndQuota(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(root, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	meta := SnapshotMetadata{Identity: runtime.CheckpointIdentity{OwnerID: "owner-a", WorkloadID: "w", Generation: 1, RuntimeIdentity: "r", ModelFingerprint: "m", ProfileFingerprint: "p", ContextLimit: 1}}
	if err := store.Put("owner-a", "../escape.kv", []byte("x"), meta); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := store.Put("owner-a", "one.kv", []byte("1234"), meta); err != nil {
		t.Fatal(err)
	}
	if err := store.Put("owner-a", "two.kv", []byte("x"), meta); err == nil {
		t.Fatal("quota overflow accepted")
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "owner-a", "link.kv")); err == nil {
		if _, _, e := store.Get("owner-a", "link.kv"); e == nil {
			t.Fatal("symlink restore accepted")
		}
	}
}

func externalQuotaMetadata(owner, command string, size int64) SnapshotMetadata {
	return SnapshotMetadata{
		Identity: runtime.CheckpointIdentity{
			NodeID: "node", TargetID: "target", AcceleratorID: "gpu0", OwnerID: owner, WorkloadID: "work-" + command,
			Generation: 1, RuntimeIdentity: "runtime", ModelFingerprint: "model", ProfileFingerprint: "profile", ContextLimit: 4096, SlotID: 0,
		},
		Fence: 2, OldFence: 1, NewFence: 2, KVBytes: size, KVTokens: 1,
		KVRuntimeDigest: "runtime-" + command, KVRef: command + ".kv", KVExternal: true, CommandID: command,
	}
}

func assertSnapshotBundleAbsent(t *testing.T, snapshots *SnapshotStore, owner, name string) {
	t.Helper()
	base := filepath.Join(snapshots.Root(), owner, name)
	for _, path := range []string{base, base + ".json", base + ".commit"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("failed snapshot left committed artifact %q: err=%v", path, err)
		}
	}
}

func TestSnapshotStoreQuotaAccountingFailsClosedAtMaxInt64(t *testing.T) {
	root := t.TempDir()
	snapshots, err := NewSnapshotStore(root, math.MaxInt64, 8)
	if err != nil {
		t.Fatal(err)
	}
	base := SnapshotMetadata{Identity: runtime.CheckpointIdentity{OwnerID: "owner-a", WorkloadID: "base", Generation: 1, RuntimeIdentity: "runtime", ModelFingerprint: "model", ProfileFingerprint: "profile", ContextLimit: 4096}}
	if err := snapshots.Put("owner-a", "base.kv", []byte("x"), base); err != nil {
		t.Fatal(err)
	}
	if err := snapshots.Put("owner-b", "global-overflow.kv", nil, externalQuotaMetadata("owner-b", "global-overflow", math.MaxInt64)); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("global max-int64 quota overflow was accepted: %v", err)
	}
	assertSnapshotBundleAbsent(t, snapshots, "owner-b", "global-overflow.kv")
	if _, _, err := snapshots.Get("owner-a", "base.kv"); err != nil {
		t.Fatalf("existing snapshot was changed after rejected global overflow: %v", err)
	}

	ownerRoot := t.TempDir()
	ownerStore, err := NewSnapshotStore(ownerRoot, math.MaxInt64, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := ownerStore.ConfigureQuotas(math.MaxInt64, 8, math.MaxInt64-1, 8, 1<<20, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := ownerStore.Put("owner-a", "base.kv", []byte("x"), base); err != nil {
		t.Fatal(err)
	}
	// Global usage reaches exactly MaxInt64, while the stricter owner quota
	// rejects the same logical replacement before any temporary file is made.
	if err := ownerStore.Put("owner-a", "owner-overflow.kv", nil, externalQuotaMetadata("owner-a", "owner-overflow", math.MaxInt64-1)); err == nil || !strings.Contains(err.Error(), "owner quota") {
		t.Fatalf("owner max-int64 quota overflow was accepted: %v", err)
	}
	assertSnapshotBundleAbsent(t, ownerStore, "owner-a", "owner-overflow.kv")
}

func TestSnapshotStoreQuotaAccountingUsesDeclaredExternalSizeAfterRestart(t *testing.T) {
	root := t.TempDir()
	snapshots, err := NewSnapshotStore(root, math.MaxInt64, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshots.Put("owner-a", "external.kv", nil, externalQuotaMetadata("owner-a", "external", math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewSnapshotStore(root, math.MaxInt64, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, metadata, err := restarted.Get("owner-a", "external.kv"); err != nil || metadata.KVBytes != math.MaxInt64 {
		t.Fatalf("MaxInt64 external snapshot did not survive restart restore: metadata=%+v err=%v", metadata, err)
	}
	if err := restarted.Put("owner-b", "after-restart.kv", []byte("x"), SnapshotMetadata{Identity: runtime.CheckpointIdentity{OwnerID: "owner-b", WorkloadID: "after-restart", Generation: 1, RuntimeIdentity: "runtime", ModelFingerprint: "model", ProfileFingerprint: "profile", ContextLimit: 4096}}); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("restart usage did not retain MaxInt64 external declaration: %v", err)
	}
	assertSnapshotBundleAbsent(t, restarted, "owner-b", "after-restart.kv")
}

func TestSnapshotStoreQuotaReplacementAccountingChecksBothDirections(t *testing.T) {
	if got, err := checkedSnapshotReplacement(math.MaxInt64, 1, 1); err != nil || got != math.MaxInt64 {
		t.Fatalf("valid replacement at MaxInt64 failed: value=%d err=%v", got, err)
	}
	if _, err := checkedSnapshotReplacement(math.MaxInt64, 1, 0); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("replacement addition overflow was accepted: %v", err)
	}
	if _, err := checkedSnapshotReplacement(0, 1, 1); err == nil || !strings.Contains(err.Error(), "underflow") {
		t.Fatalf("replacement subtraction underflow was accepted: %v", err)
	}
	if _, err := checkedSnapshotReplacement(1, math.MaxInt64, 2); err == nil || !strings.Contains(err.Error(), "underflow") {
		t.Fatalf("invalid replacement accounting was accepted: %v", err)
	}
}

func TestSnapshotStoreCorruptExternalMetadataFailsClosedForScanOwnerAndReplacement(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(root, 1<<20, 8)
	if err != nil {
		t.Fatal(err)
	}
	metadata := externalQuotaMetadata("owner-a", "corrupt", 4096)
	if err := store.Put("owner-a", "corrupt.kv", nil, metadata); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(root, "owner-a", "corrupt.kv.json")
	if err := os.WriteFile(metaPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get("owner-a", "corrupt.kv"); err == nil || !strings.Contains(err.Error(), "invalid snapshot metadata") {
		t.Fatalf("corrupt external sidecar was readable: %v", err)
	}
	newMetadata := externalQuotaMetadata("owner-b", "new", 1)
	if err := store.Put("owner-b", "new.kv", nil, newMetadata); err == nil || !strings.Contains(err.Error(), "metadata sidecar") {
		t.Fatalf("quota scan silently ignored corrupt sidecar: %v", err)
	}
	assertSnapshotBundleAbsent(t, store, "owner-b", "new.kv")
	if err := store.Put("owner-a", "corrupt.kv", nil, metadata); err == nil || (!strings.Contains(err.Error(), "metadata sidecar") && !strings.Contains(err.Error(), "replacement metadata")) {
		t.Fatalf("replacement silently ignored corrupt sidecar: %v", err)
	}
}

func TestSnapshotStoreDeleteRejectsActiveReferenceAndPreservesRestartRestore(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(root, 1<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	metadata := SnapshotMetadata{
		Identity: runtime.CheckpointIdentity{
			NodeID: "node", TargetID: "target", AcceleratorID: "gpu0", OwnerID: "owner-a", WorkloadID: "work-a",
			Generation: 1, RuntimeIdentity: "runtime", ModelFingerprint: "model", ProfileFingerprint: "profile", ContextLimit: 4096, SlotID: 1,
		},
		Fence: 2, OldFence: 1, NewFence: 2, KVTokens: 1, KVRuntimeDigest: "runtime-digest", ActiveReferences: 1, Terminalized: false, CommandID: "op-a",
	}
	if err := store.Put("owner-a", "active.kv", []byte("snapshot"), metadata); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("owner-a", "active.kv"); !errors.Is(err, ErrSnapshotActiveReferences) {
		t.Fatalf("active snapshot delete err=%v", err)
	}
	if _, _, err := store.Get("owner-a", "active.kv"); err != nil {
		t.Fatalf("active restore artifact was deleted: %v", err)
	}
	if err := store.MarkInactiveForOperation("owner-a", "active.kv", "wrong-op"); !errors.Is(err, ErrSnapshotDeleteExpectation) {
		t.Fatalf("late release identity was not rejected: %v", err)
	}
	if err := store.MarkInactiveForOperation("owner-a", "active.kv", "op-a"); err != nil {
		t.Fatal(err)
	}
	// A fresh store instance must still recover the terminalized bundle before
	// privileged cleanup removes it.
	restarted, err := NewSnapshotStore(root, 1<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, metadata, err := restarted.Get("owner-a", "active.kv"); err != nil || !metadata.Terminalized || metadata.ActiveReferences != 0 {
		t.Fatalf("restart restore lost terminal metadata: metadata=%+v err=%v", metadata, err)
	}
	if err := restarted.DeletePrivileged("owner-a", "active.kv", SnapshotDeleteExpectation{OwnerID: "owner-a", OperationID: "op-a", ActiveReferences: 0, Terminalized: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Get("owner-a", "active.kv"); err == nil {
		t.Fatal("privileged cleanup did not remove terminalized snapshot")
	}
}

func TestSnapshotStorePutOverwriteGuardsAndSameOwnerIdempotence(t *testing.T) {
	root := t.TempDir()
	snapshots, err := NewSnapshotStore(root, 1<<20, 8)
	if err != nil {
		t.Fatal(err)
	}
	metadata := SnapshotMetadata{
		Identity: runtime.CheckpointIdentity{
			NodeID: "node", TargetID: "target", AcceleratorID: "gpu0", OwnerID: "owner-a", WorkloadID: "work-a",
			Generation: 1, RuntimeIdentity: "runtime", ModelFingerprint: "model", ProfileFingerprint: "profile", ContextLimit: 4096, SlotID: 0,
		},
		Fence: 2, OldFence: 1, NewFence: 2, ActiveReferences: 1, Terminalized: false, CommandID: "op-a",
	}
	data := []byte("immutable-snapshot")
	if err := snapshots.Put("owner-a", "same.kv", data, metadata); err != nil {
		t.Fatal(err)
	}
	// Replaying the same owner/operation and exact content must not rewrite an
	// active bundle or disturb its reference count.
	if err := snapshots.Put("owner-a", "same.kv", data, metadata); err != nil {
		t.Fatalf("same-owner idempotent Put failed: %v", err)
	}
	if err := snapshots.Put("owner-a", "same.kv", []byte("tampered"), metadata); !errors.Is(err, ErrSnapshotActiveReferences) {
		t.Fatalf("active snapshot content overwrite was accepted: %v", err)
	}
	differentOperation := metadata
	differentOperation.CommandID = "op-other"
	if err := snapshots.Put("owner-a", "same.kv", data, differentOperation); !errors.Is(err, ErrSnapshotActiveReferences) {
		t.Fatalf("active snapshot operation overwrite was accepted: %v", err)
	}
	differentRevision := metadata
	differentRevision.WorkloadRevision = 2
	if err := snapshots.Put("owner-a", "same.kv", data, differentRevision); !errors.Is(err, ErrSnapshotActiveReferences) {
		t.Fatalf("active snapshot workload revision overwrite was accepted: %v", err)
	}
	differentFence := metadata
	differentFence.Fence = 3
	if err := snapshots.Put("owner-a", "same.kv", data, differentFence); !errors.Is(err, ErrSnapshotActiveReferences) {
		t.Fatalf("active snapshot fence overwrite was accepted: %v", err)
	}
	if err := snapshots.MarkInactiveForOperation("owner-a", "same.kv", "op-a"); err != nil {
		t.Fatal(err)
	}
	if err := snapshots.Put("owner-a", "same.kv", data, metadata); err != nil {
		t.Fatalf("same-owner terminalized idempotent Put failed: %v", err)
	}
	if err := snapshots.Put("owner-a", "same.kv", data, differentOperation); !errors.Is(err, ErrSnapshotDeleteExpectation) {
		t.Fatalf("terminalized different-operation overwrite was accepted: %v", err)
	}

	path := filepath.Join(snapshots.Root(), "owner-a", "same.kv")
	outside := filepath.Join(root, "outside.kv")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err == nil {
		if _, _, getErr := snapshots.Get("owner-a", "same.kv"); getErr == nil {
			t.Fatal("nofollow snapshot read accepted a symlink")
		}
		if _, _, descriptorErr := readSnapshotDescriptor(path, 1<<20); descriptorErr == nil {
			t.Fatal("snapshot descriptor helper accepted a symlink")
		}
	}

	// POSIX permissions and hardlinks are part of the same descriptor safety
	// contract. Windows does not expose equivalent mode/link guarantees, so the
	// platform-specific assertions are intentionally skipped there.
	if goruntime.GOOS != "windows" {
		_ = os.Remove(path)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, getErr := snapshots.Get("owner-a", "same.kv"); getErr == nil {
			t.Fatal("world-readable snapshot was accepted")
		}
	}
}

func TestPartialOutputStitchAvoidsDuplicatePrefix(t *testing.T) {
	partial := PartialOutput{Prefix: []byte("hello "), TokenCount: 2}
	if got := string(partial.Stitch([]byte("world"))); got != "hello world" {
		t.Fatalf("suffix stitch=%q", got)
	}
	if got := string(partial.Stitch([]byte("hello world"))); got != "hello world" {
		t.Fatalf("duplicate stitch=%q", got)
	}
}

func TestCheckpointRecoveryKeepsReadyFalseOnUnresolvedOperation(t *testing.T) {
	snapshots, err := NewSnapshotStore(t.TempDir(), 1<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCheckpointCoordinator(&checkpointFakeRuntime{}, snapshots, ProbeCapabilityProof())
	c.Operations = store.NewMemoryStore()
	_, err = createCheckpointTestOperation(c.Operations, &store.LLMCheckpointOperation{ID: "recover-op", IdempotencyKey: "recover-key", OwnerID: "owner", WorkloadID: "work", WorkloadRevision: 1, NodeID: "node", AcceleratorID: "gpu0", TargetID: "target", Model: "model", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "conv-recover", ContinuationConversationID: "continuation-recover", SlotID: 1, Generation: 1, Fence: 2, Phase: "saved"}, "saved")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Recover(context.Background()); err == nil {
		t.Fatal("unresolved operation was silently recovered")
	}
	if c.Ready() {
		t.Fatal("coordinator advertised readiness with unresolved recovery")
	}
	noStore := NewCheckpointCoordinator(&checkpointFakeRuntime{}, snapshots, ProbeCapabilityProof())
	if err := noStore.Recover(context.Background()); err == nil {
		t.Fatal("missing durable operation store was treated as clean recovery")
	}
}

func TestCheckpointRecoveryRejectsMismatchedNodeEvidence(t *testing.T) {
	snapshots, err := NewSnapshotStore(t.TempDir(), 1<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCheckpointCoordinator(&checkpointFakeRuntime{}, snapshots, ProbeCapabilityProof())
	c.Operations = store.NewMemoryStore()
	_, err = createCheckpointTestOperation(c.Operations, &store.LLMCheckpointOperation{ID: "evidence-op", IdempotencyKey: "evidence-key", OwnerID: "owner", WorkloadID: "work", WorkloadRevision: 1, NodeID: "node", AcceleratorID: "gpu0", TargetID: "target", Model: "model", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "conv-evidence", ContinuationConversationID: "continuation-evidence", SlotID: 1, Generation: 1, Fence: 2, Phase: "resumed", SnapshotName: "victim.kv", SnapshotDigest: "digest"}, "resumed")
	if err != nil {
		t.Fatal(err)
	}
	c.SetRecoveryEvidenceQuery(func(context.Context, *store.LLMCheckpointOperation) (RecoveryObservation, error) {
		return RecoveryObservation{NodeID: "other-node", TargetID: "target", AcceleratorID: "gpu0", OperationID: "evidence-op", SlotID: 1}, nil
	})
	if err := c.Recover(context.Background()); err == nil || c.Ready() {
		t.Fatalf("mismatched physical evidence was accepted: err=%v ready=%v", err, c.Ready())
	}
}

func createCheckpointTestOperation(operations store.LLMCheckpointOperationStore, op *store.LLMCheckpointOperation, targetPhase string) (*store.LLMCheckpointOperation, error) {
	root := *op
	snapshotName, snapshotDigest := root.SnapshotName, root.SnapshotDigest
	root.Phase = "planned"
	root.PhaseOrdinal = checkpointRecoveryOrdinal(root.Phase)
	root.SnapshotName = ""
	root.SnapshotDigest = ""
	current, _, err := operations.CreateLLMCheckpointOperation(context.Background(), &root)
	if err != nil {
		return nil, err
	}
	path := []string{"assigned", "started", "paused", "saved", "stopped", "released"}
	if targetPhase == "restore_planned" || targetPhase == "restore_assigned" || targetPhase == "reloaded" || targetPhase == "restored" || targetPhase == "resumed" || targetPhase == "continued" || targetPhase == "reused" {
		path = append(path, "restore_planned", "restore_assigned", "reloaded", "restored", "resumed")
	}
	for _, phase := range path {
		next := *current
		next.Phase = phase
		next.PhaseOrdinal = checkpointRecoveryOrdinal(phase)
		if phase == "saved" || phase == "stopped" || phase == "released" || strings.HasPrefix(phase, "restore_") || phase == "reloaded" || phase == "restored" || phase == "resumed" {
			next.SnapshotName = snapshotName
			next.SnapshotDigest = snapshotDigest
		}
		if phase == "restore_planned" || phase == "restore_assigned" || phase == "reloaded" || phase == "restored" || phase == "resumed" {
			next.SlotID = -1
		}
		current, err = operations.UpdateLLMCheckpointOperation(context.Background(), &next, current.Revision)
		if err != nil {
			return nil, err
		}
		if phase == targetPhase {
			return current, nil
		}
	}
	return current, nil
}
