package nodeagent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/runtime"
	"vram-governor/internal/wsproto"
)

type commandCheckpointDriver struct{ actions []string }

func (d *commandCheckpointDriver) QuerySlots(context.Context) (runtime.SlotInventory, error) {
	d.actions = append(d.actions, "query")
	return runtime.SlotInventory{Slots: []runtime.SlotState{{ID: 2, ContextLimit: 4096}}}, nil
}
func (d *commandCheckpointDriver) AssignSlot(context.Context, int) (runtime.SlotAssignment, error) {
	d.actions = append(d.actions, "assign")
	return runtime.SlotAssignment{SlotID: 2, ContextLimit: 4096}, nil
}
func (d *commandCheckpointDriver) PauseAtBoundary(context.Context, int) (runtime.SlotBoundary, error) {
	d.actions = append(d.actions, "pause")
	return runtime.SlotBoundary{Prefix: []byte("prefix"), TokenCount: 3}, nil
}
func (d *commandCheckpointDriver) SaveKV(context.Context, int, string) (runtime.CheckpointResult, error) {
	d.actions = append(d.actions, "save")
	return runtime.CheckpointResult{SnapshotRef: "x.kv", SizeBytes: 4, TokensSaved: 3}, nil
}
func (d *commandCheckpointDriver) ConfirmStopped(context.Context, int) (bool, error) {
	d.actions = append(d.actions, "stop_confirm")
	return true, nil
}
func (d *commandCheckpointDriver) ReleaseSlot(context.Context, int) error {
	d.actions = append(d.actions, "release")
	return nil
}
func (d *commandCheckpointDriver) Reload(context.Context, int) error {
	d.actions = append(d.actions, "reload")
	return nil
}
func (d *commandCheckpointDriver) RestoreKV(context.Context, int, string) (runtime.RestoreResult, error) {
	d.actions = append(d.actions, "restore")
	return runtime.RestoreResult{TokensRestored: 2}, nil
}
func (d *commandCheckpointDriver) VerifyReuse(context.Context, int, int) (int, error) {
	d.actions = append(d.actions, "reuse")
	return 2, nil
}
func (d *commandCheckpointDriver) Resume(context.Context, int, string, int) (string, error) {
	d.actions = append(d.actions, "resume")
	return "real-generation", nil
}

// failingProductionProofDriver is deliberately small but implements the real
// conversation-aware contract. Each failure is one-shot, so the deferred
// cleanup path can demonstrate that a retry reaches the release seam.
type failingProductionProofDriver struct {
	failAt   string
	failed   bool
	releases int
	calls    map[string]int
}

func (d *failingProductionProofDriver) step(action string) error {
	if d.calls == nil {
		d.calls = make(map[string]int)
	}
	d.calls[action]++
	if d.failAt == action && !d.failed {
		d.failed = true
		return fmt.Errorf("injected %s failure", action)
	}
	return nil
}
func (d *failingProductionProofDriver) QuerySlots(context.Context) (runtime.SlotInventory, error) {
	if err := d.step("query"); err != nil {
		return runtime.SlotInventory{}, err
	}
	return runtime.SlotInventory{Slots: []runtime.SlotState{{ID: 0, ContextLimit: 4096}}}, nil
}
func (d *failingProductionProofDriver) AssignSlot(context.Context, int) (runtime.SlotAssignment, error) {
	err := d.step("assign")
	return runtime.SlotAssignment{SlotID: 0, ContextLimit: 4096}, err
}
func (d *failingProductionProofDriver) PauseAtBoundary(context.Context, int) (runtime.SlotBoundary, error) {
	return runtime.SlotBoundary{Prefix: []byte("prefix"), TokenCount: 3}, nil
}
func (d *failingProductionProofDriver) SaveKV(context.Context, int, string) (runtime.CheckpointResult, error) {
	if err := d.step("save"); err != nil {
		return runtime.CheckpointResult{}, err
	}
	return runtime.CheckpointResult{SnapshotRef: "proof.kv", SizeBytes: 8, Digest: "sha256:proof", TokensSaved: 3}, nil
}
func (d *failingProductionProofDriver) ConfirmStopped(context.Context, int) (bool, error) {
	if err := d.step("stop_confirm"); err != nil {
		return false, err
	}
	return true, nil
}
func (d *failingProductionProofDriver) ReleaseSlot(context.Context, int) error {
	d.releases++
	return d.step("release")
}
func (d *failingProductionProofDriver) Reload(context.Context, int) error { return d.step("reload") }
func (d *failingProductionProofDriver) RestoreKV(context.Context, int, string) (runtime.RestoreResult, error) {
	if err := d.step("restore"); err != nil {
		return runtime.RestoreResult{}, err
	}
	return runtime.RestoreResult{TokensRestored: 3}, nil
}
func (d *failingProductionProofDriver) VerifyReuse(context.Context, int, int) (int, error) {
	if err := d.step("reuse_verify"); err != nil {
		return 0, err
	}
	return 2, nil
}
func (d *failingProductionProofDriver) Resume(context.Context, int, string, int) (string, error) {
	if err := d.step("resume"); err != nil {
		return "", err
	}
	return "resume", nil
}
func (d *failingProductionProofDriver) StartCheckpointConversation(context.Context, int, string, string, int) error {
	return d.step("start")
}
func (d *failingProductionProofDriver) PauseAtBoundaryWithConversation(context.Context, int, string) (runtime.SlotBoundary, error) {
	if err := d.step("pause"); err != nil {
		return runtime.SlotBoundary{}, err
	}
	return runtime.SlotBoundary{Prefix: []byte("prefix"), TokenCount: 3}, nil
}
func (d *failingProductionProofDriver) ResumeWithConversation(context.Context, int, string, string, int) (string, error) {
	if err := d.step("resume"); err != nil {
		return "", err
	}
	return "resume", nil
}
func (d *failingProductionProofDriver) ContinueCheckpointConversation(context.Context, int, string, string, string) error {
	return d.step("continue")
}

func signedCheckpointCommand(secret, node, action, operation, key string, slot any) wsproto.CommandPayload {
	fence := int64(7)
	if operation == "op-2" {
		fence = 8
	}
	args := map[string]any{"target_kind": "llamacpp", "target_id": node + "-runtime", "accelerator_id": node + "-gpu0", "model": "model", "runtime_identity": "runtime", "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "profile_fingerprint": "profile", "context_fingerprint": "ctx:4096", "owner_id": "owner", "workload_id": "work", "generation": int64(1), "fencing_token": fence, "context_limit": int64(4096), "checkpoint_action": action, "checkpoint_operation_id": operation, "idempotency_key": key}
	if action == "save" || action == "restore" {
		args["snapshot_name"] = "owner-work.kv"
	}
	if slot != nil {
		args["slot_id"] = slot
	}
	if action == "save" || action == "restore" {
		args["snapshot_name"] = "x.kv"
	}
	if action == "reuse_verify" {
		args["saved_tokens"] = 3
	}
	if action == "resume" {
		args["partial_output_hash"] = "sha256:x"
		args["partial_output_offset"] = 6
	}
	if action == "continue" {
		args["continuation_conversation_id"] = "continuation-op"
		args["controller_stream"] = true
	}
	cmd := wsproto.CommandPayload{ID: operation + ":" + key, IdempotencyKey: key, NodeID: node, Command: "checkpoint_" + action, Args: args, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	cmd.Signature, _ = wsproto.SignCommand(cmd, []byte(secret))
	return cmd
}

func TestApplyProductionCheckpointProofIsFailClosed(t *testing.T) {
	ad := &wsproto.AdapterAdvertisement{Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}}
	if err := ApplyProductionCheckpointProof(ad, runtime.CheckpointCapabilityProof{ProbeOnly: true}); err == nil {
		t.Fatal("public proof application accepted without local authority")
	}
	if ad.Capabilities.SessionCheckpointVerified || ad.Capabilities.SupportsSessionCheckpoint {
		t.Fatal("failed proof changed advertisement")
	}
	proof := runtime.CheckpointCapabilityProof{ProofVersion: runtime.CheckpointCapabilityProofVersion, ModelAlias: "local-model", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64), Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true, BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true, ProvenAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour), NodeID: "node", TargetID: "target", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextLimit: 4096, SlotID: 0, Generation: 1, OldFence: 1, NewFence: 2, SavedTokens: 2, ReusedTokens: 1, SnapshotBytes: 1, SnapshotDigest: "sha256:snapshot", Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef", EvidenceID: "evidence", Signature: "signed", Digest: "sha256:evidence"}
	proof.Digest = CheckpointProofDigest(proof)
	if !proof.Complete() {
		t.Fatal("synthetic v2 validator fixture should satisfy structural proof checks")
	}
	if err := ApplyProductionCheckpointProof(ad, proof); err == nil {
		t.Fatal("synthetic proof minted a production capability without local authority")
	}
	if ad.Capabilities.SupportsSessionCheckpoint || ad.Capabilities.SessionCheckpointVerified || ad.CheckpointProof.Complete() {
		t.Fatalf("public compatibility API bypassed the missing local authority: capabilities=%+v proof=%+v", ad.Capabilities, ad.CheckpointProof)
	}
}

func TestCheckpointProofBindingRejectsMissingLocalAuthorityBeforeQuery(t *testing.T) {
	driver := &commandCheckpointDriver{}
	if _, err := GenerateProductionCheckpointProof(context.Background(), "node", "node-runtime", "node-gpu0", "model", "runtime", "profile", 4096, 1, 1, 2, driver, strings.Repeat("s", 32)); err == nil || !strings.Contains(err.Error(), "locally established") {
		t.Fatalf("public production proof API did not fail closed: %v", err)
	}
	if len(driver.actions) != 0 {
		t.Fatalf("missing binding was detected only after runtime side effects: %v", driver.actions)
	}
}

func TestCheckpointCommandEnvelopeRejectsCrossOwner(t *testing.T) {
	args := map[string]any{"target_kind": "llamacpp", "target_id": "node-llama", "accelerator_id": "node-llama-gpu0", "model": "m", "runtime_identity": "r", "capability_version": "v", "capability_revision": "rev", "profile_fingerprint": "p", "context_fingerprint": "c", "owner_id": "owner-a", "workload_id": "w", "generation": uint64(1), "fencing_token": uint64(2), "context_limit": 4096, "checkpoint_action": "restore", "checkpoint_operation_id": "op", "snapshot_name": "../owner-a.kv"}
	if err := wsproto.ValidateCheckpointCommandArgs("checkpoint_restore", args); err == nil {
		t.Fatal("cross-owner traversal snapshot accepted")
	}
}

func signedTestCheckpointProof(secret string) runtime.CheckpointCapabilityProof {
	proof := runtime.CheckpointCapabilityProof{
		ProofVersion: runtime.CheckpointCapabilityProofVersion, ModelAlias: "local-model", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true,
		SnapshotSave: true, BackendStopConfirmed: true, SnapshotRestore: true,
		KVReused: true, ProvenAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		NodeID: "node", TargetID: "node-runtime", ModelFingerprint: "model",
		RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextLimit: 4096,
		SlotID: 0, Generation: 3, OldFence: 7, NewFence: 8, SavedTokens: 4,
		ReusedTokens: 2, EvidenceID: "evidence", SnapshotDigest: "sha256:snapshot",
		SnapshotBytes: 128, AcceleratorID: "node-gpu0", Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef",
	}
	proof.Digest = CheckpointProofDigest(proof)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	proof.Signature = hex.EncodeToString(mac.Sum(nil))
	return proof
}

func TestPublicCheckpointProofReissuanceFailsBeforeFilesystemWrites(t *testing.T) {
	secret := strings.Repeat("u", 32)
	proof := signedTestCheckpointProof(secret)
	root := t.TempDir()
	statePath := filepath.Join(root, "not-created", "proof-issuance.json")
	if _, err := RotateCheckpointProofNonceDurable(statePath, proof, secret); err == nil || !strings.Contains(err.Error(), "locally authorized") {
		t.Fatalf("public durable issuance accepted caller-supplied proof: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(statePath)); !os.IsNotExist(err) {
		t.Fatalf("public durable issuance performed filesystem work before authority: stat err=%v", err)
	}
	if _, err := RotateCheckpointProofNonce(proof, secret); err == nil {
		t.Fatal("nondurable public issuance accepted caller-supplied proof")
	}
}

func TestDurableCheckpointProofIssuanceSurvivesRestartAndRejectsRollback(t *testing.T) {
	secret := strings.Repeat("s", 32)
	path := filepath.Join(t.TempDir(), "proof-issuance.json")
	base := signedTestCheckpointProof(secret)

	first, err := rotateCheckpointProofNonceDurable(path, base, nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rotateCheckpointProofNonceDurable(path, first, nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	firstEpoch, firstOK := parseCheckpointProofIssuance(first.Nonce)
	secondEpoch, secondOK := parseCheckpointProofIssuance(second.Nonce)
	if !firstOK || !secondOK || secondEpoch <= firstEpoch || first.Nonce == second.Nonce {
		t.Fatalf("durable issuance did not advance: first=%q second=%q", first.Nonce, second.Nonce)
	}

	// A fresh process has no in-memory counter, but the same sidecar must
	// continue from its persisted epoch.
	restarted, err := rotateCheckpointProofNonceDurable(path, second, nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	restartedEpoch, ok := parseCheckpointProofIssuance(restarted.Nonce)
	if !ok || restartedEpoch <= secondEpoch {
		t.Fatalf("restart issuance rolled back: previous=%d restarted=%d", secondEpoch, restartedEpoch)
	}

	rollback := restarted
	rollback.ModelFingerprint = "changed-runtime-model"
	rollback.Digest = CheckpointProofDigest(rollback)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(rollback.Digest))
	rollback.Signature = hex.EncodeToString(mac.Sum(nil))
	if _, err := rotateCheckpointProofNonceDurable(path, rollback, nil, secret); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("immutable exercise rollback accepted: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("issuance sidecar is not private: %o", info.Mode().Perm())
	}
}

func TestDurableCheckpointProofEpochSurvivesWallClockRollback(t *testing.T) {
	secret := strings.Repeat("w", 32)
	path := filepath.Join(t.TempDir(), "proof-issuance.json")
	base := signedTestCheckpointProof(secret)
	first, err := rotateCheckpointProofNonceDurable(path, base, nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	firstEpoch, ok := parseCheckpointProofIssuance(first.Nonce)
	if !ok {
		t.Fatalf("first proof has no durable epoch: %q", first.Nonce)
	}
	priorClock := checkpointProofClock
	checkpointProofClock = func() time.Time { return time.Unix(1, 0).UTC() }
	t.Cleanup(func() { checkpointProofClock = priorClock })
	second, err := rotateCheckpointProofNonceDurable(path, first, nil, secret)
	if err != nil {
		t.Fatalf("clock rollback prevented durable epoch advance: %v", err)
	}
	secondEpoch, ok := parseCheckpointProofIssuance(second.Nonce)
	if !ok || secondEpoch <= firstEpoch {
		t.Fatalf("wall-clock rollback reset issuance epoch: first=%q second=%q", first.Nonce, second.Nonce)
	}
	if second.Nonce[:20] >= first.Nonce[:20] {
		t.Fatalf("clock test did not produce a rolled-back timestamp: first=%q second=%q", first.Nonce, second.Nonce)
	}
	state, err := loadCheckpointProofIssuanceState(path)
	if err != nil || state.Epoch != secondEpoch {
		t.Fatalf("durable epoch did not follow monotonic state: state=%+v err=%v", state, err)
	}
}

func TestCheckpointIssuanceLockNeverStealsOldMtimeLock(t *testing.T) {
	secret := strings.Repeat("l", 32)
	root := t.TempDir()
	statePath := filepath.Join(root, "proof-issuance.json")
	lockPath := statePath + ".lock"
	lockBytes := []byte("original lock owner")
	if err := os.WriteFile(lockPath, lockBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	priorTimeout := checkpointIssuanceLockTimeout
	checkpointIssuanceLockTimeout = 40 * time.Millisecond
	t.Cleanup(func() { checkpointIssuanceLockTimeout = priorTimeout })
	if _, err := rotateCheckpointProofNonceDurable(statePath, signedTestCheckpointProof(secret), nil, secret); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("old-mtime lock did not fail closed: %v", err)
	}
	if body, err := os.ReadFile(lockPath); err != nil || !bytes.Equal(body, lockBytes) {
		t.Fatalf("old-mtime owner lock was removed or replaced: body=%q err=%v", body, err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("contended lock mutated issuance sidecar: stat err=%v", err)
	}
}

func TestCheckpointIssuanceStateRejectsCorruptV2ReplayMaps(t *testing.T) {
	issuedAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	validDigest := "sha256:" + strings.Repeat("a", 64)
	base := checkpointProofIssuanceState{
		Version: checkpointProofIssuanceStateVersion, Epoch: 4,
		HighWater: map[string]uint64{"node|target": 4}, Bindings: map[string]string{"node|target": validDigest},
		Generations: map[string]uint64{"node|target": 3}, Fences: map[string]uint64{"node|target": 8},
		Exercises: map[string]string{"node|target": validDigest}, IssuedAt: map[string]time.Time{"node|target": issuedAt},
	}
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	mutants := map[string]string{
		"duplicate top-level key":   strings.Replace(body, `"version":"`+checkpointProofIssuanceStateVersion+`",`, `"version":"`+checkpointProofIssuanceStateVersion+`","version":"`+checkpointProofIssuanceStateVersion+`",`, 1),
		"duplicate counter key":     strings.Replace(body, `"high_water":{"node|target":4}`, `"high_water":{"node|target":4,"node|target":4}`, 1),
		"null high-water":           strings.Replace(body, `"high_water":{"node|target":4}`, `"high_water":null`, 1),
		"null binding map":          strings.Replace(body, `"bindings":{"node|target":"`+validDigest+`"}`, `"bindings":null`, 1),
		"null generation map":       strings.Replace(body, `"generations":{"node|target":3}`, `"generations":null`, 1),
		"missing exercise map":      strings.Replace(body, `,"exercises":{"node|target":"`+validDigest+`"}`, "", 1),
		"missing_target_generation": strings.Replace(body, `"generations":{"node|target":3}`, `"generations":{}`, 1),
		"missing_target_fence":      strings.Replace(body, `"fences":{"node|target":8}`, `"fences":{}`, 1),
		"missing_target_exercise":   strings.Replace(body, `"exercises":{"node|target":"`+validDigest+`"}`, `"exercises":{}`, 1),
		"missing_target_issued_at":  strings.Replace(body, `"issued_at":{"node|target":"2026-01-02T03:04:05Z"}`, `"issued_at":{}`, 1),
		"extra_unbound_target":      strings.Replace(body, `"generations":{"node|target":3}`, `"generations":{"node|target":3,"orphan|target":1}`, 1),
		"alternate-case field":      strings.Replace(body, `"high_water"`, `"High_water"`, 1),
		"unknown field":             strings.Replace(body, `"version":"`+checkpointProofIssuanceStateVersion+`",`, `"version":"`+checkpointProofIssuanceStateVersion+`","unknown":0,`, 1),
		"trailing value":            body + `{}`,
	}
	for name, mutant := range mutants {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "issuance.json")
			if err := os.WriteFile(path, []byte(mutant), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadCheckpointProofIssuanceState(path); err == nil {
				t.Fatalf("corrupt version-two issuance state was accepted: %s", mutant)
			}
		})
	}
}

func TestCheckpointIssuanceStatePreservesLegacyV1WithoutOptionalMaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-issuance.json")
	legacyBinding := "sha256:" + strings.Repeat("a", 64)
	body := `{"version":"llm-checkpoint-proof-issuance-v1","epoch":4,"high_water":{"node|target":4},"bindings":{"node|target":"` + legacyBinding + `"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := loadCheckpointProofIssuanceState(path)
	if err != nil {
		t.Fatalf("valid legacy v1 sidecar without additive maps was rejected: %v", err)
	}
	if state.Version != checkpointProofIssuanceStateLegacyVersion || state.Epoch != 4 || state.HighWater["node|target"] != 4 || state.Bindings["node|target"] != legacyBinding || state.Generations == nil || state.Fences == nil || state.Exercises == nil || state.IssuedAt == nil {
		t.Fatalf("legacy sidecar was not preserved with initialized additive maps: %+v", state)
	}
}

func TestDurableCheckpointProofRebindRollbacksLeaveSidecarUnchanged(t *testing.T) {
	secret := strings.Repeat("q", 32)
	path := filepath.Join(t.TempDir(), "proof-issuance.json")
	prior, err := rotateCheckpointProofNonceDurable(path, signedTestCheckpointProof(secret), nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	makeFresh := func() runtime.CheckpointCapabilityProof {
		fresh := prior
		fresh.OldFence, fresh.NewFence = prior.NewFence, prior.NewFence+1
		fresh.EvidenceID = "fresh-rebind-exercise"
		fresh.SnapshotDigest = "sha256:fresh-rebind-snapshot"
		fresh.Nonce = "00000000000000000002-e00000000000000000002-0123456789abcdef0123456789abcdef"
		fresh.ProvenAt = time.Now().UTC()
		fresh.ExpiresAt = fresh.ProvenAt.Add(time.Hour)
		return signNodeTestCheckpointProof(secret, fresh)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*runtime.CheckpointCapabilityProof)
		want   string
	}{
		{name: "generation_rollback", mutate: func(proof *runtime.CheckpointCapabilityProof) { proof.Generation-- }, want: "generation"},
		{name: "fence_rollback", mutate: func(proof *runtime.CheckpointCapabilityProof) {
			proof.OldFence, proof.NewFence = prior.NewFence-1, prior.NewFence
		}, want: "fence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := makeFresh()
			tc.mutate(&candidate)
			candidate = signNodeTestCheckpointProof(secret, candidate)
			if _, err := rebindCheckpointProofNonceDurable(path, prior, candidate, secret); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rollback candidate was not rejected for %s: %v", tc.want, err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, baseline) {
				t.Fatalf("rejected %s rotation mutated durable sidecar: err=%v", tc.want, err)
			}
		})
	}
	t.Run("valid_fresh_rebind", func(t *testing.T) {
		issued, err := rebindCheckpointProofNonceDurable(path, prior, makeFresh(), secret)
		if err != nil {
			t.Fatalf("valid fresh rebind was rejected: %v", err)
		}
		state, err := loadCheckpointProofIssuanceState(path)
		if err != nil || !issued.Complete() || state.Epoch != 2 || state.Generations[prior.NodeID+"|"+prior.TargetID] != prior.Generation {
			t.Fatalf("valid fresh rebind did not commit coherent counters: proof=%+v state=%+v err=%v", issued, state, err)
		}
	})
}

func TestCheckpointProofSidecarCommitBeforeProofWriteRetainsEpoch(t *testing.T) {
	secret := strings.Repeat("c", 32)
	root := t.TempDir()
	statePath := filepath.Join(root, "proof-issuance.json")
	proofPath := filepath.Join(root, "proof.json")
	if err := os.Mkdir(proofPath, 0o700); err != nil {
		t.Fatal(err)
	}
	base := signedTestCheckpointProof(secret)
	issued, err := rotateCheckpointProofNonceDurable(statePath, base, nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistSignedCheckpointProof(proofPath, issued); err == nil {
		t.Fatal("proof write fault fixture unexpectedly persisted over a directory")
	}
	stateAfterCommit, err := loadCheckpointProofIssuanceState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	firstEpoch := stateAfterCommit.Epoch
	// A restart sees the durable sidecar even though the proof rename did not
	// complete. Reissuing the same immutable exercise advances, never resets,
	// the epoch and leaves its fence/generation/exercise highwaters intact.
	retried, err := rotateCheckpointProofNonceDurable(statePath, base, nil, secret)
	if err != nil {
		t.Fatalf("restart could not recover after the proof-write boundary: %v", err)
	}
	retriedEpoch, ok := parseCheckpointProofIssuance(retried.Nonce)
	if !ok || retriedEpoch <= firstEpoch {
		t.Fatalf("proof-write crash reset issuance epoch: before=%d retried=%q", firstEpoch, retried.Nonce)
	}
	stateAfterRetry, err := loadCheckpointProofIssuanceState(statePath)
	if err != nil || stateAfterRetry.Fences[base.NodeID+"|"+base.TargetID] != base.NewFence || stateAfterRetry.Generations[base.NodeID+"|"+base.TargetID] != base.Generation || stateAfterRetry.Exercises[base.NodeID+"|"+base.TargetID] == "" {
		t.Fatalf("proof-write recovery lost exercise highwaters: state=%+v err=%v", stateAfterRetry, err)
	}
}

func TestDurableCheckpointProofRebindRequiresPriorCASAndAdvancedFence(t *testing.T) {
	secret := strings.Repeat("b", 32)
	path := filepath.Join(t.TempDir(), "proof-issuance.json")
	prior := signedTestCheckpointProof(secret)
	issuedPrior, err := rotateCheckpointProofNonceDurable(path, prior, nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	fresh := prior
	fresh.ModelFingerprint = "model-after-profile-switch"
	fresh.OldFence, fresh.NewFence = issuedPrior.NewFence, issuedPrior.NewFence+1
	fresh.Generation = issuedPrior.Generation + 1
	fresh.EvidenceID = "fresh-live-exercise"
	fresh.SnapshotDigest = "sha256:fresh-snapshot"
	fresh.Nonce = "fresh-live-nonce"
	fresh.ProvenAt = time.Now().UTC()
	fresh.ExpiresAt = fresh.ProvenAt.Add(time.Hour)
	fresh = signNodeTestCheckpointProof(secret, fresh)
	issuedFresh, err := rebindCheckpointProofNonceDurable(path, issuedPrior, fresh, secret)
	if err != nil {
		t.Fatalf("valid fresh rebind was rejected: %v", err)
	}

	state, err := loadCheckpointProofIssuanceState(path)
	if err != nil {
		t.Fatal(err)
	}
	key := issuedFresh.NodeID + "|" + issuedFresh.TargetID
	epochBeforeRejected := state.Epoch
	nonadvanced := fresh
	nonadvanced.OldFence, nonadvanced.NewFence = issuedFresh.NewFence-1, issuedFresh.NewFence
	nonadvanced.EvidenceID = "different-exercise-with-reused-fence"
	nonadvanced.Nonce = "nonadvanced-live-nonce"
	nonadvanced = signNodeTestCheckpointProof(secret, nonadvanced)
	if _, err := rebindCheckpointProofNonceDurable(path, issuedFresh, nonadvanced, secret); err == nil || !strings.Contains(err.Error(), "fence") {
		t.Fatalf("nonadvanced rebind fence was accepted: %v", err)
	}

	wrongPrior := issuedPrior
	wrongPrior.ModelFingerprint = "unrelated-prior-binding"
	wrongPrior = signNodeTestCheckpointProof(secret, wrongPrior)
	unrelated := fresh
	unrelated.ModelFingerprint = "another-current-binding"
	unrelated.OldFence, unrelated.NewFence = issuedFresh.NewFence, issuedFresh.NewFence+1
	unrelated.EvidenceID = "another-fresh-exercise"
	unrelated.Nonce = "another-live-nonce"
	unrelated = signNodeTestCheckpointProof(secret, unrelated)
	if _, err := rebindCheckpointProofNonceDurable(path, wrongPrior, unrelated, secret); err == nil || !strings.Contains(err.Error(), "expected-prior") {
		t.Fatalf("rebind with a mismatched expected prior binding was accepted: %v", err)
	}
	regressedGeneration := fresh
	regressedGeneration.OldFence, regressedGeneration.NewFence = issuedFresh.NewFence, issuedFresh.NewFence+1
	regressedGeneration.Generation = issuedFresh.Generation - 1
	regressedGeneration.EvidenceID = "generation-regressed-exercise"
	regressedGeneration.Nonce = "generation-regressed-nonce"
	regressedGeneration = signNodeTestCheckpointProof(secret, regressedGeneration)
	if _, err := rebindCheckpointProofNonceDurable(path, issuedFresh, regressedGeneration, secret); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("generation-regressed rebind was accepted: %v", err)
	}
	unsignedPrior := issuedFresh
	unsignedPrior.Signature = "not-a-signature"
	unsignedCandidate := fresh
	unsignedCandidate.OldFence, unsignedCandidate.NewFence = issuedFresh.NewFence, issuedFresh.NewFence+2
	unsignedCandidate.Generation = issuedFresh.Generation + 1
	unsignedCandidate.EvidenceID = "unsigned-prior-attempt"
	unsignedCandidate.Nonce = "unsigned-prior-nonce"
	unsignedCandidate = signNodeTestCheckpointProof(secret, unsignedCandidate)
	if _, err := rebindCheckpointProofNonceDurable(path, unsignedPrior, unsignedCandidate, secret); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("rebind with an unsigned prior token was accepted: %v", err)
	}
	state, err = loadCheckpointProofIssuanceState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.Epoch != epochBeforeRejected || state.Fences[key] != issuedFresh.NewFence || state.Bindings[key] != checkpointProofBindingDigest(issuedFresh) {
		t.Fatalf("rejected rebind changed durable highwaters: %+v", state)
	}
}

func TestDurableCheckpointProofIssuanceAcceptsFreshExerciseAfterExpiry(t *testing.T) {
	secret := strings.Repeat("x", 32)
	root := t.TempDir()
	path := filepath.Join(root, "proof-issuance.json")
	oldTTL := productionCheckpointProofTTL
	productionCheckpointProofTTL = 40 * time.Millisecond
	defer func() { productionCheckpointProofTTL = oldTTL }()
	_, server := newFaithfulCheckpointServer(t, root)
	defer server.Close()
	cfg := &Config{
		NodeID: "node-expiry", CommandSigningSecret: secret,
		CommandStatePath: filepath.Join(root, "commands.json"),
		Checkpoint:       CheckpointConfig{Enabled: true, ProofExerciseEnabled: true, Root: root, IssuanceStatePath: path, MaxBytes: 1 << 20, MaxFiles: 8, PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 8, MaxMetadataBytes: 1 << 20, MaxOutputBytes: 1 << 20, ExpirySeconds: 3600, CleanupIntervalSeconds: 60, ProofPath: filepath.Join(root, "proof.json")},
	}
	cfg.CommandRecoveryGeneration = 11
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, AcceleratorIndex: 0, ContextLimit: 4096, Slots: 1}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	advertisement, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	targetID := cfg.NodeID + "-" + advertisement.ID
	profile := advertisement.ActiveRuntimeProfile
	if profile == "" {
		profile = "default"
	}
	generation := advertisement.CapabilityGeneration
	if generation == 0 {
		generation = cfg.CommandRecoveryGeneration
	}
	processor := newCommandProcessor(cfg, log, true)
	driver := newManagedCheckpointDriver(processor, cfg, cfg.LlamaCPP.Servers[0], targetID, advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, generation)
	managedDriver := driver.(*managedCheckpointDriver)
	first, err := exerciseCheckpointEvidence(context.Background(), cfg.NodeID, targetID, "node-expiry-gpu0", advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, generation, 1, 2, driver, secret)
	if err != nil {
		t.Fatalf("first real production exercise failed: %v", err)
	}
	first = syntheticSignedV2ValidatorFixture(secret, first)
	issuedFirst, err := rotateCheckpointProofNonceDurable(path, first, nil, secret)
	if err != nil {
		t.Fatalf("first durable rotation failed: %v", err)
	}
	if err := PersistSignedCheckpointProof(checkpointProofPath(cfg.Checkpoint.ProofPath, targetID), issuedFirst); err != nil {
		t.Fatal(err)
	}
	firstEpoch, ok := parseCheckpointProofIssuance(issuedFirst.Nonce)
	if !ok {
		t.Fatal("first durable issuance omitted epoch")
	}
	time.Sleep(60 * time.Millisecond)
	if !time.Now().UTC().After(first.ExpiresAt) {
		t.Fatalf("test proof did not expire: expires=%s", first.ExpiresAt)
	}

	// Rebuild the processor without clearing its durable phase journal.  The
	// next managed driver must select a fresh operation and fence from the
	// retained terminal rows before exercising the runtime again.
	restarted := newCommandProcessor(cfg, log, true)
	if len(restarted.checkpointPhases) == 0 {
		t.Fatal("restart did not retain the first proof phase journal")
	}
	driver2 := newManagedCheckpointDriver(restarted, cfg, cfg.LlamaCPP.Servers[0], targetID, advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, generation)
	managedDriver2, ok := driver2.(*managedCheckpointDriver)
	if !ok || managedDriver2 == nil || managedDriver2.CheckpointFence() <= managedDriver.CheckpointFence() {
		t.Fatalf("restart did not advance proof fence: first=%d second=%v", managedDriver.CheckpointFence(), driver2)
	}
	second, err := exerciseCheckpointEvidence(context.Background(), cfg.NodeID, targetID, "node-expiry-gpu0", advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, generation, managedDriver2.CheckpointFence()-1, managedDriver2.CheckpointFence(), driver2, secret)
	if err != nil {
		t.Fatalf("second real production exercise after expiry failed: %v", err)
	}
	second = syntheticSignedV2ValidatorFixture(secret, second)
	issuedSecond, err := rotateCheckpointProofNonceDurable(path, second, nil, secret)
	if err != nil {
		t.Fatalf("fresh exercise after expiry was rejected: %v", err)
	}
	secondEpoch, ok := parseCheckpointProofIssuance(issuedSecond.Nonce)
	if !ok || secondEpoch <= firstEpoch || issuedSecond.Nonce == issuedFirst.Nonce || issuedSecond.EvidenceID == issuedFirst.EvidenceID || issuedSecond.NewFence <= issuedFirst.NewFence {
		t.Fatalf("fresh durable issuance was not distinct and monotonic: first=%+v second=%+v", issuedFirst, issuedSecond)
	}

	// Generate a separately signed, complete proof with a different stable
	// runtime identity.  No proof field is edited after signing; durable
	// rotation must reject the real mismatched exercise against the retained
	// binding.
	driver3 := newManagedCheckpointDriver(restarted, cfg, cfg.LlamaCPP.Servers[0], targetID, advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, generation)
	managedDriver3, ok := driver3.(*managedCheckpointDriver)
	if !ok || managedDriver3 == nil {
		t.Fatal("third managed proof driver was not constructed")
	}
	mismatch, err := exerciseCheckpointEvidence(context.Background(), cfg.NodeID, targetID, "node-expiry-gpu0", advertisement.ModelFingerprint, "different-runtime", profile, advertisement.ContextLimit, generation, managedDriver3.CheckpointFence()-1, managedDriver3.CheckpointFence(), driver3, secret)
	if err != nil {
		t.Fatalf("mismatch exercise did not complete as a real proof: %v", err)
	}
	mismatch = syntheticSignedV2ValidatorFixture(secret, mismatch)
	if _, err := rotateCheckpointProofNonceDurable(path, mismatch, nil, secret); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("real mismatched exercise was accepted: %v", err)
	}
}

func TestDurableCheckpointProofIssuanceSerializesConcurrentRefreshes(t *testing.T) {
	secret := strings.Repeat("c", 32)
	path := filepath.Join(t.TempDir(), "proof-issuance.json")
	base := signedTestCheckpointProof(secret)
	const refreshes = 12
	type outcome struct {
		epoch uint64
		err   error
	}
	out := make(chan outcome, refreshes)
	var wg sync.WaitGroup
	for i := 0; i < refreshes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proof, err := rotateCheckpointProofNonceDurable(path, base, nil, secret)
			epoch, _ := parseCheckpointProofIssuance(proof.Nonce)
			out <- outcome{epoch: epoch, err: err}
		}()
	}
	wg.Wait()
	close(out)
	seen := make(map[uint64]struct{}, refreshes)
	for result := range out {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.epoch == 0 {
			t.Fatal("concurrent refresh omitted durable epoch")
		}
		if _, exists := seen[result.epoch]; exists {
			t.Fatalf("concurrent refresh reused epoch %d", result.epoch)
		}
		seen[result.epoch] = struct{}{}
	}
	if len(seen) != refreshes {
		t.Fatalf("got %d unique issuance epochs, want %d", len(seen), refreshes)
	}
	state, err := loadCheckpointProofIssuanceState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.Epoch != refreshes {
		t.Fatalf("persisted issuance epoch=%d want %d", state.Epoch, refreshes)
	}
}

func signNodeTestCheckpointProof(secret string, proof runtime.CheckpointCapabilityProof) runtime.CheckpointCapabilityProof {
	// These are synthetic validator fixtures only; this helper does not observe
	// or establish local launch-plan/unit authority.
	if proof.ProofVersion == "" {
		proof.ProofVersion = runtime.CheckpointCapabilityProofVersion
	}
	if proof.ModelAlias == "" {
		proof.ModelAlias = "synthetic-model-alias"
	}
	if proof.LocalCheckpointBinding == "" {
		proof.LocalCheckpointBinding = "sha256:" + strings.Repeat("a", 64)
	}
	if _, ok := runtime.CheckpointProofIssuanceEpoch(proof.Nonce); !ok {
		sum := sha256.Sum256([]byte(proof.Nonce))
		proof.Nonce = fmt.Sprintf("%020d-e%020d-%x", uint64(1), uint64(1), sum[:16])
	}
	proof.Digest = CheckpointProofDigest(proof)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	proof.Signature = hex.EncodeToString(mac.Sum(nil))
	return proof
}

func syntheticSignedV2ValidatorFixture(secret string, proof runtime.CheckpointCapabilityProof) runtime.CheckpointCapabilityProof {
	// Synthetic signed proof data exercises validators and durable journals; it
	// is not evidence that this process has a production checkpoint binding.
	proof.Verified = true
	proof.ProofVersion = runtime.CheckpointCapabilityProofVersion
	proof.ModelAlias = "synthetic-model-alias"
	proof.LocalCheckpointBinding = "sha256:" + strings.Repeat("a", 64)
	if proof.ProvenAt.IsZero() {
		proof.ProvenAt = time.Now().UTC()
	}
	if proof.ExpiresAt.IsZero() || !time.Now().Before(proof.ExpiresAt) {
		proof.ExpiresAt = time.Now().UTC().Add(time.Hour)
	}
	if proof.Nonce == "" {
		proof.Nonce = "synthetic-nonce"
	}
	return signNodeTestCheckpointProof(secret, proof)
}

func signedLegacyPriorFixture(secret string) (runtime.CheckpointCapabilityProof, []byte) {
	proof := signedTestCheckpointProof(secret)
	proof.ProofVersion, proof.ModelAlias, proof.LocalCheckpointBinding = "", "", ""
	proof.Nonce = "legacy-unstructured-nonce"
	proof.Digest = legacyCheckpointProofDigest(proof)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	proof.Signature = hex.EncodeToString(mac.Sum(nil))
	encoded, _ := json.Marshal(proof)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &fields)
	delete(fields, "proof_version")
	delete(fields, "model_alias")
	delete(fields, "local_checkpoint_binding")
	if proof.Reason == "" {
		delete(fields, "reason")
	}
	encoded, _ = json.Marshal(fields)
	return proof, encoded
}

func TestCheckpointProofV1MigrationRequiresAuthenticatedPriorCASAndFreshV2Exercise(t *testing.T) {
	secret := strings.Repeat("m", 32)
	root := t.TempDir()
	statePath := filepath.Join(root, "proof-issuance.json")
	prior, legacyProofBytes := signedLegacyPriorFixture(secret)
	proofPath := filepath.Join(root, "proof.json")
	if err := os.WriteFile(proofPath, legacyProofBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	loadedPrior, err := loadSignedCheckpointProofForRebind(proofPath, secret)
	if err != nil || loadedPrior.ProofVersion != "" || loadedPrior.Digest != prior.Digest {
		t.Fatalf("authenticated legacy proof did not decode as prior-only: proof=%+v err=%v", loadedPrior, err)
	}
	if _, err := LoadSignedCheckpointProof(proofPath, secret); err == nil {
		t.Fatal("authenticated legacy prior decoded as an advertisable capability")
	}
	key := prior.NodeID + "|" + prior.TargetID
	other := "other-node|other-target"
	otherBinding := "sha256:" + strings.Repeat("b", 64)
	otherExercise := "sha256:" + strings.Repeat("c", 64)
	legacyExercise := "sha256:" + strings.Repeat("d", 64)
	oldIssued := time.Unix(1700000000, 0).UTC()
	legacyState := checkpointProofIssuanceState{
		Version: checkpointProofIssuanceStateLegacyVersion, Epoch: 5,
		HighWater:   map[string]uint64{key: 5, other: 3},
		Bindings:    map[string]string{key: legacyCheckpointProofBindingDigest(prior), other: otherBinding},
		Generations: map[string]uint64{key: prior.Generation, other: 2},
		Fences:      map[string]uint64{key: prior.NewFence, other: 4},
		Exercises:   map[string]string{key: legacyExercise, other: otherExercise},
		IssuedAt:    map[string]time.Time{key: oldIssued, other: oldIssued},
	}
	stateBytes, err := json.Marshal(legacyState)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, stateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := syntheticSignedV2ValidatorFixture(secret, signedTestCheckpointProof(secret))
	fresh.OldFence, fresh.NewFence = prior.NewFence, prior.NewFence+1
	fresh.Generation = prior.Generation
	fresh.EvidenceID = "newly-exercised-v2-evidence"
	fresh.SnapshotDigest = "sha256:fresh-migration-exercise"
	fresh = signNodeTestCheckpointProof(secret, fresh)
	issued, err := rebindCheckpointProofNonceDurable(statePath, loadedPrior, fresh, secret)
	if err != nil {
		t.Fatalf("fresh authenticated migration failed: %v", err)
	}
	if !issued.Complete() || issued.ProofVersion != runtime.CheckpointCapabilityProofVersion {
		t.Fatalf("migration did not issue a complete v2 proof: %+v", issued)
	}
	state, err := loadCheckpointProofIssuanceState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != checkpointProofIssuanceStateVersion || state.Epoch != 6 || state.HighWater[key] != 6 || state.HighWater[other] != 3 || state.Generations[other] != 2 || state.Fences[other] != 4 || state.Exercises[other] != otherExercise || !state.IssuedAt[other].Equal(oldIssued) {
		t.Fatalf("migration reset or lost durable prior state: %+v", state)
	}
	stale := loadedPrior
	stale.ModelFingerprint = "stale-prior"
	stale.Digest = legacyCheckpointProofDigest(stale)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(stale.Digest))
	stale.Signature = hex.EncodeToString(mac.Sum(nil))
	if _, err := rebindCheckpointProofNonceDurable(statePath, stale, fresh, secret); err == nil || !strings.Contains(err.Error(), "prior") {
		t.Fatalf("stale authenticated expected-prior binding was accepted: %v", err)
	}

	missingSidecar := filepath.Join(root, "missing-sidecar.json")
	if _, err := rebindCheckpointProofNonceDurable(missingSidecar, loadedPrior, fresh, secret); err == nil || !strings.Contains(err.Error(), "sidecar is missing") {
		t.Fatalf("authenticated legacy proof migrated without existing prior state: %v", err)
	}
	if _, err := os.Stat(missingSidecar); !os.IsNotExist(err) {
		t.Fatalf("missing sidecar migration created a reset state: %v", err)
	}
}

func TestCheckpointProofV1MigrationRejectsUnmigratableOtherTarget(t *testing.T) {
	t.Run("other_target_missing_safety_counters", func(t *testing.T) {
		secret := strings.Repeat("u", 32)
		root := t.TempDir()
		prior, _ := signedLegacyPriorFixture(secret)
		statePath := filepath.Join(root, "proof-issuance.json")
		currentKey := prior.NodeID + "|" + prior.TargetID
		otherKey := "other-node|other-target"
		currentExercise := "sha256:" + strings.Repeat("e", 64)
		legacyState := checkpointProofIssuanceState{
			Version: checkpointProofIssuanceStateLegacyVersion, Epoch: 5,
			HighWater: map[string]uint64{currentKey: 5, otherKey: 3},
			Bindings: map[string]string{
				currentKey: legacyCheckpointProofBindingDigest(prior),
				otherKey:   "sha256:" + strings.Repeat("b", 64),
			},
			Generations: map[string]uint64{currentKey: prior.Generation},
			Fences:      map[string]uint64{currentKey: prior.NewFence},
			Exercises:   map[string]string{currentKey: currentExercise},
			IssuedAt:    map[string]time.Time{currentKey: prior.ProvenAt},
		}
		body, err := json.Marshal(legacyState)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		fresh := syntheticSignedV2ValidatorFixture(secret, signedTestCheckpointProof(secret))
		fresh.OldFence, fresh.NewFence = prior.NewFence, prior.NewFence+1
		fresh.Generation = prior.Generation
		fresh.EvidenceID = "fresh-current-target-only"
		fresh.SnapshotDigest = "sha256:fresh-current-target-only"
		fresh = signNodeTestCheckpointProof(secret, fresh)
		if _, err := rebindCheckpointProofNonceDurable(statePath, prior, fresh, secret); err == nil || !strings.Contains(err.Error(), "unrelated target") {
			t.Fatalf("migration accepted a sidecar that cannot preserve another target's safety counters: %v", err)
		}
		after, err := os.ReadFile(statePath)
		if err != nil || !bytes.Equal(after, body) {
			t.Fatalf("rejected multi-target migration mutated version-one sidecar: err=%v", err)
		}
	})
}

// faithfulCheckpointServer implements the small, documented llama-server
// surface used by the production endpoint driver. It keeps the initial stream
// open until the node sends DELETE /v1/stream, writes an actual KV file on
// save, and emits cached-token usage only from the resumed continuation.
// This deliberately exercises the managed command path instead of replacing
// the runtime with a boolean-producing test double.
type faithfulCheckpointServer struct {
	root string
	mu   sync.Mutex

	processing   bool
	modelID      string
	contextLimit int
	streams      map[string]chan struct{}

	completionRequests int
	saveRequests       int
	restoreRequests    int
	deleteRequests     int
}

func newFaithfulCheckpointServer(t *testing.T, root string) (*faithfulCheckpointServer, *httptest.Server) {
	t.Helper()
	state := &faithfulCheckpointServer{root: root, streams: make(map[string]chan struct{})}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.handle(t, w, r)
	}))
	return state, server
}

func (s *faithfulCheckpointServer) handle(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		s.mu.Lock()
		modelID := s.modelID
		s.mu.Unlock()
		if modelID == "" {
			modelID = "model"
		}
		body, _ := json.Marshal(map[string]any{"data": []map[string]string{{"id": modelID, "status": "loaded"}}})
		writeCheckpointJSON(w, string(body))
	case r.Method == http.MethodGet && r.URL.Path == "/api/ps":
		writeCheckpointJSON(w, `{"models":[]}`)
	case r.Method == http.MethodGet && r.URL.Path == "/slots":
		s.mu.Lock()
		processing := s.processing
		contextLimit := s.contextLimit
		s.mu.Unlock()
		if contextLimit == 0 {
			contextLimit = 4096
		}
		body, _ := json.Marshal([]map[string]any{{"id": 0, "n_ctx": contextLimit, "is_processing": processing, "n_prompt_tokens": 3, "n_prompt_tokens_cached": 2}})
		writeCheckpointJSON(w, string(body))
	case r.Method == http.MethodGet && r.URL.Path == "/v1/stream":
		// The endpoint driver normally observes usage on the resumed POST
		// stream. Keep the history endpoint truthful for implementations that
		// need to recover a remote-only conversation binding.
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"faithful-prefix\"}}],\"usage\":{\"prompt_tokens_cached\":2}}\n\ndata: [DONE]\n\n")
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/stream":
		conversationID := r.URL.Query().Get("conv_id")
		s.mu.Lock()
		s.deleteRequests++
		stop := s.streams[conversationID]
		delete(s.streams, conversationID)
		s.processing = false
		s.mu.Unlock()
		if stop != nil {
			close(stop)
		}
		writeCheckpointJSON(w, `{}`)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		s.handleCheckpointCompletion(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/slots/"):
		s.handleCheckpointSlot(t, w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *faithfulCheckpointServer) handleCheckpointCompletion(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Continue bool `json:"continue_final_message"`
	}
	_ = json.NewDecoder(r.Body).Decode(&request)
	conversationID := r.Header.Get("X-Conversation-Id")
	if conversationID == "" {
		http.Error(w, "conversation id required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	s.mu.Lock()
	s.completionRequests++
	s.processing = true
	if !request.Continue {
		stop := make(chan struct{})
		s.streams[conversationID] = stop
		s.mu.Unlock()
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"faithful-prefix\"}}]}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case <-stop:
		case <-r.Context().Done():
		}
		s.mu.Lock()
		s.processing = false
		delete(s.streams, conversationID)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"continued\"}}],\"usage\":{\"prompt_tokens_cached\":2}}\n\ndata: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
	s.mu.Lock()
	s.processing = false
	s.mu.Unlock()
}

func (s *faithfulCheckpointServer) handleCheckpointSlot(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	var slotRequest struct {
		Filename string `json:"filename"`
	}
	_ = json.NewDecoder(r.Body).Decode(&slotRequest)
	switch r.URL.Query().Get("action") {
	case "save":
		s.mu.Lock()
		s.saveRequests++
		s.mu.Unlock()
		if slotRequest.Filename == "" {
			http.Error(w, "filename required", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(filepath.Join(s.root, slotRequest.Filename), []byte("faithful-kv-snapshot"), 0o600); err != nil {
			t.Fatalf("write faithful snapshot: %v", err)
		}
		writeCheckpointJSON(w, `{"filename":"`+slotRequest.Filename+`","n_saved":3,"n_written":3}`)
	case "restore":
		s.mu.Lock()
		s.restoreRequests++
		s.mu.Unlock()
		writeCheckpointJSON(w, `{"n_restored":3}`)
	default:
		http.Error(w, "unsupported slot action", http.StatusBadRequest)
	}
}

func writeCheckpointJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

func TestGenerateProductionCheckpointProofManagedLifecycleAndDiscovery(t *testing.T) {
	secret := strings.Repeat("p", 32)
	root := t.TempDir()
	state, server := newFaithfulCheckpointServer(t, root)
	defer server.Close()

	cfg := &Config{
		NodeID:               "node",
		CommandSigningSecret: secret,
		Checkpoint: CheckpointConfig{
			Enabled: true, ProofExerciseEnabled: true, Root: root,
			MaxBytes: 1 << 20, MaxFiles: 8,
			PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 8,
			MaxMetadataBytes: 1 << 20, MaxOutputBytes: 1 << 20,
			ExpirySeconds: 3600, CleanupIntervalSeconds: 60,
			ProofPath: filepath.Join(root, "production-proof.json"),
		},
	}
	cfg.CommandRecoveryGeneration = 7
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, AcceleratorIndex: 0, ContextLimit: 4096, Slots: 1}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	advertisement, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	targetID := cfg.NodeID + "-" + advertisement.ID
	profile := advertisement.ActiveRuntimeProfile
	if profile == "" {
		profile = "default"
	}
	generation := advertisement.CapabilityGeneration
	if generation == 0 {
		generation = 1
	}
	// Exercise a non-default generation explicitly; the managed driver must
	// carry this exact value into every signed command.
	generation = 7
	advertisement.CapabilityGeneration = generation
	processor := newCommandProcessor(cfg, log, true)
	driver := newManagedCheckpointDriver(processor, cfg, cfg.LlamaCPP.Servers[0], targetID, advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, generation)
	evidence, err := exerciseCheckpointEvidence(context.Background(), cfg.NodeID, targetID, "node-gpu0", advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, generation, 1, 2, driver, secret)
	if err != nil {
		t.Fatalf("managed evidence exercise failed: %v", err)
	}
	if evidence.Complete() || evidence.ProofVersion != "" || evidence.LocalCheckpointBinding != "" {
		t.Fatalf("private exercise minted a production capability proof: %+v", evidence)
	}
	if evidence.Generation != 7 {
		t.Fatalf("managed exercise used generation %d; want exact exercised generation 7", evidence.Generation)
	}
	proof := syntheticSignedV2ValidatorFixture(secret, evidence)
	if !proof.Complete() || proof.Digest != CheckpointProofDigest(proof) {
		t.Fatalf("synthetic validator fixture is not self-consistent: %+v", proof)
	}
	processor.mu.Lock()
	for operation, phase := range processor.checkpointPhases {
		if phase.OwnerID == "checkpoint-proof" && phase.Generation != 7 {
			processor.mu.Unlock()
			t.Fatalf("signed command operation %q used generation %d; want 7", operation, phase.Generation)
		}
	}
	processor.mu.Unlock()
	if mismatch := newManagedCheckpointDriver(processor, cfg, cfg.LlamaCPP.Servers[0], targetID, advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, 7); mismatch == nil {
		t.Fatal("managed proof driver was not constructed")
	} else if _, mismatchErr := exerciseCheckpointEvidence(context.Background(), cfg.NodeID, targetID, "node-gpu0", advertisement.ModelFingerprint, advertisement.Version, profile, advertisement.ContextLimit, 8, 1, 2, mismatch, secret); mismatchErr == nil || !strings.Contains(mismatchErr.Error(), "generation") {
		t.Fatalf("generation mismatch was accepted: %v", mismatchErr)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	if !hmac.Equal([]byte(proof.Signature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Fatal("synthetic validator fixture signature did not verify")
	}

	proofPath := checkpointProofPath(cfg.Checkpoint.ProofPath, targetID)
	if err := PersistSignedCheckpointProof(proofPath, proof); err != nil {
		t.Fatal(err)
	}
	if err := ApplyProductionCheckpointProof(&advertisement, proof); err == nil {
		t.Fatal("synthetic signed fixture minted a production capability without local authority")
	}
	if advertisement.Capabilities.SupportsSessionCheckpoint || advertisement.Capabilities.SessionCheckpointVerified || advertisement.CheckpointProof.Complete() {
		t.Fatalf("synthetic signed fixture bypassed local authority: capabilities=%+v proof=%+v", advertisement.Capabilities, advertisement.CheckpointProof)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".kv") || strings.HasSuffix(entry.Name(), ".manifest.json") {
			t.Fatalf("managed proof left an owned checkpoint artifact: %s", entry.Name())
		}
	}

	state.mu.Lock()
	completionRequests, saveRequests, restoreRequests, deleteRequests := state.completionRequests, state.saveRequests, state.restoreRequests, state.deleteRequests
	state.mu.Unlock()
	checkpointProofSessionIssued = sync.Map{}
	first := discoverAdaptersForSession(context.Background(), cfg, log, processor, false)
	if len(first) != 1 || first[0].CheckpointProof.Complete() || first[0].Capabilities.SupportsSessionCheckpoint || first[0].Capabilities.SessionCheckpointVerified {
		t.Fatalf("discovery reused a proof without local launcher/unit authority: %+v", first)
	}
	second := discoverAdaptersForSession(context.Background(), cfg, log, processor, true)
	if len(second) != 1 || second[0].CheckpointProof.Complete() || second[0].Capabilities.SupportsSessionCheckpoint {
		t.Fatalf("reconnect reused a proof without local launcher/unit authority: %+v", second)
	}
	state.mu.Lock()
	if state.completionRequests != completionRequests || state.saveRequests != saveRequests || state.restoreRequests != restoreRequests || state.deleteRequests != deleteRequests {
		t.Fatalf("discovery touched runtime despite missing local authority: before=%d/%d/%d/%d after=%d/%d/%d/%d", completionRequests, saveRequests, restoreRequests, deleteRequests, state.completionRequests, state.saveRequests, state.restoreRequests, state.deleteRequests)
	}
	state.mu.Unlock()
	loaded, err := LoadSignedCheckpointProof(proofPath, secret)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Nonce != proof.Nonce {
		t.Fatalf("discovery changed the persisted signed fixture: disk=%q original=%q", loaded.Nonce, proof.Nonce)
	}
}

func TestRefreshCapabilitiesManagedProofReentryIsBounded(t *testing.T) {
	secret := strings.Repeat("r", 32)
	root := t.TempDir()
	checkpointProofExerciseAttempts = sync.Map{}
	checkpointProofSessionIssued = sync.Map{}
	t.Cleanup(func() {
		checkpointProofExerciseAttempts = sync.Map{}
		checkpointProofSessionIssued = sync.Map{}
	})
	_, server := newFaithfulCheckpointServer(t, root)
	defer server.Close()
	cfg := &Config{
		NodeID:               "node-refresh",
		CommandSigningSecret: secret,
		Checkpoint: CheckpointConfig{
			Enabled: true, ProofExerciseEnabled: true, Root: root,
			MaxBytes: 1 << 20, MaxFiles: 8, PerOwnerMaxBytes: 1 << 20,
			PerOwnerMaxFiles: 8, MaxMetadataBytes: 1 << 20,
			MaxOutputBytes: 1 << 20, ExpirySeconds: 3600,
			CleanupIntervalSeconds: 60, ProofPath: filepath.Join(root, "proof.json"),
		},
		CommandStatePath: filepath.Join(root, "commands.json"),
	}
	cfg.CommandRecoveryGeneration = 9
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, AcceleratorIndex: 0, ContextLimit: 4096, Slots: 1}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	proofPhaseEntered := make(chan struct{})
	releaseProofPhase := make(chan struct{})
	proofPhaseOnce := sync.Once{}
	readyViolation := make(chan string, 1)
	p.onExternalWork = func(command wsproto.CommandPayload) {
		if p.Ready() {
			select {
			case readyViolation <- command.Command:
			default:
			}
		}
		if strings.HasPrefix(command.Command, "checkpoint_") {
			proofPhaseOnce.Do(func() {
				close(proofPhaseEntered)
				<-releaseProofPhase
			})
		}
	}
	command := wsproto.CommandPayload{ID: "refresh-managed", IdempotencyKey: "refresh-managed", NodeID: cfg.NodeID, Command: "refresh_capabilities", Args: map[string]any{}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(20 * time.Second)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	done := make(chan wsproto.CommandResultPayload, 1)
	go func() { done <- p.Handle(context.Background(), command) }()
	select {
	case <-proofPhaseEntered:
		if p.Ready() {
			t.Fatal("managed proof re-entry exposed Ready=true during a live phase")
		}
		concurrent := command
		concurrent.ID, concurrent.IdempotencyKey = "refresh-concurrent", "refresh-concurrent"
		concurrent.Signature, _ = wsproto.SignCommand(concurrent, []byte(secret))
		concurrentDone := make(chan wsproto.CommandResultPayload, 1)
		go func() { concurrentDone <- p.Handle(context.Background(), concurrent) }()
		select {
		case result := <-concurrentDone:
			t.Fatalf("concurrent external refresh crossed the serialized proof boundary: %+v", result)
		case <-time.After(100 * time.Millisecond):
			if p.Ready() {
				t.Fatal("concurrent proof refresh exposed a stale Ready=true heartbeat")
			}
		}
		close(releaseProofPhase)
		select {
		case result := <-done:
			if !result.OK {
				t.Fatalf("managed refresh failed after proof barrier: %+v", result)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("managed refresh did not complete after proof barrier")
		}
		select {
		case result := <-concurrentDone:
			if !result.OK {
				t.Fatalf("serialized concurrent refresh failed: %+v", result)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("serialized concurrent refresh did not complete")
		}
	case result := <-done:
		if !result.OK {
			t.Fatalf("managed refresh failed: %+v", result)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("managed refresh did not complete within its bounded proof window")
	}
	if !p.Ready() {
		t.Fatal("successful managed refresh left processor unready")
	}
	select {
	case commandName := <-readyViolation:
		t.Fatalf("external callback %q observed Ready=true", commandName)
	default:
	}
}

func TestGenerateProductionCheckpointProofCleansEveryIntermediateFailure(t *testing.T) {
	secret := strings.Repeat("f", 32)
	for _, stage := range []string{"assign", "start", "pause", "save", "stop_confirm", "release", "reload", "restore", "resume", "continue", "reuse_verify"} {
		t.Run(stage, func(t *testing.T) {
			driver := &failingProductionProofDriver{failAt: stage}
			proof, err := exerciseCheckpointEvidence(context.Background(), "node", "node-runtime", "node-gpu0", "model", "runtime", "profile", 4096, 7, 1, 2, driver, secret)
			if err == nil {
				t.Fatalf("injected %s failure unexpectedly produced proof: %+v", stage, proof)
			}
			if stage != "assign" && driver.releases == 0 {
				t.Fatalf("failure at %s stranded assigned ownership; calls=%v", stage, driver.calls)
			}
		})
	}
}

func TestDiscoverAdaptersCleanProofBootstrapReleasesSlotAndSurvivesRebuild(t *testing.T) {
	secret := strings.Repeat("b", 32)
	root := t.TempDir()
	state, server := newFaithfulCheckpointServer(t, root)
	defer server.Close()

	cfg := &Config{
		NodeID:               "node",
		CommandSigningSecret: secret,
		CommandStatePath:     filepath.Join(root, "command-state.json"),
		Checkpoint: CheckpointConfig{
			Enabled: true, ProofExerciseEnabled: true, Root: root,
			MaxBytes: 1 << 20, MaxFiles: 8,
			PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 8,
			MaxMetadataBytes: 1 << 20, MaxOutputBytes: 1 << 20,
			ExpirySeconds: 3600, CleanupIntervalSeconds: 60,
			ProofPath: filepath.Join(root, "production-proof.json"),
		},
	}
	cfg.CommandRecoveryGeneration = 1
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{
		ID: "runtime", Endpoint: server.URL, AcceleratorIndex: 0,
		ContextLimit: 4096, Slots: 1, RouterManaged: true,
	}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// This is deliberately a clean bootstrap: the only proof is the one that
	// discoverAdapters creates after driving the signed command processor and
	// the faithful HTTP backend.  Pre-seeding a proof would bypass the path this
	// regression protects.
	checkpointProofExerciseAttempts = sync.Map{}
	checkpointProofSessionIssued = sync.Map{}
	t.Cleanup(func() {
		checkpointProofExerciseAttempts = sync.Map{}
		checkpointProofSessionIssued = sync.Map{}
	})
	targetID := "node-runtime"
	proofPath := checkpointProofPath(cfg.Checkpoint.ProofPath, targetID)
	if _, err := os.Stat(proofPath); !os.IsNotExist(err) {
		t.Fatalf("clean bootstrap unexpectedly had a proof: err=%v", err)
	}
	processor := newCommandProcessor(cfg, log, true)
	ads := discoverAdapters(context.Background(), cfg, log, processor)
	if len(ads) != 1 || ads[0].CheckpointProof.Complete() || ads[0].Capabilities.SupportsSessionCheckpoint || ads[0].Capabilities.SessionCheckpointVerified {
		t.Fatalf("clean discovery advertised capability without local launcher/unit authority: %+v", ads)
	}
	if _, err := os.Stat(proofPath); !os.IsNotExist(err) {
		t.Fatalf("clean discovery persisted a proof without local authority: %v", err)
	}
	profile := ads[0].ActiveRuntimeProfile
	if profile == "" {
		profile = "default"
	}
	evidenceDriver := newManagedCheckpointDriver(processor, cfg, cfg.LlamaCPP.Servers[0], targetID, ads[0].ModelFingerprint, ads[0].Version, profile, ads[0].ContextLimit, ads[0].CapabilityGeneration)
	evidence, err := exerciseCheckpointEvidence(context.Background(), cfg.NodeID, targetID, "node-gpu0", ads[0].ModelFingerprint, ads[0].Version, profile, ads[0].ContextLimit, ads[0].CapabilityGeneration, 1, 2, evidenceDriver, secret)
	if err != nil || evidence.Complete() {
		t.Fatalf("private evidence exercise failed or minted a capability: evidence=%+v err=%v", evidence, err)
	}
	state.mu.Lock()
	if state.completionRequests < 2 || state.saveRequests != 1 || state.restoreRequests != 1 || state.deleteRequests < 1 {
		t.Fatalf("private evidence exercise did not reach the faithful backend: completions=%d saves=%d restores=%d deletes=%d", state.completionRequests, state.saveRequests, state.restoreRequests, state.deleteRequests)
	}
	state.mu.Unlock()

	processor.mu.Lock()
	if len(processor.checkpointSlots) != 0 {
		t.Fatalf("final signed checkpoint_release left slot ownership: %+v", processor.checkpointSlots)
	}
	proofReleaseFound := false
	for operation, phase := range processor.checkpointPhases {
		if phase.OwnerID == "checkpoint-proof" {
			if phase.Action != "release" || phase.Phase != 15 || phase.SlotID != 0 {
				processor.mu.Unlock()
				t.Fatalf("proof operation did not reach terminal release: operation=%q phase=%+v", operation, phase)
			}
			proofReleaseFound = true
		}
	}
	processor.mu.Unlock()
	if !proofReleaseFound {
		t.Fatal("private evidence exercise was not durably journaled")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".kv") || strings.HasSuffix(entry.Name(), ".manifest.json") {
			t.Fatalf("clean proof bootstrap left owned checkpoint artifact: %s", entry.Name())
		}
	}

	makeCommand := func(operation, action, owner string, fence uint64, extra map[string]any) wsproto.CommandPayload {
		args := map[string]any{
			"target_kind": "llamacpp", "target_id": targetID,
			"accelerator_id": "node-gpu0", "model": ads[0].ModelFingerprint,
			"runtime_identity": ads[0].Version, "capability_version": ads[0].Version,
			"capability_revision": domain.CapabilityContractVersion,
			"profile_fingerprint": "default", "context_fingerprint": "ctx:4096",
			"owner_id": owner, "workload_id": operation, "generation": int64(2),
			"fencing_token": int64(fence), "context_limit": int64(4096),
			"checkpoint_action": action, "checkpoint_operation_id": operation,
			"idempotency_key": operation + ":" + action,
		}
		for key, value := range extra {
			args[key] = value
		}
		command := wsproto.CommandPayload{
			ID: operation + ":" + action, IdempotencyKey: operation + ":" + action,
			NodeID: cfg.NodeID, Command: "checkpoint_" + action, Args: args,
			IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute),
		}
		command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
		return command
	}

	// The slot released by the proof must be available to a distinct, newer
	// fenced operation.  Exercise both assignment and real conversation start
	// through commandProcessor; a helper-only state mutation would miss the
	// ownership regression.
	operation, owner, conversation := "followup-operation", "followup-owner", "followup-conversation"
	assigned := processor.Handle(context.Background(), makeCommand(operation, "slot_assign", owner, 3, map[string]any{"slot_id": int64(0)}))
	if !assigned.OK || assigned.Result["slot_id"] != 0 {
		t.Fatalf("new same-slot assignment was rejected after proof release: %+v", assigned)
	}
	started := processor.Handle(context.Background(), makeCommand(operation, "start", owner, 3, map[string]any{"slot_id": int64(0), "conversation_id": conversation}))
	if !started.OK || started.Result["conversation_id"] != conversation {
		t.Fatalf("new same-slot start was rejected after proof release: %+v", started)
	}
	paused := processor.Handle(context.Background(), makeCommand(operation, "pause", owner, 3, map[string]any{"slot_id": int64(0), "conversation_id": conversation}))
	if !paused.OK {
		t.Fatalf("follow-up conversation did not reach a safe boundary: %+v", paused)
	}
	stopped := processor.Handle(context.Background(), makeCommand(operation, "stop_confirm", owner, 3, map[string]any{"slot_id": int64(0)}))
	if !stopped.OK {
		t.Fatalf("follow-up stop confirmation failed: %+v", stopped)
	}
	released := processor.Handle(context.Background(), makeCommand(operation, "release", owner, 3, map[string]any{"slot_id": int64(0)}))
	if !released.OK {
		t.Fatalf("follow-up release failed: %+v", released)
	}

	// Rebuild from the durable node journal and clear process-local discovery
	// state. Neither the proof operation nor the completed follow-up may
	// resurrect ownership; discovery may only rotate the signed proof nonce.
	restarted := newCommandProcessor(cfg, log, true)
	restarted.mu.Lock()
	if len(restarted.checkpointSlots) != 0 {
		got := make(map[string]string, len(restarted.checkpointSlots))
		for key, value := range restarted.checkpointSlots {
			got[key] = value
		}
		restarted.mu.Unlock()
		t.Fatalf("restart resurrected released checkpoint ownership: %+v", got)
	}
	restarted.mu.Unlock()
	checkpointProofSessionIssued = sync.Map{}
	state.mu.Lock()
	completionBeforeRestart := state.completionRequests
	state.mu.Unlock()
	restartedAds := discoverAdapters(context.Background(), cfg, log, restarted)
	if len(restartedAds) != 1 || restartedAds[0].CheckpointProof.Complete() || restartedAds[0].Capabilities.SupportsSessionCheckpoint || restartedAds[0].Capabilities.SessionCheckpointVerified {
		t.Fatalf("restart reused proof without local launcher/unit authority: %+v", restartedAds)
	}
	state.mu.Lock()
	completionAfterRestart := state.completionRequests
	state.mu.Unlock()
	if completionAfterRestart != completionBeforeRestart {
		t.Fatalf("restart reran a disruptive proof exercise without local authority: %d -> %d", completionBeforeRestart, completionAfterRestart)
	}
}
func TestDiscoveryRejectsPersistedProofAcrossSessionsWithoutLocalAuthority(t *testing.T) {
	secret := strings.Repeat("d", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			_, _ = io.WriteString(w, `{"data":[{"id":"model","status":"loaded"}]}`)
		case "/api/ps":
			_, _ = io.WriteString(w, `{"models":[]}`)
		case "/slots":
			_, _ = io.WriteString(w, `[{"id":0,"n_ctx":4096,"is_processing":false}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	cfg := &Config{NodeID: "node", CommandSigningSecret: secret, Checkpoint: CheckpointConfig{Enabled: true, ProofPath: filepath.Join(root, "production-proof.json"), Root: root}}
	cfg.CommandRecoveryGeneration = 1
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, AcceleratorIndex: 0, ContextLimit: 4096, Slots: 1}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	initial, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	targetID := cfg.NodeID + "-" + initial.ID
	proofPath := checkpointProofPath(cfg.Checkpoint.ProofPath, targetID)
	proof := signedTestCheckpointProof(secret)
	proof.TargetID, proof.ModelFingerprint, proof.RuntimeIdentity = targetID, initial.ModelFingerprint, initial.Version
	proof.AcceleratorID, proof.Generation, proof.ContextLimit = "node-gpu0", 1, initial.ContextLimit
	proof.ProfileFingerprint = "default"
	proof = signNodeTestCheckpointProof(secret, proof)
	if err := PersistSignedCheckpointProof(proofPath, proof); err != nil {
		t.Fatal(err)
	}
	checkpointProofSessionIssued = sync.Map{}
	first := discoverAdaptersForSession(context.Background(), cfg, log, nil, false)
	if len(first) != 1 || first[0].CheckpointProof.Complete() || first[0].Capabilities.SupportsSessionCheckpoint {
		t.Fatalf("discovery reused persisted proof without local authority: %+v", first)
	}
	second := discoverAdaptersForSession(context.Background(), cfg, log, nil, false)
	if len(second) != 1 || second[0].Capabilities.SupportsSessionCheckpoint {
		t.Fatal("same-session discovery reused checkpoint capability")
	}
	reconnect := discoverAdaptersForSession(context.Background(), cfg, log, nil, true)
	if len(reconnect) != 1 || reconnect[0].Capabilities.SupportsSessionCheckpoint {
		t.Fatal("reconnect reused checkpoint capability without local authority")
	}
	// Simulate an agent process restart: clear only process memory, preserving
	// both the proof and issuance sidecar on disk.
	checkpointProofSessionIssued = sync.Map{}
	restarted := discoverAdaptersForSession(context.Background(), cfg, log, nil, false)
	if len(restarted) != 1 || restarted[0].Capabilities.SupportsSessionCheckpoint {
		t.Fatal("agent restart reused checkpoint capability without local authority")
	}
	if _, err := os.Stat(checkpointProofIssuancePath(proofPath)); !os.IsNotExist(err) {
		t.Fatalf("prior proof without sidecar unexpectedly created issuance state: %v", err)
	}
}

func TestDiscoveryFailsClosedWithoutLocalBindingAcrossModelProfileContextAndRestart(t *testing.T) {
	secret := strings.Repeat("r", 32)
	root := t.TempDir()
	state, server := newFaithfulCheckpointServer(t, root)
	defer server.Close()
	state.mu.Lock()
	state.contextLimit = 8192
	state.mu.Unlock()
	cfg := &Config{
		NodeID: "node-rebind", CommandSigningSecret: secret,
		CommandStatePath: filepath.Join(root, "commands.json"), CommandRecoveryGeneration: 7,
		Checkpoint: CheckpointConfig{Enabled: true, ProofExerciseEnabled: true, Root: root, ProofPath: filepath.Join(root, "proof.json")},
	}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, AcceleratorIndex: 0, ContextLimit: 8192, Slots: 1, RouterManaged: true, RuntimeProfiles: []RuntimeProfileConfig{{ID: "ctx-8k", ContextLimit: 8192, Slots: 1}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	checkpointProofExerciseAttempts = sync.Map{}
	checkpointProofSessionIssued = sync.Map{}
	t.Cleanup(func() { checkpointProofExerciseAttempts = sync.Map{}; checkpointProofSessionIssued = sync.Map{} })
	processor := newCommandProcessor(cfg, log, true)
	assertUnsupported := func(label string) {
		t.Helper()
		ads := discoverAdaptersForSession(context.Background(), cfg, log, processor, false)
		if len(ads) != 1 || ads[0].CheckpointProof.Complete() || ads[0].Capabilities.SupportsSessionCheckpoint || ads[0].Capabilities.SessionCheckpointVerified {
			t.Fatalf("%s produced checkpoint capability without local binding: %+v", label, ads)
		}
	}
	assertUnsupported("initial profile")
	state.mu.Lock()
	state.modelID, state.contextLimit = "model-b", 32768
	state.mu.Unlock()
	cfg.CommandRecoveryGeneration = 9
	assertUnsupported("changed model, context profile, and generation")
	checkpointProofSessionIssued = sync.Map{}
	assertUnsupported("agent restart")
	state.mu.Lock()
	completions, saves, restores := state.completionRequests, state.saveRequests, state.restoreRequests
	state.mu.Unlock()
	if completions != 0 || saves != 0 || restores != 0 {
		t.Fatalf("discovery performed disruptive work without local binding: completions=%d saves=%d restores=%d", completions, saves, restores)
	}
}

func TestCheckpointProofExerciseClaimRenewsAfterBoundedExpiry(t *testing.T) {
	oldInterval := checkpointProofExerciseRetryInterval
	checkpointProofExerciseRetryInterval = time.Minute
	checkpointProofExerciseAttempts = sync.Map{}
	t.Cleanup(func() {
		checkpointProofExerciseRetryInterval = oldInterval
		checkpointProofExerciseAttempts = sync.Map{}
	})
	if !claimCheckpointProofExercise("node-runtime") {
		t.Fatal("first proof exercise claim was not admitted")
	}
	if claimCheckpointProofExercise("node-runtime") {
		t.Fatal("fresh proof exercise claim was duplicated")
	}
	checkpointProofExerciseAttempts.Store("node-runtime", checkpointProofExerciseAttempt{ClaimedAt: time.Now().Add(-2 * time.Minute)})
	if !claimCheckpointProofExercise("node-runtime") {
		t.Fatal("expired failed proof exercise claim was not renewed")
	}
}

func TestCheckpointProofExerciseClaimAllowsOnlyOneConcurrentOwner(t *testing.T) {
	checkpointProofExerciseAttempts = sync.Map{}
	t.Cleanup(func() { checkpointProofExerciseAttempts = sync.Map{} })
	const workers = 32
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- claimCheckpointProofExercise("concurrent-target")
		}()
	}
	wg.Wait()
	close(results)
	claims := 0
	for admitted := range results {
		if admitted {
			claims++
		}
	}
	if claims != 1 {
		t.Fatalf("concurrent proof exercise claims=%d want 1", claims)
	}
}

func TestManagedCheckpointProofIdentityAdvancesPastRetainedPhaseJournal(t *testing.T) {
	secret := strings.Repeat("i", 32)
	cfg := &Config{NodeID: "node", CommandSigningSecret: secret}
	server := LlamaCPPServerConfig{ID: "runtime", AcceleratorIndex: 0}
	processor := &commandProcessor{cfg: cfg, checkpointPhases: map[string]checkpointPhaseState{
		"retained-proof-operation": {OperationID: "retained-proof-operation", TargetID: "node-runtime", AcceleratorID: "node-gpu0", Fence: 11, Generation: 9},
	}, fences: map[string]int64{fenceKey("node-runtime", "model"): 11}}
	driver := newManagedCheckpointDriver(processor, cfg, server, "node-runtime", "model", "runtime", "profile", 4096, 9)
	managed, ok := driver.(*managedCheckpointDriver)
	if !ok || managed == nil {
		t.Fatal("managed checkpoint driver was not constructed")
	}
	if managed.operationID == "retained-proof-operation" {
		t.Fatal("new proof reused a retained operation identity")
	}
	if managed.fence <= 11 {
		t.Fatalf("new proof fence did not advance past retained journal: %d", managed.fence)
	}
	if managed.generation != 9 {
		t.Fatalf("managed proof changed the advertised non-default generation: %d", managed.generation)
	}
}

func TestCheckpointOwnerReferencesSurviveReleaseExpiryAndTerminalCleanup(t *testing.T) {
	cfg := CheckpointConfig{Root: t.TempDir(), MaxMetadataBytes: 1 << 20, ExpirySeconds: 1}
	if err := validateCheckpointRoot(cfg); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(cfg.Root, "owner-work.kv")
	if err := os.WriteFile(snapshot, []byte("checkpoint"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordOwnedCheckpoint(cfg, "owner", "owner-work.kv", "op-1", 10); err != nil {
		t.Fatal(err)
	}
	if err := markOwnedCheckpointInactive(cfg, "owner", "owner-work.kv", "op-1"); err != nil {
		t.Fatal(err)
	}
	manifest, err := readCheckpointOwnerManifest(cfg, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.Entries["owner-work.kv"].ActiveReferences; got != 1 {
		t.Fatalf("release dropped resumable reference: %d", got)
	}
	if err := recordOwnedCheckpoint(cfg, "owner", "owner-work.kv", "op-2", 10); err != nil {
		t.Fatal(err)
	}
	manifest, err = readCheckpointOwnerManifest(cfg, "owner")
	if err != nil {
		t.Fatal(err)
	}
	entry := manifest.Entries["owner-work.kv"]
	if entry.ActiveReferences != 2 || entry.References["op-1"] != 1 || entry.References["op-2"] != 1 {
		t.Fatalf("restart manifest did not reconstruct operation refs: %+v", entry)
	}
	entry.CreatedAt = time.Now().Add(-time.Hour)
	manifest.Entries["owner-work.kv"] = entry
	if err := writeCheckpointOwnerManifest(cfg, manifest); err != nil {
		t.Fatal(err)
	}
	cleanupCheckpointRoot(cfg)
	if _, err := os.Stat(snapshot); err != nil {
		t.Fatalf("expiry removed active/resumable snapshot: %v", err)
	}
	if err := FinalizeOwnedCheckpoint(cfg, "owner", "owner-work.kv", "op-1"); err != nil {
		t.Fatal(err)
	}
	cleanupCheckpointRoot(cfg)
	if _, err := os.Stat(snapshot); err != nil {
		t.Fatalf("expiry removed snapshot with one active operation: %v", err)
	}
	if err := FinalizeOwnedCheckpoint(cfg, "owner", "owner-work.kv", "op-2"); err != nil {
		t.Fatal(err)
	}
	cleanupCheckpointRoot(cfg)
	if _, err := os.Stat(snapshot); !os.IsNotExist(err) {
		t.Fatalf("terminal expired snapshot was not removed: %v", err)
	}
}

func TestCheckpointCleanupIdempotentOnlyForProvenOwnerOperation(t *testing.T) {
	cfg := CheckpointConfig{Root: t.TempDir(), MaxMetadataBytes: 1 << 20}
	if err := validateCheckpointRoot(cfg); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(cfg.Root, "proof-owned.kv")
	if err := os.WriteFile(snapshot, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordOwnedCheckpoint(cfg, "owner-a", "proof-owned.kv", "op-a", 5); err != nil {
		t.Fatal(err)
	}
	if err := FinalizeOwnedCheckpoint(cfg, "owner-a", "proof-owned.kv", "op-a"); err != nil {
		t.Fatal(err)
	}
	if err := CleanupOwnedCheckpoint(cfg, "owner-a", "proof-owned.kv", "op-a"); err != nil {
		t.Fatalf("same owner/operation cleanup retry was not idempotent: %v", err)
	}
	if _, err := os.Stat(snapshot); !os.IsNotExist(err) {
		t.Fatalf("terminal cleanup did not remove owned snapshot: %v", err)
	}
	if err := CleanupOwnedCheckpoint(cfg, "owner-b", "proof-owned.kv", "op-a"); err == nil {
		t.Fatal("foreign owner cleanup was accepted after owner-a terminalization")
	}
}

func TestCheckpointTerminalCleanupRetiresMissingPrimaryExactlyOnce(t *testing.T) {
	cfg := CheckpointConfig{Root: t.TempDir(), MaxMetadataBytes: 1 << 20}
	if err := validateCheckpointRoot(cfg); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(cfg.Root, "missing-primary.kv")
	if err := os.WriteFile(primary, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary+".json", []byte(`{"owner":"owner"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordOwnedCheckpoint(cfg, "owner", "missing-primary.kv", "op", 5); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	if err := FinalizeOwnedCheckpoint(cfg, "owner", "missing-primary.kv", "op"); err != nil {
		t.Fatalf("missing-primary terminal cleanup failed: %v", err)
	}
	if err := FinalizeOwnedCheckpoint(cfg, "owner", "missing-primary.kv", "op"); err != nil {
		t.Fatalf("same owner/operation terminal retry was not idempotent: %v", err)
	}
	if _, err := os.Stat(primary + ".json"); !os.IsNotExist(err) {
		t.Fatalf("terminal cleanup retained sidecar: %v", err)
	}
	manifestPath, err := checkpointOwnerManifestPath(cfg, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("terminal cleanup retained an empty owner manifest: %v", err)
	}
	if err := CleanupOwnedCheckpoint(cfg, "owner", "missing-primary.kv", "op"); err != nil {
		t.Fatalf("same owner/operation cleanup retry was not idempotent: %v", err)
	}
}

func TestCheckpointFinalizationAndCleanupFailuresFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(CheckpointConfig) error
	}{
		{name: "finalization", call: func(cfg CheckpointConfig) error {
			return FinalizeOwnedCheckpoint(cfg, "owner", "foreign-dir.kv", "op")
		}},
		{name: "cleanup", call: func(cfg CheckpointConfig) error {
			return CleanupOwnedCheckpoint(cfg, "owner", "foreign-dir.kv", "op")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := CheckpointConfig{Root: t.TempDir(), MaxMetadataBytes: 1 << 20}
			if err := validateCheckpointRoot(cfg); err != nil {
				t.Fatal(err)
			}
			if err := recordOwnedCheckpoint(cfg, "owner", "foreign-dir.kv", "op", 5); err != nil {
				t.Fatal(err)
			}
			snapshotDir := filepath.Join(cfg.Root, "foreign-dir.kv")
			if err := os.Mkdir(snapshotDir, 0o700); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(snapshotDir, "foreign-data")
			if err := os.WriteFile(foreign, []byte("must survive"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.name == "cleanup" {
				manifest, err := readCheckpointOwnerManifest(cfg, "owner")
				if err != nil {
					t.Fatal(err)
				}
				entry := manifest.Entries["foreign-dir.kv"]
				entry.ActiveReferences = 0
				entry.Terminalized = true
				entry.TerminalizedOperationID = "op"
				entry.References = map[string]int{}
				manifest.Entries["foreign-dir.kv"] = entry
				if err := writeCheckpointOwnerManifest(cfg, manifest); err != nil {
					t.Fatal(err)
				}
			}
			if err := tc.call(cfg); err == nil {
				t.Fatalf("injected %s failure unexpectedly succeeded", tc.name)
			}
			if body, err := os.ReadFile(foreign); err != nil || string(body) != "must survive" {
				t.Fatalf("foreign data changed after %s failure: body=%q err=%v", tc.name, body, err)
			}
		})
	}
}

func TestCheckpointQuotaArithmeticAndMaxInt64OwnerAccountingFailClosed(t *testing.T) {
	if got, err := checkedCheckpointReplacement(math.MaxInt64, 1, 1); err != nil || got != math.MaxInt64 {
		t.Fatalf("valid MaxInt64 replacement failed: value=%d err=%v", got, err)
	}
	for _, tc := range []struct {
		name        string
		left, right int64
		want        string
	}{
		{name: "addition overflow", left: math.MaxInt64, right: 1, want: "overflow"},
		{name: "subtraction underflow", left: 0, right: 1, want: "underflow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.name == "addition overflow" {
				_, err = checkedCheckpointAdd(tc.left, tc.right)
			} else {
				_, err = checkedCheckpointSub(tc.left, tc.right)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("arithmetic failure was accepted: %v", err)
			}
		})
	}
	cfg := CheckpointConfig{Root: t.TempDir(), MaxBytes: math.MaxInt64, MaxFiles: 8, PerOwnerMaxBytes: math.MaxInt64, PerOwnerMaxFiles: 8, MaxMetadataBytes: 1 << 20}
	if err := validateCheckpointRoot(cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Root, "owner.kv")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordOwnedCheckpoint(cfg, "owner", "owner.kv", "op", math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	if err := checkpointQuotaAllowed(cfg, "owner", "other.kv", 1); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("MaxInt64 owner accounting overflow was accepted: %v", err)
	}
	if err := checkpointQuotaAllowed(cfg, "owner", "owner.kv", 1); err == nil || !strings.Contains(err.Error(), "underflow") {
		t.Fatalf("replacement underflow was accepted: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("quota rejection changed existing checkpoint: %v", err)
	}
}

func TestCommandProcessorCheckpointPhaseFenceSequenceAndReplay(t *testing.T) {
	secret := strings.Repeat("c", 32)
	cfg := &Config{NodeID: "node", CommandSigningSecret: secret, Checkpoint: CheckpointConfig{Enabled: true, Root: t.TempDir(), MaxBytes: 1 << 20, MaxFiles: 4, PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 4, MaxMetadataBytes: 1 << 20, MaxOutputBytes: 1 << 20, ExpirySeconds: 3600, CleanupIntervalSeconds: 60}}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: "http://driver.invalid", ContextLimit: 4096, Slots: 1}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	driver := &commandCheckpointDriver{}
	p.checkpointDrivers["runtime"] = driver
	for _, phase := range []struct {
		action string
		slot   any
	}{{"slot_assign", nil}, {"pause", 2}, {"save", 2}, {"stop_confirm", 2}, {"release", 2}} {
		result := p.Handle(context.Background(), signedCheckpointCommand(secret, "node", phase.action, "op-1", "key-1:"+phase.action, phase.slot))
		if !result.OK {
			t.Fatalf("phase %s failed: %+v", phase.action, result)
		}
	}
	if got, want := driver.actions, []string{"query", "assign", "pause", "save", "stop_confirm", "release"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("driver sequence=%v want %v", got, want)
	}
	// Equal-fence operations cannot steal the released operation's slot until
	// they have their own assignment; an out-of-order stale phase is rejected.
	stale := p.Handle(context.Background(), signedCheckpointCommand(secret, "node", "pause", "op-1", "stale-pause", 2))
	if stale.OK || !strings.Contains(stale.Error, "out of order") {
		t.Fatalf("stale phase accepted: %+v", stale)
	}
	different := p.Handle(context.Background(), signedCheckpointCommand(secret, "node", "pause", "op-2", "key-2:pause", 2))
	if different.OK || !strings.Contains(different.Error, "must begin") && !strings.Contains(different.Error, "owned") {
		t.Fatalf("different operation bypassed assignment/ownership: %+v", different)
	}
	for _, phase := range []struct {
		action string
		slot   any
	}{{"slot_assign", nil}, {"reload", 2}, {"restore", 2}, {"resume", 2}, {"continue", 2}, {"reuse_verify", 2}} {
		result := p.Handle(context.Background(), signedCheckpointCommand(secret, "node", phase.action, "op-2", "key-2:"+phase.action, phase.slot))
		if !result.OK {
			t.Fatalf("restore phase %s failed: %+v", phase.action, result)
		}
	}
}
