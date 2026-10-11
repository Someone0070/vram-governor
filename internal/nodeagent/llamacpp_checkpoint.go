package nodeagent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/runtime"
	"vram-governor/internal/safefile"
	"vram-governor/internal/wsproto"
)

var checkpointManifestMu sync.Mutex
var managedCheckpointOperationCounter atomic.Uint64
var checkpointProofClock = time.Now

// checkpointTerminalizedOperations is deliberately process-local.  A cleanup
// retry is idempotent only after this process has completed the exact owner /
// operation terminal transition; an absent manifest or bundle is never, by
// itself, evidence that an arbitrary caller may clean a path.
var checkpointTerminalizedOperations sync.Map
var checkpointSnapshotNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.kv$`)

func checkedCheckpointAdd(left, right int64) (int64, error) {
	if left < 0 || right < 0 {
		return 0, fmt.Errorf("checkpoint quota accounting has a negative size")
	}
	if right > math.MaxInt64-left {
		return 0, fmt.Errorf("checkpoint quota accounting overflow")
	}
	return left + right, nil
}

func checkedCheckpointSub(left, right int64) (int64, error) {
	if left < 0 || right < 0 || right > left {
		return 0, fmt.Errorf("checkpoint quota accounting underflow")
	}
	return left - right, nil
}

func checkedCheckpointReplacement(used, incoming, replaced int64) (int64, error) {
	withoutReplacement, err := checkedCheckpointSub(used, replaced)
	if err != nil {
		return 0, err
	}
	return checkedCheckpointAdd(withoutReplacement, incoming)
}

func checkedCheckpointFileCount(count int) (int, error) {
	if count < 0 || count == int(^uint(0)>>1) {
		return 0, fmt.Errorf("checkpoint quota file count overflow")
	}
	return count + 1, nil
}

func checkedCheckpointReferenceAdd(count int) (int, error) {
	if count < 0 || count == int(^uint(0)>>1) {
		return 0, fmt.Errorf("checkpoint reference count overflow")
	}
	return count + 1, nil
}

// checkpointProofIssuanceState is node-local durable state.  The completed
// exercise itself lives in the signed proof file; this sidecar only records
// the monotonic issuance high-water and the immutable exercise binding.  It
// is intentionally separate from process memory so a reconnect or process
// restart cannot reuse an old issuance epoch.
type checkpointProofIssuanceState struct {
	Version     string               `json:"version"`
	Epoch       uint64               `json:"epoch"`
	HighWater   map[string]uint64    `json:"high_water"`
	Bindings    map[string]string    `json:"bindings"`
	Generations map[string]uint64    `json:"generations,omitempty"`
	Fences      map[string]uint64    `json:"fences,omitempty"`
	Exercises   map[string]string    `json:"exercises,omitempty"`
	IssuedAt    map[string]time.Time `json:"issued_at,omitempty"`
}

const checkpointProofIssuanceStateVersion = "llm-checkpoint-proof-issuance-v2"
const checkpointProofIssuanceStateLegacyVersion = "llm-checkpoint-proof-issuance-v1"

var checkpointIssuanceLockTimeout = 5 * time.Second

// checkpointProofIssuancePath derives a node-local sidecar from the proof
// path.  A caller may pass an explicit CheckpointConfig.IssuanceStatePath;
// this fallback keeps older configurations durable without a migration.
func checkpointProofIssuancePath(proofPath string) string {
	if strings.TrimSpace(proofPath) == "" {
		return ""
	}
	return proofPath + ".issuance.json"
}

func checkpointProofBindingDigest(proof runtime.CheckpointCapabilityProof) string {
	// The issuance sidecar binds the target and the runtime contract, not one
	// particular exercise.  ProvenAt/ExpiresAt, evidence and snapshot material,
	// slot placement, and fencing are intentionally per-exercise values: a new
	// live Generate followed by a durable Rotate must be accepted after an old
	// proof expires.  Generation remains part of the runtime contract so a
	// reconnect cannot rotate a proof from an older recovery epoch.
	material, _ := json.Marshal(struct {
		ProofVersion, ModelAlias, LocalCheckpointBinding                                       string
		NodeID, TargetID, ModelFingerprint, RuntimeIdentity, ProfileFingerprint, AcceleratorID string
		ContextLimit                                                                           int
		Generation                                                                             uint64
	}{
		proof.ProofVersion, proof.ModelAlias, proof.LocalCheckpointBinding,
		proof.NodeID, proof.TargetID, proof.ModelFingerprint, proof.RuntimeIdentity,
		proof.ProfileFingerprint, proof.AcceleratorID, proof.ContextLimit, proof.Generation,
	})
	sum := sha256.Sum256(material)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func legacyCheckpointProofBindingDigest(proof runtime.CheckpointCapabilityProof) string {
	material, _ := json.Marshal(struct {
		NodeID, TargetID, ModelFingerprint, RuntimeIdentity, ProfileFingerprint, AcceleratorID string
		ContextLimit                                                                           int
		Generation                                                                             uint64
	}{
		proof.NodeID, proof.TargetID, proof.ModelFingerprint, proof.RuntimeIdentity,
		proof.ProfileFingerprint, proof.AcceleratorID, proof.ContextLimit, proof.Generation,
	})
	sum := sha256.Sum256(material)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func checkpointProofExerciseDigest(proof runtime.CheckpointCapabilityProof) string {
	// This identifies one completed exercise while deliberately omitting
	// issuance-only material.  It lets the durable journal distinguish a fresh
	// exercise with a reused fence from a harmless re-rotation of the same
	// exercise.
	material, _ := json.Marshal(struct {
		ProofVersion, ModelAlias, LocalCheckpointBinding                                                                      string
		Verified, ProbeOnly, SlotAssignment, SafeBoundaryPause, SnapshotSave, BackendStopConfirmed, SnapshotRestore, KVReused bool
		SlotID, SavedTokens, ReusedTokens                                                                                     int
		OldFence, NewFence                                                                                                    uint64
		EvidenceID, SnapshotDigest                                                                                            string
		SnapshotBytes                                                                                                         int64
	}{
		proof.ProofVersion, proof.ModelAlias, proof.LocalCheckpointBinding,
		proof.Verified, proof.ProbeOnly, proof.SlotAssignment, proof.SafeBoundaryPause,
		proof.SnapshotSave, proof.BackendStopConfirmed, proof.SnapshotRestore, proof.KVReused,
		proof.SlotID, proof.SavedTokens, proof.ReusedTokens, proof.OldFence, proof.NewFence,
		proof.EvidenceID, proof.SnapshotDigest, proof.SnapshotBytes,
	})
	sum := sha256.Sum256(material)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validCheckpointProofStateDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func parseCheckpointProofIssuance(nonce string) (uint64, bool) {
	return runtime.CheckpointProofIssuanceEpoch(nonce)
}

func newCheckpointProofNonce(epoch uint64, now time.Time, randomBytes []byte) string {
	if epoch == 0 {
		return ""
	}
	return fmt.Sprintf("%020d-e%020d-%s", now.UnixNano(), epoch, hex.EncodeToString(randomBytes))
}

// GenerateProductionCheckpointProof is retained as a fail-closed compatibility
// entry point. This prerequisite has no locally established launcher/unit
// binding source, so it refuses before touching the runtime until that
// authority is integrated.
func GenerateProductionCheckpointProof(context.Context, string, string, string, string, string, string, int, uint64, uint64, uint64, runtime.SlotCheckpointDriver, string) (runtime.CheckpointCapabilityProof, error) {
	return runtime.CheckpointCapabilityProof{}, fmt.Errorf("production checkpoint proof requires a locally established launch-plan and unit binding")
}

// exerciseCheckpointEvidence is a private evidence-only seam for deterministic
// lifecycle tests. Its result lacks both production proof version and binding,
// and therefore can never satisfy capability predicates or be advertised.
type productionCheckpointCleaner interface {
	CleanupProductionCheckpoint(context.Context, int, string) error
}

// productionCheckpointProofTTL is kept as a package variable so deterministic
// lifecycle tests can exercise expiry without sleeping for a day. Production
// remains deliberately conservative; a capability proof is valid for one day
// unless a caller explicitly overrides the test seam in this package.
var productionCheckpointProofTTL = 24 * time.Hour

func exerciseCheckpointEvidence(ctx context.Context, nodeID, targetID, acceleratorID, model, runtimeIdentity, profile string, contextLimit int, generation, oldFence, newFence uint64, driver runtime.SlotCheckpointDriver, secret string) (proof runtime.CheckpointCapabilityProof, err error) {
	if driver == nil || strings.TrimSpace(nodeID) == "" || strings.TrimSpace(targetID) == "" || strings.TrimSpace(model) == "" || strings.TrimSpace(runtimeIdentity) == "" || contextLimit <= 0 || generation == 0 || newFence <= oldFence || len(secret) < 16 {
		return proof, fmt.Errorf("production checkpoint proof inputs are incomplete")
	}
	if exercised, ok := driver.(interface{ CheckpointGeneration() uint64 }); ok && exercised.CheckpointGeneration() != generation {
		return proof, fmt.Errorf("production checkpoint proof generation does not match exercised command generation")
	}
	inventory, err := driver.QuerySlots(ctx)
	if err != nil {
		return proof, err
	}
	slot := -1
	for _, candidate := range inventory.Slots {
		if !candidate.Processing && candidate.ContextLimit >= contextLimit {
			slot = candidate.ID
			break
		}
	}
	if slot < 0 {
		return proof, fmt.Errorf("no safe idle checkpoint slot")
	}
	ownsSlot := true
	releaseConfirmed := false
	snapshotName := ""
	// Every successful assignment creates node-side ownership.  Keep a
	// bounded, independent cleanup context so an upstream discovery timeout
	// cannot strand that ownership after any later phase error.  Drivers with a
	// managed command journal use the stronger legal/idempotent cleanup seam;
	// compatibility drivers still receive the stop-confirm + release pair.
	defer func() {
		if !ownsSlot || releaseConfirmed {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var cleanupErr error
		if cleaner, ok := driver.(productionCheckpointCleaner); ok {
			cleanupErr = cleaner.CleanupProductionCheckpoint(cleanupCtx, slot, snapshotName)
		} else {
			_, stopErr := driver.ConfirmStopped(cleanupCtx, slot)
			releaseErr := driver.ReleaseSlot(cleanupCtx, slot)
			if stopErr != nil {
				cleanupErr = stopErr
			}
			if releaseErr != nil && cleanupErr == nil {
				cleanupErr = releaseErr
			}
		}
		if cleanupErr != nil {
			// Returning a proof after an unconfirmed cleanup would advertise a
			// capability while retaining an unknown slot/snapshot owner.
			proof = runtime.CheckpointCapabilityProof{}
			if err == nil {
				err = fmt.Errorf("production checkpoint cleanup failed: %w", cleanupErr)
			}
		}
	}()
	assignment, err := driver.AssignSlot(ctx, slot)
	if err != nil {
		return proof, err
	}
	if assignment.SlotID != slot {
		return proof, fmt.Errorf("runtime assigned unexpected slot")
	}
	conversationDriver, ok := driver.(runtime.ConversationSlotCheckpointDriver)
	if !ok {
		return proof, fmt.Errorf("production proof requires conversation-aware llama driver")
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return proof, err
	}
	// The issuance timestamp is part of the nonce so the controller can
	// compact its durable replay journal after a bounded retention window. The
	// random suffix keeps two exercises in the same nanosecond distinct.
	nonce := fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(nonceBytes))
	conversationID := "proof-" + nonce
	if err := conversationDriver.StartCheckpointConversation(ctx, slot, conversationID, model, contextLimit); err != nil {
		return proof, err
	}
	boundary, err := conversationDriver.PauseAtBoundaryWithConversation(ctx, slot, conversationID)
	if err != nil {
		return proof, err
	}
	if len(boundary.Prefix) == 0 || boundary.TokenCount <= 0 {
		return proof, fmt.Errorf("runtime did not capture a non-empty assistant prefix at pause boundary")
	}
	name := "proof-" + nonce + ".kv"
	snapshotName = name
	saved, err := driver.SaveKV(ctx, slot, name)
	if err != nil {
		return proof, err
	}
	if saved.TokensSaved <= 0 || saved.SizeBytes <= 0 || saved.SnapshotRef == "" {
		return proof, fmt.Errorf("runtime returned incomplete checkpoint measurement")
	}
	stopped, err := driver.ConfirmStopped(ctx, slot)
	if err != nil || !stopped {
		if err == nil {
			err = fmt.Errorf("backend did not confirm stop")
		}
		return proof, err
	}
	if err := driver.ReleaseSlot(ctx, slot); err != nil {
		return proof, err
	}
	releaseConfirmed = true
	ownsSlot = false
	// A second assignment begins a new ownership interval. Keep cleanup armed
	// even if the runtime reports an ambiguous assignment error.
	ownsSlot = true
	releaseConfirmed = false
	assignment, err = driver.AssignSlot(ctx, slot)
	if err != nil {
		return proof, err
	}
	if assignment.SlotID != slot {
		return proof, fmt.Errorf("runtime reassigned unexpected slot")
	}
	if err := driver.Reload(ctx, slot); err != nil {
		return proof, err
	}
	restored, err := driver.RestoreKV(ctx, slot, saved.SnapshotRef)
	if err != nil || restored.TokensRestored <= 0 {
		if err == nil {
			err = fmt.Errorf("runtime restored no KV tokens")
		}
		return proof, err
	}
	prefixSum := sha256.Sum256(boundary.Prefix)
	continuationID := "proof-resume-" + nonce
	if _, err := conversationDriver.ResumeWithConversation(ctx, slot, continuationID, "sha256:"+hex.EncodeToString(prefixSum[:]), len(boundary.Prefix)); err != nil {
		return proof, err
	}
	continuationDriver, ok := driver.(runtime.CheckpointContinuationDriver)
	if !ok {
		return proof, fmt.Errorf("production proof requires a real continuation driver")
	}
	if err := continuationDriver.ContinueCheckpointConversation(ctx, slot, continuationID, model, string(boundary.Prefix)); err != nil {
		return proof, err
	}
	// Measure reuse only after the resumed generation has completed. An idle
	// slot's prompt count is not evidence that the continuation used the KV.
	reused, err := driver.VerifyReuse(ctx, slot, saved.TokensSaved)
	if err != nil || reused <= 0 || reused > saved.TokensSaved {
		if err == nil {
			err = fmt.Errorf("runtime KV reuse measurement invalid")
		}
		return proof, err
	}
	if saved.Digest == "" {
		return proof, fmt.Errorf("runtime did not return the actual KV digest")
	}
	// Reuse verification is the terminal evidence for the capability exercise,
	// but it does not release the authoritative node slot.  The proof must not
	// be signed or advertised while the exercise operation still owns that
	// slot.  Route the final release through the driver so managed proofs issue
	// the same authenticated/fenced checkpoint_release command as every other
	// production phase; this also durably records the terminal release phase
	// before the proof becomes controller-visible.
	if err := driver.ReleaseSlot(ctx, slot); err != nil {
		return proof, err
	}
	releaseConfirmed = true
	ownsSlot = false
	if fencer, ok := driver.(interface{ CheckpointFence() uint64 }); ok && fencer.CheckpointFence() > 0 {
		newFence = fencer.CheckpointFence()
		if newFence > 0 && oldFence >= newFence {
			oldFence = newFence - 1
		}
	}
	provenAt := time.Now().UTC()
	ttl := productionCheckpointProofTTL
	if ttl <= 0 {
		ttl = time.Nanosecond
	}
	proof = runtime.CheckpointCapabilityProof{Verified: false, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true, BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true, ProvenAt: provenAt, ExpiresAt: provenAt.Add(ttl), NodeID: nodeID, TargetID: targetID, ModelFingerprint: model, RuntimeIdentity: runtimeIdentity, ProfileFingerprint: profile, ContextLimit: contextLimit, SlotID: slot, Generation: generation, OldFence: oldFence, NewFence: newFence, SavedTokens: saved.TokensSaved, ReusedTokens: reused, EvidenceID: "checkpoint-proof-" + nonce, SnapshotDigest: saved.Digest, SnapshotBytes: saved.SizeBytes, AcceleratorID: acceleratorID, Nonce: nonce}
	// A managed proof has already crossed the terminal ownership seam in the
	// authenticated reuse_verify command.  Do not finalize or clean it again:
	// the command processor owns that transition exactly once and may already
	// have removed the bundle and owner manifest before returning its evidence.
	proof.Digest = CheckpointProofDigest(proof)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	proof.Signature = hex.EncodeToString(mac.Sum(nil))
	return proof, nil
}

// managedCheckpointDriver is used only by the explicit proof exercise. It
// routes every lifecycle call through the same authenticated commandProcessor
// used by controller websocket commands; it is not a second runtime protocol.
type managedCheckpointDriver struct {
	handler           CommandHandler
	cfg               *Config
	server            LlamaCPPServerConfig
	targetID          string
	model             string
	runtimeIdentity   string
	profile           string
	contextLimit      int
	generation        uint64
	operationID       string
	idempotencyPrefix string
	fence             uint64
	slot              int
	snapshotDigest    string
	snapshotName      string
	callMu            sync.Mutex
	callSequence      map[string]uint64
}

func newManagedCheckpointDriver(handler CommandHandler, cfg *Config, server LlamaCPPServerConfig, targetID, model, runtimeIdentity, profile string, contextLimit int, generation uint64) runtime.SlotCheckpointDriver {
	if generation == 0 || generation > math.MaxInt64 {
		return nil
	}
	acceleratorID := fmt.Sprintf("%s-gpu%d", cfg.NodeID, server.AcceleratorIndex)
	seed := sha256.Sum256([]byte(targetID + "|" + model + "|" + fmt.Sprint(time.Now().UnixNano()) + "|" + fmt.Sprint(managedCheckpointOperationCounter.Add(1))))
	operation := "proof-op-" + hex.EncodeToString(seed[:10])
	// A reconnect can rebuild the command processor while its phase journal
	// still contains a released or partially-completed proof.  Never reuse its
	// operation identity, and advance the new fence past every durable row for
	// this target/accelerator.  The advertised generation remains the exact
	// non-default generation supplied by discovery.
	fence := uint64(2)
	if processor, ok := handler.(*commandProcessor); ok && processor != nil {
		processor.mu.Lock()
		maxFence := int64(1)
		for existingID, phase := range processor.checkpointPhases {
			if existingID == operation {
				operation = fmt.Sprintf("%s-%d", operation, managedCheckpointOperationCounter.Add(1))
			}
			if phase.TargetID == targetID && phase.AcceleratorID == acceleratorID && phase.Fence > maxFence {
				maxFence = phase.Fence
			}
		}
		for key, result := range processor.results {
			if strings.HasPrefix(key, "key:") || result.Result == nil {
				continue
			}
			if existing, _ := result.Result["checkpoint_operation_id"].(string); existing == operation {
				operation = fmt.Sprintf("%s-%d", operation, managedCheckpointOperationCounter.Add(1))
			}
		}
		if current := processor.fences[fenceKey(targetID, model)]; current > maxFence {
			maxFence = current
		}
		processor.mu.Unlock()
		if maxFence >= math.MaxInt64 {
			return nil
		}
		fence = uint64(maxFence + 1)
	}
	return &managedCheckpointDriver{handler: handler, cfg: cfg, server: server, targetID: targetID, model: model, runtimeIdentity: runtimeIdentity, profile: profile, contextLimit: contextLimit, generation: generation, operationID: operation, idempotencyPrefix: operation, fence: fence, slot: -1, callSequence: make(map[string]uint64)}
}

func (d *managedCheckpointDriver) CheckpointFence() uint64 {
	if d == nil {
		return 0
	}
	return d.fence
}

func (d *managedCheckpointDriver) call(ctx context.Context, action string, extra map[string]any) (map[string]any, error) {
	if d == nil || d.handler == nil || d.cfg == nil {
		return nil, fmt.Errorf("managed checkpoint command handler is unavailable")
	}
	d.callMu.Lock()
	if d.callSequence == nil {
		d.callSequence = make(map[string]uint64)
	}
	d.callSequence[action]++
	sequence := d.callSequence[action]
	d.callMu.Unlock()
	idempotencyKey := fmt.Sprintf("%s:%s:%d", d.idempotencyPrefix, action, sequence)
	args := map[string]any{
		"target_kind": "llamacpp", "target_id": d.targetID,
		"accelerator_id": fmt.Sprintf("%s-gpu%d", d.cfg.NodeID, d.server.AcceleratorIndex),
		"model":          d.model, "runtime_identity": d.runtimeIdentity,
		"capability_version": d.runtimeIdentity, "capability_revision": domain.CapabilityContractVersion,
		"profile_fingerprint": d.profile, "context_fingerprint": fmt.Sprintf("ctx:%d", d.contextLimit),
		"owner_id": "checkpoint-proof", "workload_id": d.operationID,
		"generation": int64(d.generation), "fencing_token": int64(d.fence), "context_limit": d.contextLimit,
		"checkpoint_action": action, "checkpoint_operation_id": d.operationID,
		"idempotency_key": idempotencyKey,
	}
	if d.slot >= 0 {
		args["slot_id"] = d.slot
	}
	for key, value := range extra {
		args[key] = value
	}
	now := time.Now().UTC()
	command := wsproto.CommandPayload{ID: fmt.Sprintf("%s:%s:%d", d.operationID, action, sequence), IdempotencyKey: idempotencyKey, NodeID: d.cfg.NodeID, Command: "checkpoint_" + action, Args: args, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	if d.cfg.CommandRecoveryEpoch != "" {
		command.Args["recovery_epoch"] = d.cfg.CommandRecoveryEpoch
	}
	signature, err := wsproto.SignCommand(command, []byte(d.cfg.CommandSigningSecret))
	if err != nil {
		return nil, err
	}
	command.Signature = signature
	result := d.handler.Handle(ctx, command)
	if result.Error != "" {
		return nil, fmt.Errorf("checkpoint command %s failed: %s", action, result.Error)
	}
	if result.Result == nil {
		return nil, fmt.Errorf("checkpoint command %s returned no evidence", action)
	}
	return result.Result, nil
}

func (d *managedCheckpointDriver) CheckpointGeneration() uint64 {
	if d == nil {
		return 0
	}
	return d.generation
}

func managedInt(value any) int {
	switch n := value.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	default:
		return -1
	}
}

func (d *managedCheckpointDriver) QuerySlots(ctx context.Context) (runtime.SlotInventory, error) {
	result, err := d.call(ctx, "slot_query", nil)
	if err != nil {
		return runtime.SlotInventory{}, err
	}
	body, _ := json.Marshal(result["slots"])
	var rows []struct {
		ID                 int  `json:"id"`
		ContextLimit       int  `json:"n_ctx"`
		Processing         bool `json:"is_processing"`
		PromptTokens       int  `json:"n_prompt_tokens"`
		CachedPromptTokens int  `json:"n_prompt_tokens_cached"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return runtime.SlotInventory{}, err
	}
	out := runtime.SlotInventory{Slots: make([]runtime.SlotState, 0, len(rows))}
	for _, row := range rows {
		out.Slots = append(out.Slots, runtime.SlotState{ID: row.ID, ContextLimit: row.ContextLimit, Processing: row.Processing, PromptTokens: row.PromptTokens, CachedPromptTokens: row.CachedPromptTokens})
	}
	return out, nil
}

func (d *managedCheckpointDriver) AssignSlot(ctx context.Context, requested int) (runtime.SlotAssignment, error) {
	if requested >= 0 {
		d.slot = requested
	}
	result, err := d.call(ctx, "slot_assign", nil)
	if err != nil {
		return runtime.SlotAssignment{}, err
	}
	d.slot = managedInt(result["slot_id"])
	if d.slot < 0 {
		return runtime.SlotAssignment{}, fmt.Errorf("proof command omitted authoritative slot")
	}
	return runtime.SlotAssignment{SlotID: d.slot, ContextLimit: managedInt(result["context_limit"])}, nil
}

func (d *managedCheckpointDriver) StartCheckpointConversation(ctx context.Context, slot int, conversationID, model string, contextLimit int) error {
	d.slot = slot
	_, err := d.call(ctx, "start", map[string]any{"slot_id": slot, "conversation_id": conversationID, "model": model, "context_limit": contextLimit})
	return err
}

func (d *managedCheckpointDriver) RegisterCheckpointConversation(ctx context.Context, slot int, conversationID, model string, contextLimit int) error {
	d.slot = slot
	_, err := d.call(ctx, "start", map[string]any{"slot_id": slot, "conversation_id": conversationID, "model": model, "context_limit": contextLimit, "managed_stream": true})
	return err
}

func (d *managedCheckpointDriver) PauseAtBoundary(ctx context.Context, slot int) (runtime.SlotBoundary, error) {
	return runtime.SlotBoundary{}, fmt.Errorf("proof pause requires conversation id")
}

func (d *managedCheckpointDriver) PauseAtBoundaryWithConversation(ctx context.Context, slot int, conversationID string) (runtime.SlotBoundary, error) {
	d.slot = slot
	result, err := d.call(ctx, "pause", map[string]any{"slot_id": slot, "conversation_id": conversationID})
	if err != nil {
		return runtime.SlotBoundary{}, err
	}
	var boundary runtime.SlotBoundary
	if value, ok := result["prefix"].([]byte); ok {
		boundary.Prefix = value
	} else if value, ok := result["prefix"].(string); ok {
		boundary.Prefix = []byte(value)
	}
	boundary.TokenCount = managedInt(result["token_count"])
	return boundary, nil
}

func (d *managedCheckpointDriver) SaveKV(ctx context.Context, slot int, name string) (runtime.CheckpointResult, error) {
	d.slot = slot
	d.snapshotName = name
	result, err := d.call(ctx, "save", map[string]any{"slot_id": slot, "snapshot_name": name})
	if err != nil {
		return runtime.CheckpointResult{}, err
	}
	digest := fmt.Sprint(result["snapshot_digest"])
	ref := fmt.Sprint(result["snapshot_ref"])
	if strings.TrimSpace(ref) == "" || ref == "<nil>" || strings.TrimSpace(digest) == "" || digest == "<nil>" {
		return runtime.CheckpointResult{}, fmt.Errorf("checkpoint save omitted authoritative snapshot reference or digest")
	}
	d.snapshotDigest = digest
	return runtime.CheckpointResult{SnapshotRef: ref, SizeBytes: int64(managedInt(result["snapshot_bytes"])), Digest: digest, TokensSaved: managedInt(result["saved_tokens"])}, nil
}

func (d *managedCheckpointDriver) ConfirmStopped(ctx context.Context, slot int) (bool, error) {
	_, err := d.call(ctx, "stop_confirm", map[string]any{"slot_id": slot})
	return err == nil, err
}
func (d *managedCheckpointDriver) ReleaseSlot(ctx context.Context, slot int) error {
	extra := map[string]any{"slot_id": slot}
	if d.snapshotName != "" {
		extra["snapshot_name"] = d.snapshotName
	}
	_, err := d.call(ctx, "release", extra)
	return err
}

// CleanupProductionCheckpoint is the failure-path counterpart to the signed
// proof exercise. It consults the durable phase journal before choosing the
// legal transition: early phases require stop_confirm before release, while a
// reacquired/reloaded slot may release directly. The operation identity and
// fence are never replaced during cleanup, making retries idempotent across a
// reconnect or a process restart.
func (d *managedCheckpointDriver) CleanupProductionCheckpoint(ctx context.Context, slot int, snapshotName string) error {
	if d == nil {
		return fmt.Errorf("managed checkpoint driver is unavailable")
	}
	d.slot = slot
	d.snapshotName = snapshotName
	phase := 0
	if processor, ok := d.handler.(*commandProcessor); ok && processor != nil {
		processor.mu.Lock()
		if state, exists := processor.checkpointPhases[d.operationID]; exists {
			phase = state.Phase
		}
		processor.mu.Unlock()
	}
	if phase != checkpointPhase("release") && phase != 15 && phase < checkpointPhase("stop_confirm") {
		if _, stopErr := d.call(ctx, "stop_confirm", map[string]any{"slot_id": slot}); stopErr != nil {
			// Continue to the release attempt. If the backend cannot confirm a
			// stop, the signed release will fail closed and the caller reports
			// the retained ownership rather than claiming cleanup succeeded.
			if _, releaseErr := d.call(ctx, "release", map[string]any{"slot_id": slot, "snapshot_name": snapshotName}); releaseErr != nil {
				return fmt.Errorf("checkpoint stop cleanup failed: %v; release cleanup failed: %w", stopErr, releaseErr)
			}
			return stopErr
		}
	}
	if phase != checkpointPhase("release") && phase != 15 {
		if _, releaseErr := d.call(ctx, "release", map[string]any{"slot_id": slot, "snapshot_name": snapshotName}); releaseErr != nil {
			return releaseErr
		}
	}
	if strings.TrimSpace(snapshotName) != "" {
		// A successful save may have left an active owner reference. Terminalize
		// and remove exactly this proof's private bundle; missing artifacts are
		// treated as an idempotent completion only after that identity is known.
		if err := FinalizeOwnedCheckpoint(d.cfg.Checkpoint, "checkpoint-proof", snapshotName, d.operationID); err == nil {
			if err := CleanupOwnedCheckpoint(d.cfg.Checkpoint, "checkpoint-proof", snapshotName, d.operationID); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if removeErr := removeFreshCheckpointBundle(d.cfg.Checkpoint, snapshotName); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	return nil
}
func (d *managedCheckpointDriver) Reload(ctx context.Context, slot int) error {
	_, err := d.call(ctx, "reload", map[string]any{"slot_id": slot})
	return err
}
func (d *managedCheckpointDriver) RestoreKV(ctx context.Context, slot int, name string) (runtime.RestoreResult, error) {
	result, err := d.call(ctx, "restore", map[string]any{"slot_id": slot, "snapshot_name": name, "snapshot_digest": d.snapshotDigest})
	return runtime.RestoreResult{TokensRestored: managedInt(result["restored_tokens"])}, err
}
func (d *managedCheckpointDriver) VerifyReuse(ctx context.Context, slot, saved int) (int, error) {
	result, err := d.call(ctx, "reuse_verify", map[string]any{"slot_id": slot, "saved_tokens": saved})
	return managedInt(result["reused_tokens"]), err
}
func (d *managedCheckpointDriver) Resume(ctx context.Context, slot int, hash string, offset int) (string, error) {
	result, err := d.call(ctx, "resume", map[string]any{"slot_id": slot, "partial_output_hash": hash, "partial_output_offset": offset, "continuation_conversation_id": "proof-resume"})
	return fmt.Sprint(result["external_id"]), err
}
func (d *managedCheckpointDriver) ResumeWithConversation(ctx context.Context, slot int, conversationID, hash string, offset int) (string, error) {
	d.slot = slot
	result, err := d.call(ctx, "resume", map[string]any{"slot_id": slot, "continuation_conversation_id": conversationID, "partial_output_hash": hash, "partial_output_offset": offset})
	return fmt.Sprint(result["external_id"]), err
}
func (d *managedCheckpointDriver) ContinueCheckpointConversation(ctx context.Context, slot int, conversationID, model, assistantPrefix string) error {
	d.slot = slot
	_, err := d.call(ctx, "continue", map[string]any{"slot_id": slot, "continuation_conversation_id": conversationID, "assistant_prefix": assistantPrefix, "model": model})
	return err
}

func CheckpointProofDigest(proof runtime.CheckpointCapabilityProof) string {
	return runtime.CheckpointProofDigest(proof)
}

func legacyCheckpointProofDigest(proof runtime.CheckpointCapabilityProof) string {
	material, _ := json.Marshal(struct {
		Verified, ProbeOnly, SlotAssignment, SafeBoundaryPause, SnapshotSave, BackendStopConfirmed, SnapshotRestore, KVReused     bool
		ProvenAt                                                                                                                  time.Time
		NodeID, TargetID, ModelFingerprint, RuntimeIdentity, ProfileFingerprint, EvidenceID, SnapshotDigest, AcceleratorID, Nonce string
		ContextLimit, SlotID                                                                                                      int
		Generation, OldFence, NewFence                                                                                            uint64
		SavedTokens, ReusedTokens                                                                                                 int
		SnapshotBytes                                                                                                             int64
		ExpiresAt                                                                                                                 time.Time
	}{proof.Verified, proof.ProbeOnly, proof.SlotAssignment, proof.SafeBoundaryPause, proof.SnapshotSave, proof.BackendStopConfirmed, proof.SnapshotRestore, proof.KVReused, proof.ProvenAt, proof.NodeID, proof.TargetID, proof.ModelFingerprint, proof.RuntimeIdentity, proof.ProfileFingerprint, proof.EvidenceID, proof.SnapshotDigest, proof.AcceleratorID, proof.Nonce, proof.ContextLimit, proof.SlotID, proof.Generation, proof.OldFence, proof.NewFence, proof.SavedTokens, proof.ReusedTokens, proof.SnapshotBytes, proof.ExpiresAt})
	sum := sha256.Sum256(material)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RotateCheckpointProofNonce is retained for source compatibility but cannot
// issue production proof material without durable locally authorized state.
func RotateCheckpointProofNonce(proof runtime.CheckpointCapabilityProof, secret string) (runtime.CheckpointCapabilityProof, error) {
	return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint proof reissuance requires a durable issuance sidecar")
}

// RotateCheckpointProofNonceDurable is retained for source compatibility but
// remains unavailable until a locally authorized issuance path is integrated.
// Callers cannot reset or initialize the durable epoch from a proof struct.
func RotateCheckpointProofNonceDurable(path string, proof runtime.CheckpointCapabilityProof, secret string) (runtime.CheckpointCapabilityProof, error) {
	return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint proof reissuance requires a locally authorized exercise")
}

// rebindCheckpointProofNonceDurable is reserved for node discovery after it
// has just completed a managed live exercise and re-read the runtime's current
// identity. The signed prior proof is an expected-binding CAS token; this
// transition cannot be requested through a controller command.
func rebindCheckpointProofNonceDurable(path string, prior, proof runtime.CheckpointCapabilityProof, secret string) (runtime.CheckpointCapabilityProof, error) {
	legacyPrior := prior.ProofVersion == ""
	priorDigest := CheckpointProofDigest(prior)
	if legacyPrior {
		priorDigest = legacyCheckpointProofDigest(prior)
	}
	if prior.NodeID == "" || prior.TargetID == "" || prior.NodeID != proof.NodeID || prior.TargetID != proof.TargetID || (!legacyPrior && !prior.ComponentsComplete()) || (legacyPrior && !legacyCheckpointComponentsComplete(prior)) || prior.Digest == "" || prior.Digest != priorDigest || prior.ProvenAt.After(time.Now().Add(2*time.Minute)) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint rebind prior proof is invalid")
	}
	priorMAC := hmac.New(sha256.New, []byte(secret))
	_, _ = priorMAC.Write([]byte(prior.Digest))
	if !hmac.Equal([]byte(prior.Signature), []byte(hex.EncodeToString(priorMAC.Sum(nil)))) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint rebind prior proof signature is invalid")
	}
	if !proof.Complete() {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint rebind proof is incomplete")
	}
	if _, ok := runtime.CheckpointProofIssuanceEpoch(proof.Nonce); !ok {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint rebind proof has no durable epoch")
	}
	if proof.NewFence <= prior.NewFence {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint rebind physical fence did not advance")
	}
	if proof.Generation < prior.Generation {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint rebind generation rolled back")
	}
	if checkpointProofExerciseDigest(proof) == checkpointProofExerciseDigest(prior) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint rebind exercise is not distinct")
	}
	return rotateCheckpointProofNonceDurable(path, proof, &prior, secret)
}

func rotateCheckpointProofNonceDurable(path string, proof runtime.CheckpointCapabilityProof, expectedPrior *runtime.CheckpointCapabilityProof, secret string) (runtime.CheckpointCapabilityProof, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint issuance state path is not canonical")
	}
	if !proof.Complete() || len(secret) < 16 || proof.Digest == "" || proof.Digest != CheckpointProofDigest(proof) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("cannot rotate incomplete checkpoint proof")
	}
	if proof.NodeID == "" || proof.TargetID == "" {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint proof identity is incomplete")
	}
	proofMAC := hmac.New(sha256.New, []byte(secret))
	_, _ = proofMAC.Write([]byte(proof.Digest))
	if !hmac.Equal([]byte(proof.Signature), []byte(hex.EncodeToString(proofMAC.Sum(nil)))) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("cannot rotate checkpoint proof with invalid signature")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return runtime.CheckpointCapabilityProof{}, err
	}
	var issued runtime.CheckpointCapabilityProof
	if err := withCheckpointIssuanceLock(path, func() error {
		if expectedPrior != nil {
			if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
				return fmt.Errorf("checkpoint proof prior sidecar is missing")
			} else if statErr != nil {
				return statErr
			}
		}
		state, err := loadCheckpointProofIssuanceState(path)
		if err != nil {
			return err
		}
		if state.Version == checkpointProofIssuanceStateLegacyVersion && expectedPrior == nil {
			return fmt.Errorf("version-one checkpoint sidecar requires an authenticated expected-prior CAS")
		}
		key := proof.NodeID + "|" + proof.TargetID
		if state.Version == checkpointProofIssuanceStateLegacyVersion && expectedPrior != nil {
			for target := range state.HighWater {
				if target == key {
					// The authenticated prior proof plus the fresh exercise below
					// can safely reconstruct only this target's additive counters.
					continue
				}
				if state.Generations[target] == 0 || state.Fences[target] == 0 || !validCheckpointProofStateDigest(state.Exercises[target]) || state.IssuedAt[target].IsZero() {
					return fmt.Errorf("version-one checkpoint sidecar has an unrelated target without safety counters")
				}
			}
		}
		binding := checkpointProofBindingDigest(proof)
		priorBinding := state.Bindings[key]
		if expectedPrior != nil {
			expectedBinding := checkpointProofBindingDigest(*expectedPrior)
			if expectedPrior.ProofVersion == "" {
				expectedBinding = legacyCheckpointProofBindingDigest(*expectedPrior)
			}
			if priorBinding == "" || priorBinding != expectedBinding {
				return fmt.Errorf("checkpoint proof rebind expected-prior binding comparison failed")
			}
		} else if priorBinding != "" && priorBinding != binding {
			return fmt.Errorf("checkpoint proof immutable exercise binding rolled back")
		}
		if state.Epoch == ^uint64(0) {
			return fmt.Errorf("checkpoint proof issuance epoch exhausted")
		}
		if state.Generations == nil {
			state.Generations = make(map[string]uint64)
		}
		if state.Fences == nil {
			state.Fences = make(map[string]uint64)
		}
		if state.Exercises == nil {
			state.Exercises = make(map[string]string)
		}
		if prior := state.Generations[key]; prior != 0 && proof.Generation < prior {
			return fmt.Errorf("checkpoint proof generation rolled back")
		}
		exercise := checkpointProofExerciseDigest(proof)
		if prior := state.Fences[key]; prior != 0 {
			if proof.NewFence < prior || expectedPrior != nil && proof.NewFence <= prior {
				return fmt.Errorf("checkpoint proof fence rolled back")
			}
			if proof.NewFence == prior && state.Exercises[key] != "" && state.Exercises[key] != exercise {
				return fmt.Errorf("checkpoint proof fence did not advance for a fresh exercise")
			}
		}
		if expectedPrior != nil && proof.NewFence <= expectedPrior.NewFence {
			return fmt.Errorf("checkpoint proof rebind fence did not advance")
		}
		state.Epoch++
		if state.HighWater == nil {
			state.HighWater = make(map[string]uint64)
		}
		if state.Bindings == nil {
			state.Bindings = make(map[string]string)
		}
		if state.IssuedAt == nil {
			state.IssuedAt = make(map[string]time.Time)
		}
		if state.Epoch <= state.HighWater[key] {
			return fmt.Errorf("checkpoint proof issuance high-water comparison failed")
		}
		state.HighWater[key] = state.Epoch
		state.Bindings[key] = binding
		state.Generations[key] = proof.Generation
		state.Fences[key] = proof.NewFence
		state.Exercises[key] = exercise
		state.Version = checkpointProofIssuanceStateVersion
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return err
		}
		now := checkpointProofClock().UTC()
		issued = proof
		issued.Nonce = newCheckpointProofNonce(state.Epoch, now, nonceBytes)
		issued.Digest = CheckpointProofDigest(issued)
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(issued.Digest))
		issued.Signature = hex.EncodeToString(mac.Sum(nil))
		state.IssuedAt[key] = now
		return persistCheckpointProofIssuanceState(path, state)
	}); err != nil {
		return runtime.CheckpointCapabilityProof{}, err
	}
	return issued, nil
}

// withCheckpointIssuanceLock provides a small cross-process compare-and-swap
// boundary. Lock age is not proof of owner death, so a contended lock fails
// closed at timeout and is only recoverable by explicit operator cleanup.
func withCheckpointIssuanceLock(statePath string, fn func() error) error {
	lockPath := statePath + ".lock"
	deadline := time.Now().Add(checkpointIssuanceLockTimeout)
	for {
		lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			createdInfo, statErr := lock.Stat()
			if statErr != nil {
				_ = lock.Close()
				return statErr
			}
			removeOwnedLock := func() {
				currentInfo, currentErr := os.Lstat(lockPath)
				if currentErr == nil && currentInfo.Mode().IsRegular() && os.SameFile(createdInfo, currentInfo) {
					_ = os.Remove(lockPath)
				}
			}
			if err := lock.Chmod(0o600); err != nil {
				_ = lock.Close()
				removeOwnedLock()
				return err
			}
			if _, err := lock.WriteString(strconv.FormatInt(time.Now().UnixNano(), 10)); err != nil {
				_ = lock.Close()
				removeOwnedLock()
				return err
			}
			if err := lock.Sync(); err != nil {
				_ = lock.Close()
				removeOwnedLock()
				return err
			}
			if err := lock.Close(); err != nil {
				removeOwnedLock()
				return err
			}
			defer removeOwnedLock()
			return fn()
		}
		busy := errors.Is(err, os.ErrExist)
		// Windows can report ERROR_ACCESS_DENIED instead of EEXIST while a
		// competing O_EXCL create is racing against the existing lock file.
		// Treat only that platform-specific spelling as contention; all other
		// errors still fail closed immediately.
		if !busy && goruntime.GOOS == "windows" && strings.Contains(strings.ToLower(err.Error()), "access is denied") {
			busy = true
		}
		if !busy {
			return err
		}
		// Never follow a lock symlink while deciding whether it is stale. A
		// malicious link could otherwise make the cleanup remove an unrelated
		// file outside the issuance directory.
		if info, statErr := os.Lstat(lockPath); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
				!singleCheckpointLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
				return fmt.Errorf("checkpoint issuance lock is unsafe")
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("checkpoint issuance state is locked")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func loadCheckpointProofIssuanceState(path string) (checkpointProofIssuanceState, error) {
	state := checkpointProofIssuanceState{Version: checkpointProofIssuanceStateVersion, HighWater: make(map[string]uint64), Bindings: make(map[string]string), Generations: make(map[string]uint64), Fences: make(map[string]uint64), Exercises: make(map[string]string), IssuedAt: make(map[string]time.Time)}
	body, err := readPrivateCheckpointFile(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return state, fmt.Errorf("checkpoint issuance state contains duplicate JSON keys: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return state, fmt.Errorf("checkpoint issuance state must be a JSON object")
	}
	allowed := map[string]struct{}{
		"version": {}, "epoch": {}, "high_water": {}, "bindings": {},
		"generations": {}, "fences": {}, "exercises": {}, "issued_at": {},
	}
	for key, raw := range fields {
		if _, ok := allowed[key]; !ok {
			return state, fmt.Errorf("checkpoint issuance state field %q is unknown or noncanonical", key)
		}
		if string(raw) == "null" {
			return state, fmt.Errorf("checkpoint issuance state field %q may not be null", key)
		}
	}
	for _, key := range []string{"version", "epoch", "high_water", "bindings"} {
		if _, ok := fields[key]; !ok {
			return state, fmt.Errorf("checkpoint issuance state is missing required field %q", key)
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || (state.Version != checkpointProofIssuanceStateVersion && state.Version != checkpointProofIssuanceStateLegacyVersion) || state.Epoch == 0 && len(state.HighWater) > 0 {
		if err == nil {
			err = fmt.Errorf("checkpoint issuance state is invalid")
		}
		return state, err
	}
	if state.Version == checkpointProofIssuanceStateVersion {
		for _, key := range []string{"generations", "fences", "exercises", "issued_at"} {
			if _, ok := fields[key]; !ok {
				return state, fmt.Errorf("version-two checkpoint issuance state is missing safety-counter field %q", key)
			}
		}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return state, fmt.Errorf("checkpoint issuance state contains trailing data")
	}
	if state.HighWater == nil {
		state.HighWater = make(map[string]uint64)
	}
	if state.Bindings == nil {
		state.Bindings = make(map[string]string)
	}
	if state.IssuedAt == nil {
		state.IssuedAt = make(map[string]time.Time)
	}
	if state.Generations == nil {
		state.Generations = make(map[string]uint64)
	}
	if state.Fences == nil {
		state.Fences = make(map[string]uint64)
	}
	if state.Exercises == nil {
		state.Exercises = make(map[string]string)
	}
	if len(state.HighWater) > 10000 || len(state.Bindings) > 10000 || len(state.Generations) > 10000 || len(state.Fences) > 10000 || len(state.Exercises) > 10000 || len(state.IssuedAt) > 10000 {
		return state, fmt.Errorf("checkpoint issuance state exceeds entry bound")
	}
	if state.Version == checkpointProofIssuanceStateVersion &&
		(!sameIssuanceTargetKeys(state.HighWater, state.Bindings) ||
			!sameIssuanceTargetKeys(state.HighWater, state.Generations) ||
			!sameIssuanceTargetKeys(state.HighWater, state.Fences) ||
			!sameIssuanceTargetKeys(state.HighWater, state.Exercises) ||
			!sameIssuanceTargetKeys(state.HighWater, state.IssuedAt)) {
		return state, fmt.Errorf("version-two checkpoint issuance state target maps are incomplete or unbound")
	}
	for key, epoch := range state.HighWater {
		if key == "" || epoch == 0 || !validCheckpointProofStateDigest(state.Bindings[key]) {
			return state, fmt.Errorf("checkpoint issuance state contains an invalid entry")
		}
		if epoch > state.Epoch {
			return state, fmt.Errorf("checkpoint issuance state epoch rolled back")
		}
	}
	for key := range state.Bindings {
		if key == "" || state.HighWater[key] == 0 {
			return state, fmt.Errorf("checkpoint issuance state contains an unbound exercise")
		}
	}
	for key, generation := range state.Generations {
		if key == "" || generation == 0 || state.HighWater[key] == 0 {
			return state, fmt.Errorf("checkpoint issuance state contains an invalid generation")
		}
	}
	for key, fence := range state.Fences {
		if key == "" || fence == 0 || state.HighWater[key] == 0 || !validCheckpointProofStateDigest(state.Exercises[key]) {
			return state, fmt.Errorf("checkpoint issuance state contains an invalid fence")
		}
	}
	for key, exercise := range state.Exercises {
		if key == "" || !validCheckpointProofStateDigest(exercise) || state.HighWater[key] == 0 {
			return state, fmt.Errorf("checkpoint issuance state contains an invalid exercise")
		}
	}
	for key, issuedAt := range state.IssuedAt {
		if key == "" || state.HighWater[key] == 0 || issuedAt.IsZero() || issuedAt.After(time.Now().Add(2*time.Minute)) {
			return state, fmt.Errorf("checkpoint issuance state contains an invalid issued-at entry")
		}
	}
	if state.Version == checkpointProofIssuanceStateVersion {
		for key := range state.HighWater {
			if state.Generations[key] == 0 || state.Fences[key] == 0 || !validCheckpointProofStateDigest(state.Exercises[key]) || state.IssuedAt[key].IsZero() {
				return state, fmt.Errorf("version-two checkpoint issuance target %q is missing safety counters", key)
			}
		}
	}
	return state, nil
}

func sameIssuanceTargetKeys[T any](expected map[string]uint64, actual map[string]T) bool {
	if len(expected) != len(actual) {
		return false
	}
	for key := range expected {
		if _, ok := actual[key]; !ok {
			return false
		}
	}
	return true
}

func persistCheckpointProofIssuanceState(path string, state checkpointProofIssuanceState) error {
	state.Version = checkpointProofIssuanceStateVersion
	if state.HighWater == nil {
		state.HighWater = make(map[string]uint64)
	}
	if state.Bindings == nil {
		state.Bindings = make(map[string]string)
	}
	if state.Generations == nil {
		state.Generations = make(map[string]uint64)
	}
	if state.Fences == nil {
		state.Fences = make(map[string]uint64)
	}
	if state.Exercises == nil {
		state.Exercises = make(map[string]string)
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(body) > 1<<20 || len(state.HighWater) > 10000 || len(state.Bindings) > 10000 || len(state.Generations) > 10000 || len(state.Fences) > 10000 || len(state.Exercises) > 10000 {
		return fmt.Errorf("checkpoint issuance state exceeds configured bound")
	}
	dir := filepath.Dir(path)
	if err := validatePrivateCheckpointDirectory(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proof-issuance-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if goruntime.GOOS != "windows" {
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return nil
}

func LoadSignedCheckpointProof(path, secret string) (runtime.CheckpointCapabilityProof, error) {
	var proof runtime.CheckpointCapabilityProof
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(secret) < 16 {
		return proof, fmt.Errorf("signed checkpoint proof path/secret required")
	}
	body, err := readPrivateCheckpointFile(path, 1<<20)
	if err != nil {
		return proof, err
	}
	if err := validateV2CheckpointProofFile(body); err != nil {
		return proof, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return proof, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return proof, fmt.Errorf("checkpoint proof contains trailing data")
	}
	if !proof.Complete() || time.Now().After(proof.ExpiresAt) || proof.ProvenAt.After(time.Now().Add(2*time.Minute)) {
		return proof, fmt.Errorf("checkpoint proof is incomplete or stale")
	}
	if proof.Digest == "" || proof.Digest != CheckpointProofDigest(proof) {
		return proof, fmt.Errorf("checkpoint proof digest mismatch")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(proof.Digest))
	if !hmac.Equal([]byte(proof.Signature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return proof, fmt.Errorf("checkpoint proof signature mismatch")
	}
	return proof, nil
}

func validateV2CheckpointProofFile(body []byte) error {
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return fmt.Errorf("checkpoint proof contains duplicate JSON keys: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return fmt.Errorf("checkpoint proof must be a JSON object")
	}
	allowed := map[string]struct{}{
		"proof_version": {}, "model_alias": {}, "local_checkpoint_binding": {},
		"verified": {}, "probe_only": {}, "slot_assignment": {}, "safe_boundary_pause": {}, "snapshot_save": {}, "backend_stop_confirmed": {}, "snapshot_restore": {}, "kv_reused": {}, "proven_at": {}, "reason": {}, "node_id": {}, "target_id": {}, "model_fingerprint": {}, "runtime_identity": {}, "profile_fingerprint": {}, "context_limit": {}, "slot_id": {}, "generation": {}, "old_fence": {}, "new_fence": {}, "saved_tokens": {}, "reused_tokens": {}, "evidence_id": {}, "signature": {}, "digest": {}, "snapshot_digest": {}, "snapshot_bytes": {}, "accelerator_id": {}, "expires_at": {}, "nonce": {},
	}
	if len(fields) != len(allowed) {
		return fmt.Errorf("checkpoint proof does not contain the exact v2 field set")
	}
	for key, raw := range fields {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("checkpoint proof field %q is unknown or noncanonical", key)
		}
		if string(raw) == "null" {
			return fmt.Errorf("checkpoint proof field %q may not be null", key)
		}
	}
	return nil
}

// loadSignedCheckpointProofForRebind authenticates an expired proof only as a
// prior-binding CAS token. Its caller must never advertise it; only a fresh
// managed exercise can replace it.
func loadSignedCheckpointProofForRebind(path, secret string) (runtime.CheckpointCapabilityProof, error) {
	var proof runtime.CheckpointCapabilityProof
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(secret) < 16 {
		return proof, fmt.Errorf("signed checkpoint proof path/secret required")
	}
	body, err := readPrivateCheckpointFile(path, 1<<20)
	if err != nil {
		return proof, err
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return proof, fmt.Errorf("checkpoint proof contains duplicate JSON keys: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return proof, fmt.Errorf("checkpoint proof is not a JSON object")
	}
	if _, isV2 := fields["proof_version"]; !isV2 {
		return decodeLegacyCheckpointProofPrior(body, secret)
	}
	if err := validateV2CheckpointProofFile(body); err != nil {
		return proof, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return runtime.CheckpointCapabilityProof{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint proof contains trailing data")
	}
	if !proof.ComponentsComplete() || proof.Digest == "" || proof.Digest != CheckpointProofDigest(proof) || proof.ProvenAt.After(time.Now().Add(2*time.Minute)) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint proof cannot authorize a rebind")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	if !hmac.Equal([]byte(proof.Signature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("checkpoint proof signature mismatch")
	}
	return proof, nil
}

func decodeLegacyCheckpointProofPrior(body []byte, secret string) (runtime.CheckpointCapabilityProof, error) {
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("legacy checkpoint proof contains duplicate JSON keys: %w", err)
	}
	legacyFields := map[string]struct{}{
		"verified": {}, "probe_only": {}, "slot_assignment": {}, "safe_boundary_pause": {}, "snapshot_save": {}, "backend_stop_confirmed": {}, "snapshot_restore": {}, "kv_reused": {}, "proven_at": {}, "reason": {}, "node_id": {}, "target_id": {}, "model_fingerprint": {}, "runtime_identity": {}, "profile_fingerprint": {}, "context_limit": {}, "slot_id": {}, "generation": {}, "old_fence": {}, "new_fence": {}, "saved_tokens": {}, "reused_tokens": {}, "evidence_id": {}, "signature": {}, "digest": {}, "snapshot_digest": {}, "snapshot_bytes": {}, "accelerator_id": {}, "expires_at": {}, "nonce": {},
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("legacy checkpoint proof is not a JSON object")
	}
	for key := range fields {
		if _, ok := legacyFields[key]; !ok {
			return runtime.CheckpointCapabilityProof{}, fmt.Errorf("legacy checkpoint proof contains unknown or noncanonical field %q", key)
		}
		if string(fields[key]) == "null" {
			return runtime.CheckpointCapabilityProof{}, fmt.Errorf("legacy checkpoint proof field %q may not be null", key)
		}
	}
	for key := range legacyFields {
		if key == "reason" {
			continue
		}
		if _, ok := fields[key]; !ok {
			return runtime.CheckpointCapabilityProof{}, fmt.Errorf("legacy checkpoint proof is missing field %q", key)
		}
	}
	var proof runtime.CheckpointCapabilityProof
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return runtime.CheckpointCapabilityProof{}, err
	}
	if !legacyCheckpointComponentsComplete(proof) || proof.Digest == "" || proof.Digest != legacyCheckpointProofDigest(proof) || proof.ProvenAt.After(time.Now().Add(2*time.Minute)) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("legacy checkpoint proof cannot authorize a prior-only migration")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	if !hmac.Equal([]byte(proof.Signature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return runtime.CheckpointCapabilityProof{}, fmt.Errorf("legacy checkpoint proof signature mismatch")
	}
	return proof, nil
}

func legacyCheckpointComponentsComplete(p runtime.CheckpointCapabilityProof) bool {
	return p.Verified && !p.ProbeOnly && p.SlotAssignment && p.SafeBoundaryPause && p.SnapshotSave && p.BackendStopConfirmed && p.SnapshotRestore && p.KVReused &&
		p.NodeID != "" && p.TargetID != "" && p.ModelFingerprint != "" && p.RuntimeIdentity != "" && p.ProfileFingerprint != "" &&
		p.ContextLimit > 0 && p.SlotID >= 0 && p.Generation > 0 && p.NewFence > p.OldFence && p.SavedTokens > 0 && p.ReusedTokens > 0 && p.ReusedTokens <= p.SavedTokens &&
		p.SnapshotBytes > 0 && p.SnapshotDigest != "" && p.EvidenceID != "" && p.Nonce != "" && p.Signature != ""
}

func PersistSignedCheckpointProof(path string, proof runtime.CheckpointCapabilityProof) error {
	if strings.TrimSpace(path) == "" || !proof.Complete() || proof.Digest != CheckpointProofDigest(proof) {
		return fmt.Errorf("cannot persist incomplete checkpoint proof")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("checkpoint proof path is not canonical")
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return fmt.Errorf("checkpoint proof is too large")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := validatePrivateCheckpointDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-proof-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(body)
		if err == nil {
			err = tmp.Sync()
		}
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	// The proof is an admission authority.  Flush both the file and its
	// containing directory so a power loss cannot advertise a name whose
	// contents were never committed. Windows does not permit opening a
	// directory for fsync; the atomic rename still provides the platform's
	// strongest available guarantee there.
	if goruntime.GOOS != "windows" {
		dir, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			return openErr
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func validateCheckpointRoot(cfg CheckpointConfig) error {
	if cfg.Root == "" || !filepath.IsAbs(cfg.Root) || filepath.Clean(cfg.Root) != cfg.Root {
		return fmt.Errorf("checkpoint root is not canonical")
	}
	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(cfg.Root, 0o700)
	info, err := os.Lstat(cfg.Root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("checkpoint root is not a private directory")
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("checkpoint root permissions are too broad")
	}
	return nil
}

func readPrivateCheckpointFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("checkpoint file bound is invalid")
	}
	// Open and validate one descriptor, then read from that same descriptor.
	// safefile selects the platform primitive and has no ordinary-open
	// fallback, so a caller cannot accidentally weaken this boundary.
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(opened) || (goruntime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("checkpoint descriptor is not safe")
	}
	if opened.Size() < 0 || opened.Size() > maxBytes {
		return nil, fmt.Errorf("checkpoint file is too large")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("checkpoint file is too large")
	}
	return body, nil
}

func validatePrivateCheckpointDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("checkpoint parent is not a directory")
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("checkpoint parent permissions are too broad")
	}
	return nil
}

func singleCheckpointLink(info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	// Unix exposes nlink through FileInfo.Sys; on Windows the field is not
	// available and descriptor/ACL checks above remain the strongest portable
	// protection.
	v := reflect.ValueOf(info.Sys())
	if v.IsValid() && v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.IsValid() && v.Kind() == reflect.Struct {
		field := v.FieldByName("Nlink")
		if field.IsValid() && field.CanUint() {
			return field.Uint() <= 1
		}
	}
	return true
}

type checkpointOwnerManifestEntry struct {
	Owner                   string         `json:"owner"`
	SnapshotName            string         `json:"snapshot_name"`
	OperationID             string         `json:"operation_id,omitempty"`
	Bytes                   int64          `json:"bytes"`
	CreatedAt               time.Time      `json:"created_at"`
	ActiveReferences        int            `json:"active_references"`
	Terminalized            bool           `json:"terminalized"`
	TerminalizedOperationID string         `json:"terminalized_operation_id,omitempty"`
	References              map[string]int `json:"references,omitempty"`
}

type checkpointOwnerManifest struct {
	Version string                                  `json:"version"`
	Owner   string                                  `json:"owner"`
	Entries map[string]checkpointOwnerManifestEntry `json:"entries"`
}

func checkpointTerminalizedKey(cfg CheckpointConfig, owner, snapshotName, operationID string) string {
	root := filepath.Clean(cfg.Root)
	return root + "\x00" + owner + "\x00" + snapshotName + "\x00" + operationID
}

func validCheckpointOwner(owner string) bool {
	if owner == "" || len(owner) > 96 || filepath.Base(owner) != owner || strings.ContainsAny(owner, "/\\\\.\x00\r\n") {
		return false
	}
	for _, r := range owner {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func checkpointOwnerManifestPath(cfg CheckpointConfig, owner string) (string, error) {
	if !validCheckpointOwner(owner) {
		return "", fmt.Errorf("checkpoint owner is invalid")
	}
	return filepath.Join(cfg.Root, ".owner-"+owner+".manifest.json"), nil
}

func readCheckpointOwnerManifest(cfg CheckpointConfig, owner string) (checkpointOwnerManifest, error) {
	var manifest checkpointOwnerManifest
	path, err := checkpointOwnerManifestPath(cfg, owner)
	if err != nil {
		return manifest, err
	}
	if err := validatePrivateCheckpointDirectory(cfg.Root); err != nil {
		return manifest, err
	}
	body, err := readPrivateCheckpointFile(path, cfg.MaxMetadataBytes)
	if errors.Is(err, os.ErrNotExist) {
		return checkpointOwnerManifest{Version: "llm-checkpoint-owner-v1", Owner: owner, Entries: make(map[string]checkpointOwnerManifestEntry)}, nil
	}
	if err != nil {
		return manifest, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Version != "llm-checkpoint-owner-v1" || manifest.Owner != owner {
		return manifest, fmt.Errorf("checkpoint owner manifest is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return manifest, fmt.Errorf("checkpoint owner manifest contains trailing data")
	}
	if manifest.Entries == nil {
		manifest.Entries = make(map[string]checkpointOwnerManifestEntry)
	}
	for name, entry := range manifest.Entries {
		if name != entry.SnapshotName || entry.Owner != owner || filepath.Base(name) != name || !strings.HasSuffix(name, ".kv") || entry.Bytes <= 0 || entry.ActiveReferences < 0 {
			return manifest, fmt.Errorf("checkpoint owner manifest entry is invalid")
		}
		if entry.References == nil {
			if entry.ActiveReferences > 0 && entry.OperationID != "" {
				entry.References = map[string]int{entry.OperationID: entry.ActiveReferences}
				manifest.Entries[name] = entry
			}
		} else {
			total := 0
			for operation, references := range entry.References {
				if operation == "" || len(operation) > 128 || references < 0 {
					return manifest, fmt.Errorf("checkpoint owner manifest reference is invalid")
				}
				if references > int(^uint(0)>>1)-total {
					return manifest, fmt.Errorf("checkpoint owner manifest reference count overflow")
				}
				total += references
			}
			if total != entry.ActiveReferences {
				return manifest, fmt.Errorf("checkpoint owner manifest reference count mismatch")
			}
		}
	}
	return manifest, nil
}

func writeCheckpointOwnerManifest(cfg CheckpointConfig, manifest checkpointOwnerManifest) error {
	path, err := checkpointOwnerManifestPath(cfg, manifest.Owner)
	if err != nil {
		return err
	}
	if err := validatePrivateCheckpointDirectory(cfg.Root); err != nil {
		return err
	}
	manifest.Version = "llm-checkpoint-owner-v1"
	if manifest.Entries == nil {
		manifest.Entries = make(map[string]checkpointOwnerManifestEntry)
	}
	// An owner manifest is the durable ownership index, not a permanent
	// marker. Once its last resumable reference is terminalized, remove the
	// empty index so a later recovery cannot mistake an owner with no entries
	// for an active checkpoint holder. The next save recreates it atomically.
	if len(manifest.Entries) == 0 {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		if goruntime.GOOS != "windows" {
			dir, openErr := os.Open(cfg.Root)
			if openErr != nil {
				return openErr
			}
			syncErr := dir.Sync()
			closeErr := dir.Close()
			if syncErr != nil {
				return syncErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		return nil
	}
	body, err := json.Marshal(manifest)
	if err != nil || int64(len(body)) > cfg.MaxMetadataBytes {
		if err == nil {
			err = fmt.Errorf("checkpoint owner manifest exceeds configured bound")
		}
		return err
	}
	tmp, err := os.CreateTemp(cfg.Root, ".owner-manifest-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err == nil {
		if _, err = tmp.Write(body); err == nil {
			err = tmp.Sync()
		}
	} else {
		err = fmt.Errorf("checkpoint owner manifest chmod: %w", err)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if goruntime.GOOS != "windows" {
		dir, openErr := os.Open(cfg.Root)
		if openErr != nil {
			return openErr
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func recordOwnedCheckpoint(cfg CheckpointConfig, owner, snapshotName, operationID string, size int64) error {
	checkpointManifestMu.Lock()
	defer checkpointManifestMu.Unlock()
	if size <= 0 || !validCheckpointSnapshotName(snapshotName) || strings.TrimSpace(operationID) == "" || len(operationID) > 128 {
		return fmt.Errorf("checkpoint ownership entry is invalid")
	}
	manifest, err := readCheckpointOwnerManifest(cfg, owner)
	if err != nil {
		return err
	}
	entry := manifest.Entries[snapshotName]
	previousOperation := entry.OperationID
	entry.Owner, entry.SnapshotName, entry.OperationID, entry.Bytes = owner, snapshotName, operationID, size
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	// One reference belongs to each distinct resumable operation.  A retry of
	// the same operation is idempotent; a later operation sharing the raw KV
	// file adds its own durable reference instead of stealing the first one.
	if entry.References == nil {
		entry.References = make(map[string]int)
		if entry.ActiveReferences > 0 && previousOperation != "" {
			entry.References[previousOperation] = entry.ActiveReferences
		}
	}
	if entry.References[operationID] == 0 {
		entry.References[operationID] = 1
		var refErr error
		entry.ActiveReferences, refErr = checkedCheckpointReferenceAdd(entry.ActiveReferences)
		if refErr != nil {
			return refErr
		}
	}
	entry.Terminalized = false
	entry.TerminalizedOperationID = ""
	checkpointTerminalizedOperations.Delete(checkpointTerminalizedKey(cfg, owner, snapshotName, operationID))
	manifest.Entries[snapshotName] = entry
	return writeCheckpointOwnerManifest(cfg, manifest)
}

func validCheckpointSnapshotName(name string) bool {
	return name != "" && filepath.Base(name) == name && !filepath.IsAbs(name) && !strings.Contains(name, "..") && checkpointSnapshotNameRE.MatchString(name)
}

func markOwnedCheckpointInactive(cfg CheckpointConfig, owner, snapshotName, operationID string) error {
	// checkpoint_release only releases a runtime slot.  It is deliberately not
	// a terminal lifecycle event: the snapshot remains resumable after a slot
	// release and its owner reference must survive node restart/expiry sweeps.
	// Terminal restore/cancel/explicit cleanup calls markOwnedCheckpointTerminal
	// below with an explicit lifecycle reason.
	return nil
}

// markOwnedCheckpointTerminal is the only node-side operation that decrements
// a resumable reference. Callers must have already observed a successful
// restore followed by terminal completion/cancel, or an explicit safe cleanup.
// Once the final reference is gone, the bundle is no longer recoverable and
// is removed together with its owner index; keeping an empty manifest would
// otherwise leave a false ownership marker behind.
func markOwnedCheckpointTerminal(cfg CheckpointConfig, owner, snapshotName, operationID string) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("checkpoint terminal lifecycle requires operation identity")
	}
	checkpointManifestMu.Lock()
	manifest, err := readCheckpointOwnerManifest(cfg, owner)
	if err != nil {
		checkpointManifestMu.Unlock()
		return err
	}
	changed := false
	terminalNames := make([]string, 0, 1)
	for name, entry := range manifest.Entries {
		if snapshotName != "" && name != snapshotName {
			continue
		}
		if operationID != "" {
			// OperationID is retained as the latest writer for backward
			// compatibility, but References is the authoritative set once a
			// snapshot has been shared by more than one resumable operation.
			if entry.References != nil {
				if _, ok := entry.References[operationID]; !ok {
					continue
				}
			} else if entry.OperationID != operationID {
				continue
			}
		}
		if entry.References == nil {
			entry.References = make(map[string]int)
			if entry.ActiveReferences > 0 && entry.OperationID != "" {
				entry.References[entry.OperationID] = entry.ActiveReferences
			}
		}
		if operationID == "" {
			return fmt.Errorf("checkpoint terminal lifecycle requires operation identity")
		}
		if references := entry.References[operationID]; references > 0 {
			if entry.ActiveReferences <= 0 {
				checkpointManifestMu.Unlock()
				return fmt.Errorf("checkpoint owner manifest reference count underflow")
			}
			references--
			if references == 0 {
				delete(entry.References, operationID)
			} else {
				entry.References[operationID] = references
			}
			entry.ActiveReferences--
			entry.Terminalized = entry.ActiveReferences == 0
			if entry.Terminalized {
				entry.TerminalizedOperationID = operationID
			} else {
				entry.TerminalizedOperationID = ""
			}
			manifest.Entries[name] = entry
			changed = true
			if entry.ActiveReferences == 0 {
				terminalNames = append(terminalNames, name)
			}
		}
	}
	if !changed {
		if _, alreadyTerminal := checkpointTerminalizedOperations.Load(checkpointTerminalizedKey(cfg, owner, snapshotName, operationID)); alreadyTerminal {
			checkpointManifestMu.Unlock()
			return nil
		}
		checkpointManifestMu.Unlock()
		return fmt.Errorf("checkpoint terminal lifecycle is not authorized for this owner/operation")
	}
	if err := writeCheckpointOwnerManifest(cfg, manifest); err != nil {
		checkpointManifestMu.Unlock()
		return err
	}
	checkpointManifestMu.Unlock()
	for _, name := range terminalNames {
		if err := removeOwnedCheckpointForOwner(cfg, owner, name); err != nil {
			return err
		}
		checkpointTerminalizedOperations.Store(checkpointTerminalizedKey(cfg, owner, name, operationID), struct{}{})
	}
	return nil
}

// FinalizeOwnedCheckpoint is the explicit lifecycle seam for the controller's
// terminal restore/cancel path. checkpoint_release intentionally does not call
// this seam because a released slot may still be resumable.
func FinalizeOwnedCheckpoint(cfg CheckpointConfig, owner, snapshotName, operationID string) error {
	return markOwnedCheckpointTerminal(cfg, owner, snapshotName, operationID)
}

// CleanupOwnedCheckpoint is an explicit safe-cleanup seam. It requires that
// the operation has already been terminalized (ActiveReferences == 0), and
// therefore cannot delete a resumable snapshot merely because it expired. A
// repeated call is accepted only when this process has already completed the
// same owner/operation transition; a missing manifest or bundle is otherwise
// an authorization failure, not an idempotent success.
func CleanupOwnedCheckpoint(cfg CheckpointConfig, owner, snapshotName string, operationIDs ...string) error {
	if len(operationIDs) != 1 || strings.TrimSpace(operationIDs[0]) == "" {
		return fmt.Errorf("checkpoint cleanup requires operation identity")
	}
	operationID := operationIDs[0]
	if _, ok := checkpointTerminalizedOperations.Load(checkpointTerminalizedKey(cfg, owner, snapshotName, operationID)); ok {
		return nil
	}
	checkpointManifestMu.Lock()
	defer checkpointManifestMu.Unlock()
	manifest, err := readCheckpointOwnerManifest(cfg, owner)
	if err != nil {
		return err
	}
	entry, claimed := manifest.Entries[snapshotName]
	if !claimed || entry.Owner != owner || entry.ActiveReferences > 0 || !entry.Terminalized {
		return fmt.Errorf("checkpoint cleanup is not authorized for this owner")
	}
	provenOperation := entry.TerminalizedOperationID
	if provenOperation == "" {
		// Entries written by an older agent did not persist the finalizing
		// operation separately.  Their latest operation is the narrowest
		// compatibility proof available; never accept an arbitrary caller.
		provenOperation = entry.OperationID
	}
	if provenOperation != operationID {
		return fmt.Errorf("checkpoint cleanup is not authorized for this operation")
	}
	if err := removeOwnedCheckpointForOwner(cfg, owner, snapshotName); err != nil {
		return err
	}
	checkpointTerminalizedOperations.Store(checkpointTerminalizedKey(cfg, owner, snapshotName, operationID), struct{}{})
	return nil
}

func cleanupCheckpointRoot(cfg CheckpointConfig) {
	checkpointManifestMu.Lock()
	defer checkpointManifestMu.Unlock()
	if cfg.ExpirySeconds <= 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(cfg.ExpirySeconds) * time.Second)
	entries, err := os.ReadDir(cfg.Root)
	if err != nil {
		return
	}
	for _, manifestEntry := range entries {
		if manifestEntry.IsDir() || !strings.HasPrefix(manifestEntry.Name(), ".owner-") || !strings.HasSuffix(manifestEntry.Name(), ".manifest.json") {
			continue
		}
		owner := strings.TrimSuffix(strings.TrimPrefix(manifestEntry.Name(), ".owner-"), ".manifest.json")
		manifest, readErr := readCheckpointOwnerManifest(cfg, owner)
		if readErr != nil {
			continue
		}
		changed := false
		for name, owned := range manifest.Entries {
			if owned.ActiveReferences != 0 || !owned.Terminalized || owned.CreatedAt.IsZero() || !owned.CreatedAt.Before(cutoff) {
				continue
			}
			base := filepath.Join(cfg.Root, name)
			info, statErr := os.Lstat(base)
			if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0)) {
				continue
			}
			cleanupOK := true
			for _, path := range []string{base, base + ".json", base + ".commit"} {
				if removeErr := removePrivateCheckpointArtifact(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					// Keep the manifest as a durable retry handle when any
					// artifact fails closed.  In particular, never delete an
					// ownership record while a symlink/foreign hardlink remains.
					cleanupOK = false
					break
				}
			}
			if !cleanupOK {
				continue
			}
			delete(manifest.Entries, name)
			changed = true
		}
		if changed {
			_ = writeCheckpointOwnerManifest(cfg, manifest)
			if goruntime.GOOS != "windows" {
				if dir, openErr := os.Open(cfg.Root); openErr == nil {
					_ = dir.Sync()
					_ = dir.Close()
				}
			}
		}
	}
}

func checkpointQuotaAllowed(cfg CheckpointConfig, owner, snapshotName string, extra int64) error {
	if extra < 0 || cfg.MaxBytes <= 0 || cfg.MaxFiles <= 0 || !validCheckpointOwner(owner) || (snapshotName != "" && !validCheckpointSnapshotName(snapshotName)) {
		return fmt.Errorf("checkpoint quotas are not configured")
	}
	globalBytes, ownerBytes, globalFiles, ownerFiles := int64(0), int64(0), 0, 0
	var replacementBytes int64
	ownerManifest, manifestErr := readCheckpointOwnerManifest(cfg, owner)
	if manifestErr != nil {
		return manifestErr
	}
	exists := false
	entries, err := os.ReadDir(cfg.Root)
	if err != nil {
		return err
	}
	for _, dir := range entries {
		if !dir.IsDir() {
			if strings.HasSuffix(dir.Name(), ".kv") {
				path := filepath.Join(cfg.Root, dir.Name())
				info, statErr := os.Lstat(path)
				if statErr != nil {
					return statErr
				}
				if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
					return fmt.Errorf("checkpoint slot file is not a regular file")
				}
				var addErr error
				globalBytes, addErr = checkedCheckpointAdd(globalBytes, info.Size())
				if addErr != nil {
					return addErr
				}
				globalFiles, addErr = checkedCheckpointFileCount(globalFiles)
				if addErr != nil {
					return addErr
				}
				// Root-level llama.cpp files are shared storage. Charge them to an
				// owner only when its durable manifest explicitly claims the file.
				if claimed, ok := ownerManifest.Entries[dir.Name()]; ok && claimed.Owner == owner {
					ownerBytes, addErr = checkedCheckpointAdd(ownerBytes, claimed.Bytes)
					if addErr != nil {
						return addErr
					}
					ownerFiles, addErr = checkedCheckpointFileCount(ownerFiles)
					if addErr != nil {
						return addErr
					}
				}
				if dir.Name() == snapshotName {
					if claimed, ok := ownerManifest.Entries[dir.Name()]; ok && claimed.Owner == owner {
						exists = true
						replacementBytes = claimed.Bytes
					}
				}
			}
			continue
		}
		if dir.Name() == "." || dir.Name() == ".." {
			continue
		}
		dirPath := filepath.Join(cfg.Root, dir.Name())
		dirInfo, dirErr := os.Lstat(dirPath)
		if dirErr != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || (goruntime.GOOS != "windows" && dirInfo.Mode().Perm()&0o077 != 0) {
			return fmt.Errorf("checkpoint owner directory is not a private directory")
		}
		files, readErr := os.ReadDir(dirPath)
		if readErr != nil {
			return readErr
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".kv") {
				continue
			}
			path := filepath.Join(dirPath, file.Name())
			info, statErr := os.Lstat(path)
			if statErr != nil {
				return statErr
			}
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
				return fmt.Errorf("checkpoint slot file is not a regular file")
			}
			var addErr error
			globalBytes, addErr = checkedCheckpointAdd(globalBytes, info.Size())
			if addErr != nil {
				return addErr
			}
			globalFiles, addErr = checkedCheckpointFileCount(globalFiles)
			if addErr != nil {
				return addErr
			}
			if dir.Name() == owner {
				ownerBytes, addErr = checkedCheckpointAdd(ownerBytes, info.Size())
				if addErr != nil {
					return addErr
				}
				ownerFiles, addErr = checkedCheckpointFileCount(ownerFiles)
				if addErr != nil {
					return addErr
				}
				if file.Name() == snapshotName {
					exists = true
					replacementBytes = info.Size()
				}
			}
		}
	}
	newFile := 0
	if !exists {
		newFile = 1
	}
	newBytes, arithmeticErr := checkedCheckpointReplacement(globalBytes, extra, replacementBytes)
	if arithmeticErr != nil {
		return arithmeticErr
	}
	globalFileCount := globalFiles
	if newFile != 0 {
		globalFileCount, arithmeticErr = checkedCheckpointFileCount(globalFileCount)
		if arithmeticErr != nil {
			return arithmeticErr
		}
	}
	if newBytes > cfg.MaxBytes || globalFileCount > cfg.MaxFiles {
		return fmt.Errorf("checkpoint global quota exceeded")
	}
	ownerNewBytes, arithmeticErr := checkedCheckpointReplacement(ownerBytes, extra, replacementBytes)
	if arithmeticErr != nil {
		return arithmeticErr
	}
	ownerFileCount := ownerFiles
	if newFile != 0 {
		ownerFileCount, arithmeticErr = checkedCheckpointFileCount(ownerFileCount)
		if arithmeticErr != nil {
			return arithmeticErr
		}
	}
	if ownerNewBytes > cfg.PerOwnerMaxBytes || ownerFileCount > cfg.PerOwnerMaxFiles {
		return fmt.Errorf("checkpoint owner quota exceeded")
	}
	return nil
}

func removeOwnedCheckpointForOwner(cfg CheckpointConfig, owner, snapshotName string) error {
	if !validCheckpointSnapshotName(snapshotName) {
		return fmt.Errorf("invalid checkpoint snapshot name")
	}
	manifest, err := readCheckpointOwnerManifest(cfg, owner)
	if err != nil {
		return err
	}
	entry, claimed := manifest.Entries[snapshotName]
	if !claimed || entry.Owner != owner || entry.ActiveReferences > 0 || !entry.Terminalized {
		return fmt.Errorf("checkpoint cleanup is not authorized for this owner")
	}
	root := cfg.Root
	path := filepath.Join(root, snapshotName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// A prior terminal cleanup may have removed the primary bundle before a
		// crash.  Treat that exact owner/operation manifest as an idempotent
		// completion, but still retire any private sidecars and the durable
		// owner entry.  Leaving a zero-reference manifest behind would make
		// restart/retry cleanup scan it forever and falsely suggest ownership.
		for _, candidate := range []string{path + ".json", path + ".commit"} {
			if removeErr := removePrivateCheckpointArtifact(candidate); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return removeErr
			}
		}
		delete(manifest.Entries, snapshotName)
		return writeCheckpointOwnerManifest(cfg, manifest)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return fmt.Errorf("checkpoint cleanup target is not a regular file")
	}
	for _, candidate := range []string{path, path + ".json", path + ".commit"} {
		if removeErr := removePrivateCheckpointArtifact(candidate); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	delete(manifest.Entries, snapshotName)
	if err := writeCheckpointOwnerManifest(cfg, manifest); err != nil {
		return err
	}
	if goruntime.GOOS != "windows" {
		dir, openErr := os.Open(root)
		if openErr != nil {
			return openErr
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return nil
}

// removeFreshCheckpointBundle is used only when the current save operation
// proved that the exact root filename did not exist before the runtime call.
// It is deliberately separate from owner-manifest cleanup: an uncommitted
// manifest must never authorize deletion of a pre-existing owner's file.
func removeFreshCheckpointBundle(cfg CheckpointConfig, snapshotName string) error {
	if !validCheckpointSnapshotName(snapshotName) {
		return fmt.Errorf("invalid checkpoint snapshot name")
	}
	path := filepath.Join(cfg.Root, snapshotName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) {
		return fmt.Errorf("checkpoint cleanup target is not a private regular file")
	}
	for _, candidate := range []string{path, path + ".json", path + ".commit"} {
		if removeErr := removePrivateCheckpointArtifact(candidate); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	if goruntime.GOOS != "windows" {
		dir, openErr := os.Open(cfg.Root)
		if openErr != nil {
			return openErr
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return nil
}

// removePrivateCheckpointArtifact validates each pathname immediately before
// unlinking it. os.Remove unlinks a symlink rather than following it, but a
// symlink/foreign hardlink is still an integrity violation and must fail
// closed instead of silently changing the checkpoint bundle.
func removePrivateCheckpointArtifact(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return fmt.Errorf("checkpoint artifact is not a private regular file")
	}
	return os.Remove(path)
}

// removeOwnedCheckpoint is retained for callers that predate owner manifests.
// It scans manifests and deletes only an explicitly owned inactive reference;
// an unowned/raw path is never treated as controller-owned.
func removeOwnedCheckpoint(cfg CheckpointConfig, snapshotName string) error {
	if snapshotName == "" || filepath.Base(snapshotName) != snapshotName || !strings.HasSuffix(snapshotName, ".kv") {
		return fmt.Errorf("invalid checkpoint snapshot name")
	}
	entries, err := os.ReadDir(cfg.Root)
	if err != nil {
		return err
	}
	for _, item := range entries {
		if item.IsDir() || !strings.HasPrefix(item.Name(), ".owner-") || !strings.HasSuffix(item.Name(), ".manifest.json") {
			continue
		}
		owner := strings.TrimSuffix(strings.TrimPrefix(item.Name(), ".owner-"), ".manifest.json")
		manifest, readErr := readCheckpointOwnerManifest(cfg, owner)
		if readErr != nil {
			continue
		}
		if _, ok := manifest.Entries[snapshotName]; ok {
			return removeOwnedCheckpointForOwner(cfg, owner, snapshotName)
		}
	}
	return fmt.Errorf("checkpoint cleanup owner manifest is missing")
}

// ApplyProductionCheckpointProof is retained for source compatibility but
// remains fail-closed until a trusted local launch-plan/unit authority is
// integrated. Callers cannot supply a binding string or proof callback to
// create that authority.
func ApplyProductionCheckpointProof(advertisement *wsproto.AdapterAdvertisement, _ runtime.CheckpointCapabilityProof) error {
	if advertisement == nil {
		return fmt.Errorf("nil adapter advertisement")
	}
	clearCheckpointCapability(advertisement)
	return fmt.Errorf("production checkpoint proof requires a locally established launch-plan and unit binding")
}

func clearCheckpointCapability(advertisement *wsproto.AdapterAdvertisement) {
	if advertisement == nil {
		return
	}
	advertisement.CheckpointProof = runtime.CheckpointCapabilityProof{}
	advertisement.Capabilities.SupportsSessionCheckpoint = false
	advertisement.Capabilities.SessionCheckpointVerified = false
	advertisement.Capabilities.SessionCheckpointProof = ""
}
