// Package store defines the controller's persistence interfaces. MemoryStore
// supports deterministic development; PostgresWorkloadStore implements the
// aggregate production store defined by the ordered migrations/0001 through
// 0022 (ending at 0022_llm_displacement.sql).
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

var ErrNotFound = errors.New("store: not found")

var ErrLLMCheckpointConflict = errors.New("store: llm checkpoint operation conflict")

// ErrLLMCheckpointNotFound is returned by recovery readers when the node has
// no durable phase journal for the requested operation.  Keeping this distinct
// from the generic store not-found error lets the controller distinguish an
// authoritative node answer from a transport or database failure.
var ErrLLMCheckpointNotFound = errors.New("store: llm checkpoint operation not_found")

var ErrLLMDisplacementConflict = errors.New("store: llm displacement operation conflict")

// LLMDisplacementStore is intentionally a narrow durable journal surface. It
// records controller intent and later observations supplied by a trusted
// integration; it does not execute or attest physical accelerator effects.
type LLMDisplacementStore interface {
	CreateLLMDisplacementOperation(context.Context, *LLMDisplacementOperation) (*LLMDisplacementOperation, bool, error)
	GetLLMDisplacementOperation(context.Context, string) (*LLMDisplacementOperation, error)
	GetLLMDisplacementOperationByIdempotency(context.Context, string, string) (*LLMDisplacementOperation, error)
	UpdateLLMDisplacementOperation(context.Context, *LLMDisplacementOperation, uint64) (*LLMDisplacementOperation, error)
	ListLLMDisplacementOperations(context.Context, string) ([]*LLMDisplacementOperation, error)
}

// llmCheckpointTerminalPhases is the shared phase set used by both stores and
// mirrored by migrations/0021_llm_checkpoints.sql.  A row in one of these
// phases no longer owns a physical slot.  "released" is included because a
// successfully saved checkpoint has released its old slot, but it may still
// be resumed; the update guard below therefore permits released -> restore
// phases while still forbidding final rows from being reopened.
var llmCheckpointTerminalPhases = map[string]struct{}{
	"completed":      {},
	"failed":         {},
	"cancelled":      {},
	"released":       {},
	"restore_failed": {},
}

// llmCheckpointFinalPhases cannot be resumed after their terminal cleanup has
// completed.  "released" is a slot-terminal phase, rather than an operation
// terminal phase: a saved checkpoint can legally progress through restore_*.
var llmCheckpointFinalPhases = map[string]struct{}{
	"completed":      {},
	"failed":         {},
	"cancelled":      {},
	"restore_failed": {},
}

func llmCheckpointPhaseIsTerminal(phase string) bool {
	_, ok := llmCheckpointTerminalPhases[phase]
	return ok
}

func llmCheckpointPhaseIsFinal(phase string) bool {
	_, ok := llmCheckpointFinalPhases[phase]
	return ok
}

func llmCheckpointHoldsSlot(phase string) bool {
	return !llmCheckpointPhaseIsTerminal(phase)
}

// validateLLMCheckpointRequiredIdentity is intentionally shared by create and
// update.  The controller needs these fields to bind a durable row to one
// owner/workload/fence; accepting a partially populated replay would allow a
// caller to retarget an existing operation after restart.
func validateLLMCheckpointRequiredIdentity(op *LLMCheckpointOperation) error {
	// Every field that can select a physical runtime is part of the durable
	// identity.  In particular, do not accept a row with only owner/workload
	// fields populated: after restart that would allow a late result from one
	// node/accelerator/model to be replayed against another.
	if op == nil || strings.TrimSpace(op.ID) == "" || strings.TrimSpace(op.IdempotencyKey) == "" || strings.TrimSpace(op.OwnerID) == "" || strings.TrimSpace(op.WorkloadID) == "" || strings.TrimSpace(op.NodeID) == "" || strings.TrimSpace(op.TargetID) == "" || strings.TrimSpace(op.AcceleratorID) == "" || strings.TrimSpace(op.RuntimeIdentity) == "" || strings.TrimSpace(op.Model) == "" || strings.TrimSpace(op.ModelFingerprint) == "" || strings.TrimSpace(op.ProfileFingerprint) == "" || strings.TrimSpace(op.ContextFingerprint) == "" || op.Generation == 0 || op.Fence == 0 || strings.TrimSpace(op.Phase) == "" {
		return errors.New("checkpoint operation identity is incomplete")
	}
	if op.WorkloadRevision == 0 {
		return errors.New("checkpoint operation workload revision is required")
	}
	if op.PhaseOrdinal <= 0 || llmCheckpointPhaseOrdinal(op.Phase) <= 0 || op.PhaseOrdinal != llmCheckpointPhaseOrdinal(op.Phase) {
		return errors.New("checkpoint operation phase or ordinal is invalid")
	}
	if strings.TrimSpace(op.ConversationID) == "" {
		return errors.New("checkpoint operation conversation identity is incomplete")
	}
	if op.SlotID < -1 {
		return errors.New("checkpoint operation slot is invalid")
	}
	if err := validateLLMCheckpointCleanup(op); err != nil {
		return err
	}
	return nil
}

func validateLLMCheckpointCleanup(op *LLMCheckpointOperation) error {
	if op == nil || op.CleanupState == "" {
		return nil
	}
	switch op.CleanupState {
	case "armed", "owned", "pending", "failed", "stopped", "confirmed":
	default:
		return errors.New("checkpoint cleanup state is invalid")
	}
	if op.CleanupState == "confirmed" {
		return nil
	}
	if strings.TrimSpace(op.CleanupTargetID) == "" || strings.TrimSpace(op.CleanupAcceleratorID) == "" || op.CleanupFence == 0 || op.CleanupGeneration == 0 {
		return errors.New("checkpoint cleanup identity is incomplete")
	}
	if op.CleanupSlotID < -1 {
		return errors.New("checkpoint cleanup slot is invalid")
	}
	if op.CleanupHandle != nil && strings.TrimSpace(op.CleanupHandle.ExternalID) == "" {
		return errors.New("checkpoint cleanup handle identity is incomplete")
	}
	if op.CleanupTerminalDisposition != "" && op.CleanupTerminalDisposition != "success" && op.CleanupTerminalDisposition != "failure" && op.CleanupTerminalDisposition != "cancel" {
		return errors.New("checkpoint cleanup terminal disposition is invalid")
	}
	if len(op.CleanupMessage) > 2048 {
		return errors.New("checkpoint cleanup message is too long")
	}
	return nil
}

// llmCheckpointPhaseOrdinal is the shared lifecycle vocabulary.  The values
// intentionally match the node phase journal (with planned/restore_planned
// representing controller-only durable intent).  There are no implicit
// numeric gaps that permit a caller to manufacture an intermediate phase.
func llmCheckpointPhaseOrdinal(phase string) int {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "planned":
		return 1
	case "assigned":
		return 1
	case "started":
		return 2
	case "paused":
		return 3
	case "saved":
		return 4
	case "stopped":
		return 5
	case "released":
		return 6
	case "restore_planned":
		return 6
	case "restore_assigned":
		return 8
	case "reloaded":
		return 9
	case "restored":
		return 10
	case "resumed":
		return 11
	case "continued":
		return 12
	case "reused":
		return 13
	case "completed", "failed", "cancelled", "restore_failed":
		return 15
	default:
		return 0
	}
}

func llmCheckpointPhaseKnown(phase string) bool { return llmCheckpointPhaseOrdinal(phase) > 0 }

// llmCheckpointIdentityEqual covers the complete immutable replay identity.
// Lifecycle phase, slot assignment, snapshot/output metadata, timestamps,
// error text, and revision are mutable and deliberately excluded. SlotID is
// included by sameLLMCheckpointIdentity for duplicate creates because a
// duplicate create must describe the same initial allocation request; updates
// use llmCheckpointImmutableIdentityEqual and permit assignment changes.
func llmCheckpointIdentityEqual(a, b *LLMCheckpointOperation, includeSlot bool) bool {
	if a == nil || b == nil {
		return false
	}
	return a.ID == b.ID &&
		a.IdempotencyKey == b.IdempotencyKey &&
		a.OwnerID == b.OwnerID &&
		a.WorkloadID == b.WorkloadID &&
		a.WorkloadRevision == b.WorkloadRevision &&
		a.NodeID == b.NodeID &&
		a.AcceleratorID == b.AcceleratorID &&
		a.TargetID == b.TargetID &&
		a.Model == b.Model &&
		(!includeSlot || a.SlotID == b.SlotID) &&
		a.Generation == b.Generation &&
		a.Fence == b.Fence &&
		a.RuntimeIdentity == b.RuntimeIdentity &&
		a.ModelFingerprint == b.ModelFingerprint &&
		a.ProfileFingerprint == b.ProfileFingerprint &&
		a.ContextFingerprint == b.ContextFingerprint &&
		a.ConversationID == b.ConversationID &&
		a.ContinuationConversationID == b.ContinuationConversationID &&
		a.CompensationOf == b.CompensationOf
}

func sameLLMCheckpointIdentity(a, b *LLMCheckpointOperation) bool {
	return llmCheckpointIdentityEqual(a, b, true)
}

func llmCheckpointImmutableIdentityEqual(a, b *LLMCheckpointOperation) bool {
	return llmCheckpointIdentityEqual(a, b, false)
}

func canonicalLLMCheckpointTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	// PostgreSQL TIMESTAMPTZ stores microseconds. Truncating before encoding
	// keeps the embedded JSON timestamp byte-for-byte equal to the indexed
	// value after a database round trip, and gives Memory the same contract.
	return t.UTC().Truncate(time.Microsecond)
}

func prepareLLMCheckpointCreate(op *LLMCheckpointOperation) (*LLMCheckpointOperation, error) {
	if op == nil {
		return nil, errors.New("checkpoint operation identity is incomplete")
	}
	copy := cloneLLMCheckpointOperation(op)
	if strings.TrimSpace(copy.ConversationID) == "" {
		seed := sha256.Sum256([]byte(copy.OwnerID + "|" + copy.WorkloadID + "|" + fmt.Sprint(copy.Generation) + "|" + fmt.Sprint(copy.Fence) + "|" + copy.ID))
		copy.ConversationID = "conv-" + hex.EncodeToString(seed[:12])
	}
	if copy.PhaseOrdinal == 0 {
		copy.PhaseOrdinal = llmCheckpointPhaseOrdinal(copy.Phase)
	}
	// A create is a durable root assertion, not a generic phase setter.  The
	// ordinary lifecycle always starts at planned.  Restore/compensation rows
	// may start at restore_planned only when they carry the snapshot and an
	// explicit durable recovery justification; every other phase must be
	// reached through UpdateLLMCheckpointOperation's transition DAG.
	switch strings.ToLower(strings.TrimSpace(copy.Phase)) {
	case "planned":
		if copy.SnapshotName != "" || copy.CompensationOf != "" || copy.RecoveryState != "" {
			return nil, errors.New("checkpoint planned root has unexpected recovery identity")
		}
	case "restore_planned":
		if strings.TrimSpace(copy.SnapshotName) == "" || (strings.TrimSpace(copy.CompensationOf) == "" && strings.TrimSpace(copy.RecoveryState) != "pending" && copy.WorkloadRevision == 0) {
			return nil, errors.New("checkpoint restore root requires snapshot and recovery justification")
		}
	default:
		return nil, errors.New("checkpoint create phase must be planned or justified restore_planned")
	}
	if err := validateLLMCheckpointRequiredIdentity(copy); err != nil {
		return nil, err
	}
	copy.Revision = 1
	if copy.CreatedAt.IsZero() {
		copy.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		copy.CreatedAt = canonicalLLMCheckpointTime(copy.CreatedAt)
	}
	if copy.UpdatedAt.IsZero() {
		copy.UpdatedAt = copy.CreatedAt
	} else {
		copy.UpdatedAt = canonicalLLMCheckpointTime(copy.UpdatedAt)
	}
	return copy, nil
}

func llmCheckpointTransitionAllowed(from, to string) bool {
	if from == "" || to == "" {
		return false
	}
	if from == to {
		return true
	}
	if !llmCheckpointPhaseKnown(from) || !llmCheckpointPhaseKnown(to) || llmCheckpointPhaseIsFinal(from) {
		return false
	}
	// Controller-only intent and node-observed phases form an explicit DAG.
	// In particular, assigned -> saved is not a legal replay: pause and stop
	// evidence must be durable before a snapshot can be accepted.
	allowed := map[string]map[string]struct{}{
		// Forward success transitions are deliberately one edge at a time.  The
		// terminal failure/cancel edges are compensation edges and do not permit
		// a successful lifecycle to skip physical evidence.
		"planned":  {"assigned": {}, "failed": {}, "cancelled": {}},
		"assigned": {"started": {}, "failed": {}, "cancelled": {}},
		// A native stream that reaches EOF without preemption has no pause/save
		// artifact.  The signed terminal observer records stop evidence directly
		// from started before releasing the slot; this edge is still explicit and
		// keeps the normal lifecycle inside the same DAG as checkpointed paths.
		"started": {"paused": {}, "stopped": {}, "failed": {}, "cancelled": {}},
		"paused":  {"saved": {}, "failed": {}, "cancelled": {}},
		"saved":   {"stopped": {}, "failed": {}, "cancelled": {}},
		"stopped": {"released": {}, "failed": {}, "cancelled": {}},
		// A released source row may be terminalized after a restore operation
		// adopts its snapshot.  This is the one cleanup edge that closes the
		// original ownership record without pretending it re-entered restore.
		"released":         {"restore_planned": {}, "completed": {}, "failed": {}, "cancelled": {}},
		"restore_planned":  {"restore_assigned": {}, "restore_failed": {}, "failed": {}, "cancelled": {}},
		"restore_assigned": {"reloaded": {}, "restore_failed": {}, "failed": {}, "cancelled": {}},
		"reloaded":         {"restored": {}, "restore_failed": {}, "failed": {}, "cancelled": {}},
		"restored":         {"resumed": {}, "restore_failed": {}, "failed": {}, "cancelled": {}},
		"resumed":          {"continued": {}, "restore_failed": {}, "failed": {}, "cancelled": {}},
		"continued":        {"reused": {}, "restore_failed": {}, "failed": {}, "cancelled": {}},
		"reused":           {"completed": {}, "failed": {}, "cancelled": {}},
	}
	_, ok := allowed[from][to]
	return ok
}

// llmCheckpointTransitionAllowedFor is the operation-aware form used by the
// stores.  A restored assignment carries a snapshot identity and is distinct
// from the initial assignment even though both use the node action
// "slot_assign".  Keeping that distinction here prevents a fresh caller from
// skipping restore_planned/reload/restore.
func llmCheckpointTransitionAllowedFor(from, to *LLMCheckpointOperation) bool {
	if from == nil || to == nil {
		return false
	}
	if from.Phase == to.Phase {
		return true
	}
	return llmCheckpointTransitionAllowed(from.Phase, to.Phase)
}

// LLMCheckpointOperation is the durable recovery record for one checkpoint
// lifecycle. It deliberately carries the complete runtime identity rather
// than a target name so restart and late-result reconciliation can fail closed.
type LLMCheckpointOperation struct {
	ID                         string `json:"id"`
	IdempotencyKey             string `json:"idempotency_key"`
	OwnerID                    string `json:"owner_id,omitempty"`
	WorkloadID                 string `json:"workload_id,omitempty"`
	NodeID                     string `json:"node_id,omitempty"`
	AcceleratorID              string `json:"accelerator_id,omitempty"`
	TargetID                   string `json:"target_id,omitempty"`
	Model                      string `json:"model,omitempty"`
	SlotID                     int    `json:"slot_id"`
	Generation                 uint64 `json:"generation"`
	Fence                      uint64 `json:"fence"`
	RuntimeIdentity            string `json:"runtime_identity,omitempty"`
	ModelFingerprint           string `json:"model_fingerprint,omitempty"`
	ProfileFingerprint         string `json:"profile_fingerprint,omitempty"`
	ContextFingerprint         string `json:"context_fingerprint,omitempty"`
	ConversationID             string `json:"conversation_id,omitempty"`
	ContinuationConversationID string `json:"continuation_conversation_id,omitempty"`
	CompensationOf             string `json:"compensation_of,omitempty"`
	// WorkloadRevision binds a compensation/recovery intent to the exact
	// workload projection that was being replaced.  It is intentionally
	// mutable only through the recovery-state fields below; the original
	// revision remains part of the immutable intent identity.
	WorkloadRevision         uint64 `json:"workload_revision,omitempty"`
	RecoveryWorkloadRevision uint64 `json:"recovery_workload_revision,omitempty"`
	RecoveryState            string `json:"recovery_state,omitempty"`
	// RecoveryHandle/Fence are written after a physical restore has accepted
	// the fresh lease and before the outer workload CAS adopts it.  Keeping the
	// exact fresh handle here prevents restart recovery from mistaking the stale
	// pre-checkpoint execution in the workload row for the restored stream.
	RecoveryHandle        *domain.ExecutionHandle `json:"recovery_handle,omitempty"`
	RecoveryFence         uint64                  `json:"recovery_fence,omitempty"`
	RecoveryAcceleratorID string                  `json:"recovery_accelerator_id,omitempty"`
	// Cleanup* is the durable custody record for a physical resumed
	// generation that has not yet crossed its terminal stop/release boundary.
	// It is separate from Recovery* because a normal post-resume execution may
	// have no outer-CAS compensation, while still needing restart-safe cleanup
	// after a refresh/publication/yield failure or a controller crash.
	// CleanupOperationID/CleanupSlotID identify the physical node operation,
	// rather than the controller's outer recovery row.  A native node can only
	// authorize a cancel when this exact operation and its assigned slot are
	// replayed with the original generation/fence.
	CleanupOperationID                string                  `json:"cleanup_operation_id,omitempty"`
	CleanupSlotID                     int                     `json:"cleanup_slot_id"`
	CleanupConversationID             string                  `json:"cleanup_conversation_id,omitempty"`
	CleanupContinuationConversationID string                  `json:"cleanup_continuation_conversation_id,omitempty"`
	CleanupState                      string                  `json:"cleanup_state,omitempty"`
	CleanupHandle                     *domain.ExecutionHandle `json:"cleanup_handle,omitempty"`
	CleanupTargetID                   string                  `json:"cleanup_target_id,omitempty"`
	CleanupNodeID                     string                  `json:"cleanup_node_id,omitempty"`
	CleanupAcceleratorID              string                  `json:"cleanup_accelerator_id,omitempty"`
	CleanupGeneration                 uint64                  `json:"cleanup_generation,omitempty"`
	CleanupFence                      uint64                  `json:"cleanup_fence,omitempty"`
	CleanupTerminalDisposition        string                  `json:"cleanup_terminal_disposition,omitempty"`
	CleanupMessage                    string                  `json:"cleanup_message,omitempty"`
	SnapshotName                      string                  `json:"snapshot_name,omitempty"`
	SnapshotDigest                    string                  `json:"snapshot_digest,omitempty"`
	Phase                             string                  `json:"phase"`
	PhaseOrdinal                      int                     `json:"phase_ordinal"`
	PartialOutputHash                 string                  `json:"partial_output_hash,omitempty"`
	PartialOutputOffset               int                     `json:"partial_output_offset,omitempty"`
	PartialOutputContent              []byte                  `json:"partial_output_content,omitempty"`
	PartialOutputUnsafeToolCall       bool                    `json:"partial_output_unsafe_tool_call,omitempty"`
	SavedTokens                       int                     `json:"saved_tokens,omitempty"`
	ReusedTokens                      int                     `json:"reused_tokens,omitempty"`
	QuotaBytes                        int64                   `json:"quota_bytes,omitempty"`
	SnapshotBytes                     int64                   `json:"snapshot_bytes,omitempty"`
	CreatedAt                         time.Time               `json:"created_at"`
	UpdatedAt                         time.Time               `json:"updated_at"`
	Error                             string                  `json:"error,omitempty"`
	Revision                          uint64                  `json:"revision"`
}

type LLMCheckpointOperationStore interface {
	CreateLLMCheckpointOperation(context.Context, *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error)
	GetLLMCheckpointOperation(context.Context, string) (*LLMCheckpointOperation, error)
	GetLLMCheckpointOperationByIdempotency(context.Context, string, string) (*LLMCheckpointOperation, error)
	UpdateLLMCheckpointOperation(context.Context, *LLMCheckpointOperation, uint64) (*LLMCheckpointOperation, error)
	ListLLMCheckpointOperations(context.Context, string) ([]*LLMCheckpointOperation, error)
}

// ErrNodeCommandConflict is returned when an idempotency key or command ID is
// reused for a different signed node command.  Replaying the original command
// is safe; silently accepting different arguments would let a stale caller
// cross the command/fence boundary.
var ErrNodeCommandConflict = errors.New("store: node command idempotency conflict")

var ErrResidencyTransitionConflict = errors.New("store: residency transition idempotency conflict")

var ErrModelResidencyConflict = errors.New("store: model residency revision conflict")

var ErrModelResidencyGenerationConflict = errors.New("store: model residency target generation conflict")

var ErrInterferenceProfileConflict = errors.New("store: interference profile version conflict")

var ErrWorkloadConflict = errors.New("store: workload revision or ownership conflict")

var ErrAcceleratorLeaseCleanupConflict = errors.New("store: accelerator lease cleanup continuation conflict")

func validateLeaseCleanupIntent(intent *domain.AcceleratorLeaseCleanupIntent) error {
	if intent == nil || intent.AcceleratorID == "" || intent.Owner == "" || intent.FencingToken <= 0 {
		return errors.New("accelerator lease cleanup intent requires exact lease identity")
	}
	if intent.Attempts < 1 {
		return errors.New("accelerator lease cleanup intent attempts must be positive")
	}
	if len(intent.LastError) > 512 || len(intent.TerminalErrorCode) > 128 {
		return errors.New("accelerator lease cleanup intent error is too long")
	}
	if intent.TerminalDisposition == "" {
		if intent.WorkloadID != "" || intent.ExpectedWorkloadRevision != 0 || intent.ReleaseConfirmed || intent.TerminalPublished || intent.AuditPublished || intent.NotificationPublished || intent.BudgetSettled {
			return errors.New("ordinary lease cleanup intent carries terminal continuation fields")
		}
		return nil
	}
	if intent.WorkloadID == "" || intent.ExpectedWorkloadRevision == 0 || intent.TerminalErrorCode == "" {
		return errors.New("terminal lease cleanup intent is incomplete")
	}
	if intent.TerminalDisposition != "success" && intent.TerminalDisposition != "failure" && intent.TerminalDisposition != "cancel" {
		return errors.New("terminal lease cleanup intent has invalid disposition")
	}
	if intent.TerminalPublished && !intent.ReleaseConfirmed {
		return errors.New("terminal continuation published before release confirmation")
	}
	if (intent.AuditPublished || intent.NotificationPublished || intent.BudgetSettled) && !intent.TerminalPublished {
		return errors.New("terminal continuation side effect published before terminal state")
	}
	return nil
}

// ModelCapacity is the measured resource envelope for one model/profile on a
// target. Values are bytes (never display MiB) and are durable so a restarted
// controller does not silently fall back to a guessed model size.
type ModelCapacity struct {
	ID                  string    `json:"id"`
	TargetID            string    `json:"target_id"`
	AcceleratorID       string    `json:"accelerator_id,omitempty"`
	Model               string    `json:"model"`
	ProfileID           string    `json:"profile_id,omitempty"`
	ModelFingerprint    string    `json:"model_fingerprint,omitempty"`
	RuntimeIdentity     string    `json:"runtime_identity,omitempty"`
	CapabilityVersion   string    `json:"capability_version,omitempty"`
	CapabilityRevision  string    `json:"capability_revision,omitempty"`
	ModelBytes          int64     `json:"model_bytes"`
	ProfileBytes        int64     `json:"profile_bytes"`
	VRAMReserveBytes    int64     `json:"vram_reserve_bytes"`
	RuntimeHardCapBytes int64     `json:"runtime_hard_cap_bytes"`
	RAMBytes            int64     `json:"ram_bytes,omitempty"`
	RAMReserveBytes     int64     `json:"ram_reserve_bytes,omitempty"`
	VRAMTotalBytes      int64     `json:"vram_total_bytes,omitempty"`
	RAMTotalBytes       int64     `json:"ram_total_bytes,omitempty"`
	UnifiedMemory       bool      `json:"unified_memory"`
	CapacitySource      string    `json:"capacity_source,omitempty"`
	Verified            bool      `json:"verified"`
	Revision            uint64    `json:"revision"`
	UpdatedAt           time.Time `json:"updated_at"`
	ObservedAt          time.Time `json:"observed_at"`
}

func (c ModelCapacity) FootprintBytes() int64 {
	if c.ModelBytes < 0 || c.ProfileBytes < 0 {
		return -1
	}
	if c.ModelBytes > math.MaxInt64-c.ProfileBytes {
		return -1
	}
	return c.ModelBytes + c.ProfileBytes
}

func modelCapacityKey(targetID, model, profileID string) string {
	return targetID + "\x00" + model + "\x00" + profileID
}

func modelCapacityID(targetID, model, profileID string) string {
	digest := sha256.Sum256([]byte(modelCapacityKey(targetID, model, profileID)))
	return "capacity-" + hex.EncodeToString(digest[:])
}

const defaultBudgetCurrency = "USD"

// workloadRequiresSettlementIntent keeps the budget crash boundary enforced
// below the manager as well as at its mutation helper. A terminal workload
// carrying a priced reservation cannot be committed without the durable
// intent that tells the recovery worker which exact claim to settle.
func workloadRequiresSettlementIntent(w *domain.Workload) bool {
	if w == nil || w.BudgetReservationToken == "" || w.BudgetReservationAttempt == 0 {
		return false
	}
	switch w.Status {
	case domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadRejected, domain.WorkloadCancelled:
		return !w.BudgetSettlementPending
	default:
		return false
	}
}

func verifyResidencyTransitionReplay(existing, requested *domain.ResidencyTransition) error {
	if existing == nil || requested == nil {
		return fmt.Errorf("%w: missing transition", ErrResidencyTransitionConflict)
	}
	if err := verifyResidencyTransitionCanonical(existing, requested, true); err != nil {
		return err
	}
	if !sameResidencyTransitionLeaseOrigin(existing, requested) {
		return fmt.Errorf("%w: lease-origin provenance differs", ErrResidencyTransitionConflict)
	}
	return nil
}

func verifyResidencyTransitionCanonical(existing, requested *domain.ResidencyTransition, compareFence bool) error {
	if existing == nil || requested == nil {
		return fmt.Errorf("%w: missing transition", ErrResidencyTransitionConflict)
	}
	fenceDiffers := compareFence && existing.FencingToken != requested.FencingToken
	if existing.IdempotencyKey != requested.IdempotencyKey || existing.TargetID != requested.TargetID || existing.AcceleratorID != requested.AcceleratorID || existing.Model != requested.Model || existing.FromTier != requested.FromTier || existing.ToTier != requested.ToTier || existing.Reason != requested.Reason || existing.RequestedBy != requested.RequestedBy || existing.WorkloadID != requested.WorkloadID || fenceDiffers || existing.CapabilityVersion != requested.CapabilityVersion || existing.CapabilityRevision != requested.CapabilityRevision || existing.TargetGeneration != requested.TargetGeneration || existing.ExecutionFingerprint != requested.ExecutionFingerprint {
		return fmt.Errorf("%w: canonical transition arguments differ", ErrResidencyTransitionConflict)
	}
	return nil
}

func sameResidencyTransitionLeaseOrigin(left, right *domain.ResidencyTransition) bool {
	return left != nil && right != nil && left.LeaseOriginAcceleratorID == right.LeaseOriginAcceleratorID &&
		left.LeaseOriginWorkloadID == right.LeaseOriginWorkloadID && left.LeaseOriginFencingToken == right.LeaseOriginFencingToken &&
		left.LeaseOriginAllocated == right.LeaseOriginAllocated
}

func residencyTransitionHasLeaseOrigin(transition *domain.ResidencyTransition) bool {
	return transition != nil && (transition.LeaseOriginAcceleratorID != "" || transition.LeaseOriginWorkloadID != "" ||
		transition.LeaseOriginFencingToken != 0 || transition.LeaseOriginAllocated)
}

func validateResidencyTransitionStoredOrigin(transition *domain.ResidencyTransition) error {
	if !residencyTransitionHasLeaseOrigin(transition) {
		return nil
	}
	if transition.LeaseOriginAcceleratorID == "" || transition.LeaseOriginWorkloadID == "" || transition.LeaseOriginFencingToken <= 0 || !transition.LeaseOriginAllocated {
		return fmt.Errorf("%w: partial or unissued lease-origin provenance", ErrResidencyTransitionConflict)
	}
	return nil
}

func validateResidencyTransitionLeaseOriginRequest(transition *domain.ResidencyTransition, lease *domain.AcceleratorLease) (string, error) {
	if transition == nil || transition.ID == "" || transition.IdempotencyKey == "" || transition.TargetID == "" || transition.Model == "" {
		return "", fmt.Errorf("%w: lease-aware transition requires id, idempotency key, target, and model", ErrResidencyTransitionConflict)
	}
	if transition.Status != domain.ResidencyTransitionPlanned || transition.Revision != 0 || transition.StartedAt != nil || transition.FinishedAt != nil ||
		transition.Error != "" || transition.ObservedTier != "" || transition.WarmModelBytes != 0 || transition.WarmModelBytesVerified ||
		transition.RuntimeIdentity != "" || transition.ObservedFence != 0 || transition.ProjectionRepairPending {
		return "", fmt.Errorf("%w: leased allocation must begin as an unobserved planned transition", ErrResidencyTransitionConflict)
	}
	if residencyTransitionHasLeaseOrigin(transition) {
		return "", fmt.Errorf("%w: caller may not supply lease-origin provenance", ErrResidencyTransitionConflict)
	}
	if lease == nil || lease.WorkloadID == "" || lease.FencingToken <= 0 || lease.ExpiresAt.IsZero() || transition.FencingToken != lease.FencingToken {
		return "", fmt.Errorf("%w: lease-aware allocation requires the exact proposed lease fence", ErrResidencyTransitionConflict)
	}
	resource := lease.AcceleratorID
	if transition.AcceleratorID != "" {
		if resource != transition.AcceleratorID {
			return "", fmt.Errorf("%w: lease resource differs from transition accelerator", ErrResidencyTransitionConflict)
		}
	} else {
		resource = "virtual/" + transition.TargetID
		if lease.AcceleratorID != resource {
			return "", fmt.Errorf("%w: virtual lease resource differs from transition target", ErrResidencyTransitionConflict)
		}
	}
	if resource == "" {
		return "", fmt.Errorf("%w: lease resource is empty", ErrResidencyTransitionConflict)
	}
	return resource, nil
}

func validateCurrentResidencyLeaseOrigin(current, requested *domain.AcceleratorLease, now time.Time) error {
	if requested == nil || requested.AcceleratorID == "" || requested.WorkloadID == "" || requested.FencingToken <= 0 || current == nil ||
		current.AcceleratorID != requested.AcceleratorID || current.WorkloadID != requested.WorkloadID || current.FencingToken != requested.FencingToken || !current.ExpiresAt.After(now) {
		return fmt.Errorf("%w: accelerator lease origin is stale, expired, or foreign", ErrResidencyTransitionConflict)
	}
	return nil
}

func verifyResidencyTransitionLeaseReplay(existing, requested *domain.ResidencyTransition, lease *domain.AcceleratorLease) error {
	resource, err := validateResidencyTransitionLeaseOriginRequest(requested, lease)
	if err != nil {
		return err
	}
	if err := verifyResidencyTransitionCanonical(existing, requested, false); err != nil {
		return err
	}
	if existing.LeaseOriginAcceleratorID != resource || existing.LeaseOriginWorkloadID != lease.WorkloadID ||
		existing.LeaseOriginFencingToken != lease.FencingToken || !existing.LeaseOriginAllocated || existing.FencingToken < lease.FencingToken {
		return fmt.Errorf("%w: stored transition was not allocated under the exact lease origin", ErrResidencyTransitionConflict)
	}
	return nil
}

func verifyNodeCommandReplay(existing, requested *domain.NodeCommand) error {
	if existing == nil || requested == nil {
		return fmt.Errorf("%w: missing command", ErrNodeCommandConflict)
	}
	if existing.NodeID != requested.NodeID || existing.IdempotencyKey != requested.IdempotencyKey || existing.Command != requested.Command {
		return fmt.Errorf("%w: node, idempotency key, or command differs", ErrNodeCommandConflict)
	}
	existingArgs, err := json.Marshal(existing.Args)
	if err != nil {
		return fmt.Errorf("%w: stored args: %v", ErrNodeCommandConflict, err)
	}
	requestedArgs, err := json.Marshal(requested.Args)
	if err != nil {
		return fmt.Errorf("%w: requested args: %v", ErrNodeCommandConflict, err)
	}
	if !bytes.Equal(existingArgs, requestedArgs) {
		return fmt.Errorf("%w: canonical args differ", ErrNodeCommandConflict)
	}
	return nil
}

func verifyNodeCommandDelivery(existing, requested *domain.NodeCommand) error {
	if err := verifyNodeCommandReplay(existing, requested); err != nil {
		return err
	}
	if existing.Signature != requested.Signature {
		return fmt.Errorf("%w: signed command differs", ErrNodeCommandConflict)
	}
	return nil
}

// NodeStore persists desired and observed node inventory.
type NodeStore interface {
	// UpsertNode creates the node if it doesn't exist (by ID) or updates it
	// in place if it does. Returns the stored copy.
	UpsertNode(ctx context.Context, n *domain.Node) (*domain.Node, error)

	GetNode(ctx context.Context, id string) (*domain.Node, error)

	ListNodes(ctx context.Context) ([]*domain.Node, error)

	// UpdateObserved patches only the observed half of a node's state
	// (used by the heartbeat/telemetry path so it never clobbers desired
	// state set via the API).
	UpdateObserved(ctx context.Context, id string, fn func(o *domain.Observed, accels *[]domain.Accelerator)) error
	UpdateDesired(ctx context.Context, id string, fn func(d *domain.Desired, scheduling *domain.SchedulingState)) error

	// DeleteNode removes a node entirely (not exposed by the public API).
	DeleteNode(ctx context.Context, id string) error
}

// EngineStore persists domain.EngineInstance rows (Phase 2 §32). Engines
// are reported by a node agent after it launches/stops a managed runtime
// process via a runtime.Driver.
type EngineStore interface {
	UpsertEngine(ctx context.Context, e *domain.EngineInstance) (*domain.EngineInstance, error)
	ListEnginesForNode(ctx context.Context, nodeID string) ([]*domain.EngineInstance, error)
	DeleteEngine(ctx context.Context, id string) error
}

// ProfileStore persists domain.PerformanceProfile rows (measurement.md §5).
// Rows are keyed by their own ID but always carry the node that measured
// them so the API can scope a listing to one node.
type ProfileStore interface {
	SaveProfile(ctx context.Context, nodeID string, p *domain.PerformanceProfile) (*domain.PerformanceProfile, error)
	ListProfilesForNode(ctx context.Context, nodeID string) ([]*domain.PerformanceProfile, error)
	ListAllProfiles(ctx context.Context) ([]*domain.PerformanceProfile, error)
}

// JobStore persists domain.Job and domain.WorkItem rows (architecture.md
// §32 Job/WorkItem, §47 Phase 3). This is a plain data-CRUD surface — the
// same shape as EngineStore/ProfileStore. The queue engine's business logic
// (leases, dispatch, retries, reaper) lives in internal/jobs and treats this
// store purely as a durable write-through target/read source for the
// canonical row shape, mirroring how liveness logic in internal/api/server.go
// sits above the dumb NodeStore rather than inside it.
type JobStore interface {
	UpsertJob(ctx context.Context, j *domain.Job) (*domain.Job, error)
	GetJob(ctx context.Context, id string) (*domain.Job, error)
	ListJobs(ctx context.Context) ([]*domain.Job, error)

	UpsertWorkItem(ctx context.Context, wi *domain.WorkItem) (*domain.WorkItem, error)
	GetWorkItem(ctx context.Context, jobID, itemID, operationVersion string) (*domain.WorkItem, error)
	ListWorkItemsForJob(ctx context.Context, jobID string) ([]*domain.WorkItem, error)
}

// WorkloadStore is the authoritative state-machine and lease surface shared
// by every protocol plane. AcquireAcceleratorLease must be atomic in durable
// implementations; the fencing token monotonically increases per device.
type WorkloadStore interface {
	CreateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, bool, error)
	UpdateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, error)
	// CompareAndSwapWorkload is the authoritative workload projection boundary.
	// The row must still have expectedRevision/status/owner. Terminal rows and
	// cancellation ownership therefore cannot be rewritten by stale observers.
	CompareAndSwapWorkload(ctx context.Context, w *domain.Workload, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.Workload, error)
	GetWorkload(ctx context.Context, id string) (*domain.Workload, error)
	ListWorkloads(ctx context.Context) ([]*domain.Workload, error)

	AcquireAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error)
	RenewAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64, ttl time.Duration) error
	ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error
	GetAcceleratorLease(ctx context.Context, acceleratorID string) (*domain.AcceleratorLease, error)
	RecordAcceleratorLeaseCleanupIntent(ctx context.Context, intent *domain.AcceleratorLeaseCleanupIntent) (*domain.AcceleratorLeaseCleanupIntent, error)
	ListAcceleratorLeaseCleanupIntents(ctx context.Context, now time.Time, limit int) ([]*domain.AcceleratorLeaseCleanupIntent, error)
	DeleteAcceleratorLeaseCleanupIntent(ctx context.Context, acceleratorID, owner string, fencingToken int64) error

	SavePromptMapping(ctx context.Context, mapping *domain.PromptMapping) error
	GetPromptMapping(ctx context.Context, publicPromptID string) (*domain.PromptMapping, error)
	AppendAuditEvent(ctx context.Context, event *domain.AuditEvent) error
	ListAuditEvents(ctx context.Context, ownerID string, limit int) ([]*domain.AuditEvent, error)

	UpsertModelResidency(ctx context.Context, residency *domain.ModelResidency) (*domain.ModelResidency, error)
	CreateModelResidency(ctx context.Context, residency *domain.ModelResidency) (*domain.ModelResidency, bool, error)
	CompareAndSwapModelResidency(ctx context.Context, residency *domain.ModelResidency, expectedRevision uint64) (*domain.ModelResidency, error)
	GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error)
	ListModelResidencies(ctx context.Context) ([]*domain.ModelResidency, error)
	CreateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, bool, error)
	AllocateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, bool, error)
	AllocateResidencyTransitionWithLease(ctx context.Context, transition *domain.ResidencyTransition, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, bool, error)
	GetResidencyTransitionByIdempotencyForLease(ctx context.Context, idempotencyKey string, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, error)
	UpdateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, error)
	CompareAndSwapResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition, expectedRevision uint64, expectedStatus domain.ResidencyTransitionStatus, expectedFence int64) (*domain.ResidencyTransition, error)
	GetResidencyTransition(ctx context.Context, id string) (*domain.ResidencyTransition, error)
	GetResidencyTransitionByIdempotency(ctx context.Context, idempotencyKey string) (*domain.ResidencyTransition, error)
	MaxResidencyFencingToken(ctx context.Context, targetID, model string) (int64, error)
	ListActiveResidencyTransitions(ctx context.Context, targetID, model string) ([]*domain.ResidencyTransition, error)
	ListResidencyTransitions(ctx context.Context, limit int) ([]*domain.ResidencyTransition, error)

	// Model capacity is separate from residency state: a model may be cold
	// while its last measured footprint remains authoritative for admission.
	UpsertModelCapacity(ctx context.Context, capacity *ModelCapacity) (*ModelCapacity, error)
	GetModelCapacity(ctx context.Context, targetID, model, profileID string) (*ModelCapacity, error)
	ListModelCapacities(ctx context.Context, targetID, model string) ([]*ModelCapacity, error)

	CreateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, bool, error)
	UpdateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, error)
	ListPendingNotifications(ctx context.Context, now time.Time, limit int) ([]*domain.NotificationDelivery, error)
	ListNotifications(ctx context.Context, ownerID string, limit int) ([]*domain.NotificationDelivery, error)

	CreateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, bool, error)
	UpdateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, error)
	CompareAndSwapNodeCommand(ctx context.Context, command *domain.NodeCommand, expectedAttempts int, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error)
	// CompareAndSwapNodeCommandRevision guards every durable delivery/result
	// update by revision, attempts, uncertainty, and status. The legacy CAS
	// above remains for compatibility with older embedders; controller paths
	// use this stronger operation.
	CompareAndSwapNodeCommandRevision(ctx context.Context, command *domain.NodeCommand, expectedRevision uint64, expectedAttempts int, expectedUncertain bool, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error)
	// AdvanceNodeCommandRecovery atomically records one recoverable retry and
	// its future due time. It does not depend on a caller's stale revision.
	AdvanceNodeCommandRecovery(ctx context.Context, id string) (*domain.NodeCommand, error)
	// PromoteNodeCommandUncertain is monotonic evidence: a valid authenticated
	// uncertain result dominates queued/sent/requeued or ordinary terminal
	// delivery observations. Once promoted, ordinary late results cannot clear
	// the uncertainty bit.
	PromoteNodeCommandUncertain(ctx context.Context, id, nodeID string, result json.RawMessage, commandError string) (*domain.NodeCommand, error)
	GetNodeCommand(ctx context.Context, id string) (*domain.NodeCommand, error)
	ListNodeCommands(ctx context.Context, nodeID string, limit int) ([]*domain.NodeCommand, error)
	// ListNodeCommandRecovery is exhaustive for one node (and optional parent
	// mutation), so recovery correctness never depends on the newest N rows.
	ListNodeCommandRecovery(ctx context.Context, nodeID, reconcilesCommandID string) ([]*domain.NodeCommand, error)

	ReserveBudget(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64) (*domain.BudgetReservation, bool, error)
	ReserveBudgetClaim(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64, attemptToken string) (*domain.BudgetReservation, bool, bool, error)
	SettleBudget(ctx context.Context, workloadID string, actualCents int64) (*domain.BudgetReservation, error)
	ReleaseBudget(ctx context.Context, workloadID string) error
	SettleBudgetClaim(ctx context.Context, workloadID, ownershipToken string, attempt uint64, actualCents int64) (*domain.BudgetReservation, error)
	ReleaseBudgetClaim(ctx context.Context, workloadID, ownershipToken string, attempt uint64) error
	ListBudgetReservations(ctx context.Context, principalID string) ([]*domain.BudgetReservation, error)

	CreateTransformationApproval(ctx context.Context, approval *domain.TransformationApproval) (*domain.TransformationApproval, bool, error)
	GetTransformationApproval(ctx context.Context, workloadID, planHash string) (*domain.TransformationApproval, error)
	ListTransformationApprovals(ctx context.Context, workloadID string) ([]*domain.TransformationApproval, error)
	SaveSchedulerLearningSample(ctx context.Context, sample *domain.SchedulerLearningSample) (*domain.SchedulerLearningSample, error)
	ListSchedulerLearningSamples(ctx context.Context, acceleratorID string, limit int) ([]*domain.SchedulerLearningSample, error)
	UpsertInterferenceProfile(ctx context.Context, profile *domain.InterferenceProfile) (*domain.InterferenceProfile, error)
	GetInterferenceProfile(ctx context.Context, key string) (*domain.InterferenceProfile, error)
	ListInterferenceProfiles(ctx context.Context) ([]*domain.InterferenceProfile, error)
	CreateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error)
	UpdateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error)
	ListTransitionPlans(ctx context.Context, workloadID string, limit int) ([]*domain.TransitionPlan, error)
	UpsertTargetPolicyOverride(ctx context.Context, policy *domain.TargetPolicyOverride) (*domain.TargetPolicyOverride, error)
	ListTargetPolicyOverrides(ctx context.Context) ([]*domain.TargetPolicyOverride, error)
}

// CheckpointRecoveryLeaseStore is the narrow, explicitly authorized lease
// reacquisition seam used only after a durable checkpoint cleanup intent has
// armed a compensation restore.  Ordinary AcquireAcceleratorLease calls must
// remain fail-closed while any unresolved cleanup custody exists, including
// when the requested workload is the same owner.
type CheckpointRecoveryLeaseStore interface {
	AcquireAcceleratorLeaseForCheckpointRecovery(context.Context, string, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
}

// BudgetClaimLinker atomically creates/resumes a budget reservation and
// publishes its exact token/attempt on the workload CAS row. Implementations
// must not expose an unlinked reservation window to admission or cleanup.
type BudgetClaimLinker interface {
	ReserveAndLinkBudgetClaim(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64, attemptToken string, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.BudgetReservation, *domain.Workload, bool, bool, error)
}

type IncidentStore interface {
	CreateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error)
	UpdateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error)
	GetIncident(ctx context.Context, id string) (*domain.Incident, error)
	ListIncidents(ctx context.Context, ownerID string) ([]*domain.Incident, error)
}

type BrowserSessionStore interface {
	CreateBrowserSession(ctx context.Context, session *domain.BrowserSession) error
	GetBrowserSession(ctx context.Context, idHash string) (*domain.BrowserSession, error)
	DeleteBrowserSession(ctx context.Context, idHash string) error
}

type NodeEnrollmentStore interface {
	CreateNodeEnrollment(ctx context.Context, enrollment *domain.NodeEnrollment) error
	GetNodeEnrollmentByHash(ctx context.Context, tokenHash string) (*domain.NodeEnrollment, error)
	GetNodeEnrollment(ctx context.Context, nodeID string) (*domain.NodeEnrollment, error)
	ListNodeEnrollments(ctx context.Context) ([]*domain.NodeEnrollment, error)
	RevokeNodeEnrollment(ctx context.Context, nodeID string) error
}

// CreatorStudioStore persists immutable logical profiles and advisory working
// sets. RuntimeProfile insertion must reject a changed digest for an existing
// profile_id + version instead of silently redefining calibration identity.
type CreatorStudioStore interface {
	UpsertRuntimeProfile(ctx context.Context, profile *domain.RuntimeProfile) (*domain.RuntimeProfile, bool, error)
	ListRuntimeProfiles(ctx context.Context) ([]*domain.RuntimeProfile, error)
	UpsertWorkingSet(ctx context.Context, workingSet *domain.WorkingSet) (*domain.WorkingSet, error)
	ReleaseWorkingSet(ctx context.Context, ownerID, sessionID, phaseID string, releasedAt time.Time) (*domain.WorkingSet, error)
	ListWorkingSets(ctx context.Context, ownerID, sessionID string, includeReleased bool) ([]*domain.WorkingSet, error)
}

// Store is the aggregate persistence surface the controller wires up.
// Both development and PostgreSQL stores implement this aggregate surface so
// controller wiring never mixes durable and ephemeral authority.
type Store interface {
	NodeStore
	EngineStore
	ProfileStore
	JobStore
	WorkloadStore
	IncidentStore
	BrowserSessionStore
	NodeEnrollmentStore
	CreatorStudioStore
}
