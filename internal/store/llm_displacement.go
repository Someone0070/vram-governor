package store

import (
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

// LLMDisplacementOperation is an immutable description of one proposed
// accelerator displacement. The mutable observation fields are controller
// journal state only; they are not physical proof unless a trusted observer
// supplied the bound evidence.
type LLMDisplacementOperation struct {
	ID                     string                          `json:"id"`
	IdempotencyKey         string                          `json:"idempotency_key"`
	OwnerID                string                          `json:"owner_id"`
	VictimWorkloadID       string                          `json:"victim_workload_id"`
	VictimOwnerID          string                          `json:"victim_owner_id"`
	VictimWorkloadRevision uint64                          `json:"victim_workload_revision"`
	UrgentWorkloadID       string                          `json:"urgent_workload_id"`
	UrgentOwnerID          string                          `json:"urgent_owner_id"`
	UrgentWorkloadRevision uint64                          `json:"urgent_workload_revision"`
	AcceleratorID          string                          `json:"accelerator_id"`
	NodeID                 string                          `json:"node_id"`
	OriginalLease          *domain.AcceleratorLease        `json:"original_lease"`
	Fence                  uint64                          `json:"fence"`
	VictimBinding          LLMDisplacementModelBinding     `json:"victim_binding"`
	UrgentBinding          LLMDisplacementModelBinding     `json:"urgent_binding"`
	ProofBinding           string                          `json:"proof_binding"`
	Phase                  string                          `json:"phase"`
	Revision               uint64                          `json:"revision"`
	CommandIntents         []LLMDisplacementCommandIntent  `json:"command_intents,omitempty"`
	ObservedResults        []LLMDisplacementObservedResult `json:"observed_results,omitempty"`
	SnapshotIdentity       string                          `json:"snapshot_identity,omitempty"`
	SafeBoundaryObserved   bool                            `json:"safe_boundary_observed,omitempty"`
	VictimStopObserved     bool                            `json:"victim_stop_observed,omitempty"`
	SnapshotObserved       bool                            `json:"snapshot_observed,omitempty"`
	UrgentLoadObserved     bool                            `json:"urgent_load_observed,omitempty"`
	UrgentStopObserved     bool                            `json:"urgent_stop_observed,omitempty"`
	VictimReloadObserved   bool                            `json:"victim_reload_observed,omitempty"`
	KVRestoreObserved      bool                            `json:"kv_restore_observed,omitempty"`
	LeaseSettled           bool                            `json:"lease_settled,omitempty"`
	SnapshotCustodySettled bool                            `json:"snapshot_custody_settled,omitempty"`
	ObservedProof          string                          `json:"observed_proof,omitempty"`
	LastError              string                          `json:"last_error,omitempty"`
	CreatedAt              time.Time                       `json:"created_at"`
	UpdatedAt              time.Time                       `json:"updated_at"`
}

type LLMDisplacementCommandIntent struct {
	Step      string `json:"step"`
	CommandID string `json:"command_id"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

// LLMDisplacementModelBinding keeps each side's full catalog and execution
// identity separate so neither model can inherit the other's mutable binding.
type LLMDisplacementModelBinding struct {
	TargetID           string   `json:"target_id"`
	NodeID             string   `json:"node_id"`
	AcceleratorID      string   `json:"accelerator_id"`
	CatalogModel       string   `json:"catalog_model"`
	CatalogAliases     []string `json:"catalog_aliases"`
	ActualAlias        string   `json:"actual_alias"`
	LocalPlanID        string   `json:"local_plan_id"`
	LocalPlanHash      string   `json:"local_plan_hash"`
	ControllerPlanID   string   `json:"controller_plan_id"`
	ControllerPlanHash string   `json:"controller_plan_hash"`
	ArtifactID         string   `json:"artifact_id"`
	ArtifactDigest     string   `json:"artifact_digest"`
	RuntimeIdentity    string   `json:"runtime_identity"`
	ProfileIdentity    string   `json:"profile_identity"`
	ContextIdentity    string   `json:"context_identity"`
	CheckpointID       string   `json:"checkpoint_id"`
	CheckpointDigest   string   `json:"checkpoint_digest"`
	ProofBinding       string   `json:"proof_binding"`
}
type LLMDisplacementObservedResult struct {
	Step           string `json:"step"`
	CommandID      string `json:"command_id"`
	ResultID       string `json:"result_id"`
	Digest         string `json:"digest"`
	ProofBinding   string `json:"proof_binding"`
	KeyID          string `json:"key_id"`
	Signature      string `json:"signature"`
	EnvelopeDigest string `json:"envelope_digest"`
}

// The trusted integration verifies this signature before storing the result.
// This primitive validates and retains the exact signed-envelope identity; it
// does not claim a nonempty signature proves physical execution or custody.
func observedResultEnvelopeDigest(r LLMDisplacementObservedResult) string {
	payload, _ := json.Marshal(struct{ Step, CommandID, ResultID, Digest, ProofBinding, KeyID string }{r.Step, r.CommandID, r.ResultID, r.Digest, r.ProofBinding, r.KeyID})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

var displacementPhases = []string{"planned", "pause_intent_sealed", "safe_boundary_paused", "snapshot_intent_sealed", "snapshot_captured", "victim_stop_intent_sealed", "victim_stopped", "urgent_load_intent_sealed", "urgent_loaded", "urgent_stop_intent_sealed", "urgent_stopped", "victim_reload_intent_sealed", "victim_reloaded", "kv_restore_intent_sealed", "kv_restored", "settlement_intent_sealed", "settled", "completed"}
var displacementUnresolvedPhases = map[string]bool{"planned": true, "pause_intent_sealed": true, "safe_boundary_paused": true, "snapshot_intent_sealed": true, "snapshot_captured": true, "victim_stop_intent_sealed": true, "victim_stopped": true, "urgent_load_intent_sealed": true, "urgent_loaded": true, "urgent_stop_intent_sealed": true, "urgent_stopped": true, "victim_reload_intent_sealed": true, "victim_reloaded": true, "kv_restore_intent_sealed": true, "kv_restored": true, "settlement_intent_sealed": true, "settled": true, "pending": true, "uncertain": true, "manual_reconciliation": true}
var displacementSteps = []string{"pause", "snapshot", "victim_stop", "urgent_load", "urgent_stop", "victim_reload", "kv_restore", "settlement"}

func cloneLLMDisplacementOperation(op *LLMDisplacementOperation) *LLMDisplacementOperation {
	if op == nil {
		return nil
	}
	out := *op
	out.VictimBinding.CatalogAliases = append([]string(nil), op.VictimBinding.CatalogAliases...)
	out.UrgentBinding.CatalogAliases = append([]string(nil), op.UrgentBinding.CatalogAliases...)
	out.CommandIntents = append([]LLMDisplacementCommandIntent(nil), op.CommandIntents...)
	out.ObservedResults = append([]LLMDisplacementObservedResult(nil), op.ObservedResults...)
	if op.OriginalLease != nil {
		lease := *op.OriginalLease
		out.OriginalLease = &lease
	}
	return &out
}

func validateLLMDisplacementIdentity(op *LLMDisplacementOperation) error {
	if op == nil || strings.TrimSpace(op.ID) == "" || strings.TrimSpace(op.IdempotencyKey) == "" || strings.TrimSpace(op.OwnerID) == "" ||
		strings.TrimSpace(op.VictimWorkloadID) == "" || strings.TrimSpace(op.VictimOwnerID) == "" || op.VictimWorkloadRevision == 0 || strings.TrimSpace(op.UrgentWorkloadID) == "" || strings.TrimSpace(op.UrgentOwnerID) == "" || op.UrgentWorkloadRevision == 0 || op.VictimWorkloadID == op.UrgentWorkloadID ||
		strings.TrimSpace(op.AcceleratorID) == "" || strings.TrimSpace(op.NodeID) == "" || op.OriginalLease == nil || op.OriginalLease.AcceleratorID != op.AcceleratorID || op.OriginalLease.WorkloadID != op.VictimWorkloadID || op.OriginalLease.FencingToken <= 0 || uint64(op.OriginalLease.FencingToken) != op.Fence || op.OriginalLease.ExpiresAt.IsZero() || op.Fence == 0 || op.Revision == 0 || op.Revision > math.MaxInt64 ||
		!validLLMDisplacementBinding(op.VictimBinding) || !validLLMDisplacementBinding(op.UrgentBinding) || op.VictimBinding.NodeID != op.NodeID || op.UrgentBinding.NodeID != op.NodeID || op.VictimBinding.AcceleratorID != op.AcceleratorID || op.UrgentBinding.AcceleratorID != op.AcceleratorID ||
		strings.TrimSpace(op.ProofBinding) == "" {
		return errors.New("llm displacement identity is incomplete or inconsistent")
	}
	if len(op.ObservedProof) > 8192 || len(op.LastError) > 2048 || len(op.CommandIntents) > len(displacementSteps) || len(op.ObservedResults) > len(displacementSteps) {
		return errors.New("llm displacement journal field is too long")
	}
	seenCommandIDs, seenResultIDs := map[string]bool{}, map[string]bool{}
	for i, intent := range op.CommandIntents {
		if strings.TrimSpace(intent.Step) == "" || strings.TrimSpace(intent.CommandID) == "" || strings.TrimSpace(intent.Digest) == "" || strings.TrimSpace(intent.Signature) == "" {
			return errors.New("sealed displacement command intent is incomplete")
		}
		if i >= len(displacementSteps) || intent.Step != displacementSteps[i] || seenCommandIDs[intent.CommandID] {
			return errors.New("displacement command intent history is malformed")
		}
		seenCommandIDs[intent.CommandID] = true
	}
	if len(op.ObservedResults) > len(op.CommandIntents) {
		return errors.New("displacement has an unsealed observed result")
	}
	for i, result := range op.ObservedResults {
		if strings.TrimSpace(result.Step) == "" || strings.TrimSpace(result.CommandID) == "" || strings.TrimSpace(result.ResultID) == "" || strings.TrimSpace(result.Digest) == "" || strings.TrimSpace(result.ProofBinding) == "" || strings.TrimSpace(result.KeyID) == "" || strings.TrimSpace(result.Signature) == "" || result.EnvelopeDigest != observedResultEnvelopeDigest(result) {
			return errors.New("displacement observed result identity is incomplete")
		}
		step := displacementSteps[i]
		if result.Step != step || seenResultIDs[result.ResultID] {
			return errors.New("displacement observed result history is malformed")
		}
		seenResultIDs[result.ResultID] = true
		if !seenCommandIDs[result.CommandID] || op.CommandIntents[i].CommandID != result.CommandID {
			return errors.New("displacement result is not linked to its unique command intent")
		}
	}
	if !validLLMDisplacementBinding(op.VictimBinding) || !validLLMDisplacementBinding(op.UrgentBinding) {
		return errors.New("displacement model binding is incomplete")
	}
	for _, result := range op.ObservedResults {
		if result.ProofBinding != op.ProofBinding {
			return errors.New("displacement observation proof is not bound to orchestration identity")
		}
	}
	if op.SafeBoundaryObserved != hasDisplacementResult(op, "pause") || op.SnapshotObserved != hasDisplacementResult(op, "snapshot") || op.VictimStopObserved != hasDisplacementResult(op, "victim_stop") || op.UrgentLoadObserved != hasDisplacementResult(op, "urgent_load") || op.UrgentStopObserved != hasDisplacementResult(op, "urgent_stop") || op.VictimReloadObserved != hasDisplacementResult(op, "victim_reload") || op.KVRestoreObserved != hasDisplacementResult(op, "kv_restore") || op.LeaseSettled != hasDisplacementResult(op, "settlement") || op.SnapshotCustodySettled != hasDisplacementResult(op, "settlement") {
		return errors.New("displacement observed flags disagree with authenticated result history")
	}
	if op.Phase != "pending" && op.Phase != "uncertain" && op.Phase != "manual_reconciliation" {
		phaseIndex := -1
		for i, p := range displacementPhases {
			if p == op.Phase {
				phaseIndex = i
				break
			}
		}
		if phaseIndex < 0 {
			return errors.New("llm displacement phase is unknown")
		}
		wantIntents, wantResults := 0, 0
		wantIntents = (phaseIndex + 1) / 2
		wantResults = phaseIndex / 2
		if op.Phase == "completed" {
			wantIntents = 8
			wantResults = 8
		}
		if len(op.CommandIntents) != wantIntents || len(op.ObservedResults) != wantResults {
			return errors.New("displacement phase disagrees with sealed intent/result history")
		}
		if op.Revision != uint64(phaseIndex+1) {
			return errors.New("displacement revision disagrees with persisted phase")
		}
	} else if op.Revision != uint64(len(op.CommandIntents)+len(op.ObservedResults)+2) || len(op.CommandIntents) < len(op.ObservedResults) || len(op.CommandIntents)-len(op.ObservedResults) > 1 {
		return errors.New("displacement reconciliation revision disagrees with retained history")
	}
	snapshotFound := false
	for _, result := range op.ObservedResults {
		if result.Step == "snapshot" {
			snapshotFound = true
			if op.SnapshotIdentity != result.ResultID {
				return errors.New("displacement snapshot identity differs from immutable authenticated result")
			}
		}
	}
	if (op.SnapshotIdentity != "") != snapshotFound {
		return errors.New("displacement snapshot identity lacks authenticated observation")
	}
	if op.ObservedProof != "" && op.Phase != "completed" {
		return errors.New("completion proof is present before terminal settlement")
	}
	if op.Phase == "completed" && !(op.SafeBoundaryObserved && op.SnapshotObserved && op.VictimStopObserved && op.UrgentLoadObserved && op.UrgentStopObserved && op.VictimReloadObserved && op.KVRestoreObserved && op.LeaseSettled && op.SnapshotCustodySettled && hasDisplacementResult(op, "settlement") && op.ObservedProof != "") {
		return errors.New("displacement cannot complete before observed boundaries and custody settlement")
	}
	if op.Phase == "completed" {
		for _, result := range op.ObservedResults {
			if result.Step == "settlement" && result.Digest != op.ObservedProof {
				return errors.New("completion proof must match observed custody settlement")
			}
		}
	}
	return nil
}

func validLLMDisplacementBinding(b LLMDisplacementModelBinding) bool {
	if strings.TrimSpace(b.TargetID) == "" || strings.TrimSpace(b.NodeID) == "" || strings.TrimSpace(b.AcceleratorID) == "" || strings.TrimSpace(b.CatalogModel) == "" || len(b.CatalogAliases) == 0 || strings.TrimSpace(b.ActualAlias) == "" || strings.TrimSpace(b.LocalPlanID) == "" || strings.TrimSpace(b.LocalPlanHash) == "" || strings.TrimSpace(b.ControllerPlanID) == "" || strings.TrimSpace(b.ControllerPlanHash) == "" || strings.TrimSpace(b.ArtifactID) == "" || strings.TrimSpace(b.ArtifactDigest) == "" || strings.TrimSpace(b.RuntimeIdentity) == "" || strings.TrimSpace(b.ProfileIdentity) == "" || strings.TrimSpace(b.ContextIdentity) == "" || strings.TrimSpace(b.CheckpointID) == "" || strings.TrimSpace(b.CheckpointDigest) == "" || strings.TrimSpace(b.ProofBinding) == "" {
		return false
	}
	seen, actual := map[string]bool{}, 0
	for _, alias := range b.CatalogAliases {
		if strings.TrimSpace(alias) == "" || seen[alias] {
			return false
		}
		seen[alias] = true
		if alias == b.ActualAlias {
			actual++
		}
	}
	return actual == 1
}

func validateLLMDisplacementWorld(op *LLMDisplacementOperation, victim, urgent *domain.Workload, currentLease *domain.AcceleratorLease, now time.Time) error {
	if victim == nil || urgent == nil || victim.Request.ID != op.VictimWorkloadID || urgent.Request.ID != op.UrgentWorkloadID || victim.Request.OwnerID != op.VictimOwnerID || urgent.Request.OwnerID != op.UrgentOwnerID || victim.Revision != op.VictimWorkloadRevision || urgent.Revision != op.UrgentWorkloadRevision {
		return ErrLLMDisplacementConflict
	}
	for _, pair := range []struct {
		w *domain.Workload
		b LLMDisplacementModelBinding
	}{{victim, op.VictimBinding}, {urgent, op.UrgentBinding}} {
		if pair.w.Plan == nil || pair.w.Plan.WorkloadID != pair.w.Request.ID || pair.w.Plan.ID != pair.b.ControllerPlanID || pair.w.Plan.PlanHash != pair.b.ControllerPlanHash || pair.w.Plan.TargetID != pair.b.TargetID || pair.w.Plan.AcceleratorID != op.AcceleratorID || pair.w.ProgressNode != op.NodeID {
			return ErrLLMDisplacementConflict
		}
	}
	if currentLease == nil || currentLease.AcceleratorID != op.AcceleratorID || currentLease.WorkloadID != op.VictimWorkloadID || currentLease.FencingToken != int64(op.Fence) || !currentLease.ExpiresAt.Equal(op.OriginalLease.ExpiresAt) || !currentLease.ExpiresAt.After(now) {
		return ErrLLMDisplacementConflict
	}
	return nil
}

func prepareLLMDisplacementCreate(op *LLMDisplacementOperation) (*LLMDisplacementOperation, error) {
	out := cloneLLMDisplacementOperation(op)
	if out == nil {
		return nil, errors.New("llm displacement identity is incomplete")
	}
	if out.Phase == "" {
		out.Phase = "planned"
	}
	if out.Phase != "planned" || len(out.CommandIntents) > 0 || len(out.ObservedResults) > 0 || out.SnapshotObserved || out.SnapshotIdentity != "" || out.SafeBoundaryObserved || out.VictimStopObserved || out.UrgentLoadObserved || out.UrgentStopObserved || out.VictimReloadObserved || out.KVRestoreObserved || out.LeaseSettled || out.SnapshotCustodySettled || out.ObservedProof != "" || out.Revision != 0 {
		return nil, errors.New("llm displacement must begin as unsealed planned intent")
	}
	out.Revision = 1
	if err := validateLLMDisplacementIdentity(out); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if out.CreatedAt.IsZero() {
		out.CreatedAt = now
	} else {
		out.CreatedAt = out.CreatedAt.UTC().Truncate(time.Microsecond)
	}
	if out.UpdatedAt.IsZero() {
		out.UpdatedAt = out.CreatedAt
	} else {
		out.UpdatedAt = out.UpdatedAt.UTC().Truncate(time.Microsecond)
	}
	return out, nil
}

func displacementIdentityEqual(a, b *LLMDisplacementOperation) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := cloneLLMDisplacementOperation(a), cloneLLMDisplacementOperation(b)
	for _, v := range []*LLMDisplacementOperation{x, y} {
		v.Phase = ""
		v.Revision = 0
		v.CommandIntents = nil
		v.ObservedResults = nil
		v.SnapshotIdentity = ""
		v.SafeBoundaryObserved = false
		v.VictimStopObserved = false
		v.SnapshotObserved = false
		v.UrgentLoadObserved = false
		v.UrgentStopObserved = false
		v.VictimReloadObserved = false
		v.KVRestoreObserved = false
		v.LeaseSettled = false
		v.SnapshotCustodySettled = false
		v.ObservedProof = ""
		v.LastError = ""
		v.CreatedAt = time.Time{}
		v.UpdatedAt = time.Time{}
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xb) == string(yb)
}

func hasDisplacementResult(op *LLMDisplacementOperation, step string) bool {
	for _, r := range op.ObservedResults {
		if r.Step == step {
			return true
		}
	}
	return false
}
func hasDisplacementIntent(op *LLMDisplacementOperation, step string) bool {
	for _, c := range op.CommandIntents {
		if c.Step == step {
			return true
		}
	}
	return false
}
func displacementIntentStep(phase string) string {
	switch phase {
	case "pause_intent_sealed":
		return "pause"
	case "snapshot_intent_sealed":
		return "snapshot"
	case "victim_stop_intent_sealed":
		return "victim_stop"
	case "urgent_load_intent_sealed":
		return "urgent_load"
	case "urgent_stop_intent_sealed":
		return "urgent_stop"
	case "victim_reload_intent_sealed":
		return "victim_reload"
	case "kv_restore_intent_sealed":
		return "kv_restore"
	case "settlement_intent_sealed":
		return "settlement"
	}
	return ""
}
func displacementResultStep(phase string) string {
	switch phase {
	case "safe_boundary_paused":
		return "pause"
	case "snapshot_captured":
		return "snapshot"
	case "victim_stopped":
		return "victim_stop"
	case "urgent_loaded":
		return "urgent_load"
	case "urgent_stopped":
		return "urgent_stop"
	case "victim_reloaded":
		return "victim_reload"
	case "kv_restored":
		return "kv_restore"
	case "settled":
		return "settlement"
	}
	return ""
}

func displacementUnresolved(phase string) bool { return phase != "completed" }

func displacementRecordRetainsCustody(op *LLMDisplacementOperation) bool {
	return op != nil && (validateLLMDisplacementIdentity(op) != nil || op.Phase != "completed")
}

func displacementTransitionAllowed(from, to string) bool {
	if to == "pending" || to == "uncertain" || to == "manual_reconciliation" {
		return from != "completed" && from != "uncertain" && from != "manual_reconciliation" && from != "pending"
	}
	for i, p := range displacementPhases {
		if p == from && i+1 < len(displacementPhases) {
			return displacementPhases[i+1] == to
		}
	}
	return false
}

func validateDisplacementUpdate(old, next *LLMDisplacementOperation, expected uint64) error {
	if err := validateLLMDisplacementIdentity(old); err != nil {
		return fmt.Errorf("%w: stored displacement identity is invalid: %v", ErrLLMDisplacementConflict, err)
	}
	if next.Revision != expected {
		return ErrLLMDisplacementConflict
	}
	if expected >= math.MaxInt64 {
		return ErrLLMDisplacementConflict
	}
	if old.Revision != expected || expected == 0 || expected >= math.MaxInt64 || old.Revision >= math.MaxInt64 || !displacementIdentityEqual(old, next) || !displacementTransitionAllowed(old.Phase, next.Phase) {
		return ErrLLMDisplacementConflict
	}
	if old.SnapshotIdentity != "" && next.SnapshotIdentity != old.SnapshotIdentity {
		return fmt.Errorf("%w: snapshot identity is immutable", ErrLLMDisplacementConflict)
	}
	if old.SafeBoundaryObserved && !next.SafeBoundaryObserved || old.VictimStopObserved && !next.VictimStopObserved || old.SnapshotObserved && !next.SnapshotObserved || old.UrgentLoadObserved && !next.UrgentLoadObserved || old.UrgentStopObserved && !next.UrgentStopObserved || old.VictimReloadObserved && !next.VictimReloadObserved || old.KVRestoreObserved && !next.KVRestoreObserved || old.LeaseSettled && !next.LeaseSettled || old.SnapshotCustodySettled && !next.SnapshotCustodySettled {
		return fmt.Errorf("%w: observed boundaries and custody are monotonic", ErrLLMDisplacementConflict)
	}
	for i := range old.CommandIntents {
		if i >= len(next.CommandIntents) || old.CommandIntents[i] != next.CommandIntents[i] {
			return fmt.Errorf("%w: command intent history is immutable", ErrLLMDisplacementConflict)
		}
	}
	for i := range old.ObservedResults {
		if i >= len(next.ObservedResults) || old.ObservedResults[i] != next.ObservedResults[i] {
			return fmt.Errorf("%w: observed result history is immutable", ErrLLMDisplacementConflict)
		}
	}
	intentStep, resultStep := displacementIntentStep(next.Phase), displacementResultStep(next.Phase)
	wantIntents, wantResults := len(old.CommandIntents), len(old.ObservedResults)
	if intentStep != "" {
		wantIntents++
		if len(next.CommandIntents) != wantIntents || next.CommandIntents[len(next.CommandIntents)-1].Step != intentStep {
			return fmt.Errorf("%w: phase must append its per-step signed intent", ErrLLMDisplacementConflict)
		}
	} else if len(next.CommandIntents) != wantIntents {
		return fmt.Errorf("%w: unexpected command intent append", ErrLLMDisplacementConflict)
	}
	if resultStep != "" {
		wantResults++
		if len(next.ObservedResults) != wantResults || next.ObservedResults[len(next.ObservedResults)-1].Step != resultStep {
			return fmt.Errorf("%w: phase must append its bound observed result", ErrLLMDisplacementConflict)
		}
	} else if len(next.ObservedResults) != wantResults {
		return fmt.Errorf("%w: unexpected observed result append", ErrLLMDisplacementConflict)
	}
	if resultStep != "" {
		result := next.ObservedResults[len(next.ObservedResults)-1]
		matched := false
		for _, intent := range next.CommandIntents {
			if intent.Step == resultStep && intent.CommandID == result.CommandID {
				matched = true
			}
		}
		if !matched || result.ProofBinding != next.ProofBinding {
			return fmt.Errorf("%w: observed result is not bound to its sealed command and proof", ErrLLMDisplacementConflict)
		}
		if resultStep == "snapshot" && next.SnapshotIdentity != result.ResultID {
			return fmt.Errorf("%w: snapshot identity differs from authenticated result", ErrLLMDisplacementConflict)
		}
	}
	switch next.Phase {
	case "safe_boundary_paused":
		if !next.SafeBoundaryObserved {
			return ErrLLMDisplacementConflict
		}
	case "snapshot_captured":
		if !next.SafeBoundaryObserved || !next.SnapshotObserved || next.SnapshotIdentity == "" {
			return ErrLLMDisplacementConflict
		}
	case "victim_stopped":
		if !next.VictimStopObserved || !next.SnapshotObserved {
			return ErrLLMDisplacementConflict
		}
	case "urgent_loaded":
		if !next.UrgentLoadObserved || !next.VictimStopObserved {
			return ErrLLMDisplacementConflict
		}
	case "urgent_stopped":
		if !next.UrgentStopObserved {
			return ErrLLMDisplacementConflict
		}
	case "victim_reloaded":
		if !next.VictimReloadObserved {
			return ErrLLMDisplacementConflict
		}
	case "kv_restored":
		if !next.KVRestoreObserved {
			return ErrLLMDisplacementConflict
		}
	case "settled":
		if !next.LeaseSettled || !next.SnapshotCustodySettled || !hasDisplacementIntent(next, "settlement") {
			return ErrLLMDisplacementConflict
		}
	}
	persistedCandidate := cloneLLMDisplacementOperation(next)
	persistedCandidate.Revision++
	if err := validateLLMDisplacementIdentity(persistedCandidate); err != nil {
		return err
	}
	return nil
}

func (m *MemoryStore) CreateLLMDisplacementOperation(_ context.Context, op *LLMDisplacementOperation) (*LLMDisplacementOperation, bool, error) {
	prepared, err := prepareLLMDisplacementCreate(op)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.llmDisplacementOps[prepared.ID]; old != nil {
		if err := validateLLMDisplacementIdentity(old); err != nil {
			return nil, false, ErrLLMDisplacementConflict
		}
		if displacementIdentityEqual(old, prepared) {
			return cloneLLMDisplacementOperation(old), false, nil
		}
		return nil, false, ErrLLMDisplacementConflict
	}
	key := prepared.OwnerID + "\x00" + prepared.IdempotencyKey
	if id := m.llmDisplacementKeys[key]; id != "" {
		old := m.llmDisplacementOps[id]
		if err := validateLLMDisplacementIdentity(old); err != nil {
			return nil, false, ErrLLMDisplacementConflict
		}
		if displacementIdentityEqual(old, prepared) {
			return cloneLLMDisplacementOperation(old), false, nil
		}
		return nil, false, ErrLLMDisplacementConflict
	}
	for _, old := range m.llmDisplacementOps {
		if old != nil && old.AcceleratorID == prepared.AcceleratorID && displacementRecordRetainsCustody(old) {
			return nil, false, ErrLLMDisplacementConflict
		}
	}
	if err := validateLLMDisplacementWorld(prepared, m.workloads[prepared.VictimWorkloadID], m.workloads[prepared.UrgentWorkloadID], m.leases[prepared.AcceleratorID], time.Now().UTC()); err != nil {
		return nil, false, err
	}
	m.llmDisplacementOps[prepared.ID] = prepared
	m.llmDisplacementKeys[key] = prepared.ID
	return cloneLLMDisplacementOperation(prepared), true, nil
}

func (m *MemoryStore) GetLLMDisplacementOperation(_ context.Context, id string) (*LLMDisplacementOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	op := m.llmDisplacementOps[id]
	if op == nil {
		return nil, ErrNotFound
	}
	return cloneLLMDisplacementOperation(op), nil
}
func (m *MemoryStore) GetLLMDisplacementOperationByIdempotency(_ context.Context, owner, key string) (*LLMDisplacementOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id := m.llmDisplacementKeys[owner+"\x00"+key]
	if id == "" || m.llmDisplacementOps[id] == nil {
		return nil, ErrNotFound
	}
	return cloneLLMDisplacementOperation(m.llmDisplacementOps[id]), nil
}
func (m *MemoryStore) UpdateLLMDisplacementOperation(_ context.Context, op *LLMDisplacementOperation, expected uint64) (*LLMDisplacementOperation, error) {
	if op == nil {
		return nil, errors.New("llm displacement identity is incomplete")
	}
	next := cloneLLMDisplacementOperation(op)
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.llmDisplacementOps[next.ID]
	if old == nil {
		return nil, ErrNotFound
	}
	if err := validateDisplacementUpdate(old, next, expected); err != nil {
		return nil, err
	}
	next.Revision = old.Revision + 1
	next.CreatedAt = old.CreatedAt
	next.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	m.llmDisplacementOps[next.ID] = next
	return cloneLLMDisplacementOperation(next), nil
}
func (m *MemoryStore) ListLLMDisplacementOperations(_ context.Context, owner string) ([]*LLMDisplacementOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*LLMDisplacementOperation, 0)
	for _, op := range m.llmDisplacementOps {
		if owner == "" || op.OwnerID == owner {
			out = append(out, cloneLLMDisplacementOperation(op))
		}
	}
	return out, nil
}

var _ LLMDisplacementStore = (*MemoryStore)(nil)
var _ LLMDisplacementStore = (*PostgresWorkloadStore)(nil)
