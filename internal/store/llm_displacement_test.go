package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

func displacementFixture(id, accelerator string) *LLMDisplacementOperation {
	modelBinding := func(target, model, alias string) LLMDisplacementModelBinding {
		return LLMDisplacementModelBinding{TargetID: target, NodeID: "node-a", AcceleratorID: accelerator, CatalogModel: model, CatalogAliases: []string{alias}, ActualAlias: alias, LocalPlanID: "local-plan-" + model, LocalPlanHash: "local-plan-hash-" + model, ControllerPlanID: "controller-plan-" + model, ControllerPlanHash: "controller-plan-hash-" + model, ArtifactID: "artifact-" + model, ArtifactDigest: "artifact-digest-" + model, RuntimeIdentity: "runtime-" + model, ProfileIdentity: "profile-" + model, ContextIdentity: "context-" + model, CheckpointID: "checkpoint-" + model, CheckpointDigest: "checkpoint-digest-" + model, ProofBinding: "proof-binding-" + model}
	}
	return &LLMDisplacementOperation{
		ID: id, IdempotencyKey: "idem-" + id, OwnerID: "operation-owner", VictimWorkloadID: "victim", VictimOwnerID: "victim-owner", VictimWorkloadRevision: 4,
		UrgentWorkloadID: "urgent", UrgentOwnerID: "urgent-owner", UrgentWorkloadRevision: 9, AcceleratorID: accelerator,
		NodeID: "node-a", OriginalLease: &domain.AcceleratorLease{AcceleratorID: accelerator, WorkloadID: "victim", FencingToken: 17, ExpiresAt: time.Now().Add(time.Hour)}, Fence: 17,
		VictimBinding: modelBinding("target-victim", "catalog-victim", "victim-alias"), UrgentBinding: modelBinding("target-urgent", "catalog-urgent", "urgent-alias"), ProofBinding: "orchestration-proof", Phase: "planned",
	}
}

func displacementResult(step, command, resultID, digest, proof string) LLMDisplacementObservedResult {
	r := LLMDisplacementObservedResult{Step: step, CommandID: command, ResultID: resultID, Digest: digest, ProofBinding: proof, KeyID: "trusted-observer-key", Signature: "signed-envelope-" + resultID}
	r.EnvelopeDigest = observedResultEnvelopeDigest(r)
	return r
}

func seedDisplacementMemoryWorld(s *MemoryStore, op *LLMDisplacementOperation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if s.workloads[op.VictimWorkloadID] == nil {
		s.workloads[op.VictimWorkloadID] = &domain.Workload{Request: domain.WorkloadRequest{ID: op.VictimWorkloadID, OwnerID: op.VictimOwnerID}, Revision: op.VictimWorkloadRevision, Status: domain.WorkloadRunning, Plan: &domain.ExecutionPlan{ID: op.VictimBinding.ControllerPlanID, WorkloadID: op.VictimWorkloadID, PlanHash: op.VictimBinding.ControllerPlanHash, TargetID: op.VictimBinding.TargetID, AcceleratorID: op.AcceleratorID}, ProgressNode: op.NodeID, CreatedAt: now, UpdatedAt: now}
	}
	if s.workloads[op.UrgentWorkloadID] == nil {
		s.workloads[op.UrgentWorkloadID] = &domain.Workload{Request: domain.WorkloadRequest{ID: op.UrgentWorkloadID, OwnerID: op.UrgentOwnerID}, Revision: op.UrgentWorkloadRevision, Status: domain.WorkloadQueued, Plan: &domain.ExecutionPlan{ID: op.UrgentBinding.ControllerPlanID, WorkloadID: op.UrgentWorkloadID, PlanHash: op.UrgentBinding.ControllerPlanHash, TargetID: op.UrgentBinding.TargetID, AcceleratorID: op.AcceleratorID}, ProgressNode: op.NodeID, CreatedAt: now, UpdatedAt: now}
	}
	if s.leases[op.AcceleratorID] == nil {
		lease := *op.OriginalLease
		s.leases[op.AcceleratorID] = &lease
	}
}
func createMemoryDisplacement(ctx context.Context, s *MemoryStore, op *LLMDisplacementOperation) (*LLMDisplacementOperation, bool, error) {
	seedDisplacementMemoryWorld(s, op)
	return s.CreateLLMDisplacementOperation(ctx, op)
}

func TestLLMDisplacementJournalMemory(t *testing.T) {
	ctx := context.Background()
	t.Run("create_from_actual_acquired_lease", func(t *testing.T) {
		s := NewMemoryStore()
		lease, created, err := s.AcquireAcceleratorLease(ctx, "gpu-live", "victim", time.Hour)
		if err != nil || !created || lease == nil {
			t.Fatalf("acquire: %+v %t %v", lease, created, err)
		}
		op := displacementFixture("live-lease-op", "gpu-live")
		if op.VictimBinding.LocalPlanID == op.VictimBinding.ControllerPlanID || op.UrgentBinding.LocalPlanHash == op.UrgentBinding.ControllerPlanHash {
			t.Fatal("fixture conflated pinned local plans with controller execution plans")
		}
		op.OriginalLease = lease
		op.Fence = uint64(lease.FencingToken)
		op.VictimBinding.AcceleratorID = "gpu-live"
		op.UrgentBinding.AcceleratorID = "gpu-live"
		seedDisplacementMemoryWorld(s, op)
		if _, created, err = s.CreateLLMDisplacementOperation(ctx, op); err != nil || !created {
			t.Fatalf("create from exact acquired lease: created=%t err=%v", created, err)
		}
	})
	t.Run("create_idempotency_and_full_identity", func(t *testing.T) {
		s := NewMemoryStore()
		in := displacementFixture("op1", "gpu0")
		got, created, err := createMemoryDisplacement(ctx, s, in)
		if err != nil || !created || got.Revision != 1 {
			t.Fatalf("create: %+v %t %v", got, created, err)
		}
		s.mu.Lock()
		s.workloads[in.VictimWorkloadID].Revision++
		s.leases[in.AcceleratorID].ExpiresAt = time.Now().Add(-time.Hour)
		s.mu.Unlock()
		retry, created, err := createMemoryDisplacement(ctx, s, in)
		if err != nil || created || retry.ID != got.ID {
			t.Fatalf("identical retry: %+v %t %v", retry, created, err)
		}
		changed := displacementFixture("op1", "gpu0")
		changed.UrgentBinding.CatalogAliases = []string{"different"}
		if _, _, err = createMemoryDisplacement(ctx, s, changed); err == nil {
			t.Fatalf("changed aliases accepted: %v", err)
		}
	})
	t.Run("create_rejects_stale_stored_world", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*MemoryStore, *LLMDisplacementOperation)
		}{
			{"victim_revision", func(s *MemoryStore, o *LLMDisplacementOperation) { s.workloads[o.VictimWorkloadID].Revision++ }},
			{"urgent_owner", func(s *MemoryStore, o *LLMDisplacementOperation) {
				s.workloads[o.UrgentWorkloadID].Request.OwnerID = "other-owner"
			}},
			{"cross_node", func(s *MemoryStore, o *LLMDisplacementOperation) {
				s.workloads[o.VictimWorkloadID].ProgressNode = "node-other"
			}},
			{"cross_target", func(s *MemoryStore, o *LLMDisplacementOperation) {
				s.workloads[o.UrgentWorkloadID].Plan.TargetID = "target-other"
			}},
			{"controller_plan_mismatch", func(s *MemoryStore, o *LLMDisplacementOperation) {
				s.workloads[o.VictimWorkloadID].Plan.ID = "controller-plan-other"
			}},
			{"stale_fence", func(s *MemoryStore, o *LLMDisplacementOperation) { s.leases[o.AcceleratorID].FencingToken++ }},
			{"expired_lease", func(s *MemoryStore, o *LLMDisplacementOperation) {
				s.leases[o.AcceleratorID].ExpiresAt = time.Now().Add(-time.Hour)
			}},
			{"missing_lease", func(s *MemoryStore, o *LLMDisplacementOperation) { delete(s.leases, o.AcceleratorID) }},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := NewMemoryStore()
				op := displacementFixture("stale-"+tc.name, "gpu0")
				seedDisplacementMemoryWorld(s, op)
				s.mu.Lock()
				tc.mutate(s, op)
				s.mu.Unlock()
				if _, _, err := s.CreateLLMDisplacementOperation(ctx, op); !errors.Is(err, ErrLLMDisplacementConflict) {
					t.Fatalf("stale world accepted: %v", err)
				}
			})
		}
	})
	t.Run("victim_and_urgent_bindings_are_complete", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*LLMDisplacementOperation)
		}{
			{"missing_urgent_plan", func(x *LLMDisplacementOperation) { x.UrgentBinding.LocalPlanID = "" }},
			{"missing_urgent_artifact_digest", func(x *LLMDisplacementOperation) { x.UrgentBinding.ArtifactDigest = "" }},
			{"missing_victim_runtime", func(x *LLMDisplacementOperation) { x.VictimBinding.RuntimeIdentity = "" }},
			{"missing_victim_profile", func(x *LLMDisplacementOperation) { x.VictimBinding.ProfileIdentity = "" }},
			{"missing_urgent_context", func(x *LLMDisplacementOperation) { x.UrgentBinding.ContextIdentity = "" }},
			{"missing_checkpoint_proof", func(x *LLMDisplacementOperation) { x.UrgentBinding.ProofBinding = "" }},
			{"missing_alias_inventory", func(x *LLMDisplacementOperation) { x.UrgentBinding.CatalogAliases = nil }},
			{"missing_controller_plan", func(x *LLMDisplacementOperation) { x.VictimBinding.ControllerPlanID = "" }},
			{"missing_local_pinned_plan", func(x *LLMDisplacementOperation) { x.UrgentBinding.LocalPlanHash = "" }},
			{"missing_actual_alias", func(x *LLMDisplacementOperation) { x.UrgentBinding.ActualAlias = "" }},
			{"duplicate_alias_inventory", func(x *LLMDisplacementOperation) {
				x.UrgentBinding.CatalogAliases = []string{"urgent-alias", "urgent-alias"}
			}},
			{"actual_alias_not_in_inventory", func(x *LLMDisplacementOperation) { x.UrgentBinding.ActualAlias = "not-listed" }},
			{"cross_node_binding", func(x *LLMDisplacementOperation) { x.UrgentBinding.NodeID = "node-b" }},
			{"cross_accelerator_binding", func(x *LLMDisplacementOperation) { x.VictimBinding.AcceleratorID = "gpu-other" }},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := NewMemoryStore()
				op := displacementFixture("invalid-"+tc.name, "gpu0")
				tc.mutate(op)
				if _, _, err := createMemoryDisplacement(ctx, s, op); err == nil {
					t.Fatal("incomplete or mismatched model binding was accepted")
				}
			})
		}
	})
	t.Run("one_unresolved_accelerator_and_expired_lease_guard", func(t *testing.T) {
		s := NewMemoryStore()
		in := displacementFixture("op1", "gpu0")
		if _, _, err := createMemoryDisplacement(ctx, s, in); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.leases["gpu0"].ExpiresAt = time.Now().Add(-time.Hour)
		s.mu.Unlock()
		if _, _, err := createMemoryDisplacement(ctx, s, displacementFixture("op2", "gpu0")); !errors.Is(err, ErrLLMDisplacementConflict) {
			t.Fatalf("second unresolved operation accepted: %v", err)
		}
		for _, workload := range []string{"victim", "urgent", "other"} {
			lease, created, err := s.AcquireAcceleratorLease(ctx, "gpu0", workload, time.Minute)
			if err != nil || created || lease == nil || lease.FencingToken != 17 {
				t.Fatalf("ordinary acquisition escaped custody for %q: %+v %t %v", workload, lease, created, err)
			}
		}
		lease, created, err := s.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, "gpu0", "victim", "checkpoint-op", time.Minute)
		if err != nil || created || lease == nil {
			t.Fatalf("checkpoint recovery escaped displacement custody: %+v %t %v", lease, created, err)
		}
		s.mu.Lock()
		s.llmDisplacementOps["op1"].Phase = "future_unknown"
		s.mu.Unlock()
		for _, acquire := range []func() (*domain.AcceleratorLease, bool, error){
			func() (*domain.AcceleratorLease, bool, error) {
				return s.AcquireAcceleratorLease(ctx, "gpu0", "other", time.Minute)
			},
			func() (*domain.AcceleratorLease, bool, error) {
				return s.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, "gpu0", "victim", "checkpoint-op", time.Minute)
			},
		} {
			if _, created, err := acquire(); err != nil || created {
				t.Fatalf("unknown malformed phase released custody: %t %v", created, err)
			}
		}
		s.mu.Lock()
		s.llmDisplacementOps["op1"].Phase = "completed"
		s.mu.Unlock()
		for _, acquire := range []func() (*domain.AcceleratorLease, bool, error){
			func() (*domain.AcceleratorLease, bool, error) {
				return s.AcquireAcceleratorLease(ctx, "gpu0", "other", time.Minute)
			},
			func() (*domain.AcceleratorLease, bool, error) {
				return s.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, "gpu0", "victim", "checkpoint-op", time.Minute)
			},
		} {
			if _, created, err := acquire(); err != nil || created {
				t.Fatalf("malformed completed record released custody: %t %v", created, err)
			}
		}
	})
	t.Run("malformed_completed_normal_revision_retains_custody_for_acquire_and_create", func(t *testing.T) {
		s := NewMemoryStore()
		initial := displacementFixture("bad-completed-revision", "gpu-revision")
		if _, _, err := createMemoryDisplacement(ctx, s, initial); err != nil {
			t.Fatal(err)
		}
		malformed := completedDisplacementFixture(initial)
		malformed.Revision = 1 // indexed/body agreement cannot excuse the wrong normal-phase revision.
		s.mu.Lock()
		s.llmDisplacementOps[initial.ID] = malformed
		s.mu.Unlock()
		for _, acquire := range []func() (*domain.AcceleratorLease, bool, error){
			func() (*domain.AcceleratorLease, bool, error) {
				return s.AcquireAcceleratorLease(ctx, initial.AcceleratorID, "replacement", time.Minute)
			},
			func() (*domain.AcceleratorLease, bool, error) {
				return s.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, initial.AcceleratorID, initial.VictimWorkloadID, "checkpoint-op", time.Minute)
			},
		} {
			if _, created, err := acquire(); err != nil || created {
				t.Fatalf("malformed completed revision released custody: created=%t err=%v", created, err)
			}
		}
		if _, _, err := s.CreateLLMDisplacementOperation(ctx, initial); !errors.Is(err, ErrLLMDisplacementConflict) {
			t.Fatalf("Create idempotency retry accepted malformed completed row: %v", err)
		}
		if _, _, err := createMemoryDisplacement(ctx, s, displacementFixture("second-bad-completed", initial.AcceleratorID)); !errors.Is(err, ErrLLMDisplacementConflict) {
			t.Fatalf("Create acquired malformed completed accelerator: %v", err)
		}
	})
	t.Run("sealed_intent_snapshot_cas_and_completion", func(t *testing.T) {
		s := NewMemoryStore()
		op, _, err := createMemoryDisplacement(ctx, s, displacementFixture("op1", "gpu0"))
		if err != nil {
			t.Fatal(err)
		}
		stored := op
		intent := func(phase, step, id string) {
			t.Helper()
			next := *stored
			next.Phase = phase
			next.CommandIntents = append(append([]LLMDisplacementCommandIntent(nil), stored.CommandIntents...), LLMDisplacementCommandIntent{Step: step, CommandID: id, Digest: "digest-" + step, Signature: "signature-" + step})
			var e error
			stored, e = s.UpdateLLMDisplacementOperation(ctx, &next, stored.Revision)
			if e != nil {
				t.Fatalf("%s: %v", phase, e)
			}
		}
		observed := func(phase, step, id string, set func(*LLMDisplacementOperation)) {
			t.Helper()
			next := *stored
			next.Phase = phase
			resultID := "result-" + step
			if step == "snapshot" {
				resultID = "snapshot-v1"
			}
			next.ObservedResults = append(append([]LLMDisplacementObservedResult(nil), stored.ObservedResults...), displacementResult(step, id, resultID, "result-digest-"+step, stored.ProofBinding))
			set(&next)
			var e error
			stored, e = s.UpdateLLMDisplacementOperation(ctx, &next, stored.Revision)
			if e != nil {
				t.Fatalf("%s: %v", phase, e)
			}
		}
		intent("pause_intent_sealed", "pause", "cmd-pause")
		futureFlag := *stored
		futureFlag.SafeBoundaryObserved = true
		if _, err := s.UpdateLLMDisplacementOperation(ctx, &futureFlag, stored.Revision); err == nil {
			t.Fatal("future observed flag accepted before its result")
		}
		intentCopy := *stored
		intentCopy.CommandIntents = append([]LLMDisplacementCommandIntent(nil), stored.CommandIntents...)
		intentCopy.CommandIntents[0].Digest = "changed"
		if _, err = s.UpdateLLMDisplacementOperation(ctx, &intentCopy, stored.Revision); !errors.Is(err, ErrLLMDisplacementConflict) {
			t.Fatalf("sealed command rewritten: %v", err)
		}
		badResult := *stored
		badResult.Phase = "safe_boundary_paused"
		badResult.SafeBoundaryObserved = true
		badResult.ObservedResults = []LLMDisplacementObservedResult{displacementResult("pause", "different-command", "result", "digest", stored.ProofBinding)}
		if _, err = s.UpdateLLMDisplacementOperation(ctx, &badResult, stored.Revision); err == nil {
			t.Fatalf("unbound pause result accepted: %v", err)
		}
		missingSignature := *stored
		missingSignature.Phase = "safe_boundary_paused"
		missingSignature.SafeBoundaryObserved = true
		unsigned := displacementResult("pause", "cmd-pause", "unsigned-result", "digest", stored.ProofBinding)
		unsigned.Signature = ""
		missingSignature.ObservedResults = []LLMDisplacementObservedResult{unsigned}
		if _, err := s.UpdateLLMDisplacementOperation(ctx, &missingSignature, stored.Revision); err == nil {
			t.Fatal("observed result without retained signature accepted")
		}
		tamperedEnvelope := *stored
		tamperedEnvelope.Phase = "safe_boundary_paused"
		tamperedEnvelope.SafeBoundaryObserved = true
		tampered := displacementResult("pause", "cmd-pause", "tampered-result", "digest", stored.ProofBinding)
		tampered.Digest = "substituted-digest"
		tamperedEnvelope.ObservedResults = []LLMDisplacementObservedResult{tampered}
		if _, err := s.UpdateLLMDisplacementOperation(ctx, &tamperedEnvelope, stored.Revision); err == nil {
			t.Fatal("observed result fields detached from signed envelope accepted")
		}
		bad := *stored
		bad.Phase = "snapshot_intent_sealed"
		if _, err = s.UpdateLLMDisplacementOperation(ctx, &bad, stored.Revision); err == nil {
			t.Fatalf("phase skip accepted: %v", err)
		}
		stale := *stored
		if _, err = s.UpdateLLMDisplacementOperation(ctx, &stale, op.Revision); !errors.Is(err, ErrLLMDisplacementConflict) {
			t.Fatalf("stale revision accepted: %v", err)
		}
		observed("safe_boundary_paused", "pause", "cmd-pause", func(x *LLMDisplacementOperation) { x.SafeBoundaryObserved = true })
		intent("snapshot_intent_sealed", "snapshot", "cmd-snapshot")
		observed("snapshot_captured", "snapshot", "cmd-snapshot", func(x *LLMDisplacementOperation) { x.SnapshotObserved = true; x.SnapshotIdentity = "snapshot-v1" })
		changedResult := *stored
		changedResult.Phase = "victim_stop_intent_sealed"
		changedResult.CommandIntents = append(append([]LLMDisplacementCommandIntent(nil), stored.CommandIntents...), LLMDisplacementCommandIntent{Step: "victim_stop", CommandID: "cmd-stop-bad", Digest: "digest", Signature: "signature"})
		changedResult.ObservedResults = append([]LLMDisplacementObservedResult(nil), stored.ObservedResults...)
		changedResult.ObservedResults[1].Signature = "rewritten-signature"
		if _, err = s.UpdateLLMDisplacementOperation(ctx, &changedResult, stored.Revision); err == nil {
			t.Fatalf("observed snapshot result rewritten: %v", err)
		}
		mutatedSnapshot := *stored
		mutatedSnapshot.Phase = "victim_stop_intent_sealed"
		mutatedSnapshot.CommandIntents = append(append([]LLMDisplacementCommandIntent(nil), stored.CommandIntents...), LLMDisplacementCommandIntent{Step: "victim_stop", CommandID: "cmd-stop-bad", Digest: "digest", Signature: "signature"})
		mutatedSnapshot.SnapshotIdentity = "snapshot-v2"
		if _, err := s.UpdateLLMDisplacementOperation(ctx, &mutatedSnapshot, stored.Revision); err == nil {
			t.Fatalf("snapshot identity rewritten: %v", err)
		}
		intent("victim_stop_intent_sealed", "victim_stop", "cmd-stop")
		duplicateCommand := *stored
		duplicateCommand.Phase = "urgent_load_intent_sealed"
		duplicateCommand.CommandIntents = append(append([]LLMDisplacementCommandIntent(nil), stored.CommandIntents...), LLMDisplacementCommandIntent{Step: "urgent_load", CommandID: "cmd-stop", Digest: "duplicate", Signature: "duplicate"})
		if _, err := s.UpdateLLMDisplacementOperation(ctx, &duplicateCommand, stored.Revision); err == nil {
			t.Fatal("duplicate command ID reused across side-effect steps")
		}
		observed("victim_stopped", "victim_stop", "cmd-stop", func(x *LLMDisplacementOperation) { x.VictimStopObserved = true })
		intent("urgent_load_intent_sealed", "urgent_load", "cmd-load")
		observed("urgent_loaded", "urgent_load", "cmd-load", func(x *LLMDisplacementOperation) { x.UrgentLoadObserved = true })
		intent("urgent_stop_intent_sealed", "urgent_stop", "cmd-urgent-stop")
		observed("urgent_stopped", "urgent_stop", "cmd-urgent-stop", func(x *LLMDisplacementOperation) { x.UrgentStopObserved = true })
		intent("victim_reload_intent_sealed", "victim_reload", "cmd-reload")
		observed("victim_reloaded", "victim_reload", "cmd-reload", func(x *LLMDisplacementOperation) { x.VictimReloadObserved = true })
		intent("kv_restore_intent_sealed", "kv_restore", "cmd-kv")
		observed("kv_restored", "kv_restore", "cmd-kv", func(x *LLMDisplacementOperation) { x.KVRestoreObserved = true })
		premature := *stored
		premature.Phase = "settled"
		premature.LeaseSettled = true
		premature.SnapshotCustodySettled = true
		if _, err := s.UpdateLLMDisplacementOperation(ctx, &premature, stored.Revision); err == nil {
			t.Fatalf("settlement without observed evidence accepted: %v", err)
		}
		intent("settlement_intent_sealed", "settlement", "cmd-settlement")
		observed("settled", "settlement", "cmd-settlement", func(x *LLMDisplacementOperation) { x.LeaseSettled = true; x.SnapshotCustodySettled = true })
		next := *stored
		next.Phase = "completed"
		next.ObservedProof = "result-digest-settlement"
		stored, err = s.UpdateLLMDisplacementOperation(ctx, &next, stored.Revision)
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		delete(s.leases, "gpu0") // the trusted settlement observer's external lease boundary
		s.mu.Unlock()
		blocked, created, err := s.AcquireAcceleratorLease(ctx, "gpu0", "urgent", time.Minute)
		if err != nil || !created || blocked.WorkloadID != "urgent" {
			t.Fatalf("settled operation retained custody: %+v %t %v", blocked, created, err)
		}
	})
	t.Run("uncertain_and_manual_reconciliation_retain_custody", func(t *testing.T) {
		for _, phase := range []string{"pending", "uncertain", "manual_reconciliation"} {
			t.Run(phase, func(t *testing.T) {
				s := NewMemoryStore()
				op, _, err := createMemoryDisplacement(ctx, s, displacementFixture("op1", "gpu0"))
				if err != nil {
					t.Fatal(err)
				}
				next := *op
				next.Phase = phase
				reconciliation, updateErr := s.UpdateLLMDisplacementOperation(ctx, &next, op.Revision)
				if updateErr != nil {
					t.Fatal(updateErr)
				}
				if reconciliation.Revision != op.Revision+1 || validateLLMDisplacementIdentity(reconciliation) != nil {
					t.Fatalf("%s reconciliation revision/history invalid: %+v", phase, reconciliation)
				}
				attemptCompletion := *reconciliation
				attemptCompletion.Phase = "completed"
				if _, err = s.UpdateLLMDisplacementOperation(ctx, &attemptCompletion, reconciliation.Revision); err == nil {
					t.Fatalf("%s operation advanced directly to completed", phase)
				}
				if _, created, err := s.AcquireAcceleratorLease(ctx, "gpu0", "other", time.Minute); err != nil || created {
					t.Fatalf("%s custody released: %t %v", phase, created, err)
				}
			})
		}
	})
	t.Run("concurrent_same_accelerator_creation", func(t *testing.T) {
		s := NewMemoryStore()
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, id := range []string{"op-a", "op-b"} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				_, _, err := createMemoryDisplacement(ctx, s, displacementFixture(id, "gpu0"))
				results <- err
			}(id)
		}
		wg.Wait()
		close(results)
		success, conflict := 0, 0
		for err := range results {
			if err == nil {
				success++
			} else if errors.Is(err, ErrLLMDisplacementConflict) {
				conflict++
			} else {
				t.Fatalf("unexpected create error: %v", err)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatalf("race results success=%d conflict=%d", success, conflict)
		}
	})
}
