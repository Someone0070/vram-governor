package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

func storeTestTimePtr(value time.Time) *time.Time { return &value }

func TestMemoryLeaseFencingAndExclusion(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	for _, id := range []string{"one", "two"} {
		_, _, err := s.CreateWorkload(ctx, &domain.Workload{Request: domain.WorkloadRequest{ID: id, OwnerID: "owner"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	first, acquired, err := s.AcquireAcceleratorLease(ctx, "gpu-0", "one", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("first lease: %+v %v %v", first, acquired, err)
	}
	current, acquired, err := s.AcquireAcceleratorLease(ctx, "gpu-0", "two", time.Minute)
	if err != nil || acquired || current.WorkloadID != "one" {
		t.Fatalf("double booking allowed: %+v %v %v", current, acquired, err)
	}
	if err := s.ReleaseAcceleratorLease(ctx, "gpu-0", "one", first.FencingToken); err != nil {
		t.Fatal(err)
	}
	second, acquired, err := s.AcquireAcceleratorLease(ctx, "gpu-0", "two", time.Minute)
	if err != nil || !acquired || second.FencingToken <= first.FencingToken {
		t.Fatalf("fence did not advance: first=%+v second=%+v acquired=%v err=%v", first, second, acquired, err)
	}
	if err := s.RenewAcceleratorLease(ctx, "gpu-0", "one", first.FencingToken, time.Minute); err == nil {
		t.Fatal("stale lease token renewed a new owner's lease")
	}
}

func TestMemoryLeaseCleanupIntentIsExactAndIdempotent(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	lease, acquired, err := s.AcquireAcceleratorLease(ctx, "gpu-cleanup", "owner-a", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire: %+v %v %v", lease, acquired, err)
	}
	if err := s.ReleaseAcceleratorLease(ctx, lease.AcceleratorID, "owner-b", lease.FencingToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-owner release was not fenced: %v", err)
	}
	if _, err := s.GetAcceleratorLease(ctx, lease.AcceleratorID); err != nil {
		t.Fatalf("wrong-owner release removed live lease: %v", err)
	}
	now := time.Now().UTC().Add(-time.Second)
	first, err := s.RecordAcceleratorLeaseCleanupIntent(ctx, &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: lease.AcceleratorID, Owner: "owner-a", FencingToken: lease.FencingToken, Attempts: 1, LastError: "first", CreatedAt: now, UpdatedAt: now})
	if err != nil || first.Attempts != 1 {
		t.Fatalf("record intent: %+v %v", first, err)
	}
	second, err := s.RecordAcceleratorLeaseCleanupIntent(ctx, &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: lease.AcceleratorID, Owner: "owner-a", FencingToken: lease.FencingToken, Attempts: 3, LastError: "retry", CreatedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute)})
	if err != nil || second.Attempts != 3 || !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("idempotent intent update lost identity/history: %+v %v", second, err)
	}
	intents, err := s.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 10)
	if err != nil || len(intents) != 1 || intents[0].FencingToken != lease.FencingToken {
		t.Fatalf("list intent: %+v %v", intents, err)
	}
	if err := s.DeleteAcceleratorLeaseCleanupIntent(ctx, lease.AcceleratorID, "owner-b", lease.FencingToken); err != nil {
		t.Fatal(err)
	}
	if intents, _ := s.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 10); len(intents) != 1 {
		t.Fatal("wrong-owner intent delete removed exact cleanup intent")
	}
	if err := s.DeleteAcceleratorLeaseCleanupIntent(ctx, lease.AcceleratorID, "owner-a", lease.FencingToken); err != nil {
		t.Fatal(err)
	}
	if intents, _ := s.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 10); len(intents) != 0 {
		t.Fatalf("cleanup intent was not deleted: %+v", intents)
	}
}

func TestMemoryLeaseCleanupRetryAttemptsAdvanceAndDelete(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	now := time.Now().UTC()
	intent := &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: "retry-gpu", Owner: "retry-owner", FencingToken: 3, Attempts: 1, LastError: "first", CreatedAt: now, UpdatedAt: now, NextRetryAt: storeTestTimePtr(now.Add(time.Second))}
	stored, err := s.RecordAcceleratorLeaseCleanupIntent(ctx, intent)
	if err != nil || stored.Attempts != 1 {
		t.Fatalf("initial retry intent: %+v %v", stored, err)
	}
	previousNext := stored.NextRetryAt
	for attempt, delay := range []time.Duration{2 * time.Second, 4 * time.Second} {
		updated := *stored
		updated.Attempts = attempt + 2
		updated.UpdatedAt = now.Add(time.Duration(attempt+1) * time.Second)
		updated.NextRetryAt = storeTestTimePtr(now.Add(delay))
		stored, err = s.RecordAcceleratorLeaseCleanupIntent(ctx, &updated)
		if err != nil || stored.Attempts != attempt+2 || stored.NextRetryAt == nil || !stored.NextRetryAt.After(*previousNext) {
			t.Fatalf("retry attempt %d did not advance monotonically: %+v %v", attempt+2, stored, err)
		}
		previousNext = stored.NextRetryAt
	}
	if err := s.DeleteAcceleratorLeaseCleanupIntent(ctx, "retry-gpu", "retry-owner", 3); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.ListAcceleratorLeaseCleanupIntents(ctx, now.Add(time.Hour), 10); err != nil || len(rows) != 0 {
		t.Fatalf("successful retry did not delete exact intent: %+v %v", rows, err)
	}
}

func TestMemoryTerminalCleanupIntentIsTypedImmutableAndPhaseDurable(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	future := time.Now().UTC().Add(time.Hour)
	base := &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: "typed-gpu", Owner: "typed-owner", FencingToken: 9, WorkloadID: "typed-workload", ExpectedWorkloadRevision: 4, TerminalDisposition: "failure", TerminalErrorCode: "terminal_failure", Attempts: 2, LastError: "terminal_failure", NextRetryAt: &future}
	stored, err := s.RecordAcceleratorLeaseCleanupIntent(ctx, base)
	if err != nil || stored.ExpectedWorkloadRevision != 4 || !stored.NextRetryAt.Equal(future) {
		t.Fatalf("typed intent exact record failed: %+v %v", stored, err)
	}
	conflict := *base
	conflict.TerminalDisposition = "cancel"
	if _, err := s.RecordAcceleratorLeaseCleanupIntent(ctx, &conflict); !errors.Is(err, ErrAcceleratorLeaseCleanupConflict) {
		t.Fatalf("conflicting continuation was accepted: %v", err)
	}
	phase := *base
	phase.ReleaseConfirmed, phase.TerminalPublished, phase.AuditPublished, phase.NotificationPublished, phase.BudgetSettled = true, true, true, true, true
	phase.Attempts = 1
	updated, err := s.RecordAcceleratorLeaseCleanupIntent(ctx, &phase)
	if err != nil || updated.Attempts != 2 || !updated.BudgetSettled {
		t.Fatalf("phase/attempt update was not monotonic: %+v %v", updated, err)
	}
	if rows, _ := s.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 1001); len(rows) != 0 {
		t.Fatal("future typed intent was exposed by due-list")
	}
}

func TestResidencyGenerationCASRejectsStaleWrites(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	base := &domain.ModelResidency{ID: "target::model", TargetID: "target", Model: "model", TargetGeneration: 2, ExecutionFingerprint: "new", ObservedTier: domain.ResidencyHotVRAM, DesiredTier: domain.ResidencyHotVRAM, UpdatedAt: time.Now().UTC()}
	stored, err := s.UpsertModelResidency(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	stale := *stored
	stale.TargetGeneration = 1
	stale.ExecutionFingerprint = "old"
	if _, err := s.CompareAndSwapModelResidency(ctx, &stale, stored.Revision); !errors.Is(err, ErrModelResidencyGenerationConflict) {
		t.Fatalf("stale generation write was accepted: %v", err)
	}
	fingerprintDrift := *stored
	fingerprintDrift.ExecutionFingerprint = "other"
	if _, err := s.CompareAndSwapModelResidency(ctx, &fingerprintDrift, stored.Revision); !errors.Is(err, ErrModelResidencyGenerationConflict) {
		t.Fatalf("same-generation fingerprint drift was accepted: %v", err)
	}
	fresh := *stored
	fresh.TargetGeneration = 3
	fresh.ExecutionFingerprint = "fresh"
	if _, err := s.CompareAndSwapModelResidency(ctx, &fresh, stored.Revision); err != nil {
		t.Fatalf("newer generation write was rejected: %v", err)
	}
}

func TestResidencyGenerationFingerprintMatrix(t *testing.T) {
	cases := []struct {
		name        string
		existingFP  string
		incomingGen uint64
		incomingFP  string
		wantErr     bool
	}{
		{name: "equal-both-empty", existingFP: "", incomingGen: 2, incomingFP: "", wantErr: true},
		{name: "equal-existing-only", existingFP: "stored", incomingGen: 2, incomingFP: "", wantErr: true},
		{name: "equal-incoming-only", existingFP: "", incomingGen: 2, incomingFP: "stored", wantErr: true},
		{name: "equal-exact", existingFP: "stored", incomingGen: 2, incomingFP: "stored"},
		{name: "lower", existingFP: "stored", incomingGen: 1, incomingFP: "stored", wantErr: true},
		{name: "higher-empty", existingFP: "stored", incomingGen: 3, incomingFP: "", wantErr: true},
		{name: "legacy-upgrade", existingFP: "", incomingGen: 3, incomingFP: "new"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := NewMemoryStore()
			stored, err := s.UpsertModelResidency(ctx, &domain.ModelResidency{ID: "matrix::model", TargetID: "matrix", Model: "model", TargetGeneration: 2, ExecutionFingerprint: tc.existingFP})
			if err != nil {
				t.Fatal(err)
			}
			incoming := *stored
			incoming.TargetGeneration = tc.incomingGen
			incoming.ExecutionFingerprint = tc.incomingFP
			_, err = s.CompareAndSwapModelResidency(ctx, &incoming, stored.Revision)
			if tc.wantErr {
				if !errors.Is(err, ErrModelResidencyGenerationConflict) {
					t.Fatalf("matrix case accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("matrix case rejected: %v", err)
			}
		})
	}
}

func TestMemoryWorkloadSnapshotsDoNotAliasMutableRequestState(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	row := &domain.Workload{
		Request:          domain.WorkloadRequest{ID: "immutable", OwnerID: "owner", Transformations: []string{"reduce_steps"}, TransformationParameters: json.RawMessage(`{"max":20}`)},
		TargetRetryAfter: map[string]time.Time{"cloud": time.Now().UTC()},
		Plan:             &domain.ExecutionPlan{ResidencyTransitionIDs: []string{"load-1"}},
	}
	if _, _, err := store.CreateWorkload(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.Request.Transformations[0] = "mutated"
	row.Request.TransformationParameters[2] = 'X'
	row.TargetRetryAfter["other"] = time.Now().UTC()
	row.Plan.ResidencyTransitionIDs[0] = "mutated"
	stored, err := store.GetWorkload(ctx, row.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Request.Transformations[0] != "reduce_steps" || !json.Valid(stored.Request.TransformationParameters) || len(stored.TargetRetryAfter) != 1 || stored.Plan.ResidencyTransitionIDs[0] != "load-1" {
		t.Fatalf("stored workload aliased caller-owned mutable state: %+v", stored)
	}
}

func TestMemoryWorkloadIdempotencyIsOwnerScoped(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	makeWorkload := func(id, owner string) *domain.Workload {
		return &domain.Workload{Request: domain.WorkloadRequest{ID: id, OwnerID: owner, IdempotencyKey: "same"}}
	}
	if _, created, _ := s.CreateWorkload(ctx, makeWorkload("a", "owner-a")); !created {
		t.Fatal("first submission was not created")
	}
	existing, created, _ := s.CreateWorkload(ctx, makeWorkload("b", "owner-a"))
	if created || existing.Request.ID != "a" {
		t.Fatalf("owner idempotency failed: %+v created=%v", existing, created)
	}
	other, created, _ := s.CreateWorkload(ctx, makeWorkload("c", "owner-b"))
	if !created || other.Request.ID != "c" {
		t.Fatalf("idempotency leaked across owners: %+v created=%v", other, created)
	}
}

func TestLegacyWorkloadRevisionRequiresFirstAtomicClaim(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	s.workloads["legacy"] = &domain.Workload{Request: domain.WorkloadRequest{ID: "legacy", OwnerID: "owner"}, Status: domain.WorkloadQueued}
	legacy, err := s.GetWorkload(ctx, "legacy")
	if err != nil || legacy.Revision != 0 {
		t.Fatalf("legacy fixture was not loaded: %+v err=%v", legacy, err)
	}
	stale := *legacy
	stale.Error = "stale"
	if _, err := s.UpdateWorkload(ctx, &stale); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("zero revision update acted as wildcard: %v", err)
	}
	claimed := *legacy
	claimed.Error = "claimed"
	updated, err := s.CompareAndSwapWorkload(ctx, &claimed, 0, domain.WorkloadQueued, "")
	if err != nil || updated.Revision != 1 || updated.Error != "claimed" {
		t.Fatalf("first atomic legacy claim did not normalize revision: %+v err=%v", updated, err)
	}
}

func TestBudgetClaimTokenPreventsLosingCleanup(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	first, allowed, created, err := s.ReserveBudgetClaim(ctx, "principal", "workload", 10, 100, "attempt-a")
	if err != nil || !allowed || !created || first.OwnershipToken == "" || first.Revision != 1 || first.Attempt != 1 {
		t.Fatalf("initial budget claim invalid: %+v allowed=%v err=%v", first, allowed, err)
	}
	second, allowed, created, err := s.ReserveBudgetClaim(ctx, "principal", "workload", 10, 100, "attempt-b")
	if !errors.Is(err, ErrWorkloadConflict) || allowed || created || second == nil || second.OwnershipToken == "attempt-b" {
		t.Fatalf("foreign budget claim was reusable: %+v allowed=%v created=%v err=%v", second, allowed, created, err)
	}
	resume, allowed, created, err := s.ReserveBudgetClaim(ctx, "principal", "workload", 10, 100, "attempt-a")
	if err != nil || !allowed || created || resume.OwnershipToken != first.OwnershipToken {
		t.Fatalf("same attempt could not resume: %+v allowed=%v created=%v err=%v", resume, allowed, created, err)
	}
	if err := s.ReleaseBudgetClaim(ctx, "workload", "losing-token", first.Attempt); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("losing cleanup released winner reservation: %v", err)
	}
	if _, err := s.SettleBudgetClaim(ctx, "workload", first.OwnershipToken, first.Attempt, 9); err != nil {
		t.Fatalf("winning claim could not settle: %v", err)
	}
	if err := s.ReleaseBudgetClaim(ctx, "workload", first.OwnershipToken, first.Attempt); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("released a settled reservation: %v", err)
	}
}

func TestReserveAndLinkBudgetClaimIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	created, _, err := s.CreateWorkload(ctx, &domain.Workload{Request: domain.WorkloadRequest{ID: "atomic-budget", PrincipalID: "principal"}, Status: domain.WorkloadQueued, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		reservation *domain.BudgetReservation
		workload    *domain.Workload
		err         error
	}
	results := make(chan result, 2)
	for _, token := range []string{"attempt-a", "attempt-b"} {
		go func(token string) {
			reservation, workload, _, _, callErr := s.ReserveAndLinkBudgetClaim(ctx, "principal", "atomic-budget", 10, 100, token, created.Revision, domain.WorkloadQueued, "")
			results <- result{reservation: reservation, workload: workload, err: callErr}
		}(token)
	}
	var winner result
	losers := 0
	for i := 0; i < 2; i++ {
		out := <-results
		if out.err == nil {
			winner = out
		} else if errors.Is(out.err, ErrWorkloadConflict) {
			losers++
		} else {
			t.Fatalf("unexpected claim error: %v", out.err)
		}
	}
	if winner.reservation == nil || winner.workload == nil || losers != 1 || winner.workload.BudgetReservationToken != winner.reservation.OwnershipToken || winner.workload.BudgetReservationAttempt != winner.reservation.Attempt {
		t.Fatalf("claim/link was not atomic: winner=%+v losers=%d", winner, losers)
	}
	if _, _, _, _, err := s.ReserveAndLinkBudgetClaim(ctx, "principal", "atomic-budget", 18, 100, winner.reservation.OwnershipToken, winner.workload.Revision, domain.WorkloadQueued, ""); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("same-token amount mutation was accepted: %v", err)
	}
	rows, err := s.ListBudgetReservations(ctx, "principal")
	if err != nil || len(rows) != 1 || rows[0].Status != domain.BudgetReserved {
		t.Fatalf("unexpected budget rows after atomic claim: %+v err=%v", rows, err)
	}
	if _, err := s.SettleBudgetClaim(ctx, "atomic-budget", winner.reservation.OwnershipToken, winner.reservation.Attempt, winner.reservation.ReservedCents); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.ReserveAndLinkBudgetClaim(ctx, "principal", "atomic-budget", winner.reservation.ReservedCents, winner.reservation.LimitCents, winner.reservation.OwnershipToken, winner.workload.Revision, domain.WorkloadQueued, ""); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("settled reservation was resumable: %v", err)
	}
}

func TestTerminalBudgetCASRequiresSettlementIntent(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	created, _, err := s.CreateWorkload(ctx, &domain.Workload{
		Request:                  domain.WorkloadRequest{ID: "terminal-budget-intent", PrincipalID: "principal"},
		Status:                   domain.WorkloadRunning,
		Plan:                     &domain.ExecutionPlan{EstimatedCostCents: 12},
		BudgetReservationToken:   "claim",
		BudgetReservationAttempt: 1,
		CreatedAt:                time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := *created
	terminal.Status = domain.WorkloadSucceeded
	if _, err := s.CompareAndSwapWorkload(ctx, &terminal, created.Revision, domain.WorkloadRunning, ""); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("terminal CAS without settlement intent was accepted: %v", err)
	}
	terminal.BudgetSettlementPending = true
	terminal.BudgetSettlementAttempt = 1
	terminal.BudgetSettlementActualCents = 12
	settled, err := s.CompareAndSwapWorkload(ctx, &terminal, created.Revision, domain.WorkloadRunning, "")
	if err != nil || !settled.BudgetSettlementPending || settled.Revision != created.Revision+1 {
		t.Fatalf("terminal CAS with intent failed: %+v err=%v", settled, err)
	}
}
