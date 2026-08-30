package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

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
