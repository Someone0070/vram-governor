package store

import (
	"context"
	"errors"
	"testing"
)

func TestPostgresLLMDisplacementCAS(t *testing.T) {
	backing, state := newDisplacementSemanticPG(t)
	ctx := context.Background()
	op := displacementFixture("cas-op", "gpu0")
	seedDisplacementSemanticWorld(state, op)
	created, ok, err := backing.CreateLLMDisplacementOperation(ctx, op)
	if err != nil || !ok {
		t.Fatalf("create: %t %v", ok, err)
	}
	sealed := *created
	sealed.Phase = "pause_intent_sealed"
	sealed.CommandIntents = []LLMDisplacementCommandIntent{{Step: "pause", CommandID: "cmd", Digest: "digest", Signature: "signature"}}
	stored, err := backing.UpdateLLMDisplacementOperation(ctx, &sealed, created.Revision)
	if err != nil {
		t.Fatal(err)
	}
	changed := *stored
	changed.CommandIntents = append([]LLMDisplacementCommandIntent(nil), stored.CommandIntents...)
	changed.CommandIntents[0].Signature = "replacement"
	if _, err := backing.UpdateLLMDisplacementOperation(ctx, &changed, stored.Revision); !errors.Is(err, ErrLLMDisplacementConflict) {
		t.Fatalf("sealed signed command was mutable: %v", err)
	}
	stale := *stored
	stale.Phase = "safe_boundary_paused"
	stale.SafeBoundaryObserved = true
	stale.ObservedResults = []LLMDisplacementObservedResult{displacementResult("pause", "cmd", "result-pause", "result-digest", stored.ProofBinding)}
	if _, err := backing.UpdateLLMDisplacementOperation(ctx, &stale, created.Revision); !errors.Is(err, ErrLLMDisplacementConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	correct := *stored
	correct.Phase = "safe_boundary_paused"
	correct.SafeBoundaryObserved = true
	correct.ObservedResults = []LLMDisplacementObservedResult{displacementResult("pause", "cmd", "result-pause", "result-digest", stored.ProofBinding)}
	updated, err := backing.UpdateLLMDisplacementOperation(ctx, &correct, stored.Revision)
	if err != nil || updated.Revision != stored.Revision+1 {
		t.Fatalf("valid CAS: %+v %v", updated, err)
	}
	got, err := backing.GetLLMDisplacementOperation(ctx, updated.ID)
	if err != nil || got.CommandIntents[0].Signature != "signature" || got.Phase != "safe_boundary_paused" || got.Revision != updated.Revision {
		t.Fatalf("CAS durability: %+v %v", got, err)
	}
}
