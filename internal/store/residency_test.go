package store

import (
	"context"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

func TestResidencyTransitionIdempotency(t *testing.T) {
	backing := NewMemoryStore()
	now := time.Now().UTC()
	residency := &domain.ModelResidency{ID: "router::model", TargetID: "router", Model: "model", DesiredTier: domain.ResidencyHotVRAM, ObservedTier: domain.ResidencyColdDisk, Policy: domain.ResidencyAuto, UpdatedAt: now}
	if _, err := backing.UpsertModelResidency(context.Background(), residency); err != nil {
		t.Fatal(err)
	}
	transition := &domain.ResidencyTransition{ID: "first", IdempotencyKey: "same-command", TargetID: "router", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Status: domain.ResidencyTransitionPlanned, CreatedAt: now}
	first, created, err := backing.CreateResidencyTransition(context.Background(), transition)
	if err != nil || !created {
		t.Fatalf("first transition: created=%t err=%v", created, err)
	}
	duplicate := *transition
	duplicate.ID = "second"
	again, created, err := backing.CreateResidencyTransition(context.Background(), &duplicate)
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("idempotency did not return original: row=%+v created=%t err=%v", again, created, err)
	}
	got, err := backing.GetModelResidency(context.Background(), "router", "model")
	if err != nil || got.ObservedTier != domain.ResidencyColdDisk {
		t.Fatalf("residency round trip: %+v err=%v", got, err)
	}
}
