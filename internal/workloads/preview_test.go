package workloads

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestPreviewPreservesLongContextProfileForRequestsThatFitShortProfile(t *testing.T) {
	backing := store.NewMemoryStore()
	manager := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), backing, time.Second)
	manager.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	manager.RegisterTarget(Target{ID: "same-model-short", Adapter: "llamacpp", Models: []string{"model-a"}, ResidentModels: []string{"model-a"}, ContextLimit: 8192, Slots: 4, CapacityVerified: true, Enabled: true})
	manager.RegisterTarget(Target{ID: "same-model-long", Adapter: "llamacpp", Models: []string{"model-a"}, ResidentModels: []string{"model-a"}, ContextLimit: 32768, Slots: 1, CapacityVerified: true, Enabled: true})

	request := domain.WorkloadRequest{OwnerID: "owner", Adapter: "llamacpp", WorkloadType: "llm.chat", Payload: json.RawMessage(`{"model":"model-a","messages":[{"role":"user","content":"hello"}]}`), Bounds: domain.WorkloadBounds{ContextTokens: 4096}, Egress: domain.EgressLocalOnly}
	preview, err := manager.Preview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Recommended != "same-model-short" {
		t.Fatalf("short request should preserve long-context target, got %q: %+v", preview.Recommended, preview.Candidates)
	}
	rows, err := backing.ListWorkloads(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("preview created durable work: rows=%d err=%v", len(rows), err)
	}

	request.Bounds.ContextTokens = 16384
	preview, err = manager.Preview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Recommended != "same-model-long" {
		t.Fatalf("long request should use only compatible target, got %q: %+v", preview.Recommended, preview.Candidates)
	}
	if preview.Candidates[len(preview.Candidates)-1].Blocker == "" {
		t.Fatalf("short-context target did not explain incompatibility: %+v", preview.Candidates)
	}
}

func TestTargetPolicyOverrideIsValidatedAndDurable(t *testing.T) {
	backing := store.NewMemoryStore()
	manager := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), backing, time.Second)
	manager.RegisterTarget(Target{ID: "gpu-route", Adapter: "llamacpp", AcceleratorVRAMMB: 10240, Enabled: true, MaxSlowdown: 1.2})
	policy := &domain.TargetPolicyOverride{TargetID: "gpu-route", Enabled: true, SharingEnabled: true, GuardedExploration: true, VRAMReserveMB: 768, MaxSlowdown: 1.35, UpdatedBy: "operator", UpdatedAt: time.Now().UTC()}
	if _, err := manager.UpdateTargetPolicy(*policy); err != nil {
		t.Fatal(err)
	}
	if _, err := backing.UpsertTargetPolicyOverride(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	stored, err := backing.ListTargetPolicyOverrides(context.Background())
	if err != nil || len(stored) != 1 || stored[0].VRAMReserveMB != 768 || !stored[0].GuardedExploration {
		t.Fatalf("policy did not round-trip: %+v err=%v", stored, err)
	}
	if _, err := manager.UpdateTargetPolicy(domain.TargetPolicyOverride{TargetID: "gpu-route", Enabled: true, GuardedExploration: true, MaxSlowdown: 1.2}); err == nil {
		t.Fatal("guarded exploration without sharing was accepted")
	}
}

func TestDiscoveredTargetAppliesDurablePolicyOnRegistration(t *testing.T) {
	backing := store.NewMemoryStore()
	_, err := backing.UpsertTargetPolicyOverride(context.Background(), &domain.TargetPolicyOverride{TargetID: "discovered", Enabled: false, Quarantined: true, VRAMReserveMB: 512, MaxSlowdown: 0, UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), backing, time.Second)
	manager.RegisterTarget(Target{ID: "discovered", Adapter: "llamacpp", Enabled: true})
	targets := manager.Targets()
	if len(targets) != 1 || targets[0].Enabled || !targets[0].Quarantined || targets[0].VRAMReserveMB != 512 {
		t.Fatalf("registered target did not inherit durable policy: %+v", targets)
	}
}
