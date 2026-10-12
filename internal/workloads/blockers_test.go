package workloads

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestClassifyBlockerAndDominantCode(t *testing.T) {
	cases := map[string]domain.AdmissionBlocker{
		"gpu: node disconnected or not ready":                       domain.BlockerNodeOffline,
		"gpu: provider/model route is quarantined":                  domain.BlockerNodeOffline,
		"gpu: model unavailable":                                    domain.BlockerRuntimeUnsupported,
		"CAPABILITY_UNAVAILABLE":                                    domain.BlockerRuntimeUnsupported,
		"gpu: accelerator residency transition in progress":         domain.BlockerTransitionBusy,
		"gpu: model loading requires an operator transition":        domain.BlockerPinnedResident,
		"gpu: all execution slots are busy":                         domain.BlockerCapacity,
		"gpu: accelerator is reserved by other":                     domain.BlockerCapacity,
		"gpu: model load failed: resident within min_residency now": domain.BlockerTransitionBusy,
	}
	for text, want := range cases {
		if got := ClassifyBlocker(text); got != want {
			t.Fatalf("ClassifyBlocker(%q)=%s want %s", text, got, want)
		}
	}
	if got := dominantBlockerCode([]domain.AdmissionBlocker{domain.BlockerNodeOffline, domain.BlockerNodeOffline}); got != domain.BlockerNodeOffline {
		t.Fatalf("shared code was not kept: %s", got)
	}
	if got := dominantBlockerCode([]domain.AdmissionBlocker{domain.BlockerNodeOffline, domain.BlockerTransitionBusy}); got != domain.BlockerCapacity {
		t.Fatalf("mixed codes must report capacity: %s", got)
	}
	if got := dominantBlockerCode(nil); got != domain.BlockerCapacity {
		t.Fatalf("no blockers must report capacity: %s", got)
	}
	// Targets that can never serve the request do not dilute a real cause.
	if got := dominantBlockerCode([]domain.AdmissionBlocker{domain.BlockerRuntimeUnsupported, domain.BlockerTransitionBusy}); got != domain.BlockerTransitionBusy {
		t.Fatalf("unsupported target masked the real cause: %s", got)
	}
	if got := dominantBlockerCode([]domain.AdmissionBlocker{domain.BlockerRuntimeUnsupported, domain.BlockerRuntimeUnsupported}); got != domain.BlockerRuntimeUnsupported {
		t.Fatalf("all-unsupported must stay unsupported: %s", got)
	}
	if got := dominantBlockerCode([]domain.AdmissionBlocker{domain.BlockerRuntimeUnsupported, domain.BlockerNodeOffline, domain.BlockerTransitionBusy}); got != domain.BlockerCapacity {
		t.Fatalf("a real mix must still report capacity: %s", got)
	}
	codes := []domain.AdmissionBlocker{domain.BlockerRuntimeUnsupported, domain.BlockerTransitionBusy}
	if got := primaryBlockerIndex(codes, domain.BlockerTransitionBusy); got != 1 {
		t.Fatalf("primary blocker must explain the reported code: %d", got)
	}
	if got := primaryBlockerIndex(codes, domain.BlockerCapacity); got != 0 {
		t.Fatalf("no matching code must fall back to the first blocker: %d", got)
	}
}

func TestBlockerCodeIgnoresTargetLackingTheModel(t *testing.T) {
	fixture, backend := newRouterFixture(t, "small")
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 10 * time.Minute, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	target := Target{
		ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"},
		ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, ResidencyPolicy: domain.ResidencyAuto,
		CapabilityVersion: "router-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities:     domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 1},
		ModelFingerprint: "router-model-fp",
		ContextLimit:     8192, Slots: 1, ActiveRuntimeProfile: "router-profile",
		RuntimeProfiles:  []RuntimeCapacityProfile{{ID: "router-profile", ContextLimit: 8192, Slots: 1}},
		Capacity:         domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 16 << 30},
		CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
	}
	mgr.RegisterTarget(target)
	// A second node that does not serve "large" at all (the 780M in production).
	mgr.RegisterTarget(Target{ID: "aaa-other-node", Adapter: "llamacpp", Endpoint: "http://127.0.0.1:1", Models: []string{"unrelated"}, ContextLimit: 4096, Slots: 1, CapacityVerified: true, Enabled: true})
	registered := mgr.targetByID(target.ID)
	for _, measurement := range []store.ModelCapacity{
		measuredCapacityWithProfile(registered, "small", 1<<30, 1<<30),
		measuredCapacityWithProfile(registered, "large", 2<<30, 1<<30),
	} {
		if _, err := mgr.SetModelCapacity(context.Background(), measurement); err != nil {
			t.Fatal(err)
		}
	}
	if err := seedHotResidency(context.Background(), backing, registered, "small", domain.ResidencyAuto); err != nil {
		t.Fatal(err)
	}
	small, err := backing.GetModelResidency(context.Background(), target.ID, "small")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	small.MinResidentUntil = &until
	if _, err := backing.UpsertModelResidency(context.Background(), small); err != nil {
		t.Fatal(err)
	}
	row, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", Priority: 1, QueuePolicy: domain.QueueWait, Payload: json.RawMessage(`{"model":"large","messages":[{"role":"user","content":"x"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	unsupported := false
	for _, alt := range row.Decision.Alternatives {
		if alt == "aaa-other-node: model unavailable" {
			unsupported = true
		}
	}
	// Precondition (negative control): the unrelated node really contributed a
	// runtime_unsupported blocker, which the old rule turned into "capacity".
	if !unsupported {
		t.Fatalf("fixture did not produce the unsupported blocker: %+v", row.Decision.Alternatives)
	}
	if row.Status != domain.WorkloadWaiting || row.Decision.BlockerCode != domain.BlockerTransitionBusy {
		t.Fatalf("node lacking the model masked the min_residency cause: %+v", row.Decision)
	}
	if len(row.Decision.Blocker) < 7 || row.Decision.Blocker[:7] != "router:" {
		t.Fatalf("primary blocker text does not explain the code: %q", row.Decision.Blocker)
	}
	if events, _ := fixture.snapshot(); len(events) != 0 {
		t.Fatalf("protected resident was touched: %v", events)
	}
}

func TestCompleteAdmissionDecisionPublishesOnlyRealEstimates(t *testing.T) {
	start := time.Now().Add(time.Minute)
	for _, tc := range []struct {
		confidence float64
		real       bool
	}{
		{.2, false}, {.25, false}, {.3, false},
		// Negative control around the threshold: one step below must stay
		// unpublished, so lowering realEstimateConfidence breaks this test.
		{realEstimateConfidence - .01, false},
		{realEstimateConfidence, true}, {.9, true},
	} {
		w := &domain.Workload{Request: domain.WorkloadRequest{ID: "w"}, Status: domain.WorkloadWaiting, Decision: domain.AdmissionDecision{Blocker: "gpu: all execution slots are busy", EstimatedStart: &start, Confidence: tc.confidence}}
		completeAdmissionDecision(w)
		if (w.Decision.ETA != nil) != tc.real || (w.Decision.RetryAfter != nil) != tc.real {
			t.Fatalf("confidence %.2f: eta=%v retry=%v want published=%t", tc.confidence, w.Decision.ETA, w.Decision.RetryAfter, tc.real)
		}
		if w.Decision.BlockerCode != domain.BlockerCapacity || w.Decision.NotificationID != "w" {
			t.Fatalf("confidence %.2f: decision=%+v", tc.confidence, w.Decision)
		}
	}
	rejected := &domain.Workload{Request: domain.WorkloadRequest{ID: "r"}, Status: domain.WorkloadRejected, Decision: domain.AdmissionDecision{Blocker: "x", BlockerCode: domain.BlockerNodeOffline, NotificationID: "stale"}}
	completeAdmissionDecision(rejected)
	if rejected.Decision.BlockerCode != domain.BlockerNodeOffline || rejected.Decision.NotificationID != "" {
		t.Fatalf("terminal decision: %+v", rejected.Decision)
	}
}

func TestFailFastKeepsRealBlockersAndCode(t *testing.T) {
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	for _, id := range []string{"a", "b"} {
		mgr.RegisterTarget(Target{ID: id, Adapter: "llamacpp", Endpoint: "http://127.0.0.1:1", Models: []string{"served"}, ContextLimit: 4096, Slots: 1, CapacityVerified: true, Enabled: true})
	}
	row, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "o", Adapter: "llamacpp", QueuePolicy: domain.QueueFailFast, Payload: json.RawMessage(`{"model":"missing","messages":[{}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != domain.WorkloadRejected || row.Decision.Blocker != "no eligible capacity (fail_fast)" || row.Decision.BlockerCode != domain.BlockerRuntimeUnsupported || len(row.Decision.Alternatives) != 2 {
		t.Fatalf("fail_fast decision lost its real cause: %+v", row.Decision)
	}
	if row.Decision.NotificationID != "" {
		t.Fatalf("rejected workload advertised a notification handle: %+v", row.Decision)
	}
}

func TestEvictionCandidatesHonorMinResidencyUnlessUrgent(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "min-res-target", Adapter: "llamacpp", AcceleratorID: "min-res-gpu", Enabled: true}
	mgr.RegisterTarget(target)
	until := time.Now().Add(4 * time.Minute).UTC()
	expired := time.Now().Add(-time.Minute).UTC()
	for model, minUntil := range map[string]*time.Time{"recent": &until, "old": &expired} {
		if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: target.ID + "::" + model, TargetID: target.ID, Model: model, ObservedTier: domain.ResidencyHotVRAM, DesiredTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto, MinResidentUntil: minUntil}); err != nil {
			t.Fatal(err)
		}
	}
	names := func(rows []*domain.ModelResidency) string {
		out := ""
		for _, row := range rows {
			out += row.Model + ","
		}
		return out
	}
	for _, tc := range []struct {
		priority int
		want     string
	}{{1, "old,"}, {UrgentPriority - 1, "old,"}, {UrgentPriority, "old,recent,"}, {9, "old,recent,"}} {
		candidates, protection, err := mgr.evictionCandidates(ctx, target, "new", tc.priority)
		if err != nil {
			t.Fatal(err)
		}
		// Ties sort by residency time; normalize order for the assertion.
		got := names(candidates)
		if got == "recent,old," {
			got = "old,recent,"
		}
		if got != tc.want {
			t.Fatalf("priority %d: candidates=%s want %s", tc.priority, got, tc.want)
		}
		protected := tc.priority < UrgentPriority
		if (protection.minResidentUntil != nil) != protected || (protected && !protection.minResidentUntil.Equal(until)) {
			t.Fatalf("priority %d: protection=%+v", tc.priority, protection)
		}
	}
}

func TestDemandEvictionHonorsMinResidencyUnlessUrgent(t *testing.T) {
	fixture, backend := newRouterFixture(t, "small")
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 10 * time.Minute, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	target := Target{
		ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"},
		ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, ResidencyPolicy: domain.ResidencyAuto,
		CapabilityVersion: "router-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities:     domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 1},
		ModelFingerprint: "router-model-fp",
		ContextLimit:     8192, Slots: 1, ActiveRuntimeProfile: "router-profile",
		RuntimeProfiles:  []RuntimeCapacityProfile{{ID: "router-profile", ContextLimit: 8192, Slots: 1}},
		Capacity:         domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 16 << 30},
		CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
	}
	mgr.RegisterTarget(target)
	registered := mgr.targetByID(target.ID)
	for _, measurement := range []store.ModelCapacity{
		measuredCapacityWithProfile(registered, "small", 1<<30, 1<<30),
		measuredCapacityWithProfile(registered, "large", 2<<30, 1<<30),
	} {
		if _, err := mgr.SetModelCapacity(context.Background(), measurement); err != nil {
			t.Fatal(err)
		}
	}
	if err := seedHotResidency(context.Background(), backing, registered, "small", domain.ResidencyAuto); err != nil {
		t.Fatal(err)
	}
	small, err := backing.GetModelResidency(context.Background(), target.ID, "small")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	small.MinResidentUntil = &until
	if _, err := backing.UpsertModelResidency(context.Background(), small); err != nil {
		t.Fatal(err)
	}
	submit := func(priority int) *domain.Workload {
		row, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", Priority: priority, QueuePolicy: domain.QueueWait, Payload: json.RawMessage(fmt.Sprintf(`{"model":"large","messages":[{"role":"user","content":"p%d"}]}`, priority))})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	routine := submit(1)
	if routine.Status != domain.WorkloadWaiting || routine.Decision.BlockerCode != domain.BlockerTransitionBusy {
		t.Fatalf("priority-1 demand evicted a resident inside min_residency: %+v", routine.Decision)
	}
	if routine.Decision.ETA == nil || !routine.Decision.ETA.Equal(until) || routine.Decision.RetryAfter == nil || routine.Decision.NotificationID != routine.Request.ID {
		t.Fatalf("protected load did not publish the min_residency ETA/notification: %+v", routine.Decision)
	}
	if events, resident := fixture.snapshot(); len(events) != 0 || !resident["small"] {
		t.Fatalf("protected resident was touched: events=%v resident=%v", events, resident)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	urgent := submit(9)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, urgent.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("priority-9 demand did not override min_residency: %+v err=%v", finished, err)
	}
	if events, resident := fixture.snapshot(); len(events) < 2 || events[0] != "unload:small" || events[1] != "load:large" || resident["small"] {
		t.Fatalf("urgent eviction events=%v resident=%v", events, resident)
	}
	// The waiting workload's notification handle is followed through the
	// in-app event stream: admission emits workload.admitted for its ID.
	if finished, err := mgr.Wait(waitCtx, routine.Request.ID); err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("queued workload never ran: %+v err=%v", finished, err)
	}
	events, err := backing.ListAuditEvents(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	admitted := false
	for _, event := range events {
		if event.WorkloadID == routine.Decision.NotificationID && event.Type == "workload.admitted" {
			admitted = true
		}
	}
	if !admitted {
		t.Fatal("no workload.admitted event for the notification handle")
	}
}
