package workloads

import (
	"context"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestTargetsShareAccelerator(t *testing.T) {
	split := Target{ID: "split", AcceleratorID: "node-gpu0", CompanionAcceleratorIDs: []string{"node-gpu1"}}
	gpu0 := Target{ID: "gpu0", AcceleratorID: "node-gpu0"}
	gpu1 := Target{ID: "gpu1", AcceleratorID: "node-gpu1"}
	other := Target{ID: "other", AcceleratorID: "node-gpu2"}
	cloud := Target{ID: "cloud"}
	for _, tc := range []struct {
		a, b Target
		want bool
	}{{split, gpu0, true}, {split, gpu1, true}, {gpu1, split, true}, {gpu0, gpu1, false}, {split, other, false}, {cloud, gpu0, false}} {
		if got := targetsShareAccelerator(tc.a, tc.b); got != tc.want {
			t.Fatalf("share(%s, %s) = %v, want %v", tc.a.ID, tc.b.ID, got, tc.want)
		}
	}
}

// A split target holds its companion GPU while it has work: a per-card
// target cannot take that GPU's lease, and the companion is released once the
// split target has been idle for the grace period.
func TestCompanionLeaseBlocksSecondGPUUntilIdle(t *testing.T) {
	previousGrace := companionGrace
	companionGrace = 200 * time.Millisecond
	defer func() { companionGrace = previousGrace }()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, 300*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	split := Target{ID: "split", AcceleratorID: "node-gpu0", CompanionAcceleratorIDs: []string{"node-gpu1"}}

	reason, err := mgr.holdCompanionLeases(ctx, split)
	if err != nil || reason != "" {
		t.Fatalf("split target could not claim its companion: reason=%q err=%v", reason, err)
	}
	if _, acquired, err := backing.AcquireAcceleratorLease(ctx, "node-gpu1", "per-card-job", time.Second); err != nil || acquired {
		t.Fatalf("per-card job took the companion GPU while the split target holds it: acquired=%v err=%v", acquired, err)
	}
	// Claiming again while held is a no-op, not a conflict.
	if reason, err := mgr.holdCompanionLeases(ctx, split); err != nil || reason != "" {
		t.Fatalf("re-claim by the holder failed: reason=%q err=%v", reason, err)
	}

	// Idle past the grace period (and beyond the lease TTL, so renewal must
	// have kept it alive until then): the keeper releases the companion.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, acquired, err := backing.AcquireAcceleratorLease(ctx, "node-gpu1", "per-card-job", time.Second); err == nil && acquired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("companion lease was never released after the split target went idle")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Now the per-card job holds GPU 1: the split target must wait.
	reason, err = mgr.holdCompanionLeases(ctx, split)
	if err != nil || !strings.Contains(reason, "node-gpu1") || !strings.Contains(reason, "per-card-job") {
		t.Fatalf("split target did not report the busy companion: reason=%q err=%v", reason, err)
	}
}

// Renewal keeps the companion lease alive while the split target is active,
// even past several lease TTLs.
func TestCompanionLeaseRenewedWhileTargetActive(t *testing.T) {
	previousGrace := companionGrace
	companionGrace = 100 * time.Millisecond
	defer func() { companionGrace = previousGrace }()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, 300*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	split := Target{ID: "split", AcceleratorID: "node-gpu0", CompanionAcceleratorIDs: []string{"node-gpu1"}}
	if reason, err := mgr.holdCompanionLeases(ctx, split); err != nil || reason != "" {
		t.Fatalf("claim failed: %q %v", reason, err)
	}
	mgr.placementMu.Lock()
	mgr.targetActive["split"] = 1
	mgr.placementMu.Unlock()
	time.Sleep(1200 * time.Millisecond) // four lease TTLs
	if _, acquired, _ := backing.AcquireAcceleratorLease(ctx, "node-gpu1", "per-card-job", time.Second); acquired {
		t.Fatal("companion lease expired while the split target was active")
	}
	mgr.placementMu.Lock()
	delete(mgr.targetActive, "split")
	mgr.placementMu.Unlock()
}

// With a copy of a model on each GPU, the scheduler orders the faster copy
// first (it spills to the slower one when the faster is busy).
func TestPoolSpeedPreferenceOrdersFasterCopyFirst(t *testing.T) {
	fast := Target{ID: "gpu0", ModelPools: map[string]ModelPool{"m": {PoolTokens: 90000, Slots: 8, MaxRequestTokens: 90000, DecodeTPS: 138, PromptTPS: 5000}}}
	slow := Target{ID: "gpu1", ModelPools: map[string]ModelPool{"m": {PoolTokens: 120000, Slots: 8, MaxRequestTokens: 120000, DecodeTPS: 56, PromptTPS: 300}}}
	request := domain.WorkloadRequest{Bounds: domain.WorkloadBounds{MaxOutput: 256}}
	requirements := Requirements{Model: "m", ContextTokens: 2256}
	if got := poolSpeedPreference(fast, slow, request, requirements); got != -1 {
		t.Fatalf("faster copy not preferred: %d", got)
	}
	if got := poolSpeedPreference(slow, fast, request, requirements); got != 1 {
		t.Fatalf("order not symmetric: %d", got)
	}
	// A request too large for the faster copy gives no speed preference:
	// only the larger pool can take it.
	if got := poolSpeedPreference(fast, slow, request, Requirements{Model: "m", ContextTokens: 100000}); got != 0 {
		t.Fatalf("speed preferred a target whose pool cannot hold the request: %d", got)
	}
	// Unknown speeds: no preference.
	unknown := Target{ID: "x", ModelPools: map[string]ModelPool{"m": {PoolTokens: 90000, Slots: 8, MaxRequestTokens: 90000}}}
	if got := poolSpeedPreference(fast, unknown, request, requirements); got != 0 {
		t.Fatalf("preference without measured speeds: %d", got)
	}
}

func TestLearnedSpeedReplacesCalibrationAfterSamples(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	target := Target{ID: "gpu0", ModelPools: map[string]ModelPool{"m": {PoolTokens: 8192, Slots: 1, MaxRequestTokens: 8192, DecodeTPS: 100, PromptTPS: 1000}}}
	job := &domain.Workload{Plan: &domain.ExecutionPlan{Model: "m"}, Execution: &domain.ExecutionHandle{Performance: &domain.ExecutionPerformance{DecodeTPS: 40, PromptTPS: 400, CompletionTokens: 64}}}
	for i := 0; i < learnedSpeedMinSamples-1; i++ {
		mgr.observeSpeed(job, target)
	}
	if got := mgr.withLearnedSpeeds(target, "m").ModelPools["m"].DecodeTPS; got != 100 {
		t.Fatalf("calibration replaced before enough samples: %v", got)
	}
	mgr.observeSpeed(job, target)
	view := mgr.withLearnedSpeeds(target, "m")
	if got := view.ModelPools["m"].DecodeTPS; got != 40 {
		t.Fatalf("learned decode speed not used: %v", got)
	}
	if target.ModelPools["m"].DecodeTPS != 100 {
		t.Fatal("the registered target's pools were modified")
	}
}

// Evicting a neighbour across GPUs is fenced by the lease of the GPU the two
// share: the split target uses its companion lease on GPU 1 to evict the GPU 1
// router, and the GPU 1 router records its eviction of the split model on GPU 1.
func TestCrossGPUReclaimUsesSharedGPULease(t *testing.T) {
	previousGrace := companionGrace
	companionGrace = time.Hour
	defer func() { companionGrace = previousGrace }()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Minute)
	ctx := context.Background()
	split := Target{ID: "split", AcceleratorID: "node-gpu0", CompanionAcceleratorIDs: []string{"node-gpu1"}}
	gpu1 := Target{ID: "gpu1", AcceleratorID: "node-gpu1"}
	gpu0 := Target{ID: "gpu0", AcceleratorID: "node-gpu0"}
	primary, _, err := backing.AcquireAcceleratorLease(ctx, "node-gpu0", "split-job", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := mgr.holdCompanionLeases(ctx, split); err != nil || reason != "" {
		t.Fatalf("companion: %q %v", reason, err)
	}
	if fence := mgr.reclaimLease(split, gpu1, primary); fence == nil || fence.AcceleratorID != "node-gpu1" {
		t.Fatalf("split evicting the GPU 1 router must use its GPU 1 companion lease, got %+v", fence)
	}
	if fence := mgr.reclaimLease(split, gpu0, primary); fence != primary {
		t.Fatalf("split evicting the GPU 0 router must use its own lease, got %+v", fence)
	}
	gpu1Lease := &domain.AcceleratorLease{AcceleratorID: "node-gpu1", WorkloadID: "gpu1-job", FencingToken: 7}
	if got := transitionAccelerator(split, gpu1Lease); got != "node-gpu1" {
		t.Fatalf("GPU 1 router evicting the split model must record it on GPU 1, got %s", got)
	}
	if got := transitionAccelerator(gpu0, gpu1Lease); got != "node-gpu0" {
		t.Fatalf("a lease on an unrelated GPU must not move the transition, got %s", got)
	}
}
