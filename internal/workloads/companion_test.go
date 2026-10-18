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
