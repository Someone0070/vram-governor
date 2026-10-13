package workloads

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

type powerCheckingAdapter struct {
	*MockAdapter
	mu     *sync.Mutex
	active *bool
}

type powerStartCountingAdapter struct {
	*MockAdapter
	starts *int
}

func (a *powerStartCountingAdapter) Start(ctx context.Context, request domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	*a.starts++
	return a.MockAdapter.Start(ctx, request, plan, target)
}

func (a *powerCheckingAdapter) Start(ctx context.Context, request domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	a.mu.Lock()
	active := *a.active
	a.mu.Unlock()
	if !active {
		return nil, ErrUnsupported
	}
	return a.MockAdapter.Start(ctx, request, plan, target)
}

func TestPowerProfileActiveBeforeWorkAndIdleAfterRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	node := &domain.Node{ID: "node", Name: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: time.Now().UTC()}, Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 24000, VRAMFreeMB: 24000}}}
	if _, err := backing.UpsertNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(quietLogger(), backing, time.Second)
	manager.SetNodeStore(backing)
	manager.SetManagedGPUPerformance("node", []int{0})
	var mu sync.Mutex
	active := false
	states := make(chan string, 4)
	manager.SetNodeControl(func(_ context.Context, nodeID, command string, args map[string]any, _ string) (map[string]any, error) {
		return map[string]any{}, nil
	})
	manager.SetGPUPerformanceControl(func(_ context.Context, nodeID, command string, args map[string]any, _ string) (map[string]any, error) {
		if nodeID != "node" || command != "set_gpu_performance_profile" || args["accelerator_id"] != "node-gpu0" {
			t.Errorf("unexpected node control: %s %s %v", nodeID, command, args)
		}
		profile := args["profile"].(string)
		mu.Lock()
		active = profile == "active"
		mu.Unlock()
		states <- profile
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	manager.RegisterAdapter(&powerCheckingAdapter{MockAdapter: NewMockAdapter(), mu: &mu, active: &active})
	manager.RegisterTarget(Target{ID: "node-mock", Adapter: "mock", AcceleratorID: "node-gpu0", Enabled: true})
	manager.Start(ctx)
	workload, _, err := manager.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"proof":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Wait(ctx, workload.Request.ID); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"active", "idle"} {
		select {
		case got := <-states:
			if got != want {
				t.Fatalf("power transition = %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing %s power transition", want)
		}
	}
}

func TestPowerProfileLateIdleSerializesBeforeNextActive(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: time.Now().UTC()}, Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 24000, VRAMFreeMB: 24000}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	m.SetManagedGPUPerformance("node", []int{0})
	idleEntered := make(chan struct{})
	releaseIdle := make(chan struct{})
	var mu sync.Mutex
	var order []string
	m.SetGPUPerformanceControl(func(_ context.Context, _, _ string, args map[string]any, _ string) (map[string]any, error) {
		profile := args["profile"].(string)
		if profile == "idle" {
			close(idleEntered)
			<-releaseIdle
		}
		mu.Lock()
		order = append(order, profile)
		mu.Unlock()
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	idleDone := make(chan error, 1)
	go func() { idleDone <- m.setGPUPerformanceProfile(ctx, "node-gpu0", "idle", "idle-one") }()
	<-idleEntered
	activeDone := make(chan error, 1)
	go func() { activeDone <- m.setGPUPerformanceProfile(ctx, "node-gpu0", "active", "active-two") }()
	close(releaseIdle)
	if err := <-idleDone; err != nil {
		t.Fatal(err)
	}
	if err := <-activeDone; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "idle" || order[1] != "active" {
		t.Fatalf("unsafe transition order: %v", order)
	}
}

func TestPowerProfileActiveFailureBlocksWorkBeforeAdapterStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: time.Now().UTC()}, Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 24000, VRAMFreeMB: 24000}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	m.SetManagedGPUPerformance("node", []int{0})
	m.SetGPUPerformanceControl(func(_ context.Context, _, _ string, args map[string]any, _ string) (map[string]any, error) {
		if args["profile"] == "active" {
			return nil, errors.New("clock actuator failed")
		}
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	starts := 0
	m.RegisterAdapter(&powerStartCountingAdapter{MockAdapter: NewMockAdapter(), starts: &starts})
	m.RegisterTarget(Target{ID: "node-mock", Adapter: "mock", AcceleratorID: "node-gpu0", Enabled: true})
	m.Start(ctx)
	row, _, err := m.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	finished, err := m.Wait(waitCtx, row.Request.ID)
	if err != nil {
		t.Fatalf("wait failed: %v status=%s decision=%+v error=%q", err, finished.Status, finished.Decision, finished.Error)
	}
	if finished.Status != domain.WorkloadFailed || starts != 0 {
		t.Fatalf("failed active transition still executed workload: status=%s starts=%d", finished.Status, starts)
	}
}

func TestRetiredTargetDuringProfileCannotStartAndCleansReservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: time.Now().UTC()}, Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 24000, VRAMFreeMB: 24000}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	m.SetManagedGPUPerformance("node", []int{0})
	profileEntered, releaseProfile := make(chan struct{}), make(chan struct{})
	var entered sync.Once
	m.SetGPUPerformanceControl(func(ctx context.Context, _, _ string, args map[string]any, _ string) (map[string]any, error) {
		if args["profile"] == "active" {
			// Retiring the target refreshes it, so the command is resent once.
			entered.Do(func() { close(profileEntered) })
			select {
			case <-releaseProfile:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	starts := 0
	m.RegisterAdapter(&powerStartCountingAdapter{MockAdapter: NewMockAdapter(), starts: &starts})
	m.RegisterTarget(Target{ID: "node-mock", Adapter: "mock", AcceleratorID: "node-gpu0", Enabled: true})
	m.Start(ctx)
	row, _, err := m.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"profile":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-profileEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("execution did not reach the blocked profile command")
	}
	m.ReconcileNodeTargets("node", map[string]struct{}{})
	close(releaseProfile)
	// The profile command is resent after the refresh and succeeds; the
	// pre-execution fact check then finds the target retired. The job must
	// never start and must give its reservation back; it then either fails
	// or waits for capacity to return.
	var finished *domain.Workload
	deadline := time.Now().Add(3 * time.Second)
	for {
		finished, err = m.Get(ctx, row.Request.ID)
		if err == nil && (finished.Status == domain.WorkloadFailed || finished.Status == domain.WorkloadWaiting) && m.targetActiveCount("node-mock") == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not settle: status=%v err=%v", finished, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if starts != 0 {
		t.Fatalf("retired target started work: status=%s starts=%d error=%q", finished.Status, starts, finished.Error)
	}
	if got := m.targetActiveCount("node-mock"); got != 0 {
		t.Fatalf("retired target reservation leaked: active=%d", got)
	}
}

func TestPowerProfileUnadvertisedGPUDoesNotSendNodeCommand(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node"}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	calls := 0
	m.SetGPUPerformanceControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		calls++
		return nil, nil
	})
	if err := m.setGPUPerformanceProfile(ctx, "node-gpu0", "active", "unadvertised"); err != nil || calls != 0 {
		t.Fatalf("unadvertised GPU was controlled: calls=%d err=%v", calls, err)
	}
}

func TestPowerProfileInitialIdleReconcilePreservesWarmResidency(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMUsedMB: 12000}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	m.SetManagedGPUPerformance("node", []int{0})
	idle := make(chan struct{}, 1)
	m.SetGPUPerformanceControl(func(_ context.Context, _, command string, args map[string]any, _ string) (map[string]any, error) {
		if command != "set_gpu_performance_profile" || args["profile"] != "idle" {
			t.Errorf("unexpected initial reconcile command: %s %v", command, args)
		}
		idle <- struct{}{}
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	m.ReconcileGPUIdleAfterTelemetry("node")
	select {
	case <-idle:
	case <-time.After(3 * time.Second):
		t.Fatal("initial warm GPU was not parked")
	}
	node, err := backing.GetNode(ctx, "node")
	if err != nil || node.Accelerators[0].VRAMUsedMB != 12000 {
		t.Fatalf("idle control changed model residency/telemetry: node=%+v err=%v", node, err)
	}
}

func TestPowerProfileIdleFailureQueuesBoundedReconciliation(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node"}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	m.SetManagedGPUPerformance("node", []int{0})
	count := 0
	recovered := make(chan struct{}, 1)
	m.SetGPUPerformanceControl(func(_ context.Context, _, _ string, args map[string]any, _ string) (map[string]any, error) {
		count++
		if count == 1 {
			return nil, errors.New("temporary idle failure")
		}
		recovered <- struct{}{}
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	if err := m.setGPUPerformanceProfile(ctx, "node-gpu0", "idle", "idle-failure"); err == nil {
		t.Fatal("idle actuator failure was swallowed")
	}
	m.ReconcileGPUIdleAfterTelemetry("node")
	if count != 1 {
		t.Fatalf("idle reconciliation ignored backoff: calls=%d", count)
	}
	m.mu.Lock()
	m.gpuIdleRetryAfter["node"] = time.Now().Add(-time.Second)
	m.mu.Unlock()
	m.ReconcileGPUIdleAfterTelemetry("node")
	select {
	case <-recovered:
	case <-time.After(3 * time.Second):
		t.Fatal("idle power did not recover after retry")
	}
}

func TestPowerProfileIdleIsNotResentToAnIdleGPU(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node"}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	m.SetManagedGPUPerformance("node", []int{0})
	var sent []string
	fail := false
	m.SetGPUPerformanceControl(func(_ context.Context, _, _ string, args map[string]any, _ string) (map[string]any, error) {
		sent = append(sent, args["profile"].(string))
		if fail {
			return nil, errors.New("node unreachable")
		}
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	step := func(profile string) {
		t.Helper()
		if err := m.setGPUPerformanceProfile(ctx, "node-gpu0", profile, newID("k")); err != nil && !fail {
			t.Fatal(err)
		}
	}
	// Admission retries release their reservation repeatedly; only the first
	// idle reaches the node, every active does.
	step("idle")
	step("idle")
	step("idle")
	step("active")
	step("active")
	step("idle")
	step("idle")
	want := []string{"idle", "active", "active", "idle"}
	if len(sent) != len(want) {
		t.Fatalf("sent %v, want %v", sent, want)
	}
	for i := range want {
		if sent[i] != want[i] {
			t.Fatalf("sent %v, want %v", sent, want)
		}
	}
	// A failed command leaves the state unknown, so the next idle is sent.
	step("active")
	fail = true
	step("idle")
	fail = false
	step("idle")
	if got := sent[len(sent)-2:]; got[0] != "idle" || got[1] != "idle" {
		t.Fatalf("after a failure the idle retry was suppressed: %v", sent)
	}
	// Re-advertisement (node reconnect) forgets the confirmed profile.
	before := len(sent)
	m.SetManagedGPUPerformance("node", []int{0})
	step("idle")
	if len(sent) != before+1 {
		t.Fatalf("idle after re-advertisement was suppressed: %v", sent)
	}
}

// With an idle linger, a job that takes the GPU right after another keeps
// active clocks: the first release's park finds the active placement and is
// skipped, so only the last job parks.
func TestPowerProfileIdleLingerKeepsBackToBackJobsActive(t *testing.T) {
	run := func(linger time.Duration) []string {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		backing := store.NewMemoryStore()
		node := &domain.Node{ID: "node", Name: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: time.Now().UTC()}, Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 24000, VRAMFreeMB: 24000}}}
		if _, err := backing.UpsertNode(ctx, node); err != nil {
			t.Fatal(err)
		}
		manager := NewManager(quietLogger(), backing, time.Second)
		manager.SetNodeStore(backing)
		manager.SetManagedGPUPerformance("node", []int{0})
		manager.SetGPUIdleLinger(linger)
		var mu sync.Mutex
		var sent []string
		manager.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
			return map[string]any{}, nil
		})
		manager.SetGPUPerformanceControl(func(_ context.Context, _, _ string, args map[string]any, _ string) (map[string]any, error) {
			mu.Lock()
			sent = append(sent, args["profile"].(string))
			mu.Unlock()
			return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
		})
		manager.RegisterAdapter(NewMockAdapter())
		manager.RegisterTarget(Target{ID: "node-mock", Adapter: "mock", AcceleratorID: "node-gpu0", Enabled: true})
		manager.Start(ctx)
		for i := 0; i < 2; i++ {
			workload, _, err := manager.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"proof":true}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Wait(ctx, workload.Request.ID); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(linger + 300*time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sent...)
	}
	if got := strings.Join(run(0), ","); got != "active,idle,active,idle" {
		t.Fatalf("without linger sent %s", got)
	}
	if got := strings.Join(run(time.Second), ","); got != "active,active,idle" {
		t.Fatalf("with linger sent %s, want the GPU parked once after the last job", got)
	}
}

// Job starts refresh the target's advertised facts while the active command
// is in flight; the node applied the profile, so the command is resent
// (freshly keyed and fenced) instead of failing the job.
func TestPowerProfileResendsWhenTargetsRefreshDuringCommand(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node"}}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(quietLogger(), backing, time.Second)
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) { return nil, nil })
	m.SetManagedGPUPerformance("node", []int{0})
	target := Target{ID: "node-comfy", Adapter: "mock", AcceleratorID: "node-gpu0", Enabled: true}
	m.RegisterAdapter(NewMockAdapter())
	m.RegisterTarget(target)
	var keys []string
	refreshes := 1
	m.SetGPUPerformanceControl(func(_ context.Context, _, _ string, _ map[string]any, key string) (map[string]any, error) {
		keys = append(keys, key)
		if refreshes > 0 {
			refreshes--
			target.QueueRunning++
			m.RegisterTarget(target)
		}
		return map[string]any{"managed": true, "accelerator_id": "node-gpu0"}, nil
	})
	if err := m.setGPUPerformanceProfile(ctx, "node-gpu0", "active", "job-1"); err != nil {
		t.Fatalf("one refresh failed the profile: %v", err)
	}
	if len(keys) != 2 || keys[0] != "job-1" || keys[1] == keys[0] {
		t.Fatalf("expected one freshly keyed resend, sent %v", keys)
	}
	refreshes = 5
	if err := m.setGPUPerformanceProfile(ctx, "node-gpu0", "active", "job-2"); !errors.Is(err, errTargetFactsChanged) {
		t.Fatalf("endless refreshes must still fail after bounded resends: %v", err)
	}
}
