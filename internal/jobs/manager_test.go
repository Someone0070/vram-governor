package jobs

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}

// ---------------------------------------------------------------------
// Capacity honored: dispatch never exceeds a worker's measured slot count.
// ---------------------------------------------------------------------

func TestCapacityHonored(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), 5*time.Second, 50*time.Millisecond, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	w := NewMockWorker("w1", MockWorkerConfig{
		MinLatency:       20 * time.Millisecond,
		MaxLatency:       40 * time.Millisecond,
		ConcurrencyLimit: 3,
	})
	status := mgr.RegisterWorker(w, &domain.PerformanceProfile{Concurrency: 3})
	if status.Slots != 3 || status.Unmeasured {
		t.Fatalf("expected measured 3-slot worker, got %+v", status)
	}

	items := make([]ItemInput, 20)
	for i := range items {
		items[i] = ItemInput{Payload: map[string]any{"prompt": "p"}}
	}
	job, err := mgr.SubmitJob("score", "pool-a", items, 0)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		j, _, _ := mgr.GetJob(job.ID)
		return j.Progress.Success+j.Progress.Failed == 20
	})

	if got := w.MaxActiveObserved(); got > 3 {
		t.Fatalf("worker saw %d concurrent calls, want <= 3 (MockWorker self-enforced limit would have errored if manager over-dispatched)", got)
	}
	j, items2, _ := mgr.GetJob(job.ID)
	if j.Progress.Failed != 0 {
		t.Fatalf("expected zero failures on a healthy single worker, got %d", j.Progress.Failed)
	}
	for _, it := range items2 {
		if it.State != domain.WorkItemSuccess {
			t.Fatalf("item %s not success: %+v", it.ItemID, it)
		}
	}
}

// ---------------------------------------------------------------------
// Zero-gap dispatch: freeing a slot immediately pulls the next queued item,
// verified via synchronization (a worker that blocks until told to release)
// rather than sleeping and hoping.
// ---------------------------------------------------------------------

type gatedWorker struct {
	id      string
	release chan struct{}
	started chan string // itemID pushed as each call starts
}

func (g *gatedWorker) ID() string { return g.id }
func (g *gatedWorker) Execute(ctx context.Context, item domain.WorkItem) (Result, error) {
	g.started <- item.ItemID
	select {
	case <-g.release:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	return Result{Output: "ok"}, nil
}

func TestZeroGapDispatch(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), 30*time.Second, 20*time.Millisecond, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	gw := &gatedWorker{id: "gated", release: make(chan struct{}), started: make(chan string, 10)}
	mgr.RegisterWorker(gw, &domain.PerformanceProfile{Concurrency: 1}) // exactly 1 slot

	items := []ItemInput{
		{ItemID: "a", Payload: map[string]any{"prompt": "a"}},
		{ItemID: "b", Payload: map[string]any{"prompt": "b"}},
	}
	job, err := mgr.SubmitJob("op", "pool", items, 0)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Exactly one item should have started (single slot).
	select {
	case first := <-gw.started:
		if first != "a" {
			t.Fatalf("expected item a to start first, got %s", first)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first item to start")
	}
	select {
	case unexpected := <-gw.started:
		t.Fatalf("second item %s started before slot freed", unexpected)
	case <-time.After(50 * time.Millisecond):
		// expected: nothing else started yet
	}

	// Release the first call -> its slot frees -> item b must be picked up
	// immediately (zero-gap), not on any timer.
	gw.release <- struct{}{}
	select {
	case second := <-gw.started:
		if second != "b" {
			t.Fatalf("expected item b next, got %s", second)
		}
	case <-time.After(time.Second):
		t.Fatal("zero-gap dispatch did not fire: item b never started after slot freed")
	}
	gw.release <- struct{}{}

	waitFor(t, 2*time.Second, func() bool {
		j, _, _ := mgr.GetJob(job.ID)
		return j.Progress.Success == 2
	})
}

// ---------------------------------------------------------------------
// Cross-worker retry: item fails only after all eligible workers tried.
// ---------------------------------------------------------------------

func TestCrossWorkerRetryExhaustsTriedSetBeforeFailing(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), 5*time.Second, 20*time.Millisecond, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	// Three workers, all always-fail. The item must be tried against all
	// three (tried-set exhausted) before terminal FAILED, not on the first
	// failure.
	for i := 0; i < 3; i++ {
		id := []string{"bad1", "bad2", "bad3"}[i]
		w := NewMockWorker(id, MockWorkerConfig{AlwaysFail: true})
		mgr.RegisterWorker(w, &domain.PerformanceProfile{Concurrency: 1})
	}

	job, err := mgr.SubmitJob("op", "pool", []ItemInput{{ItemID: "only", Payload: map[string]any{"prompt": "x"}}}, 10)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		j, _, _ := mgr.GetJob(job.ID)
		return j.Progress.Failed == 1
	})

	_, items, _ := mgr.GetJob(job.ID)
	item := items[0]
	if item.State != domain.WorkItemFailed {
		t.Fatalf("expected FAILED, got %s", item.State)
	}
	if len(item.TriedWorkers) != 3 {
		t.Fatalf("expected all 3 workers tried before FAILED, got %v", item.TriedWorkers)
	}
	seen := map[string]bool{}
	for _, w := range item.TriedWorkers {
		seen[w] = true
	}
	for _, id := range []string{"bad1", "bad2", "bad3"} {
		if !seen[id] {
			t.Fatalf("worker %s was never tried: %v", id, item.TriedWorkers)
		}
	}
}

// A bad worker mixed with a good one: item must eventually succeed via the
// good worker, and the bad worker must appear in the tried set (proving
// retry actually moved to a different worker rather than hammering the
// same one).
func TestCrossWorkerRetryRescuesFromBadWorker(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), 5*time.Second, 20*time.Millisecond, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	bad := NewMockWorker("bad", MockWorkerConfig{AlwaysFail: true})
	good := NewMockWorker("good", MockWorkerConfig{})
	mgr.RegisterWorker(bad, &domain.PerformanceProfile{Concurrency: 1})
	mgr.RegisterWorker(good, &domain.PerformanceProfile{Concurrency: 1})

	items := make([]ItemInput, 10)
	for i := range items {
		items[i] = ItemInput{Payload: map[string]any{"prompt": "p"}}
	}
	job, err := mgr.SubmitJob("op", "pool", items, 0)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		j, _, _ := mgr.GetJob(job.ID)
		return j.Progress.Success+j.Progress.Failed == 10
	})

	j, _, _ := mgr.GetJob(job.ID)
	if j.Progress.Success != 10 {
		t.Fatalf("expected all 10 items rescued by the good worker, got success=%d failed=%d", j.Progress.Success, j.Progress.Failed)
	}
	if j.Progress.Retried == 0 {
		t.Fatalf("expected retried count > 0 (items had to move off the bad worker)")
	}
}

// ---------------------------------------------------------------------
// Lease expiry -> requeue.
// ---------------------------------------------------------------------

type stallForeverWorker struct{ id string }

func (s *stallForeverWorker) ID() string { return s.id }
func (s *stallForeverWorker) Execute(ctx context.Context, item domain.WorkItem) (Result, error) {
	<-ctx.Done() // never resolves on its own; only the lease-deadline ctx will fire
	return Result{}, ctx.Err()
}

func TestLeaseExpiryRequeues(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), 100*time.Millisecond, 30*time.Millisecond, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	// Register only "stuck" first and submit, so the single item is
	// deterministically leased to it (no random-pick ambiguity). Only once
	// it's confirmed in flight do we add "rescuer" capacity, so the retry
	// after lease expiry has somewhere else to go.
	stuck := &stallForeverWorker{id: "stuck"}
	mgr.RegisterWorker(stuck, &domain.PerformanceProfile{Concurrency: 1})

	job, err := mgr.SubmitJob("op", "pool", []ItemInput{{ItemID: "x", Payload: map[string]any{"prompt": "x"}}}, 10)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, time.Second, func() bool {
		_, items, _ := mgr.GetJob(job.ID)
		return items[0].State == domain.WorkItemLeased || items[0].State == domain.WorkItemRunning
	})

	rescuer := NewMockWorker("rescuer", MockWorkerConfig{})
	mgr.RegisterWorker(rescuer, &domain.PerformanceProfile{Concurrency: 1})

	// Item should eventually succeed once its lease on "stuck" expires and
	// it gets requeued to "rescuer".
	waitFor(t, 3*time.Second, func() bool {
		j, _, _ := mgr.GetJob(job.ID)
		return j.Progress.Success == 1
	})

	_, items, _ := mgr.GetJob(job.ID)
	item := items[0]
	if !contains(item.TriedWorkers, "stuck") {
		t.Fatalf("expected 'stuck' worker to be in the tried set after lease expiry, got %v", item.TriedWorkers)
	}
	if item.Attempt < 2 {
		t.Fatalf("expected at least 2 attempts (original + retry after expiry), got %d", item.Attempt)
	}
}

// ---------------------------------------------------------------------
// Dedupe: a duplicate/late result for an already-SUCCESS item is ignored.
// ---------------------------------------------------------------------

func TestDedupeLateResultIgnored(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), 60*time.Millisecond, 15*time.Millisecond, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	// slowThenLate: takes longer than the lease TTL so the reaper requeues
	// the item to a second (fast) worker while the original call is still
	// in flight; the original call's result arrives late.
	var callCount sync.Mutex
	calls := 0
	slow := workerFunc{id: "slow", fn: func(ctx context.Context, item domain.WorkItem) (Result, error) {
		callCount.Lock()
		calls++
		callCount.Unlock()
		// Ignore ctx (simulates a worker that doesn't respect cancellation,
		// e.g. a network call already in flight) and finish just after the
		// lease would have expired.
		time.Sleep(150 * time.Millisecond)
		return Result{Output: "late"}, nil
	}}
	fast := NewMockWorker("fast", MockWorkerConfig{MinLatency: 5 * time.Millisecond})
	mgr.RegisterWorker(&slow, &domain.PerformanceProfile{Concurrency: 1})
	mgr.RegisterWorker(fast, &domain.PerformanceProfile{Concurrency: 1})

	job, err := mgr.SubmitJob("op", "pool", []ItemInput{{ItemID: "x", Payload: map[string]any{"prompt": "x"}}}, 10)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Item should reach SUCCESS via the fast worker once the slow lease
	// expires and it's reassigned.
	waitFor(t, 3*time.Second, func() bool {
		j, _, _ := mgr.GetJob(job.ID)
		return j.Progress.Success == 1
	})
	successAt := time.Now()

	// Wait long enough for the slow worker's late result to arrive and be
	// dropped, then assert nothing double-counted.
	time.Sleep(300 * time.Millisecond)
	j, items, _ := mgr.GetJob(job.ID)
	if j.Progress.Success != 1 {
		t.Fatalf("late duplicate corrupted counts: success=%d (want 1)", j.Progress.Success)
	}
	if items[0].State != domain.WorkItemSuccess {
		t.Fatalf("item state changed after late duplicate: %s", items[0].State)
	}
	_ = successAt
}

// workerFunc adapts a plain function to the Worker interface for tests that
// need custom timing/behavior beyond what MockWorker's knobs cover.
type workerFunc struct {
	id string
	fn func(ctx context.Context, item domain.WorkItem) (Result, error)
}

func (w *workerFunc) ID() string { return w.id }
func (w *workerFunc) Execute(ctx context.Context, item domain.WorkItem) (Result, error) {
	return w.fn(ctx, item)
}

// ---------------------------------------------------------------------
// Client-abort / cancel drop: a cancelled job's late in-flight result must
// not cause a phantom re-lease or be counted.
// ---------------------------------------------------------------------

func TestCancelDropsLateResult(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), 5*time.Second, 20*time.Millisecond, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	release := make(chan struct{})
	started := make(chan string, 1)
	gw := &gatedWorker{id: "gw", release: release, started: started}
	mgr.RegisterWorker(gw, &domain.PerformanceProfile{Concurrency: 1})

	job, err := mgr.SubmitJob("op", "pool", []ItemInput{
		{ItemID: "inflight", Payload: map[string]any{"prompt": "x"}},
		{ItemID: "queued", Payload: map[string]any{"prompt": "y"}},
	}, 10)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("item never started")
	}

	if err := mgr.CancelJob(job.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	j, items, _ := mgr.GetJob(job.ID)
	if j.Status != domain.JobCancelled {
		t.Fatalf("expected job cancelled, got %s", j.Status)
	}
	for _, it := range items {
		if it.ItemID == "queued" && it.State != domain.WorkItemCancelled {
			t.Fatalf("expected queued item cancelled (never dispatched), got %s", it.State)
		}
	}

	// Now let the in-flight call resolve late.
	release <- struct{}{}
	time.Sleep(100 * time.Millisecond)

	j, items, _ = mgr.GetJob(job.ID)
	if j.Progress.Success != 0 || j.Progress.Failed != 0 {
		t.Fatalf("cancelled job's late result was counted: success=%d failed=%d", j.Progress.Success, j.Progress.Failed)
	}
	for _, it := range items {
		if it.ItemID == "inflight" && it.State == domain.WorkItemSuccess {
			t.Fatalf("late result after cancel was applied to item state: %+v", it)
		}
	}
}

func TestOperationVersionIsPartOfItemIdentity(t *testing.T) {
	mgr := NewManager(testLogger(), store.NewMemoryStore(), time.Second, 20*time.Millisecond, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()
	mgr.RegisterWorker(NewMockWorker("worker", MockWorkerConfig{}), &domain.PerformanceProfile{Concurrency: 2})

	job, err := mgr.SubmitJob("render", "default", []ItemInput{
		{ItemID: "frame-1", OperationVersion: "resize-v1", Payload: map[string]any{"prompt": "first"}},
		{ItemID: "frame-1", OperationVersion: "resize-v2", Payload: map[string]any{"prompt": "second"}},
	}, 3)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, time.Second, func() bool {
		current, _, _ := mgr.GetJob(job.ID)
		return current.Progress.Success == 2
	})
	_, items, err := mgr.GetJob(job.ID)
	if err != nil || len(items) != 2 {
		t.Fatalf("expected two independently-addressable versions, items=%d err=%v", len(items), err)
	}
	if items[0].OperationVersion == items[1].OperationVersion {
		t.Fatalf("operation versions collided: %+v", items)
	}
}
