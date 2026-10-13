package workloads

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

type flakyTargetObservationStore struct {
	store.WorkloadStore
	mu       sync.Mutex
	failures int
}

type orderedTargetObservationStore struct {
	store.WorkloadStore
	mu           sync.Mutex
	calls        int
	firstStarted chan struct{}
	releaseFirst chan struct{}
}

type blockingResidencyCASStore struct {
	store.WorkloadStore
	entered chan struct{}
	release chan struct{}
}

type missingResidencyOnceStore struct {
	store.WorkloadStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type newerResidencyOnCASStore struct {
	store.WorkloadStore
	newer *domain.ModelResidency
	once  sync.Once
}

type projectionRepairFailureStore struct {
	store.WorkloadStore
	failOnce sync.Once
}

func seedHotResidency(ctx context.Context, backing store.WorkloadStore, target Target, model string, policy domain.ResidencyPolicyMode) error {
	row, err := backing.GetModelResidency(ctx, target.ID, model)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if row == nil {
		_, err = backing.UpsertModelResidency(ctx, &domain.ModelResidency{
			ID: target.ID + "::" + model, TargetID: target.ID, AcceleratorID: target.AcceleratorID,
			Model: model, TargetGeneration: 1, ExecutionFingerprint: targetExecutionFingerprint(target),
			ObservedTier: domain.ResidencyHotVRAM, DesiredTier: domain.ResidencyHotVRAM, Policy: policy,
		})
		return err
	}
	row.ObservedTier = domain.ResidencyHotVRAM
	row.DesiredTier = domain.ResidencyHotVRAM
	row.Policy = policy
	_, err = backing.CompareAndSwapModelResidency(ctx, row, row.Revision)
	return err
}

func (s *projectionRepairFailureStore) CompareAndSwapModelResidency(ctx context.Context, residency *domain.ModelResidency, expectedRevision uint64) (*domain.ModelResidency, error) {
	failed := false
	s.failOnce.Do(func() { failed = true })
	if failed {
		return nil, errors.New("injected projection repair CAS failure")
	}
	return s.WorkloadStore.CompareAndSwapModelResidency(ctx, residency, expectedRevision)
}

func (s *newerResidencyOnCASStore) CompareAndSwapModelResidency(ctx context.Context, residency *domain.ModelResidency, expectedRevision uint64) (*domain.ModelResidency, error) {
	s.once.Do(func() { _, _ = s.WorkloadStore.UpsertModelResidency(ctx, s.newer) })
	return s.WorkloadStore.CompareAndSwapModelResidency(ctx, residency, expectedRevision)
}

func (s *missingResidencyOnceStore) GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error) {
	first := false
	s.once.Do(func() { first = true })
	if first {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, nil
	}
	return s.WorkloadStore.GetModelResidency(ctx, targetID, model)
}

func (s *blockingResidencyCASStore) CompareAndSwapModelResidency(ctx context.Context, residency *domain.ModelResidency, expectedRevision uint64) (*domain.ModelResidency, error) {
	close(s.entered)
	<-s.release
	return s.WorkloadStore.CompareAndSwapModelResidency(ctx, residency, expectedRevision)
}

func (s *orderedTargetObservationStore) GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	switch call {
	case 1:
		close(s.firstStarted)
		<-s.releaseFirst
		return nil, nil
	case 2:
		return nil, errors.New("newer target observation temporarily unavailable")
	default:
		return s.WorkloadStore.GetModelResidency(ctx, targetID, model)
	}
}

func (s *flakyTargetObservationStore) GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error) {
	s.mu.Lock()
	if s.failures > 0 {
		s.failures--
		s.mu.Unlock()
		return nil, errors.New("injected target observation read failure")
	}
	s.mu.Unlock()
	return s.WorkloadStore.GetModelResidency(ctx, targetID, model)
}

func TestInitialTargetObservationFailureIsRetriedDurably(t *testing.T) {
	base := store.NewMemoryStore()
	backing := &flakyTargetObservationStore{WorkloadStore: base, failures: 1}
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{
		ID: "node-a-gpu0", Adapter: "llamacpp", Models: []string{"model"},
		AcceleratorID: "node-a-gpu0", SupportsModelLifecycle: true,
		Enabled: true, ResidencyPolicy: domain.ResidencyAuto,
	}
	mgr.RegisterTarget(target)
	mgr.mu.RLock()
	_, pending := mgr.pendingResidencyObservations[target.ID]
	mgr.mu.RUnlock()
	if !pending {
		t.Fatal("initial target observation failure was not retained for recovery")
	}
	mgr.recoverPendingResidencyObservations(context.Background())
	mgr.mu.RLock()
	_, pending = mgr.pendingResidencyObservations[target.ID]
	mgr.mu.RUnlock()
	if pending {
		t.Fatal("successful target observation remained queued after retry")
	}
	row, err := base.GetModelResidency(context.Background(), target.ID, "model")
	if err != nil || row == nil || row.ObservedTier == "" {
		t.Fatalf("retry did not persist authoritative target observation: row=%+v err=%v", row, err)
	}
}

func TestOlderTargetObservationCannotDeleteNewerRetry(t *testing.T) {
	base := store.NewMemoryStore()
	backing := &orderedTargetObservationStore{WorkloadStore: base, firstStarted: make(chan struct{}), releaseFirst: make(chan struct{})}
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "node-a-gpu0", Adapter: "llamacpp", Models: []string{"model"}, AcceleratorID: "node-a-gpu0", SupportsModelLifecycle: true, Enabled: true, ResidencyPolicy: domain.ResidencyAuto}
	oldDone := make(chan struct{})
	go func() {
		mgr.RegisterTarget(target)
		close(oldDone)
	}()
	select {
	case <-backing.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("older target observation did not reach its barrier")
	}
	newTarget := target
	newTarget.CapabilityVersion = "runtime-v2"
	newDone := make(chan struct{})
	go func() {
		mgr.RegisterTarget(newTarget)
		close(newDone)
	}()
	select {
	case <-newDone:
	case <-time.After(time.Second):
		t.Fatal("newer target registration did not complete")
	}
	close(backing.releaseFirst)
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("older target registration did not complete")
	}
	mgr.mu.RLock()
	pending, exists := mgr.pendingResidencyObservations[target.ID]
	mgr.mu.RUnlock()
	if !exists || pending.generation == 0 || pending.target.CapabilityVersion != "runtime-v2" {
		t.Fatalf("older success erased newer retry: pending=%+v exists=%v", pending, exists)
	}
	mgr.recoverPendingResidencyObservations(context.Background())
	mgr.mu.RLock()
	_, exists = mgr.pendingResidencyObservations[target.ID]
	mgr.mu.RUnlock()
	if exists {
		t.Fatal("newer target retry was not removed after its own successful observation")
	}
}

func TestCancelledResidencyObserverCannotOverwriteNewerFacts(t *testing.T) {
	base := store.NewMemoryStore()
	initial := &domain.ModelResidency{ID: "target::model", TargetID: "target", Model: "model", TargetGeneration: 1, ExecutionFingerprint: "test-fingerprint", ObservedTier: domain.ResidencyColdDisk, DesiredTier: domain.ResidencyColdDisk, UpdatedAt: time.Now().UTC()}
	if _, err := base.UpsertModelResidency(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	backing := &blockingResidencyCASStore{WorkloadStore: base, entered: make(chan struct{}), release: make(chan struct{})}
	mgr := NewManager(quietLogger(), backing, time.Second)
	stale := *initial
	stale.ObservedTier = domain.ResidencyHotVRAM
	stale.DesiredTier = domain.ResidencyHotVRAM
	stale.WarmModelBytes = 111
	stale.UpdatedAt = time.Now().UTC()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.persistResidencyProjection(cancelled, &stale, initial.Revision) }()
	select {
	case <-backing.entered:
	case <-time.After(time.Second):
		t.Fatal("cancelled observer did not reach CAS barrier")
	}
	newer := *initial
	newer.Revision = initial.Revision + 1
	newer.ObservedTier = domain.ResidencyWarmRAM
	newer.DesiredTier = domain.ResidencyWarmRAM
	newer.WarmModelBytes = 999
	newer.LastError = "new authoritative runtime observation"
	newer.UpdatedAt = time.Now().UTC().Add(time.Millisecond)
	if _, err := base.UpsertModelResidency(context.Background(), &newer); err != nil {
		t.Fatal(err)
	}
	close(backing.release)
	if err := <-done; !errors.Is(err, store.ErrModelResidencyConflict) {
		t.Fatalf("cancelled stale observer returned wrong result: %v", err)
	}
	final, err := base.GetModelResidency(context.Background(), "target", "model")
	if err != nil {
		t.Fatal(err)
	}
	if final.Revision != newer.Revision || final.ObservedTier != newer.ObservedTier || final.WarmModelBytes != newer.WarmModelBytes || final.LastError != newer.LastError {
		t.Fatalf("stale cancelled observer overwrote newer facts: final=%+v newer=%+v", final, newer)
	}
}

func TestOlderMissingResidencyCannotOverwriteNewerCreate(t *testing.T) {
	base := store.NewMemoryStore()
	backing := &missingResidencyOnceStore{WorkloadStore: base, entered: make(chan struct{}), release: make(chan struct{})}
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "insert-race", Adapter: "llamacpp", Models: []string{"model"}, AcceleratorID: "old-gpu", SupportsModelLifecycle: true, Enabled: true, ResidencyPolicy: domain.ResidencyAuto, CapacityVerified: false, WarmRAMSupported: false}
	mgr.mu.Lock()
	mgr.targets[target.ID] = target
	mgr.mu.Unlock()
	observationDone := make(chan bool, 1)
	go func() { observationDone <- mgr.observeTargetResidency(context.Background(), target) }()
	select {
	case <-backing.entered:
	case <-time.After(time.Second):
		t.Fatal("older observation did not reach missing-row barrier")
	}
	newer := &domain.ModelResidency{ID: target.ID + "::model", TargetID: target.ID, AcceleratorID: "new-gpu", Adapter: "llamacpp", Model: "model", TargetGeneration: 1, ExecutionFingerprint: "newer-fingerprint", DesiredTier: domain.ResidencyWarmRAM, ObservedTier: domain.ResidencyWarmRAM, CapacityVerified: true, WarmRAMSupported: true, WarmModelBytes: 987654, WarmModelBytesVerified: true, UpdatedAt: time.Now().UTC()}
	if _, created, err := base.CreateModelResidency(context.Background(), newer); err != nil || !created {
		t.Fatalf("newer residency create failed: created=%v err=%v", created, err)
	}
	close(backing.release)
	if ok := <-observationDone; !ok {
		t.Fatal("older observation did not safely adopt the newer row")
	}
	final, err := base.GetModelResidency(context.Background(), target.ID, "model")
	if err != nil {
		t.Fatal(err)
	}
	if final.AcceleratorID != newer.AcceleratorID || final.ObservedTier != newer.ObservedTier || final.WarmModelBytes != newer.WarmModelBytes || !final.CapacityVerified || !final.WarmRAMSupported || !final.WarmModelBytesVerified {
		t.Fatalf("older missing-row retry overwrote newer material facts: final=%+v newer=%+v", final, newer)
	}
}

func TestRegisterTargetRestartSeedsDurableGenerationByFingerprint(t *testing.T) {
	ctx := context.Background()
	target := Target{ID: "restart-generation", Adapter: "llamacpp", Endpoint: "https://old", Models: []string{"model"}, AcceleratorID: "gpu-0", SupportsModelLifecycle: true, Enabled: true, ResidencyPolicy: domain.ResidencyAuto, Slots: 1, MaxAcceleratorsPerWorkload: 1}
	normalizer := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	normalizer.RegisterTarget(target)
	normalizer.mu.RLock()
	normalized := normalizer.targets[target.ID]
	normalizer.mu.RUnlock()
	fingerprint := targetExecutionFingerprint(normalized)
	seed := func() store.WorkloadStore {
		backing := store.NewMemoryStore()
		if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: target.ID + "::model", TargetID: target.ID, Model: "model", TargetGeneration: 2, ExecutionFingerprint: fingerprint, UpdatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		return backing
	}
	changedBacking := seed()
	changed := normalized
	changed.Endpoint = "https://new"
	changedMgr := NewManager(quietLogger(), changedBacking, time.Second)
	changedMgr.RegisterTarget(changed)
	changedMgr.mu.RLock()
	changedGeneration := changedMgr.targetGenerations[target.ID]
	changedMgr.mu.RUnlock()
	if changedGeneration != 3 {
		t.Fatalf("changed fingerprint reused durable generation: got %d want 3", changedGeneration)
	}
	exactBacking := seed()
	exactMgr := NewManager(quietLogger(), exactBacking, time.Second)
	exactMgr.RegisterTarget(normalized)
	exactMgr.mu.RLock()
	exactGeneration := exactMgr.targetGenerations[target.ID]
	exactMgr.mu.RUnlock()
	if exactGeneration != 2 {
		t.Fatalf("exact fingerprint failed to reuse durable generation: got %d want 2", exactGeneration)
	}
}

func TestResidencyObservationPreservesNewerWarmTransition(t *testing.T) {
	base := store.NewMemoryStore()
	now := time.Now().UTC()
	initial := &domain.ModelResidency{ID: "transition-race::model", TargetID: "transition-race", Model: "model", TargetGeneration: 1, ExecutionFingerprint: "test-fingerprint", DesiredTier: domain.ResidencyColdDisk, ObservedTier: domain.ResidencyColdDisk, UpdatedAt: now}
	if _, err := base.UpsertModelResidency(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	newer := *initial
	newer.DesiredTier = domain.ResidencyWarmRAM
	newer.ObservedTier = domain.ResidencyWarmRAM
	newer.WarmModelBytes = 12345
	newer.WarmModelBytesVerified = true
	newer.UpdatedAt = now.Add(time.Second)
	backing := &newerResidencyOnCASStore{WorkloadStore: base, newer: &newer}
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "transition-race", Adapter: "llamacpp", Models: []string{"model"}, AcceleratorID: "gpu0", ResidentModels: nil, SupportsModelLifecycle: true, Enabled: true, ResidencyPolicy: domain.ResidencyAuto}
	mgr.mu.Lock()
	mgr.targets[target.ID] = target
	mgr.mu.Unlock()
	if !mgr.observeTargetResidency(context.Background(), target) {
		t.Fatal("observation did not complete after transition conflict")
	}
	final, err := base.GetModelResidency(context.Background(), target.ID, "model")
	if err != nil {
		t.Fatal(err)
	}
	if final.ObservedTier != domain.ResidencyWarmRAM || final.DesiredTier != domain.ResidencyWarmRAM || final.WarmModelBytes != newer.WarmModelBytes || !final.WarmModelBytesVerified {
		t.Fatalf("older observation overwrote newer warm transition: %+v", final)
	}
}

func TestResidencyTierNormalizationRequiresWarmProofAndClearsIncompatibleClaims(t *testing.T) {
	warm := &domain.ModelResidency{ObservedTier: domain.ResidencyWarmRAM, DesiredTier: domain.ResidencyWarmRAM, WarmModelBytes: 0, WarmModelBytesVerified: false}
	if err := normalizeResidencyTier(warm, domain.ResidencyWarmRAM, 0, false); err == nil {
		t.Fatal("unverified warm residency was accepted")
	}
	if err := normalizeResidencyTier(warm, domain.ResidencyWarmRAM, 4096, true); err != nil || warm.WarmModelBytes != 4096 || !warm.WarmModelBytesVerified || warm.MinResidentUntil != nil {
		t.Fatalf("verified warm residency was not normalized: %+v err=%v", warm, err)
	}
	warm.SessionCheckpointable = true
	warm.MinResidentUntil = ptrTime(time.Now().UTC())
	if err := normalizeResidencyTier(warm, domain.ResidencyColdDisk, 0, false); err != nil || warm.WarmModelBytes != 0 || warm.WarmModelBytesVerified || warm.SessionCheckpointable || warm.MinResidentUntil != nil {
		t.Fatalf("cold normalization retained incompatible claims: %+v err=%v", warm, err)
	}
	if err := normalizeResidencyTier(warm, domain.ResidencyHotVRAM, 0, false); err != nil || warm.WarmModelBytes != 0 || warm.WarmModelBytesVerified {
		t.Fatalf("hot normalization retained warm claims: %+v err=%v", warm, err)
	}
}

type routerFixture struct {
	mu       sync.Mutex
	resident map[string]bool
	events   []string
}

func newRouterFixture(t *testing.T, initiallyLoaded ...string) (*routerFixture, *httptest.Server) {
	t.Helper()
	fixture := &routerFixture{resident: map[string]bool{"small": false, "large": false}}
	for _, model := range initiallyLoaded {
		fixture.resident[model] = true
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		switch r.URL.Path {
		case "/v1/models":
			data := make([]map[string]string, 0, len(fixture.resident))
			for model, loaded := range fixture.resident {
				status := "unloaded"
				if loaded {
					status = "loaded"
				}
				data = append(data, map[string]string{"id": model, "status": status})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case "/models/load", "/models/unload":
			var body struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			loaded := r.URL.Path == "/models/load"
			fixture.resident[body.Model] = loaded
			action := "unload:"
			if loaded {
				action = "load:"
			}
			fixture.events = append(fixture.events, action+body.Model)
			w.WriteHeader(http.StatusOK)
		case "/v1/chat/completions":
			var body struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			fixture.events = append(fixture.events, "execute:"+body.Model)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "chat-1", "choices": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	return fixture, server
}

func (f *routerFixture) snapshot() ([]string, map[string]bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	events := append([]string(nil), f.events...)
	resident := make(map[string]bool, len(f.resident))
	for model, loaded := range f.resident {
		resident[model] = loaded
	}
	return events, resident
}

func TestOllamaLifecycleUsesGenerateAndRunningModelState(t *testing.T) {
	var mu sync.Mutex
	resident := map[string]bool{"small": true}
	var keepAliveValues []int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/generate":
			var body struct {
				Model     string `json:"model"`
				KeepAlive int    `json:"keep_alive"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			keepAliveValues = append(keepAliveValues, body.KeepAlive)
			resident[body.Model] = body.KeepAlive != 0
			_ = json.NewEncoder(w).Encode(map[string]any{"model": body.Model, "done": true})
		case "/api/ps":
			models := []map[string]string{}
			for model, loaded := range resident {
				if loaded {
					models = append(models, map[string]string{"name": model, "model": model})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"models": models})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	target := Target{ID: "ollama", Endpoint: backend.URL, RuntimeArgs: []string{"ollama", "context=4096"}, SupportsModelLifecycle: true}
	if err := adapter.LoadModel(context.Background(), target, "large"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.UnloadModel(context.Background(), target, "small"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keepAliveValues) != 2 || keepAliveValues[0] != -1 || keepAliveValues[1] != 0 || !resident["large"] || resident["small"] {
		t.Fatalf("unexpected Ollama lifecycle state: keep_alive=%v resident=%v", keepAliveValues, resident)
	}
}

func TestLlamaRouterMissingModelIsColdOnly(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/models/unload", "/models/load":
			w.WriteHeader(http.StatusOK)
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	target := Target{ID: "router-missing", Adapter: "llamacpp", Endpoint: backend.URL, Models: []string{"model"}, SupportsModelLifecycle: true, Enabled: true}

	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	residency, err := backing.GetModelResidency(context.Background(), target.ID, "model")
	if err != nil {
		t.Fatal(err)
	}
	residency.ObservedTier = domain.ResidencyHotVRAM
	residency.DesiredTier = domain.ResidencyHotVRAM
	if _, err := backing.UpsertModelResidency(context.Background(), residency); err != nil {
		t.Fatal(err)
	}
	coldTransition, err := mgr.transitionModel(context.Background(), adapter, target, "model", domain.ResidencyColdDisk, "test_unload", "test", "", "missing-cold", nil)
	if err != nil || coldTransition == nil || coldTransition.Status != domain.ResidencyTransitionSucceeded {
		t.Fatalf("missing model should prove cold unload: transition=%+v err=%v", coldTransition, err)
	}
	projected, err := backing.GetModelResidency(context.Background(), target.ID, "model")
	if err != nil || projected.ObservedTier != domain.ResidencyColdDisk {
		t.Fatalf("cold projection was not persisted: residency=%+v err=%v", projected, err)
	}

	loadStore := store.NewMemoryStore()
	loadMgr := NewManager(quietLogger(), loadStore, time.Second)
	loadMgr.RegisterAdapter(adapter)
	loadMgr.RegisterTarget(target)
	loadCtx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	hotTransition, err := loadMgr.transitionModel(loadCtx, adapter, target, "model", domain.ResidencyHotVRAM, "test_load", "test", "", "missing-hot", nil)
	if err == nil || hotTransition == nil || hotTransition.Status != domain.ResidencyTransitionFailed {
		t.Fatalf("missing model must not prove hot load: transition=%+v err=%v", hotTransition, err)
	}
}

type observedComfyReclaimer struct{ *HTTPAdapter }

func (a *observedComfyReclaimer) ReclaimAcceleratorObserved(ctx context.Context, target Target, fence int64) (ResidencyObservation, error) {
	if err := a.ReclaimAccelerator(ctx, target); err != nil {
		return ResidencyObservation{}, err
	}
	return ResidencyObservation{TargetID: target.ID, Model: "runtime-cache", RuntimeIdentity: strings.Join([]string{target.ID, target.Adapter, target.RuntimeProtocol, target.CapabilityVersion, target.ModelFingerprint}, "|"), Tier: domain.ResidencyColdDisk, FencingToken: uint64(fence)}, nil
}

type uncertainComfyReclaimer struct{}

func (uncertainComfyReclaimer) ReclaimAccelerator(context.Context, Target) error {
	return errors.New("observation_unavailable: ComfyUI cache status is not observable")
}

func (uncertainComfyReclaimer) ReclaimAcceleratorObserved(context.Context, Target, int64) (ResidencyObservation, error) {
	return ResidencyObservation{}, errors.New("observation_unavailable: ComfyUI cache status is not observable")
}

type countingReclaimer struct{ calls int }

func (r *countingReclaimer) ReclaimAccelerator(context.Context, Target) error {
	r.calls++
	return nil
}

func TestNativeComfyReclaimRejectedBeforeSideEffect(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	reclaimer := &countingReclaimer{}
	target := Target{ID: "native-comfy", Adapter: "comfy", RuntimeProtocol: "native", AcceleratorID: "gpu-0", Enabled: true}
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "native-reclaim", OwnerID: "operator"}}
	transition, err := mgr.transitionRuntimeCache(context.Background(), reclaimer, target, workload, nil, "native-reclaim")
	if err == nil || transition != nil || reclaimer.calls != 0 {
		t.Fatalf("native Comfy reclaim crossed the side-effect boundary: transition=%+v err=%v calls=%d", transition, err, reclaimer.calls)
	}
}

func TestLegacyUnobservableReclaimIsDiscoverableForManualReconciliation(t *testing.T) {
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	transition := &domain.ResidencyTransition{ID: "legacy-native-reclaim", IdempotencyKey: "legacy-native-reclaim", TargetID: "node-native-comfy", Model: "runtime-cache", FromTier: domain.ResidencyHotVRAM, ToTier: domain.ResidencyColdDisk, Status: domain.ResidencyTransitionRunning, FencingToken: 23, CreatedAt: now, StartedAt: &now}
	if _, _, err := backing.CreateResidencyTransition(context.Background(), transition); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.initializeResidencyRecovery(context.Background())
	mgr.recoverRegisteredResidencyTransitions(context.Background())
	row, err := backing.GetResidencyTransition(context.Background(), transition.ID)
	if err != nil || row.Status != domain.ResidencyTransitionManualReconciliation || row.Error != "no authoritative projection or correlated backend query" {
		t.Fatalf("legacy unobservable reclaim was not surfaced durably: row=%+v err=%v", row, err)
	}
	active, activeErr := backing.ListActiveResidencyTransitions(context.Background(), transition.TargetID, transition.Model)
	if activeErr != nil || len(active) != 0 {
		t.Fatalf("manual reconciliation marker remained active: rows=%+v err=%v", active, activeErr)
	}
	mgr.mu.RLock()
	_, stillQueued := mgr.recoveryTransitions[transition.ID]
	mgr.mu.RUnlock()
	if stillQueued {
		t.Fatal("manual reconciliation marker remained in the automatic recovery queue")
	}
}

func TestRuntimeCacheReclaimObservationUnavailableRemainsRecoverable(t *testing.T) {
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	target := Target{ID: "comfy", Adapter: "comfy", RuntimeProtocol: managedComfyProtocol, AcceleratorID: "gpu-0", CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, SupportsAcceleratorReclaim: true, Enabled: true}
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "reclaim-uncertain", OwnerID: "operator"}}
	lease := &domain.AcceleratorLease{AcceleratorID: "gpu-0", WorkloadID: workload.Request.ID, FencingToken: 17}
	transition, err := mgr.transitionRuntimeCache(context.Background(), uncertainComfyReclaimer{}, target, workload, lease, "test-observation-unavailable")
	if err == nil || !strings.Contains(err.Error(), "observation_unavailable") {
		t.Fatalf("unobservable reclaim unexpectedly succeeded: transition=%+v err=%v", transition, err)
	}
	if transition == nil || transition.Status != domain.ResidencyTransitionRunning || transition.FencingToken != 17 {
		t.Fatalf("unobservable reclaim was terminalized or lost its fence: %+v", transition)
	}
	stored, getErr := backing.GetResidencyTransition(context.Background(), transition.ID)
	if getErr != nil || stored.Status != domain.ResidencyTransitionRunning || stored.FencingToken != 17 {
		t.Fatalf("recoverable reclaim was not durably retained: row=%+v err=%v", stored, getErr)
	}
}

func TestOperatorOllamaLoadReclaimsForeignComfyCacheFirst(t *testing.T) {
	var mu sync.Mutex
	freed := false
	loaded := false
	comfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/free" {
			http.NotFound(w, r)
			return
		}
		freed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer comfy.Close()
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/generate":
			if !freed {
				http.Error(w, "foreign cache still resident", http.StatusInternalServerError)
				return
			}
			loaded = true
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true})
		case "/api/ps":
			models := []map[string]string{}
			if loaded {
				models = append(models, map[string]string{"model": "large"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"models": models})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ollama.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(&observedComfyReclaimer{HTTPAdapter: NewHTTPAdapter("comfy", "comfy", comfy.Client())})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", ollama.Client()))
	mgr.RegisterTarget(Target{ID: "comfy", Adapter: "comfy", Endpoint: comfy.URL, RuntimeProtocol: managedComfyProtocol, AcceleratorID: "gpu-0", CapabilityVersion: "managed-comfy-v1", CapabilityRevision: domain.CapabilityContractVersion, Slots: 1, SupportsAcceleratorReclaim: true, Enabled: true})
	mgr.RegisterTarget(Target{ID: "ollama", Adapter: "llamacpp", Endpoint: ollama.URL, AcceleratorID: "gpu-0", Models: []string{"large"}, RuntimeArgs: []string{"ollama"}, SupportsModelLifecycle: true, MaxResidentModels: 1, Slots: 1, Enabled: true})
	residency, transitions, err := mgr.ConfigureResidency(context.Background(), "ollama", "large", domain.ResidencyHotVRAM, domain.ResidencyAuto, "operator", "load-large")
	if err != nil {
		t.Fatal(err)
	}
	if residency.ObservedTier != domain.ResidencyHotVRAM || !freed || !loaded || len(transitions) != 2 {
		t.Fatalf("reclaim/load result residency=%+v transitions=%d freed=%t loaded=%t", residency, len(transitions), freed, loaded)
	}
}

func TestExecutionPerformanceUsesMeasuredWallClockAndUsage(t *testing.T) {
	start := time.Now().UTC()
	performance := executionPerformance(start, start.Add(2*time.Second), start.Add(250*time.Millisecond), []byte(`{"usage":{"prompt_tokens":40,"completion_tokens":20,"total_tokens":60}}`), "test")
	if performance.TTFTMS != 250 || performance.DecodeTPS != 10 || performance.TotalTPS != 30 || performance.PromptTPS != 0 {
		t.Fatalf("unexpected measured performance: %+v", performance)
	}
}

func TestResidencyIdleClockUsesLatestLoadOrUse(t *testing.T) {
	oldUse := time.Now().UTC().Add(-time.Hour)
	recentLoad := time.Now().UTC().Add(-time.Minute)
	if got := residencyTime(&domain.ModelResidency{LastUsedAt: &oldUse, LastLoadedAt: &recentLoad}); !got.Equal(recentLoad) {
		t.Fatalf("manual load was treated as idle since stale use: got=%s want=%s", got, recentLoad)
	}
}

func TestResidencyTransitionUsesOwningNodeControlChannel(t *testing.T) {
	backing := store.NewMemoryStore()
	_, err := backing.UpsertNode(context.Background(), &domain.Node{ID: "node-1", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true}, Accelerators: []domain.Accelerator{{ID: "gpu-1", VRAMTotalMB: 16_000, VRAMFreeMB: 16_000}}})
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetNodeStore(backing)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	mgr.RegisterTarget(Target{ID: "node-1-ollama", Adapter: "llamacpp", Endpoint: "http://controller-must-not-call.invalid", AcceleratorID: "gpu-1", Models: []string{"model"}, RuntimeArgs: []string{"ollama"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxAcceleratorsPerWorkload: 1}, SupportsModelLifecycle: true, MaxResidentModels: 1, Slots: 1, Enabled: true})
	var nodeID, command string
	var args map[string]any
	mgr.SetNodeControl(func(_ context.Context, gotNode, gotCommand string, gotArgs map[string]any, _ string) (map[string]any, error) {
		nodeID, command, args = gotNode, gotCommand, gotArgs
		return map[string]any{"target_id": gotArgs["target_id"], "model": gotArgs["model"], "runtime_identity": "node-1-ollama|llamacpp||runtime-v1|", "fencing_token": gotArgs["fencing_token"], "tier": "hot_vram", "resident": true, "warm_ram": false}, nil
	})
	residency, _, err := mgr.ConfigureResidency(context.Background(), "node-1-ollama", "model", domain.ResidencyHotVRAM, domain.ResidencyAuto, "operator", "node-load")
	if err != nil {
		t.Fatal(err)
	}
	if nodeID != "node-1" || command != "load_model" || args["target_id"] != "node-1-ollama" || args["model"] != "model" || residency.ObservedTier != domain.ResidencyHotVRAM {
		t.Fatalf("transition bypassed node control: node=%q command=%q args=%+v residency=%+v", nodeID, command, args, residency)
	}
}

func TestResidencyTransitionOmissionDuringCommandCannotCommitStaleResult(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node-fence", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true}, Accelerators: []domain.Accelerator{{ID: "node-fence-gpu", NodeID: "node-fence", VRAMTotalMB: 16_000, VRAMFreeMB: 16_000}}}); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetNodeStore(backing)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	adapter := NewHTTPAdapter("llamacpp", "llama", nil)
	mgr.RegisterAdapter(adapter)
	target := Target{ID: "node-fence-ollama", Adapter: "llamacpp", AcceleratorID: "node-fence-gpu", Models: []string{"model"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true}, SupportsModelLifecycle: true, MaxResidentModels: 1, Slots: 1, Enabled: true}
	mgr.RegisterTarget(target)
	entered, release := make(chan struct{}), make(chan struct{})
	mgr.SetNodeControl(func(_ context.Context, _, command string, args map[string]any, _ string) (map[string]any, error) {
		if command != "load_model" {
			return nil, fmt.Errorf("unexpected command %s", command)
		}
		close(entered)
		<-release
		return map[string]any{"target_id": args["target_id"], "model": args["model"], "runtime_identity": residencyCapacityIdentity(target), "fencing_token": args["fencing_token"], "tier": "hot_vram", "resident": true, "warm_ram": false}, nil
	})
	done := make(chan error, 1)
	go func() {
		_, _, err := mgr.ConfigureResidency(ctx, target.ID, "model", domain.ResidencyHotVRAM, domain.ResidencyAuto, "operator", "fenced-load")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("operator transition did not reach command barrier")
	}
	mgr.ReconcileNodeTargets("node-fence", map[string]struct{}{})
	close(release)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "target changed") {
			t.Fatalf("stale operator transition unexpectedly committed: err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("operator transition did not settle after target omission")
	}
	row, err := backing.GetModelResidency(ctx, target.ID, "model")
	if err == nil && row.ObservedTier == domain.ResidencyHotVRAM {
		t.Fatalf("stale transition committed hot residency after omission: %+v", row)
	}
}

func TestManagerKeepsIndeterminateResidencyTransitionForReconciliation(t *testing.T) {
	backing := store.NewMemoryStore()
	_, err := backing.UpsertNode(context.Background(), &domain.Node{ID: "node-reconcile", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true}, Accelerators: []domain.Accelerator{{ID: "node-reconcile-gpu0", VRAMTotalMB: 16_000, VRAMFreeMB: 16_000}}})
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetNodeStore(backing)
	mgr.SetGPUPerformanceControl(nil)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: 10 * time.Millisecond})
	target := Target{ID: "node-reconcile-ollama", Adapter: "llamacpp", AcceleratorID: "node-reconcile-gpu0", Models: []string{"model"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxAcceleratorsPerWorkload: 1}, SupportsModelLifecycle: true, Enabled: true}
	mgr.RegisterTarget(target)
	calls := 0
	mgr.SetNodeControl(func(ctx context.Context, _ string, command string, args map[string]any, _ string) (map[string]any, error) {
		calls++
		if calls == 1 {
			time.Sleep(25 * time.Millisecond) // late node completion after controller cancellation
		}
		if command != "load_model" {
			return nil, fmt.Errorf("unexpected command %s", command)
		}
		return map[string]any{"target_id": args["target_id"], "model": args["model"], "runtime_identity": "node-reconcile-ollama|llamacpp||runtime-v1|", "fencing_token": args["fencing_token"], "tier": "hot_vram", "resident": true, "warm_ram": false}, nil
	})
	_, _, err = mgr.ConfigureResidency(context.Background(), target.ID, "model", domain.ResidencyHotVRAM, domain.ResidencyAuto, "operator", "late-manager-key")
	rows, _ := backing.ListResidencyTransitions(context.Background(), 20)
	var pending *domain.ResidencyTransition
	for _, row := range rows {
		if row.IdempotencyKey == "late-manager-key" {
			pending = row
		}
	}
	if err == nil || pending == nil || pending.Status != domain.ResidencyTransitionRunning || !strings.HasPrefix(pending.Error, "reconciling:") {
		t.Fatalf("indeterminate manager transition was finalized: transition=%+v err=%v", pending, err)
	}
	time.Sleep(30 * time.Millisecond)
	mgr.mu.RLock()
	adapter := mgr.controllerResidency
	mgr.mu.RUnlock()
	if _, err := adapter.TransitionWithNodeIDFromTier(context.Background(), target, "model", domain.ResidencyColdDisk, domain.ResidencyHotVRAM, "late-manager-key", "node-reconcile"); err != nil {
		t.Fatalf("late result was not reconciled with original key: %v", err)
	}
	mgr.recoverResidencyTransitionsForTarget(context.Background(), target.ID)
	rows, err = backing.ListResidencyTransitions(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.IdempotencyKey == "late-manager-key" && row.Status != domain.ResidencyTransitionSucceeded {
			t.Fatalf("manager restart reconciliation did not complete row: %+v", row)
		}
	}
}

func TestDemandLoadEvictsLeastProtectedResidentUnderOneLease(t *testing.T) {
	fixture, backend := newRouterFixture(t, "small")
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	target := Target{
		ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"},
		ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, ResidencyPolicy: domain.ResidencyAuto,
		CapabilityVersion: "router-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 1},
		ModelFingerprint: "router-model-fp",
		ContextLimit: 8192, Slots: 1, ActiveRuntimeProfile: "router-profile",
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "router-profile", ContextLimit: 8192, Slots: 1}},
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 16 << 30},
		CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
	}
	mgr.RegisterTarget(target)
	registered := mgr.targetByID(target.ID)
	for _, measurement := range []store.ModelCapacity{
		measuredCapacityWithProfile(registered, "small", 1<<30, 1<<30),
		measuredCapacityWithProfile(registered, "large", 2<<30, 1<<30),
	} {
		if _, err := mgr.SetModelCapacity(context.Background(), measurement); err != nil {
			t.Fatalf("seed bounded router model/profile capacity for %s: %v", measurement.Model, err)
		}
	}

	workload, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"large","messages":[{"role":"user","content":"hello"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	finished, err := mgr.Wait(waitCtx, workload.Request.ID)
	waitCancel()
	if err != nil || finished == nil || finished.Status != domain.WorkloadSucceeded {
		current, getErr := backing.GetWorkload(context.Background(), workload.Request.ID)
		blocker := ""
		var alternatives []string
		if current != nil {
			blocker = current.Decision.Blocker
			alternatives = append(alternatives, current.Decision.Alternatives...)
		}
		t.Fatalf("demand-loaded workload: result=%+v current=%+v blocker=%q alternatives=%v waitErr=%v getErr=%v", finished, current, blocker, alternatives, err, getErr)
	}
	if finished.Plan == nil || len(finished.Plan.ResidencyTransitionIDs) != 2 {
		t.Fatalf("plan must retain unload/load transition evidence: %+v", finished.Plan)
	}
	events, resident := fixture.snapshot()
	want := []string{"unload:small", "load:large", "execute:large"}
	if len(events) != len(want) {
		t.Fatalf("router events=%v want=%v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("router events=%v want=%v", events, want)
		}
	}
	if resident["small"] || !resident["large"] {
		t.Fatalf("unexpected resident set: %+v", resident)
	}
	large, _ := backing.GetModelResidency(context.Background(), "router", "large")
	if large.ObservedTier != domain.ResidencyHotVRAM || large.UseCount != 1 || large.LastUsedAt == nil {
		t.Fatalf("usage was not persisted: %+v", large)
	}
}

func TestLeasedHistoricalReplayFailsBeforeResidencyReconciliation(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	manager := NewManager(quietLogger(), backing, time.Second)
	target := Target{
		ID: "leased-history-target", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "leased-history-gpu",
		Models: []string{"history-model"}, Enabled: true, SupportsModelLifecycle: true,
		CapabilityVersion: "leased-history-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true},
		ModelFingerprint: "leased-history-fingerprint",
	}
	manager.RegisterTarget(target)
	current := manager.targetByID(target.ID)
	initialGeneration := manager.targetGeneration(target.ID)
	lease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "current-admission", time.Minute)
	if err != nil || !acquired { t.Fatalf("acquire current admission lease: acquired=%t err=%v", acquired, err) }

	identity, _, err := canonicalResidencyIdentity(current, "history-model", false)
	if err != nil { t.Fatal(err) }
	finished := time.Now().UTC()
	legacy := &domain.ResidencyTransition{
		ID: "historical-unleased-replay", IdempotencyKey: "historical-unleased-replay-key", TargetID: current.ID,
		AcceleratorID: current.AcceleratorID, Model: "history-model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM,
		Reason: "historical-replay runtime=" + strings.Join([]string{current.ID, current.Adapter, current.RuntimeProtocol, current.CapabilityVersion, current.ModelFingerprint}, "|"),
		RequestedBy: "current-admission", WorkloadID: "current-workload", CapabilityVersion: current.CapabilityVersion,
		CapabilityRevision: current.CapabilityRevision, TargetGeneration: initialGeneration, ExecutionFingerprint: targetExecutionFingerprint(current),
		Status: domain.ResidencyTransitionPlanned, CreatedAt: finished,
	}
	allocated, _, err := backing.AllocateResidencyTransition(ctx, legacy)
	if err != nil { t.Fatalf("allocate historical unleased row: %v", err) }
	succeeded := *allocated
	succeeded.Status = domain.ResidencyTransitionSucceeded
	succeeded.ObservedTier = domain.ResidencyHotVRAM
	succeeded.RuntimeIdentity = identity
	succeeded.ObservedFence = allocated.FencingToken
	succeeded.FinishedAt = &finished
	if _, err := backing.CompareAndSwapResidencyTransition(ctx, &succeeded, allocated.Revision, domain.ResidencyTransitionPlanned, allocated.FencingToken); err != nil {
		t.Fatalf("persist historical successful result: %v", err)
	}

	projection := &domain.ModelResidency{
		ID: current.ID + "::history-model", TargetID: current.ID, AcceleratorID: current.AcceleratorID,
		Adapter: current.Adapter, Model: "history-model", TargetGeneration: initialGeneration + 5,
		ExecutionFingerprint: targetExecutionFingerprint(current), ObservedTier: domain.ResidencyColdDisk,
		DesiredTier: domain.ResidencyColdDisk, UpdatedAt: time.Now().UTC(),
	}
	storedProjection, err := backing.UpsertModelResidency(ctx, projection)
	if err != nil { t.Fatalf("seed newer durable residency generation: %v", err) }

	_, err = manager.transitionModel(ctx, nil, current, "history-model", domain.ResidencyHotVRAM,
		"historical-replay", "current-admission", "current-workload", legacy.IdempotencyKey, lease)
	if !errors.Is(err, store.ErrResidencyTransitionConflict) { t.Fatalf("leased caller accepted legacy unleased replay: %v", err) }
	if got := manager.targetGeneration(target.ID); got != initialGeneration { t.Fatalf("rejected leased replay rebound in-memory target generation: got=%d want=%d", got, initialGeneration) }
	after, err := backing.GetModelResidency(ctx, target.ID, "history-model")
	if err != nil || after == nil || after.Revision != storedProjection.Revision || after.TargetGeneration != storedProjection.TargetGeneration || after.ObservedTier != storedProjection.ObservedTier {
		t.Fatalf("rejected leased replay changed the durable projection: before=%+v after=%+v err=%v", storedProjection, after, err)
	}
}

func TestLeasedEmptyIdempotencyKeyFailsBeforeResidencyReconciliation(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	manager := NewManager(quietLogger(), backing, time.Second)
	target := Target{
		ID: "leased-empty-key-target", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "leased-empty-key-gpu",
		Models: []string{"empty-key-model"}, Enabled: true, SupportsModelLifecycle: true,
		CapabilityVersion: "leased-empty-key-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true},
		ModelFingerprint: "leased-empty-key-fingerprint",
	}
	manager.RegisterTarget(target)
	current := manager.targetByID(target.ID)
	initialGeneration := manager.targetGeneration(target.ID)
	lease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "empty-key-admission", time.Minute)
	if err != nil || !acquired { t.Fatalf("acquire current admission lease: acquired=%t err=%v", acquired, err) }

	projection := &domain.ModelResidency{
		ID: current.ID + "::empty-key-model", TargetID: current.ID, AcceleratorID: current.AcceleratorID,
		Adapter: current.Adapter, Model: "empty-key-model", TargetGeneration: initialGeneration + 5,
		ExecutionFingerprint: targetExecutionFingerprint(current), ObservedTier: domain.ResidencyColdDisk,
		DesiredTier: domain.ResidencyColdDisk, UpdatedAt: time.Now().UTC(),
	}
	storedProjection, err := backing.UpsertModelResidency(ctx, projection)
	if err != nil { t.Fatalf("seed newer durable residency generation: %v", err) }

	_, err = manager.transitionModel(ctx, nil, current, "empty-key-model", domain.ResidencyHotVRAM,
		"empty-key", "empty-key-admission", "empty-key-workload", "", lease)
	if !errors.Is(err, store.ErrResidencyTransitionConflict) { t.Fatalf("leased empty idempotency key was not rejected: %v", err) }
	if got := manager.targetGeneration(target.ID); got != initialGeneration {
		t.Fatalf("rejected empty-key request rebound in-memory generation: got=%d want=%d", got, initialGeneration)
	}
	after, err := backing.GetModelResidency(ctx, target.ID, "empty-key-model")
	if err != nil || after == nil || after.Revision != storedProjection.Revision || after.TargetGeneration != storedProjection.TargetGeneration || after.ObservedTier != storedProjection.ObservedTier {
		t.Fatalf("rejected empty-key request changed durable projection: before=%+v after=%+v err=%v", storedProjection, after, err)
	}
}

func TestPinnedResidentBlocksDemandReplacement(t *testing.T) {
	fixture, backend := newRouterFixture(t, "small")
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterTarget(Target{ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"}, ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, Enabled: true})
	residency, _ := backing.GetModelResidency(context.Background(), "router", "small")
	residency.Policy = domain.ResidencyPinned
	_, _ = backing.UpsertModelResidency(context.Background(), residency)

	workload, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"large","messages":[{"role":"user","content":"hello"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if workload.Status != domain.WorkloadWaiting || len(workload.Decision.Alternatives) == 0 {
		t.Fatalf("pinned resident should yield an explained wait: %+v", workload)
	}
	events, resident := fixture.snapshot()
	if len(events) != 0 || !resident["small"] || resident["large"] {
		t.Fatalf("pinned model was disrupted: events=%v resident=%+v", events, resident)
	}
}

func TestFailedDemandLoadRestoresEvictedResident(t *testing.T) {
	var mu sync.Mutex
	resident := map[string]bool{"small": true, "large": false}
	var events []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/models":
			data := []map[string]string{}
			for model, loaded := range resident {
				status := "unloaded"
				if loaded {
					status = "loaded"
				}
				data = append(data, map[string]string{"id": model, "status": status})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case "/models/unload":
			resident["small"] = false
			events = append(events, "unload:small")
			w.WriteHeader(http.StatusOK)
		case "/models/load":
			var body struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			events = append(events, "load:"+body.Model)
			if body.Model == "large" {
				http.Error(w, "cannot load", http.StatusInternalServerError)
				return
			}
			resident[body.Model] = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	// These residents are evictable by design; min_residency protection is
	// covered by TestDemandEvictionHonorsMinResidencyUnlessUrgent.
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterTarget(Target{ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"}, ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, Enabled: true})
	workload, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"large","messages":[{}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if workload.Status != domain.WorkloadWaiting {
		t.Fatalf("failed load should remain waitable: %+v", workload)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"unload:small", "load:large", "load:small"}
	if len(events) != len(want) || !resident["small"] || resident["large"] {
		t.Fatalf("rollback events=%v resident=%+v", events, resident)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("rollback events=%v want=%v", events, want)
		}
	}
}

func TestIdleReconcilerUnloadsButQueuedDemandRetainsModel(t *testing.T) {
	fixture, backend := newRouterFixture(t, "small")
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, ReconcileInterval: time.Millisecond, DefaultIdleUnloadAfter: time.Millisecond, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterTarget(Target{ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"}, ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, Enabled: true})
	_, _, err := backing.CreateWorkload(context.Background(), &domain.Workload{Request: domain.WorkloadRequest{ID: "queued", OwnerID: "alice", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"small","messages":[{}]}`)}, Status: domain.WorkloadQueued, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Millisecond)
	mgr.reconcileResidency(context.Background())
	events, resident := fixture.snapshot()
	if len(events) != 0 || !resident["small"] {
		t.Fatalf("queued demand should retain model: events=%v resident=%+v", events, resident)
	}
	queued, _ := backing.GetWorkload(context.Background(), "queued")
	queued.Status = domain.WorkloadCancelled
	_, _ = backing.UpdateWorkload(context.Background(), queued)
	time.Sleep(2 * time.Millisecond)
	mgr.reconcileResidency(context.Background())
	events, resident = fixture.snapshot()
	if len(events) != 1 || events[0] != "unload:small" || resident["small"] {
		t.Fatalf("idle model was not unloaded: events=%v resident=%+v", events, resident)
	}
}

func TestQuietHoursAcrossMidnight(t *testing.T) {
	inside := time.Date(2026, 8, 25, 1, 30, 0, 0, time.Local)
	outside := time.Date(2026, 8, 25, 12, 0, 0, 0, time.Local)
	if !withinQuietHours(inside, "23:00", "07:00") || withinQuietHours(outside, "23:00", "07:00") {
		t.Fatal("overnight quiet-hours window evaluated incorrectly")
	}
}

func TestRestartReconcilesTransitionWithoutReplayingRouterCommand(t *testing.T) {
	backing := store.NewMemoryStore()
	now := time.Now().UTC().Add(-time.Second)
	_, _ = backing.UpsertModelResidency(context.Background(), &domain.ModelResidency{ID: "router::model", TargetID: "router", Adapter: "llamacpp", Model: "model", DesiredTier: domain.ResidencyHotVRAM, ObservedTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto, UpdatedAt: now})
	identity := "router|llamacpp||runtime-v1|"
	transition := &domain.ResidencyTransition{ID: "interrupted", IdempotencyKey: "load-once", TargetID: "router", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, FencingToken: 7, ObservedFence: 7, ObservedTier: domain.ResidencyHotVRAM, RuntimeIdentity: identity, Error: "observed tier=hot_vram warm_model_bytes=0 locked_bytes=0 released_vram=false runtime=" + identity + " fence=7", Status: domain.ResidencyTransitionRunning, CreatedAt: now, StartedAt: &now}
	_, _, _ = backing.CreateResidencyTransition(context.Background(), transition)

	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	mgr.RegisterTarget(Target{ID: "router", Adapter: "llamacpp", Endpoint: "http://unused.invalid", Models: []string{"model"}, ResidentModels: []string{"model"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true}, SupportsModelLifecycle: true, Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	rows, err := backing.ListResidencyTransitions(context.Background(), 10)
	if err != nil || len(rows) != 1 || rows[0].Status != domain.ResidencyTransitionSucceeded {
		t.Fatalf("restart recovery did not reconcile observed state: row=%+v err=%v", rows[0], err)
	}
	events, _ := backing.ListAuditEvents(context.Background(), "", 10)
	found := false
	for _, event := range events {
		if event.Type == "residency.transition.recovered" {
			found = true
		}
	}
	if !found {
		t.Fatal("recovered transition was not audited")
	}
}

func TestProjectionRepairFailureRetainsSucceededPendingEvidence(t *testing.T) {
	base := store.NewMemoryStore()
	backing := &projectionRepairFailureStore{WorkloadStore: base}
	now := time.Now().UTC()
	identity := "router|llamacpp||runtime-v1|"
	residency := &domain.ModelResidency{ID: "router::model", TargetID: "router", Adapter: "llamacpp", Model: "model", DesiredTier: domain.ResidencyHotVRAM, ObservedTier: domain.ResidencyColdDisk, Policy: domain.ResidencyAuto, UpdatedAt: now}
	storedResidency, err := base.UpsertModelResidency(context.Background(), residency)
	if err != nil {
		t.Fatal(err)
	}
	transition := &domain.ResidencyTransition{ID: "repair-pending", IdempotencyKey: "repair-pending", TargetID: "router", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, FencingToken: 9, ObservedFence: 9, ObservedTier: domain.ResidencyHotVRAM, RuntimeIdentity: identity, Status: domain.ResidencyTransitionSucceeded, ProjectionRepairPending: true, CreatedAt: now}
	if _, _, err := base.CreateResidencyTransition(context.Background(), transition); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "router", Adapter: "llamacpp", RuntimeProtocol: "", Models: []string{"model"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true}, SupportsModelLifecycle: true, Enabled: true}
	if err := mgr.acceptSucceededResidencyTransition(context.Background(), transition, target, storedResidency, storedResidency.Revision, 0); err == nil {
		t.Fatal("projection repair unexpectedly succeeded")
	}
	row, err := base.GetResidencyTransition(context.Background(), transition.ID)
	if err != nil || row.Status != domain.ResidencyTransitionSucceeded || !row.ProjectionRepairPending || row.ObservedTier != domain.ResidencyHotVRAM || row.RuntimeIdentity != identity {
		t.Fatalf("projection failure lost authoritative succeeded evidence: row=%+v err=%v", row, err)
	}
}

func TestMeasuredCapacityAdmissionUsesAggregateBytesAndHardCap(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "capacity-target", Adapter: "llamacpp", AcceleratorID: "capacity-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "capacity-rev", ModelFingerprint: "capacity-model", MaxResidentModels: 4, Capacity: domain.CapacityBudget{
		VRAMTotalBytes: 16 * 1024 * 1024 * 1024, VRAMReserveBytes: 512 * 1024 * 1024, VRAMHardCapBytes: 15 * 1024 * 1024 * 1024,
	}, Enabled: true}
	mgr.RegisterTarget(target)
	put := func(model string, bytes int64) {
		t.Helper()
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, model, bytes)); err != nil {
			t.Fatal(err)
		}
	}
	put("resident", 9*1024*1024*1024)
	put("requested", 6*1024*1024*1024+1)
	resident := &domain.ModelResidency{ID: target.ID + "::resident", TargetID: target.ID, Model: "resident", ObservedTier: domain.ResidencyHotVRAM, DesiredTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto}
	if _, err := backing.UpsertModelResidency(ctx, resident); err != nil {
		t.Fatal(err)
	}
	if err := mgr.checkResidentCapacity(ctx, target, "requested"); err == nil {
		t.Fatal("aggregate footprint over runtime hard cap was admitted")
	}
	// A 10 GiB target can fit a 4 GiB model with a 512 MiB reserve exactly;
	// this exercises byte arithmetic without product-name branches.
	for _, budget := range []int64{10, 16, 24, 32} {
		caseTarget := target
		caseTarget.ID = fmt.Sprintf("capacity-%d-gib", budget)
		caseTarget.AcceleratorID = fmt.Sprintf("capacity-gpu-%d", budget)
		caseTarget.ModelFingerprint = caseTarget.ID + "-model"
		caseTarget.CapabilityRevision = "capacity-rev"
		caseTarget.MaxResidentModels = 4
		caseTarget.Capacity.VRAMTotalBytes = budget * 1024 * 1024 * 1024
		caseTarget.Capacity.VRAMHardCapBytes = caseTarget.Capacity.VRAMTotalBytes
		caseTarget.Capacity.VRAMReserveBytes = 512 * 1024 * 1024
		mgr.RegisterTarget(caseTarget)
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(caseTarget, "model", 4*1024*1024*1024, 128*1024*1024)); err != nil {
			t.Fatal(err)
		}
		if err := mgr.checkResidentCapacity(ctx, caseTarget, "model"); err != nil {
			t.Fatalf("%d GiB measured target rejected fitting model: %v", budget, err)
		}
		boundary := caseTarget
		boundary.ID += "-boundary"
		boundary.AcceleratorID += "-boundary"
		boundary.ModelFingerprint = boundary.ID + "-fingerprint"
		mgr.RegisterTarget(boundary)
		residentBytes := budget*1024*1024*1024 - boundary.Capacity.VRAMReserveBytes - 4*1024*1024*1024
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(boundary, "resident", residentBytes)); err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(boundary, "requested", 4*1024*1024*1024+1)); err != nil {
			t.Fatal(err)
		}
		if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: boundary.ID + "::resident", TargetID: boundary.ID, AcceleratorID: boundary.AcceleratorID, Model: "resident", ObservedTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto}); err != nil {
			t.Fatal(err)
		}
		if err := mgr.checkResidentCapacity(ctx, boundary, "requested"); err == nil {
			t.Fatalf("%d GiB one-byte-over boundary was admitted", budget)
		}
		candidates, _, err := mgr.evictionCandidates(ctx, boundary, "requested", 0)
		if err != nil || len(candidates) != 1 || candidates[0].Model != "resident" {
			t.Fatalf("%d GiB over-boundary did not expose the eligible reclaim victim: candidates=%+v err=%v", budget, candidates, err)
		}
	}
	unified := Target{ID: "capacity-unified", Adapter: "llamacpp", CapabilityVersion: "runtime-v1", CapabilityRevision: "capacity-rev", ModelFingerprint: "unified-model-fingerprint", MaxResidentModels: 4, Capacity: domain.CapacityBudget{
		RAMTotalBytes: 16 * 1024 * 1024 * 1024, RAMReserveBytes: 512 * 1024 * 1024, RAMHardCapBytes: 15 * 1024 * 1024 * 1024,
	}, Enabled: true}
	unified.AcceleratorID = "capacity-unified-gpu"
	mgr.RegisterTarget(unified)
	if _, err := mgr.SetModelCapacity(ctx, measuredUnifiedCapacity(unified, "unified-model", 4*1024*1024*1024, 128*1024*1024)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.checkResidentCapacity(ctx, unified, "unified-model"); err != nil {
		t.Fatalf("unified-memory measured target rejected fitting model: %v", err)
	}
	unifiedBoundary := unified
	unifiedBoundary.ID = "capacity-unified-boundary"
	unifiedBoundary.AcceleratorID = "capacity-unified-boundary-gpu"
	unifiedBoundary.ModelFingerprint = "unified-boundary-fingerprint"
	mgr.RegisterTarget(unifiedBoundary)
	if _, err := mgr.SetModelCapacity(ctx, measuredUnifiedFootprint(unifiedBoundary, "resident", 15*1024*1024*1024+512*1024*1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.SetModelCapacity(ctx, measuredUnifiedFootprint(unifiedBoundary, "requested", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: unifiedBoundary.ID + "::resident", TargetID: unifiedBoundary.ID, AcceleratorID: unifiedBoundary.AcceleratorID, Model: "resident", ObservedTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.checkResidentCapacity(ctx, unifiedBoundary, "requested"); err == nil {
		t.Fatal("unified-memory one-byte-over boundary was admitted")
	}
	// A fresh manager reads the same measured envelope from the durable store;
	// restart must not silently revert to an unbounded/guessed budget.
	restarted := NewManager(quietLogger(), backing, time.Second)
	restarted.RegisterTarget(target)
	if err := restarted.checkResidentCapacity(ctx, target, "requested"); err == nil {
		t.Fatal("restarted manager lost the durable hard-cap admission decision")
	}
}

func TestCanonicalReserveCountedOnceAtExactBoundary(t *testing.T) {
	ctx := context.Background()
	const reserve = int64(512 << 20)
	const cap10 = int64(10 << 30)
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "canonical-reserve-vram", Adapter: "llamacpp", AcceleratorID: "canonical-reserve-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "canonical-reserve-rev", ModelFingerprint: "canonical-reserve-fp", MaxResidentModels: 4, Capacity: domain.CapacityBudget{VRAMTotalBytes: cap10, VRAMReserveBytes: reserve, VRAMHardCapBytes: cap10}, Enabled: true}
	mgr.RegisterTarget(target)
	put := func(model string, bytes int64) {
		t.Helper()
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, model, bytes)); err != nil {
			t.Fatal(err)
		}
	}
	put("fit", cap10-reserve)
	if err := mgr.checkResidentCapacity(ctx, target, "fit"); err != nil {
		t.Fatalf("9.5 GiB model should fit with one 512 MiB reserve: %v", err)
	}
	put("resident-a", 4<<30)
	put("resident-b", cap10-reserve-(4<<30))
	for _, model := range []string{"resident-a", "resident-b"} {
		if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: target.ID + "::" + model, TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: model, ObservedTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto}); err != nil {
			t.Fatal(err)
		}
	}
	if err := mgr.checkResidentCapacity(ctx, target, "resident-b"); err != nil {
		t.Fatalf("two residents should pay one canonical reserve: %v", err)
	}
	put("over", cap10-reserve-(4<<30)+1)
	if err := mgr.checkResidentCapacity(ctx, target, "over"); err == nil {
		t.Fatal("one-byte-over two-resident boundary was admitted")
	}

	unified := Target{ID: "canonical-reserve-unified", Adapter: "llamacpp", AcceleratorID: "canonical-reserve-unified-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "canonical-reserve-rev", ModelFingerprint: "canonical-reserve-unified-fp", MaxResidentModels: 4, Capacity: domain.CapacityBudget{RAMTotalBytes: cap10, RAMReserveBytes: reserve, RAMHardCapBytes: cap10}, Enabled: true}
	mgr.RegisterTarget(unified)
	putUnified := func(model string, bytes int64) {
		t.Helper()
		if _, err := mgr.SetModelCapacity(ctx, measuredUnifiedFootprint(unified, model, bytes)); err != nil {
			t.Fatal(err)
		}
	}
	putUnified("fit", cap10-reserve)
	if err := mgr.checkResidentCapacity(ctx, unified, "fit"); err != nil {
		t.Fatalf("unified 9.5 GiB model should fit with one reserve: %v", err)
	}
	putUnified("resident-a", 4<<30)
	putUnified("resident-b", cap10-reserve-(4<<30))
	for _, model := range []string{"resident-a", "resident-b"} {
		if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: unified.ID + "::" + model, TargetID: unified.ID, AcceleratorID: unified.AcceleratorID, Model: model, ObservedTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto}); err != nil {
			t.Fatal(err)
		}
	}
	if err := mgr.checkResidentCapacity(ctx, unified, "resident-b"); err != nil {
		t.Fatalf("two unified residents should pay one canonical reserve: %v", err)
	}
	putUnified("over", cap10-reserve-(4<<30)+1)
	if err := mgr.checkResidentCapacity(ctx, unified, "over"); err == nil {
		t.Fatal("one-byte-over unified boundary was admitted")
	}
}

func TestCheckedMiBConversionFailsClosedBeforeAdmission(t *testing.T) {
	near := math.MaxInt64 / bytesPerMiB
	if got, err := checkedMiBToBytes(near, "near"); err != nil || got != near*bytesPerMiB {
		t.Fatalf("near-boundary MiB conversion changed: got=%d err=%v", got, err)
	}
	for _, value := range []int64{-1, 1 << 44, near + 1} {
		if _, err := checkedMiBToBytes(value, "invalid"); err == nil {
			t.Fatalf("invalid MiB value %d was converted", value)
		}
	}
	ctx := context.Background()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	for _, target := range []Target{
		{ID: "overflow-target", AcceleratorID: "overflow-gpu", AcceleratorVRAMMB: 1 << 44, Enabled: true},
		{ID: "negative-target", AcceleratorID: "negative-gpu", VRAMReserveMB: -1, Enabled: true},
	} {
		mgr.RegisterTarget(target)
		if err := mgr.checkResidentCapacity(ctx, target, "model"); err == nil {
			t.Fatalf("invalid target MiB envelope was allowed through no-budget admission: %+v", target)
		}
	}
	activeTarget := Target{ID: "active-overflow-target", AcceleratorID: "active-overflow-gpu", Enabled: true}
	mgr.RegisterTarget(activeTarget)
	mgr.placementMu.Lock()
	mgr.activePlacements["invalid-active"] = activePlacement{workloadID: "invalid-active", acceleratorID: activeTarget.AcceleratorID, vramMB: 1 << 44}
	mgr.placementMu.Unlock()
	if err := mgr.checkResidentCapacity(ctx, activeTarget, "model"); err == nil {
		t.Fatal("invalid active placement MiB value was allowed through no-budget admission")
	}
}

func TestConcurrentAdmissionsOnSharedAcceleratorNeverOvercommit(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "admission-concurrent", Adapter: "admission-mock", AcceleratorID: "shared-admission-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "admission-rev", ModelFingerprint: "admission-model", MaxResidentModels: 4, Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, Enabled: true}
	adapter := newAdmissionLifecycleAdapter("admission-mock")
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	for _, model := range []string{"model-a", "model-b"} {
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, model, 10<<30)); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		model := "model-a"
		if i%2 == 1 {
			model = "model-b"
		}
		wg.Add(1)
		go func(index int, requested string) {
			defer wg.Done()
			workload := &domain.Workload{Request: domain.WorkloadRequest{ID: fmt.Sprintf("admission-%d", index), OwnerID: "concurrent", IdempotencyKey: fmt.Sprintf("admission-%d", index)}}
			_, _ = mgr.ensureModelResident(ctx, target, requested, workload, nil)
		}(i, model)
	}
	wg.Wait()
	rows, err := backing.ListModelResidencies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var hot int
	for _, row := range rows {
		if row.TargetID == target.ID && row.ObservedTier == domain.ResidencyHotVRAM {
			hot++
		}
	}
	if hot > 1 {
		t.Fatalf("concurrent admissions left %d hot 10 GiB residents on a 16 GiB accelerator", hot)
	}
}

func TestEnsureModelResidentReclaimsAndRechecksMeasuredCapacityBoundaries(t *testing.T) {
	for _, gib := range []int64{10, 16, 24, 32} {
		t.Run(fmt.Sprintf("%dGiB", gib), func(t *testing.T) {
			ctx := context.Background()
			backing := store.NewMemoryStore()
			mgr := NewManager(quietLogger(), backing, time.Second)
			// These residents are evictable by design; min_residency protection is
			// covered by TestDemandEvictionHonorsMinResidencyUnlessUrgent.
			mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0})
			adapterName := fmt.Sprintf("admission-path-%d", gib)
			adapter := newAdmissionLifecycleAdapter(adapterName)
			mgr.RegisterAdapter(adapter)
			const reserve = int64(512 << 20)
			limit := gib << 30
			target := Target{ID: fmt.Sprintf("admission-path-%d", gib), Adapter: adapterName, AcceleratorID: fmt.Sprintf("admission-path-gpu-%d", gib), Models: []string{"victim", "requested"}, ResidentModels: []string{"victim"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 4}, ModelFingerprint: fmt.Sprintf("admission-path-fp-%d", gib), MaxResidentModels: 4, SupportsModelLifecycle: true, Capacity: domain.CapacityBudget{VRAMTotalBytes: limit, VRAMReserveBytes: reserve, VRAMHardCapBytes: limit}, Enabled: true}
			mgr.RegisterTarget(target)
			victimBytes := limit - reserve - (4 << 30)
			if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "victim", victimBytes)); err != nil {
				t.Fatal(err)
			}
			if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "requested", 4<<30+1)); err != nil {
				t.Fatal(err)
			}
			adapter.SetLoaded("victim", true)
			if err := seedHotResidency(ctx, backing, target, "victim", domain.ResidencyAuto); err != nil {
				t.Fatal(err)
			}
			workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "admission-path-request", OwnerID: "test", IdempotencyKey: "admission-path-request"}}
			if _, err := mgr.ensureModelResident(ctx, target, "requested", workload, nil); err != nil {
				t.Fatalf("production admission path rejected reclaimable %d GiB boundary: %v", gib, err)
			}
			loads, unloads := adapter.Counts()
			if unloads != 1 || loads != 1 {
				t.Fatalf("production path did not issue exactly one unload then load at %d GiB: loads=%d unloads=%d", gib, loads, unloads)
			}
			row, err := backing.GetModelResidency(ctx, target.ID, "requested")
			if err != nil || row.ObservedTier != domain.ResidencyHotVRAM {
				t.Fatalf("requested model did not finish hot after recheck: row=%+v err=%v", row, err)
			}
			if err := mgr.checkResidentCapacity(ctx, target, "requested"); err != nil {
				t.Fatalf("post-reclaim capacity recheck failed at %d GiB: %v", gib, err)
			}

			protected := target
			protected.ID += "-protected"
			protected.AcceleratorID += "-protected"
			protected.ResidentModels = []string{"protected"}
			mgr.RegisterTarget(protected)
			if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(protected, "protected", victimBytes)); err != nil {
				t.Fatal(err)
			}
			if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(protected, "requested", 4<<30+1)); err != nil {
				t.Fatal(err)
			}
			adapter.SetLoaded("protected", true)
			if err := seedHotResidency(ctx, backing, protected, "protected", domain.ResidencyPinned); err != nil {
				t.Fatal(err)
			}
			beforeLoads, beforeUnloads := adapter.Counts()
			if _, err := mgr.ensureModelResident(ctx, protected, "requested", workload, nil); err == nil {
				t.Fatalf("protected one-byte-over boundary was admitted at %d GiB", gib)
			}
			afterLoads, afterUnloads := adapter.Counts()
			if afterLoads != beforeLoads || afterUnloads != beforeUnloads {
				t.Fatalf("protected boundary issued lifecycle side effects at %d GiB: before=%d/%d after=%d/%d", gib, beforeLoads, beforeUnloads, afterLoads, afterUnloads)
			}
		})
	}

	t.Run("unified-memory", func(t *testing.T) {
		ctx := context.Background()
		backing := store.NewMemoryStore()
		mgr := NewManager(quietLogger(), backing, time.Second)
		// These residents are evictable by design; min_residency protection is
		// covered by TestDemandEvictionHonorsMinResidencyUnlessUrgent.
		mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0})
		adapter := newAdmissionLifecycleAdapter("admission-path-unified")
		mgr.RegisterAdapter(adapter)
		const reserve = int64(512 << 20)
		const limit = int64(10 << 30)
		target := Target{ID: "admission-path-unified", Adapter: "admission-path-unified", AcceleratorID: "admission-path-unified-gpu", Models: []string{"victim", "requested"}, ResidentModels: []string{"victim"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 4}, ModelFingerprint: "admission-path-unified-fp", MaxResidentModels: 4, SupportsModelLifecycle: true, Capacity: domain.CapacityBudget{RAMTotalBytes: limit, RAMReserveBytes: reserve, RAMHardCapBytes: limit}, Enabled: true}
		mgr.RegisterTarget(target)
		victimBytes := limit - reserve - (4 << 30)
		for model, bytes := range map[string]int64{"victim": victimBytes, "requested": 4<<30 + 1} {
			if _, err := mgr.SetModelCapacity(ctx, measuredUnifiedFootprint(target, model, bytes)); err != nil {
				t.Fatal(err)
			}
		}
		adapter.SetLoaded("victim", true)
		if err := seedHotResidency(ctx, backing, target, "victim", domain.ResidencyAuto); err != nil {
			t.Fatal(err)
		}
		workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "admission-path-unified-request", OwnerID: "test", IdempotencyKey: "admission-path-unified-request"}}
		if _, err := mgr.ensureModelResident(ctx, target, "requested", workload, nil); err != nil {
			t.Fatalf("unified production admission path rejected reclaimable boundary: %v", err)
		}
		loads, unloads := adapter.Counts()
		if loads != 1 || unloads != 1 {
			t.Fatalf("unified production path lifecycle mismatch: loads=%d unloads=%d", loads, unloads)
		}
	})
}

func TestProductionSubmitCountsInFlightModelExactlyOnceAndOtherPlacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	adapter := newAdmissionLifecycleAdapter("production-admission")
	entered, release := make(chan struct{}), make(chan struct{})
	adapter.ConfigureStartGate(entered, release)
	mgr.RegisterAdapter(adapter)
	const reserve = int64(512 << 20)
	const limit = int64(10 << 30)
	const modelBytes = limit - reserve
	target := Target{ID: "production-admission-target", Adapter: adapter.Name(), AcceleratorID: "production-admission-gpu", Models: []string{"model"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 4}, ModelFingerprint: "production-admission-fingerprint", MaxResidentModels: 4, SupportsModelLifecycle: true, Slots: 1, StandaloneVRAMMB: modelBytes / bytesPerMiB, AcceleratorVRAMMB: limit / bytesPerMiB, VRAMReserveMB: reserve / bytesPerMiB, Capacity: domain.CapacityBudget{VRAMTotalBytes: limit, VRAMReserveBytes: reserve, VRAMHardCapBytes: limit}, Enabled: true}
	mgr.RegisterTarget(target)
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", modelBytes)); err != nil {
		t.Fatal(err)
	}
	mgr.Start(ctx)
	workload, _, err := mgr.Submit(ctx, domain.WorkloadRequest{ID: "production-admission-workload", OwnerID: "owner", Adapter: adapter.Name(), Payload: json.RawMessage(`{"model":"model"}`)})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("production manager flow did not reach execution after reserveTarget and ensureModelResident")
	}
	refreshDone := make(chan struct{})
	go func() {
		mgr.RegisterTarget(target)
		close(refreshDone)
	}()
	select {
	case <-refreshDone:
	case <-time.After(time.Second):
		t.Fatal("RegisterTarget blocked behind a pending backend command")
	}
	// The first workload is the exact in-flight reservation and is excluded
	// only when its workload ID is supplied. A hypothetical concurrent
	// placement must still see that active allocation and fail over the cap.
	if err := mgr.checkResidentCapacityForWorkload(ctx, target, "model", "other-placement"); err == nil {
		t.Fatal("concurrent other placement was admitted without counting active allocation")
	}
	close(release)
	finished, err := mgr.Wait(ctx, workload.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("production admission did not finish: workload=%+v err=%v", finished, err)
	}
	loads, unloads := adapter.Counts()
	if loads != 1 || unloads != 0 {
		t.Fatalf("production flow lifecycle mismatch: loads=%d unloads=%d", loads, unloads)
	}
	row, err := backing.GetModelResidency(ctx, target.ID, "model")
	if err != nil || row.ObservedTier != domain.ResidencyHotVRAM {
		t.Fatalf("production flow did not persist hot model residency: row=%+v err=%v", row, err)
	}
	if err := mgr.checkResidentCapacity(ctx, target, "model"); err != nil {
		t.Fatalf("final production capacity check double-counted the exact model: %v", err)
	}
}

func TestProductionAdmissionRefreshInterleavingsReconcileWithoutColdStartOrDuplicateLoad(t *testing.T) {
	for _, tc := range []struct {
		name              string
		initialResident   bool
		refreshedResident bool
	}{
		{name: "hot_snapshot_refresh_removes", initialResident: true},
		{name: "cold_snapshot_refresh_adds", refreshedResident: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backing := store.NewMemoryStore()
			mgr := NewManager(quietLogger(), backing, time.Second)
			adapter := newAdmissionLifecycleAdapter("refresh-" + tc.name)
			requirementsEntered, requirementsRelease := make(chan struct{}), make(chan struct{})
			adapter.ConfigureRequirementsGate(requirementsEntered, requirementsRelease)
			mgr.RegisterAdapter(adapter)
			target := Target{ID: "refresh-" + tc.name, Adapter: adapter.Name(), AcceleratorID: "refresh-gpu-" + tc.name, Models: []string{"model"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 2}, ModelFingerprint: "refresh-fingerprint-" + tc.name, SupportsModelLifecycle: true, MaxResidentModels: 2, Slots: 1, Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, Enabled: true}
			if tc.initialResident {
				target.ResidentModels = []string{"model"}
				adapter.SetLoaded("model", true)
			}
			mgr.RegisterTarget(target)
			if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", 1<<30)); err != nil {
				t.Fatal(err)
			}
			mgr.Start(ctx)
			defer mgr.Close()
			type submission struct {
				workload *domain.Workload
				err      error
			}
			submitted := make(chan submission, 1)
			go func() {
				workload, _, err := mgr.Submit(ctx, domain.WorkloadRequest{ID: target.ID + "-workload", OwnerID: "refresh-test", Adapter: adapter.Name(), Payload: json.RawMessage(`{"model":"model"}`)})
				submitted <- submission{workload: workload, err: err}
			}()
			select {
			case <-requirementsEntered:
			case <-time.After(3 * time.Second):
				t.Fatal("admission did not reach deterministic pre-reservation barrier")
			}
			refreshed := target
			if tc.refreshedResident {
				refreshed.ResidentModels = []string{"model"}
			} else {
				// A complete empty refresh is authoritative. Simulate the physical
				// removal as well; admission must perform one real reload rather than
				// reusing the stale durable hot row.
				adapter.SetLoaded("model", false)
				refreshed.ResidentModels = nil
			}
			// This refresh runs after the scheduler's target snapshot but before
			// reserveTarget/ensureModelResident. The admission fence must consume
			// these current facts instead of the stale snapshot.
			mgr.RegisterTarget(refreshed)
			close(requirementsRelease)
			result := <-submitted
			if result.err != nil {
				t.Fatal(result.err)
			}
			workload := result.workload
			finished, err := mgr.Wait(ctx, workload.Request.ID)
			if err != nil || finished.Status != domain.WorkloadSucceeded {
				t.Fatalf("refresh interleaving did not reconcile to runnable hot state: workload=%+v err=%v", finished, err)
			}
			loads, _ := adapter.Counts()
			expectedLoads := 0
			if !tc.refreshedResident {
				expectedLoads = 1
			}
			if loads != expectedLoads {
				t.Fatalf("refresh interleaving model load count=%d want=%d for %s", loads, expectedLoads, tc.name)
			}
			row, rowErr := backing.GetModelResidency(ctx, target.ID, "model")
			if rowErr != nil || row.ObservedTier != domain.ResidencyHotVRAM {
				t.Fatalf("refresh interleaving lost authoritative hot residency: row=%+v err=%v", row, rowErr)
			}
		})
	}
}

func TestProductionMeasuredCapacityMatrixReclaimsAndChecksBoundaries(t *testing.T) {
	const reserve = int64(512 << 20)
	for _, gib := range []int64{10, 16, 24, 32} {
		t.Run(fmt.Sprintf("%dGiB", gib), func(t *testing.T) {
			limit := gib << 30
			newManager := func(id string) (*Manager, *admissionLifecycleAdapter, Target, context.Context, context.CancelFunc, store.Store) {
				ctx, cancel := context.WithCancel(context.Background())
				backing := store.NewMemoryStore()
				mgr := NewManager(quietLogger(), backing, time.Second)
				adapter := newAdmissionLifecycleAdapter(id + "-adapter")
				mgr.RegisterAdapter(adapter)
				target := Target{ID: id, Adapter: adapter.Name(), AcceleratorID: id + "-gpu", Models: []string{"model", "victim"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 4}, ModelFingerprint: id + "-fingerprint", MaxResidentModels: 4, SupportsModelLifecycle: true, Slots: 1, StandaloneVRAMMB: (limit - reserve) / bytesPerMiB, AcceleratorVRAMMB: limit / bytesPerMiB, VRAMReserveMB: reserve / bytesPerMiB, Capacity: domain.CapacityBudget{VRAMTotalBytes: limit, VRAMReserveBytes: reserve, VRAMHardCapBytes: limit}, Enabled: true}
				mgr.RegisterTarget(target)
				mgr.Start(ctx)
				return mgr, adapter, target, ctx, cancel, backing
			}
			run := func(t *testing.T, id string, modelBytes int64, resident bool, protected bool) (loads, unloads int, final *domain.Workload) {
				t.Helper()
				mgr, adapter, target, ctx, cancel, backing := newManager(id)
				defer func() { cancel(); mgr.Close() }()
				if resident {
					if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "victim", limit-reserve-modelBytes+1)); err != nil {
						t.Fatal(err)
					}
					adapter.SetLoaded("victim", true)
					policy := domain.ResidencyAuto
					if protected {
						policy = domain.ResidencyPinned
					}
					if err := seedHotResidency(ctx, backing, target, "victim", policy); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", modelBytes)); err != nil {
					t.Fatal(err)
				}
				workload, _, err := mgr.Submit(ctx, domain.WorkloadRequest{ID: id + "-workload", OwnerID: "owner", Adapter: adapter.Name(), Payload: json.RawMessage(`{"model":"model"}`)})
				if err != nil {
					t.Fatal(err)
				}
				if protected {
					time.Sleep(50 * time.Millisecond)
					final, _ = mgr.Get(ctx, workload.Request.ID)
				} else {
					final, err = mgr.Wait(ctx, workload.Request.ID)
					if err != nil {
						t.Fatal(err)
					}
				}
				loads, unloads = adapter.Counts()
				return loads, unloads, final
			}

			loads, unloads, exact := run(t, fmt.Sprintf("matrix-exact-%d", gib), limit-reserve, false, false)
			if exact == nil || exact.Status != domain.WorkloadSucceeded || loads != 1 || unloads != 0 {
				t.Fatalf("exact production boundary failed at %d GiB: workload=%+v loads=%d unloads=%d", gib, exact, loads, unloads)
			}
			loads, unloads, reclaim := run(t, fmt.Sprintf("matrix-reclaim-%d", gib), 4<<30+1, true, false)
			if reclaim == nil || reclaim.Status != domain.WorkloadSucceeded || loads != 1 || unloads != 1 {
				t.Fatalf("reclaim production boundary failed at %d GiB: workload=%+v loads=%d unloads=%d", gib, reclaim, loads, unloads)
			}
			loads, unloads, blocked := run(t, fmt.Sprintf("matrix-blocked-%d", gib), 4<<30+1, true, true)
			if loads != 0 || unloads != 0 || blocked == nil || blocked.Status == domain.WorkloadSucceeded {
				t.Fatalf("protected one-byte-over production boundary was admitted at %d GiB: workload=%+v loads=%d unloads=%d", gib, blocked, loads, unloads)
			}
		})
	}

	t.Run("unified-memory", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		backing := store.NewMemoryStore()
		mgr := NewManager(quietLogger(), backing, time.Second)
		adapter := newAdmissionLifecycleAdapter("matrix-unified-adapter")
		mgr.RegisterAdapter(adapter)
		const limit = int64(10 << 30)
		target := Target{ID: "matrix-unified", Adapter: adapter.Name(), AcceleratorID: "matrix-unified-gpu", Models: []string{"model"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxResidentModels: 4}, ModelFingerprint: "matrix-unified-fingerprint", MaxResidentModels: 4, SupportsModelLifecycle: true, Capacity: domain.CapacityBudget{RAMTotalBytes: limit, RAMReserveBytes: reserve, RAMHardCapBytes: limit}, Enabled: true}
		mgr.RegisterTarget(target)
		mgr.Start(ctx)
		if _, err := mgr.SetModelCapacity(ctx, measuredUnifiedFootprint(target, "model", limit-reserve)); err != nil {
			t.Fatal(err)
		}
		workload, _, err := mgr.Submit(ctx, domain.WorkloadRequest{ID: "matrix-unified-workload", OwnerID: "owner", Adapter: adapter.Name(), Payload: json.RawMessage(`{"model":"model"}`)})
		if err != nil {
			t.Fatal(err)
		}
		finished, err := mgr.Wait(ctx, workload.Request.ID)
		if err != nil || finished.Status != domain.WorkloadSucceeded {
			t.Fatalf("unified production exact boundary failed: workload=%+v err=%v", finished, err)
		}
		if err := mgr.checkResidentCapacity(ctx, target, "model"); err != nil {
			t.Fatalf("unified final check double-counted model footprint: %v", err)
		}
	})
}

func TestEvictionCandidatesProtectActiveQueuedAndOperatorResidents(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "eviction-target", Adapter: "llamacpp", AcceleratorID: "eviction-gpu", Enabled: true}
	mgr.RegisterTarget(target)
	mgr.RegisterAdapter(modelAwareMockAdapter{NewMockAdapter()})
	for _, model := range []string{"active", "queued", "pinned", "manual", "off", "victim"} {
		policy := domain.ResidencyAuto
		switch model {
		case "pinned":
			policy = domain.ResidencyPinned
		case "manual":
			policy = domain.ResidencyManual
		case "off":
			policy = domain.ResidencyOff
		}
		if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: target.ID + "::" + model, TargetID: target.ID, Model: model, ObservedTier: domain.ResidencyHotVRAM, DesiredTier: domain.ResidencyHotVRAM, Policy: policy, LastUsedAt: ptrTime(time.Now().UTC())}); err != nil {
			t.Fatal(err)
		}
	}
	mgr.placementMu.Lock()
	mgr.activePlacements["active-workload"] = activePlacement{model: "active"}
	mgr.placementMu.Unlock()
	queued := &domain.Workload{Request: domain.WorkloadRequest{ID: "queued-workload", Adapter: "model-mock", Payload: json.RawMessage(`{"model":"queued"}`)}, Status: domain.WorkloadQueued}
	if _, _, err := backing.CreateWorkload(ctx, queued); err != nil {
		t.Fatal(err)
	}
	candidates, _, err := mgr.evictionCandidates(ctx, target, "new", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Model != "victim" {
		t.Fatalf("protected residents were offered as victims: %+v", candidates)
	}
	for _, field := range []string{"running", "pending"} {
		target.QueueRunning, target.QueuePending = 0, 0
		if field == "running" {
			target.QueueRunning = 1
		} else {
			target.QueuePending = 1
		}
		if got, _, err := mgr.evictionCandidates(ctx, target, "new", 0); err != nil || len(got) != 0 {
			t.Fatalf("target %s queue counter did not protect all residents: candidates=%+v err=%v", field, got, err)
		}
	}
}

func TestCapacityIdentityAndFreshnessFailClosed(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "identity-target", Adapter: "llamacpp", AcceleratorID: "identity-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "revision-a", ModelFingerprint: "model-a", MaxResidentModels: 2, Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, Enabled: true}
	mgr.RegisterTarget(target)
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", 4<<30)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.checkResidentCapacity(ctx, target, "model"); err != nil {
		t.Fatalf("bound capacity was rejected: %v", err)
	}
	row, err := backing.GetModelCapacity(ctx, target.ID, "model", "")
	if err != nil || row.RuntimeIdentity == "" || row.ModelFingerprint != target.ModelFingerprint || row.ObservedAt.IsZero() {
		t.Fatalf("capacity binding omitted identity/freshness: row=%+v err=%v", row, err)
	}
	row.RuntimeIdentity = "different-runtime"
	if _, err := backing.UpsertModelCapacity(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err := mgr.checkResidentCapacity(ctx, target, "model"); err == nil {
		t.Fatal("mismatched runtime capacity was admitted")
	}
}

func TestPhysicalAcceleratorAggregateAcrossTargets(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	base := func(id string) Target {
		return Target{ID: id, Adapter: "llamacpp", AcceleratorID: "shared-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "shared-rev", ModelFingerprint: id + "-fingerprint", MaxResidentModels: 2, Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, Enabled: true}
	}
	targetA, targetB, targetC := base("target-a"), base("target-b"), base("target-c")
	mgr.RegisterTarget(targetA)
	mgr.RegisterTarget(targetB)
	mgr.RegisterTarget(targetC)
	for _, capacity := range []store.ModelCapacity{measuredCapacity(base("target-a"), "model-a", 8<<30), measuredCapacity(base("target-b"), "model-b", 8<<30), measuredCapacity(base("target-c"), "model-c", 1<<30)} {
		if _, err := mgr.SetModelCapacity(ctx, capacity); err != nil {
			t.Fatal(err)
		}
	}
	for _, residency := range []*domain.ModelResidency{{ID: "target-a::model-a", TargetID: "target-a", AcceleratorID: "shared-gpu", Model: "model-a", ObservedTier: domain.ResidencyHotVRAM}, {ID: "target-b::model-b", TargetID: "target-b", AcceleratorID: "shared-gpu", Model: "model-b", ObservedTier: domain.ResidencyHotVRAM}} {
		if _, err := backing.UpsertModelResidency(ctx, residency); err != nil {
			t.Fatal(err)
		}
	}
	if err := mgr.checkResidentCapacity(ctx, targetC, "model-c"); err == nil {
		t.Fatal("shared physical accelerator aggregate was admitted over budget")
	}
	conflicting := base("target-conflicting")
	conflicting.Capacity.VRAMTotalBytes = 24 << 30
	conflicting.Capacity.VRAMHardCapBytes = 24 << 30
	mgr.RegisterTarget(conflicting)
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(conflicting, "model-conflicting", 1<<30)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.checkResidentCapacity(ctx, conflicting, "model-conflicting"); err == nil {
		t.Fatal("conflicting envelopes for one physical accelerator were not rejected")
	}
}

func TestConcurrentCapacityMeasurementsRemainBounded(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "concurrent-capacity", Adapter: "llamacpp", AcceleratorID: "concurrent-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "concurrent-rev", ModelFingerprint: "concurrent-model", MaxResidentModels: 2, Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, Enabled: true}
	mgr.RegisterTarget(target)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", 8<<30)); err != nil {
				t.Errorf("concurrent capacity write: %v", err)
			}
		}()
	}
	wg.Wait()
	rows, err := backing.ListModelCapacities(ctx, target.ID, "model")
	if err != nil || len(rows) != 1 || rows[0].ModelBytes != 8<<30 {
		t.Fatalf("concurrent measurements produced unbounded/mismatched rows: rows=%+v err=%v", rows, err)
	}
}

func measuredCapacity(target Target, model string, modelBytes int64) store.ModelCapacity {
	now := time.Now().UTC()
	hardCap := target.Capacity.VRAMHardCapBytes
	if hardCap <= 0 && target.Capacity.RAMTotalBytes > 0 {
		hardCap = target.Capacity.RAMHardCapBytes
	}
	return store.ModelCapacity{TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: model, ProfileID: target.ActiveRuntimeProfile, ModelFingerprint: target.ModelFingerprint, RuntimeIdentity: residencyCapacityIdentity(target), CapabilityVersion: target.CapabilityVersion, CapabilityRevision: target.CapabilityRevision, ModelBytes: modelBytes, VRAMReserveBytes: target.Capacity.VRAMReserveBytes, RAMReserveBytes: target.Capacity.RAMReserveBytes, RuntimeHardCapBytes: hardCap, VRAMTotalBytes: target.Capacity.VRAMTotalBytes, RAMTotalBytes: target.Capacity.RAMTotalBytes, UnifiedMemory: target.Capacity.VRAMTotalBytes <= 0 && target.Capacity.VRAMHardCapBytes <= 0 && target.Capacity.RAMTotalBytes > 0, CapacitySource: "runtime:test", Verified: true, ObservedAt: now, UpdatedAt: now}
}

func measuredCapacityWithProfile(target Target, model string, modelBytes, profileBytes int64) store.ModelCapacity {
	capacity := measuredCapacity(target, model, modelBytes)
	capacity.ProfileBytes = profileBytes
	return capacity
}

func measuredUnifiedCapacity(target Target, model string, modelBytes, profileBytes int64) store.ModelCapacity {
	capacity := measuredCapacityWithProfile(target, model, modelBytes, profileBytes)
	capacity.ModelBytes = 0
	capacity.RAMBytes = modelBytes + profileBytes
	return capacity
}

func measuredUnifiedFootprint(target Target, model string, ramBytes int64) store.ModelCapacity {
	capacity := measuredCapacity(target, model, 1)
	capacity.RAMBytes = ramBytes
	return capacity
}

type admissionLifecycleAdapter struct {
	*MockAdapter
	name                string
	mu                  sync.Mutex
	loaded              map[string]bool
	loads               int
	unloads             int
	startEntered        chan struct{}
	startRelease        chan struct{}
	startOnce           sync.Once
	requirementsEntered chan struct{}
	requirementsRelease chan struct{}
	requirementsOnce    sync.Once
}

func newAdmissionLifecycleAdapter(name string) *admissionLifecycleAdapter {
	return &admissionLifecycleAdapter{MockAdapter: NewMockAdapter(), name: name, loaded: make(map[string]bool)}
}

func (a *admissionLifecycleAdapter) Name() string { return a.name }
func (a *admissionLifecycleAdapter) Requirements(ctx context.Context, req domain.WorkloadRequest) (Requirements, error) {
	if a.requirementsEntered != nil {
		a.requirementsOnce.Do(func() { close(a.requirementsEntered) })
		select {
		case <-a.requirementsRelease:
		case <-ctx.Done():
			return Requirements{}, ctx.Err()
		}
	}
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return Requirements{}, err
	}
	return Requirements{Model: payload.Model, AcceleratorRequired: true}, nil
}
// The in-process admission fixture has no separate request allocation. This
// zero-byte proof is test-only; production adapters must obtain their own
// identity-bound runtime observation or use the verified initialized-pool
// fallback.
func (a *admissionLifecycleAdapter) ObserveRequestVRAMIncrement(_ context.Context, target Target, request domain.WorkloadRequest, requirements Requirements) (RequestVRAMIncrementObservation, error) {
	return RequestVRAMIncrementObservation{
		TargetID: target.ID, AcceleratorID: target.AcceleratorID, RequestID: request.ID,
		Model: requirements.Model, ProfileID: target.ActiveRuntimeProfile,
		RuntimeIdentity: residencyCapacityIdentity(target), CapabilityVersion: target.CapabilityVersion,
		CapabilityRevision: target.CapabilityRevision, ModelFingerprint: target.ModelFingerprint,
		ContextTokens: requirements.ContextTokens, Source: "runtime:test-no-additional-allocation",
		Verified: true, ObservedAt: time.Now().UTC(),
	}, nil
}
func (a *admissionLifecycleAdapter) Start(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	if a.startEntered != nil {
		a.startOnce.Do(func() { close(a.startEntered) })
		select {
		case <-a.startRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return a.MockAdapter.Start(ctx, req, plan, target)
}
func (a *admissionLifecycleAdapter) LoadModel(_ context.Context, _ Target, model string) error {
	a.mu.Lock()
	a.loaded[model] = true
	a.loads++
	a.mu.Unlock()
	return nil
}
func (a *admissionLifecycleAdapter) UnloadModel(_ context.Context, _ Target, model string) error {
	a.mu.Lock()
	delete(a.loaded, model)
	a.unloads++
	a.mu.Unlock()
	return nil
}
func (a *admissionLifecycleAdapter) SetLoaded(model string, loaded bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.loaded[model] = loaded
}
func (a *admissionLifecycleAdapter) Counts() (loads, unloads int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.loads, a.unloads
}
func (a *admissionLifecycleAdapter) ConfigureStartGate(entered, release chan struct{}) {
	a.startEntered = entered
	a.startRelease = release
}
func (a *admissionLifecycleAdapter) ConfigureRequirementsGate(entered, release chan struct{}) {
	a.requirementsEntered = entered
	a.requirementsRelease = release
}
func (a *admissionLifecycleAdapter) ObserveResidency(_ context.Context, target Target, model string) (ResidencyObservation, error) {
	a.mu.Lock()
	loaded := a.loaded[model]
	a.mu.Unlock()
	tier := domain.ResidencyColdDisk
	if loaded {
		tier = domain.ResidencyHotVRAM
	}
	return ResidencyObservation{TargetID: target.ID, Model: model, RuntimeIdentity: residencyCapacityIdentity(target), Tier: tier, FencingToken: 1}, nil
}
func (a *admissionLifecycleAdapter) ObserveResidencyExpected(ctx context.Context, target Target, model string, _ domain.ResidencyTier) (ResidencyObservation, error) {
	return a.ObserveResidency(ctx, target, model)
}

type protectedLifecycleAdapter struct {
	*MockAdapter
	unloads int
}

func (a *protectedLifecycleAdapter) LoadModel(context.Context, Target, string) error { return nil }
func (a *protectedLifecycleAdapter) UnloadModel(context.Context, Target, string) error {
	a.unloads++
	return nil
}

func TestReclaimForeignTargetsProtectsActiveQueuedPinnedManualAndOffResidents(t *testing.T) {
	for _, tc := range []struct {
		name      string
		policy    domain.ResidencyPolicyMode
		active    bool
		queued    bool
		counter   bool
		wantError bool
	}{
		{name: "active", active: true},
		{name: "queued", queued: true, wantError: true},
		{name: "queue-counter", counter: true},
		{name: "pinned", policy: domain.ResidencyPinned, wantError: true},
		{name: "manual", policy: domain.ResidencyManual, wantError: true},
		{name: "off", policy: domain.ResidencyOff, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			backing := store.NewMemoryStore()
			mgr := NewManager(quietLogger(), backing, time.Second)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/free" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			adapter := &observedComfyReclaimer{HTTPAdapter: NewHTTPAdapter("comfy", "comfy", server.Client())}
			mgr.RegisterAdapter(adapter)
			selected := Target{ID: "selected-reclaim", Adapter: "comfy", AcceleratorID: "reclaim-gpu", Enabled: true}
			foreign := Target{ID: "foreign-reclaim", Adapter: "comfy", RuntimeProtocol: managedComfyProtocol, CapabilityVersion: "managed-comfy-v1", CapabilityRevision: domain.CapabilityContractVersion, AcceleratorID: "reclaim-gpu", ResidencyPolicy: tc.policy, SupportsAcceleratorReclaim: true, Endpoint: server.URL, Enabled: true}
			mgr.RegisterTarget(selected)
			mgr.RegisterTarget(foreign)
			if tc.active {
				mgr.placementMu.Lock()
				mgr.targetActive[foreign.ID] = 1
				mgr.placementMu.Unlock()
			}
			if tc.queued {
				queued := &domain.Workload{Request: domain.WorkloadRequest{ID: "queued-reclaim", Adapter: "comfy"}, Status: domain.WorkloadQueued, Plan: &domain.ExecutionPlan{TargetID: foreign.ID}}
				if _, _, err := backing.CreateWorkload(ctx, queued); err != nil {
					t.Fatal(err)
				}
			}
			if tc.counter {
				foreign.QueueRunning = 1
				foreign.QueuePending = 1
				mgr.RegisterTarget(foreign)
			}
			_, err := mgr.reclaimForeignTargets(ctx, selected, &domain.Workload{Request: domain.WorkloadRequest{ID: "request", OwnerID: "owner"}}, nil)
			if (err != nil) != tc.wantError || server.URL == "" {
				t.Fatalf("managed Comfy protection mismatch: err=%v wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestStaleRuntimeQueueCountersDoNotBlockDemandEviction(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	target := Target{ID: "router", Adapter: "mock", AcceleratorID: "node-gpu0", Slots: 4, Enabled: true, QueueRunning: 1}
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(target)
	resident := &domain.ModelResidency{TargetID: target.ID, Model: "old", AcceleratorID: target.AcceleratorID, Policy: domain.ResidencyAuto, DesiredTier: domain.ResidencyHotVRAM, ObservedTier: domain.ResidencyHotVRAM}
	if _, err := backing.UpsertModelResidency(ctx, resident); err != nil {
		t.Fatal(err)
	}
	registered := mgr.targetByID(target.ID)
	if candidates, _, err := mgr.evictionCandidates(ctx, registered, "new", 1); err != nil || len(candidates) != 0 {
		t.Fatalf("fresh busy counters must protect residents: candidates=%d err=%v", len(candidates), err)
	}
	mgr.placementMu.Lock()
	mgr.targetReleasedAt[target.ID] = time.Now().Add(time.Second)
	mgr.placementMu.Unlock()
	if candidates, _, err := mgr.evictionCandidates(ctx, registered, "new", 1); err != nil || len(candidates) != 1 {
		t.Fatalf("counters advertised before the last release still blocked eviction: candidates=%d err=%v", len(candidates), err)
	}
}

// A failed admission attempt records its eviction/load transitions under its
// lease. The retry runs under a new lease and must get fresh transition keys;
// replaying the first attempt's keys was refused by the store ("no exact
// allocated lease origin") on every retry until the request's deadline.
func TestDemandLoadRetryAfterFailedAttemptUsesFreshTransitionKeys(t *testing.T) {
	var mu sync.Mutex
	resident := map[string]bool{"small": true, "large": false}
	failLarge := true
	var events []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/models":
			data := []map[string]string{}
			for model, loaded := range resident {
				status := "unloaded"
				if loaded {
					status = "loaded"
				}
				data = append(data, map[string]string{"id": model, "status": status})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case "/models/unload":
			var body struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for model := range resident {
				resident[model] = false
			}
			events = append(events, "unload")
			w.WriteHeader(http.StatusOK)
		case "/models/load":
			var body struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			events = append(events, "load:"+body.Model)
			if body.Model == "large" && failLarge {
				failLarge = false
				http.Error(w, "node briefly not ready", http.StatusServiceUnavailable)
				return
			}
			for model := range resident {
				resident[model] = false
			}
			resident[body.Model] = true
			w.WriteHeader(http.StatusOK)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": "ok"}}}})
		}
	}))
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterTarget(Target{ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"}, ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, Enabled: true})
	workload, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"large","messages":[{}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if workload.Status != domain.WorkloadWaiting {
		t.Fatalf("first attempt should fail and wait: %+v", workload)
	}
	retry, err := backing.GetWorkload(context.Background(), workload.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	retry.TargetRetryAfter = nil
	mgr.tryAdmit(context.Background(), retry)
	after, err := backing.GetWorkload(context.Background(), workload.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if after.Status == domain.WorkloadWaiting || !resident["large"] {
		t.Fatalf("retry did not load the model: status=%s blocker=%q events=%v resident=%v", after.Status, after.Decision.Blocker, events, resident)
	}
}

// A model the runtime cannot load (live: llama.cpp "unknown model
// architecture") must not be retried on every admission pass: each attempt
// made the node briefly not-ready for all other work. Definite load failures
// back off exponentially, and after three in a row the request fails with
// the reason instead of waiting out its deadline.
func TestModelLoadFailuresBackOffThenFailFast(t *testing.T) {
	base, max := modelLoadBackoffBase, modelLoadBackoffMax
	modelLoadBackoffBase, modelLoadBackoffMax = 40*time.Millisecond, time.Second
	defer func() { modelLoadBackoffBase, modelLoadBackoffMax = base, max }()
	backing := store.NewMemoryStore()
	_, err := backing.UpsertNode(context.Background(), &domain.Node{ID: "node-1", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true}, Accelerators: []domain.Accelerator{{ID: "gpu-1", VRAMTotalMB: 16_000, VRAMFreeMB: 16_000}}})
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetNodeStore(backing)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	target := Target{ID: "node-1-router", Adapter: "llamacpp", Endpoint: "http://controller-must-not-call.invalid", AcceleratorID: "gpu-1", Models: []string{"broken"}, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, MaxAcceleratorsPerWorkload: 1}, SupportsModelLifecycle: true, MaxResidentModels: 1, Slots: 1, Enabled: true}
	mgr.RegisterTarget(target)
	loads := 0
	mgr.SetNodeControl(func(_ context.Context, _, command string, _ map[string]any, _ string) (map[string]any, error) {
		if command == "load_model" {
			loads++
		}
		return nil, fmt.Errorf("node command failed: model failed to load in the runtime")
	})
	workload, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", QueuePolicy: domain.QueueWait, Payload: json.RawMessage(`{"model":"broken","messages":[{"role":"user","content":"hi"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	pass := func() *domain.Workload {
		t.Helper()
		row, _ := backing.GetWorkload(context.Background(), workload.Request.ID)
		if row.Status == domain.WorkloadWaiting {
			row.TargetRetryAfter = nil
			mgr.tryAdmit(context.Background(), row)
			row, _ = backing.GetWorkload(context.Background(), workload.Request.ID)
		}
		return row
	}
	first, _ := backing.GetWorkload(context.Background(), workload.Request.ID)
	if loads != 1 || first.Status != domain.WorkloadWaiting || !strings.Contains(strings.Join(first.Decision.Alternatives, " "), "model failed to load in the runtime") {
		t.Fatalf("first attempt: loads=%d status=%s alternatives=%v", loads, first.Status, first.Decision.Alternatives)
	}
	if row := pass(); loads != 1 || row.Status != domain.WorkloadWaiting || row.Decision.BlockerCode != domain.BlockerTransitionBusy {
		t.Fatalf("inside the backoff the load was retried or the request ended: loads=%d row=%+v", loads, row.Decision)
	}
	time.Sleep(50 * time.Millisecond)
	pass() // second failure, backoff 80 ms
	time.Sleep(90 * time.Millisecond)
	pass() // third failure
	final := pass()
	if loads != 3 {
		t.Fatalf("loads=%d, want 3 (one per expired backoff)", loads)
	}
	if final.Status != domain.WorkloadRejected || !strings.Contains(final.Error, "failed to load 3 time(s)") || final.Decision.BlockerCode != domain.BlockerRuntimeUnsupported {
		t.Fatalf("request did not fail fast after 3 failures: status=%s error=%q decision=%+v", final.Status, final.Error, final.Decision)
	}
	upgraded := target
	upgraded.CapabilityVersion = "runtime-v2"
	if _, _, fenced := mgr.modelLoadFenced(upgraded, "broken"); fenced {
		t.Fatal("runtime change did not lift the fence")
	}
}

// An LLM router's busy counters lag behind its requests. Counters from before
// the LB's last release must not stop a reclaim (Comfy then ran beside a
// still-loaded model and ran out of memory); fresh ones mean untracked work
// and must refuse admission rather than skip the target silently.
func TestReclaimForeignLifecycleTargetHonoursOnlyFreshBusyCounters(t *testing.T) {
	for _, stale := range []bool{false, true} {
		ctx := context.Background()
		mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
		mgr.RegisterAdapter(newAdmissionLifecycleAdapter("router-mock"))
		selected := Target{ID: "comfy", Adapter: "comfy", AcceleratorID: "shared-gpu", Enabled: true}
		foreign := Target{ID: "router", Adapter: "router-mock", AcceleratorID: "shared-gpu", SupportsModelLifecycle: true, Enabled: true, QueueRunning: 1}
		mgr.RegisterTarget(selected)
		mgr.RegisterTarget(foreign)
		if stale {
			mgr.placementMu.Lock()
			mgr.targetReleasedAt[foreign.ID] = time.Now().Add(time.Second)
			mgr.placementMu.Unlock()
		}
		_, err := mgr.reclaimForeignTargets(ctx, selected, &domain.Workload{Request: domain.WorkloadRequest{ID: "image", OwnerID: "owner"}}, nil)
		busy := err != nil && strings.Contains(err.Error(), "reports running or queued work")
		if busy == stale {
			t.Fatalf("stale=%t: err=%v", stale, err)
		}
	}
}
