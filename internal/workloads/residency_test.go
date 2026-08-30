package workloads

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

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
	mgr.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", comfy.Client()))
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", ollama.Client()))
	mgr.RegisterTarget(Target{ID: "comfy", Adapter: "comfy", Endpoint: comfy.URL, AcceleratorID: "gpu-0", Slots: 1, SupportsAcceleratorReclaim: true, Enabled: true})
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
	mgr.RegisterTarget(Target{ID: "node-1-ollama", Adapter: "llamacpp", Endpoint: "http://controller-must-not-call.invalid", AcceleratorID: "gpu-1", Models: []string{"model"}, RuntimeArgs: []string{"ollama"}, SupportsModelLifecycle: true, MaxResidentModels: 1, Slots: 1, Enabled: true})
	var nodeID, command string
	var args map[string]any
	mgr.SetNodeControl(func(_ context.Context, gotNode, gotCommand string, gotArgs map[string]any, _ string) (map[string]any, error) {
		nodeID, command, args = gotNode, gotCommand, gotArgs
		return map[string]any{"resident": true}, nil
	})
	residency, _, err := mgr.ConfigureResidency(context.Background(), "node-1-ollama", "model", domain.ResidencyHotVRAM, domain.ResidencyAuto, "operator", "node-load")
	if err != nil {
		t.Fatal(err)
	}
	if nodeID != "node-1" || command != "load_model" || args["target_id"] != "node-1-ollama" || args["model"] != "model" || residency.ObservedTier != domain.ResidencyHotVRAM {
		t.Fatalf("transition bypassed node control: node=%q command=%q args=%+v residency=%+v", nodeID, command, args, residency)
	}
}

func TestDemandLoadEvictsLeastProtectedResidentUnderOneLease(t *testing.T) {
	fixture, backend := newRouterFixture(t, "small")
	defer backend.Close()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetResidencyOptions(ResidencyOptions{Enabled: true, DefaultMinResidency: 0, TransitionTimeout: time.Second})
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterTarget(Target{ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"small", "large"}, ResidentModels: []string{"small"}, SupportsModelLifecycle: true, MaxResidentModels: 1, ResidencyPolicy: domain.ResidencyAuto, Enabled: true})

	workload, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"large","messages":[{"role":"user","content":"hello"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	finished, err := mgr.Wait(context.Background(), workload.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("demand-loaded workload: %+v err=%v", finished, err)
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
	transition := &domain.ResidencyTransition{ID: "interrupted", IdempotencyKey: "load-once", TargetID: "router", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Status: domain.ResidencyTransitionRunning, CreatedAt: now, StartedAt: &now}
	_, _, _ = backing.CreateResidencyTransition(context.Background(), transition)

	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	mgr.RegisterTarget(Target{ID: "router", Adapter: "llamacpp", Endpoint: "http://unused.invalid", Models: []string{"model"}, ResidentModels: []string{"model"}, SupportsModelLifecycle: true, Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	rows, err := backing.ListResidencyTransitions(context.Background(), 10)
	if err != nil || len(rows) != 1 || rows[0].Status != domain.ResidencyTransitionSucceeded {
		t.Fatalf("restart recovery did not reconcile observed state: rows=%+v err=%v", rows, err)
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
