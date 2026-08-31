package workloads

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestComfyCatalogIsNotClaimedAsResidentVRAM(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterTarget(Target{
		ID: "comfy", Adapter: "comfy", Models: []string{"video.safetensors", "vae.safetensors"},
		SupportsAcceleratorReclaim: true, Enabled: true,
	})
	targets := mgr.Targets()
	if len(targets) != 1 || len(targets[0].ResidentModels) != 0 {
		t.Fatalf("Comfy model catalog was incorrectly marked resident: %+v", targets)
	}
}

func TestRuntimeRefreshPreservesMeasuredCapacityAndLearnedEnvelope(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterTarget(Target{
		ID: "node-short", Adapter: "llamacpp", AcceleratorID: "node-gpu0",
		CapabilityVersion: "ollama-v1", AcceleratorVRAMMB: 10240,
		StandaloneVRAMMB: 3072, WorkloadClass: "llm", PredictedSlowdown: 1.1,
		ContextLimit: 2048, Slots: 2, Enabled: true,
	})
	// A periodic runtime advertisement does not carry scheduler learning or
	// physical telemetry. Those values must not disappear.
	mgr.RegisterTarget(Target{
		ID: "node-short", Adapter: "llamacpp", AcceleratorID: "node-gpu0",
		CapabilityVersion: "ollama-v1", ContextLimit: 2048, Slots: 2, Enabled: true,
	})
	target := mgr.Targets()[0]
	if target.AcceleratorVRAMMB != 10240 || target.StandaloneVRAMMB != 3072 || target.WorkloadClass != "llm" || target.PredictedSlowdown != 1.1 {
		t.Fatalf("runtime refresh erased scheduler evidence: %+v", target)
	}

	mgr.UpdateAcceleratorCapacity("node-gpu0", 12288)
	target = mgr.Targets()[0]
	if target.AcceleratorVRAMMB != 12288 {
		t.Fatalf("live accelerator capacity was not applied: %+v", target)
	}
}

func TestCapacityArrivalReappliesPersistedSharingPolicy(t *testing.T) {
	backing := store.NewMemoryStore()
	_, err := backing.UpsertTargetPolicyOverride(context.Background(), &domain.TargetPolicyOverride{
		TargetID: "node-short", Enabled: true, SharingEnabled: true, GuardedExploration: true,
		VRAMReserveMB: 1024, MaxSlowdown: 1.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(quietLogger(), backing, time.Second)
	manager.RegisterTarget(Target{ID: "node-short", Adapter: "llamacpp", AcceleratorID: "node-gpu0", Enabled: true})
	if manager.Targets()[0].SharingEnabled {
		t.Fatal("sharing policy should wait for a physical capacity envelope")
	}
	manager.UpdateAcceleratorCapacity("node-gpu0", 10240)
	target := manager.Targets()[0]
	if !target.SharingEnabled || !target.GuardedExploration || target.VRAMReserveMB != 1024 || target.MaxSlowdown != 1.5 {
		t.Fatalf("persisted policy was not restored after telemetry arrived: %+v", target)
	}
}

func TestCapabilityChangeInvalidatesOldRuntimeEnvelope(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterTarget(Target{
		ID: "route", Adapter: "llamacpp", AcceleratorID: "gpu0", CapabilityVersion: "v1",
		StandaloneVRAMMB: 5000, StandaloneVRAMSource: "learned-total", Enabled: true,
	})
	mgr.RegisterTarget(Target{
		ID: "route", Adapter: "llamacpp", AcceleratorID: "gpu0", CapabilityVersion: "v2", Enabled: true,
	})
	target := mgr.Targets()[0]
	if target.StandaloneVRAMMB != 0 || target.StandaloneVRAMSource != "" || target.StandaloneVRAMVerified {
		t.Fatalf("new runtime capability inherited a stale envelope: %+v", target)
	}
}

func TestNodeTargetReconciliationRemovesOnlyInactiveStaleRoutes(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterTarget(Target{ID: "node-a-old", Adapter: "llamacpp", Enabled: true})
	mgr.RegisterTarget(Target{ID: "node-a-current", Adapter: "llamacpp", Enabled: true})
	mgr.RegisterTarget(Target{ID: "node-b-route", Adapter: "llamacpp", Enabled: true})
	mgr.RegisterTarget(Target{ID: "static-route", Adapter: "llamacpp", Enabled: true})

	mgr.ReconcileNodeTargets("node-a", map[string]struct{}{"node-a-current": {}})
	ids := map[string]bool{}
	for _, target := range mgr.Targets() {
		ids[target.ID] = true
	}
	if ids["node-a-old"] || !ids["node-a-current"] || !ids["node-b-route"] || !ids["static-route"] {
		t.Fatalf("unexpected reconciled targets: %+v", ids)
	}
}

func TestLLMAndComfyShareOnePhysicalLease(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/chat/completions":
			time.Sleep(150 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "chat-1", "choices": []any{}})
		case r.URL.Path == "/prompt":
			_ = json.NewEncoder(w).Encode(map[string]any{"prompt_id": "backend-prompt"})
		case r.URL.Path == "/history/backend-prompt":
			_ = json.NewEncoder(w).Encode(map[string]any{"backend-prompt": map[string]any{"status": map[string]any{"completed": true, "status_str": "success"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), s, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", backend.Client()))
	mgr.RegisterTarget(Target{ID: "llm", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"model"}, Enabled: true})
	mgr.RegisterTarget(Target{ID: "image", Adapter: "comfy", Endpoint: backend.URL, AcceleratorID: "gpu-0", Enabled: true})
	mgr.Start(ctx)

	llm, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hi"}]}`)})
	if err != nil || llm.Status != domain.WorkloadRunning {
		t.Fatalf("LLM admission: %+v err=%v", llm, err)
	}
	comfy, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "comfy", Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"KSampler"}}}`), Recoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	if comfy.Status != domain.WorkloadWaiting {
		t.Fatalf("Comfy double-booked the LLM accelerator: %s", comfy.Status)
	}
	if _, err := mgr.Wait(context.Background(), llm.Request.ID); err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, comfy.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("Comfy did not run after release: %+v err=%v", finished, err)
	}
}

func TestComfyPromptMappingTracksTargetAndBackendWithoutOverwriteRace(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/prompt":
			_ = json.NewEncoder(w).Encode(map[string]any{"prompt_id": "backend-sticky"})
		case "/history/backend-sticky":
			_ = json.NewEncoder(w).Encode(map[string]any{"backend-sticky": map[string]any{"status": map[string]any{"completed": true, "status_str": "success"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", backend.Client()))
	mgr.RegisterTarget(Target{ID: "comfy-gpu", Adapter: "comfy", Endpoint: backend.URL, AcceleratorID: "gpu-0", Enabled: true})
	mgr.Start(ctx)
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: "public-sticky", Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"KSampler"}}}`), Recoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	if _, err := mgr.Wait(waitCtx, row.Request.ID); err != nil {
		t.Fatal(err)
	}
	// This is the API's later client-id write in the race-prone ordering.
	if err := backing.SavePromptMapping(ctx, &domain.PromptMapping{PublicPromptID: "public-sticky", WorkloadID: row.Request.ID, ClientID: "client-a"}); err != nil {
		t.Fatal(err)
	}
	mapping, err := backing.GetPromptMapping(ctx, "public-sticky")
	if err != nil || mapping.TargetID != "comfy-gpu" || mapping.BackendPromptID != "backend-sticky" || mapping.ClientID != "client-a" {
		t.Fatalf("sticky mapping was incomplete or overwritten: %+v err=%v", mapping, err)
	}
}

func TestComfyStagesCentralInputsAndCollectsOutputs(t *testing.T) {
	artifactStore, err := artifacts.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input, err := artifactStore.Put(context.Background(), "owner", "", "input.png", "image/png", strings.NewReader("input-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	var staged bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload/image":
			file, header, err := r.FormFile("image")
			if err != nil {
				t.Errorf("staged upload: %v", err)
				return
			}
			data, _ := io.ReadAll(file)
			file.Close()
			staged = header.Filename == input.ID && string(data) == "input-bytes"
			_ = json.NewEncoder(w).Encode(map[string]string{"name": input.ID})
		case "/prompt":
			if !staged {
				t.Error("prompt submitted before central input staging")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"prompt_id": "backend-output"})
		case "/history/backend-output":
			_ = json.NewEncoder(w).Encode(map[string]any{"backend-output": map[string]any{"status": map[string]any{"completed": true, "status_str": "success"}, "outputs": map[string]any{"9": map[string]any{"images": []any{map[string]any{"filename": "result.png", "subfolder": "", "type": "output"}}}}}})
		case "/view":
			w.Header().Set("Content-Type", "image/png")
			_, _ = io.WriteString(w, "output-bytes")
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	adapter := NewHTTPAdapter("comfy", "comfy", backend.Client())
	adapter.SetArtifactStore(artifactStore)
	manager.RegisterAdapter(adapter)
	manager.RegisterTarget(Target{ID: "comfy", Adapter: "comfy", Endpoint: backend.URL, AcceleratorID: "gpu-0", Enabled: true})
	manager.Start(ctx)
	row, _, err := manager.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: "public-output", ArtifactRefs: []string{input.ID}, Payload: json.RawMessage(`{"prompt":{"1":{"inputs":{"image":"` + input.ID + `"},"class_type":"LoadImage"}}}`), Recoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	finished, err := manager.Wait(waitCtx, row.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded || len(finished.OutputRefs) != 1 || !strings.Contains(string(finished.InlineOutput), finished.OutputRefs[0]) {
		t.Fatalf("Comfy output was not centralized and rewritten: %+v err=%v", finished, err)
	}
	metadata, reader, err := artifactStore.Open(ctx, finished.OutputRefs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, _ := io.ReadAll(reader)
	if metadata.OwnerID != "owner" || metadata.WorkloadID != row.Request.ID || string(data) != "output-bytes" {
		t.Fatalf("central output artifact mismatch: %+v data=%q", metadata, data)
	}
}

func TestCompatibilityAndEgressFilterProduceHonestWaitingDecision(t *testing.T) {
	s := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), s, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", nil))
	mgr.RegisterTarget(Target{ID: "cloud-comfy", Adapter: "comfy", Endpoint: "https://example.invalid", Cloud: true, Models: []string{"base.safetensors"}, CustomNodes: []string{"KSampler"}, Enabled: true})
	row, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "u", Adapter: "comfy", Egress: domain.EgressLocalOnly, Payload: json.RawMessage(`{"prompt":{"1":{}},"model":"missing.safetensors","required_custom_nodes":["PrivateNode"]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != domain.WorkloadWaiting || row.Decision.Admitted || len(row.Decision.Alternatives) == 0 {
		t.Fatalf("expected explained waiting decision, got %+v", row)
	}
}

func TestLLMAdapterUsesBoundedContextAndStripsGovernorMetadata(t *testing.T) {
	var forwarded map[string]any
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&forwarded); err != nil {
			t.Errorf("decode backend request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "chat-1", "choices": []any{}})
	}))
	defer backend.Close()

	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	req := domain.WorkloadRequest{
		Payload: json.RawMessage(`{"model":"same-model","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":1000,"governor":{"context_tokens":3000}}`),
		Bounds:  domain.WorkloadBounds{ContextTokens: 3000, MaxOutput: 1000},
	}
	requirements, err := adapter.Requirements(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if requirements.Model != "same-model" || requirements.ContextTokens != 4000 {
		t.Fatalf("unexpected requirements: %+v", requirements)
	}
	if _, err := adapter.Start(context.Background(), req, &domain.ExecutionPlan{}, Target{ID: "llm", Endpoint: backend.URL}); err != nil {
		t.Fatal(err)
	}
	if _, exists := forwarded["governor"]; exists {
		t.Fatalf("private governor metadata leaked to backend: %+v", forwarded)
	}
	if stream, ok := forwarded["stream"].(bool); !ok || stream {
		t.Fatalf("backend execution should be non-streaming: %+v", forwarded)
	}
}

func TestLocalLLMAsyncExecutionIsObservableAndCancellable(t *testing.T) {
	request := domain.WorkloadRequest{Payload: json.RawMessage(`{"model":"same-model","messages":[{"role":"user","content":"hello"}]}`)}

	cancelStarted := make(chan struct{})
	backendCancelled := make(chan struct{})
	cancelBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(cancelStarted)
		flusher, _ := w.(http.Flusher)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				close(backendCancelled)
				return
			case <-ticker.C:
				_, _ = w.Write([]byte(" "))
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
	}))
	defer cancelBackend.Close()
	cancelAdapter := NewHTTPAdapter("llamacpp", "llama", cancelBackend.Client())
	handle, err := cancelAdapter.StartAsync(context.Background(), request, nil, Target{ID: "llm", Endpoint: cancelBackend.URL})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelStarted:
	case <-time.After(time.Second):
		t.Fatal("async backend did not start")
	}
	observation, err := cancelAdapter.Observe(context.Background(), request, nil, handle, Target{})
	if err != nil || observation.Status != domain.WorkloadRunning {
		t.Fatalf("in-flight LLM was not observable: %+v err=%v", observation, err)
	}
	cancelCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cancelAdapter.Cancel(cancelCtx, handle, Target{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backendCancelled:
	case <-time.After(time.Second):
		t.Fatal("async cancellation did not reach the backend")
	}

	// A separate run proves completion output and performance survive polling.
	completeStarted := make(chan struct{})
	released := make(chan struct{})
	completeBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(completeStarted)
		<-released
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "chat-async", "usage": map[string]int{"prompt_tokens": 2, "completion_tokens": 1}})
	}))
	defer completeBackend.Close()
	completeAdapter := NewHTTPAdapter("llamacpp", "llama", completeBackend.Client())
	handle, err = completeAdapter.StartAsync(context.Background(), request, nil, Target{ID: "llm", Endpoint: completeBackend.URL})
	if err != nil {
		t.Fatal(err)
	}
	<-completeStarted
	close(released)
	deadline := time.Now().Add(time.Second)
	for {
		observation, err = completeAdapter.Observe(context.Background(), request, nil, handle, Target{})
		if err != nil {
			t.Fatal(err)
		}
		if observation.Status == domain.WorkloadSucceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("async completion was not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	output, _, err := completeAdapter.CollectOutputs(context.Background(), request, nil, handle, Target{})
	if err != nil || !strings.Contains(string(output), "chat-async") || handle.Performance == nil {
		t.Fatalf("async output/performance was lost: output=%s handle=%+v err=%v", output, handle, err)
	}
}

func TestBuiltInAdaptersRejectUnimplementedDisruptionPromises(t *testing.T) {
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	manager.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	manager.RegisterAdapter(NewHTTPAdapter("openrouter", "openrouter", nil))
	base := domain.WorkloadRequest{OwnerID: "owner", Payload: json.RawMessage(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`)}

	checkpoint := base
	checkpoint.Adapter = "llamacpp"
	checkpoint.Disruption = domain.DisruptionCheckpointable
	if _, _, err := manager.Submit(context.Background(), checkpoint); err == nil || !strings.Contains(err.Error(), "checkpoint/resume") {
		t.Fatalf("unsupported checkpoint promise was accepted: %v", err)
	}

	cloudCancel := base
	cloudCancel.Adapter = "openrouter"
	cloudCancel.Disruption = domain.DisruptionCancelable
	if _, _, err := manager.Submit(context.Background(), cloudCancel); err == nil || !strings.Contains(err.Error(), "in-flight cancellation") {
		t.Fatalf("unsupported cloud cancellation promise was accepted: %v", err)
	}
}

func TestManagerPersistsFinalAsyncLLMPerformance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "chat-durable-performance",
			"usage": map[string]int{"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
		})
	}))
	defer backend.Close()

	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterTarget(Target{ID: "llm", Adapter: "llamacpp", Endpoint: backend.URL, Models: []string{"model"}, ResidentModels: []string{"model"}, ContextLimit: 4096, Slots: 1, CapacityVerified: true, Enabled: true})
	mgr.Start(ctx)
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hello"}]}`), Bounds: domain.WorkloadBounds{ContextTokens: 32, MaxOutput: 8}})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, row.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finished.Execution == nil || finished.Execution.Performance == nil {
		t.Fatalf("final async performance was not persisted: %+v", finished.Execution)
	}
	performance := finished.Execution.Performance
	if performance.PromptTokens != 8 || performance.CompletionTokens != 4 || performance.TotalTokens != 12 || performance.Source != "gateway_wall_clock_async" {
		t.Fatalf("unexpected durable performance: %+v", performance)
	}
}

func TestCompletedSlowdownUsesMeasuredStandaloneDuration(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	target := Target{ID: "llm", Adapter: "llamacpp", AcceleratorID: "gpu", CapabilityVersion: "runtime-v1", ModelFingerprint: "model-v1", WorkloadClass: "llm"}
	request := domain.WorkloadRequest{Adapter: "llamacpp", WorkloadType: "llm.chat", Bounds: domain.WorkloadBounds{ContextTokens: 512, MaxOutput: 32}}
	mgr.interferenceProfiles[standaloneRequestProfileKey(target, request)] = &domain.InterferenceProfile{Samples: 2, P95DurationMS: 1000}
	workload := &domain.Workload{Request: request}

	ratio := mgr.completedSlowdown(workload, target, &domain.ExecutionHandle{Performance: &domain.ExecutionPerformance{DurationMS: 1500}}, time.Now())
	if math.Abs(ratio-1.5) > .001 {
		t.Fatalf("expected 1.5x measured slowdown, got %f", ratio)
	}
	ratio = mgr.completedSlowdown(workload, target, &domain.ExecutionHandle{Performance: &domain.ExecutionPerformance{DurationMS: 750}}, time.Now())
	if ratio != 1 {
		t.Fatalf("faster shared execution must normalize to 1x, got %f", ratio)
	}
}

func TestComfyRequirementsAreInferredFromWorkflowLoadersAndNodeClasses(t *testing.T) {
	adapter := NewHTTPAdapter("comfy", "comfy", nil)
	payload := json.RawMessage(`{"prompt":{"1":{"class_type":"UNETLoader","inputs":{"unet_name":"z_image.safetensors"}},"2":{"class_type":"VAELoader","inputs":{"vae_name":"ae.safetensors"}},"3":{"class_type":"PrivateSampler","inputs":{"seed":1}}}}`)
	requirements, err := adapter.Requirements(context.Background(), domain.WorkloadRequest{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(requirements.RequiredModels, ",") != "ae.safetensors,z_image.safetensors" || strings.Join(requirements.CustomNodes, ",") != "PrivateSampler,UNETLoader,VAELoader" {
		t.Fatalf("workflow compatibility was not inferred: %+v", requirements)
	}

	backing := store.NewMemoryStore()
	manager := NewManager(quietLogger(), backing, time.Second)
	manager.RegisterAdapter(adapter)
	manager.RegisterTarget(Target{ID: "incomplete", Adapter: "comfy", Endpoint: "http://comfy.invalid", Models: []string{"z_image.safetensors"}, CustomNodes: []string{"PrivateSampler", "UNETLoader", "VAELoader"}, Enabled: true})
	row, _, err := manager.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "u", Adapter: "comfy", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != domain.WorkloadWaiting || !strings.Contains(row.Decision.Alternatives[0], "ae.safetensors") {
		t.Fatalf("backend missing a workflow artifact was admitted: %+v", row.Decision)
	}
}

func TestComfyTransformationPlanContainsMaterialChangeAndRequiresProof(t *testing.T) {
	var forwarded map[string]any
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&forwarded)
		_ = json.NewEncoder(w).Encode(map[string]string{"prompt_id": "transformed"})
	}))
	defer backend.Close()
	adapter := NewHTTPAdapter("comfy", "comfy", backend.Client())
	req := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"KSampler","inputs":{"steps":50}}}}`), Transformations: []string{"reduce_steps"}, TransformationParameters: json.RawMessage(`{"reduce_steps":{"max_steps":20}}`)}
	if err := adapter.Validate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Plan(context.Background(), req, Target{ID: "comfy", Endpoint: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan.Material), `"steps":20`) || !strings.Contains(string(req.Payload), `"steps":50`) {
		t.Fatalf("plan was not transformed immutably: request=%s plan=%s", req.Payload, plan.Material)
	}
	if _, err := adapter.Start(context.Background(), req, plan, Target{ID: "comfy", Endpoint: backend.URL}); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(forwarded)
	if !strings.Contains(string(encoded), `"steps":20`) {
		t.Fatalf("backend did not receive approved transformed material: %s", encoded)
	}
	unsafe := req
	unsafe.Transformations = []string{"checkpoint_chunks"}
	unsafe.TransformationParameters = nil
	if err := adapter.Validate(context.Background(), unsafe); err == nil || !strings.Contains(err.Error(), "checkpoint-safe") {
		t.Fatalf("unproven checkpoint chunking was accepted: %v", err)
	}
}

func TestContextBestFitPreservesLargeContextTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := NewMockAdapter()
	mock.Delay = 100 * time.Millisecond
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(mock)
	mgr.RegisterTarget(Target{ID: "short-context", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-0", ContextLimit: 4096, Slots: 4, Enabled: true})
	mgr.RegisterTarget(Target{ID: "long-context", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-1", ContextLimit: 32768, Slots: 1, Enabled: true})
	mgr.Start(ctx)

	short, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "mock", Payload: json.RawMessage(`{"kind":"short"}`), Bounds: domain.WorkloadBounds{ContextTokens: 2000, MaxOutput: 500}})
	if err != nil {
		t.Fatal(err)
	}
	if short.Plan == nil || short.Plan.TargetID != "short-context" {
		t.Fatalf("short request should use smallest sufficient context target: %+v", short)
	}
	if short.Decision.ContextLimit != 4096 || short.Decision.TargetSlots != 4 {
		t.Fatalf("admission should expose selected capacity: %+v", short.Decision)
	}

	long, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "mock", Payload: json.RawMessage(`{"kind":"long"}`), Bounds: domain.WorkloadBounds{ContextTokens: 16000, MaxOutput: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	if long.Plan == nil || long.Plan.TargetID != "long-context" {
		t.Fatalf("long request should only use the sufficient target: %+v", long)
	}
}

type profileLifecycleMock struct{ *MockAdapter }

func (a *profileLifecycleMock) Name() string { return "profile-mock" }
func (a *profileLifecycleMock) Requirements(_ context.Context, req domain.WorkloadRequest) (Requirements, error) {
	var body struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(req.Payload, &body)
	return Requirements{Model: body.Model, ContextTokens: req.Bounds.ContextTokens + req.Bounds.MaxOutput, AcceleratorRequired: true}, nil
}
func (a *profileLifecycleMock) LoadModel(context.Context, Target, string) error   { return nil }
func (a *profileLifecycleMock) UnloadModel(context.Context, Target, string) error { return nil }

func TestContextBestFitBeatsResidentLongProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	adapter := &profileLifecycleMock{MockAdapter: NewMockAdapter()}
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(Target{
		ID: "short-cold", Adapter: adapter.Name(), Endpoint: "in-process", AcceleratorID: "gpu-short",
		Models: []string{"same-model"}, ContextLimit: 2048, Slots: 2, SupportsModelLifecycle: true, Enabled: true,
	})
	mgr.RegisterTarget(Target{
		ID: "long-hot", Adapter: adapter.Name(), Endpoint: "in-process", AcceleratorID: "gpu-long",
		Models: []string{"same-model"}, ResidentModels: []string{"same-model"}, ContextLimit: 8192, Slots: 1, SupportsModelLifecycle: true, Enabled: true,
	})
	mgr.Start(ctx)

	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{
		OwnerID: "owner", Adapter: adapter.Name(), Payload: json.RawMessage(`{"model":"same-model"}`),
		Bounds: domain.WorkloadBounds{ContextTokens: 512, MaxOutput: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Plan == nil || row.Plan.TargetID != "short-cold" {
		t.Fatalf("resident long-context route stole a short request: %+v", row)
	}
}

func TestOneRuntimeUsesConfiguredSlotsUnderOneAcceleratorLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := NewMockAdapter()
	mock.Delay = 200 * time.Millisecond
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(mock)
	mgr.RegisterTarget(Target{ID: "multi-slot", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-0", ContextLimit: 8192, Slots: 2, Enabled: true})
	mgr.Start(ctx)

	first := submitMock(t, ctx, mgr, "first", "")
	second := submitMock(t, ctx, mgr, "second", "")
	third := submitMock(t, ctx, mgr, "third", "")
	if first.Status != domain.WorkloadRunning || second.Status != domain.WorkloadRunning {
		t.Fatalf("two configured slots should run together: first=%s second=%s", first.Status, second.Status)
	}
	if third.Status != domain.WorkloadWaiting || !containsString(third.Decision.Alternatives, "multi-slot: all execution slots are busy") {
		t.Fatalf("third request should wait on the slot limit: %+v", third)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, third.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("waiting request did not use a released slot: %+v err=%v", finished, err)
	}
}

func TestPrincipalConcurrencyLimitQueuesUntilEarlierWorkFinishes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := NewMockAdapter()
	mock.Delay = 150 * time.Millisecond
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(mock)
	mgr.RegisterTarget(Target{ID: "two-slot", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-0", Slots: 2, Enabled: true})
	mgr.Start(ctx)

	request := func(item string) domain.WorkloadRequest {
		return domain.WorkloadRequest{OwnerID: "owner", PrincipalID: "principal", Adapter: "mock", ItemID: item, Payload: json.RawMessage(`{"ok":true}`), ConcurrencyLimit: 1}
	}
	first, _, err := mgr.Submit(ctx, request("first"))
	if err != nil || first.Status != domain.WorkloadRunning {
		t.Fatalf("first admission: %+v err=%v", first, err)
	}
	second, _, err := mgr.Submit(ctx, request("second"))
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != domain.WorkloadWaiting || second.Decision.Blocker != "principal concurrency limit 1 reached" {
		t.Fatalf("second job bypassed principal concurrency limit: %+v", second)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, second.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("queued principal job did not run after release: %+v err=%v", finished, err)
	}
}

func TestCloudBudgetReservationPreventsBudgetEscape(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(Target{ID: "cloud", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "virtual-cloud", Slots: 2, Cloud: true, Enabled: true, InputCentsPerMTok: 1, OutputCentsPerMTok: 1})
	mgr.Start(ctx)

	request := func(item string) domain.WorkloadRequest {
		return domain.WorkloadRequest{OwnerID: "owner", PrincipalID: "principal", Adapter: "mock", ItemID: item, Payload: json.RawMessage(`{"ok":true}`), Bounds: domain.WorkloadBounds{ContextTokens: 100_000}, Egress: domain.EgressAllowed, BudgetLimitCents: 1}
	}
	first, _, err := mgr.Submit(ctx, request("first"))
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	if finished, err := mgr.Wait(waitCtx, first.Request.ID); err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("first cloud workload: %+v err=%v", finished, err)
	}

	second, _, err := mgr.Submit(ctx, request("second"))
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != domain.WorkloadWaiting || second.Decision.Blocker != "cloud: principal cloud budget exhausted" {
		t.Fatalf("second workload escaped budget: %+v", second)
	}
	reservations, err := backing.ListBudgetReservations(ctx, "principal")
	if err != nil || len(reservations) != 1 || reservations[0].Status != domain.BudgetSettled || reservations[0].ActualCents != 1 {
		t.Fatalf("unexpected durable budget ledger: %+v err=%v", reservations, err)
	}
}

func TestOpenRouterRateLimitFallsBackOnceWithoutRetryStorm(t *testing.T) {
	var limitedCalls, fallbackCalls int
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limitedCalls++
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer limited.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "fallback-result", "choices": []any{}})
	}))
	defer fallback.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("openrouter", "openrouter", limited.Client()))
	mgr.RegisterTarget(Target{ID: "a-limited", Adapter: "openrouter", Endpoint: limited.URL, AcceleratorID: "cloud-a", Models: []string{"allowed-model"}, Cloud: true, Enabled: true, InputCentsPerMTok: 1, OutputCentsPerMTok: 1})
	mgr.RegisterTarget(Target{ID: "b-fallback", Adapter: "openrouter", Endpoint: fallback.URL, AcceleratorID: "cloud-b", Models: []string{"allowed-model"}, Cloud: true, Enabled: true, InputCentsPerMTok: 1, OutputCentsPerMTok: 1})
	mgr.Start(ctx)

	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", PrincipalID: "principal", Adapter: "openrouter", ItemID: "fallback", Payload: json.RawMessage(`{"model":"allowed-model","messages":[{"role":"user","content":"hello"}]}`), Bounds: domain.WorkloadBounds{ContextTokens: 100_000}, Egress: domain.EgressAllowed, BudgetLimitCents: 1, Recoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, row.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded || finished.Plan == nil || finished.Plan.TargetID != "b-fallback" {
		t.Fatalf("fallback did not succeed: %+v err=%v", finished, err)
	}
	if limitedCalls != 1 || fallbackCalls != 1 || finished.ExecutionAttempts != 2 {
		t.Fatalf("unexpected retry behavior: limited=%d fallback=%d attempts=%d", limitedCalls, fallbackCalls, finished.ExecutionAttempts)
	}
	var limitedTarget Target
	for _, target := range mgr.Targets() {
		if target.ID == "a-limited" {
			limitedTarget = target
		}
	}
	if limitedTarget.CircuitState != "open" || limitedTarget.CircuitOpenUntil == nil {
		t.Fatalf("rate-limited target circuit was not opened: %+v", limitedTarget)
	}
	reservations, _ := backing.ListBudgetReservations(ctx, "principal")
	if len(reservations) != 1 || reservations[0].ActualCents != 1 || reservations[0].Status != domain.BudgetSettled {
		t.Fatalf("fallback escaped or duplicated its budget reservation: %+v", reservations)
	}
}

func TestOpenRouterProviderIsPinnedAndActualUsageSettlesBudget(t *testing.T) {
	var forwarded map[string]any
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&forwarded)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "result", "choices": []any{}, "usage": map[string]int{"prompt_tokens": 1_000, "completion_tokens": 1_000}})
	}))
	defer backend.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("openrouter", "openrouter", backend.Client()))
	mgr.RegisterTarget(Target{ID: "pinned", Adapter: "openrouter", Endpoint: backend.URL, AcceleratorID: "cloud", Models: []string{"allowed"}, Provider: "provider-a", Cloud: true, Enabled: true, InputCentsPerMTok: 100, OutputCentsPerMTok: 100})
	mgr.Start(ctx)
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", PrincipalID: "principal", Adapter: "openrouter", Payload: json.RawMessage(`{"model":"allowed","provider":{"order":["untrusted"]},"messages":[{"role":"user","content":"hello"}]}`), Bounds: domain.WorkloadBounds{ContextTokens: 100_000}, Egress: domain.EgressAllowed, BudgetLimitCents: 10, Recoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, row.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded || finished.ActualCostCents != 1 {
		t.Fatalf("actual usage was not settled: %+v err=%v", finished, err)
	}
	provider, _ := forwarded["provider"].(map[string]any)
	order, _ := provider["order"].([]any)
	if len(order) != 1 || order[0] != "provider-a" || provider["allow_fallbacks"] != false {
		t.Fatalf("client bypassed provider pin: %+v", forwarded)
	}
	reservations, _ := backing.ListBudgetReservations(ctx, "principal")
	if len(reservations) != 1 || reservations[0].ReservedCents != 10 || reservations[0].ActualCents != 1 {
		t.Fatalf("budget did not move from conservative reservation to actual usage: %+v", reservations)
	}
}

func TestQuarantinedCloudRouteIsNotEligible(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("openrouter", "openrouter", nil))
	mgr.RegisterTarget(Target{ID: "quarantine", Adapter: "openrouter", Endpoint: "https://example.invalid", Models: []string{"model"}, Cloud: true, Quarantined: true, Enabled: true})
	row, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "owner", Adapter: "openrouter", Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hello"}]}`), Egress: domain.EgressAllowed})
	if err != nil || row.Status != domain.WorkloadWaiting || !strings.Contains(row.Decision.Blocker, "quarantined") {
		t.Fatalf("quarantined route was eligible: %+v err=%v", row, err)
	}
}

func TestCancelDoesNotRewriteTerminalWorkload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(Target{ID: "mock", Adapter: "mock", AcceleratorID: "gpu-0", Enabled: true})
	mgr.Start(ctx)
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"ok":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	if _, err := mgr.Wait(waitCtx, row.Request.ID); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Cancel(ctx, row.Request.ID, "owner", false); err != nil {
		t.Fatal(err)
	}
	after, err := mgr.Get(ctx, row.Request.ID)
	if err != nil || after.Status != domain.WorkloadSucceeded {
		t.Fatalf("terminal result was rewritten by cancellation: %+v err=%v", after, err)
	}
}

type cancellationRaceAdapter struct {
	*MockAdapter
	started             chan struct{}
	cancellationStarted chan struct{}
}

func newCancellationRaceAdapter() *cancellationRaceAdapter {
	return &cancellationRaceAdapter{
		MockAdapter:         NewMockAdapter(),
		started:             make(chan struct{}),
		cancellationStarted: make(chan struct{}),
	}
}

func (a *cancellationRaceAdapter) Name() string { return "cancel-race" }

func (a *cancellationRaceAdapter) Start(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, Target) (*domain.ExecutionHandle, error) {
	close(a.started)
	return &domain.ExecutionHandle{ExternalID: "cancel-race-backend", StartedAt: time.Now().UTC()}, nil
}

func (a *cancellationRaceAdapter) Observe(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (Observation, error) {
	select {
	case <-a.cancellationStarted:
		return Observation{Status: domain.WorkloadFailed, Error: "backend reported interrupt"}, nil
	default:
		return Observation{Status: domain.WorkloadRunning, Progress: .25}, nil
	}
}

func (a *cancellationRaceAdapter) Cancel(context.Context, *domain.ExecutionHandle, Target) error {
	close(a.cancellationStarted)
	// Keep cancellation in progress long enough for the observer to see the
	// backend's interrupt response and exercise the terminal-state race.
	time.Sleep(650 * time.Millisecond)
	return nil
}

func TestCancellationOwnsLeaseUntilBackendStopAndWinsObserverRace(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	adapter := newCancellationRaceAdapter()
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(Target{ID: "cancel-race-target", Adapter: adapter.Name(), AcceleratorID: "gpu-0", Enabled: true})
	mgr.Start(ctx)

	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: adapter.Name(), Payload: json.RawMessage(`{"ok":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-adapter.started:
	case <-time.After(time.Second):
		t.Fatal("execution did not start")
	}
	if err := mgr.Cancel(ctx, row.Request.ID, "owner", false); err != nil {
		t.Fatal(err)
	}
	after, err := mgr.Get(ctx, row.Request.ID)
	if err != nil || after.Status != domain.WorkloadCancelled {
		t.Fatalf("observer overwrote cancellation: %+v err=%v", after, err)
	}
	if target := mgr.targetByID("cancel-race-target"); target.Active != 0 {
		t.Fatalf("target lease remained active after confirmed backend stop: %+v", target)
	}
}

func TestFailFastSubmissionDoesNotBlockBehindResidencyTransition(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(Target{ID: "mock", Adapter: "mock", AcceleratorID: "gpu-0", Enabled: true})
	mgr.reconcileMu.Lock()
	defer mgr.reconcileMu.Unlock()

	started := time.Now()
	row, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{
		OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"ok":true}`), QueuePolicy: domain.QueueFailFast,
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("fail-fast submission blocked behind transition for %s", elapsed)
	}
	if row.Status != domain.WorkloadRejected || !strings.Contains(strings.Join(row.Decision.Alternatives, " "), "transition") {
		t.Fatalf("missing structured transition decision: %+v", row)
	}
}

func TestTransformationApprovalIsBoundToExactPlanAndCapabilities(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(Target{ID: "transform-target", Adapter: "mock", AcceleratorID: "gpu-0", CapabilityVersion: "cap-v1", Enabled: true})

	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"workflow":"immutable-v1"}`), TransformationPolicy: domain.TransformAsk, Transformations: []string{"checkpoint_chunks"}})
	if err != nil || row.Status != domain.WorkloadPendingApproval || row.Plan == nil {
		t.Fatalf("expected exact transformation preview: %+v err=%v", row, err)
	}
	originalHash := row.Plan.PlanHash
	if _, err := mgr.ApproveTransformation(ctx, row.Request.ID, "wrong-hash", "owner", string(domain.TransformAsk)); err == nil {
		t.Fatal("mismatched plan hash was approved")
	}
	if _, err := mgr.ApproveTransformation(ctx, row.Request.ID, originalHash, "owner", string(domain.TransformAsk)); err != nil {
		t.Fatal(err)
	}

	// A capability refresh is material to transformation safety. Replacing the
	// target before reconciliation must force a new preview and approval.
	mgr.RegisterTarget(Target{ID: "transform-target", Adapter: "mock", AcceleratorID: "gpu-0", CapabilityVersion: "cap-v2", Enabled: true})
	mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	changed, err := mgr.Get(ctx, row.Request.ID)
	if err != nil || changed.Status != domain.WorkloadPendingApproval || changed.Plan == nil || changed.Plan.PlanHash == originalHash {
		t.Fatalf("capability change reused stale approval: %+v err=%v", changed, err)
	}
	if _, err := mgr.ApproveTransformation(ctx, row.Request.ID, changed.Plan.PlanHash, "review-agent", string(domain.TransformDelegateSafeReview)); err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, row.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded {
		t.Fatalf("approved current plan did not execute: %+v err=%v", finished, err)
	}
	approvals, err := backing.ListTransformationApprovals(ctx, row.Request.ID)
	if err != nil || len(approvals) != 2 {
		t.Fatalf("approvals were not durable and plan-specific: %+v err=%v", approvals, err)
	}
}

func TestDelegatedReviewRejectsUnsafeTransformation(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(Target{ID: "target", Adapter: "mock", Enabled: true})
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"workflow":"v1"}`), Transformations: []string{"install_custom_node"}})
	if err != nil || row.Plan == nil {
		t.Fatalf("preview: %+v err=%v", row, err)
	}
	if _, err := mgr.ApproveTransformation(ctx, row.Request.ID, row.Plan.PlanHash, "agent", string(domain.TransformDelegateSafeReview)); err == nil {
		t.Fatal("delegated reviewer approved a non-allowlisted transformation")
	}
}

func TestMeasuredCrossRuntimeSharingUsesOnePhysicalLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := NewMockAdapter()
	mock.Delay = 180 * time.Millisecond
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(mock)
	common := Target{Adapter: "mock", AcceleratorID: "gpu-0", CapabilityVersion: "runtime-v1", Slots: 1, AcceleratorVRAMMB: 24_000, VRAMReserveMB: 1_000, SharingEnabled: true, PredictedSlowdown: 1.12, MaxSlowdown: 1.30, Enabled: true}
	videoTarget := common
	videoTarget.ID, videoTarget.WorkloadClass, videoTarget.StandaloneVRAMMB = "a-video", "video", 12_000
	llmTarget := common
	llmTarget.ID, llmTarget.WorkloadClass, llmTarget.StandaloneVRAMMB = "b-llm", "llm", 4_000
	mgr.RegisterTarget(videoTarget)
	mgr.RegisterTarget(llmTarget)
	mgr.Start(ctx)

	video, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", ItemID: "video", Payload: json.RawMessage(`{"kind":"video"}`), Disruption: domain.DisruptionSlowdown})
	if err != nil || video.Plan == nil || video.Plan.TargetID != "a-video" {
		t.Fatalf("video admission: %+v err=%v", video, err)
	}
	interactive, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", ItemID: "interactive", Payload: json.RawMessage(`{"kind":"llm"}`), QoS: domain.QoSInteractive, Priority: 50, Disruption: domain.DisruptionSlowdown})
	if err != nil || interactive.Status != domain.WorkloadRunning || interactive.Plan == nil || interactive.Plan.TargetID != "b-llm" {
		t.Fatalf("bounded interactive workload was not co-scheduled: %+v err=%v", interactive, err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	for _, id := range []string{video.Request.ID, interactive.Request.ID} {
		finished, err := mgr.Wait(waitCtx, id)
		if err != nil || finished.Status != domain.WorkloadSucceeded {
			t.Fatalf("shared workload %s: %+v err=%v", id, finished, err)
		}
	}
	samples, err := backing.ListSchedulerLearningSamples(ctx, "gpu-0", 10)
	if err != nil || len(samples) != 1 || samples[0].Outcome != "succeeded" {
		t.Fatalf("successful real sharing was not persisted as learning evidence: %+v err=%v", samples, err)
	}
	profiles, err := backing.ListInterferenceProfiles(ctx)
	var classProfile *domain.InterferenceProfile
	for _, profile := range profiles {
		if !strings.Contains(profile.Key, "|fp:") {
			classProfile = profile
		}
	}
	if err != nil || len(profiles) != 2 || classProfile == nil || classProfile.Samples != 1 || classProfile.Successes != 1 || classProfile.Version != 1 || classProfile.RuntimeVersion != "runtime-v1" || classProfile.Confidence <= 0 {
		t.Fatalf("successful sharing did not calibrate a durable runtime-scoped profile: %+v err=%v", profiles, err)
	}
}

func TestWaitingETAUsesDurableTargetHistory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	started := now.Add(-500 * time.Millisecond)
	_, _, err := backing.CreateWorkload(ctx, &domain.Workload{
		Request:    domain.WorkloadRequest{ID: "historical", OwnerID: "owner", Adapter: "mock", WorkloadType: "eta-test"},
		Status:     domain.WorkloadSucceeded,
		Plan:       &domain.ExecutionPlan{ID: "historical-plan", TargetID: "only"},
		Execution:  &domain.ExecutionHandle{StartedAt: started},
		CreatedAt:  started,
		UpdatedAt:  now,
		FinishedAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}
	mock := NewMockAdapter()
	mock.Delay = 250 * time.Millisecond
	mgr := NewManager(quietLogger(), backing, 5*time.Second)
	mgr.RegisterAdapter(mock)
	mgr.RegisterTarget(Target{ID: "only", Adapter: "mock", Slots: 1, Enabled: true, CapacityVerified: true})
	mgr.Start(ctx)
	first, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", WorkloadType: "eta-test", ItemID: "first", Payload: json.RawMessage(`{}`)})
	if err != nil || first.Status != domain.WorkloadRunning {
		t.Fatalf("first admission: %+v err=%v", first, err)
	}
	before := time.Now().UTC()
	second, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", WorkloadType: "eta-test", ItemID: "second", Payload: json.RawMessage(`{}`)})
	if err != nil || second.Status != domain.WorkloadWaiting || second.Decision.EstimatedStart == nil || second.Decision.EstimatedEnd == nil {
		t.Fatalf("waiting decision omitted ETA range: %+v err=%v", second, err)
	}
	if second.Decision.EstimatedStart.After(before.Add(2*time.Second)) || second.Decision.Confidence <= .35 {
		t.Fatalf("waiting ETA ignored durable runtime history: %+v", second.Decision)
	}
}

func TestExclusiveLearningBootstrapsUnknownStandaloneEnvelopes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mock := NewMockAdapter()
	mock.Delay = 10 * time.Millisecond
	mock.ObservedVRAMMB = 6_000
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(mock)
	base := Target{Adapter: "mock", AcceleratorID: "gpu-learn", CapabilityVersion: "runtime-v1", Slots: 1, AcceleratorVRAMMB: 24_000, VRAMReserveMB: 1_000, SharingEnabled: true, GuardedExploration: true, MaxSlowdown: 1.25}
	llm := base
	llm.ID, llm.WorkloadClass, llm.Enabled = "a-llm", "llm", true
	video := base
	video.ID, video.WorkloadClass, video.Enabled = "b-video", "video", false
	mgr.RegisterTarget(llm)
	mgr.RegisterTarget(video)
	mgr.Start(ctx)

	train := func(prefix string) {
		for index := 0; index < 3; index++ {
			row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", WorkloadType: "training", ItemID: fmt.Sprintf("%s-%d", prefix, index), Payload: json.RawMessage(`{}`), Disruption: domain.DisruptionSlowdown})
			if err != nil {
				t.Fatal(err)
			}
			waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Second)
			finished, waitErr := mgr.Wait(waitCtx, row.Request.ID)
			waitCancel()
			if waitErr != nil || finished.Status != domain.WorkloadSucceeded {
				t.Fatalf("exclusive training failed: %+v err=%v", finished, waitErr)
			}
		}
	}
	train("llm")
	llm.Enabled, video.Enabled = false, true
	mgr.RegisterTarget(llm)
	mgr.RegisterTarget(video)
	train("video")

	profiles, err := backing.ListInterferenceProfiles(ctx)
	if err != nil || len(profiles) != 4 {
		t.Fatalf("exclusive profiles were not learned: %+v err=%v", profiles, err)
	}
	for _, profile := range profiles {
		if strings.Contains(profile.Key, "|fp:") {
			continue
		}
		if profile.Samples != 3 || profile.P95VRAMMB != 6_000 || profile.Confidence < .5 || profile.P95DurationMS <= 0 {
			t.Fatalf("exclusive envelope is not admission-ready: %+v", profile)
		}
	}
	llm.Enabled, video.Enabled = true, true
	mgr.RegisterTarget(llm)
	mgr.RegisterTarget(video)
	mock.Delay = 180 * time.Millisecond
	first, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", WorkloadType: "shared", ItemID: "learned-first", Payload: json.RawMessage(`{}`), Disruption: domain.DisruptionSlowdown})
	if err != nil || first.Status != domain.WorkloadRunning {
		t.Fatalf("learned victim admission: %+v err=%v", first, err)
	}
	second, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", WorkloadType: "shared", ItemID: "learned-second", Payload: json.RawMessage(`{}`), Disruption: domain.DisruptionSlowdown})
	if err != nil || second.Status != domain.WorkloadRunning || first.Plan == nil || second.Plan == nil ||
		second.Plan.TargetID == first.Plan.TargetID || second.Plan.AcceleratorID != first.Plan.AcceleratorID {
		t.Fatalf("learned standalone envelopes did not bootstrap guarded sharing: %+v err=%v", second, err)
	}
}

func TestRestartRestoresLearnedStandaloneEnvelope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	target := Target{ID: "learned", Adapter: "mock", AcceleratorID: "gpu-0", CapabilityVersion: "runtime-v1", WorkloadClass: "llm", Enabled: true}
	_, err := backing.UpsertInterferenceProfile(ctx, &domain.InterferenceProfile{Key: standaloneProfileKey(target), AcceleratorID: target.AcceleratorID, RuntimeVersion: target.CapabilityVersion, WorkloadClasses: []string{"llm"}, P95VRAMMB: 7_500, P95DurationMS: 250, Samples: 3, Successes: 3, Confidence: .5, Version: 3, UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterTarget(target)
	mgr.Start(ctx)
	targets := mgr.Targets()
	if len(targets) != 1 || targets[0].StandaloneVRAMMB != 7_500 {
		t.Fatalf("restart did not restore learned standalone envelope: %+v", targets)
	}
}

func TestUnknownSharingIsConservativeAndGuardedRollbackAbortsNewcomer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := NewMockAdapter()
	mock.Delay = 120 * time.Millisecond
	mock.ObservedSlowdown = 2.0
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(mock)
	base := Target{Adapter: "mock", AcceleratorID: "gpu-0", CapabilityVersion: "runtime-v1", Slots: 1, AcceleratorVRAMMB: 24_000, VRAMReserveMB: 2_000, StandaloneVRAMMB: 6_000, SharingEnabled: true, MaxSlowdown: 1.25, Enabled: true}
	victim := base
	victim.ID, victim.WorkloadClass, victim.PredictedSlowdown, victim.GuardedExploration = "a-victim", "video", 0, true
	newcomer := base
	newcomer.ID, newcomer.WorkloadClass, newcomer.GuardedExploration = "b-newcomer", "llm", true
	mgr.RegisterTarget(victim)
	mgr.RegisterTarget(newcomer)
	mgr.Start(ctx)

	first, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", ItemID: "victim", Payload: json.RawMessage(`{"kind":"video"}`), Disruption: domain.DisruptionSlowdown})
	if err != nil || first.Status != domain.WorkloadRunning {
		t.Fatalf("victim admission: %+v err=%v", first, err)
	}
	second, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", ItemID: "newcomer", Payload: json.RawMessage(`{"kind":"llm"}`), Disruption: domain.DisruptionSlowdown})
	if err != nil || second.Status != domain.WorkloadRunning {
		t.Fatalf("guarded exploration with rollback headroom was not admitted: %+v err=%v", second, err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	rolledBack, err := mgr.Wait(waitCtx, second.Request.ID)
	if err != nil || rolledBack.Status != domain.WorkloadFailed || !strings.Contains(rolledBack.Error, "slowdown threshold") {
		t.Fatalf("unsafe exploration was not rolled back: %+v err=%v", rolledBack, err)
	}
	samples, err := backing.ListSchedulerLearningSamples(ctx, "gpu-0", 10)
	if err != nil || len(samples) != 1 || samples[0].Outcome != "rolled_back" {
		t.Fatalf("rollback evidence was not persisted: %+v err=%v", samples, err)
	}
	profiles, err := backing.ListInterferenceProfiles(ctx)
	var classProfile *domain.InterferenceProfile
	for _, profile := range profiles {
		if !strings.Contains(profile.Key, "|fp:") {
			classProfile = profile
		}
	}
	if err != nil || len(profiles) != 2 || classProfile == nil || classProfile.Samples != 1 || classProfile.Rollbacks != 1 || classProfile.PredictedSlowdown < 2 {
		t.Fatalf("rollback did not calibrate conservative interference limits: %+v err=%v", profiles, err)
	}
}

type checkpointTestAdapter struct{}

func (checkpointTestAdapter) Name() string                                           { return "preempt" }
func (checkpointTestAdapter) Version() string                                        { return "v1" }
func (checkpointTestAdapter) Validate(context.Context, domain.WorkloadRequest) error { return nil }
func (checkpointTestAdapter) Requirements(context.Context, domain.WorkloadRequest) (Requirements, error) {
	return Requirements{AcceleratorRequired: true}, nil
}
func (checkpointTestAdapter) Plan(context.Context, domain.WorkloadRequest, Target) (*domain.ExecutionPlan, error) {
	return &domain.ExecutionPlan{}, nil
}
func (checkpointTestAdapter) Start(_ context.Context, req domain.WorkloadRequest, _ *domain.ExecutionPlan, _ Target) (*domain.ExecutionHandle, error) {
	state := json.RawMessage(`{"finish":true}`)
	if req.ItemID == "victim" {
		state = json.RawMessage(`{"initial_victim":true}`)
	}
	return &domain.ExecutionHandle{ExternalID: req.ItemID, Opaque: state, StartedAt: time.Now().UTC()}, nil
}
func (checkpointTestAdapter) Observe(ctx context.Context, _ domain.WorkloadRequest, _ *domain.ExecutionPlan, handle *domain.ExecutionHandle, _ Target) (Observation, error) {
	if strings.Contains(string(handle.Opaque), "initial_victim") {
		<-ctx.Done()
		return Observation{}, ctx.Err()
	}
	return Observation{Status: domain.WorkloadSucceeded, Progress: 1}, nil
}
func (checkpointTestAdapter) Yield(context.Context, *domain.ExecutionHandle, Target) error {
	return nil
}
func (checkpointTestAdapter) Checkpoint(context.Context, *domain.ExecutionHandle, Target) (string, error) {
	return "checkpoint://victim", nil
}
func (checkpointTestAdapter) Resume(_ context.Context, req domain.WorkloadRequest, _ *domain.ExecutionPlan, _ string, _ Target) (*domain.ExecutionHandle, error) {
	return &domain.ExecutionHandle{ExternalID: req.ItemID + "-resumed", Opaque: json.RawMessage(`{"resumed":true}`), StartedAt: time.Now().UTC()}, nil
}
func (checkpointTestAdapter) Cancel(context.Context, *domain.ExecutionHandle, Target) error {
	return nil
}
func (checkpointTestAdapter) CollectOutputs(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (json.RawMessage, []string, error) {
	return json.RawMessage(`{"ok":true}`), nil, nil
}

func TestCheckpointableVictimResumesAfterPriorityPreemption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, 200*time.Millisecond)
	mgr.RegisterAdapter(checkpointTestAdapter{})
	mgr.RegisterTarget(Target{ID: "gpu", Adapter: "preempt", AcceleratorID: "gpu-0", Slots: 1, Enabled: true})
	mgr.Start(ctx)
	victim, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "preempt", ItemID: "victim", Payload: json.RawMessage(`{}`), Priority: 1, Recoverable: true, Disruption: domain.DisruptionCheckpointable})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		victim, _ = mgr.Get(ctx, victim.Request.ID)
		if victim.Execution != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if victim.Execution == nil {
		t.Fatal("victim never reached a checkpointable execution state")
	}
	urgent, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "preempt", ItemID: "urgent", Payload: json.RawMessage(`{}`), QoS: domain.QoSInteractive, Priority: 80, Disruption: domain.DisruptionLocked, PreemptionBudget: 1})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 4*time.Second)
	defer waitCancel()
	urgentDone, err := mgr.Wait(waitCtx, urgent.Request.ID)
	if err != nil || urgentDone.Status != domain.WorkloadSucceeded {
		t.Fatalf("urgent workload did not run after checkpoint transition: %+v err=%v", urgentDone, err)
	}
	victimDone, err := mgr.Wait(waitCtx, victim.Request.ID)
	if err != nil || victimDone.Status != domain.WorkloadSucceeded || victimDone.PreemptionCount != 1 || victimDone.CheckpointRef != "" {
		t.Fatalf("victim did not resume from checkpoint: %+v err=%v", victimDone, err)
	}
	plans, err := backing.ListTransitionPlans(ctx, urgent.Request.ID, 10)
	if err != nil || len(plans) != 1 || plans[0].Status != domain.TransitionPlanCompleted || plans[0].VictimWorkloadID != victim.Request.ID || len(plans[0].Rollback) != 1 {
		t.Fatalf("preemption transition was not durably explained: %+v err=%v", plans, err)
	}
	if len(urgentDone.TransitionPlanIDs) != 1 || len(victimDone.TransitionPlanIDs) != 1 || urgentDone.TransitionPlanIDs[0] != plans[0].ID || victimDone.TransitionPlanIDs[0] != plans[0].ID {
		t.Fatalf("workloads do not reference their transition plan: urgent=%+v victim=%+v", urgentDone.TransitionPlanIDs, victimDone.TransitionPlanIDs)
	}
}

func TestLockedVictimCannotBePreemptedByPriority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(checkpointTestAdapter{})
	mgr.RegisterTarget(Target{ID: "gpu", Adapter: "preempt", AcceleratorID: "gpu-0", Slots: 1, Enabled: true})
	mgr.Start(ctx)
	victim, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "preempt", ItemID: "victim", Payload: json.RawMessage(`{}`), Priority: 1, Disruption: domain.DisruptionLocked})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		victim, _ = mgr.Get(ctx, victim.Request.ID)
		if victim.Execution != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	urgent, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "preempt", ItemID: "urgent", Payload: json.RawMessage(`{}`), QoS: domain.QoSInteractive, Priority: 100, Disruption: domain.DisruptionLocked, PreemptionBudget: 1})
	if err != nil || urgent.Status != domain.WorkloadWaiting {
		t.Fatalf("priority bypassed locked victim: %+v err=%v", urgent, err)
	}
	after, _ := mgr.Get(ctx, victim.Request.ID)
	if after.Status != domain.WorkloadRunning || after.PreemptionCount != 0 {
		t.Fatalf("locked victim was disrupted: %+v", after)
	}
}

func TestRestartDoesNotReplayInterruptedTransitionPlan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	plan, err := backing.CreateTransitionPlan(ctx, &domain.TransitionPlan{ID: "transition-plan-restart", WorkloadID: "newcomer", VictimWorkloadID: "victim", Reason: "preempt", Status: domain.TransitionPlanExecuting, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.Start(ctx)
	plans, err := backing.ListTransitionPlans(ctx, plan.WorkloadID, 10)
	if err != nil || len(plans) != 1 || plans[0].Status != domain.TransitionPlanFailed || plans[0].FinishedAt == nil || !strings.Contains(plans[0].Error, "not replayed") {
		t.Fatalf("interrupted transition was not safely reconciled: %+v err=%v", plans, err)
	}
}

type completedRestartAdapter struct {
	*MockAdapter
	starts int
}

func newCompletedRestartAdapter() *completedRestartAdapter {
	return &completedRestartAdapter{MockAdapter: NewMockAdapter()}
}

func (a *completedRestartAdapter) Name() string { return "restart-complete" }
func (a *completedRestartAdapter) Start(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	a.starts++
	return a.MockAdapter.Start(ctx, req, plan, target)
}
func (a *completedRestartAdapter) Observe(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (Observation, error) {
	return Observation{Status: domain.WorkloadSucceeded, Progress: 1}, nil
}
func (a *completedRestartAdapter) CollectOutputs(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (json.RawMessage, []string, error) {
	return json.RawMessage(`{"recovered":true}`), nil, nil
}

func TestRestartReattachesCompletedExternalExecutionWithoutDuplicateStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	request := domain.WorkloadRequest{ID: "restart-work", OwnerID: "owner", Adapter: "restart-complete", Payload: json.RawMessage(`{}`), Recoverable: true}
	_, created, err := backing.CreateWorkload(ctx, &domain.Workload{
		Request: request, Status: domain.WorkloadRunning,
		Plan:      &domain.ExecutionPlan{ID: "plan-before-restart", WorkloadID: request.ID, TargetID: "restart-target", AcceleratorID: "gpu-0"},
		Execution: &domain.ExecutionHandle{ExternalID: "external-before-restart", StartedAt: now},
		CreatedAt: now, UpdatedAt: now, StartedAt: &now, ExecutionAttempts: 1,
	})
	if err != nil || !created {
		t.Fatalf("seed running workload: created=%t err=%v", created, err)
	}
	adapter := newCompletedRestartAdapter()
	manager := NewManager(quietLogger(), backing, time.Second)
	manager.RegisterAdapter(adapter)
	manager.RegisterTarget(Target{ID: "restart-target", Adapter: adapter.Name(), AcceleratorID: "gpu-0", Enabled: true})
	manager.Start(ctx)
	recovered, err := manager.Get(ctx, request.ID)
	if err != nil || recovered.Status != domain.WorkloadSucceeded || !strings.Contains(string(recovered.InlineOutput), "recovered") || recovered.ExecutionAttempts != 1 || adapter.starts != 0 {
		t.Fatalf("persisted execution was duplicated instead of reattached: %+v starts=%d err=%v", recovered, adapter.starts, err)
	}
}

func TestRestartDoesNotReplayExecutionWhoseBackendStateCannotBeConfirmed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	request := domain.WorkloadRequest{ID: "restart-stale", OwnerID: "owner", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`), Recoverable: true}
	_, _, err := backing.CreateWorkload(ctx, &domain.Workload{
		Request: request, Status: domain.WorkloadRunning,
		Plan:      &domain.ExecutionPlan{ID: "stale-plan", WorkloadID: request.ID, TargetID: "llm", AcceleratorID: "gpu-0"},
		Execution: &domain.ExecutionHandle{ExternalID: "http-run-from-dead-controller", StartedAt: now},
		CreatedAt: now, UpdatedAt: now, StartedAt: &now, ExecutionAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(quietLogger(), backing, time.Second)
	manager.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", nil))
	manager.RegisterTarget(Target{ID: "llm", Adapter: "llamacpp", Endpoint: "http://127.0.0.1:1", AcceleratorID: "gpu-0", Enabled: true})
	manager.Start(ctx)
	recovered, err := manager.Get(ctx, request.ID)
	if err != nil || recovered.Status != domain.WorkloadFailed || recovered.ExecutionAttempts != 1 || !strings.Contains(recovered.Error, "not duplicated") {
		t.Fatalf("unconfirmed restart execution was replayed: %+v err=%v", recovered, err)
	}
}

type lateResultAdapter struct{ release chan struct{} }

func (lateResultAdapter) Name() string                                           { return "late" }
func (lateResultAdapter) Version() string                                        { return "v1" }
func (lateResultAdapter) Validate(context.Context, domain.WorkloadRequest) error { return nil }
func (lateResultAdapter) Requirements(context.Context, domain.WorkloadRequest) (Requirements, error) {
	return Requirements{AcceleratorRequired: true}, nil
}
func (lateResultAdapter) Plan(context.Context, domain.WorkloadRequest, Target) (*domain.ExecutionPlan, error) {
	return &domain.ExecutionPlan{}, nil
}
func (lateResultAdapter) Start(_ context.Context, req domain.WorkloadRequest, _ *domain.ExecutionPlan, _ Target) (*domain.ExecutionHandle, error) {
	return &domain.ExecutionHandle{ExternalID: req.ID, StartedAt: time.Now().UTC()}, nil
}
func (a lateResultAdapter) Observe(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (Observation, error) {
	<-a.release
	return Observation{Status: domain.WorkloadSucceeded, Progress: 1}, nil
}
func (lateResultAdapter) Yield(context.Context, *domain.ExecutionHandle, Target) error {
	return ErrUnsupported
}
func (lateResultAdapter) Checkpoint(context.Context, *domain.ExecutionHandle, Target) (string, error) {
	return "", ErrUnsupported
}
func (lateResultAdapter) Resume(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, string, Target) (*domain.ExecutionHandle, error) {
	return nil, ErrUnsupported
}
func (lateResultAdapter) Cancel(context.Context, *domain.ExecutionHandle, Target) error { return nil }
func (lateResultAdapter) CollectOutputs(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (json.RawMessage, []string, error) {
	return json.RawMessage(`{"ok":true}`), nil, nil
}

type unconfirmedStopAdapter struct{ lateResultAdapter }

func (unconfirmedStopAdapter) Name() string { return "unconfirmed-stop" }
func (unconfirmedStopAdapter) Cancel(context.Context, *domain.ExecutionHandle, Target) error {
	return ErrUnsupported
}

func TestNodeLossRequeuesRecoverableWorkAndIgnoresLateFencedResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	node := &domain.Node{ID: "node", Name: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now}, Accelerators: []domain.Accelerator{{ID: "gpu-0", NodeID: "node", VRAMTotalMB: 24_000, VRAMFreeMB: 24_000}}}
	if _, err := backing.UpsertNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	mgr := NewManager(quietLogger(), backing, 200*time.Millisecond)
	mgr.SetNodeStore(backing)
	mgr.RegisterAdapter(lateResultAdapter{release: release})
	mgr.RegisterTarget(Target{ID: "late-target", Adapter: "late", AcceleratorID: "gpu-0", Enabled: true})
	mgr.Start(ctx)
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "late", Payload: json.RawMessage(`{}`), Recoverable: true, IdempotencyKey: "recover-once"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		row, _ = mgr.Get(ctx, row.Request.ID)
		if row.Execution != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if row.Execution == nil {
		t.Fatal("first attempt never started")
	}
	if err := backing.UpdateObserved(ctx, "node", func(observed *domain.Observed, _ *[]domain.Accelerator) {
		observed.Connectivity = domain.ConnectivityLost
		observed.Ready = false
	}); err != nil {
		t.Fatal(err)
	}
	mgr.reconcile(ctx)
	close(release)
	time.Sleep(30 * time.Millisecond)
	lateIgnored, _ := mgr.Get(ctx, row.Request.ID)
	if lateIgnored.Status == domain.WorkloadSucceeded || lateIgnored.ExecutionAttempts != 1 {
		t.Fatalf("late fenced result overwrote requeue: %+v", lateIgnored)
	}
	if err := backing.UpdateObserved(ctx, "node", func(observed *domain.Observed, _ *[]domain.Accelerator) {
		observed.Connectivity = domain.ConnectivityConnected
		observed.Ready = true
		observed.LastSeenAt = time.Now().UTC()
	}); err != nil {
		t.Fatal(err)
	}
	lateIgnored.TargetRetryAfter["late-target"] = time.Now().Add(-time.Second)
	if _, err := backing.UpdateWorkload(ctx, lateIgnored); err != nil {
		t.Fatal(err)
	}
	mgr.reconcile(ctx)
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	finished, err := mgr.Wait(waitCtx, row.Request.ID)
	if err != nil || finished.Status != domain.WorkloadSucceeded || finished.ExecutionAttempts != 2 {
		t.Fatalf("recoverable work did not reschedule exactly once: %+v err=%v", finished, err)
	}
}

func TestNodeLossDoesNotDuplicateRecoverableWorkWhenBackendStopIsUnconfirmed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	node := &domain.Node{ID: "node", Name: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now}, Accelerators: []domain.Accelerator{{ID: "gpu-0", NodeID: "node", VRAMTotalMB: 24_000, VRAMFreeMB: 24_000}}}
	if _, err := backing.UpsertNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	adapter := unconfirmedStopAdapter{lateResultAdapter{release: release}}
	manager := NewManager(quietLogger(), backing, 200*time.Millisecond)
	manager.SetNodeStore(backing)
	manager.RegisterAdapter(adapter)
	manager.RegisterTarget(Target{ID: "unconfirmed-target", Adapter: adapter.Name(), AcceleratorID: "gpu-0", Enabled: true})
	manager.Start(ctx)
	row, _, err := manager.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: adapter.Name(), Payload: json.RawMessage(`{}`), Recoverable: true, IdempotencyKey: "must-not-duplicate"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		row, _ = manager.Get(ctx, row.Request.ID)
		if row.Execution != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if row.Execution == nil {
		t.Fatal("execution did not start")
	}
	if err := backing.UpdateObserved(ctx, "node", func(observed *domain.Observed, _ *[]domain.Accelerator) {
		observed.Connectivity = domain.ConnectivityLost
		observed.Ready = false
	}); err != nil {
		t.Fatal(err)
	}
	manager.reconcile(ctx)
	close(release)
	finished, err := manager.Get(ctx, row.Request.ID)
	if err != nil || finished.Status != domain.WorkloadFailed || finished.ExecutionAttempts != 1 || !strings.Contains(finished.Error, "not duplicated") {
		t.Fatalf("unconfirmed backend execution was re-admitted: %+v err=%v", finished, err)
	}
}

func TestStickyPlacementDoesNotSpillClientToLargerTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := NewMockAdapter()
	mock.Delay = 200 * time.Millisecond
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(mock)
	mgr.RegisterTarget(Target{ID: "short-context", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-0", ContextLimit: 4096, Slots: 1, Enabled: true})
	mgr.RegisterTarget(Target{ID: "long-context", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-1", ContextLimit: 32768, Slots: 1, Enabled: true})
	mgr.Start(ctx)

	first := submitMock(t, ctx, mgr, "first", "client-a")
	if first.Plan == nil || first.Plan.TargetID != "short-context" {
		t.Fatalf("initial sticky request should establish the best-fit binding: %+v", first)
	}
	second := submitMock(t, ctx, mgr, "second", "client-a")
	if second.Status != domain.WorkloadWaiting {
		t.Fatalf("sticky client should wait instead of spilling to idle long-context target: %+v", second)
	}
	if second.Plan != nil {
		t.Fatalf("waiting sticky request unexpectedly received a plan: %+v", second.Plan)
	}
}

func TestLongStreamRenewsPhysicalLeaseAcrossAdapters(t *testing.T) {
	streamStarted := make(chan struct{})
	releaseStream := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"chunk\"}\n\n")
		w.(http.Flusher).Flush()
		close(streamStarted)
		<-releaseStream
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), 150*time.Millisecond)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(Target{ID: "llm", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"model"}, ContextLimit: 8192, Slots: 1, Enabled: true})
	mgr.RegisterTarget(Target{ID: "batch", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-0", Enabled: true})
	mgr.Start(ctx)
	stream, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hi"}],"stream":true}`), InteractiveStream: true})
	if err != nil || stream.Status != domain.WorkloadRunning {
		t.Fatalf("stream admission: %+v err=%v", stream, err)
	}
	streamDone := make(chan error, 1)
	go func() {
		_, runErr := mgr.RunStream(context.Background(), stream.Request.ID, func([]byte) error { return nil })
		streamDone <- runErr
	}()
	select {
	case <-streamStarted:
	case <-time.After(time.Second):
		t.Fatal("stream backend did not start")
	}
	time.Sleep(400 * time.Millisecond)
	batch, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "mock", Payload: json.RawMessage(`{"job":"batch"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Status != domain.WorkloadWaiting {
		t.Fatalf("expired stream lease allowed another adapter to double-book the GPU: %+v", batch)
	}
	close(releaseStream)
	select {
	case err := <-streamDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not finish")
	}
}

func submitMock(t *testing.T, ctx context.Context, mgr *Manager, item, placementKey string) *domain.Workload {
	t.Helper()
	policy := domain.PlacementBestFit
	if placementKey != "" {
		policy = domain.PlacementSticky
	}
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{
		OwnerID:         "u",
		Adapter:         "mock",
		ItemID:          item,
		Payload:         json.RawMessage(`{"kind":"short"}`),
		Bounds:          domain.WorkloadBounds{ContextTokens: 2000, MaxOutput: 500},
		PlacementKey:    placementKey,
		PlacementPolicy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}
