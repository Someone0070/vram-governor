package workloads

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/nodeagent"
	checkpointRuntime "vram-governor/internal/runtime"
	"vram-governor/internal/store"
	"vram-governor/internal/wsproto"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestManagerCloseCancelsExecutionAndRejectsRestart(t *testing.T) {
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	manager.Start(parent)

	executionCtx, executionCancel := context.WithCancel(context.Background())
	manager.mu.Lock()
	manager.cancels["running-workload"] = executionCancel
	manager.mu.Unlock()
	select {
	case <-executionCtx.Done():
		t.Fatal("test execution context was cancelled before manager close")
	default:
	}

	manager.Close()
	select {
	case <-executionCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("manager close did not cancel its registered execution")
	}

	manager.lifecycleMu.Lock()
	closed := manager.lifecycleClosed
	started := manager.recoveryStarted
	manager.lifecycleMu.Unlock()
	if !closed || !started {
		t.Fatalf("manager lifecycle state after close: closed=%v started=%v", closed, started)
	}
	manager.Start(context.Background())
	manager.lifecycleMu.Lock()
	stillClosed := manager.lifecycleClosed
	manager.lifecycleMu.Unlock()
	if !stillClosed {
		t.Fatal("manager restart after Close reopened lifecycle")
	}
}

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
		case r.URL.Path == "/object_info":
			_, _ = io.WriteString(w, `{"KSampler":{"input":{"required":{}},"output":[]}}`)
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
	// These in-process fixtures use bounded synthetic runtime measurements, not live GPU observations.
	sharedPhysicalBudget := domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMHardCapBytes: 8 << 30, VRAMReserveBytes: 1 << 30}
	sharedProfile := []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 1}}
	mgr.RegisterTarget(Target{ID: "llm", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"model"}, Slots: 1, ActiveRuntimeProfile: "ctx-8k", ContextLimit: 8192, RuntimeProfiles: sharedProfile, Capacity: sharedPhysicalBudget, CapacitySource: "runtime:/slots", CapacityVerified: true, CapabilityVersion: "fixture-runtime-v1", CapabilityRevision: "fixture-capacity-r1", ModelFingerprint: "fixture-model-fingerprint", Enabled: true})
	mgr.RegisterTarget(Target{ID: "image", Adapter: "comfy", Endpoint: backend.URL, AcceleratorID: "gpu-0", Slots: 1, ActiveRuntimeProfile: "ctx-8k", ContextLimit: 8192, RuntimeProfiles: sharedProfile, Capacity: sharedPhysicalBudget, CapacitySource: "runtime:/slots", CapacityVerified: true, CapabilityVersion: "fixture-runtime-v1", CapabilityRevision: "fixture-capacity-r1", ModelFingerprint: "fixture-model-fingerprint", Enabled: true})
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(mgr.targetByID("llm"), "model", 2<<30, 1<<30)); err != nil {
		t.Fatalf("seed measured LLM model capacity on shared physical accelerator: %v", err)
	}
	mgr.Start(ctx)

	llm, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hi"}]}`)})
	if err != nil || llm.Status != domain.WorkloadRunning {
		t.Fatalf("LLM admission: %+v err=%v", llm, err)
	}
	comfy, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "u", Adapter: "comfy", Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"KSampler","inputs":{}}}}`), Recoverable: true})
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
		case "/object_info":
			_, _ = io.WriteString(w, `{"KSampler":{"input":{"required":{}},"output":[]}}`)
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
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: "public-sticky", Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"KSampler","inputs":{}}}}`), Recoverable: true})
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
		case "/object_info":
			_, _ = io.WriteString(w, `{"LoadImage":{"input":{"required":{"image":["STRING"]}},"output":[]}}`)
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
			_ = json.NewEncoder(w).Encode(map[string]any{"backend-output": map[string]any{"status": map[string]any{"completed": true, "status_str": "success"}, "outputs": map[string]any{
				// Load nodes such as LoadVideo echo the staged input; it is
				// not a result and must not become an output artifact.
				"1": map[string]any{"images": []any{map[string]any{"filename": input.ID, "subfolder": "", "type": "input"}}},
				"9": map[string]any{"images": []any{map[string]any{"filename": "result.png", "subfolder": "", "type": "output"}}}}}})
		case "/view":
			if r.URL.Query().Get("type") == "input" {
				t.Error("staged input echo was fetched as an output")
				w.Header().Set("Content-Type", "application/octet-stream")
			} else {
				w.Header().Set("Content-Type", "image/png")
			}
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
func (a *profileLifecycleMock) ObserveResidency(_ context.Context, target Target, model string) (ResidencyObservation, error) {
	identity := strings.Join([]string{target.ID, target.Adapter, target.RuntimeProtocol, target.CapabilityVersion, target.ModelFingerprint}, "|")
	return ResidencyObservation{TargetID: target.ID, Model: model, RuntimeIdentity: identity, Tier: domain.ResidencyHotVRAM, FencingToken: 1}, nil
}

func TestContextBestFitBeatsResidentLongProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	adapter := &profileLifecycleMock{MockAdapter: NewMockAdapter()}
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(adapter)
	// Each target gets an explicit fixture model footprint and initialized profile pool.
	fixtureBudget := domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMHardCapBytes: 8 << 30, VRAMReserveBytes: 1 << 30}
	mgr.RegisterTarget(Target{
		ID: "short-cold", Adapter: adapter.Name(), Endpoint: "in-process", AcceleratorID: "gpu-short",
		Models: []string{"same-model"}, ContextLimit: 2048, Slots: 2, ActiveRuntimeProfile: "ctx-short", SupportsModelLifecycle: true,
		Capacity: fixtureBudget, CapacitySource: "runtime:/slots", CapacityVerified: true,
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-short", ContextLimit: 2048, Slots: 2}},
		CapabilityVersion: "fixture-profile-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true},
		ModelFingerprint: "fixture-profile-model-fingerprint", Enabled: true,
	})
	mgr.RegisterTarget(Target{
		ID: "long-hot", Adapter: adapter.Name(), Endpoint: "in-process", AcceleratorID: "gpu-long",
		Models: []string{"same-model"}, ResidentModels: []string{"same-model"}, ContextLimit: 8192, Slots: 1, ActiveRuntimeProfile: "ctx-long", SupportsModelLifecycle: true,
		Capacity: fixtureBudget, CapacitySource: "runtime:/slots", CapacityVerified: true,
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-long", ContextLimit: 8192, Slots: 1}},
		CapabilityVersion: "fixture-profile-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true},
		ModelFingerprint: "fixture-profile-model-fingerprint", Enabled: true,
	})
	for _, targetID := range []string{"short-cold", "long-hot"} {
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(mgr.targetByID(targetID), "same-model", 2<<30, 512<<20)); err != nil {
			t.Fatalf("seed measured model capacity for %s placement fixture: %v", targetID, err)
		}
	}
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

func TestWorkloadRevisionCASAndCancellationOwnership(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	created, _, err := backing.CreateWorkload(ctx, &domain.Workload{
		Request: domain.WorkloadRequest{ID: "revision-cas", OwnerID: "owner", Adapter: "mock"},
		Status:  domain.WorkloadRunning, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil || created.Revision != 1 {
		t.Fatalf("workload revision was not initialized: %+v err=%v", created, err)
	}
	var encoded map[string]any
	if body, marshalErr := json.Marshal(created); marshalErr != nil || body == nil {
		t.Fatalf("workload JSON body could not be encoded: %v", marshalErr)
	} else if err := json.Unmarshal(body, &encoded); err != nil || encoded["revision"] != float64(1) {
		t.Fatalf("workload revision was not present in JSON body: body=%s err=%v", body, err)
	}
	stale, err := backing.GetWorkload(ctx, created.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimed := *created
	claimed.CancellationOwner = "owner"
	claimedRow, err := backing.CompareAndSwapWorkload(ctx, &claimed, created.Revision, domain.WorkloadRunning, "")
	if err != nil || claimedRow.Revision != 2 || claimedRow.CancellationOwner != "owner" {
		t.Fatalf("cancellation claim was not durable: %+v err=%v", claimedRow, err)
	}
	stale.Progress = .8
	if _, err := backing.CompareAndSwapWorkload(ctx, stale, stale.Revision, domain.WorkloadRunning, ""); !errors.Is(err, store.ErrWorkloadConflict) {
		t.Fatalf("stale observer crossed cancellation ownership: %v", err)
	}
	terminal := *claimedRow
	terminal.Status = domain.WorkloadCancelled
	terminal.CancellationOwner = ""
	terminal.FinishedAt = ptrTime(now)
	terminal.UpdatedAt = now
	settled, err := backing.CompareAndSwapWorkload(ctx, &terminal, claimedRow.Revision, domain.WorkloadRunning, "owner")
	if err != nil || settled.Status != domain.WorkloadCancelled || settled.Revision != 3 {
		t.Fatalf("cancellation did not win terminal CAS: %+v err=%v", settled, err)
	}
	late := *stale
	late.Status = domain.WorkloadFailed
	if _, err := backing.CompareAndSwapWorkload(ctx, &late, late.Revision, domain.WorkloadCancelled, ""); !errors.Is(err, store.ErrWorkloadConflict) {
		t.Fatalf("late observer rewrote cancelled workload: %v", err)
	}
}

func TestWorkloadMutationCASCancellationRaceSeeded(t *testing.T) {
	ctx := context.Background()
	for seed := 0; seed < 100; seed++ {
		backing := store.NewMemoryStore()
		mgr := NewManager(quietLogger(), backing, time.Second)
		now := time.Now().UTC()
		row := &domain.Workload{
			Request: domain.WorkloadRequest{ID: fmt.Sprintf("cas-race-%03d", seed), OwnerID: "owner", Adapter: "mock"},
			Status:  domain.WorkloadQueued, CreatedAt: now, UpdatedAt: now,
		}
		created, _, err := backing.CreateWorkload(ctx, row)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			mgr.fail(ctx, created, "seeded observer failure")
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = mgr.Cancel(ctx, created.Request.ID, "owner", false)
		}()
		close(start)
		wg.Wait()
		final, err := backing.GetWorkload(ctx, created.Request.ID)
		if err != nil {
			t.Fatal(err)
		}
		if final.Status != domain.WorkloadCancelled && final.Status != domain.WorkloadFailed {
			t.Fatalf("seed %d left nonterminal workload: %+v", seed, final)
		}
		if final.CancellationOwner != "" || final.Revision < 2 {
			t.Fatalf("seed %d lost mutation ownership/revision: %+v", seed, final)
		}
	}
}

func TestFullWorkloadProjectionNeverOverwritesNewerSameStatusFields(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	now := time.Now().UTC()
	created, _, err := backing.CreateWorkload(ctx, &domain.Workload{
		Request: domain.WorkloadRequest{ID: "projection-conflict", OwnerID: "owner", Adapter: "mock"},
		Status:  domain.WorkloadRunning, Progress: .2, Error: "old", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	newer := *created
	newer.Progress, newer.Error = .8, "newer observer fact"
	newer.UpdatedAt = now.Add(time.Second)
	updatedNewer, err := backing.CompareAndSwapWorkload(ctx, &newer, created.Revision, domain.WorkloadRunning, "")
	if err != nil {
		t.Fatal(err)
	}
	stale := *created
	stale.Error = "stale projection"
	if _, err := mgr.replaceWorkloadCAS(ctx, &stale, workloadStatuses(domain.WorkloadRunning), ""); !errors.Is(err, store.ErrWorkloadConflict) {
		t.Fatalf("stale full projection was accepted: %v", err)
	}
	final, err := backing.GetWorkload(ctx, created.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Progress != .8 || final.Error != "newer observer fact" || final.Revision != updatedNewer.Revision {
		t.Fatalf("newer same-status facts were overwritten: %+v", final)
	}
}

func TestCancellationOwnerRetryIsIdempotentAndForeignOwnerConflicts(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	now := time.Now().UTC()
	row, _, err := backing.CreateWorkload(ctx, &domain.Workload{Request: domain.WorkloadRequest{ID: "cancel-owner-retry", OwnerID: "owner"}, Status: domain.WorkloadRunning, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	claimed := *row
	claimed.CancellationOwner = "owner"
	if _, err := backing.CompareAndSwapWorkload(ctx, &claimed, row.Revision, domain.WorkloadRunning, ""); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Cancel(ctx, row.Request.ID, "owner", false); err != nil {
		t.Fatalf("same cancellation owner retry was not idempotent: %v", err)
	}
	if err := mgr.Cancel(ctx, row.Request.ID, "intruder", true); !errors.Is(err, store.ErrWorkloadConflict) {
		t.Fatalf("foreign cancellation owner did not fail ownership check: %v", err)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }

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

type budgetIntentFailureStore struct {
	store.WorkloadStore
	settleFailures  int
	releaseFailures int
}

func (s *budgetIntentFailureStore) SettleBudgetClaim(ctx context.Context, workloadID, token string, attempt uint64, actualCents int64) (*domain.BudgetReservation, error) {
	if s.settleFailures > 0 {
		s.settleFailures--
		return nil, errors.New("injected settlement side-effect failure")
	}
	return s.WorkloadStore.SettleBudgetClaim(ctx, workloadID, token, attempt, actualCents)
}

func (s *budgetIntentFailureStore) ReleaseBudgetClaim(ctx context.Context, workloadID, token string, attempt uint64) error {
	if s.releaseFailures > 0 {
		s.releaseFailures--
		return errors.New("injected release side-effect failure")
	}
	return s.WorkloadStore.ReleaseBudgetClaim(ctx, workloadID, token, attempt)
}

func TestBudgetSideEffectsAreIntentBeforeCrashSafe(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	settlement, allowed, created, err := base.ReserveBudgetClaim(ctx, "principal", "settle-intent", 10, 100, "settle-attempt")
	if err != nil || !allowed || !created {
		t.Fatalf("reserve settlement claim: %+v allowed=%t created=%t err=%v", settlement, allowed, created, err)
	}
	settleStore := &budgetIntentFailureStore{WorkloadStore: base, settleFailures: 1}
	settleManager := NewManager(quietLogger(), settleStore, time.Second)
	_, _, err = base.CreateWorkload(ctx, &domain.Workload{Request: domain.WorkloadRequest{ID: "settle-intent"}, Status: domain.WorkloadSucceeded, Plan: &domain.ExecutionPlan{EstimatedCostCents: 10}, BudgetReservationToken: settlement.OwnershipToken, BudgetReservationAttempt: settlement.Attempt, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := base.GetWorkload(ctx, "settle-intent")
	settleManager.settleWorkloadBudget(ctx, row)
	row, _ = base.GetWorkload(ctx, "settle-intent")
	if !row.BudgetSettlementPending || row.BudgetSettlementAttempt != settlement.Attempt {
		t.Fatalf("settlement intent was not durable before side effect: %+v", row)
	}
	ledger, _ := base.ListBudgetReservations(ctx, "principal")
	if len(ledger) != 1 || ledger[0].Status != domain.BudgetReserved {
		t.Fatalf("failed settlement mutated ledger before retry: %+v", ledger)
	}
	settleManager.retryBudgetSettlementIntent(ctx, row)
	row, _ = base.GetWorkload(ctx, "settle-intent")
	if row.BudgetSettlementPending {
		t.Fatalf("settlement intent was not cleared after idempotent retry: %+v", row)
	}

	release, allowed, created, err := base.ReserveBudgetClaim(ctx, "principal", "release-intent", 10, 100, "release-attempt")
	if err != nil || !allowed || !created {
		t.Fatalf("reserve release claim: %+v allowed=%t created=%t err=%v", release, allowed, created, err)
	}
	releaseStore := &budgetIntentFailureStore{WorkloadStore: base, releaseFailures: 1}
	releaseManager := NewManager(quietLogger(), releaseStore, time.Second)
	_, _, err = base.CreateWorkload(ctx, &domain.Workload{Request: domain.WorkloadRequest{ID: "release-intent"}, Status: domain.WorkloadQueued, BudgetReservationToken: release.OwnershipToken, BudgetReservationAttempt: release.Attempt, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseManager.releaseBudgetClaimAfterWorkloadCAS(ctx, "release-intent", release.OwnershipToken, release.Attempt); err == nil {
		t.Fatal("injected release failure was swallowed")
	}
	releaseRow, _ := base.GetWorkload(ctx, "release-intent")
	if releaseRow.BudgetCleanupToken != release.OwnershipToken || releaseRow.BudgetReservationToken != release.OwnershipToken {
		t.Fatalf("cleanup intent did not retain exact published linkage: %+v", releaseRow)
	}
	if err := releaseManager.retryBudgetCleanupIntent(ctx, releaseRow); err != nil {
		t.Fatal(err)
	}
	releaseRow, _ = base.GetWorkload(ctx, "release-intent")
	if releaseRow.BudgetCleanupToken != "" || releaseRow.BudgetReservationToken != "" {
		t.Fatalf("cleanup intent remained after successful retry: %+v", releaseRow)
	}
}

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
	victim, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "preempt", ItemID: "victim", Payload: json.RawMessage(`{}`), Priority: 1, Recoverable: true, Disruption: domain.DisruptionCheckpointable, InterruptionConsent: true})
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

func TestCheckpointableVictimWithoutInterruptionConsentCannotBePreempted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
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
		t.Fatal("victim never reached a running state")
	}
	urgent, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "preempt", ItemID: "urgent-no-consent", Payload: json.RawMessage(`{}`), QoS: domain.QoSInteractive, Priority: 100, Disruption: domain.DisruptionLocked, PreemptionBudget: 1})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, getErr := mgr.Get(ctx, urgent.Request.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	after, _ := mgr.Get(ctx, victim.Request.ID)
	if after.PreemptionCount != 0 || after.Status != domain.WorkloadRunning {
		t.Fatalf("no-consent victim changed state: %+v", after)
	}
}

type preemptionStopTestAdapter struct {
	checkpointTestAdapter
	name       string
	cancelErr  error
	cancelCall int
	cancelled  *domain.ExecutionHandle
	cancelTo   Target
}

func (a *preemptionStopTestAdapter) Name() string { return a.name }
func (a *preemptionStopTestAdapter) Cancel(_ context.Context, handle *domain.ExecutionHandle, target Target) error {
	a.cancelCall++
	a.cancelled = handle
	a.cancelTo = target
	return a.cancelErr
}

func seedPreemptionStopFixture(t *testing.T, cancelErr error, plan *domain.ExecutionPlan) (*Manager, *store.MemoryStore, *preemptionStopTestAdapter, *domain.Workload, *domain.Workload, *domain.AcceleratorLease, Target) {
	t.Helper()
	ctx := context.Background()
	const (
		adapterName = "preemption-stop-test"
		targetID    = "preemption-stop-target"
		accelerator = "preemption-stop-accelerator"
		victimID    = "preemption-stop-victim"
		newcomerID  = "preemption-stop-newcomer"
	)
	backing := store.NewMemoryStore()
	adapter := &preemptionStopTestAdapter{name: adapterName, cancelErr: cancelErr}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(adapter)
	target := Target{ID: targetID, Adapter: adapterName, AcceleratorID: accelerator, Slots: 1, Enabled: true}
	mgr.RegisterTarget(target)
	if plan != nil {
		plan.TargetID = targetID
	}
	now := time.Now().UTC()
	handle := &domain.ExecutionHandle{ExternalID: "exact-preemption-stop-handle", StartedAt: now}
	victim, _, err := backing.CreateWorkload(ctx, &domain.Workload{
		Request: domain.WorkloadRequest{ID: victimID, OwnerID: "preemption-stop-owner", Adapter: adapterName, Priority: 1, Disruption: domain.DisruptionCancelable},
		Status:  domain.WorkloadRunning, Plan: plan, Execution: handle, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, acquired, err := backing.AcquireAcceleratorLease(ctx, accelerator, victimID, time.Minute)
	if err != nil || !acquired || lease == nil {
		t.Fatalf("seed exact victim accelerator lease: lease=%+v acquired=%t err=%v", lease, acquired, err)
	}
	mgr.placementMu.Lock()
	mgr.targetLeases[targetID] = lease
	mgr.targetActive[targetID] = 1
	mgr.activePlacements[victimID] = activePlacement{workloadID: victimID, targetID: targetID, acceleratorID: accelerator, disruption: domain.DisruptionCancelable}
	mgr.placementMu.Unlock()
	newcomer, _, err := backing.CreateWorkload(ctx, &domain.Workload{
		Request: domain.WorkloadRequest{ID: newcomerID, OwnerID: "preemption-stop-owner", Adapter: adapterName, Priority: 80, Disruption: domain.DisruptionLocked, PreemptionBudget: 1},
		Status:  domain.WorkloadWaiting, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mgr, backing, adapter, victim, newcomer, lease, target
}

func TestPreemptionNilPlanVictimIgnoredWithoutMutation(t *testing.T) {
	ctx := context.Background()
	mgr, backing, adapter, victim, newcomer, lease, target := seedPreemptionStopFixture(t, nil, nil)
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		if mgr.tryPreempt(ctx, newcomer, target) {
			t.Error("nil-plan victim guard assertion: tryPreempt unexpectedly accepted a victim without a plan")
		}
	}()
	if panicked != nil {
		t.Fatalf("nil-plan victim guard assertion: tryPreempt panicked on a victim with no plan: %v", panicked)
	}
	got, err := backing.GetWorkload(ctx, victim.Request.ID)
	if err != nil || got.Status != domain.WorkloadRunning || got.Plan != nil || got.Execution == nil || got.Execution.ExternalID != "exact-preemption-stop-handle" || got.PreemptionCount != 0 {
		t.Fatalf("nil-plan victim guard assertion: victim changed: workload=%+v err=%v", got, err)
	}
	currentLease, err := backing.GetAcceleratorLease(ctx, lease.AcceleratorID)
	if err != nil || currentLease.WorkloadID != victim.Request.ID || currentLease.FencingToken != lease.FencingToken {
		t.Fatalf("nil-plan victim guard assertion: durable lease changed: lease=%+v err=%v", currentLease, err)
	}
	mgr.placementMu.Lock()
	placement, placed := mgr.activePlacements[victim.Request.ID]
	active := mgr.targetActive[target.ID]
	managerLease := mgr.targetLeases[target.ID]
	mgr.placementMu.Unlock()
	if !placed || placement.targetID != target.ID || active != 1 || managerLease == nil || managerLease.FencingToken != lease.FencingToken {
		t.Fatalf("nil-plan victim guard assertion: in-memory placement changed: placement=%+v placed=%t active=%d lease=%+v", placement, placed, active, managerLease)
	}
	if newcomer.Status != domain.WorkloadWaiting || newcomer.PreemptionsInitiated != 0 || adapter.cancelCall != 0 {
		t.Fatalf("nil-plan victim guard assertion: newcomer or backend changed: newcomer=%+v cancel_calls=%d", newcomer, adapter.cancelCall)
	}
	plans, err := backing.ListTransitionPlans(ctx, newcomer.Request.ID, 10)
	if err != nil || len(plans) != 0 {
		t.Fatalf("nil-plan victim guard assertion: transition plans were created: plans=%+v err=%v", plans, err)
	}
}

func TestPreemptionCancelableRequiresConfirmedStop(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "unsupported", err: ErrUnsupported},
		{name: "other error", err: errors.New("node cancel response lost")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mgr, backing, adapter, victim, newcomer, lease, target := seedPreemptionStopFixture(t, tc.err, &domain.ExecutionPlan{})
			if mgr.tryPreempt(ctx, newcomer, target) {
				if tc.name == "unsupported" {
					t.Fatal("cancel stop confirmation assertion: unsupported cancellation was treated as confirmed")
				}
				t.Fatalf("cancel stop confirmation assertion: %s cancellation was treated as confirmed", tc.name)
			}
			if adapter.cancelCall != 1 || adapter.cancelled == nil || adapter.cancelled.ExternalID != victim.Execution.ExternalID || adapter.cancelTo.ID != target.ID || adapter.cancelTo.AcceleratorID != target.AcceleratorID {
				t.Fatalf("cancel stop confirmation assertion: exact cancellation call missing: calls=%d handle=%+v target=%+v", adapter.cancelCall, adapter.cancelled, adapter.cancelTo)
			}
			got, err := backing.GetWorkload(ctx, victim.Request.ID)
			if err != nil || got.Status != domain.WorkloadRunning || got.Execution == nil || got.Execution.ExternalID != victim.Execution.ExternalID || got.PreemptionCount != 0 || len(got.TransitionPlanIDs) != 0 {
				t.Fatalf("cancel stop confirmation assertion: victim changed without stop proof: workload=%+v err=%v", got, err)
			}
			currentLease, err := backing.GetAcceleratorLease(ctx, lease.AcceleratorID)
			if err != nil || currentLease.WorkloadID != victim.Request.ID || currentLease.FencingToken != lease.FencingToken {
				t.Fatalf("cancel stop confirmation assertion: durable lease changed: lease=%+v err=%v", currentLease, err)
			}
			mgr.placementMu.Lock()
			placement, placed := mgr.activePlacements[victim.Request.ID]
			active := mgr.targetActive[target.ID]
			managerLease := mgr.targetLeases[target.ID]
			mgr.placementMu.Unlock()
			if !placed || placement.targetID != target.ID || active != 1 || managerLease == nil || managerLease.FencingToken != lease.FencingToken {
				t.Fatalf("cancel stop confirmation assertion: in-memory placement changed: placement=%+v placed=%t active=%d lease=%+v", placement, placed, active, managerLease)
			}
			if newcomer.Status != domain.WorkloadWaiting || newcomer.PreemptionsInitiated != 0 || len(newcomer.TransitionPlanIDs) != 0 {
				t.Fatalf("cancel stop confirmation assertion: newcomer admission changed: %+v", newcomer)
			}
			plans, err := backing.ListTransitionPlans(ctx, newcomer.Request.ID, 10)
			if err != nil || len(plans) != 1 || plans[0].Status != domain.TransitionPlanFailed || !strings.Contains(plans[0].Error, "backend stop unconfirmed") {
				t.Fatalf("cancel stop confirmation assertion: failed transition was not recorded: plans=%+v err=%v", plans, err)
			}
		})
	}

	// Keep a live-manager positive control: confirmed cancellation must still
	// release its exact victim placement and let the waiting newcomer execute.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	adapter := &preemptionStopTestAdapter{name: "preemption-stop-positive"}
	mgr := NewManager(quietLogger(), backing, 200*time.Millisecond)
	mgr.RegisterAdapter(adapter)
	target := Target{ID: "preemption-stop-positive-target", Adapter: adapter.Name(), AcceleratorID: "preemption-stop-positive-gpu", Slots: 1, Enabled: true}
	mgr.RegisterTarget(target)
	mgr.Start(ctx)
	victim, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "positive-owner", Adapter: adapter.Name(), ItemID: "victim", Payload: json.RawMessage(`{}`), Priority: 1, Disruption: domain.DisruptionCancelable})
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
	if victim.Status != domain.WorkloadRunning || victim.Execution == nil {
		t.Fatalf("cancel positive control: victim never started: %+v", victim)
	}
	newcomer, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "positive-owner", Adapter: adapter.Name(), ItemID: "newcomer", Payload: json.RawMessage(`{}`), QoS: domain.QoSInteractive, Priority: 80, Disruption: domain.DisruptionLocked, PreemptionBudget: 1})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 4*time.Second)
	defer waitCancel()
	newcomer, err = mgr.Wait(waitCtx, newcomer.Request.ID)
	if err != nil || newcomer.Status != domain.WorkloadSucceeded {
		t.Fatalf("cancel positive control: newcomer did not execute after confirmed victim stop: workload=%+v err=%v", newcomer, err)
	}
	victim, err = mgr.Get(ctx, victim.Request.ID)
	if err != nil || victim.Status != domain.WorkloadCancelled || victim.PreemptionCount != 1 {
		t.Fatalf("cancel positive control: victim did not terminalize after confirmed stop: workload=%+v err=%v", victim, err)
	}
	if adapter.cancelCall < 1 || adapter.cancelled == nil || adapter.cancelTo.ID != target.ID {
		t.Fatalf("cancel positive control: exact stop was not confirmed: calls=%d handle=%+v target=%+v", adapter.cancelCall, adapter.cancelled, adapter.cancelTo)
	}
	mgr.placementMu.Lock()
	_, stillPlaced := mgr.activePlacements[victim.Request.ID]
	active := mgr.targetActive[target.ID]
	managerLease := mgr.targetLeases[target.ID]
	mgr.placementMu.Unlock()
	lease, leaseErr := backing.GetAcceleratorLease(ctx, target.AcceleratorID)
	if stillPlaced || active != 0 || managerLease != nil || !errors.Is(leaseErr, store.ErrNotFound) || lease != nil {
		t.Fatalf("cancel positive control: victim capacity was not released: placed=%t active=%d manager_lease=%+v durable_lease=%+v lease_err=%v", stillPlaced, active, managerLease, lease, leaseErr)
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
	target := Target{
		ID: "llm", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"model"},
		ContextLimit: 8192, Slots: 1, ActiveRuntimeProfile: "stream-profile",
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "stream-profile", ContextLimit: 8192, Slots: 1}},
		CapabilityVersion: "stream-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelFingerprint: "stream-model-fp",
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 8 << 30},
		CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
	}
	mgr.RegisterTarget(target)
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(mgr.targetByID(target.ID), "model", 2<<30, 1<<30)); err != nil {
		t.Fatalf("seed bounded stream model/profile capacity: %v", err)
	}
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

func TestRunStreamCloseWaitsForExecutionUnwind(t *testing.T) {
	streamStarted := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"chunk\"}\n\n")
		w.(http.Flusher).Flush()
		close(streamStarted)
		<-r.Context().Done()
	}))
	defer backend.Close()

	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, 150*time.Millisecond)
	mgr.RegisterAdapter(NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	target := Target{
		ID: "llm-close", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-close", Models: []string{"model"},
		ContextLimit: 8192, Slots: 1, ActiveRuntimeProfile: "stream-profile",
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "stream-profile", ContextLimit: 8192, Slots: 1}},
		CapabilityVersion: "stream-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelFingerprint: "stream-model-fp",
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 8 << 30},
		CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
	}
	mgr.RegisterTarget(target)
	if _, err := mgr.SetModelCapacity(context.Background(), measuredCapacityWithProfile(mgr.targetByID(target.ID), "model", 2<<30, 1<<30)); err != nil {
		t.Fatalf("seed bounded close-stream model/profile capacity: %v", err)
	}
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(rootCtx)
	stream, _, err := mgr.Submit(rootCtx, domain.WorkloadRequest{OwnerID: "u", Adapter: "llamacpp", Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hi"}],"stream":true}`), InteractiveStream: true})
	if err != nil || stream.Status != domain.WorkloadRunning {
		t.Fatalf("stream admission: %+v err=%v", stream, err)
	}
	runDone := make(chan error, 1)
	go func() {
		_, runErr := mgr.RunStream(context.Background(), stream.Request.ID, func([]byte) error { return nil })
		runDone <- runErr
	}()
	select {
	case <-streamStarted:
	case <-time.After(time.Second):
		t.Fatal("stream backend did not start")
	}
	closeDone := make(chan struct{})
	go func() {
		mgr.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("manager Close returned before stream execution unwound")
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("RunStream remained active after manager Close")
	}
}

func TestPendingStreamTimerStopFalseRetainsCloseOwnership(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	if !mgr.trackAsync() {
		t.Fatal("manager did not accept timer ownership")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	pending := &pendingStream{}
	pending.timer = time.AfterFunc(time.Millisecond, func() {
		close(entered)
		<-release
		pending.timerDone.Do(mgr.untrackAsync)
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("timer callback did not start")
	}
	if pending.timer.Stop() {
		t.Fatal("Stop unexpectedly reported an executing callback as stopped")
	}
	mgr.stopPendingStreamTimer(pending)
	closeDone := make(chan struct{})
	go func() {
		mgr.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("Close returned while the fired timer callback still owned async work")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after timer callback released ownership")
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

type modelAwareMockAdapter struct{ *MockAdapter }

type blockedLeaseStore struct {
	store.WorkloadStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type failingReleaseLeaseStore struct{ *blockedLeaseStore }

type countingReleaseLeaseStore struct {
	store.WorkloadStore
	failures int
	calls    int
}

type countingReleaseMemoryStore struct {
	*store.MemoryStore
	failures int
	calls    int
}

type failingCleanupIntentStore struct{ store.WorkloadStore }

func (s *failingCleanupIntentStore) RecordAcceleratorLeaseCleanupIntent(context.Context, *domain.AcceleratorLeaseCleanupIntent) (*domain.AcceleratorLeaseCleanupIntent, error) {
	return nil, errors.New("injected cleanup intent persistence failure")
}

type contextCheckingReleaseStore struct{ store.WorkloadStore }

func (s *contextCheckingReleaseStore) ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.WorkloadStore.ReleaseAcceleratorLease(ctx, acceleratorID, workloadID, fencingToken)
}

func (s *failingReleaseLeaseStore) ReleaseAcceleratorLease(context.Context, string, string, int64) error {
	return errors.New("injected lease release failure")
}

func (s *countingReleaseLeaseStore) ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error {
	s.calls++
	if s.calls <= s.failures {
		return errors.New("injected counted lease release failure")
	}
	return s.WorkloadStore.ReleaseAcceleratorLease(ctx, acceleratorID, workloadID, fencingToken)
}

func (s *countingReleaseMemoryStore) ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error {
	s.calls++
	if s.calls <= s.failures {
		return errors.New("injected counted lease release failure")
	}
	return s.MemoryStore.ReleaseAcceleratorLease(ctx, acceleratorID, workloadID, fencingToken)
}

func (s *blockedLeaseStore) AcquireAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.release:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	return s.WorkloadStore.AcquireAcceleratorLease(ctx, acceleratorID, workloadID, ttl)
}

func (modelAwareMockAdapter) Name() string { return "model-mock" }
func (modelAwareMockAdapter) Requirements(_ context.Context, req domain.WorkloadRequest) (Requirements, error) {
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return Requirements{}, err
	}
	return Requirements{Model: payload.Model, ContextTokens: req.Bounds.ContextTokens + req.Bounds.MaxOutput, AcceleratorRequired: true}, nil
}

func TestRuntimeProfileSchedulerSwitchesIdleTargetToSmallestSufficientProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	// These bounded byte values are synthetic in-process fixture data, not GPU measurements.
	const (
		fixturePhysicalBytes               int64 = 8 << 30
		fixtureModelBytes                  int64 = 3 << 30
		fixtureInitializedProfilePoolBytes int64 = 2 << 30
	)
	fixtureEnvelope := domain.CapacityBudget{VRAMTotalBytes: fixturePhysicalBytes, VRAMHardCapBytes: fixturePhysicalBytes}
	if _, err := backing.UpsertNode(ctx, &domain.Node{
		ID: "node", SchedulingState: domain.SchedulingEnabled,
		Desired:      domain.Desired{SchedulingEnabled: true},
		Observed:     domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now},
		Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 24_000, VRAMFreeMB: 24_000}},
	}); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	mgr.SetNodeStore(backing)
	adapter := modelAwareMockAdapter{NewMockAdapter()}
	if _, hasIncrementObserver := interface{}(adapter).(RequestVRAMIncrementObserver); hasIncrementObserver {
		t.Fatal("profile-switch mock must not claim a measured per-request increment")
	}
	mgr.RegisterAdapter(adapter)
	registered := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "model-mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", Models: []string{"model"}, ResidentModels: []string{"model"},
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", SupportsRuntimeProfileSwitch: true, Enabled: true,
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp", CapacitySource: "runtime:/slots", CapacityVerified: true,
		Capacity: fixtureEnvelope,
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}},
	}
	mgr.RegisterTarget(registered)
	projectedCapacityTarget := mgr.targetByID(registered.ID)
	projectedCapacityTarget.ActiveRuntimeProfile = "ctx-32k"
	projectedCapacityTarget.ContextLimit = 32768
	projectedCapacityTarget.Slots = 1
	projectedCapacityTarget.CapacitySource = "runtime:/slots"
	projectedCapacityTarget.CapacityVerified = true
	fixtureCapacity := measuredCapacityWithProfile(projectedCapacityTarget, "model", fixtureModelBytes, fixtureInitializedProfilePoolBytes)
	storedFixtureCapacity, err := backing.UpsertModelCapacity(ctx, &fixtureCapacity)
	if err != nil {
		t.Fatalf("seed synthetic ctx32k initialized-pool fixture capacity: %v", err)
	}
	if storedFixtureCapacity == nil || storedFixtureCapacity.ModelBytes != fixtureModelBytes || storedFixtureCapacity.FootprintBytes() != fixtureModelBytes+fixtureInitializedProfilePoolBytes ||
		storedFixtureCapacity.ProfileBytes != fixtureInitializedProfilePoolBytes || storedFixtureCapacity.VRAMTotalBytes != fixturePhysicalBytes || storedFixtureCapacity.RuntimeHardCapBytes != fixturePhysicalBytes {
		t.Fatalf("synthetic fixture model/pool capacity or physical envelope is inconsistent: %+v", storedFixtureCapacity)
	}
	var commands int
	mgr.SetNodeControl(func(_ context.Context, nodeID, command string, args map[string]any, _ string) (map[string]any, error) {
		commands++
		if nodeID != "node" || command != "switch_runtime_profile" || args["target_id"] != "node-runtime" || args["profile_id"] != "ctx-32k" {
			t.Fatalf("unexpected profile command: node=%q command=%q args=%+v", nodeID, command, args)
		}
		if fence, ok := args["fencing_token"].(int64); !ok || fence <= 0 {
			t.Fatalf("profile switch lacks the fencing token the node requires: %+v", args)
		}
		return map[string]any{"adapters": []any{map[string]any{
			"id": "runtime", "adapter": "model-mock", "endpoint": "http://runtime", "accelerator_index": 0,
			"version": "runtime-v1", "model_fingerprint": "model-fp", "capability_version": "runtime-v1", "capability_revision": "cap-v1",
			"context_limit": 32768, "slots": 1, "capacity_source": "runtime:/slots", "capabilities_verified": true, "active_runtime_profile": "ctx-32k",
			"runtime_profiles": []any{map[string]any{"id": "ctx-8k", "context_limit": 8192, "slots": 4}, map[string]any{"id": "ctx-32k", "context_limit": 32768, "slots": 1}},
		}}}, nil
	})
	mgr.Start(ctx)
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{
		OwnerID: "owner", Adapter: "model-mock", Payload: json.RawMessage(`{"model":"model"}`),
		Bounds: domain.WorkloadBounds{ContextTokens: 30_000, MaxOutput: 1_000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if commands != 1 || (row.Status != domain.WorkloadRunning && row.Status != domain.WorkloadSucceeded) || row.Decision.ContextLimit != 32768 || row.Decision.TargetSlots != 1 {
		t.Fatalf("idle runtime was not switched and admitted with confirmed capacity: commands=%d row=%+v", commands, row)
	}
	var projected Target
	for _, current := range mgr.Targets() {
		if current.ID == registered.ID {
			projected = current
			break
		}
	}
	if projected.ID == "" || projected.ActiveRuntimeProfile != "ctx-32k" || projected.ContextLimit != 32768 || projected.Slots != 1 ||
		projected.CapacitySource != "runtime:/slots" || !projected.CapacityVerified || projected.Capacity != fixtureEnvelope ||
		mgr.targetGeneration(projected.ID) == 0 {
		t.Fatalf("projected target is not bound to the exact ctx32k runtime profile and synthetic physical envelope: %+v", projected)
	}
	ctx32ProfileCount := 0
	for _, profile := range projected.RuntimeProfiles {
		if profile.ID == "ctx-32k" && profile.ContextLimit == 32768 && profile.Slots == 1 {
			ctx32ProfileCount++
		}
	}
	if ctx32ProfileCount != 1 {
		t.Fatalf("projected runtime profile catalog is not uniquely bound to ctx32k/32768/1: %+v", projected.RuntimeProfiles)
	}
	currentCapacity, err := backing.GetModelCapacity(ctx, projected.ID, "model", projected.ActiveRuntimeProfile)
	if err != nil || currentCapacity == nil || currentCapacity.ModelBytes != fixtureModelBytes || currentCapacity.ProfileBytes != fixtureInitializedProfilePoolBytes ||
		currentCapacity.FootprintBytes() != fixtureModelBytes+fixtureInitializedProfilePoolBytes || !currentCapacity.Verified || currentCapacity.CapacitySource != "runtime:test" ||
		currentCapacity.AcceleratorID != projected.AcceleratorID || currentCapacity.ProfileID != projected.ActiveRuntimeProfile ||
		currentCapacity.RuntimeIdentity != residencyCapacityIdentity(projected) || currentCapacity.ModelFingerprint != projected.ModelFingerprint ||
		currentCapacity.CapabilityVersion != projected.CapabilityVersion || currentCapacity.CapabilityRevision != projected.CapabilityRevision ||
		currentCapacity.VRAMTotalBytes != fixturePhysicalBytes || currentCapacity.RuntimeHardCapBytes != fixturePhysicalBytes ||
		validateCapacityBinding(currentCapacity, projected, time.Now().UTC()) != nil {
		t.Fatalf("current measured model/profile capacity is not exactly bound to the projected target: capacity=%+v err=%v", currentCapacity, err)
	}
	mgr.placementMu.Lock()
	activePlacement, requestStillActive := mgr.activePlacements[row.Request.ID]
	mgr.placementMu.Unlock()
	if requestStillActive && (activePlacement.targetID != projected.ID || activePlacement.targetGeneration != mgr.targetGeneration(projected.ID) ||
		activePlacement.profileID != projected.ActiveRuntimeProfile || activePlacement.runtimeIdentity != residencyCapacityIdentity(projected) ||
		activePlacement.requestIncrementVerified || activePlacement.requestIncrementBytes != 0) {
		t.Fatalf("active profile-switch request lost its current binding or fabricated a measured increment: %+v", activePlacement)
	}
}

func runtimeProfileProjectionFixture(t *testing.T) (*Manager, Target, *runtimeProfileTransition) {
	t.Helper()
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	target := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	manager.RegisterTarget(target)
	target = manager.targetByID(target.ID)
	transition, _, err := manager.beginRuntimeProfileTransition(target, target.RuntimeProfiles[1], "node", manager.targetGeneration(target.ID))
	if err != nil {
		t.Fatal(err)
	}
	return manager, target, transition
}

func runtimeProfileProjectionResult(target Target) map[string]any {
	return runtimeProfileProjectionResultFor(target, RuntimeCapacityProfile{ID: "ctx-32k", ContextLimit: 32768, Slots: 1})
}

func runtimeProfileProjectionResultFor(target Target, profile RuntimeCapacityProfile) map[string]any {
	adapterID := target.ID
	if target.NodeID != "" {
		adapterID = strings.TrimPrefix(adapterID, target.NodeID+"-")
	}
	acceleratorIndex := 0
	if target.NodeID != "" {
		indexText := strings.TrimPrefix(target.AcceleratorID, target.NodeID+"-gpu")
		if parsed, err := strconv.Atoi(indexText); err == nil {
			acceleratorIndex = parsed
		}
	}
	profiles := make([]any, 0, len(target.RuntimeProfiles))
	for _, advertised := range target.RuntimeProfiles {
		profiles = append(profiles, map[string]any{"id": advertised.ID, "context_limit": advertised.ContextLimit, "slots": advertised.Slots})
	}
	return map[string]any{"adapters": []any{map[string]any{
		"id": adapterID, "adapter": target.Adapter, "endpoint": target.Endpoint, "accelerator_index": acceleratorIndex,
		"version": target.RuntimeIdentity, "model_fingerprint": target.ModelFingerprint,
		"capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision,
		"context_limit": profile.ContextLimit, "slots": profile.Slots, "capacity_source": "runtime:/slots", "capabilities_verified": true,
		"active_runtime_profile": profile.ID, "runtime_profiles": profiles,
	}}}
}

func TestRuntimeProfileTransitionRejectsInsufficientGenerationSpace(t *testing.T) {
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer manager.Close()
	target := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	manager.RegisterTarget(target)
	target = manager.targetByID(target.ID)
	manager.mu.Lock()
	manager.targetGenerations[target.ID] = ^uint64(0) - 1
	manager.mu.Unlock()
	if _, _, err := manager.beginRuntimeProfileTransition(target, target.RuntimeProfiles[1], "node", ^uint64(0)-1); err == nil || !strings.Contains(err.Error(), "complete switch") {
		t.Fatalf("profile transition began without room for its pending and projected generation fences: %v", err)
	}
	if current := manager.targetByID(target.ID); !current.CapacityVerified || current.CapacitySource != "runtime:/slots" || current.ActiveRuntimeProfile != "ctx-8k" {
		t.Fatalf("rejected profile transition changed published capacity: %+v", current)
	}
	manager.mu.RLock()
	transitionCount := len(manager.runtimeProfileTransitions)
	manager.mu.RUnlock()
	if transitionCount != 0 || manager.targetGeneration(target.ID) != ^uint64(0)-1 {
		t.Fatalf("rejected profile transition left ticket/generation side effects: transitions=%d generation=%d", transitionCount, manager.targetGeneration(target.ID))
	}
}

func TestRuntimeProfileSwitchRequiresObservedSlotsEvidence(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any) map[string]any
	}{
		{name: "profile id only", mutate: func(map[string]any) map[string]any { return map[string]any{"profile_id": "ctx-32k"} }},
		{name: "missing adapters", mutate: func(map[string]any) map[string]any { return map[string]any{} }},
		{name: "unverified", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["capabilities_verified"] = false
			return result
		}},
		{name: "fallback source", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["capacity_source"] = "config"
			return result
		}},
		{name: "wrong route", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["endpoint"] = "http://other"
			return result
		}},
		{name: "wrong accelerator", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["accelerator_index"] = 1
			return result
		}},
		{name: "missing accelerator index", mutate: func(result map[string]any) map[string]any {
			delete(result["adapters"].([]any)[0].(map[string]any), "accelerator_index")
			return result
		}},
		{name: "negative accelerator index", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["accelerator_index"] = -1
			return result
		}},
		{name: "missing adapter identity", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["adapter"] = ""
			return result
		}},
		{name: "missing endpoint identity", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["endpoint"] = ""
			return result
		}},
		{name: "wrong context", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["context_limit"] = 16384
			return result
		}},
		{name: "wrong slots", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["slots"] = 2
			return result
		}},
		{name: "wrong profile", mutate: func(result map[string]any) map[string]any {
			result["adapters"].([]any)[0].(map[string]any)["active_runtime_profile"] = "ctx-8k"
			return result
		}},
		{name: "duplicate target observation", mutate: func(result map[string]any) map[string]any {
			adapters := result["adapters"].([]any)
			result["adapters"] = append(adapters, adapters[0])
			return result
		}},
		{name: "duplicate profile observation", mutate: func(result map[string]any) map[string]any {
			ad := result["adapters"].([]any)[0].(map[string]any)
			profiles := ad["runtime_profiles"].([]any)
			ad["runtime_profiles"] = append(profiles, profiles[1])
			return result
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			manager, target, transition := runtimeProfileProjectionFixture(t)
			defer manager.Close()
			if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", test.mutate(runtimeProfileProjectionResult(target))); err == nil {
				t.Fatal("unbound or incomplete runtime slot observation was accepted")
			}
			pending := manager.targetByID(target.ID)
			if pending.CapacityVerified || pending.CapacitySource != "runtime-profile:pending" || pending.ContextLimit != 0 || pending.Slots != 0 {
				t.Fatalf("rejected observation exposed capacity: %+v", pending)
			}
		})
	}
}

func TestRuntimeProfilePendingRevokesOldVerifiedSlots(t *testing.T) {
	manager, target, _ := runtimeProfileProjectionFixture(t)
	defer manager.Close()
	pending := manager.targetByID(target.ID)
	if pending.CapacityVerified || pending.ContextLimit != 0 || pending.Slots != 0 || pending.CapacitySource != "runtime-profile:pending" || len(pending.RuntimeProfiles) != 2 || pending.MaxAcceleratorsPerWorkload != 1 {
		t.Fatalf("pending transition retained old verified capacity: %+v", pending)
	}
	if got := manager.availableSlots(target); got != 0 {
		t.Fatalf("pending profile still exposed %d slots", got)
	}
	if got := manager.CurrentlyAvailableSlotsForModel(context.Background(), pending, "model"); got != 0 {
		t.Fatalf("pending profile advertised %d available slots", got)
	}
	_, acquired, reason, err := manager.reserveTarget(context.Background(), pending, &domain.Workload{Request: domain.WorkloadRequest{ID: "pending-work"}}, Requirements{})
	if err != nil || acquired || !strings.Contains(reason, "awaiting observed capacity") {
		t.Fatalf("pending profile entered admission: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
}

func TestRuntimeProfileUnresolvedTicketBlocksSecondPhysicalSwitch(t *testing.T) {
	manager, target, transition := runtimeProfileProjectionFixture(t)
	defer manager.Close()

	pending := manager.targetByID(target.ID)
	if _, _, err := manager.beginRuntimeProfileTransition(pending, pending.RuntimeProfiles[0], "node", manager.targetGeneration(target.ID)); err == nil || !strings.Contains(err.Error(), "observation_unavailable") {
		t.Fatalf("unresolved profile switch was replaced: transition=%+v err=%v", transition, err)
	}
	manager.mu.RLock()
	key := manager.runtimeProfileTransitionTarget[target.ID]
	retained := manager.runtimeProfileTransitions[key]
	manager.mu.RUnlock()
	current := manager.targetByID(target.ID)
	if key != transition.commandKey || retained != transition || current.CapacityVerified || current.Slots != 0 || current.ContextLimit != 0 {
		t.Fatalf("unresolved ticket or conservative capacity changed: key=%q retained=%p want=%p target=%+v", key, retained, transition, current)
	}
	manager.RegisterTarget(target)
	current = manager.targetByID(target.ID)
	manager.mu.RLock()
	retained = manager.runtimeProfileTransitions[manager.runtimeProfileTransitionTarget[target.ID]]
	manager.mu.RUnlock()
	if retained != transition || current.CapacityVerified || current.Slots != 0 || current.ContextLimit != 0 {
		t.Fatalf("unlinked registration cleared unresolved profile uncertainty: retained=%p want=%p target=%+v", retained, transition, current)
	}
}

func TestRuntimeProfileDispatchFenceRequiresExactOriginatingTicket(t *testing.T) {
	manager, target, transition := runtimeProfileProjectionFixture(t)
	defer manager.Close()
	args := map[string]any{"target_id": target.ID, "profile_id": transition.profile.ID}
	if !manager.RuntimeProfileDispatchAllowed("node", target.ID, args, transition.commandKey) {
		t.Fatal("originating manager switch could not pass its exact retained ticket")
	}
	if !manager.RuntimeProfileDispatchAllowed("node", target.ID, args, transition.commandKey) {
		t.Fatal("same-key exact ticket replay was not idempotently authorized")
	}
	if manager.RuntimeProfileDispatchAllowed("node", target.ID, args, "unrelated-http-key") {
		t.Fatal("unrelated HTTP/scheduler key bypassed the pending manager ticket")
	}
	aliasArgs := map[string]any{"target_id": "node-alias", "profile_id": transition.profile.ID}
	if manager.RuntimeProfileDispatchAllowed("node", "node-alias", aliasArgs, transition.commandKey) {
		t.Fatal("different route reused the originating ticket")
	}
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", runtimeProfileProjectionResult(target)); err != nil {
		t.Fatal(err)
	}
	if manager.RuntimeProfileDispatchAllowed("node", target.ID, args, transition.commandKey) {
		t.Fatal("retired projected ticket remained valid for a new physical dispatch")
	}
	withoutTicket := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer withoutTicket.Close()
	withoutTicket.RegisterTarget(target)
	if withoutTicket.RuntimeProfileDispatchAllowed("node", target.ID, args, "raw-http-key") {
		t.Fatal("direct switch without a current scheduler ticket was allowed")
	}
}

func TestRuntimeProfileDispatchClaimExcludesRetirementAndRouteReplacement(t *testing.T) {
	t.Run("retirement waits for claimed physical dispatch", func(t *testing.T) {
		manager, target, transition := runtimeProfileProjectionFixture(t)
		defer manager.Close()
		args := map[string]any{"target_id": target.ID, "profile_id": transition.profile.ID}
		release, err := manager.ClaimRuntimeProfileDispatch("node", target.ID, args, transition.commandKey)
		if err != nil {
			t.Fatal(err)
		}
		retired := make(chan struct{})
		go func() { manager.ReconcileNodeTargets("node", map[string]struct{}{}); close(retired) }()
		time.Sleep(20 * time.Millisecond)
		if got := manager.targetByID(target.ID); got.ID == "" {
			t.Fatal("target retired while the exact physical dispatch claim was held")
		}
		release()
		select {
		case <-retired:
		case <-time.After(time.Second):
			t.Fatal("target retirement did not resume after dispatch claim release")
		}
		if got := manager.targetByID(target.ID); got.ID != "" {
			t.Fatalf("target remained live after authorized retirement: %+v", got)
		}
	})
	t.Run("route replacement waits for claimed physical dispatch", func(t *testing.T) {
		manager, target, transition := runtimeProfileProjectionFixture(t)
		defer manager.Close()
		args := map[string]any{"target_id": target.ID, "profile_id": transition.profile.ID}
		release, err := manager.ClaimRuntimeProfileDispatch("node", target.ID, args, transition.commandKey)
		if err != nil {
			t.Fatal(err)
		}
		replacement := target
		replacement.Endpoint = "http://replacement-route"
		registered := make(chan struct{})
		go func() { manager.RegisterTarget(replacement); close(registered) }()
		time.Sleep(20 * time.Millisecond)
		if got := manager.targetByID(target.ID); got.Endpoint != target.Endpoint {
			t.Fatalf("new route identity committed while old physical dispatch was claimed: %+v", got)
		}
		release()
		select {
		case <-registered:
		case <-time.After(time.Second):
			t.Fatal("route registration did not resume after dispatch claim release")
		}
		if got := manager.targetByID(target.ID); got.Endpoint != target.Endpoint {
			t.Fatalf("route replacement published during unresolved physical dispatch: %+v", got)
		}
		if !manager.RuntimeProfileDispatchAllowed("node", target.ID, args, transition.commandKey) {
			t.Fatal("discarded route refresh invalidated the still-current exact ticket")
		}
	})
}

func TestRuntimeProfileUnknownEffectQuarantinesAlreadyRegisteredCardAliases(t *testing.T) {
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer manager.Close()
	primary := Target{
		ID: "node-a-runtime", NodeID: "node-a", Adapter: "mock", Endpoint: "http://runtime-a", AcceleratorID: "node-a-gpu0",
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	alias := primary
	alias.ID = "node-b-runtime-alias"
	alias.NodeID = "node-b"
	alias.Endpoint = "http://runtime-b"
	manager.RegisterTarget(primary)
	manager.RegisterTarget(alias)
	primary = manager.targetByID(primary.ID)
	alias = manager.targetByID(alias.ID)
	transition, _, err := manager.beginRuntimeProfileTransition(primary, primary.RuntimeProfiles[1], primary.NodeID, manager.targetGeneration(primary.ID))
	if err != nil {
		t.Fatal(err)
	}
	if got := manager.CurrentlyAvailableSlotsForModel(context.Background(), alias, "model"); got != 0 {
		t.Fatalf("already-registered alias exposed %d slots after physical switch became uncertain", got)
	}
	if got := manager.availableSlots(alias); got != 0 {
		t.Fatalf("already-registered alias exposed %d internal slots after physical switch became uncertain", got)
	}
	for _, exposed := range manager.Targets() {
		if exposed.ID == alias.ID && (exposed.CapacityVerified || exposed.Slots != 0 || exposed.ContextLimit != 0) {
			t.Fatalf("scheduler-facing target list exposed alias capacity while switch was pending: %+v", exposed)
		}
	}
	_, acquired, reason, err := manager.reserveTarget(context.Background(), alias, &domain.Workload{Request: domain.WorkloadRequest{ID: "alias-work"}}, Requirements{})
	if err != nil || acquired || !strings.Contains(reason, "operator reconciliation") {
		t.Fatalf("already-registered card alias entered admission: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, primary.NodeID, runtimeProfileProjectionResult(primary)); err != nil {
		t.Fatal(err)
	}
	refreshedAlias := manager.targetByID(alias.ID)
	if manager.CurrentlyAvailableSlotsForModel(context.Background(), refreshedAlias, "model") != 0 {
		t.Fatalf("proof for one route restored stale alias capacity: %+v", refreshedAlias)
	}
	for _, exposed := range manager.Targets() {
		if exposed.ID == alias.ID && (exposed.CapacityVerified || exposed.Slots != 0 || exposed.ContextLimit != 0) {
			t.Fatalf("proof for one route exposed another alias's stored capacity: %+v", exposed)
		}
	}
}

func TestRuntimeProfileAcceptedHistoryIsScopedToPhysicalCardAndExactRoute(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	makeTarget := func(id string, gpu int, profile RuntimeCapacityProfile) Target {
		return Target{
			ID: id, NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: fmt.Sprintf("node-gpu%d", gpu),
			CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
			ContextLimit: profile.ContextLimit, Slots: profile.Slots, ActiveRuntimeProfile: profile.ID, CapacitySource: "runtime:/slots", CapacityVerified: true,
			SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
		}
	}
	profile := RuntimeCapacityProfile{ID: "ctx-32k", ContextLimit: 32768, Slots: 1}
	primary := makeTarget("node-runtime", 0, profile)
	otherCard := makeTarget("node-runtime-gpu1", 1, profile)
	for i, target := range []Target{primary, otherCard} {
		result, err := json.Marshal(runtimeProfileProjectionResultFor(target, profile))
		if err != nil {
			t.Fatal(err)
		}
		row := &domain.NodeCommand{ID: fmt.Sprintf("accepted-card-%d", i), IdempotencyKey: fmt.Sprintf("accepted-key-%d", i), NodeID: "node", Command: "switch_runtime_profile", Args: map[string]any{"target_id": strings.TrimPrefix(target.ID, "node-"), "profile_id": profile.ID}, Attempts: 1, Status: domain.NodeCommandSucceeded, Result: result, CreatedAt: base.Add(time.Duration(i) * time.Minute), UpdatedAt: base.Add(time.Duration(i) * time.Minute)}
		if !runtimeProfileCommandHasAcceptedResult(row) || !runtimeProfileAcceptedResultMatchesTarget(row, target) {
			t.Fatalf("fixture row %s is not accepted exact-route evidence", row.ID)
		}
		if _, _, err := backing.CreateNodeCommand(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	manager := NewManager(quietLogger(), backing, time.Second)
	defer manager.Close()
	alias := primary
	alias.ID = "node-runtime-alias"
	manager.RegisterTarget(primary)
	manager.RegisterTarget(alias)
	manager.RegisterTarget(otherCard)
	registeredPrimary := manager.targetByID(primary.ID)
	registeredAlias := manager.targetByID(alias.ID)
	registeredOther := manager.targetByID(otherCard.ID)
	if !registeredPrimary.CapacityVerified || registeredPrimary.Slots != 1 {
		t.Fatalf("accepted proof for the primary route did not remain usable: %+v", registeredPrimary)
	}
	if registeredAlias.CapacityVerified || manager.CurrentlyAvailableSlotsForModel(ctx, registeredAlias, "model") != 0 {
		t.Fatalf("accepted proof was copied to an alias route without its own observation: %+v", registeredAlias)
	}
	if !registeredOther.CapacityVerified || manager.CurrentlyAvailableSlotsForModel(ctx, registeredOther, "model") != 1 {
		t.Fatalf("GPU0 proof contaminated independent GPU1 capacity: %+v", registeredOther)
	}
	_, acquired, reason, err := manager.reserveTarget(ctx, registeredOther, &domain.Workload{Request: domain.WorkloadRequest{ID: "gpu1-work"}}, Requirements{})
	if err != nil || !acquired {
		t.Fatalf("independently accepted GPU1 route was not admissible: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
	if reservation := manager.targetLeases[otherCard.ID]; reservation == nil {
		t.Fatal("GPU1 admission did not publish its target lease")
	}
}

func TestRuntimeProfileHistoryReducerIsOrderIndependent(t *testing.T) {
	target := Target{ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp", ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}}
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	rows := make([]*domain.NodeCommand, 0, 2)
	for _, profile := range target.RuntimeProfiles {
		observed := target
		observed.ActiveRuntimeProfile, observed.ContextLimit, observed.Slots = profile.ID, profile.ContextLimit, profile.Slots
		body, err := json.Marshal(runtimeProfileProjectionResultFor(observed, profile))
		if err != nil {
			t.Fatal(err)
		}
		row := &domain.NodeCommand{ID: "tie-" + profile.ID, IdempotencyKey: "tie-key-" + profile.ID, NodeID: "node", Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": profile.ID}, Attempts: 1, Status: domain.NodeCommandSucceeded, Result: body, CreatedAt: base, UpdatedAt: base}
		if !runtimeProfileCommandHasAcceptedResult(row) || !runtimeProfileAcceptedResultMatchesTarget(row, observed) {
			t.Fatalf("tie fixture %s is not accepted evidence", row.ID)
		}
		rows = append(rows, row)
	}
	known := map[string]Target{target.ID: target}
	forward := reduceRuntimeProfileHistory("node", target, rows, known)
	reverse := []*domain.NodeCommand{rows[1], rows[0]}
	backward := reduceRuntimeProfileHistory("node", target, reverse, known)
	if forward == "" || forward != backward || !strings.Contains(forward, "ambiguous durable ordering for card node-gpu0") {
		t.Fatalf("accepted-history tie depended on input order or was not ambiguous: forward=%q reverse=%q", forward, backward)
	}
}

func TestRuntimeProfileHistoryLegacySucceededRowBlocksOnlyWhileRecent(t *testing.T) {
	target := Target{ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k"}
	legacy := func(completed time.Time) []*domain.NodeCommand {
		return []*domain.NodeCommand{{ID: "legacy-switch", NodeID: "node", Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": "ctx-8k"}, Attempts: 1, Status: domain.NodeCommandSucceeded, Result: json.RawMessage(`{"changed":true}`), CreatedAt: completed, UpdatedAt: completed, CompletedAt: &completed}}
	}
	known := map[string]Target{target.ID: target}
	if blocker := reduceRuntimeProfileHistory("node", target, legacy(time.Now().UTC().Add(-time.Minute)), known); !strings.Contains(blocker, "lacks accepted route/card proof") {
		t.Fatalf("recent unproven success did not block: %q", blocker)
	}
	if blocker := reduceRuntimeProfileHistory("node", target, legacy(time.Now().UTC().Add(-48*time.Hour)), known); blocker != "" {
		t.Fatalf("settled legacy success still withholds capacity: %q", blocker)
	}
}

type gatedRuntimeProfileHistoryStore struct {
	store.WorkloadStore
	mu      sync.Mutex
	gate    bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gatedRuntimeProfileHistoryStore) ListNodeCommandRecovery(ctx context.Context, nodeID, status string) ([]*domain.NodeCommand, error) {
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	if gate {
		s.once.Do(func() {
			close(s.entered)
			<-s.release
		})
	}
	return s.WorkloadStore.ListNodeCommandRecovery(ctx, nodeID, status)
}

func TestRuntimeProfileTransitionWinsRegistrationHistoryRace(t *testing.T) {
	backing := store.NewMemoryStore()
	history := &gatedRuntimeProfileHistoryStore{WorkloadStore: backing, entered: make(chan struct{}), release: make(chan struct{})}
	manager := NewManager(quietLogger(), history, time.Second)
	defer manager.Close()
	primary := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	manager.RegisterTarget(primary)
	primary = manager.targetByID(primary.ID)
	alias := primary
	alias.ID = "node-runtime-alias"
	history.mu.Lock()
	history.gate = true
	history.mu.Unlock()
	registered := make(chan struct{})
	go func() {
		manager.RegisterTarget(alias)
		close(registered)
	}()
	select {
	case <-history.entered:
	case <-time.After(time.Second):
		t.Fatal("registration did not pause at durable profile history lookup")
	}
	transition, _, err := manager.beginRuntimeProfileTransition(primary, primary.RuntimeProfiles[1], "node", manager.targetGeneration(primary.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", runtimeProfileProjectionResult(primary)); err != nil {
		t.Fatalf("correlated transition could not complete before the registration barrier was released: %v", err)
	}
	close(history.release)
	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("registration did not finish after history lookup resumed")
	}
	registeredAlias := manager.targetByID(alias.ID)
	if registeredAlias.ID != "" {
		t.Fatalf("stale in-flight registration published after the completed profile transition: %+v", registeredAlias)
	}
	if got := manager.CurrentlyAvailableSlotsForModel(context.Background(), alias, "model"); got != 0 {
		t.Fatalf("registration race exposed %d slots", got)
	}
	_, acquired, reason, err := manager.reserveTarget(context.Background(), alias, &domain.Workload{Request: domain.WorkloadRequest{ID: "registration-race-work"}}, Requirements{})
	if err != nil || acquired || (!strings.Contains(reason, "target facts changed") && !strings.Contains(reason, "operator reconciliation")) {
		t.Fatalf("registration race admitted workload: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
}

type unavailableRuntimeProfileHistoryStore struct {
	store.WorkloadStore
}

type retryableRuntimeProfileHistoryStore struct {
	store.WorkloadStore
	mu   sync.Mutex
	fail bool
}

func (s *retryableRuntimeProfileHistoryStore) ListNodeCommandRecovery(ctx context.Context, nodeID, status string) ([]*domain.NodeCommand, error) {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return nil, errors.New("transient node command history failure")
	}
	return s.WorkloadStore.ListNodeCommandRecovery(ctx, nodeID, status)
}

func (s unavailableRuntimeProfileHistoryStore) ListNodeCommandRecovery(context.Context, string, string) ([]*domain.NodeCommand, error) {
	return nil, errors.New("node command history unavailable")
}

func TestRuntimeProfileHistoryFailureWithholdsRegisteredCapacity(t *testing.T) {
	backing := store.NewMemoryStore()
	manager := NewManager(quietLogger(), unavailableRuntimeProfileHistoryStore{WorkloadStore: backing}, time.Second)
	defer manager.Close()
	target := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true, Enabled: true,
	}
	manager.RegisterTarget(target)
	registered := manager.targetByID(target.ID)
	if registered.CapacityVerified || registered.Slots != 0 || registered.ContextLimit != 0 || registered.CapacitySource != "runtime-profile:observation_unavailable" {
		t.Fatalf("history lookup failure failed open and restored capacity: %+v", registered)
	}
	if got := manager.CurrentlyAvailableSlotsForModel(context.Background(), registered, "model"); got != 0 {
		t.Fatalf("history lookup failure exposed %d slots", got)
	}
	_, acquired, reason, err := manager.reserveTarget(context.Background(), registered, &domain.Workload{Request: domain.WorkloadRequest{ID: "history-unavailable-work"}}, Requirements{})
	if err != nil || acquired || !strings.Contains(reason, "operator reconciliation") {
		t.Fatalf("history lookup failure admitted a workload: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
}

func TestRuntimeProfileHistoryRetryRestoresCapacityAndKeepsPendingAliasesBlocked(t *testing.T) {
	backing := store.NewMemoryStore()
	history := &retryableRuntimeProfileHistoryStore{WorkloadStore: backing, fail: true}
	manager := NewManager(quietLogger(), history, time.Second)
	defer manager.Close()
	target := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	manager.mu.Lock()
	manager.runtimeProfileBlockedTargets[target.ID] = "stale target blocker"
	manager.runtimeProfileBlockedNodes[target.NodeID] = "stale node blocker"
	manager.runtimeProfileBlockedCards[target.AcceleratorID] = "stale card blocker"
	manager.mu.Unlock()
	manager.RegisterTarget(target)
	blockedTarget := manager.targetByID(target.ID)
	manager.mu.RLock()
	failedTargetBlocker := manager.runtimeProfileBlockedTargets[target.ID]
	manager.mu.RUnlock()
	if blockedTarget.CapacityVerified || failedTargetBlocker == "" {
		t.Fatalf("transient history failure did not quarantine target: target=%+v blocker=%q", blockedTarget, failedTargetBlocker)
	}
	history.mu.Lock()
	history.fail = false
	history.mu.Unlock()
	manager.RegisterTarget(target)
	registered := manager.targetByID(target.ID)
	if !registered.CapacityVerified || registered.Slots != 4 || registered.ContextLimit != 8192 {
		t.Fatalf("same-manager retry did not restore verified capacity: %+v", registered)
	}
	manager.mu.RLock()
	targetBlocker := manager.runtimeProfileBlockedTargets[target.ID]
	nodeBlocker := manager.runtimeProfileBlockedNodes[target.NodeID]
	cardBlocker := manager.runtimeProfileBlockedCards[target.AcceleratorID]
	manager.mu.RUnlock()
	if targetBlocker != "" || nodeBlocker != "" || cardBlocker != "" {
		t.Fatalf("successful history retry retained stale blockers: target=%q node=%q card=%q", targetBlocker, nodeBlocker, cardBlocker)
	}

	transition, _, err := manager.beginRuntimeProfileTransition(registered, registered.RuntimeProfiles[1], target.NodeID, manager.targetGeneration(target.ID))
	if err != nil {
		t.Fatal(err)
	}
	alias := target
	alias.ID = "node-runtime-alias"
	manager.RegisterTarget(alias)
	manager.mu.RLock()
	nodeBlocker = manager.runtimeProfileBlockedNodes[target.NodeID]
	cardBlocker = manager.runtimeProfileBlockedCards[target.AcceleratorID]
	manager.mu.RUnlock()
	if nodeBlocker == "" || cardBlocker == "" {
		t.Fatalf("pending profile ticket did not retain node/card alias blockers: node=%q card=%q ticket=%+v", nodeBlocker, cardBlocker, transition)
	}
	if aliasTarget := manager.targetByID(alias.ID); aliasTarget.CapacityVerified || aliasTarget.Slots != 0 {
		t.Fatalf("pending alias registration exposed capacity: %+v", aliasTarget)
	}
}

func TestExhaustedLiveGenerationInvalidatesChangedAuthoritativeFacts(t *testing.T) {
	t.Run("changed advertisement", func(t *testing.T) {
		manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
		defer manager.Close()
		target := Target{ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", ContextLimit: 8192, Slots: 4, CapacityVerified: true, Enabled: true}
		manager.RegisterTarget(target)
		manager.mu.Lock()
		manager.targetGenerations[target.ID] = ^uint64(0)
		manager.mu.Unlock()
		changed := target
		changed.Endpoint = "http://changed-route"
		manager.RegisterTarget(changed)
		if current := manager.targetByID(target.ID); current.ID != "" {
			t.Fatalf("changed authoritative route left stale schedulable target: %+v", current)
		}
		manager.mu.RLock()
		retired := manager.retiredTargets[target.ID]
		blocked := manager.runtimeProfileBlockedCards[target.AcceleratorID]
		generation := manager.targetGenerations[target.ID]
		manager.mu.RUnlock()
		if retired.ID != target.ID || retired.Enabled || blocked == "" || generation != ^uint64(0) {
			t.Fatalf("failed changed route was not conservatively retired: retired=%+v blocked=%q generation=%d", retired, blocked, generation)
		}
		manager.RegisterTarget(target)
		if current := manager.targetByID(target.ID); current.ID != "" {
			t.Fatalf("exhausted retired route was resurrected: %+v", current)
		}
	})

	t.Run("lower VRAM telemetry", func(t *testing.T) {
		manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
		defer manager.Close()
		target := Target{ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", AcceleratorVRAMMB: 24000, ContextLimit: 8192, Slots: 4, CapacityVerified: true, Enabled: true}
		manager.RegisterTarget(target)
		manager.mu.Lock()
		manager.targetGenerations[target.ID] = ^uint64(0)
		manager.mu.Unlock()
		manager.UpdateAcceleratorCapacity(target.AcceleratorID, 12000)
		if current := manager.targetByID(target.ID); current.ID != "" {
			t.Fatalf("lower authoritative VRAM telemetry left stale route schedulable: %+v", current)
		}
		manager.mu.RLock()
		retired := manager.retiredTargets[target.ID]
		generation := manager.targetGenerations[target.ID]
		blocked := manager.runtimeProfileBlockedCards[target.AcceleratorID]
		manager.mu.RUnlock()
		if retired.ID != target.ID || generation != ^uint64(0) || blocked == "" {
			t.Fatalf("lower VRAM failure did not preserve exhausted tombstone and block: retired=%+v generation=%d blocked=%q", retired, generation, blocked)
		}
	})

	t.Run("fresh non-saturated update", func(t *testing.T) {
		manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
		defer manager.Close()
		target := Target{ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", AcceleratorVRAMMB: 24000, Enabled: true}
		manager.RegisterTarget(target)
		before := manager.targetGeneration(target.ID)
		manager.UpdateAcceleratorCapacity(target.AcceleratorID, 12000)
		current := manager.targetByID(target.ID)
		if current.ID == "" || current.AcceleratorVRAMMB != 12000 || manager.targetGeneration(target.ID) <= before {
			t.Fatalf("fresh lower VRAM update did not publish with a new fence: target=%+v before=%d after=%d", current, before, manager.targetGeneration(target.ID))
		}
	})
}

func TestSetTargetResidentExhaustedRemovalDoesNotMutateLiveBackingSlice(t *testing.T) {
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer manager.Close()
	residentModels := []string{"a", "b"}
	target := Target{ID: "resident-target", Adapter: "mock", ResidentModels: residentModels, Enabled: true}
	manager.RegisterTarget(target)
	registered := manager.targetByID(target.ID)
	manager.mu.Lock()
	manager.targetGenerations[target.ID] = ^uint64(0)
	manager.mu.Unlock()
	if err := manager.setTargetResident(target.ID, "a", false); err == nil || !strings.Contains(err.Error(), "generation is exhausted") {
		t.Fatalf("resident removal did not fail closed at exhausted generation: %v", err)
	}
	if len(residentModels) != 2 || residentModels[0] != "a" || residentModels[1] != "b" {
		t.Fatalf("failed removal mutated caller's resident backing slice: %#v", residentModels)
	}
	current := manager.targetByID(target.ID)
	manager.mu.RLock()
	retired := manager.retiredTargets[target.ID]
	generation := manager.targetGenerations[target.ID]
	manager.mu.RUnlock()
	if current.ID != "" || retired.ID != target.ID || len(retired.ResidentModels) != 2 || retired.ResidentModels[0] != "a" || retired.ResidentModels[1] != "b" || generation != ^uint64(0) {
		t.Fatalf("failed resident removal left a stale projection or changed the exhausted tombstone: current=%+v retired=%+v generation=%d", current, retired, generation)
	}
	if len(registered.ResidentModels) != 2 || registered.ResidentModels[0] != "a" || registered.ResidentModels[1] != "b" {
		t.Fatalf("snapshot resident list changed despite failed mutation: %#v", registered.ResidentModels)
	}
}

func TestRuntimeProfileHistoryRestoresOnlyKnownTerminalEvidence(t *testing.T) {
	for _, test := range []struct {
		name        string
		validResult bool
	}{
		{name: "accepted success", validResult: true},
		{name: "malformed success", validResult: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			backing := store.NewMemoryStore()
			manager := NewManager(quietLogger(), backing, time.Second)
			defer manager.Close()
			target := Target{
				ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
				CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
				ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true, Enabled: true,
				RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}},
			}
			result, err := json.Marshal(runtimeProfileProjectionResult(target))
			if err != nil {
				t.Fatal(err)
			}
			if !test.validResult {
				result = json.RawMessage(`{"profile_id":"ctx-32k"}`)
			} else {
				target.ActiveRuntimeProfile = "ctx-32k"
				target.ContextLimit = 32768
				target.Slots = 1
			}
			prior := &domain.NodeCommand{
				ID: "old-profile-switch", IdempotencyKey: "old-profile-key", NodeID: "node",
				Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": "ctx-32k"},
				Attempts: 1, Status: domain.NodeCommandSucceeded, Result: result,
			}
			if _, _, err := backing.CreateNodeCommand(context.Background(), prior); err != nil {
				t.Fatal(err)
			}
			manager.RegisterTarget(target)
			registered := manager.targetByID(target.ID)
			if test.validResult {
				if !registered.CapacityVerified || registered.Slots != 1 || registered.ContextLimit != 32768 || registered.ActiveRuntimeProfile != "ctx-32k" {
					t.Fatalf("known terminal result incorrectly quarantined a fresh observation: %+v", registered)
				}
			} else if registered.CapacityVerified || registered.Slots != 0 || registered.ContextLimit != 0 || registered.CapacitySource != "runtime-profile:observation_unavailable" {
				t.Fatalf("malformed terminal row restored capacity without accepted proof: %+v", registered)
			}
		})
	}
}

func TestRuntimeProfileHistoryUsesLatestAcceptedAndRetainsUnresolved(t *testing.T) {
	for _, test := range []struct {
		name              string
		includeUnresolved bool
		wantVerified      bool
	}{
		{name: "latest accepted observation", wantVerified: true},
		{name: "older unresolved effect remains blocking", includeUnresolved: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			backing := store.NewMemoryStore()
			manager := NewManager(quietLogger(), backing, time.Second)
			defer manager.Close()
			target := Target{
				ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
				CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
				ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
				RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
			}
			newResult := runtimeProfileProjectionResultFor(target, target.RuntimeProfiles[0])
			newerBody, err := json.Marshal(newResult)
			if err != nil {
				t.Fatal(err)
			}
			olderBody, err := json.Marshal(runtimeProfileProjectionResult(target))
			if err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			rows := []*domain.NodeCommand{
				{ID: "profile-older", IdempotencyKey: "key-older", NodeID: "node", Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": "ctx-32k"}, Attempts: 1, Status: domain.NodeCommandSucceeded, Result: olderBody, CreatedAt: base, UpdatedAt: base},
				{ID: "profile-newer", IdempotencyKey: "key-newer", NodeID: "node", Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": "ctx-8k"}, Attempts: 1, Status: domain.NodeCommandSucceeded, Result: newerBody, CreatedAt: base.Add(time.Minute), UpdatedAt: base.Add(time.Minute)},
			}
			for _, row := range rows {
				if row.Status == domain.NodeCommandSucceeded && !runtimeProfileCommandHasAcceptedResult(row) {
					t.Fatalf("history fixture row %s is not accepted evidence", row.ID)
				}
			}
			if test.includeUnresolved {
				rows = append(rows, &domain.NodeCommand{ID: "profile-unresolved", IdempotencyKey: "key-unresolved", NodeID: "node", Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": "ctx-32k"}, Attempts: 1, Status: domain.NodeCommandSent, CreatedAt: base.Add(-time.Minute), UpdatedAt: base.Add(-time.Minute)})
			}
			for _, row := range rows {
				if _, _, err := backing.CreateNodeCommand(ctx, row); err != nil {
					t.Fatal(err)
				}
			}
			manager.RegisterTarget(target)
			registered := manager.targetByID(target.ID)
			if test.wantVerified {
				if !registered.CapacityVerified || registered.ActiveRuntimeProfile != "ctx-8k" || registered.ContextLimit != 8192 || registered.Slots != 4 {
					t.Fatalf("older success overrode latest accepted history: %+v", registered)
				}
			} else if registered.CapacityVerified || registered.Slots != 0 || registered.ContextLimit != 0 {
				t.Fatalf("newer accepted evidence erased an older unresolved physical effect: %+v", registered)
			}
		})
	}
}

func TestRuntimeProfileRepeatedSwitchHistoryUsesPretransitionBasis(t *testing.T) {
	manager, target, transition := runtimeProfileProjectionFixture(t)
	defer manager.Close()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rows := make([]*domain.NodeCommand, 0, 4)
	addAccepted := func(id string, profile RuntimeCapacityProfile, observed Target, created time.Time) {
		t.Helper()
		body, err := json.Marshal(runtimeProfileProjectionResultFor(observed, profile))
		if err != nil {
			t.Fatal(err)
		}
		row := &domain.NodeCommand{
			ID: id, IdempotencyKey: id + "-key", NodeID: "node", Command: "switch_runtime_profile",
			Args: map[string]any{"target_id": "node-runtime", "profile_id": profile.ID}, Attempts: 1,
			Status: domain.NodeCommandSucceeded, Result: body, CreatedAt: created, UpdatedAt: created,
		}
		if !runtimeProfileCommandHasAcceptedResult(row) {
			t.Fatalf("fixture row %s is not a valid accepted result", id)
		}
		if _, _, err := manager.store.CreateNodeCommand(context.Background(), row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	checkDispatch := func(ticket *runtimeProfileTransition) {
		t.Helper()
		history := make([]*domain.NodeCommand, 0, len(rows))
		for _, row := range rows {
			if row.IdempotencyKey != ticket.commandKey {
				history = append(history, row)
			}
		}
		if reason := manager.RuntimeProfileHistoryBlocker("node", target.ID, history); reason != "" {
			t.Fatalf("valid same-route dispatch was blocked by its prior accepted basis: %s", reason)
		}
		args := map[string]any{"target_id": target.ID, "profile_id": ticket.profile.ID}
		if !manager.RuntimeProfileDispatchAllowed("node", target.ID, args, ticket.commandKey) {
			t.Fatalf("current generation-bound ticket %s was not dispatchable", ticket.commandKey)
		}
	}

	addAccepted("accepted-initial", target.RuntimeProfiles[0], target, base)
	checkDispatch(transition)
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", runtimeProfileProjectionResultFor(target, transition.profile)); err != nil {
		t.Fatal(err)
	}

	addAccepted("accepted-first-switch", transition.profile, manager.targetByID(target.ID), base.Add(time.Minute))

	for index, profile := range []RuntimeCapacityProfile{target.RuntimeProfiles[0], target.RuntimeProfiles[1]} {
		current := manager.targetByID(target.ID)
		observed := current
		observed.ActiveRuntimeProfile = profile.ID
		observed.ContextLimit, observed.Slots = profile.ContextLimit, profile.Slots
		observed.CapacityVerified, observed.CapacitySource = true, "runtime:/slots"
		next, _, err := manager.beginRuntimeProfileTransition(current, profile, "node", manager.targetGeneration(target.ID))
		if err != nil {
			t.Fatalf("install subsequent physical switch %d: %v", index+2, err)
		}
		checkDispatch(next)
		if err := manager.ProjectRuntimeProfileCommandResult(next.commandKey, "node", runtimeProfileProjectionResultFor(observed, profile)); err != nil {
			t.Fatalf("project subsequent switch %d: %v", index+2, err)
		}
		addAccepted(fmt.Sprintf("accepted-%d", index+2), profile, observed, base.Add(time.Duration(index+2)*time.Minute))
	}
}

func TestRuntimeProfileZeroContextAdmissionCannotMutatePendingGeneration(t *testing.T) {
	backing := store.NewMemoryStore()
	manager := NewManager(quietLogger(), backing, time.Second)
	defer manager.Close()
	manager.RegisterAdapter(modelRequirementsMockAdapter{MockAdapter: NewMockAdapter()})
	target := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		Models: []string{"model"}, CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsModelLifecycle: true, SupportsRuntimeProfileSwitch: true,
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	manager.RegisterTarget(target)
	target = manager.targetByID(target.ID)
	if containsString(target.ResidentModels, "model") {
		t.Fatal("zero-context fixture must begin with the model not resident")
	}
	pretransitionGeneration := manager.targetGeneration(target.ID)
	coldResidency, err := manager.store.GetModelResidency(context.Background(), target.ID, "model")
	if err != nil {
		t.Fatalf("read registered cold residency seed: %v", err)
	}
	if coldResidency == nil || coldResidency.TargetID != target.ID || coldResidency.Model != "model" ||
		coldResidency.TargetGeneration != pretransitionGeneration ||
		coldResidency.ExecutionFingerprint == "" || coldResidency.ExecutionFingerprint != targetExecutionFingerprint(target) ||
		coldResidency.DesiredTier != domain.ResidencyColdDisk || coldResidency.ObservedTier != domain.ResidencyColdDisk {
		t.Fatal("registered cold residency seed did not match the canonical target fence")
	}
	hotResidency := *coldResidency
	hotResidency.DesiredTier = domain.ResidencyHotVRAM
	hotResidency.ObservedTier = domain.ResidencyHotVRAM
	hotResidency.UpdatedAt = time.Now().UTC()
	seededResidency, err := manager.store.UpsertModelResidency(context.Background(), &hotResidency)
	if err != nil {
		t.Fatalf("seed durable HOT residency: %v", err)
	}
	if seededResidency == nil || seededResidency.TargetGeneration != coldResidency.TargetGeneration ||
		seededResidency.ExecutionFingerprint != coldResidency.ExecutionFingerprint ||
		seededResidency.DesiredTier != domain.ResidencyHotVRAM || seededResidency.ObservedTier != domain.ResidencyHotVRAM {
		t.Fatal("durable HOT residency seed did not retain its canonical fence")
	}
	if _, _, err := manager.beginRuntimeProfileTransition(target, target.RuntimeProfiles[1], "node", manager.targetGeneration(target.ID)); err != nil {
		t.Fatal(err)
	}
	workload, _, err := manager.Submit(context.Background(), domain.WorkloadRequest{
		ID: "zero-context-pending", OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"model":"model"}`),
		Bounds: domain.WorkloadBounds{ContextTokens: 0, MaxOutput: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := manager.targetGeneration(target.ID)
	manager.tryAdmit(context.Background(), workload)
	after := manager.targetByID(target.ID)
	if manager.targetGeneration(target.ID) != before || containsString(after.ResidentModels, "model") || after.CapacitySource != "runtime-profile:pending" {
		t.Fatalf("zero-context HOT reconciliation mutated a pending profile generation: before=%d after=%d target=%+v", before, manager.targetGeneration(target.ID), after)
	}
}

type modelRequirementsMockAdapter struct{ *MockAdapter }

func (modelRequirementsMockAdapter) Name() string { return "mock" }
func (modelRequirementsMockAdapter) Requirements(_ context.Context, req domain.WorkloadRequest) (Requirements, error) {
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return Requirements{}, err
	}
	return Requirements{Model: payload.Model, ContextTokens: req.Bounds.ContextTokens + req.Bounds.MaxOutput, AcceleratorRequired: true}, nil
}

func TestRuntimeProfileResultClaimFencesResidentGenerationMutation(t *testing.T) {
	manager, target, transition := runtimeProfileProjectionFixture(t)
	defer manager.Close()
	result := runtimeProfileProjectionResult(target)
	pendingGeneration := manager.targetGeneration(target.ID)
	if err := manager.setTargetResident(target.ID, "model", true, pendingGeneration); err == nil || !strings.Contains(err.Error(), "observation_unavailable") {
		t.Fatalf("resident metadata mutated an unresolved profile generation: %v", err)
	}
	if manager.targetGeneration(target.ID) != pendingGeneration || containsString(manager.targetByID(target.ID).ResidentModels, "model") {
		t.Fatal("rejected resident mutation changed pending target generation or models")
	}
	claim, err := manager.ClaimRuntimeProfileResult(transition.commandKey, "node", result)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		close(started)
		finished <- manager.setTargetResident(target.ID, "model", true)
	}()
	<-started
	deadline := time.Now().Add(time.Second)
	for transition.dispatchMu.TryLock() {
		transition.dispatchMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("resident mutation never acquired its dispatch lifecycle claim")
		}
		time.Sleep(time.Millisecond)
	}
	if containsString(manager.targetByID(target.ID).ResidentModels, "model") {
		t.Fatal("resident mutation crossed an uncommitted profile result claim")
	}
	if err := claim.Project(result); err != nil {
		claim.Release()
		t.Fatal(err)
	}
	claim.Release()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("settled resident metadata mutation did not resume: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("resident metadata mutation did not resume after result commit")
	}
	if !containsString(manager.targetByID(target.ID).ResidentModels, "model") {
		t.Fatal("settled resident metadata was not applied")
	}
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", result); err != nil {
		t.Fatalf("same correlated result was no longer idempotent after resident metadata update: %v", err)
	}
}

func TestResidencyHighWaterRecoveryRejectsPendingProfileGeneration(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &profileLifecycleMock{MockAdapter: NewMockAdapter()}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(adapter)
	target := Target{
		ID: "node-a-runtime", NodeID: "node-a", Adapter: adapter.Name(), Endpoint: "http://runtime", AcceleratorID: "node-a-gpu0",
		Models: []string{"model"}, CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, SupportsModelLifecycle: true, Enabled: true,
	}
	mgr.RegisterTarget(target)
	target = mgr.targetByID(target.ID)
	if target.ID == "" {
		t.Fatal("pending high-water target was not registered")
	}
	baseGeneration := mgr.targetGeneration(target.ID)
	stored, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{
		TargetID: target.ID, AcceleratorID: target.AcceleratorID, Adapter: target.Adapter, Model: "model",
		DesiredTier: domain.ResidencyColdDisk, ObservedTier: domain.ResidencyColdDisk, Policy: domain.ResidencyAuto,
		TargetGeneration: baseGeneration + 8, ExecutionFingerprint: targetExecutionFingerprint(target), UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.TargetGeneration != baseGeneration+8 || stored.ExecutionFingerprint != targetExecutionFingerprint(target) {
		t.Fatal("pending high-water seed did not persist the canonical generation and fingerprint")
	}
	transition, _, err := mgr.beginRuntimeProfileTransition(target, target.RuntimeProfiles[1], target.NodeID, baseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	pendingGeneration := mgr.targetGeneration(target.ID)
	if _, err := mgr.transitionModel(ctx, adapter, target, "model", domain.ResidencyColdDisk, "test", "owner", "", "pending-high-water", nil); err == nil || !strings.Contains(err.Error(), "pending profile generation") {
		t.Fatalf("direct transition writer did not reject the current pending profile ticket: %v", err)
	}
	if got := mgr.targetGeneration(target.ID); got != pendingGeneration || got != transition.expectedGeneration {
		t.Fatalf("pending high-water recovery changed the live generation: got=%d want=%d", got, transition.expectedGeneration)
	}
	after, err := backing.GetModelResidency(ctx, target.ID, "model")
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != stored.Revision || after.TargetGeneration != stored.TargetGeneration || after.DesiredTier != stored.DesiredTier || after.ObservedTier != stored.ObservedTier {
		t.Fatalf("pending high-water recovery mutated durable residency: before=%+v after=%+v", stored, after)
	}
}

func TestResidencyHighWaterRecoveryAdvancesSettledGenerationMonotonically(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &profileLifecycleMock{MockAdapter: NewMockAdapter()}
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	mgr.RegisterAdapter(adapter)
	target := Target{ID: "high-water", Adapter: adapter.Name(), Models: []string{"model"}, Enabled: true}
	mgr.RegisterTarget(target)
	baseGeneration := mgr.targetGeneration(target.ID)
	const durableHighWater = uint64(40)
	if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{
		TargetID: target.ID, Adapter: target.Adapter, Model: "model", DesiredTier: domain.ResidencyColdDisk,
		ObservedTier: domain.ResidencyColdDisk, Policy: domain.ResidencyAuto, TargetGeneration: durableHighWater,
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.ConfigureResidency(ctx, target.ID, "model", domain.ResidencyColdDisk, "", "operator", "settled-high-water"); err != nil {
		t.Fatalf("settled high-water recovery failed: %v", err)
	}
	if got := mgr.targetGeneration(target.ID); got != durableHighWater+1 || got <= baseGeneration {
		t.Fatalf("settled durable high-water was not advanced monotonically: got=%d base=%d high_water=%d", got, baseGeneration, durableHighWater)
	}
	if _, _, err := mgr.ConfigureResidency(ctx, target.ID, "model", domain.ResidencyColdDisk, "", "operator", "settled-high-water-replay"); err != nil {
		t.Fatalf("settled high-water replay failed: %v", err)
	}
	if got := mgr.targetGeneration(target.ID); got != durableHighWater+1 {
		t.Fatalf("replaying settled high-water recovery moved the generation: got=%d want=%d", got, durableHighWater+1)
	}

	cancelManager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	cancelManagerCloseSafe := true
	defer func() {
		if cancelManagerCloseSafe {
			cancelManager.Close()
		}
	}()
	cancelTarget := Target{
		ID: "node-cancel-high-water", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		Models: []string{"model"}, CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	cancelManager.RegisterTarget(cancelTarget)
	cancelTarget = cancelManager.targetByID(cancelTarget.ID)
	if _, err := cancelManager.store.UpsertModelResidency(ctx, &domain.ModelResidency{
		TargetID: cancelTarget.ID, AcceleratorID: cancelTarget.AcceleratorID, Adapter: cancelTarget.Adapter, Model: "model",
		DesiredTier: domain.ResidencyColdDisk, ObservedTier: domain.ResidencyColdDisk, Policy: domain.ResidencyAuto,
		TargetGeneration: cancelManager.targetGeneration(cancelTarget.ID), ExecutionFingerprint: targetExecutionFingerprint(cancelTarget), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	transition, _, err := cancelManager.beginRuntimeProfileTransition(cancelTarget, cancelTarget.RuntimeProfiles[1], cancelTarget.NodeID, cancelManager.targetGeneration(cancelTarget.ID))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := cancelManager.ClaimRuntimeProfileResult(transition.commandKey, transition.nodeID, runtimeProfileProjectionResult(cancelTarget))
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Release()
	if err := claim.Project(runtimeProfileProjectionResult(cancelTarget)); err != nil {
		t.Fatal(err)
	}
	preCancelGeneration := cancelManager.targetGeneration(cancelTarget.ID)
	cancelManager.mu.RLock()
	preCancelProjectedGeneration := transition.projectedGeneration
	cancelManager.mu.RUnlock()
	durable, err := cancelManager.store.GetModelResidency(ctx, cancelTarget.ID, "model")
	if err != nil || durable == nil {
		t.Fatalf("read cancellation high-water seed: row=%+v err=%v", durable, err)
	}
	highWater := *durable
	highWater.TargetGeneration = preCancelGeneration + 8
	highWater.ExecutionFingerprint = targetExecutionFingerprint(cancelTarget)
	seeded, err := cancelManager.store.UpsertModelResidency(ctx, &highWater)
	if err != nil || seeded == nil || seeded.TargetGeneration != preCancelGeneration+8 {
		t.Fatalf("seed cancellation high-water row: row=%+v err=%v", seeded, err)
	}
	cancelCtx, cancelConfigure := context.WithCancel(ctx)
	configureStarted := make(chan struct{})
	configureDone := make(chan error, 1)
	configureSettled := false
	go func() {
		close(configureStarted)
		_, _, configureErr := cancelManager.ConfigureResidency(cancelCtx, cancelTarget.ID, "model", domain.ResidencyColdDisk, "", "operator", "cancel-high-water")
		configureDone <- configureErr
	}()
	defer func() {
		cancelConfigure()
		claim.Release()
		if !configureSettled {
			select {
			case <-configureDone:
				configureSettled = true
			case <-time.After(time.Second):
				cancelManagerCloseSafe = false
				t.Errorf("canceled ConfigureResidency worker did not join during test cleanup")
			}
		}
	}()
	<-configureStarted
	configureBlockedOnClaim := false
	claimWaitDeadline := time.Now().Add(time.Second)
	for time.Now().Before(claimWaitDeadline) {
		if transition.dispatchMu.TryLock() {
			transition.dispatchMu.Unlock()
			runtime.Gosched()
			continue
		}
		configureBlockedOnClaim = true
		break
	}
	if !configureBlockedOnClaim {
		cancelConfigure()
		claim.Release()
		t.Fatal("ConfigureResidency did not reach the held result-claim commit fence")
	}
	cancelConfigure()
	claim.Release()
	select {
	case configureErr := <-configureDone:
		configureSettled = true
		if !errors.Is(configureErr, context.Canceled) {
			t.Fatalf("canceled high-water reconciliation returned %v", configureErr)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled high-water reconciliation did not join within its bound")
	}
	if got := cancelManager.targetGeneration(cancelTarget.ID); got != preCancelGeneration {
		t.Fatalf("canceled high-water recovery changed the live generation: got=%d want=%d", got, preCancelGeneration)
	}
	cancelManager.mu.RLock()
	postCancelProjectedGeneration := transition.projectedGeneration
	cancelManager.mu.RUnlock()
	if postCancelProjectedGeneration != preCancelProjectedGeneration {
		t.Fatalf("canceled high-water recovery changed the projected ticket: before=%d after=%d", preCancelProjectedGeneration, postCancelProjectedGeneration)
	}
	durableAfter, err := cancelManager.store.GetModelResidency(ctx, cancelTarget.ID, "model")
	if err != nil || durableAfter == nil || !reflect.DeepEqual(seeded, durableAfter) {
		t.Fatalf("canceled high-water recovery mutated the durable row: before=%+v after=%+v err=%v", seeded, durableAfter, err)
	}
}

func TestResidencyHighWaterRecoveryRejectsMaxUint64BeforeLiveMutation(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	manager := NewManager(quietLogger(), backing, time.Second)
	defer manager.Close()
	target := Target{ID: "max-high-water", Adapter: "mock", Enabled: true}
	manager.RegisterTarget(target)
	target = manager.targetByID(target.ID)
	if target.ID == "" {
		t.Fatal("max high-water target was not registered")
	}
	baseGeneration := manager.targetGeneration(target.ID)
	projection := &domain.ModelResidency{
		TargetID: target.ID, Adapter: target.Adapter, Model: "model", TargetGeneration: ^uint64(0),
		ExecutionFingerprint: "durable-fingerprint-drift", ObservedTier: domain.ResidencyColdDisk,
	}
	if _, err := backing.UpsertModelResidency(ctx, projection); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.reconcileResidencyGeneration(target, projection, baseGeneration); err == nil || !strings.Contains(err.Error(), "generation is exhausted") {
		t.Fatalf("maximum durable high-water generation did not fail closed: %v", err)
	}
	if got := manager.targetGeneration(target.ID); got != baseGeneration {
		t.Fatalf("overflow failure mutated live target generation: got=%d want=%d", got, baseGeneration)
	}
}

func TestTargetRegistrationPreservesExhaustedDurableGeneration(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	seedManager := NewManager(quietLogger(), backing, time.Second)
	seedTarget := Target{ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", Enabled: true}
	seedManager.RegisterTarget(seedTarget)
	canonical := seedManager.targetByID(seedTarget.ID)
	if canonical.ID == "" {
		t.Fatal("seed target was not registered")
	}
	if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{
		TargetID: canonical.ID, Adapter: canonical.Adapter, Model: "model",
		DesiredTier: domain.ResidencyColdDisk, ObservedTier: domain.ResidencyColdDisk,
		TargetGeneration: ^uint64(0), ExecutionFingerprint: targetExecutionFingerprint(canonical),
	}); err != nil {
		t.Fatal(err)
	}
	seedManager.Close()

	changed := canonical
	changed.Endpoint = "http://changed-route"
	changedManager := NewManager(quietLogger(), backing, time.Second)
	changedManager.RegisterTarget(changed)
	if got := changedManager.targetByID(changed.ID); got.ID != "" {
		t.Fatalf("changed target was published over an exhausted durable generation: %+v", got)
	}
	if got := changedManager.targetGeneration(changed.ID); got != 0 || changedManager.pendingObservationGeneration != 0 {
		t.Fatalf("rejected changed registration mutated live generation or observation state: generation=%d observations=%d", got, changedManager.pendingObservationGeneration)
	}
	changedManager.Close()

	manager := NewManager(quietLogger(), backing, time.Second)
	manager.RegisterTarget(canonical)
	if got := manager.targetGeneration(canonical.ID); got != ^uint64(0) {
		t.Fatalf("exact-fingerprint durable recovery did not land on MaxUint64: got=%d", got)
	}
	manager.RegisterTarget(canonical)
	if got := manager.targetGeneration(canonical.ID); got != ^uint64(0) {
		t.Fatalf("exact registration replay advanced or wrapped the exhausted generation: got=%d", got)
	}
	if _, err := manager.UpdateTargetPolicy(domain.TargetPolicyOverride{TargetID: canonical.ID, Quarantined: true}); err == nil || !strings.Contains(err.Error(), "generation is exhausted") {
		t.Fatalf("changed target policy did not fail at the exhausted generation: %v", err)
	}
	if current := manager.targetByID(canonical.ID); current.Quarantined || !current.Enabled || manager.targetGeneration(canonical.ID) != ^uint64(0) {
		t.Fatalf("failed exhausted-generation mutation published changed target facts: %+v generation=%d", current, manager.targetGeneration(canonical.ID))
	}

	manager.ReconcileNodeTargets(canonical.NodeID, map[string]struct{}{})
	if got := manager.targetByID(canonical.ID); got.ID != "" {
		t.Fatalf("authoritative route retirement left target published: %+v", got)
	}
	if got := manager.targetGeneration(canonical.ID); got != ^uint64(0) {
		t.Fatalf("route retirement wrapped the exhausted generation: got=%d", got)
	}
	manager.RegisterTarget(canonical)
	if got := manager.targetByID(canonical.ID); got.ID != "" {
		t.Fatalf("same-process resurrection reused a retired exhausted generation: %+v", got)
	}
	manager.Close()
}

func TestRuntimeProfileHistoryRejectsAmbiguousAcceptedOrdering(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	manager := NewManager(quietLogger(), backing, time.Second)
	defer manager.Close()
	target := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0",
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, profile := range []RuntimeCapacityProfile{target.RuntimeProfiles[0], target.RuntimeProfiles[1]} {
		observed := target
		observed.ActiveRuntimeProfile = profile.ID
		observed.ContextLimit = profile.ContextLimit
		observed.Slots = profile.Slots
		body, err := json.Marshal(runtimeProfileProjectionResultFor(observed, profile))
		if err != nil {
			t.Fatal(err)
		}
		row := &domain.NodeCommand{
			ID: "profile-" + profile.ID, IdempotencyKey: "key-" + profile.ID, NodeID: "node", Command: "switch_runtime_profile",
			Args: map[string]any{"target_id": "runtime", "profile_id": profile.ID}, Attempts: 1, Status: domain.NodeCommandSucceeded,
			Result: body, CreatedAt: base, UpdatedAt: base,
		}
		if !runtimeProfileCommandHasAcceptedResult(row) || !runtimeProfileAcceptedResultMatchesTarget(row, observed) {
			t.Fatalf("ambiguous-order fixture row %s is not valid accepted evidence", row.ID)
		}
		if _, _, err := backing.CreateNodeCommand(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	manager.RegisterTarget(target)
	registered := manager.targetByID(target.ID)
	if registered.CapacityVerified || registered.Slots != 0 || registered.ContextLimit != 0 || registered.CapacitySource != "runtime-profile:observation_unavailable" {
		t.Fatalf("equally ordered conflicting profile effects selected an arbitrary history row: %+v", registered)
	}
}

func TestRuntimeProfileReplayIdempotentGeneration(t *testing.T) {
	manager, target, transition := runtimeProfileProjectionFixture(t)
	defer manager.Close()
	result := runtimeProfileProjectionResult(target)
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", result); err != nil {
		t.Fatal(err)
	}
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", result); err != nil {
		t.Fatalf("identical result replay was not idempotent: %v", err)
	}
	projected := manager.targetByID(target.ID)
	projectedGeneration := manager.targetGeneration(target.ID)
	manager.RegisterTarget(projected)
	if manager.targetGeneration(target.ID) != projectedGeneration {
		t.Fatal("fresh same-profile registration unexpectedly advanced the authoritative profile generation")
	}
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", result); err != nil {
		t.Fatalf("same-proof result waiter failed after a fresh identical registration: %v", err)
	}
	manager.RegisterTarget(target)
	if current := manager.targetByID(target.ID); current.ActiveRuntimeProfile != "ctx-32k" || current.Slots != 1 || current.ContextLimit != 32768 || !current.CapacityVerified {
		t.Fatalf("stale pre-switch registration reverted projected capacity: %+v", current)
	}
	changed := manager.targetByID(target.ID)
	changed.Models = []string{"new-model"}
	manager.RegisterTarget(changed)
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", result); err == nil {
		t.Fatal("replay crossed a newer target generation")
	}
}

func TestLateResultCannotResurrectRetiredTarget(t *testing.T) {
	manager, target, transition := runtimeProfileProjectionFixture(t)
	defer manager.Close()
	manager.ReconcileNodeTargets("node", map[string]struct{}{})
	manager.mu.RLock()
	retained := manager.runtimeProfileTransitions[manager.runtimeProfileTransitionTarget[target.ID]]
	manager.mu.RUnlock()
	if retained != transition {
		t.Fatalf("retiring an unknown-effect target discarded its unresolved ticket: got=%p want=%p", retained, transition)
	}
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", runtimeProfileProjectionResult(target)); err == nil || !strings.Contains(err.Error(), "stale or retired") {
		t.Fatal("late result projected onto a retired target")
	}
	if got := manager.targetByID(target.ID); got.ID != "" {
		t.Fatalf("late result resurrected retired target: %+v", got)
	}
}

func TestRuntimeProfileObservationFailureStaysUnverified(t *testing.T) {
	manager, target, transition := runtimeProfileProjectionFixture(t)
	defer manager.Close()
	result := runtimeProfileProjectionResult(target)
	result["adapters"].([]any)[0].(map[string]any)["capacity_source"] = "config"
	if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", result); err == nil {
		t.Fatal("fallback capacity source was accepted")
	}
	current := manager.targetByID(target.ID)
	if current.CapacityVerified || current.Slots != 0 || current.ContextLimit != 0 || current.CapacitySource != "runtime-profile:pending" {
		t.Fatalf("failed observation exposed verified capacity: %+v", current)
	}
}

func TestRuntimeProfileProjectionRejectsWrongNodeAndStaleGeneration(t *testing.T) {
	t.Run("wrong node", func(t *testing.T) {
		manager, target, transition := runtimeProfileProjectionFixture(t)
		defer manager.Close()
		if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "other-node", runtimeProfileProjectionResult(target)); err == nil {
			t.Fatal("observation from another node was accepted")
		}
	})
	t.Run("stale generation", func(t *testing.T) {
		manager, target, transition := runtimeProfileProjectionFixture(t)
		defer manager.Close()
		manager.mu.Lock()
		manager.targetGenerations[target.ID]++
		manager.mu.Unlock()
		if err := manager.ProjectRuntimeProfileCommandResult(transition.commandKey, "node", runtimeProfileProjectionResult(target)); err == nil {
			t.Fatal("observation crossed a newer target generation")
		}
	})
}

func TestReserveTargetLeaseDriftReleasesWithoutInMemoryResidue(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	backing := &blockedLeaseStore{WorkloadStore: base, entered: make(chan struct{}), release: make(chan struct{})}
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "lease-fence", Adapter: "mock", AcceleratorID: "lease-gpu", CapabilityVersion: "v1", ModelFingerprint: "fp", Slots: 1, Enabled: true}
	mgr.RegisterTarget(target)
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "lease-work"}}
	done := make(chan struct {
		reservation *targetReservation
		acquired    bool
		reason      string
		err         error
	}, 1)
	go func() {
		reservation, acquired, reason, err := mgr.reserveTarget(ctx, target, workload, Requirements{})
		done <- struct {
			reservation *targetReservation
			acquired    bool
			reason      string
			err         error
		}{reservation, acquired, reason, err}
	}()
	select {
	case <-backing.entered:
	case <-time.After(time.Second):
		t.Fatal("lease acquisition did not reach barrier")
	}
	updated := target
	updated.CapabilityVersion = "v2"
	mgr.RegisterTarget(updated)
	close(backing.release)
	result := <-done
	if result.err != nil || result.acquired || result.reservation != nil || !strings.Contains(result.reason, "target facts changed") {
		t.Fatalf("lease drift was committed: result=%+v", result)
	}
	mgr.placementMu.Lock()
	defer mgr.placementMu.Unlock()
	if len(mgr.activePlacements) != 0 || len(mgr.targetLeases) != 0 || len(mgr.targetActive) != 0 {
		t.Fatalf("lease drift left in-memory reservation residue: placements=%v leases=%v active=%v", mgr.activePlacements, mgr.targetLeases, mgr.targetActive)
	}
}

type requestIncrementTestAdapter struct {
	*MockAdapter
	bytes       int64
	generations map[string]uint64
	mutate      func(*RequestVRAMIncrementObservation)
}

func (a *requestIncrementTestAdapter) ObserveRequestVRAMIncrement(_ context.Context, target Target, request domain.WorkloadRequest, requirements Requirements) (RequestVRAMIncrementObservation, error) {
	observation := RequestVRAMIncrementObservation{
		TargetID: target.ID, AcceleratorID: target.AcceleratorID, RequestID: request.ID,
		Model: requirements.Model, ProfileID: target.ActiveRuntimeProfile,
		RuntimeIdentity: residencyCapacityIdentity(target), CapabilityVersion: target.CapabilityVersion,
		CapabilityRevision: target.CapabilityRevision, ModelFingerprint: target.ModelFingerprint,
		TargetGeneration: a.generations[target.ID], ContextTokens: requirements.ContextTokens,
		Bytes: a.bytes, Source: "runtime:test", Verified: true, ObservedAt: time.Now().UTC(),
	}
	if a.mutate != nil {
		a.mutate(&observation)
	}
	return observation, nil
}

func TestRequestVRAMAccountingCountsEachProvenIncrementAndRejectsSlotNPlusOne(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	target := Target{ID: "request-vram-n", Adapter: "mock", AcceleratorID: "request-vram-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-rev", ModelFingerprint: "request-vram-fp", Slots: 2, Capacity: domain.CapacityBudget{VRAMTotalBytes: 10 << 30, VRAMHardCapBytes: 10 << 30, VRAMReserveBytes: 2 << 30}, Enabled: true}
	adapter := &requestIncrementTestAdapter{MockAdapter: NewMockAdapter(), bytes: 2 << 30}
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	adapter.generations = map[string]uint64{target.ID: mgr.targetGeneration(target.ID)}
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", 4<<30)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"request-n1", "request-n2"} {
		workload := &domain.Workload{Request: domain.WorkloadRequest{ID: id}}
		reservation, acquired, reason, err := mgr.reserveTarget(ctx, target, workload, Requirements{Model: "model", ContextTokens: 128, EstimatedVRAMMB: 99})
		if err != nil || !acquired || reservation == nil {
			t.Fatalf("slot %s was not admitted: acquired=%v reason=%q err=%v", id, acquired, reason, err)
		}
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, target, "model", "request-n2"); err != nil {
		t.Fatalf("exact 10 GiB model + two increments + one reserve did not fit: %v", err)
	}
	mgr.placementMu.Lock()
	for _, id := range []string{"request-n1", "request-n2"} {
		placement := mgr.activePlacements[id]
		if !placement.requestIncrementVerified || placement.requestIncrementBytes != 2<<30 {
			mgr.placementMu.Unlock()
			t.Fatalf("generic estimate replaced independent increment proof for %s: %+v", id, placement)
		}
	}
	mgr.placementMu.Unlock()
	if _, acquired, reason, err := mgr.reserveTarget(ctx, target, &domain.Workload{Request: domain.WorkloadRequest{ID: "request-n3"}}, Requirements{Model: "model", ContextTokens: 128}); err != nil || acquired || !strings.Contains(reason, "slots are busy") {
		t.Fatalf("N+1 request exceeded the verified slot bound: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
}

func TestRequestVRAMAccountingUnknownGenericEstimateFailsClosed(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	target := Target{ID: "request-vram-unknown", Adapter: "mock", AcceleratorID: "request-vram-unknown-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-unknown-rev", ModelFingerprint: "request-vram-unknown-fp", Slots: 1, Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMHardCapBytes: 8 << 30}, Enabled: true}
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(target)
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", 4<<30)); err != nil {
		t.Fatal(err)
	}
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "unknown-estimate"}}
	if _, acquired, reason, err := mgr.reserveTarget(ctx, target, workload, Requirements{Model: "model", ContextTokens: 128, EstimatedVRAMMB: 1}); err != nil || !acquired {
		t.Fatalf("reservation setup failed: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, target, "model", workload.Request.ID); err == nil || !strings.Contains(err.Error(), "increment is unknown") {
		t.Fatalf("unverified generic estimate was treated as free or measured capacity: %v", err)
	}
	mgr.placementMu.Lock()
	placement := mgr.activePlacements[workload.Request.ID]
	mgr.placementMu.Unlock()
	if placement.requestIncrementVerified || placement.requestIncrementBytes != 0 {
		t.Fatalf("generic request estimate minted increment proof: %+v", placement)
	}
}

func TestRequestVRAMAccountingRejectsStaleOrWrongIdentityObservation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*RequestVRAMIncrementObservation)
	}{
		{name: "stale generation", mutate: func(o *RequestVRAMIncrementObservation) { o.TargetGeneration++ }},
		{name: "wrong profile", mutate: func(o *RequestVRAMIncrementObservation) { o.ProfileID = "other-profile" }},
		{name: "wrong accelerator", mutate: func(o *RequestVRAMIncrementObservation) { o.AcceleratorID = "other-gpu" }},
		{name: "wrong request", mutate: func(o *RequestVRAMIncrementObservation) { o.RequestID = "other-request" }},
		{name: "wrong runtime", mutate: func(o *RequestVRAMIncrementObservation) { o.RuntimeIdentity = "other-runtime" }},
		{name: "negative bytes", mutate: func(o *RequestVRAMIncrementObservation) { o.Bytes = -1 }},
		{name: "future timestamp", mutate: func(o *RequestVRAMIncrementObservation) { o.ObservedAt = time.Now().Add(time.Hour) }},
		{name: "stale timestamp", mutate: func(o *RequestVRAMIncrementObservation) { o.ObservedAt = time.Now().Add(-modelCapacityMaxAge - time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
			defer mgr.Close()
			target := Target{ID: "request-vram-invalid-" + strings.ReplaceAll(tc.name, " ", "-"), Adapter: "mock", AcceleratorID: "request-vram-invalid-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-invalid-rev", ModelFingerprint: "request-vram-invalid-fp", Slots: 1, Enabled: true}
			adapter := &requestIncrementTestAdapter{MockAdapter: NewMockAdapter(), bytes: 1 << 20, mutate: tc.mutate}
			mgr.RegisterAdapter(adapter)
			mgr.RegisterTarget(target)
			adapter.generations = map[string]uint64{target.ID: mgr.targetGeneration(target.ID)}
			if _, acquired, reason, err := mgr.reserveTarget(context.Background(), target, &domain.Workload{Request: domain.WorkloadRequest{ID: "invalid-proof"}}, Requirements{Model: "model", ContextTokens: 16}); err != nil || acquired || !strings.Contains(reason, "observation is invalid") {
				t.Fatalf("invalid increment observation was admitted: acquired=%v reason=%q err=%v", acquired, reason, err)
			}
			mgr.placementMu.Lock()
			defer mgr.placementMu.Unlock()
			if len(mgr.activePlacements) != 0 {
				t.Fatalf("invalid proof left a published placement: %+v", mgr.activePlacements)
			}
		})
	}
}

func TestRequestVRAMAccountingRejectsByteSumOverflow(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer mgr.Close()
	target := Target{ID: "request-vram-overflow", Adapter: "mock", AcceleratorID: "request-vram-overflow-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-overflow-rev", ModelFingerprint: "request-vram-overflow-fp", Slots: 2, Capacity: domain.CapacityBudget{VRAMTotalBytes: math.MaxInt64, VRAMHardCapBytes: math.MaxInt64}, Enabled: true}
	adapter := &requestIncrementTestAdapter{MockAdapter: NewMockAdapter(), bytes: math.MaxInt64}
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	adapter.generations = map[string]uint64{target.ID: mgr.targetGeneration(target.ID)}
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "model", 1)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"overflow-first", "overflow-second"} {
		if id == "overflow-second" {
			adapter.bytes = 1
		}
		if _, acquired, reason, err := mgr.reserveTarget(ctx, target, &domain.Workload{Request: domain.WorkloadRequest{ID: id}}, Requirements{Model: "model", ContextTokens: 1}); err != nil || !acquired {
			t.Fatalf("overflow fixture placement failed: acquired=%v reason=%q err=%v", acquired, reason, err)
		}
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, target, "model", "overflow-second"); err == nil || !strings.Contains(err.Error(), "overflows int64") {
		t.Fatalf("request increment byte sum overflow was admitted: %v", err)
	}
}

func TestRequestVRAMAccountingInitializedProfilePoolIsChargedOnceWithinVerifiedBounds(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer mgr.Close()
	target := Target{
		ID: "request-vram-pool", Adapter: "mock", AcceleratorID: "request-vram-pool-gpu",
		CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-pool-rev", ModelFingerprint: "request-vram-pool-fp",
		ActiveRuntimeProfile: "ctx-4k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		ContextLimit: 4096, Slots: 2, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-4k", ContextLimit: 4096, Slots: 2}},
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 5 << 30, VRAMHardCapBytes: 5 << 30}, Enabled: true,
	}
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(target)
	registered := mgr.targetByID(target.ID)
	if !registered.CapacityVerified || registered.Slots != 2 || registered.ContextLimit != 4096 || registered.ActiveRuntimeProfile != "ctx-4k" {
		t.Fatalf("fixture did not retain verified runtime-profile facts: %+v", registered)
	}
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(registered, "model", 3<<30, 2<<30)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pool-request-1", "pool-request-2"} {
		_, acquired, reason, err := mgr.reserveTarget(ctx, registered, &domain.Workload{Request: domain.WorkloadRequest{ID: id}}, Requirements{Model: "model", ContextTokens: 1024, EstimatedVRAMMB: 2048})
		if err != nil || !acquired {
			t.Fatalf("verified pool slot %s not reserved: acquired=%v reason=%q err=%v", id, acquired, reason, err)
		}
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, registered, "model", "pool-request-2"); err != nil {
		t.Fatalf("two bounded requests double-charged the already initialized 2 GiB pool: %v", err)
	}
}

func TestRequestVRAMAccountingCountsOtherTargetIncrementsOnSameAccelerator(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	baseTarget := Target{
		Adapter: "mock", AcceleratorID: "request-vram-shared-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-shared-rev",
		ModelFingerprint: "request-vram-shared-fp", Slots: 2, SharingEnabled: true, StandaloneVRAMMB: 1024,
		AcceleratorVRAMMB: 6 * 1024, VRAMReserveMB: 1024, PredictedSlowdown: .1, MaxSlowdown: 1.2,
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 6 << 30, VRAMHardCapBytes: 6 << 30, VRAMReserveBytes: 1 << 30}, Enabled: true,
	}
	targetA, targetB := baseTarget, baseTarget
	targetA.ID, targetA.ModelFingerprint = "request-vram-target-a", "request-vram-fp-a"
	targetB.ID, targetB.ModelFingerprint = "request-vram-target-b", "request-vram-fp-b"
	adapter := &requestIncrementTestAdapter{MockAdapter: NewMockAdapter(), bytes: 1 << 30}
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(targetA)
	mgr.RegisterTarget(targetB)
	adapter.generations = map[string]uint64{targetA.ID: mgr.targetGeneration(targetA.ID), targetB.ID: mgr.targetGeneration(targetB.ID)}
	for _, item := range []struct {
		target Target
		model  string
	}{{targetA, "model-a"}, {targetB, "model-b"}} {
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(item.target, item.model, 2<<30)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: targetA.ID + "::model-a", TargetID: targetA.ID, AcceleratorID: targetA.AcceleratorID, Model: "model-a", ObservedTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		target Target
		model  string
		id     string
	}{{targetA, "model-a", "shared-request-a"}, {targetB, "model-b", "shared-request-b"}} {
		workload := &domain.Workload{Request: domain.WorkloadRequest{ID: item.id, Disruption: domain.DisruptionSlowdown}}
		if _, acquired, reason, err := mgr.reserveTarget(ctx, item.target, workload, Requirements{Model: item.model, ContextTokens: 128}); err != nil || !acquired {
			t.Fatalf("shared physical accelerator placement %s failed: acquired=%v reason=%q err=%v", item.id, acquired, reason, err)
		}
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, targetB, "model-b", "shared-request-b"); err == nil {
		t.Fatal("physical accelerator admission omitted the other target's distinct 1 GiB request increment")
	}
}

func TestRequestVRAMAccountingSameModelOnDifferentRuntimeCountsBothFootprints(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	baseTarget := Target{
		Adapter: "mock", AcceleratorID: "request-vram-alias-gpu", CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-alias-rev",
		ModelFingerprint: "request-vram-alias-fp", Slots: 2, SharingEnabled: true, StandaloneVRAMMB: 1024,
		AcceleratorVRAMMB: 5 * 1024, VRAMReserveMB: 1024, PredictedSlowdown: .1, MaxSlowdown: 1.2,
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 5 << 30, VRAMHardCapBytes: 5 << 30, VRAMReserveBytes: 1 << 30}, Enabled: true,
	}
	targetA, targetB := baseTarget, baseTarget
	targetA.ID, targetA.ModelFingerprint = "request-vram-alias-a", "request-vram-alias-fp-a"
	targetB.ID, targetB.ModelFingerprint = "request-vram-alias-b", "request-vram-alias-fp-b"
	adapter := &requestIncrementTestAdapter{MockAdapter: NewMockAdapter(), bytes: 1 << 30}
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(targetA)
	mgr.RegisterTarget(targetB)
	adapter.generations = map[string]uint64{targetA.ID: mgr.targetGeneration(targetA.ID), targetB.ID: mgr.targetGeneration(targetB.ID)}
	for _, target := range []Target{targetA, targetB} {
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(target, "same-model", 2<<30)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: targetA.ID + "::same-model", TargetID: targetA.ID, AcceleratorID: targetA.AcceleratorID, Model: "same-model", ObservedTier: domain.ResidencyHotVRAM, Policy: domain.ResidencyAuto}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ target Target; id string }{{targetA, "alias-request-a"}, {targetB, "alias-request-b"}} {
		workload := &domain.Workload{Request: domain.WorkloadRequest{ID: item.id, Disruption: domain.DisruptionSlowdown}}
		if _, acquired, reason, err := mgr.reserveTarget(ctx, item.target, workload, Requirements{Model: "same-model", ContextTokens: 128}); err != nil || !acquired {
			t.Fatalf("alias placement %s failed: acquired=%v reason=%q err=%v", item.id, acquired, reason, err)
		}
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, targetB, "same-model", "alias-request-b"); err == nil {
		t.Fatal("same-name model allocations on different runtime identities were deduplicated; both footprints and increments must be charged")
	}
}

func requestVRAMAccountingProfileTarget(id, accelerator string) Target {
	return Target{
		ID: id, Adapter: "mock", AcceleratorID: accelerator,
		CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-profile-rev-" + id,
		ModelFingerprint: "request-vram-profile-fp-" + id,
		ActiveRuntimeProfile: "ctx-4k", CapacitySource: "runtime:/slots", CapacityVerified: true,
		ContextLimit: 4096, Slots: 2, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-4k", ContextLimit: 4096, Slots: 2}},
		SharingEnabled: true, StandaloneVRAMMB: 1, AcceleratorVRAMMB: 10 * 1024, VRAMReserveMB: 1,
		PredictedSlowdown: .1, MaxSlowdown: 1.2,
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMHardCapBytes: 8 << 30}, Enabled: true,
	}
}

func TestRequestVRAMAccountingCountsActiveAllocationsWithoutHotResidency(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "measured increment"
		if unknown {
			name = "unknown increment"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			backing := store.NewMemoryStore()
			mgr := NewManager(quietLogger(), backing, time.Second)
			defer mgr.Close()
			targetA := requestVRAMAccountingProfileTarget("request-vram-no-row-a", "request-vram-no-row-gpu")
			targetB := requestVRAMAccountingProfileTarget("request-vram-no-row-b", "request-vram-no-row-gpu")
			var adapter Adapter
			if unknown {
				adapter = NewMockAdapter()
			} else {
				measured := &requestIncrementTestAdapter{MockAdapter: NewMockAdapter(), bytes: 0}
				adapter = measured
				mgr.RegisterAdapter(measured)
			}
			if unknown {
				mgr.RegisterAdapter(adapter)
			}
			mgr.RegisterTarget(targetA)
			mgr.RegisterTarget(targetB)
			registeredA, registeredB := mgr.targetByID(targetA.ID), mgr.targetByID(targetB.ID)
			if measured, ok := adapter.(*requestIncrementTestAdapter); ok {
				measured.generations = map[string]uint64{
					registeredA.ID: mgr.targetGeneration(registeredA.ID),
					registeredB.ID: mgr.targetGeneration(registeredB.ID),
				}
			}
			for _, item := range []struct {
				target Target
				model  string
			}{{registeredA, "same-model-a"}, {registeredB, "same-model-b"}} {
				if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(item.target, item.model, 3<<30, 2<<30)); err != nil {
					t.Fatal(err)
				}
			}
			for _, item := range []struct {
				target Target
				model  string
				id     string
			}{{registeredA, "same-model-a", "no-row-a"}, {registeredB, "same-model-b", "no-row-b"}} {
				workload := &domain.Workload{Request: domain.WorkloadRequest{ID: item.id, Disruption: domain.DisruptionSlowdown}}
				if _, acquired, reason, err := mgr.reserveTarget(ctx, item.target, workload, Requirements{Model: item.model, ContextTokens: 128}); err != nil || !acquired {
					t.Fatalf("active setup %s failed: acquired=%v reason=%q err=%v", item.id, acquired, reason, err)
				}
			}
			rows, err := backing.ListModelResidencies(ctx)
			if err != nil || len(rows) != 0 {
				t.Fatalf("hot residency row unexpectedly exists: rows=%d err=%v", len(rows), err)
			}
			if err := mgr.checkResidentCapacityForWorkload(ctx, registeredB, "same-model-b", "no-row-b"); err == nil || !strings.Contains(err.Error(), "measured resident capacity") {
				t.Fatalf("active allocations without hot rows did not charge both 5-GiB footprints (unknown=%v): %v", unknown, err)
			}
		})
	}
}

func TestRequestVRAMAccountingUnmeasuredPhysicalRequestRequiresExclusiveAccelerator(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer mgr.Close()
	target := Target{ID: "request-vram-no-budget", Adapter: "mock", AcceleratorID: "request-vram-no-budget-gpu", Slots: 1, Enabled: true}
	other := Target{ID: "request-vram-no-budget-other", Adapter: "mock", AcceleratorID: "request-vram-no-budget-gpu", Slots: 1, Enabled: true}
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(target)
	mgr.RegisterTarget(other)
	registered := mgr.targetByID(target.ID)
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "physical-no-budget"}}
	if _, acquired, reason, err := mgr.reserveTarget(ctx, registered, workload, Requirements{Model: "unmeasured-model", ContextTokens: 128}); err != nil || !acquired {
		t.Fatalf("reservation fixture failed: acquired=%v reason=%q err=%v", acquired, reason, err)
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, registered, "unmeasured-model", workload.Request.ID); err != nil {
		t.Fatalf("unmeasured model on an otherwise idle accelerator was rejected: %v", err)
	}
	otherRegistered := mgr.targetByID(other.ID)
	if err := mgr.checkResidentCapacityForWorkload(ctx, otherRegistered, "other-unmeasured-model", "physical-no-budget-other"); err == nil || !strings.Contains(err.Error(), "unmeasured model cannot share accelerator") {
		t.Fatalf("unmeasured model was co-placed with another target's active work: %v", err)
	}
}

func TestRequestVRAMAccountingRejectsChangedVerifiedPoolBindings(t *testing.T) {
	for _, mutation := range []string{"context shrink", "profile change", "generation change"} {
		t.Run(mutation, func(t *testing.T) {
			ctx := context.Background()
			mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
			defer mgr.Close()
			target := requestVRAMAccountingProfileTarget("request-vram-changed-"+strings.ReplaceAll(mutation, " ", "-"), "request-vram-changed-gpu")
			mgr.RegisterAdapter(NewMockAdapter())
			mgr.RegisterTarget(target)
			registered := mgr.targetByID(target.ID)
			if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(registered, "model", 3<<30, 2<<30)); err != nil {
				t.Fatal(err)
			}
			workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "changed-pool-" + mutation}}
			if _, acquired, reason, err := mgr.reserveTarget(ctx, registered, workload, Requirements{Model: "model", ContextTokens: 128}); err != nil || !acquired {
				t.Fatalf("known-positive bounded reservation failed: acquired=%v reason=%q err=%v", acquired, reason, err)
			}
			switch mutation {
			case "context shrink":
				updated := mgr.targetByID(target.ID)
				updated.ContextLimit = 64
				updated.RuntimeProfiles = []RuntimeCapacityProfile{{ID: "ctx-4k", ContextLimit: 64, Slots: 2}}
				mgr.RegisterTarget(updated)
			case "profile change":
				updated := mgr.targetByID(target.ID)
				updated.ActiveRuntimeProfile = "ctx-2k"
				updated.RuntimeProfiles = []RuntimeCapacityProfile{{ID: "ctx-2k", ContextLimit: 2048, Slots: 2}}
				mgr.RegisterTarget(updated)
			case "generation change":
				mgr.mu.Lock()
				mgr.targetGenerations[target.ID]++
				mgr.mu.Unlock()
			}
			err := mgr.checkResidentCapacityForWorkload(ctx, mgr.targetByID(target.ID), "model", workload.Request.ID)
			if err == nil {
				t.Fatal("changed verified pool binding was accepted")
			}
			if mutation == "profile change" {
				if !strings.Contains(err.Error(), "capacity measurement missing") {
					t.Fatalf("profile change did not fail on the newly selected measured profile: %v", err)
				}
			} else if !strings.Contains(err.Error(), "active physical allocation binding is stale") {
				t.Fatalf("changed verified pool binding did not fail its generation/context fence: %v", err)
			}
		})
	}
}

func TestRequestVRAMAccountingThirdIncrementOverflowsWithThreeSlots(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer mgr.Close()
	target := Target{
		ID: "request-vram-three-slot-overflow", Adapter: "mock", AcceleratorID: "request-vram-three-slot-gpu",
		CapabilityVersion: "runtime-v1", CapabilityRevision: "request-vram-three-slot-rev", ModelFingerprint: "request-vram-three-slot-fp",
		Slots: 3, SharingEnabled: true, StandaloneVRAMMB: 1, AcceleratorVRAMMB: 10 * 1024, VRAMReserveMB: 1,
		PredictedSlowdown: .1, MaxSlowdown: 1.2,
		Capacity: domain.CapacityBudget{VRAMTotalBytes: math.MaxInt64, VRAMHardCapBytes: math.MaxInt64}, Enabled: true,
	}
	adapter := &requestIncrementTestAdapter{MockAdapter: NewMockAdapter(), bytes: math.MaxInt64/3 + 1}
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	registered := mgr.targetByID(target.ID)
	adapter.generations = map[string]uint64{registered.ID: mgr.targetGeneration(registered.ID)}
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacity(registered, "model", 1)); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"three-slot-1", "three-slot-2", "three-slot-3"} {
		if _, acquired, reason, err := mgr.reserveTarget(ctx, registered, &domain.Workload{Request: domain.WorkloadRequest{ID: id}}, Requirements{Model: "model", ContextTokens: 1}); err != nil || !acquired {
			t.Fatalf("three-slot fixture %s failed: acquired=%v reason=%q err=%v", id, acquired, reason, err)
		}
		if i < 2 {
			if err := mgr.checkResidentCapacityForWorkload(ctx, registered, "model", id); err != nil {
				t.Fatalf("three-slot prefix %s should fit before the third increment: %v", id, err)
			}
		}
	}
	if err := mgr.checkResidentCapacityForWorkload(ctx, registered, "model", "three-slot-3"); err == nil || !strings.Contains(err.Error(), "overflows int64") {
		t.Fatalf("third byte increment exceeded int64 without checked overflow despite three free slots: %v", err)
	}
}

func TestReserveTargetLeaseRollbackFailureRecordsReconciliationResidue(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	backing := &failingReleaseLeaseStore{blockedLeaseStore: &blockedLeaseStore{WorkloadStore: base, entered: make(chan struct{}), release: make(chan struct{})}}
	mgr := NewManager(quietLogger(), backing, time.Second)
	target := Target{ID: "lease-rollback-fence", Adapter: "mock", AcceleratorID: "lease-rollback-gpu", CapabilityVersion: "v1", ModelFingerprint: "fp", Slots: 1, Enabled: true}
	mgr.RegisterTarget(target)
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "lease-rollback-work"}}
	done := make(chan struct {
		reservation *targetReservation
		acquired    bool
		reason      string
		err         error
	}, 1)
	go func() {
		reservation, acquired, reason, err := mgr.reserveTarget(ctx, target, workload, Requirements{})
		done <- struct {
			reservation *targetReservation
			acquired    bool
			reason      string
			err         error
		}{reservation, acquired, reason, err}
	}()
	select {
	case <-backing.entered:
	case <-time.After(time.Second):
		t.Fatal("lease acquisition did not reach barrier")
	}
	updated := target
	updated.CapabilityVersion = "v2"
	mgr.RegisterTarget(updated)
	close(backing.release)
	result := <-done
	if result.err == nil || !strings.Contains(result.err.Error(), "rollback pending reconciliation") || result.acquired || result.reservation != nil {
		t.Fatalf("lease rollback failure was not surfaced: result=%+v", result)
	}
	intents, intentErr := base.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC().Add(2*time.Second), 10)
	if intentErr != nil || len(intents) != 1 {
		t.Fatalf("durable lease cleanup intent was not recorded: intents=%+v err=%v", intents, intentErr)
	}
}

func makeReleaseTargetFixture(t *testing.T, backing store.WorkloadStore, lease *domain.AcceleratorLease) (*Manager, *targetReservation) {
	t.Helper()
	mgr := NewManager(quietLogger(), backing, time.Second)
	reservation := &targetReservation{targetID: "cleanup-target", workloadID: lease.WorkloadID, lease: lease}
	mgr.placementMu.Lock()
	mgr.activePlacements[lease.WorkloadID] = activePlacement{workloadID: lease.WorkloadID, targetID: reservation.targetID, acceleratorID: lease.AcceleratorID}
	mgr.targetActive[reservation.targetID] = 1
	mgr.targetLeases[reservation.targetID] = lease
	mgr.placementMu.Unlock()
	mgr.mu.Lock()
	mgr.reservations[lease.WorkloadID] = reservation
	mgr.mu.Unlock()
	return mgr, reservation
}

func TestReleaseTargetUsesBoundedContextAndDurableIntent(t *testing.T) {
	base := store.NewMemoryStore()
	lease, acquired, err := base.AcquireAcceleratorLease(context.Background(), "cleanup-gpu", "cleanup-workload", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire: %+v %v %v", lease, acquired, err)
	}
	failing := &failingReleaseLeaseStore{blockedLeaseStore: &blockedLeaseStore{WorkloadStore: base, entered: make(chan struct{}), release: make(chan struct{})}}
	mgr, reservation := makeReleaseTargetFixture(t, failing, lease)
	if err := mgr.releaseTarget(context.Background(), reservation); !errors.Is(err, errLeaseCleanupRecorded) {
		t.Fatalf("durable cleanup intent did not remain visible to terminal continuation: %v", err)
	}
	if reservation.released {
		t.Fatal("reservation was finalized before physical release confirmation")
	}
	intents, err := base.ListAcceleratorLeaseCleanupIntents(context.Background(), time.Now().UTC().Add(2*time.Second), 10)
	if err != nil || len(intents) != 1 || intents[0].Owner != lease.WorkloadID || intents[0].FencingToken != lease.FencingToken {
		t.Fatalf("exact cleanup intent missing: %+v %v", intents, err)
	}

	cancelAware := &contextCheckingReleaseStore{WorkloadStore: base}
	lease2, acquired, err := base.AcquireAcceleratorLease(context.Background(), "cleanup-gpu-2", "cleanup-workload-2", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("second acquire: %+v %v %v", lease2, acquired, err)
	}
	mgr2, reservation2 := makeReleaseTargetFixture(t, cancelAware, lease2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := mgr2.releaseTarget(ctx, reservation2); err != nil || !reservation2.released {
		t.Fatalf("already-cancelled context blocked bounded release: err=%v released=%v", err, reservation2.released)
	}
}

func TestGenericLeaseCleanupRetryAdvancesExistingIntent(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	lease, acquired, err := base.AcquireAcceleratorLease(ctx, "retry-gpu", "retry-workload", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire: %+v %v", lease, err)
	}
	backing := &countingReleaseLeaseStore{WorkloadStore: base, failures: 2}
	mgr := NewManager(quietLogger(), backing, time.Second)
	if err := mgr.rollbackAcceleratorLease(ctx, lease, lease.WorkloadID); !errors.Is(err, errLeaseCleanupRecorded) {
		t.Fatalf("initial failed release was not durably recorded: %v", err)
	}
	for expectedAttempts := 2; expectedAttempts <= 3; expectedAttempts++ {
		rows, listErr := base.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC().Add(time.Hour), 10)
		if listErr != nil || len(rows) != 1 || rows[0].Attempts != expectedAttempts-1 {
			t.Fatalf("before retry %d exact intent missing: %+v %v", expectedAttempts, rows, listErr)
		}
		past := time.Now().UTC().Add(-time.Second)
		rows[0].NextRetryAt = &past
		if _, err := base.RecordAcceleratorLeaseCleanupIntent(ctx, rows[0]); err != nil {
			t.Fatal(err)
		}
		mgr.retryAcceleratorLeaseCleanupIntents(ctx)
		if expectedAttempts == 3 {
			continue
		}
		rows, listErr = base.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC().Add(time.Hour), 10)
		if listErr != nil || len(rows) != 1 || rows[0].Attempts != expectedAttempts {
			t.Fatalf("retry %d did not persist exact increment: %+v %v", expectedAttempts, rows, listErr)
		}
		if rows[0].NextRetryAt == nil || !rows[0].NextRetryAt.After(rows[0].UpdatedAt) {
			t.Fatalf("retry %d did not schedule bounded future retry: %+v", expectedAttempts, rows[0])
		}
	}
	if rows, err := base.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC().Add(time.Hour), 10); err != nil || len(rows) != 0 {
		t.Fatalf("successful exact retry did not delete intent: %+v %v", rows, err)
	}
	if backing.calls != 3 {
		t.Fatalf("release attempts were not initial+two retries: %d", backing.calls)
	}
}

func TestReleaseTargetRetainsOwnershipWhenIntentPersistenceFails(t *testing.T) {
	base := store.NewMemoryStore()
	lease, acquired, err := base.AcquireAcceleratorLease(context.Background(), "cleanup-gpu-fail", "cleanup-workload-fail", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire: %+v %v %v", lease, acquired, err)
	}
	backing := &failingCleanupIntentStore{WorkloadStore: &failingReleaseLeaseStore{blockedLeaseStore: &blockedLeaseStore{WorkloadStore: base, entered: make(chan struct{}), release: make(chan struct{})}}}
	mgr, reservation := makeReleaseTargetFixture(t, backing, lease)
	if err := mgr.releaseTarget(context.Background(), reservation); err == nil {
		t.Fatal("release succeeded without physical release or durable cleanup intent")
	}
	if reservation.released {
		t.Fatal("terminal reservation state published before cleanup durability")
	}
	mgr.placementMu.Lock()
	_, stillOwned := mgr.activePlacements[lease.WorkloadID]
	mgr.placementMu.Unlock()
	if !stillOwned {
		t.Fatal("in-memory placement ownership was discarded before cleanup durability")
	}
}

func TestTerminalLeaseCleanupContinuationResumesAllDispositions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		disposition string
		want        domain.WorkloadStatus
	}{
		{name: "success", disposition: "success", want: domain.WorkloadSucceeded},
		{name: "failure", disposition: "failure", want: domain.WorkloadFailed},
		{name: "cancel", disposition: "cancel", want: domain.WorkloadCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base := store.NewMemoryStore()
			workloadID := "terminal-continuation-" + tc.name
			lease, acquired, err := base.AcquireAcceleratorLease(ctx, "terminal-gpu-"+tc.name, workloadID, time.Minute)
			if err != nil || !acquired {
				t.Fatalf("acquire: %+v %v %v", lease, acquired, err)
			}
			workload := &domain.Workload{Request: domain.WorkloadRequest{ID: workloadID, OwnerID: "owner"}, Status: domain.WorkloadQueued}
			if _, _, err := base.CreateWorkload(ctx, workload); err != nil {
				t.Fatal(err)
			}
			failing := &failingReleaseLeaseStore{blockedLeaseStore: &blockedLeaseStore{WorkloadStore: base, entered: make(chan struct{}), release: make(chan struct{})}}
			mgr, reservation := makeReleaseTargetFixture(t, failing, lease)
			if err := mgr.releaseBeforeTerminal(ctx, workload, reservation, tc.disposition, "continuation test"); !errors.Is(err, errLeaseCleanupRecorded) {
				t.Fatalf("cleanup was not deferred durably: %v", err)
			}
			intents, err := base.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC().Add(2*time.Second), 10)
			if err != nil || len(intents) != 1 || intents[0].WorkloadID != workloadID || intents[0].TerminalDisposition != tc.disposition {
				t.Fatalf("terminal cleanup intent incomplete: %+v %v", intents, err)
			}
			past := time.Now().UTC().Add(-time.Second)
			intents[0].NextRetryAt = &past
			if _, err := base.RecordAcceleratorLeaseCleanupIntent(ctx, intents[0]); err != nil {
				t.Fatal(err)
			}
			restarted := NewManager(quietLogger(), base, time.Second)
			restarted.retryAcceleratorLeaseCleanupIntents(ctx)
			finished, err := restarted.Wait(ctx, workloadID)
			if err != nil || finished.Status != tc.want {
				t.Fatalf("restart did not resume %s terminal continuation: workload=%+v err=%v", tc.disposition, finished, err)
			}
			remaining, err := base.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC().Add(time.Second), 10)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("cleanup intent remained after terminal continuation: %+v %v", remaining, err)
			}
		})
	}
}

func TestTargetExecutionFingerprintCoversDispatchAndCapacityFacts(t *testing.T) {
	base := Target{ID: "fingerprint", Adapter: "mock", Endpoint: "https://runtime", RuntimeProtocol: "signed-v1", AcceleratorID: "gpu-0", Models: []string{"model"}, CustomNodes: []string{"node"}, ContextLimit: 4096, Slots: 2, CapabilityVersion: "v1", CapabilityRevision: "r1", Capabilities: domain.ResidencyCapabilities{Version: "r1", MaxResidentModels: 2}, Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, MaxAcceleratorsPerWorkload: 1, ModelFingerprint: "model-fp", CapacitySource: "runtime:ps", CapacityVerified: true, RuntimeArgs: []string{"--ctx", "4096"}, SupportsModelLifecycle: true, SupportsAcceleratorReclaim: true, MaxResidentModels: 2, WarmRAMSupported: true, ResidencyPolicy: domain.ResidencyAuto, Enabled: true, SharingEnabled: true, MaxSlowdown: 1.2, SafetyCritical: false, Provider: "provider", InputCentsPerMTok: 1, OutputCentsPerMTok: 2, Authorization: "secret"}
	cases := []struct {
		name   string
		mutate func(*Target)
	}{
		{"endpoint", func(v *Target) { v.Endpoint = "https://other" }},
		{"model catalog", func(v *Target) { v.Models = []string{"other"} }},
		{"custom node", func(v *Target) { v.CustomNodes = []string{"other"} }},
		{"capacity", func(v *Target) { v.Capacity.VRAMHardCapBytes++ }},
		{"runtime profile", func(v *Target) { v.ActiveRuntimeProfile = "small" }},
		{"slots", func(v *Target) { v.Slots++ }},
		{"policy", func(v *Target) { v.ResidencyPolicy = domain.ResidencyPinned }},
		{"provider pricing", func(v *Target) { v.InputCentsPerMTok++ }},
		{"authorization", func(v *Target) { v.Authorization = "different-secret" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.mutate(&changed)
			if targetExecutionGenerationEqual(base, changed) || targetIdentityMatches(base, changed) {
				t.Fatalf("mutation %q did not advance execution fingerprint", tc.name)
			}
		})
	}
}

func TestRuntimeProfileSchedulerDoesNotSwitchWhileAcceleratorIsActive(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(modelAwareMockAdapter{NewMockAdapter()})
	mgr.RegisterTarget(Target{
		ID: "runtime", Adapter: "model-mock", AcceleratorID: "gpu-0", Models: []string{"model"}, ResidentModels: []string{"model"},
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", SupportsRuntimeProfileSwitch: true, Enabled: true,
		RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}},
	})
	mgr.placementMu.Lock()
	mgr.activePlacements["active-video"] = activePlacement{workloadID: "active-video", targetID: "video", acceleratorID: "gpu-0"}
	mgr.placementMu.Unlock()
	commands := 0
	mgr.SetNodeControl(func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		commands++
		return nil, nil
	})
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{
		OwnerID: "owner", Adapter: "model-mock", Payload: json.RawMessage(`{"model":"model"}`),
		Bounds: domain.WorkloadBounds{ContextTokens: 30_000, MaxOutput: 1_000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if commands != 0 || row.Status != domain.WorkloadWaiting || !strings.Contains(strings.Join(row.Decision.Alternatives, " "), "waiting for the accelerator to become idle") {
		t.Fatalf("active accelerator was not protected from a profile switch: commands=%d row=%+v", commands, row)
	}
}

func TestRuntimeProfileStaleResultCannotResurrectRetiredTarget(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true}, Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 16_000, VRAMFreeMB: 16_000}}}); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.SetNodeStore(backing)
	target := Target{ID: "node-runtime", NodeID: "node", Adapter: "model-mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "fp", ActiveRuntimeProfile: "ctx-8k", ContextLimit: 8192, Slots: 4, CapacitySource: "runtime:/slots", CapacityVerified: true, SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true}
	mgr.RegisterTarget(target)
	entered, release := make(chan struct{}), make(chan struct{})
	mgr.SetNodeControl(func(_ context.Context, _ string, command string, _ map[string]any, _ string) (map[string]any, error) {
		if command != "switch_runtime_profile" {
			return nil, fmt.Errorf("unexpected command %s", command)
		}
		close(entered)
		<-release
		return map[string]any{"profile_id": "ctx-32k"}, nil
	})
	done := make(chan struct {
		target Target
		reason string
		err    error
	}, 1)
	go func() {
		updated, reason, err := mgr.ensureRuntimeProfile(ctx, target, target.RuntimeProfiles[1], &domain.Workload{Request: domain.WorkloadRequest{ID: "profile-stale"}})
		done <- struct {
			target Target
			reason string
			err    error
		}{updated, reason, err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("runtime profile command did not reach barrier")
	}
	mgr.ReconcileNodeTargets("node", map[string]struct{}{})
	close(release)
	result := <-done
	if result.err == nil || !strings.Contains(result.err.Error(), "stale or retired") {
		t.Fatalf("stale profile result was accepted: target=%+v reason=%q err=%v", result.target, result.reason, result.err)
	}
	if got := mgr.targetByID(target.ID); got.ID != "" {
		t.Fatalf("retired target was resurrected by stale profile result: %+v", got)
	}
}

func TestModelAcceleratorLimitDefaultsToOneAndCanBeRaised(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := NewMockAdapter()
	mock.Delay = 2 * time.Second
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(modelAwareMockAdapter{mock})
	for _, target := range []Target{
		{
			ID: "card-a", Adapter: "model-mock", AcceleratorID: "gpu-a", Models: []string{"model"}, ContextLimit: 8192, Slots: 1,
			ActiveRuntimeProfile: "model-profile", RuntimeProfiles: []RuntimeCapacityProfile{{ID: "model-profile", ContextLimit: 8192, Slots: 1}},
			CapabilityVersion: "model-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelFingerprint: "model-fixture-fp",
			Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 8 << 30},
			CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
		},
		{
			ID: "card-b", Adapter: "model-mock", AcceleratorID: "gpu-b", Models: []string{"model"}, ContextLimit: 8192, Slots: 1,
			ActiveRuntimeProfile: "model-profile", RuntimeProfiles: []RuntimeCapacityProfile{{ID: "model-profile", ContextLimit: 8192, Slots: 1}},
			CapabilityVersion: "model-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelFingerprint: "model-fixture-fp",
			Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 8 << 30},
			CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
		},
	} {
		mgr.RegisterTarget(target)
		registered := mgr.targetByID(target.ID)
		if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(registered, "model", 2<<30, 1<<30)); err != nil {
			t.Fatalf("seed measured model/profile capacity for %s: %v", target.ID, err)
		}
	}
	mgr.Start(ctx)
	request := func(item string) *domain.Workload {
		row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", ItemID: item, Adapter: "model-mock", Payload: json.RawMessage(`{"model":"model"}`), Bounds: domain.WorkloadBounds{ContextTokens: 1000}})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	first := request("first")
	if first.Status != domain.WorkloadRunning {
		t.Fatalf("first model workload was not admitted: %+v", first)
	}
	second := request("second")
	if second.Status != domain.WorkloadWaiting || !strings.Contains(strings.Join(second.Decision.Alternatives, " "), "model accelerator limit 1 reached") {
		t.Fatalf("default one-card model limit was not enforced: %+v", second)
	}
	mgr.SetModelCapacityPolicies(2, nil)
	mgr.reconcile(ctx)
	second, err := mgr.Get(ctx, second.Request.ID)
	if err != nil || second.Status != domain.WorkloadRunning || second.Plan == nil || second.Plan.TargetID == first.Plan.TargetID {
		t.Fatalf("raising the setting did not permit the second card: %+v err=%v", second, err)
	}
}

func TestModelCapacitySnapshotHonorsCardCeilingAndForeignOccupancy(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(modelAwareMockAdapter{NewMockAdapter()})
	target := Target{
		ID: "llm-b", Adapter: "model-mock", AcceleratorID: "gpu-b", Models: []string{"model"}, ContextLimit: 4096, Slots: 4,
		ActiveRuntimeProfile: "model-profile", RuntimeProfiles: []RuntimeCapacityProfile{{ID: "model-profile", ContextLimit: 4096, Slots: 4}},
		CapabilityVersion: "model-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelFingerprint: "model-fixture-fp",
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 16 << 30},
		CapacityVerified: true, CapacitySource: "runtime:/slots", Enabled: true,
	}
	mgr.RegisterTarget(target)
	target = mgr.targetByID(target.ID)
	if _, err := mgr.SetModelCapacity(context.Background(), measuredCapacityWithProfile(target, "model", 2<<30, 1<<30)); err != nil {
		t.Fatalf("seed measured snapshot model/profile capacity: %v", err)
	}
	mgr.placementMu.Lock()
	mgr.activePlacements["same-model-on-a"] = activePlacement{workloadID: "same-model-on-a", targetID: "llm-a", acceleratorID: "gpu-a", model: "model"}
	mgr.placementMu.Unlock()
	if got := mgr.CurrentlyAvailableSlotsForModel(context.Background(), target, "model"); got != 0 {
		t.Fatalf("snapshot promised %d slots on a second card despite the one-card ceiling", got)
	}
	mgr.SetModelCapacityPolicies(2, nil)
	if got := mgr.CurrentlyAvailableSlotsForModel(context.Background(), target, "model"); got != 4 {
		t.Fatalf("raised card ceiling did not expose the second card's slots: %d", got)
	}
	mgr.placementMu.Lock()
	mgr.activePlacements["foreign"] = activePlacement{workloadID: "foreign", targetID: "comfy-b", acceleratorID: "gpu-b"}
	mgr.placementMu.Unlock()
	if got := mgr.CurrentlyAvailableSlotsForModel(context.Background(), target, "model"); got != 0 {
		t.Fatalf("snapshot promised %d slots while another adapter occupied the card", got)
	}
}

type checkpointCompensationAdapter struct {
	checkpointTestAdapter
	resumeCalls int
	failResume  bool
}

func (a *checkpointCompensationAdapter) ResumeWithLease(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, string, Target, SlotLease, CheckpointCommand) (*domain.ExecutionHandle, error) {
	a.resumeCalls++
	if a.failResume {
		return nil, errors.New("injected compensation resume failure")
	}
	return &domain.ExecutionHandle{ExternalID: "compensated-victim", StartedAt: time.Now().UTC()}, nil
}

func (a *checkpointCompensationAdapter) CheckpointWithLease(context.Context, *domain.ExecutionHandle, Target, SlotLease, CheckpointCommand) (string, error) {
	return "victim.kv", nil
}

type checkpointRecoveryCrashAdapter struct {
	checkpointCompensationAdapter
	cancelled []string
	cancelErr error
}

func (a *checkpointRecoveryCrashAdapter) Cancel(_ context.Context, handle *domain.ExecutionHandle, _ Target) error {
	if handle != nil {
		a.cancelled = append(a.cancelled, handle.ExternalID)
	}
	return a.cancelErr
}

func (a *checkpointRecoveryCrashAdapter) Plan(context.Context, domain.WorkloadRequest, Target) (*domain.ExecutionPlan, error) {
	return &domain.ExecutionPlan{ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096}, nil
}

// checkpointPhysicalRestoreCrashAdapter terminates the controller worker after
// the node has accepted the restore command but before ResumeWithLease can
// publish a fresh handle into the durable operation row.  The pre-resume
// cleanup journal is the only restart-visible identity at this seam, so the
// restarted manager must synthesize one bounded cancel and release the exact
// fresh fence without issuing a second restore.
type checkpointPhysicalRestoreCrashAdapter struct {
	checkpointRecoveryCrashAdapter
	reached    chan struct{}
	once       sync.Once
	operations store.LLMCheckpointOperationStore
}

func (a *checkpointPhysicalRestoreCrashAdapter) ResumeWithLease(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, checkpoint string, target Target, lease SlotLease, command CheckpointCommand) (*domain.ExecutionHandle, error) {
	a.resumeCalls++
	if a.operations != nil {
		conversation := command.ConversationID
		if conversation == "" {
			conversation = "physical-compensation-conversation"
		}
		handle := &domain.ExecutionHandle{ExternalID: "physical-compensation-handle", Opaque: []byte(`{"slot_id":0,"operation_id":"physical-crash-transition:compensate","generation":1,"fence":2,"conversation_id":"physical-compensation-conversation"}`)}
		_, _, _ = a.operations.CreateLLMCheckpointOperation(ctx, &store.LLMCheckpointOperation{
			ID: command.ID, IdempotencyKey: command.IdempotencyKey, OwnerID: req.OwnerID, WorkloadID: req.ID,
			NodeID: target.NodeID, AcceleratorID: lease.AcceleratorID, TargetID: target.ID, Model: "model", ModelFingerprint: "model",
			RuntimeIdentity: target.RuntimeIdentity, ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: conversation,
			ContinuationConversationID: "continuation-physical-compensation", CompensationOf: command.CompensationOf, WorkloadRevision: command.WorkloadRevision,
			SnapshotName: checkpoint, SlotID: 0, Generation: lease.Generation, Fence: lease.Fence, Phase: "restore_planned",
			PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), RecoveryState: "pending", CleanupOperationID: command.ID, CleanupSlotID: 0,
			CleanupConversationID: conversation, CleanupState: "owned", CleanupHandle: handle, CleanupTargetID: target.ID, CleanupNodeID: target.NodeID,
			CleanupAcceleratorID: lease.AcceleratorID, CleanupGeneration: lease.Generation, CleanupFence: lease.Fence,
		})
	}
	a.once.Do(func() { close(a.reached) })
	runtime.Goexit()
	return nil, nil
}

func TestCheckpointRecoveryCrashBeforeFreshHandleJournalRetriesStopWithoutDuplicateRestore(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &checkpointPhysicalRestoreCrashAdapter{reached: make(chan struct{}), operations: backing}
	target := Target{ID: "physical-crash-gpu", NodeID: "physical-crash-node", Adapter: "preempt", AcceleratorID: "physical-crash-accelerator", RuntimeIdentity: "runtime", Enabled: true}
	manager := NewManager(quietLogger(), backing, time.Second)
	manager.RegisterAdapter(adapter)
	manager.RegisterTarget(target)
	victim := &domain.Workload{
		Request:   domain.WorkloadRequest{ID: "physical-crash-victim", OwnerID: "owner", Adapter: "preempt"},
		Status:    domain.WorkloadRunning,
		Revision:  1,
		Plan:      &domain.ExecutionPlan{TargetID: target.ID, ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096},
		Execution: &domain.ExecutionHandle{ExternalID: "stale-physical-crash"},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	created, _, err := backing.CreateWorkload(ctx, victim)
	if err != nil {
		t.Fatal(err)
	}
	oldLease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, created.Request.ID, time.Minute)
	if err != nil || !acquired || oldLease == nil {
		t.Fatalf("acquire old lease: lease=%+v acquired=%v err=%v", oldLease, acquired, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = manager.restoreCheckpointVictim(ctx, created, target, adapter, "physical-crash.kv", oldLease, "physical-crash-transition")
	}()
	select {
	case <-adapter.reached:
	case <-time.After(time.Second):
		t.Fatal("restore did not reach the injected physical crash boundary")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("controller worker did not terminate at the injected crash boundary")
	}
	if adapter.resumeCalls != 1 {
		t.Fatalf("unexpected physical restore count before restart: %d", adapter.resumeCalls)
	}

	operation, err := backing.GetLLMCheckpointOperation(ctx, "physical-crash-transition:outer-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if operation.RecoveryState != "pending" || operation.CleanupState != "pending" || operation.CleanupHandle != nil || operation.CleanupAcceleratorID != target.AcceleratorID || operation.CleanupFence <= operation.Fence {
		t.Fatalf("physical crash did not leave durable pre-resume custody: %+v", operation)
	}
	freshLease, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID)
	if err != nil || freshLease == nil || freshLease.FencingToken <= oldLease.FencingToken || freshLease.WorkloadID != created.Request.ID {
		t.Fatalf("fresh lease was not retained across the crash seam: lease=%+v err=%v old=%+v", freshLease, err, oldLease)
	}

	restarted := NewManager(quietLogger(), backing, time.Second)
	restarted.RegisterAdapter(adapter)
	restarted.RegisterTarget(target)
	restarted.recoverCheckpointRecoveryIntents(ctx)
	restarted.recoverCheckpointCleanupIntents(ctx)

	if adapter.resumeCalls != 1 {
		t.Fatalf("restart issued a duplicate physical restore: %d calls", adapter.resumeCalls)
	}
	if len(adapter.cancelled) != 1 || !strings.Contains(adapter.cancelled[0], "physical-compensation-handle") {
		t.Fatalf("restart did not cancel the physical compensation cleanup handle: %v", adapter.cancelled)
	}
	if lease, leaseErr := backing.GetAcceleratorLease(ctx, target.AcceleratorID); leaseErr == nil && lease != nil {
		t.Fatalf("restart released the fresh lease before confirmed cleanup: %+v", lease)
	}
	operation, err = backing.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || operation.RecoveryState != "requeued" || operation.CleanupState != "confirmed" {
		t.Fatalf("restart did not converge the missing-handle cleanup intent: op=%+v err=%v", operation, err)
	}
	requeued, err := backing.GetWorkload(ctx, created.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if requeued.Status != domain.WorkloadQueued || requeued.Execution != nil || requeued.CheckpointRef != "physical-crash.kv" {
		t.Fatalf("restart did not requeue the victim after confirmed cleanup: %+v", requeued)
	}
}

// TestCheckpointRecoveryCrashAfterPhysicalRestoreBeforeAdoption exercises the
// exact seam where the node has returned a fresh resumed handle/fence but the
// outer workload projection has not yet adopted it. A restarted manager must
// use the durable fresh identity (never the stale old handle), and must be able
// to either adopt it when the original projection is still current or cancel
// and requeue it when another writer has advanced that projection.
func TestCheckpointRecoveryCrashAfterPhysicalRestoreBeforeAdoption(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &checkpointRecoveryCrashAdapter{}
	target := Target{ID: "recovery-gpu", NodeID: "recovery-node", Adapter: "preempt", AcceleratorID: "recovery-gpu-0", RuntimeIdentity: "runtime", Enabled: true}
	manager := NewManager(quietLogger(), backing, time.Second)
	manager.RegisterAdapter(adapter)
	manager.RegisterTarget(target)

	seed := func(t *testing.T, id string, advanceProjection bool) (*store.LLMCheckpointOperation, *domain.ExecutionHandle, *domain.AcceleratorLease) {
		t.Helper()
		victim := &domain.Workload{
			Request:   domain.WorkloadRequest{ID: id, OwnerID: "recovery-owner", Adapter: "preempt"},
			Status:    domain.WorkloadRunning,
			Plan:      &domain.ExecutionPlan{TargetID: target.ID, ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096},
			Execution: &domain.ExecutionHandle{ExternalID: "stale-" + id, Opaque: json.RawMessage(`{"stale":true}`)},
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		created, _, err := backing.CreateWorkload(ctx, victim)
		if err != nil {
			t.Fatal(err)
		}
		oldLease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID+"-"+id, id, time.Minute)
		if err != nil || !acquired {
			t.Fatalf("acquire old lease: lease=%+v acquired=%v err=%v", oldLease, acquired, err)
		}
		oldLease.AcceleratorID = target.AcceleratorID + "-" + id
		// The target uses a distinct accelerator per case so the two durable
		// intents cannot serialize each other in the in-memory store.
		caseTarget := target
		caseTarget.AcceleratorID = oldLease.AcceleratorID
		intent, err := manager.persistCheckpointRecoveryIntent(ctx, created, caseTarget, "victim-"+id+".kv", "transition-"+id, oldLease)
		if err != nil {
			t.Fatalf("persist outer recovery intent: %v", err)
		}
		handle, freshLease, err := manager.restoreCheckpointVictim(ctx, created, caseTarget, adapter, "victim-"+id+".kv", oldLease, "transition-"+id)
		if err != nil || handle == nil || freshLease == nil || freshLease.FencingToken <= oldLease.FencingToken {
			t.Fatalf("physical restore did not cross fresh fence: handle=%+v lease=%+v err=%v", handle, freshLease, err)
		}
		if advanceProjection {
			changed, getErr := backing.GetWorkload(ctx, id)
			if getErr != nil {
				t.Fatal(getErr)
			}
			changed.Error = "newer projection won before adoption"
			changed.UpdatedAt = time.Now().UTC()
			if _, updateErr := backing.UpdateWorkload(ctx, changed); updateErr != nil {
				t.Fatal(updateErr)
			}
		}
		return intent, handle, freshLease
	}

	adoptIntent, restoredHandle, restoredLease := seed(t, "adopt", false)
	// This is the crash point: seed has completed physical restore and the
	// durable intent is `restored`, but no outer workload CAS has run yet.
	restarted := NewManager(quietLogger(), backing, time.Second)
	restarted.RegisterAdapter(adapter)
	restarted.RegisterTarget(target)
	restarted.recoverCheckpointRecoveryIntents(ctx)
	adopted, err := backing.GetWorkload(ctx, "adopt")
	if err != nil {
		t.Fatal(err)
	}
	if adopted.Execution == nil || adopted.Execution.ExternalID != restoredHandle.ExternalID || adopted.Execution.ExternalID == "stale-adopt" || adopted.CheckpointRef != "" || adopted.Status != domain.WorkloadRunning {
		t.Fatalf("restart adopted stale/missing handle after restore seam: workload=%+v restored=%+v", adopted, restoredHandle)
	}
	marked, err := backing.GetLLMCheckpointOperation(ctx, adoptIntent.ID)
	if err != nil || marked.RecoveryState != "adopted" || marked.RecoveryHandle == nil || marked.RecoveryFence != uint64(restoredLease.FencingToken) || marked.RecoveryWorkloadRevision == 0 {
		t.Fatalf("fresh restore identity was not durably adopted: op=%+v err=%v", marked, err)
	}

	cancelIntent, _, cancelLease := seed(t, "cancel", true)
	restarted.recoverCheckpointRecoveryIntents(ctx)
	cancelled, err := backing.GetWorkload(ctx, "cancel")
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != domain.WorkloadQueued || cancelled.Execution != nil || cancelled.CheckpointRef != "victim-cancel.kv" {
		t.Fatalf("restart did not safely cancel/requeue a non-adoptable fresh restore: %+v", cancelled)
	}
	marked, err = backing.GetLLMCheckpointOperation(ctx, cancelIntent.ID)
	if err != nil || marked.RecoveryState != "requeued" {
		t.Fatalf("cancelled restore intent was not durably requeued: op=%+v err=%v", marked, err)
	}
	if lease, leaseErr := backing.GetAcceleratorLease(ctx, cancelLease.AcceleratorID); leaseErr == nil && lease != nil {
		t.Fatalf("fresh cancelled fence remained live: %+v", lease)
	}
	if len(adapter.cancelled) == 0 || adapter.cancelled[len(adapter.cancelled)-1] != "compensated-victim" {
		t.Fatalf("fresh restore handle was not cancelled through adapter: %v", adapter.cancelled)
	}
}

func TestCheckpointPreemptionNewcomerCASCrashRecoversDurableRestore(t *testing.T) {
	const (
		victimID   = "newcomer-cas-victim"
		newcomerID = "newcomer-cas-newcomer"
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backing := &newcomerCASCrashStore{MemoryStore: store.NewMemoryStore(), victimID: victimID, newcomerID: newcomerID}
	adapter := &checkpointRecoveryCrashAdapter{}
	target := Target{ID: "newcomer-cas-gpu", NodeID: "newcomer-cas-node", Adapter: "preempt", AcceleratorID: "newcomer-cas-accelerator", RuntimeIdentity: "runtime", ModelFingerprint: "model", ActiveRuntimeProfile: "profile", ContextLimit: 4096, Slots: 1, Enabled: true}
	mgr := NewManager(quietLogger(), backing, 50*time.Millisecond)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	mgr.Start(ctx)
	defer mgr.Close()

	victim, _, err := mgr.Submit(ctx, domain.WorkloadRequest{
		ID: victimID, ItemID: "victim", OwnerID: "newcomer-cas-owner", Adapter: "preempt",
		Payload: json.RawMessage(`{}`), Priority: 1, Recoverable: true,
		Disruption: domain.DisruptionCheckpointable, InterruptionConsent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		victim, _ = backing.GetWorkload(ctx, victimID)
		if victim.Status == domain.WorkloadRunning && victim.Execution != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if victim.Status != domain.WorkloadRunning || victim.Execution == nil {
		t.Fatalf("victim never reached running state: %+v", victim)
	}

	// Submit performs one reconciliation synchronously. Run the newcomer in a
	// worker goroutine so the injected Goexit below terminates only that
	// controller worker, just as a process crash would leave this test process
	// available to restart a second Manager.
	go func() {
		_, _, _ = mgr.Submit(ctx, domain.WorkloadRequest{
			ID: newcomerID, ItemID: newcomerID, OwnerID: "newcomer-cas-owner", Adapter: "preempt",
			Payload: json.RawMessage(`{}`), QoS: domain.QoSInteractive, Priority: 80,
			Disruption: domain.DisruptionLocked, PreemptionBudget: 1,
		})
	}()

	var restored *store.LLMCheckpointOperation
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, listErr := backing.ListLLMCheckpointOperations(ctx, "newcomer-cas-owner")
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, row := range rows {
			if row != nil && row.WorkloadID == victimID && row.RecoveryState == "restored" {
				restored = row
				break
			}
		}
		victimWon, newcomerFailed, crashed := backing.states()
		if restored != nil && victimWon && newcomerFailed && crashed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if restored == nil {
		victimNow, _ := backing.GetWorkload(ctx, victimID)
		newcomerNow, _ := backing.GetWorkload(ctx, newcomerID)
		plans, _ := backing.ListTransitionPlans(ctx, newcomerID, 10)
		rows, _ := backing.ListLLMCheckpointOperations(ctx, "newcomer-cas-owner")
		victimWon, newcomerFailed, crashed := backing.states()
		planErrors := make([]string, 0, len(plans))
		for _, plan := range plans {
			if plan != nil {
				planErrors = append(planErrors, plan.Error)
			}
		}
		t.Fatalf("newcomer-CAS compensation did not durably record a restored intent: victim=%+v plan=%+v newcomer=%+v plan_errors=%v rows=%+v flags=%v/%v/%v", victimNow, victimNow.Plan, newcomerNow, planErrors, rows, victimWon, newcomerFailed, crashed)
	}
	victimWon, newcomerFailed, crashed := backing.states()
	if !victimWon || !newcomerFailed || !crashed {
		t.Fatalf("test did not reach the real CAS/crash seam: victim_won=%v newcomer_failed=%v crashed=%v", victimWon, newcomerFailed, crashed)
	}
	if restored.RecoveryHandle == nil || restored.RecoveryHandle.ExternalID != "compensated-victim" || restored.RecoveryFence <= restored.Fence || restored.RecoveryAcceleratorID != target.AcceleratorID || restored.RecoveryWorkloadRevision == 0 || restored.RecoveryWorkloadRevision != restored.WorkloadRevision {
		t.Fatalf("fresh restore identity was not durable before adoption: %+v", restored)
	}
	if victim.Status == domain.WorkloadRunning && victim.Execution != nil && victim.Execution.ExternalID == restored.RecoveryHandle.ExternalID {
		t.Fatal("test observed adoption before the injected crash")
	}

	// The old scheduler goroutine exited at the adoption CAS. Closing it leaves
	// the durable fresh lease untouched, matching a controller process crash.
	mgr.Close()

	restarted := NewManager(quietLogger(), backing, 50*time.Millisecond)
	restarted.RegisterAdapter(adapter)
	restarted.RegisterTarget(target)
	restarted.Start(ctx)
	defer restarted.Close()

	var recovered *store.LLMCheckpointOperation
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		recovered, _ = backing.GetLLMCheckpointOperation(ctx, restored.ID)
		victim, _ = backing.GetWorkload(ctx, victimID)
		if recovered != nil && recovered.RecoveryState == "requeued" && victim.Status == domain.WorkloadQueued {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if recovered == nil || recovered.RecoveryState != "requeued" {
		t.Fatalf("restart did not terminalize restored intent: %+v", recovered)
	}
	if victim.Status != domain.WorkloadQueued || victim.Execution != nil || victim.CheckpointRef != "victim.kv" {
		t.Fatalf("restart did not safely cancel/requeue exact restored execution: %+v", victim)
	}
	if lease, leaseErr := backing.GetAcceleratorLease(ctx, target.AcceleratorID); leaseErr == nil && lease != nil {
		t.Fatalf("fresh compensation lease remained live after restart cleanup: %+v", lease)
	}
	if len(adapter.cancelled) == 0 || adapter.cancelled[len(adapter.cancelled)-1] != restored.RecoveryHandle.ExternalID {
		t.Fatalf("restart did not cancel the exact fresh handle: cancelled=%v restored=%+v", adapter.cancelled, restored.RecoveryHandle)
	}
	if adapter.resumeCalls != 1 {
		t.Fatalf("restart duplicated the physical restore: resume_calls=%d", adapter.resumeCalls)
	}
	newcomer, err := backing.GetWorkload(ctx, newcomerID)
	if err != nil {
		t.Fatal(err)
	}
	if newcomer.Status == domain.WorkloadRunning || newcomer.Status == domain.WorkloadSucceeded || newcomer.Execution != nil {
		t.Fatalf("newcomer was admitted despite its injected CAS failure: %+v", newcomer)
	}
}

func TestCheckpointCASCompensationReacquiresAndResumes(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Minute)
	target := Target{ID: "gpu", NodeID: "node", Adapter: "preempt", AcceleratorID: "gpu-0", RuntimeIdentity: "runtime", Enabled: true}
	mgr.RegisterTarget(target)
	victim := &domain.Workload{Request: domain.WorkloadRequest{ID: "victim", OwnerID: "owner", Adapter: "preempt"}, Revision: 1, Plan: &domain.ExecutionPlan{TargetID: target.ID, ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096}}
	oldLease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, victim.Request.ID, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire victim lease: %+v acquired=%v err=%v", oldLease, acquired, err)
	}
	oldLease.AcceleratorID = target.AcceleratorID
	adapter := &checkpointCompensationAdapter{}
	if _, err := mgr.persistCheckpointRecoveryIntent(ctx, victim, target, "victim.kv", "transition", oldLease); err != nil {
		t.Fatalf("persist compensation intent: %v", err)
	}
	handle, freshLease, err := mgr.restoreCheckpointVictim(ctx, victim, target, adapter, "victim.kv", oldLease, "transition")
	if err != nil || handle == nil || freshLease == nil || freshLease.FencingToken <= oldLease.FencingToken || adapter.resumeCalls != 1 {
		t.Fatalf("physical checkpoint compensation did not restore the victim: handle=%v lease=%+v calls=%d err=%v", handle, freshLease, adapter.resumeCalls, err)
	}
	current, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID)
	if err != nil || current.WorkloadID != victim.Request.ID || current.FencingToken != freshLease.FencingToken {
		t.Fatalf("compensation did not publish the fresh fenced owner: lease=%+v err=%v", current, err)
	}
}

func TestCheckpointRestoreMissingIntentCreatesDurableCustody(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Minute)
	target := Target{ID: "missing-intent-gpu", NodeID: "missing-intent-node", Adapter: "preempt", AcceleratorID: "missing-intent-accelerator", RuntimeIdentity: "runtime", Enabled: true}
	mgr.RegisterTarget(target)
	victim := &domain.Workload{
		Request:  domain.WorkloadRequest{ID: "missing-intent-victim", OwnerID: "owner", Adapter: "preempt"},
		Revision: 1,
		Plan:     &domain.ExecutionPlan{TargetID: target.ID, ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096},
	}
	oldLease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, victim.Request.ID, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire old lease: %+v acquired=%v err=%v", oldLease, acquired, err)
	}
	adapter := &checkpointRecoveryCrashAdapter{}
	handle, lease, err := mgr.restoreCheckpointVictim(ctx, victim, target, adapter, "missing-intent.kv", oldLease, "missing-intent-transition")
	if err != nil || handle == nil || lease == nil || lease.FencingToken <= oldLease.FencingToken {
		t.Fatalf("restore without a preexisting intent did not establish durable custody: handle=%+v lease=%+v err=%v", handle, lease, err)
	}
	intent, intentErr := backing.GetLLMCheckpointOperation(ctx, "missing-intent-transition:outer-recovery")
	if intentErr != nil || intent.RecoveryState != "restored" || intent.RecoveryHandle == nil || intent.CleanupState != "owned" {
		t.Fatalf("missing-intent restore did not persist exact fresh custody: op=%+v err=%v", intent, intentErr)
	}
	if len(adapter.cancelled) != 0 {
		t.Fatalf("successful missing-intent restore was cancelled prematurely: %v", adapter.cancelled)
	}
}

func TestCheckpointRestoreMissingIntentCancelFailureKeepsFreshFence(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Minute)
	target := Target{ID: "missing-intent-cancel-failure", NodeID: "missing-intent-node", Adapter: "preempt", AcceleratorID: "missing-intent-cancel-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr.RegisterTarget(target)
	victim := &domain.Workload{
		Request:  domain.WorkloadRequest{ID: "missing-intent-cancel-victim", OwnerID: "owner", Adapter: "preempt"},
		Revision: 1,
		Plan:     &domain.ExecutionPlan{TargetID: target.ID, ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096},
	}
	oldLease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, victim.Request.ID, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire old lease: %+v acquired=%v err=%v", oldLease, acquired, err)
	}
	adapter := &checkpointRecoveryCrashAdapter{cancelErr: errors.New("injected missing-intent cancellation failure")}
	mgr.RegisterAdapter(adapter)
	handle, freshLease, err := mgr.restoreCheckpointVictim(ctx, victim, target, adapter, "missing-intent-cancel.kv", oldLease, "missing-intent-cancel-transition")
	if err != nil || handle == nil || freshLease == nil {
		t.Fatalf("missing-intent restore did not cross durable custody boundary: handle=%+v fresh=%+v err=%v", handle, freshLease, err)
	}
	if cleanupErr := mgr.abandonRestoredCheckpointVictim(ctx, victim, target, adapter, handle, freshLease, false); cleanupErr == nil || !strings.Contains(cleanupErr.Error(), "stop unconfirmed") {
		t.Fatalf("missing-intent cancellation failure was not surfaced: fresh=%+v err=%v", freshLease, cleanupErr)
	}
	live, leaseErr := backing.GetAcceleratorLease(ctx, target.AcceleratorID)
	if leaseErr != nil || live == nil || live.FencingToken <= oldLease.FencingToken {
		t.Fatalf("missing-intent cleanup discarded the fresh fence after cancel failure: lease=%+v err=%v old=%+v", live, leaseErr, oldLease)
	}
	if len(adapter.cancelled) != 1 || adapter.cancelled[0] != "compensated-victim" {
		t.Fatalf("missing-intent cleanup did not attempt the exact fresh handle: %v", adapter.cancelled)
	}
	if _, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "missing-intent-replacement", time.Minute); err != nil || acquired {
		t.Fatalf("replacement reused a fresh fence whose stop was unconfirmed: acquired=%v err=%v", acquired, err)
	}
	adapter.cancelErr = nil
	restarted := NewManager(quietLogger(), backing, time.Minute)
	restarted.RegisterAdapter(adapter)
	restarted.RegisterTarget(target)
	restarted.recoverCheckpointRecoveryIntents(ctx)
	restarted.recoverCheckpointCleanupIntents(ctx)
	if lease, leaseErr := backing.GetAcceleratorLease(ctx, target.AcceleratorID); leaseErr == nil && lease != nil {
		op, _ := backing.GetLLMCheckpointOperation(ctx, "missing-intent-cancel-transition:outer-recovery")
		t.Fatalf("restart did not converge missing-intent cleanup: lease=%+v op=%+v cancelled=%v", lease, op, adapter.cancelled)
	}
	if adapter.resumeCalls != 1 {
		t.Fatalf("restart duplicated the physical restore: %d calls", adapter.resumeCalls)
	}
}

func TestCheckpointCompensationCancelFailureRetriesFromFailedIntent(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &checkpointRecoveryCrashAdapter{cancelErr: errors.New("injected compensation cancellation failure")}
	target := Target{ID: "compensation-cancel-failure", NodeID: "compensation-node", Adapter: "preempt", AcceleratorID: "compensation-cancel-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr := NewManager(quietLogger(), backing, time.Minute)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	victim := &domain.Workload{
		Request:   domain.WorkloadRequest{ID: "compensation-cancel-victim", OwnerID: "owner", Adapter: "preempt"},
		Status:    domain.WorkloadRunning,
		Revision:  1,
		Plan:      &domain.ExecutionPlan{TargetID: target.ID, ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096},
		Execution: &domain.ExecutionHandle{ExternalID: "stale-compensation"},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	created, _, err := backing.CreateWorkload(ctx, victim)
	if err != nil {
		t.Fatal(err)
	}
	oldLease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, victim.Request.ID, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire compensation old lease: %+v acquired=%v err=%v", oldLease, acquired, err)
	}
	intent, err := mgr.persistCheckpointRecoveryIntent(ctx, created, target, "compensation-cancel.kv", "compensation-cancel-transition", oldLease)
	if err != nil {
		t.Fatalf("persist compensation intent: %v", err)
	}
	mgr.placementMu.Lock()
	mgr.targetLeases[target.ID] = oldLease
	mgr.targetActive[target.ID] = 1
	mgr.activePlacements[victim.Request.ID] = activePlacement{workloadID: victim.Request.ID, targetID: target.ID, acceleratorID: target.AcceleratorID}
	mgr.placementMu.Unlock()
	handle, freshLease, err := mgr.restoreCheckpointVictim(ctx, created, target, adapter, "compensation-cancel.kv", oldLease, "compensation-cancel-transition")
	if err != nil || handle == nil || freshLease == nil {
		t.Fatalf("restore did not cross fresh fence: handle=%+v lease=%+v err=%v", handle, freshLease, err)
	}
	if cleanupErr := mgr.abandonRestoredCheckpointVictim(ctx, created, target, adapter, handle, freshLease, false); cleanupErr == nil || !strings.Contains(cleanupErr.Error(), "stop unconfirmed") {
		t.Fatalf("compensation cleanup cancellation failure was not surfaced: %v", cleanupErr)
	}
	live, leaseErr := backing.GetAcceleratorLease(ctx, target.AcceleratorID)
	if leaseErr != nil || live == nil || live.FencingToken != freshLease.FencingToken {
		t.Fatalf("compensation cleanup discarded the fresh fence: lease=%+v err=%v fresh=%+v", live, leaseErr, freshLease)
	}
	mgr.placementMu.Lock()
	if current := mgr.targetLeases[target.ID]; current == nil || current.FencingToken != freshLease.FencingToken {
		mgr.placementMu.Unlock()
		t.Fatalf("in-memory fresh fence was cleared after cancellation failure: %+v", current)
	}
	if _, ok := mgr.activePlacements[victim.Request.ID]; !ok {
		mgr.placementMu.Unlock()
		t.Fatal("victim placement was cleared before fresh backend stop confirmation")
	}
	mgr.placementMu.Unlock()
	if err := mgr.markCheckpointRecoveryIntentFailed(ctx, intent.ID, errors.New("compensation cleanup pending retry")); err != nil {
		t.Fatalf("mark failed recovery intent: %v", err)
	}
	adapter.cancelErr = nil
	restarted := NewManager(quietLogger(), backing, time.Minute)
	restarted.RegisterAdapter(adapter)
	restarted.RegisterTarget(target)
	restarted.recoverCheckpointRecoveryIntents(ctx)
	recovered, err := backing.GetLLMCheckpointOperation(ctx, intent.ID)
	if err != nil || recovered.RecoveryState != "requeued" {
		t.Fatalf("restart did not resolve failed compensation intent: op=%+v err=%v", recovered, err)
	}
	requeued, err := backing.GetWorkload(ctx, victim.Request.ID)
	if err != nil || requeued.Status != domain.WorkloadQueued || requeued.Execution != nil || requeued.CheckpointRef != "compensation-cancel.kv" {
		t.Fatalf("restart did not safely requeue after confirmed compensation cleanup: %+v err=%v", requeued, err)
	}
	if lease, leaseErr := backing.GetAcceleratorLease(ctx, target.AcceleratorID); leaseErr == nil && lease != nil {
		t.Fatalf("restart left the fresh compensation fence live after confirmed stop: %+v", lease)
	}
	if calls := adapter.resumeCalls; calls != 1 {
		t.Fatalf("restart duplicated physical compensation restore: %d calls", calls)
	}
}

func TestCheckpointCleanupRetryRetainsFenceUntilStopAndStoppedRestartIsIdempotent(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &checkpointRecoveryCrashAdapter{cancelErr: errors.New("offline node")}
	target := Target{ID: "cleanup-retry-target", NodeID: "cleanup-retry-node", Adapter: "preempt", AcceleratorID: "cleanup-retry-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr := NewManager(quietLogger(), backing, time.Minute)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	lease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "cleanup-retry-workload", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire cleanup lease: %+v acquired=%v err=%v", lease, acquired, err)
	}
	operation := &store.LLMCheckpointOperation{
		ID: "cleanup-retry-operation", IdempotencyKey: "cleanup-retry-operation", OwnerID: "owner", WorkloadID: lease.WorkloadID,
		NodeID: target.NodeID, AcceleratorID: target.AcceleratorID, TargetID: target.ID, Model: "model", ModelFingerprint: "model",
		RuntimeIdentity: target.RuntimeIdentity, ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "source-conversation",
		ContinuationConversationID: "continuation-cleanup-retry-operation", CompensationOf: "checkpoint-source", WorkloadRevision: 1,
		SnapshotName: "cleanup-retry.kv", SlotID: 0, Generation: 7, Fence: uint64(lease.FencingToken), Phase: "restore_planned",
		PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), CleanupOperationID: "cleanup-retry-operation:compensate", CleanupSlotID: 0,
		CleanupConversationID: "source-conversation", CleanupContinuationConversationID: "continuation-cleanup-retry-operation", CleanupState: "pending",
		CleanupHandle: &domain.ExecutionHandle{ExternalID: "cleanup-retry-handle"}, CleanupTargetID: target.ID, CleanupNodeID: target.NodeID,
		CleanupAcceleratorID: target.AcceleratorID, CleanupGeneration: 7, CleanupFence: uint64(lease.FencingToken), CleanupTerminalDisposition: "failure",
	}
	if _, inserted, err := backing.CreateLLMCheckpointOperation(ctx, operation); err != nil || !inserted {
		t.Fatalf("create pending cleanup: inserted=%v err=%v", inserted, err)
	}
	mgr.recoverCheckpointCleanupIntents(ctx)
	failed, err := backing.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || failed.CleanupState != "failed" {
		t.Fatalf("offline cleanup did not persist retryable failure: op=%+v err=%v", failed, err)
	}
	live, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID)
	if err != nil || live == nil || live.FencingToken != lease.FencingToken {
		t.Fatalf("offline cleanup lost the authoritative fence: lease=%+v err=%v", live, err)
	}
	if !live.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("offline cleanup left the authoritative fence expired: lease=%+v", live)
	}
	if _, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "replacement-before-stop", time.Minute); err != nil || acquired {
		t.Fatalf("admission bypassed failed cleanup custody: acquired=%v err=%v", acquired, err)
	}
	adapter.cancelErr = nil
	// The periodic recovery entry point is intentionally invoked directly here
	// so the test remains deterministic while proving the same retry path used
	// by Manager.loop after an offline node reconnects.
	mgr.recoverCheckpointCleanupIntents(ctx)
	stopped, err := backing.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || stopped.CleanupState != "confirmed" {
		t.Fatalf("cleanup retry did not converge after node recovery: op=%+v err=%v", stopped, err)
	}
	if live, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID); err == nil && live != nil {
		t.Fatalf("confirmed cleanup retained the lease: %+v", live)
	}
	if _, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "replacement-after-stop", time.Minute); err != nil || !acquired {
		t.Fatalf("admission did not reopen after confirmed stop/release: acquired=%v err=%v", acquired, err)
	}
	// A restarted manager may observe the stopped/released seam again.  The
	// confirmed row must be a no-op, never a second cancel or a new lease fence.
	restarted := NewManager(quietLogger(), backing, time.Minute)
	restarted.RegisterTarget(target)
	restarted.recoverCheckpointCleanupIntents(ctx)
	confirmed, err := backing.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || confirmed.CleanupState != "confirmed" {
		t.Fatalf("restart changed confirmed cleanup state: op=%+v err=%v", confirmed, err)
	}
}

func TestCheckpointStoppedBoundaryRestartReleasesWithoutSecondCancel(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &checkpointRecoveryCrashAdapter{}
	target := Target{ID: "stopped-boundary-target", NodeID: "stopped-boundary-node", Adapter: "preempt", AcceleratorID: "stopped-boundary-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr := NewManager(quietLogger(), backing, time.Minute)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	lease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "stopped-boundary-workload", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire stopped-boundary lease: %+v acquired=%v err=%v", lease, acquired, err)
	}
	operation := &store.LLMCheckpointOperation{
		ID: "stopped-boundary-operation", IdempotencyKey: "stopped-boundary-operation", OwnerID: "owner", WorkloadID: lease.WorkloadID,
		NodeID: target.NodeID, AcceleratorID: target.AcceleratorID, TargetID: target.ID, Model: "model", ModelFingerprint: "model",
		RuntimeIdentity: target.RuntimeIdentity, ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "stopped-boundary-conversation",
		WorkloadRevision: 1, SnapshotName: "stopped-boundary.kv", SlotID: 0, Generation: 7, Fence: uint64(lease.FencingToken), Phase: "restore_planned",
		PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), CleanupOperationID: "stopped-boundary-operation", CleanupSlotID: 0,
		CleanupConversationID: "stopped-boundary-conversation", CleanupState: "stopped", CleanupHandle: &domain.ExecutionHandle{ExternalID: "stopped-boundary-handle"},
		CleanupTargetID: target.ID, CleanupNodeID: target.NodeID, CleanupAcceleratorID: target.AcceleratorID, CleanupGeneration: 7, CleanupFence: uint64(lease.FencingToken),
	}
	if _, inserted, err := backing.CreateLLMCheckpointOperation(ctx, operation); err != nil || !inserted {
		t.Fatalf("create stopped-boundary operation: inserted=%v err=%v", inserted, err)
	}
	// This models a controller crash after the durable stop marker and before
	// the lease DELETE. Recovery must perform only the idempotent release.
	mgr.recoverCheckpointCleanupIntents(ctx)
	recovered, err := backing.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || recovered.CleanupState != "confirmed" {
		t.Fatalf("stopped boundary did not converge: op=%+v err=%v", recovered, err)
	}
	if _, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stopped boundary retained lease: err=%v", err)
	}
	if len(adapter.cancelled) != 0 {
		t.Fatalf("stopped boundary issued a second physical cancel: %v", adapter.cancelled)
	}
}

func TestCheckpointStoppedBoundaryReleaseFailureRetainsStoppedAndConverges(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	backing := &countingReleaseMemoryStore{MemoryStore: base, failures: 1}
	adapter := &checkpointRecoveryCrashAdapter{}
	target := Target{ID: "stopped-release-retry-target", NodeID: "stopped-release-retry-node", Adapter: "preempt", AcceleratorID: "stopped-release-retry-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr := NewManager(quietLogger(), backing, time.Minute)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	lease, acquired, err := base.AcquireAcceleratorLease(ctx, target.AcceleratorID, "stopped-release-retry-workload", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire stopped-release-retry lease: %+v acquired=%v err=%v", lease, acquired, err)
	}
	if _, inserted, err := base.CreateWorkload(ctx, &domain.Workload{Request: domain.WorkloadRequest{ID: lease.WorkloadID, OwnerID: "owner"}, Status: domain.WorkloadQueued, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}); err != nil || !inserted {
		t.Fatalf("create stopped-release-retry workload: inserted=%v err=%v", inserted, err)
	}
	operation := &store.LLMCheckpointOperation{
		ID: "stopped-release-retry-operation", IdempotencyKey: "stopped-release-retry-operation", OwnerID: "owner", WorkloadID: lease.WorkloadID,
		NodeID: target.NodeID, AcceleratorID: target.AcceleratorID, TargetID: target.ID, Model: "model", ModelFingerprint: "model",
		RuntimeIdentity: target.RuntimeIdentity, ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "stopped-release-retry-conversation",
		WorkloadRevision: 1, SnapshotName: "stopped-release-retry.kv", SlotID: 0, Generation: 7, Fence: uint64(lease.FencingToken), Phase: "restore_planned",
		PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), CleanupOperationID: "stopped-release-retry-operation", CleanupSlotID: 0,
		CleanupConversationID: "stopped-release-retry-conversation", CleanupState: "stopped", CleanupHandle: &domain.ExecutionHandle{ExternalID: "stopped-release-retry-handle"},
		CleanupTargetID: target.ID, CleanupNodeID: target.NodeID, CleanupAcceleratorID: target.AcceleratorID, CleanupGeneration: 7, CleanupFence: uint64(lease.FencingToken),
		CleanupTerminalDisposition: "failure", CleanupMessage: "original terminal failure",
	}
	if _, inserted, err := base.CreateLLMCheckpointOperation(ctx, operation); err != nil || !inserted {
		t.Fatalf("create stopped-release-retry operation: inserted=%v err=%v", inserted, err)
	}
	// Recovery must not send another physical cancel after the durable stopped
	// marker. A transient release error leaves that marker authoritative.
	mgr.recoverCheckpointCleanupIntents(ctx)
	stopped, err := base.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || stopped.CleanupState != "stopped" {
		t.Fatalf("release failure regressed stopped marker: op=%+v err=%v", stopped, err)
	}
	if !strings.Contains(stopped.CleanupMessage, "lease release pending") {
		t.Fatalf("release failure diagnostic was not retained: %+v release_calls=%d", stopped, backing.calls)
	}
	if len(adapter.cancelled) != 0 {
		t.Fatalf("stopped retry issued a second physical cancel: %v", adapter.cancelled)
	}
	if live, err := base.GetAcceleratorLease(ctx, target.AcceleratorID); err != nil || live == nil {
		t.Fatalf("release failure unexpectedly removed authoritative fence: lease=%+v err=%v", live, err)
	}
	intents, err := base.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC().Add(time.Hour), 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("release retry intent missing: intents=%+v err=%v", intents, err)
	}
	past := time.Now().UTC().Add(-time.Second)
	intents[0].NextRetryAt = &past
	if _, err := base.RecordAcceleratorLeaseCleanupIntent(ctx, intents[0]); err != nil {
		t.Fatal(err)
	}
	mgr.retryAcceleratorLeaseCleanupIntents(ctx)
	if _, err := base.GetAcceleratorLease(ctx, target.AcceleratorID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("generic release retry did not remove exact lease: err=%v", err)
	}
	// The checkpoint pass observes the generic release winning the race and
	// finalizes the stopped row without touching the backend.
	mgr.recoverCheckpointCleanupIntents(ctx)
	confirmed, err := base.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || confirmed.CleanupState != "confirmed" {
		t.Fatalf("stopped row did not converge after generic release: op=%+v err=%v", confirmed, err)
	}
	workload, err := base.GetWorkload(ctx, lease.WorkloadID)
	if err != nil || workload.Status != domain.WorkloadFailed {
		t.Fatalf("stopped row did not finalize terminal disposition: workload=%+v err=%v", workload, err)
	}
}

func TestCheckpointRecoveryStoppedProjectionNeverReAdoptsOrCancels(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &checkpointRecoveryCrashAdapter{}
	target := Target{ID: "stopped-projection-target", NodeID: "stopped-projection-node", Adapter: "preempt", AcceleratorID: "stopped-projection-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr := NewManager(quietLogger(), backing, time.Minute)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	handle := &domain.ExecutionHandle{ExternalID: "already-stopped-fresh-handle", Opaque: []byte(`{"fresh":true}`)}
	workload := &domain.Workload{
		Request: domain.WorkloadRequest{ID: "stopped-projection-workload", OwnerID: "owner", Adapter: target.Adapter},
		Status:  domain.WorkloadRunning, Revision: 2,
		Plan:      &domain.ExecutionPlan{TargetID: target.ID, ModelFingerprint: "model", ProfileDigest: "profile", TargetContextLimit: 4096},
		Execution: handle, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if _, inserted, err := backing.CreateWorkload(ctx, workload); err != nil || !inserted {
		t.Fatalf("create running stopped-projection workload: inserted=%v err=%v", inserted, err)
	}
	oldLease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, workload.Request.ID, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire stopped-projection lease: lease=%+v acquired=%v err=%v", oldLease, acquired, err)
	}
	if err := backing.ReleaseAcceleratorLease(ctx, target.AcceleratorID, workload.Request.ID, oldLease.FencingToken); err != nil {
		t.Fatal(err)
	}
	lease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, workload.Request.ID, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("reacquire stopped-projection lease: lease=%+v acquired=%v err=%v", lease, acquired, err)
	}
	operation := &store.LLMCheckpointOperation{
		ID: "stopped-projection-outer", IdempotencyKey: "stopped-projection-outer", OwnerID: workload.Request.OwnerID,
		WorkloadID: workload.Request.ID, NodeID: target.NodeID, AcceleratorID: target.AcceleratorID, TargetID: target.ID,
		Model: "model", ModelFingerprint: "model", RuntimeIdentity: target.RuntimeIdentity, ProfileFingerprint: "profile",
		ContextFingerprint: "ctx:4096", ConversationID: "source", ContinuationConversationID: "continuation", CompensationOf: "transition",
		WorkloadRevision: 1, SnapshotName: "stopped-projection.kv", SlotID: -1, Generation: 7, Fence: 1,
		Phase: "restore_planned", PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), RecoveryState: "failed", RecoveryHandle: handle,
		RecoveryAcceleratorID: target.AcceleratorID, RecoveryFence: uint64(lease.FencingToken),
		CleanupOperationID: "stopped-projection-physical", CleanupSlotID: 0, CleanupConversationID: "source", CleanupState: "stopped",
		CleanupHandle: handle, CleanupTargetID: target.ID, CleanupNodeID: target.NodeID, CleanupAcceleratorID: target.AcceleratorID,
		CleanupGeneration: 7, CleanupFence: uint64(lease.FencingToken),
	}
	if _, inserted, err := backing.CreateLLMCheckpointOperation(ctx, operation); err != nil || !inserted {
		t.Fatalf("create stopped-projection operation: inserted=%v err=%v", inserted, err)
	}
	mgr.recoverCheckpointRecoveryIntents(ctx)
	if len(adapter.cancelled) != 0 {
		t.Fatalf("restart re-cancelled a durable stopped backend: %v", adapter.cancelled)
	}
	updated, err := backing.GetWorkload(ctx, workload.Request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != domain.WorkloadQueued || updated.Execution != nil || updated.CheckpointRef != operation.SnapshotName {
		t.Fatalf("stopped running projection was re-adopted instead of requeued: %+v", updated)
	}
	recovered, err := backing.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || recovered.CleanupState != "confirmed" || recovered.RecoveryState != "requeued" {
		t.Fatalf("stopped recovery did not release/finalize: op=%+v err=%v", recovered, err)
	}
	if _, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stopped recovery retained exact lease after release: err=%v", err)
	}
}

func TestCheckpointStoppedReleaseFailureIsIdempotentAcross100Retries(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	backing := &countingReleaseMemoryStore{MemoryStore: base, failures: 100}
	adapter := &checkpointRecoveryCrashAdapter{}
	target := Target{ID: "stopped-release-100-target", NodeID: "stopped-release-100-node", Adapter: "preempt", AcceleratorID: "stopped-release-100-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr := NewManager(quietLogger(), backing, time.Minute)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	operations := make([]string, 0, 100)
	for index := 0; index < 100; index++ {
		workloadID := fmt.Sprintf("stopped-release-100-workload-%d", index)
		acceleratorID := fmt.Sprintf("stopped-release-100-gpu-%d", index)
		if _, inserted, err := base.CreateWorkload(ctx, &domain.Workload{Request: domain.WorkloadRequest{ID: workloadID, OwnerID: "owner"}, Status: domain.WorkloadQueued, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}); err != nil || !inserted {
			t.Fatalf("create workload %d: inserted=%v err=%v", index, inserted, err)
		}
		lease, acquired, err := base.AcquireAcceleratorLease(ctx, acceleratorID, workloadID, time.Minute)
		if err != nil || !acquired {
			t.Fatalf("acquire lease %d: lease=%+v acquired=%v err=%v", index, lease, acquired, err)
		}
		operationID := fmt.Sprintf("stopped-release-100-operation-%d", index)
		operations = append(operations, operationID)
		operation := &store.LLMCheckpointOperation{
			ID: operationID, IdempotencyKey: operationID, OwnerID: "owner", WorkloadID: workloadID, NodeID: target.NodeID,
			AcceleratorID: acceleratorID, TargetID: target.ID, Model: "model", ModelFingerprint: "model", RuntimeIdentity: target.RuntimeIdentity,
			ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "source", ContinuationConversationID: operationID,
			WorkloadRevision: 1, SnapshotName: operationID + ".kv", SlotID: 0, Generation: 7, Fence: uint64(lease.FencingToken),
			Phase: "restore_planned", PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), CleanupOperationID: operationID, CleanupSlotID: 0,
			CleanupConversationID: "source", CleanupState: "stopped", CleanupHandle: &domain.ExecutionHandle{ExternalID: operationID + "-handle"},
			CleanupTargetID: target.ID, CleanupNodeID: target.NodeID, CleanupAcceleratorID: acceleratorID, CleanupGeneration: 7, CleanupFence: uint64(lease.FencingToken),
		}
		if _, inserted, err := base.CreateLLMCheckpointOperation(ctx, operation); err != nil || !inserted {
			t.Fatalf("create operation %d: inserted=%v err=%v", index, inserted, err)
		}
		if err := mgr.cleanupCheckpointOperation(ctx, operation); err == nil {
			t.Fatalf("release failure %d was not surfaced", index)
		}
		stopped, err := base.GetLLMCheckpointOperation(ctx, operationID)
		if err != nil || stopped.CleanupState != "stopped" {
			t.Fatalf("release failure %d regressed stopped state: op=%+v err=%v", index, stopped, err)
		}
	}
	if len(adapter.cancelled) != 0 {
		t.Fatalf("stopped retry path issued physical cancels: %v", adapter.cancelled)
	}
	backing.failures = 0
	for index, operationID := range operations {
		operation, err := base.GetLLMCheckpointOperation(ctx, operationID)
		if err != nil {
			t.Fatal(err)
		}
		if err := mgr.cleanupCheckpointOperation(ctx, operation); err != nil {
			t.Fatalf("release retry %d did not converge: %v", index, err)
		}
		confirmed, err := base.GetLLMCheckpointOperation(ctx, operationID)
		if err != nil || confirmed.CleanupState != "confirmed" {
			t.Fatalf("release retry %d did not confirm: op=%+v err=%v", index, confirmed, err)
		}
	}
}

// safetyResumeAdapter deliberately separates physical resume, observation,
// yield, and cancellation so execute-time cleanup seams can inject one
// failure at a time. The adapter's handle is the only authority that permits
// a lease release after ResumeWithLease has crossed the node boundary.
type safetyResumeAdapter struct {
	checkpointTestAdapter
	resumeStarted chan struct{}
	resumeRelease chan struct{}
	resumeOnce    sync.Once
	mu            sync.Mutex
	resumeCalls   int
	cancelCalls   int
	yieldCalls    int
	cancelErr     error
	yieldErr      error
	observation   Observation
}

func newSafetyResumeAdapter(observation Observation) *safetyResumeAdapter {
	return &safetyResumeAdapter{resumeStarted: make(chan struct{}), resumeRelease: make(chan struct{}), observation: observation}
}

func (a *safetyResumeAdapter) Name() string { return "resume-safety" }

func (a *safetyResumeAdapter) CheckpointWithLease(context.Context, *domain.ExecutionHandle, Target, SlotLease, CheckpointCommand) (string, error) {
	return "checkpoint://safety", nil
}

func (a *safetyResumeAdapter) ResumeWithLease(ctx context.Context, req domain.WorkloadRequest, _ *domain.ExecutionPlan, _ string, _ Target, _ SlotLease, _ CheckpointCommand) (*domain.ExecutionHandle, error) {
	a.mu.Lock()
	a.resumeCalls++
	a.mu.Unlock()
	a.resumeOnce.Do(func() { close(a.resumeStarted) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.resumeRelease:
	}
	return &domain.ExecutionHandle{ExternalID: "resume-" + req.ID, StartedAt: time.Now().UTC()}, nil
}

func (a *safetyResumeAdapter) Observe(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (Observation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.observation, nil
}

func (a *safetyResumeAdapter) Cancel(context.Context, *domain.ExecutionHandle, Target) error {
	a.mu.Lock()
	a.cancelCalls++
	err := a.cancelErr
	a.mu.Unlock()
	return err
}

func (a *safetyResumeAdapter) Yield(context.Context, *domain.ExecutionHandle, Target) error {
	a.mu.Lock()
	a.yieldCalls++
	err := a.yieldErr
	a.mu.Unlock()
	return err
}

func (a *safetyResumeAdapter) stats() (resumeCalls, cancelCalls, yieldCalls int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.resumeCalls, a.cancelCalls, a.yieldCalls
}

// safetyPublicationConflictStore rejects exactly the first attempt to publish
// a fresh resumed handle. The underlying row remains unchanged so the test
// exercises the manager's publication-CAS compensation path.
type safetyPublicationConflictStore struct {
	*store.MemoryStore
	mu       sync.Mutex
	injected bool
}

func (s *safetyPublicationConflictStore) CompareAndSwapWorkload(ctx context.Context, w *domain.Workload, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.Workload, error) {
	if w != nil && w.Execution != nil && strings.HasPrefix(w.Execution.ExternalID, "resume-") {
		s.mu.Lock()
		inject := !s.injected
		if inject {
			s.injected = true
		}
		s.mu.Unlock()
		if inject {
			return nil, store.ErrWorkloadConflict
		}
	}
	return s.MemoryStore.CompareAndSwapWorkload(ctx, w, expectedRevision, expectedStatus, expectedCancellationOwner)
}

func seedDirectResumeExecution(t *testing.T, backing store.WorkloadStore, mgr *Manager, adapter *safetyResumeAdapter, target Target, id string) (*domain.Workload, *targetReservation, Target) {
	t.Helper()
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	target = mgr.targetByID(target.ID)
	now := time.Now().UTC()
	row := &domain.Workload{
		Request:       domain.WorkloadRequest{ID: id, OwnerID: "owner", Adapter: adapter.Name()},
		Status:        domain.WorkloadRunning,
		Plan:          &domain.ExecutionPlan{ID: "plan-" + id, WorkloadID: id, TargetID: target.ID, TargetContextLimit: 4096},
		CheckpointRef: "checkpoint://" + id,
		Decision:      domain.AdmissionDecision{Admitted: true, TargetID: target.ID},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	created, _, err := backing.CreateWorkload(context.Background(), row)
	if err != nil {
		t.Fatal(err)
	}
	lease, acquired, err := backing.AcquireAcceleratorLease(context.Background(), target.AcceleratorID, id, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("seed resume lease: lease=%+v acquired=%v err=%v", lease, acquired, err)
	}
	reservation := &targetReservation{targetID: target.ID, workloadID: id, targetGeneration: mgr.targetGeneration(target.ID), lease: lease}
	mgr.placementMu.Lock()
	mgr.targetActive[target.ID] = 1
	mgr.targetLeases[target.ID] = lease
	mgr.activePlacements[id] = activePlacement{workloadID: id, targetID: target.ID, acceleratorID: target.AcceleratorID}
	mgr.placementMu.Unlock()
	mgr.mu.Lock()
	mgr.reservations[id] = reservation
	mgr.mu.Unlock()
	return created, reservation, target
}

func waitForDirectCleanupRetry(t *testing.T, mgr *Manager, backing store.WorkloadStore, id, acceleratorID string, adapter *safetyResumeAdapter) *domain.Workload {
	t.Helper()
	adapter.mu.Lock()
	adapter.cancelErr = nil
	adapter.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mgr.retryInMemoryLeaseReleases(context.Background())
		row, _ := backing.GetWorkload(context.Background(), id)
		if row != nil && row.Status == domain.WorkloadFailed {
			if lease, err := backing.GetAcceleratorLease(context.Background(), acceleratorID); err == nil && lease != nil {
				t.Fatalf("cleanup retry published terminal failure while lease remained live: %+v", lease)
			}
			return row
		}
		time.Sleep(5 * time.Millisecond)
	}
	row, _ := backing.GetWorkload(context.Background(), id)
	t.Fatalf("bounded cleanup retry did not resolve: %+v", row)
	return row
}

func TestResumeRefreshRaceKeepsFenceUntilStopRetry(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	adapter := newSafetyResumeAdapter(Observation{Status: domain.WorkloadRunning})
	adapter.cancelErr = errors.New("injected cancellation failure")
	target := Target{ID: "resume-refresh", Adapter: adapter.Name(), AcceleratorID: "resume-refresh-gpu", CapabilityVersion: "v1", Enabled: true}
	row, reservation, target := seedDirectResumeExecution(t, backing, mgr, adapter, target, "resume-refresh-workload")

	done := make(chan struct{})
	go func() {
		mgr.execute(ctx, row.Request.ID, target, reservation)
		close(done)
	}()
	select {
	case <-adapter.resumeStarted:
	case <-time.After(time.Second):
		latest, _ := backing.GetWorkload(ctx, row.Request.ID)
		t.Fatalf("resume did not reach the injected race barrier: latest=%+v target=%+v generation=%d", latest, target, mgr.targetGeneration(target.ID))
	}
	refreshed := target
	refreshed.CapabilityVersion = "v2"
	mgr.RegisterTarget(refreshed)
	close(adapter.resumeRelease)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("execute did not finish bounded refresh cleanup")
	}
	if lease, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID); err != nil || lease == nil {
		t.Fatalf("refresh race released a live backend fence: lease=%+v err=%v", lease, err)
	}
	failed, _ := backing.GetWorkload(ctx, row.Request.ID)
	if failed.Error == "" || !strings.Contains(failed.Error, "unconfirmed") {
		t.Fatalf("refresh race did not expose cleanup failure: %+v", failed)
	}
	if _, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "replacement", time.Minute); err != nil || acquired {
		t.Fatalf("replacement reused a fenced accelerator: acquired=%v err=%v", acquired, err)
	}
	resolved := waitForDirectCleanupRetry(t, mgr, backing, row.Request.ID, target.AcceleratorID, adapter)
	if resolved.Status != domain.WorkloadFailed {
		t.Fatalf("stop retry did not terminalize refreshed workload: %+v", resolved)
	}
	resumeCalls, cancelCalls, _ := adapter.stats()
	if resumeCalls != 1 || cancelCalls < 2 {
		t.Fatalf("refresh cleanup replayed resume or did not retry cancellation: resumes=%d cancels=%d", resumeCalls, cancelCalls)
	}
}

func TestResumePublicationCASFailureKeepsFenceUntilStopRetry(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	backing := &safetyPublicationConflictStore{MemoryStore: base}
	mgr := NewManager(quietLogger(), backing, time.Second)
	adapter := newSafetyResumeAdapter(Observation{Status: domain.WorkloadRunning})
	adapter.cancelErr = errors.New("injected publication cancellation failure")
	target := Target{ID: "resume-publication", Adapter: adapter.Name(), AcceleratorID: "resume-publication-gpu", CapabilityVersion: "v1", Enabled: true}
	row, reservation, target := seedDirectResumeExecution(t, backing, mgr, adapter, target, "resume-publication-workload")
	close(adapter.resumeRelease)
	done := make(chan struct{})
	go func() {
		mgr.execute(ctx, row.Request.ID, target, reservation)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publication CAS cleanup did not finish boundedly")
	}
	if lease, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID); err != nil || lease == nil {
		t.Fatalf("publication CAS failure released a live backend fence: lease=%+v err=%v", lease, err)
	}
	failed, _ := backing.GetWorkload(ctx, row.Request.ID)
	if failed.Error == "" || !strings.Contains(failed.Error, "publication") {
		t.Fatalf("publication CAS failure was not visible: %+v", failed)
	}
	resolved := waitForDirectCleanupRetry(t, mgr, backing, row.Request.ID, target.AcceleratorID, adapter)
	if resolved.Status != domain.WorkloadFailed {
		t.Fatalf("publication cleanup retry did not terminalize workload: %+v", resolved)
	}
	resumeCalls, _, _ := adapter.stats()
	if resumeCalls != 1 {
		t.Fatalf("publication cleanup retried physical resume: %d calls", resumeCalls)
	}
}

func TestResumeSharingYieldFailureKeepsFenceUntilStopRetry(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	adapter := newSafetyResumeAdapter(Observation{Status: domain.WorkloadRunning, VRAMUsedMB: 95})
	adapter.cancelErr = errors.New("injected sharing cancellation failure")
	adapter.yieldErr = errors.New("injected sharing yield failure")
	target := Target{ID: "resume-sharing", Adapter: adapter.Name(), AcceleratorID: "resume-sharing-gpu", CapabilityVersion: "v1", Enabled: true}
	row, reservation, target := seedDirectResumeExecution(t, backing, mgr, adapter, target, "resume-sharing-workload")
	reservation.shared = true
	reservation.capacityVRAMMB = 100
	reservation.reserveVRAMMB = 10
	close(adapter.resumeRelease)
	done := make(chan struct{})
	go func() {
		mgr.execute(ctx, row.Request.ID, target, reservation)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sharing-yield cleanup did not finish boundedly")
	}
	if lease, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID); err != nil || lease == nil {
		t.Fatalf("sharing-yield failure released a live backend fence: lease=%+v err=%v", lease, err)
	}
	failed, _ := backing.GetWorkload(ctx, row.Request.ID)
	if failed.Error == "" || !strings.Contains(failed.Error, "yield failed") {
		t.Fatalf("sharing-yield failure was not visible: %+v", failed)
	}
	resolved := waitForDirectCleanupRetry(t, mgr, backing, row.Request.ID, target.AcceleratorID, adapter)
	if resolved.Status != domain.WorkloadFailed {
		t.Fatalf("sharing cleanup retry did not terminalize workload: %+v", resolved)
	}
	resumeCalls, cancelCalls, yieldCalls := adapter.stats()
	if resumeCalls != 1 || cancelCalls < 2 || yieldCalls == 0 {
		t.Fatalf("sharing cleanup did not preserve physical identity: resumes=%d cancels=%d yields=%d", resumeCalls, cancelCalls, yieldCalls)
	}
}

// outerCASConflictStore injects a real durable revision race at the exact
// victim projection CAS after the physical checkpoint has already committed.
// Embedding MemoryStore keeps every other WorkloadStore surface authoritative;
// only the one CAS is made adversarial.
type outerCASConflictStore struct {
	*store.MemoryStore
	victimID   string
	newcomerID string
	mu         sync.Mutex
	injected   bool
}

func (s *outerCASConflictStore) CompareAndSwapWorkload(ctx context.Context, w *domain.Workload, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.Workload, error) {
	if w != nil && w.Request.ID == s.victimID && w.Status == domain.WorkloadQueued && strings.Contains(w.Error, "preempted: checkpointed") {
		s.mu.Lock()
		first := !s.injected
		if first {
			s.injected = true
		}
		s.mu.Unlock()
		if first {
			current, err := s.MemoryStore.GetWorkload(ctx, s.victimID)
			if err != nil {
				return nil, err
			}
			current.Error = "injected outer CAS revision conflict"
			current.UpdatedAt = time.Now().UTC()
			if _, err := s.MemoryStore.UpdateWorkload(ctx, current); err != nil {
				return nil, err
			}
			return nil, store.ErrWorkloadConflict
		}
	}
	return s.MemoryStore.CompareAndSwapWorkload(ctx, w, expectedRevision, expectedStatus, expectedCancellationOwner)
}

func (s *outerCASConflictStore) conflictInjected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.injected
}

// newcomerCASCrashStore lets the real scheduler complete the victim CAS, then
// rejects exactly the newcomer projection CAS.  Its final CAS hook simulates a
// controller crash immediately after restoreCheckpointVictim has durably
// recorded the fresh handle and before the restored projection is adopted.
type newcomerCASCrashStore struct {
	*store.MemoryStore
	victimID     string
	newcomerID   string
	mu           sync.Mutex
	victimWon    bool
	newcomerFail bool
	crashed      bool
}

func (s *newcomerCASCrashStore) CompareAndSwapWorkload(ctx context.Context, w *domain.Workload, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.Workload, error) {
	if w != nil && w.Request.ID == s.newcomerID {
		s.mu.Lock()
		inject := s.victimWon && !s.newcomerFail
		if inject {
			s.newcomerFail = true
		}
		s.mu.Unlock()
		if inject {
			return nil, store.ErrWorkloadConflict
		}
	}
	if w != nil && w.Request.ID == s.victimID && w.Status == domain.WorkloadQueued && strings.Contains(w.Error, "preempted: checkpointed") {
		updated, err := s.MemoryStore.CompareAndSwapWorkload(ctx, w, expectedRevision, expectedStatus, expectedCancellationOwner)
		if err == nil {
			s.mu.Lock()
			s.victimWon = true
			s.mu.Unlock()
		}
		return updated, err
	}
	if w != nil && w.Request.ID == s.victimID && w.Status == domain.WorkloadRunning && w.Execution != nil && w.Execution.ExternalID == "compensated-victim" {
		s.mu.Lock()
		crash := !s.crashed
		if crash {
			s.crashed = true
		}
		s.mu.Unlock()
		if crash {
			// Goexit terminates only the scheduler goroutine, preserving the
			// durable intent and fresh lease exactly as a process crash would.
			runtime.Goexit()
		}
	}
	return s.MemoryStore.CompareAndSwapWorkload(ctx, w, expectedRevision, expectedStatus, expectedCancellationOwner)
}

func (s *newcomerCASCrashStore) states() (victimWon, newcomerFail, crashed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.victimWon, s.newcomerFail, s.crashed
}

// nativeOuterCASCommandHandler is a signed NodeControl endpoint with a small
// authoritative phase journal. It deliberately sits behind
// NewSignedNodeCommandControl so this test exercises the same envelope and
// argument validation used by the production HTTPAdapter path.
type nativeOuterCASCommandHandler struct {
	nodeID  string
	secret  []byte
	mu      sync.Mutex
	actions []string
	errors  []string
}

func (h *nativeOuterCASCommandHandler) Handle(_ context.Context, command wsproto.CommandPayload) wsproto.CommandResultPayload {
	if command.NodeID != h.nodeID || !wsproto.VerifyCommand(command, h.secret) {
		h.mu.Lock()
		h.errors = append(h.errors, "signature")
		h.mu.Unlock()
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: h.nodeID, Error: "invalid signed node command"}
	}
	if err := wsproto.ValidateCheckpointCommandArgs(command.Command, command.Args); err != nil {
		h.mu.Lock()
		h.errors = append(h.errors, command.Command+": "+err.Error())
		h.mu.Unlock()
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: h.nodeID, Error: err.Error()}
	}
	action := strings.TrimPrefix(command.Command, "checkpoint_")
	h.mu.Lock()
	h.actions = append(h.actions, action)
	h.mu.Unlock()
	result := map[string]any{}
	switch action {
	case "slot_assign":
		result["slot_id"] = 0
	case "pause":
		result["prefix"] = "cHJlZml4"
		result["token_count"] = 7
	case "save":
		result["snapshot_ref"] = "victim.kv"
		result["snapshot_digest"] = "runtime-digest"
		result["snapshot_bytes"] = 8
		result["saved_tokens"] = 7
	case "resume":
		result["external_id"] = "native-resumed-conversation"
	case "reuse_verify":
		result["reused_tokens"] = 1
	}
	return wsproto.CommandResultPayload{ID: command.ID, NodeID: h.nodeID, OK: true, Result: result, CompletedAt: time.Now().UTC()}
}

func (h *nativeOuterCASCommandHandler) actionList() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.actions...)
}

func (h *nativeOuterCASCommandHandler) errorList() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.errors...)
}

// nativeOuterCASAdapter uses the production HTTPAdapter for checkpoint and
// restore while providing a deliberately long-lived controller-side victim
// handle. The restore path still opens a real HTTP streaming continuation.
type nativeOuterCASAdapter struct {
	*HTTPAdapter
	operations store.LLMCheckpointOperationStore
}

func (a *nativeOuterCASAdapter) Start(_ context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	h := &domain.ExecutionHandle{ExternalID: "native-victim-handle", StartedAt: time.Now().UTC()}
	h.Opaque, _ = json.Marshal(map[string]any{"slot_id": 0, "accelerator_id": target.AcceleratorID, "conversation_id": "native-victim-conversation", "operation_id": "native-victim-operation"})
	a.runMu.Lock()
	a.runs[h.ExternalID] = &httpRun{startedAt: h.StartedAt}
	a.runMu.Unlock()
	a.recordCheckpointExecution(h, req, plan, target)
	return h, nil
}

func (a *nativeOuterCASAdapter) CheckpointWithLease(ctx context.Context, h *domain.ExecutionHandle, target Target, lease SlotLease, command CheckpointCommand) (string, error) {
	command.ID = "native-victim-operation"
	command.IdempotencyKey = "native-victim-operation"
	if a.operations != nil {
		created, _, err := a.operations.CreateLLMCheckpointOperation(ctx, &store.LLMCheckpointOperation{
			ID: command.ID, IdempotencyKey: command.IdempotencyKey, OwnerID: command.OwnerID, WorkloadID: command.WorkloadID,
			NodeID: target.NodeID, AcceleratorID: lease.AcceleratorID, TargetID: target.ID, Model: command.ModelFingerprint,
			SlotID: 0, Generation: command.Generation, Fence: command.Fence, RuntimeIdentity: command.RuntimeIdentity,
			ModelFingerprint: command.ModelFingerprint, ProfileFingerprint: command.ProfileFingerprint,
			ContextFingerprint: fmt.Sprintf("ctx:%d", command.ContextLimit), ConversationID: "native-victim-conversation",
			ContinuationConversationID: "continuation-native-victim-operation", WorkloadRevision: command.WorkloadRevision,
			Phase: "planned", PhaseOrdinal: checkpointRecoveryOrdinal("planned"),
		})
		if err != nil && !errors.Is(err, store.ErrLLMCheckpointConflict) {
			return "", err
		}
		if err == nil {
			assigned := *created
			assigned.Phase = "assigned"
			assigned.PhaseOrdinal = checkpointRecoveryOrdinal("assigned")
			assignedRow, assignErr := a.operations.UpdateLLMCheckpointOperation(ctx, &assigned, created.Revision)
			if assignErr != nil {
				return "", assignErr
			}
			started := *assignedRow
			started.Phase = "started"
			started.PhaseOrdinal = checkpointRecoveryOrdinal("started")
			if _, err := a.operations.UpdateLLMCheckpointOperation(ctx, &started, assignedRow.Revision); err != nil {
				return "", err
			}
		}
	}
	return a.HTTPAdapter.CheckpointWithLease(ctx, h, target, lease, command)
}

func (a *nativeOuterCASAdapter) StartAsync(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	return a.Start(ctx, req, plan, target)
}

func (a *nativeOuterCASAdapter) Observe(ctx context.Context, _ domain.WorkloadRequest, _ *domain.ExecutionPlan, _ *domain.ExecutionHandle, _ Target) (Observation, error) {
	<-ctx.Done()
	return Observation{}, ctx.Err()
}

// TestNativeCommandProcessorAuthorizesExactCompensationCancel exercises the
// production nodeagent commandProcessor rather than a permissive controller
// mock.  The operation id deliberately names the physical compensation row;
// a wrong slot is rejected, while the exact slot/generation/fence/conversation
// tuple is accepted and must reach the real llama.cpp driver cancel boundary.
func TestNativeCommandProcessorAuthorizesExactCompensationCancel(t *testing.T) {
	const (
		nodeID        = "native-compensation-node"
		targetID      = nodeID + "-runtime"
		acceleratorID = nodeID + "-gpu0"
		ownerID       = "native-owner"
		workloadID    = "native-workload"
		operationID   = "native-transition:compensate"
		model         = "native-model"
		runtimeID     = "native-runtime"
	)
	root := t.TempDir()
	snapshotName := "native-compensation.kv"
	snapshot := []byte("native checkpoint bytes")
	if err := os.WriteFile(filepath.Join(root, snapshotName), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(snapshot)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	manifest := map[string]any{
		"version": "llm-checkpoint-owner-v1", "owner": ownerID,
		"entries": map[string]any{snapshotName: map[string]any{
			"owner": ownerID, "snapshot_name": snapshotName, "operation_id": operationID,
			"bytes": int64(len(snapshot)), "created_at": time.Now().UTC(),
			"active_references": 1, "terminalized": false,
			"references": map[string]int{operationID: 1},
		}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".owner-"+ownerID+".manifest.json"), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/slots":
			_, _ = io.WriteString(w, `[{"id":0,"n_ctx":4096,"is_processing":false,"n_prompt_tokens":7,"n_prompt_tokens_cached":2}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/slots/0" && r.URL.Query().Get("action") == "restore":
			_, _ = io.WriteString(w, `{"n_restored":7}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/stream":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"prefix\"}}],\"usage\":{\"prompt_tokens_cached\":2}}\n\ndata: [DONE]\n\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	statePath := filepath.Join(root, "command-state.json")
	secret := "native-compensation-signing-secret"
	cfg := &nodeagent.Config{
		NodeID: nodeID, CommandSigningSecret: secret, CommandStatePath: statePath,
		Checkpoint: nodeagent.CheckpointConfig{
			Enabled: true, Root: root, MaxBytes: 1 << 20, MaxFiles: 32,
			PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 8,
			MaxMetadataBytes: 1 << 16, MaxOutputBytes: 1 << 16,
			ExpirySeconds: 3600, CleanupIntervalSeconds: 60,
		},
	}
	cfg.LlamaCPP.Servers = []nodeagent.LlamaCPPServerConfig{{
		ID: "runtime", Endpoint: backend.URL, AcceleratorIndex: 0,
		ContextLimit: 4096, Slots: 1,
		ModelFingerprints:   map[string]string{model: model},
		RuntimeFingerprints: map[string]string{runtimeID: runtimeID},
	}}
	handler := nodeagent.NewCommandHandler(cfg, quietLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	makeCommand := func(action string, slot int, extra map[string]any) wsproto.CommandPayload {
		args := map[string]any{
			"target_kind": "llamacpp", "target_id": targetID,
			"accelerator_id": acceleratorID, "model": model,
			"runtime_identity": runtimeID, "capability_version": domain.CapabilityContractVersion,
			"capability_revision": domain.CapabilityContractVersion,
			"profile_fingerprint": "native-profile", "context_fingerprint": "ctx:4096",
			"owner_id": ownerID, "workload_id": workloadID,
			"generation": int64(17), "fencing_token": int64(29), "context_limit": 4096,
			"checkpoint_action": action, "checkpoint_operation_id": operationID,
			"idempotency_key": operationID + ":" + action,
			"slot_id":         slot, "conversation_id": "source-conversation",
			"continuation_conversation_id": "continuation-" + operationID,
		}
		if action == "restore" || action == "cancel" || action == "release" {
			args["snapshot_name"] = snapshotName
		}
		if action == "restore" {
			args["snapshot_digest"] = digest
		}
		if action == "resume" {
			args["partial_output_hash"] = "sha256:" + hex.EncodeToString(digestBytes[:])
			args["partial_output_offset"] = 6
		}
		for key, value := range extra {
			args[key] = value
		}
		now := time.Now().UTC()
		command := wsproto.CommandPayload{ID: args["idempotency_key"].(string), IdempotencyKey: args["idempotency_key"].(string), NodeID: nodeID, Command: "checkpoint_" + action, Args: args, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		signature, signErr := wsproto.SignCommand(command, []byte(secret))
		if signErr != nil {
			t.Fatal(signErr)
		}
		command.Signature = signature
		return command
	}
	call := func(command wsproto.CommandPayload) wsproto.CommandResultPayload {
		result := handler.Handle(ctx, command)
		if result.Error != "" {
			t.Fatalf("native %s command failed: %s", command.Command, result.Error)
		}
		if !result.OK {
			t.Fatalf("native %s command was not successful: %+v", command.Command, result)
		}
		return result
	}

	call(makeCommand("slot_assign", 0, nil))
	call(makeCommand("reload", 0, map[string]any{"snapshot_name": snapshotName}))
	call(makeCommand("restore", 0, nil))
	call(makeCommand("resume", 0, nil))
	wrong := makeCommand("cancel", 1, map[string]any{"compensation_of": operationID, "conversation_id": "continuation-" + operationID, "idempotency_key": operationID + ":cancel-wrong-slot"})
	wrongResult := handler.Handle(ctx, wrong)
	if wrongResult.Error == "" {
		t.Fatal("native commandProcessor accepted compensation cancel for the wrong slot")
	}
	call(makeCommand("cancel", 0, map[string]any{"compensation_of": operationID, "conversation_id": "continuation-" + operationID}))
	call(makeCommand("release", 0, map[string]any{"conversation_id": "continuation-" + operationID}))
}

func TestNativeHTTPCheckpointCASConflictAdoptsDurably(t *testing.T) {
	const (
		nodeID        = "node-native-cas"
		targetID      = "target-native-cas"
		acceleratorID = "gpu-native-cas"
		victimID      = "native-cas-victim"
		urgentID      = "native-cas-urgent"
	)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"native-resumed\",\"choices\":[{\"delta\":{\"content\":\"suffix\"}}]}\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer backend.Close()

	proof := checkpointRuntime.CheckpointCapabilityProof{
		ProofVersion: checkpointRuntime.CheckpointCapabilityProofVersion, ModelAlias: "model-alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true,
		BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true,
		ProvenAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
		NodeID: nodeID, TargetID: targetID, AcceleratorID: acceleratorID,
		ModelFingerprint: "model-native-cas", RuntimeIdentity: "runtime-native-cas",
		ProfileFingerprint: "profile-native-cas", ContextLimit: 4096, SlotID: 0,
		Generation: 1, OldFence: 1, NewFence: 2, SavedTokens: 7, ReusedTokens: 1,
		EvidenceID: "native-cas-evidence", Signature: "native-cas-signature", Digest: "native-cas-digest",
		SnapshotDigest: "runtime-digest", SnapshotBytes: 8, Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef",
	}
	if !proof.Complete() {
		t.Fatal("test proof must satisfy the production admission predicate")
	}

	backing := &outerCASConflictStore{MemoryStore: store.NewMemoryStore(), victimID: victimID, newcomerID: urgentID}
	snapshotStore, err := NewSnapshotStore(t.TempDir(), 1<<20, 8)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := NewCheckpointCoordinator(nil, snapshotStore, proof)
	coordinator.Operations = backing
	commandHandler := &nativeOuterCASCommandHandler{nodeID: nodeID, secret: []byte("native-cas-signing-secret-32")}
	control := NewSignedNodeCommandControl(commandHandler, nodeID, commandHandler.secret)
	adapter := &nativeOuterCASAdapter{HTTPAdapter: NewHTTPAdapter("native-cas", "llama", backend.Client()), operations: backing}
	adapter.SetLLMCheckpointCoordinator(coordinator)
	adapter.ConfigureCheckpointChannel(func(context.Context, Target) (NodeControl, string, bool) {
		return control, nodeID, true
	})
	target := Target{
		ID: targetID, NodeID: nodeID, Adapter: "native-cas", Endpoint: backend.URL,
		AcceleratorID: acceleratorID, Models: []string{"model-native-cas"}, ContextLimit: 4096, Slots: 1,
		ActiveRuntimeProfile: proof.ProfileFingerprint, RuntimeProfiles: []RuntimeCapacityProfile{{ID: proof.ProfileFingerprint, ContextLimit: 4096, Slots: 1}},
		CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		RuntimeIdentity: proof.RuntimeIdentity, ModelFingerprint: proof.ModelFingerprint,
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 8 << 30},
		CapacityVerified: true, CapacitySource: "runtime:/slots",
		CheckpointProof: proof, Enabled: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(quietLogger(), backing, time.Second)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	registeredTarget := mgr.targetByID(target.ID)
	if _, err := mgr.SetModelCapacity(ctx, measuredCapacityWithProfile(registeredTarget, "model-native-cas", 2<<30, 1<<30)); err != nil {
		t.Fatalf("seed measured native checkpoint model/profile capacity: %v", err)
	}
	// RegisterTarget's production fast path type-asserts the concrete
	// HTTPAdapter; this wrapper deliberately embeds it so install the exact
	// target-scoped proof explicitly for the integration harness.
	adapter.SetTargetCheckpointProof(target.ID, proof)
	mgr.Start(ctx)
	defer mgr.Close()

	victim, _, err := mgr.Submit(ctx, domain.WorkloadRequest{
		ID: victimID, ItemID: victimID, OwnerID: "native-cas-owner", Adapter: "native-cas",
		Payload:  json.RawMessage(`{"model":"model-native-cas","messages":[{"role":"user","content":"checkpoint me"}]}`),
		Priority: 1, Recoverable: true, Disruption: domain.DisruptionCheckpointable, InterruptionConsent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		victim, _ = backing.GetWorkload(ctx, victimID)
		if victim.Status == domain.WorkloadRunning && victim.Execution != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if victim.Status != domain.WorkloadRunning || victim.Execution == nil {
		t.Fatalf("native victim never reached running state: %+v", victim)
	}

	urgent, _, err := mgr.Submit(ctx, domain.WorkloadRequest{
		ID: urgentID, ItemID: urgentID, OwnerID: "native-cas-owner", Adapter: "native-cas",
		Payload: json.RawMessage(`{"model":"model-native-cas","messages":[{"role":"user","content":"urgent"}]}`),
		QoS:     domain.QoSInteractive, Priority: 80, Disruption: domain.DisruptionLocked, PreemptionBudget: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = urgent

	var intent *store.LLMCheckpointOperation
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, listErr := backing.ListLLMCheckpointOperations(ctx, "native-cas-owner")
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, row := range rows {
			if row != nil && row.RecoveryState == "adopted" && row.WorkloadID == victimID {
				intent = row
				break
			}
		}
		if intent != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !backing.conflictInjected() || intent == nil {
		victimNow, _ := backing.GetWorkload(ctx, victimID)
		urgentNow, _ := backing.GetWorkload(ctx, urgentID)
		plans, _ := backing.ListTransitionPlans(ctx, urgentID, 10)
		rows, _ := backing.ListLLMCheckpointOperations(ctx, "native-cas-owner")
		rowSummary := make([]string, 0, len(rows))
		for _, row := range rows {
			if row != nil {
				rowSummary = append(rowSummary, fmt.Sprintf("%s phase=%s rev=%d fence=%d comp=%s recovery=%s err=%s", row.ID, row.Phase, row.Revision, row.Fence, row.CompensationOf, row.RecoveryState, row.Error))
			}
		}
		planErrors := make([]string, 0, len(plans))
		for _, plan := range plans {
			if plan != nil {
				planErrors = append(planErrors, plan.Error)
			}
		}
		t.Fatalf("real outer CAS conflict did not reach durable adoption: injected=%v intent=%+v victim=%+v urgent=%+v plan_errors=%v rows=%v actions=%v handler_errors=%v", backing.conflictInjected(), intent, victimNow, urgentNow, planErrors, rowSummary, commandHandler.actionList(), commandHandler.errorList())
	}

	adopted, err := backing.GetWorkload(ctx, victimID)
	if err != nil {
		t.Fatal(err)
	}
	if adopted.Status != domain.WorkloadRunning || adopted.Execution == nil || adopted.Execution.ExternalID == "native-victim-handle" || adopted.CheckpointRef != "" {
		t.Fatalf("victim durable projection was stale after outer CAS conflict: %+v", adopted)
	}
	lease, err := backing.GetAcceleratorLease(ctx, acceleratorID)
	if err != nil || lease.WorkloadID != victimID || lease.FencingToken <= int64(intent.Fence) {
		t.Fatalf("restored victim does not own the fresh durable fence: lease=%+v intent=%+v err=%v", lease, intent, err)
	}
	urgent, err = backing.GetWorkload(ctx, urgentID)
	if err != nil {
		t.Fatal(err)
	}
	if urgent.Status == domain.WorkloadSucceeded || urgent.Status == domain.WorkloadRunning || urgent.Execution != nil {
		t.Fatalf("newcomer was falsely admitted/completed after victim CAS conflict: %+v", urgent)
	}

	// A new Manager recovery pass must preserve the adopted durable intent and
	// the live victim handle rather than requeueing or replaying the snapshot.
	restarted := NewManager(quietLogger(), backing, time.Second)
	restarted.recoverCheckpointRecoveryIntents(ctx)
	recoveredIntent, err := backing.GetLLMCheckpointOperation(ctx, intent.ID)
	if err != nil || recoveredIntent.RecoveryState != "adopted" {
		t.Fatalf("adopted recovery intent did not survive restart pass: %+v err=%v", recoveredIntent, err)
	}
	recoveredVictim, err := backing.GetWorkload(ctx, victimID)
	if err != nil || recoveredVictim.Status != domain.WorkloadRunning || recoveredVictim.Execution == nil || recoveredVictim.Execution.ExternalID != adopted.Execution.ExternalID {
		t.Fatalf("restart recovery rewrote adopted victim: %+v err=%v", recoveredVictim, err)
	}
	actions := commandHandler.actionList()
	for _, required := range []string{"slot_assign", "pause", "save", "stop_confirm", "release", "reload", "restore", "resume", "continue", "reuse_verify"} {
		found := false
		for _, action := range actions {
			if action == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("signed native checkpoint path omitted %s: actions=%v", required, actions)
		}
	}
}

type handoffTransitionReadMutator struct {
	store.WorkloadStore
	mutate func(*domain.ResidencyTransition)
}

func (s handoffTransitionReadMutator) GetResidencyTransition(ctx context.Context, id string) (*domain.ResidencyTransition, error) {
	transition, err := s.WorkloadStore.GetResidencyTransition(ctx, id)
	if err == nil && transition != nil && s.mutate != nil { s.mutate(transition) }
	return transition, err
}

func TestAdmissionOwnedPlacementGenerationHandoff(t *testing.T) {
	before := Target{
		ID: "handoff-target", Adapter: "mock", Endpoint: "in-process", AcceleratorID: "gpu-handoff",
		Models: []string{"owned-model", "other-model"}, ContextLimit: 2048, Slots: 2,
		ActiveRuntimeProfile: "profile-handoff", RuntimeProfiles: []RuntimeCapacityProfile{{ID: "profile-handoff", ContextLimit: 2048, Slots: 2}},
		CapabilityVersion: "handoff-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true},
		ModelFingerprint: "handoff-model-fingerprint", Enabled: true,
	}
	const beforeGeneration = uint64(9)
	placement := activePlacement{
		workloadID: "handoff-workload", targetID: before.ID, acceleratorID: before.AcceleratorID,
		model: "owned-model", contextTokens: 544, targetGeneration: beforeGeneration,
		profileID: before.ActiveRuntimeProfile, runtimeIdentity: residencyCapacityIdentity(before),
	}
	tests := []struct {
		name              string
		victims           []string
		unprofiled        bool
		omitPlacement     bool
		omitReservation   bool
		replaceReservation bool
		release           string
		mutatePlacement   func(*activePlacement)
		mutateTarget      func(*Target)
		mutateTransition  func(*domain.ResidencyTransition)
		staleLease        bool
		foreignTransition bool
		allocatedHighwater bool
		unallocatedOrigin bool
		foreignOrigin      bool
		removeOrigin       bool
		wantSuccess       bool
	}{
		{name: "single owned load", wantSuccess: true},
		{name: "allocated same-model highwater exceeds accelerator lease", allocatedHighwater: true, wantSuccess: true},
		{name: "high-fence legacy allocation cannot claim current admission", unallocatedOrigin: true},
		{name: "same-key receipt from another lease origin", foreignOrigin: true, allocatedHighwater: true},
		{name: "removed store-issued provenance cannot hand off", removeOrigin: true},
		{name: "multi-victim replacement", victims: []string{"victim-a", "victim-b"}, wantSuccess: true},
		{name: "legacy unprofiled context-zero load", unprofiled: true, wantSuccess: true},
		{name: "missing placement", omitPlacement: true},
		{name: "missing reservation", omitReservation: true},
		{name: "replaced reservation", replaceReservation: true},
		{name: "replaced placement", mutatePlacement: func(current *activePlacement) { current.workloadID = "replacement-workload" }},
		{name: "wrong placement generation", mutatePlacement: func(current *activePlacement) { current.targetGeneration-- }},
		{name: "released reservation", release: "released"},
		{name: "releasing reservation", release: "requested"},
		{name: "cancelled reservation", release: "in-flight"},
		{name: "changed placement identity", mutatePlacement: func(current *activePlacement) { current.runtimeIdentity = "different-runtime-identity" }},
		{name: "changed target profile facts", mutateTarget: func(current *Target) { current.ContextLimit++ }},
		{name: "changed target device", mutateTarget: func(current *Target) { current.AcceleratorID = "different-device" }},
		{name: "changed target model", mutateTarget: func(current *Target) { current.ModelFingerprint = "different-model" }},
		{name: "changed target capacity", mutateTarget: func(current *Target) { current.Capacity.VRAMHardCapBytes++ }},
		{name: "changed target runtime", mutateTarget: func(current *Target) { current.CapabilityVersion = "different-runtime" }},
		{name: "unrelated target refresh", mutateTarget: func(current *Target) { current.ResidentModels = []string{"unowned-model", "owned-model"} }},
		{name: "foreign transition", foreignTransition: true},
		{name: "stale admission lease fence", staleLease: true},
		{name: "wrong transition owner", mutateTransition: func(current *domain.ResidencyTransition) { current.RequestedBy = "foreign-owner" }},
		{name: "wrong transition generation", mutateTransition: func(current *domain.ResidencyTransition) { current.TargetGeneration++ }},
		{name: "wrong transition model", mutateTransition: func(current *domain.ResidencyTransition) { current.Model = "foreign-model" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixtureBefore := before
			fixtureBefore.ResidentModels = append([]string(nil), test.victims...)
			if test.unprofiled {
				fixtureBefore.ActiveRuntimeProfile = ""
				fixtureBefore.RuntimeProfiles = nil
			}
			fixturePlacement := placement
			fixturePlacement.profileID = fixtureBefore.ActiveRuntimeProfile
			fixturePlacement.runtimeIdentity = residencyCapacityIdentity(fixtureBefore)
			if test.unprofiled { fixturePlacement.contextTokens = 0 }
			fixtureAfter := fixtureBefore
			for _, victim := range test.victims { fixtureAfter.ResidentModels = withoutExact(fixtureAfter.ResidentModels, victim) }
			fixtureAfter.ResidentModels = append(fixtureAfter.ResidentModels, "owned-model")
			afterGeneration := beforeGeneration + uint64(len(test.victims)) + 1
			backing := store.NewMemoryStore()
			lease, acquired, leaseErr := backing.AcquireAcceleratorLease(context.Background(), fixtureBefore.AcceleratorID, "handoff-lease-owner", time.Minute)
			if leaseErr != nil || !acquired { t.Fatalf("acquire fixture accelerator lease: acquired=%t err=%v", acquired, leaseErr) }
			placementReservation := &targetReservation{targetID: fixtureBefore.ID, workloadID: fixturePlacement.workloadID, targetGeneration: beforeGeneration, lease: lease}
			if test.allocatedHighwater {
				now := time.Now().UTC()
				historical := &domain.ResidencyTransition{ID:"historical-owned-model", IdempotencyKey:"historical-owned-model-key", TargetID:fixtureBefore.ID,
					AcceleratorID:fixtureBefore.AcceleratorID, Model:"owned-model", FromTier:domain.ResidencyColdDisk, ToTier:domain.ResidencyColdDisk,
					Reason:"prior completed model-fence allocation", RequestedBy:"prior-owner", WorkloadID:"prior-workload", Status:domain.ResidencyTransitionPlanned,
					Revision:1, TargetGeneration:beforeGeneration, ExecutionFingerprint:targetExecutionFingerprint(fixtureBefore), FencingToken:lease.FencingToken+20,
					CapabilityVersion:fixtureBefore.CapabilityVersion, CapabilityRevision:fixtureBefore.CapabilityRevision}
				allocated, _, allocateErr := backing.AllocateResidencyTransition(context.Background(), historical)
				if allocateErr != nil { t.Fatalf("allocate historical same-model fence: %v", allocateErr) }
				running := *allocated
				running.Status = domain.ResidencyTransitionRunning
				running.StartedAt = &now
				if _, casErr := backing.CompareAndSwapResidencyTransition(context.Background(), &running, allocated.Revision, domain.ResidencyTransitionPlanned, allocated.FencingToken); casErr != nil { t.Fatalf("start historical allocated fence: %v", casErr) }
				failed := running
				failed.Status = domain.ResidencyTransitionFailed
				failed.Error = "historical allocation fixture"
				failed.FinishedAt = &now
				if _, casErr := backing.CompareAndSwapResidencyTransition(context.Background(), &failed, running.Revision+1, domain.ResidencyTransitionRunning, allocated.FencingToken); casErr != nil { t.Fatalf("finish historical allocated fence: %v", casErr) }
			}
			currentTarget := fixtureAfter
			if test.mutateTarget != nil {
				test.mutateTarget(&currentTarget)
			}
			currentPlacement := fixturePlacement
			if test.mutatePlacement != nil {
				test.mutatePlacement(&currentPlacement)
			}
			transitionIDs := make([]string, 0, len(test.victims)+1)
			cursor := fixtureBefore
			generation := beforeGeneration
			allocationLease := lease
			var allocateErr error
			if test.foreignOrigin {
				if releaseErr := backing.ReleaseAcceleratorLease(context.Background(), lease.AcceleratorID, lease.WorkloadID, lease.FencingToken); releaseErr != nil { t.Fatalf("release initial lease for foreign-origin fixture: %v", releaseErr) }
				foreignLease, foreignAcquired, foreignErr := backing.AcquireAcceleratorLease(context.Background(), fixtureBefore.AcceleratorID, "foreign-origin-owner", time.Minute)
				if foreignErr != nil || !foreignAcquired { t.Fatalf("acquire foreign-origin lease: acquired=%t err=%v", foreignAcquired, foreignErr) }
				allocationLease = foreignLease
			}
			createReceipt := func(id, model, reason, key string, to domain.ResidencyTier) {
				identity, _, identityErr := canonicalResidencyIdentity(cursor, model, false)
				if identityErr != nil { t.Fatalf("transition identity: %v", identityErr) }
				from := domain.ResidencyColdDisk
				if to == domain.ResidencyColdDisk { from = domain.ResidencyHotVRAM }
				finished := time.Now().UTC()
				// Allocation supplies origin/revision; execution observations arrive in the following CASes.
				row := &domain.ResidencyTransition{ID:id, IdempotencyKey:key, TargetID:cursor.ID, AcceleratorID:cursor.AcceleratorID, Model:model,
					FromTier:from, ToTier:to, Reason:reason+" runtime="+residencyCapacityIdentity(cursor), RequestedBy:"handoff-owner", WorkloadID:fixturePlacement.workloadID,
					Status:domain.ResidencyTransitionPlanned, TargetGeneration:generation, ExecutionFingerprint:targetExecutionFingerprint(cursor),
					FencingToken:allocationLease.FencingToken, CapabilityVersion:cursor.CapabilityVersion,
					CapabilityRevision:cursor.CapabilityRevision}
				if test.unallocatedOrigin { row.FencingToken = lease.FencingToken + 20 }
				if test.foreignTransition { row.WorkloadID = "foreign-workload"; test.foreignTransition = false }
				if test.mutateTransition != nil { test.mutateTransition(row); test.mutateTransition = nil }
				var allocated *domain.ResidencyTransition
				if test.unallocatedOrigin {
					allocated, _, allocateErr = backing.AllocateResidencyTransition(context.Background(), row)
				} else {
					allocated, _, allocateErr = backing.AllocateResidencyTransitionWithLease(context.Background(), row, allocationLease)
				}
				if allocateErr != nil { t.Fatalf("allocate receipt: %v", allocateErr) }
				running := *allocated
				running.Status = domain.ResidencyTransitionRunning
				running.StartedAt = &finished
				if _, casErr := backing.CompareAndSwapResidencyTransition(context.Background(), &running, allocated.Revision, domain.ResidencyTransitionPlanned, allocated.FencingToken); casErr != nil { t.Fatalf("start allocated receipt: %v", casErr) }
				succeeded := running
				succeeded.Status = domain.ResidencyTransitionSucceeded
				succeeded.ObservedTier = to
				succeeded.RuntimeIdentity = identity
				succeeded.ObservedFence = allocated.FencingToken
				succeeded.FinishedAt = &finished
				if _, casErr := backing.CompareAndSwapResidencyTransition(context.Background(), &succeeded, running.Revision+1, domain.ResidencyTransitionRunning, allocated.FencingToken); casErr != nil { t.Fatalf("complete allocated receipt: %v", casErr) }
				transitionIDs = append(transitionIDs, id)
				if to == domain.ResidencyColdDisk { cursor.ResidentModels = withoutExact(cursor.ResidentModels, model) } else { cursor.ResidentModels = append(cursor.ResidentModels, model) }
				generation++
			}
			for index, victim := range test.victims {
				createReceipt(fmt.Sprintf("victim-%d", index), victim, "capacity_for_demand", demandEvictKey(fixturePlacement.workloadID, fixtureBefore.ID, victim, allocationLease), domain.ResidencyColdDisk)
			}
			createReceipt("load-owned", "owned-model", "workload_demand", demandLoadKey(fixturePlacement.workloadID, fixtureBefore.ID, "owned-model", "", allocationLease), domain.ResidencyHotVRAM)
			if test.foreignOrigin {
				if releaseErr := backing.ReleaseAcceleratorLease(context.Background(), allocationLease.AcceleratorID, allocationLease.WorkloadID, allocationLease.FencingToken); releaseErr != nil { t.Fatalf("release foreign-origin lease: %v", releaseErr) }
				lease, acquired, leaseErr = backing.AcquireAcceleratorLease(context.Background(), fixtureBefore.AcceleratorID, "handoff-lease-owner", time.Minute)
				if leaseErr != nil || !acquired { t.Fatalf("reacquire current handoff lease: acquired=%t err=%v", acquired, leaseErr) }
				placementReservation.lease = lease
			}
			if test.allocatedHighwater {
				loaded, getErr := backing.GetResidencyTransition(context.Background(), "load-owned")
				highwater, highwaterErr := backing.MaxResidencyFencingToken(context.Background(), fixtureBefore.ID, "owned-model")
				loadedFence := int64(0)
				if loaded != nil { loadedFence = loaded.FencingToken }
				if getErr != nil || highwaterErr != nil || loaded == nil || loadedFence <= lease.FencingToken || loadedFence != highwater {
					t.Fatalf("allocated transition did not advance its independent model fence: lease=%d loaded=%+v highwater=%d errors=%v/%v", lease.FencingToken, loaded, highwater, getErr, highwaterErr)
				}
			}
			reservations := map[string]*targetReservation{placementReservation.workloadID: placementReservation}
			if test.omitReservation { delete(reservations, placementReservation.workloadID) }
			if test.replaceReservation { reservations[placementReservation.workloadID] = &targetReservation{targetID: fixtureBefore.ID, workloadID: fixturePlacement.workloadID, targetGeneration: beforeGeneration, lease: placementReservation.lease} }
			manager := &Manager{
				store:             backing,
				targets:           map[string]Target{fixtureBefore.ID: currentTarget},
				targetGenerations: map[string]uint64{fixtureBefore.ID: afterGeneration},
				reservations:      reservations,
				activePlacements:  make(map[string]activePlacement),
			}
			if test.removeOrigin {
				manager.store = handoffTransitionReadMutator{WorkloadStore: backing, mutate: func(row *domain.ResidencyTransition) {
					row.LeaseOriginAcceleratorID = ""
					row.LeaseOriginWorkloadID = ""
					row.LeaseOriginFencingToken = 0
					row.LeaseOriginAllocated = false
				}}
			}
			if test.release == "released" { placementReservation.released = true }
			if test.release == "requested" { placementReservation.releaseRequested = true }
			if test.release == "in-flight" { placementReservation.releaseInFlight = true }
			if test.staleLease { placementReservation.lease.FencingToken++ }
			if !test.omitPlacement {
				manager.activePlacements[placementReservation.workloadID] = currentPlacement
			}
			err := manager.handoffAdmissionOwnedPlacementGeneration(placementReservation, fixtureBefore, fixtureAfter, beforeGeneration, afterGeneration, "owned-model", "handoff-owner", "", transitionIDs, fixturePlacement)
			if (err == nil) != test.wantSuccess {
				t.Fatalf("handoff error=%v, wantSuccess=%t", err, test.wantSuccess)
			}
			actualPlacement, placementPresent := manager.activePlacements[placementReservation.workloadID]
			if test.wantSuccess {
				if placementReservation.targetGeneration != afterGeneration || !placementPresent || actualPlacement.targetGeneration != afterGeneration {
					t.Fatalf("owned handoff did not rebind both fences: reservation=%d placement=%+v present=%t", placementReservation.targetGeneration, actualPlacement, placementPresent)
				}
			} else if placementReservation.targetGeneration != beforeGeneration || (placementPresent && actualPlacement.targetGeneration != currentPlacement.targetGeneration) {
				t.Fatalf("rejected handoff changed the existing binding: reservation=%d placement=%+v present=%t", placementReservation.targetGeneration, actualPlacement, placementPresent)
			}
		})
	}

	// Exercise the handoff through real Submit -> durable transition store ->
	// stateful lifecycle observation. The lifecycle fixture reports its actual
	// loaded map, so an unload failure cannot be hidden by an unconditional tier.
	for _, scenario := range []struct {
		name     string
		victims  []string
	}{
		{name: "actual single-load legacy context-zero"},
		{name: "actual multiple-victim eviction and load", victims: []string{"live-victim-a", "live-victim-b"}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backing := store.NewMemoryStore()
			adapter := newAdmissionLifecycleAdapter("handoff-live")
			manager := NewManager(quietLogger(), backing, time.Second)
			manager.RegisterAdapter(adapter)
			target := Target{
				ID: "handoff-live-target", Adapter: adapter.Name(), Endpoint: "in-process", AcceleratorID: "gpu-handoff-live",
				Models: []string{"owned-model"}, ResidentModels: append([]string(nil), scenario.victims...),
					SupportsModelLifecycle: true, MaxResidentModels: 1, Slots: 1, Enabled: true,
				CapabilityVersion: "handoff-live-v1", CapabilityRevision: domain.CapabilityContractVersion,
				Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true},
				ModelFingerprint: "handoff-live-model-fingerprint", ResidencyPolicy: domain.ResidencyAuto,
				Capacity: domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMReserveBytes: 1 << 30, VRAMHardCapBytes: 8 << 30},
				CapacityVerified: true, CapacitySource: "runtime:/slots",
			}
			manager.RegisterTarget(target)
			registered := manager.targetByID(target.ID)
			generation := manager.targetGeneration(target.ID)
			for _, measuredModel := range append(append([]string(nil), scenario.victims...), "owned-model") {
				if _, capacityErr := manager.SetModelCapacity(ctx, measuredCapacity(registered, measuredModel, 1<<30)); capacityErr != nil {
					t.Fatalf("seed authoritative physical capacity for %s: %v", measuredModel, capacityErr)
				}
			}
			for _, victim := range scenario.victims {
				adapter.SetLoaded(victim, true)
				row := &domain.ModelResidency{ID: "res-" + victim, TargetID: target.ID, AcceleratorID: target.AcceleratorID,
					Adapter: target.Adapter, Model: victim, DesiredTier: domain.ResidencyHotVRAM, ObservedTier: domain.ResidencyHotVRAM,
					Policy: domain.ResidencyAuto, UpdatedAt: time.Now().UTC()}
				bindResidencyTargetFacts(row, registered, generation)
				if _, err := backing.UpsertModelResidency(ctx, row); err != nil { t.Fatalf("seed victim residency %s: %v", victim, err) }
			}
			manager.Start(ctx)
			workload, _, err := manager.Submit(ctx, domain.WorkloadRequest{OwnerID: "handoff-live-owner", Adapter: adapter.Name(), Payload: json.RawMessage(`{"model":"owned-model"}`)})
			if err != nil { t.Fatalf("actual lifecycle admission: %v", err) }
			if workload.Plan == nil || workload.Plan.TargetID != target.ID { t.Fatalf("actual admission selected unexpected target: %+v", workload.Plan) }
			current := manager.targetByID(target.ID)
			if !sameStringSet(current.ResidentModels, []string{"owned-model"}) { t.Fatalf("actual handoff did not publish expected resident set: %v", current.ResidentModels) }
			loads, unloads := adapter.Counts()
			if loads != 1 || unloads != len(scenario.victims) { t.Fatalf("stateful lifecycle effects loads=%d unloads=%d; want 1/%d", loads, unloads, len(scenario.victims)) }
			for _, victim := range scenario.victims {
				if row, getErr := backing.GetModelResidency(ctx, target.ID, victim); getErr != nil || row.ObservedTier != domain.ResidencyColdDisk { t.Fatalf("victim %s durable observation=%+v err=%v", victim, row, getErr) }
			}
			loaded, getErr := backing.GetModelResidency(ctx, target.ID, "owned-model")
			if getErr != nil || loaded.ObservedTier != domain.ResidencyHotVRAM { t.Fatalf("requested model durable observation=%+v err=%v", loaded, getErr) }
		})
	}
}

func TestRuntimeProfileHistoryIgnoresDefiniteRejection(t *testing.T) {
	target := Target{ID: "node-runtime", NodeID: "node", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k"}
	known := map[string]Target{target.ID: target}
	completed := time.Now().UTC()
	row := func(uncertain bool, done *time.Time) []*domain.NodeCommand {
		return []*domain.NodeCommand{{ID: "rejected-switch", NodeID: "node", Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": "ctx-8k"}, Attempts: 1, Status: domain.NodeCommandFailed, Error: "fencing_token must be a nonnegative integer", Uncertain: uncertain, CreatedAt: completed, UpdatedAt: completed, CompletedAt: done}}
	}
	if blocker := reduceRuntimeProfileHistory("node", target, row(false, &completed), known); blocker != "" {
		t.Fatalf("a definite node rejection still withholds the target: %q", blocker)
	}
	if blocker := reduceRuntimeProfileHistory("node", target, row(true, &completed), known); blocker == "" {
		t.Fatal("an uncertain failed switch must keep blocking until reconciled")
	}
	if blocker := reduceRuntimeProfileHistory("node", target, row(false, nil), known); blocker == "" {
		t.Fatal("a failed switch without a node result must keep blocking")
	}
	rejectedObservation := row(false, &completed)
	rejectedObservation[0].Error = "runtime profile observation rejected: missing adapters"
	if blocker := reduceRuntimeProfileHistory("node", target, rejectedObservation, known); blocker == "" {
		t.Fatal("a switch whose result the controller rejected may have happened and must keep blocking")
	}
}

// A profile switch the node definitively rejects (live: missing fence) left
// the target withheld with "operator reconciliation required" until the
// controller restarted. The previous profile is now restored at once and the
// next admission pass can switch again.
func TestRejectedRuntimeProfileSwitchRestoresTargetImmediately(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	now := time.Now().UTC()
	envelope := domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMHardCapBytes: 8 << 30}
	if _, err := backing.UpsertNode(ctx, &domain.Node{ID: "node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now}, Accelerators: []domain.Accelerator{{ID: "node-gpu0", NodeID: "node", VRAMTotalMB: 24_000, VRAMFreeMB: 24_000}}}); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(quietLogger(), backing, time.Second)
	defer mgr.Close()
	mgr.SetNodeStore(backing)
	mgr.RegisterAdapter(modelAwareMockAdapter{NewMockAdapter()})
	registered := Target{
		ID: "node-runtime", NodeID: "node", Adapter: "model-mock", Endpoint: "http://runtime", AcceleratorID: "node-gpu0", Models: []string{"model"}, ResidentModels: []string{"model"},
		ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", SupportsRuntimeProfileSwitch: true, Enabled: true,
		CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp", CapacitySource: "runtime:/slots", CapacityVerified: true,
		Capacity: envelope, RuntimeProfiles: []RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}},
	}
	mgr.RegisterTarget(registered)
	projected := mgr.targetByID(registered.ID)
	projected.ActiveRuntimeProfile, projected.ContextLimit, projected.Slots = "ctx-32k", 32768, 1
	capacity := measuredCapacityWithProfile(projected, "model", 3<<30, 2<<30)
	if _, err := backing.UpsertModelCapacity(ctx, &capacity); err != nil {
		t.Fatal(err)
	}
	commands := 0
	mgr.SetNodeControl(func(_ context.Context, _, command string, _ map[string]any, _ string) (map[string]any, error) {
		commands++
		if commands == 1 {
			return nil, fmt.Errorf("%w: fencing_token must be a nonnegative integer", ErrNodeCommandFailed)
		}
		return map[string]any{"adapters": []any{map[string]any{
			"id": "runtime", "adapter": "model-mock", "endpoint": "http://runtime", "accelerator_index": 0,
			"version": "runtime-v1", "model_fingerprint": "model-fp", "capability_version": "runtime-v1", "capability_revision": "cap-v1",
			"context_limit": 32768, "slots": 1, "capacity_source": "runtime:/slots", "capabilities_verified": true, "active_runtime_profile": "ctx-32k",
			"runtime_profiles": []any{map[string]any{"id": "ctx-8k", "context_limit": 8192, "slots": 4}, map[string]any{"id": "ctx-32k", "context_limit": 32768, "slots": 1}},
		}}}, nil
	})
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "model-mock", QueuePolicy: domain.QueueWait, Payload: json.RawMessage(`{"model":"model"}`), Bounds: domain.WorkloadBounds{ContextTokens: 30_000, MaxOutput: 1_000}})
	if err != nil {
		t.Fatal(err)
	}
	restored := mgr.targetByID(registered.ID)
	if commands != 1 || row.Status != domain.WorkloadWaiting || restored.ActiveRuntimeProfile != "ctx-8k" || restored.ContextLimit != 8192 || !restored.CapacityVerified || restored.CapacitySource != "runtime:/slots" {
		t.Fatalf("rejected switch did not restore the previous profile: commands=%d status=%s target=%+v", commands, row.Status, restored)
	}
	mgr.mu.RLock()
	pending, blockedNode, blockedCard := mgr.runtimeProfileTransitionTarget[registered.ID], mgr.runtimeProfileBlockedNodes["node"], mgr.runtimeProfileBlockedCards["node-gpu0"]
	mgr.mu.RUnlock()
	if pending != "" || blockedNode != "" || blockedCard != "" {
		t.Fatalf("rejected switch left blocks: pending=%q node=%q card=%q", pending, blockedNode, blockedCard)
	}
	latest, _ := backing.GetWorkload(ctx, row.Request.ID)
	latest.TargetRetryAfter = nil
	mgr.tryAdmit(ctx, latest)
	after, _ := backing.GetWorkload(ctx, row.Request.ID)
	if commands != 2 || (after.Status != domain.WorkloadRunning && after.Status != domain.WorkloadSucceeded) || mgr.targetByID(registered.ID).ActiveRuntimeProfile != "ctx-32k" {
		t.Fatalf("next pass did not switch and admit: commands=%d status=%s decision=%+v", commands, after.Status, after.Decision)
	}
}
