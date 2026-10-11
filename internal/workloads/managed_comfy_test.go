package workloads

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

type managedComfyFixture struct {
	mu            sync.Mutex
	state         string
	checkpointRef string
	authorization string
	idempotency   []string
	starts        int
}

func (f *managedComfyFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if f.authorization != "" && r.Header.Get("Authorization") != f.authorization {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, State: "failed", Error: "unauthorized"})
		return
	}
	if value := r.Header.Get("Idempotency-Key"); value != "" {
		f.idempotency = append(f.idempotency, value)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/object_info":
		_, _ = w.Write([]byte(`{"ChunkedVideo":{"input":{"required":{},"optional":{}},"output":["VIDEO"],"output_name":["video"]},"Video":{"input":{"required":{"ckpt_name":[["video.safetensors"]]},"optional":{}},"output":["VIDEO"],"output_name":["video"]},"LoaderA":{"input":{"required":{"ckpt_name":[["a.safetensors"]]},"optional":{}},"output":["MODEL"],"output_name":["model"]},"LoaderB":{"input":{"required":{"unet_name":[["b.safetensors"]]},"optional":{}},"output":["MODEL"],"output_name":["model"]}}`))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/executions":
		var request managedComfyStartRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || request.ProtocolVersion != managedComfyWireVersion || request.WorkloadID == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, State: "failed", Error: "bad start"})
			return
		}
		f.starts++
		f.state = "running"
		if request.CheckpointRef != "" {
			f.checkpointRef = request.CheckpointRef
		}
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, ExecutionID: "exec-1", State: f.state})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/executions/exec-1":
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, ExecutionID: "exec-1", State: f.state, CheckpointRef: f.checkpointRef, Progress: .5, ProgressStage: "chunk", ProgressCurrent: 1, ProgressTotal: 2, VRAMUsedMB: 4096, Slowdown: 1.1, TemperatureC: 62})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/executions/exec-1/checkpoint":
		f.state, f.checkpointRef = "checkpointed", "checkpoint://exec-1/chunk-1"
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, ExecutionID: "exec-1", State: f.state, CheckpointRef: f.checkpointRef})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/executions/exec-1/yield":
		f.state = "yielded"
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, ExecutionID: "exec-1", State: f.state})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/executions/exec-1/cancel":
		f.state = "cancelled"
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, ExecutionID: "exec-1", State: f.state})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/executions/exec-1/outputs":
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: managedComfyWireVersion, ExecutionID: "exec-1", State: "completed", Output: json.RawMessage(`{"frames":24}`), ArtifactRefs: []string{"artifact-video"}})
	default:
		http.NotFound(w, r)
	}
}

func TestManagedComfyLifecycle(t *testing.T) {
	fixture := &managedComfyFixture{authorization: "Bearer harness-secret"}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	adapter := NewHTTPAdapter("comfy", "comfy", server.Client())
	target := Target{ID: "managed", Adapter: "comfy", Endpoint: server.URL, RuntimeProtocol: managedComfyProtocol, Authorization: fixture.authorization}
	request := domain.WorkloadRequest{ID: "workload-1", IdempotencyKey: "submit-1", Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"ChunkedVideo","inputs":{}}}}`)}
	plan := &domain.ExecutionPlan{PlanHash: "plan-hash", Material: request.Payload}

	handle, err := adapter.Start(context.Background(), request, plan, target)
	if err != nil || handle.ExternalID != "exec-1" {
		t.Fatalf("start failed: handle=%+v err=%v", handle, err)
	}
	observation, err := adapter.Observe(context.Background(), request, plan, handle, target)
	if err != nil || observation.Status != domain.WorkloadRunning || observation.Progress != .5 || observation.VRAMUsedMB != 4096 {
		t.Fatalf("observation lost managed state: %+v err=%v", observation, err)
	}
	checkpoint, err := adapter.Checkpoint(context.Background(), handle, target)
	if err != nil || checkpoint != "checkpoint://exec-1/chunk-1" {
		t.Fatalf("checkpoint was not confirmed: %q err=%v", checkpoint, err)
	}
	resumed, err := adapter.Resume(context.Background(), request, plan, checkpoint, target)
	if err != nil || resumed.ExternalID != "exec-1" {
		t.Fatalf("resume failed: handle=%+v err=%v", resumed, err)
	}
	if err := adapter.Yield(context.Background(), resumed, target); err != nil {
		t.Fatalf("yield failed: %v", err)
	}
	if err := adapter.Cancel(context.Background(), resumed, target); err != nil {
		t.Fatalf("cancel failed: %v", err)
	}
	output, refs, err := adapter.CollectOutputs(context.Background(), request, plan, resumed, target)
	if err != nil || !strings.Contains(string(output), `"frames":24`) || len(refs) != 1 || refs[0] != "artifact-video" {
		t.Fatalf("outputs failed: output=%s refs=%v err=%v", output, refs, err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.starts != 2 || len(fixture.idempotency) < 5 {
		t.Fatalf("idempotent control was not used: starts=%d keys=%v", fixture.starts, fixture.idempotency)
	}
}

func TestManagedComfyRejectsAmbiguousState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(managedComfyState{ProtocolVersion: "managed-comfy/v2", ExecutionID: "exec", State: "running"})
	}))
	defer server.Close()
	adapter := NewHTTPAdapter("comfy", "comfy", server.Client())
	target := Target{ID: "managed", Endpoint: server.URL, RuntimeProtocol: managedComfyProtocol}
	request := domain.WorkloadRequest{ID: "workload", Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"Video","inputs":{}}}}`)}
	if _, err := adapter.Start(context.Background(), request, nil, target); err == nil || !strings.Contains(err.Error(), "protocol mismatch") {
		t.Fatalf("protocol mismatch was accepted: %v", err)
	}
}

func TestTargetSpecificDisruptionSelectsManagedComfy(t *testing.T) {
	fixture := &managedComfyFixture{}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", server.Client()))
	mgr.RegisterTarget(Target{ID: "native", Adapter: "comfy", Endpoint: server.URL, RuntimeProtocol: "native", AcceleratorID: "gpu-native", Models: []string{"video.safetensors"}, Slots: 1, Enabled: true})
	mgr.RegisterTarget(Target{ID: "managed", Adapter: "comfy", Endpoint: server.URL, RuntimeProtocol: managedComfyProtocol, AcceleratorID: "gpu-managed", Models: []string{"video.safetensors"}, Slots: 1, Enabled: true})
	mgr.Start(ctx)
	request := domain.WorkloadRequest{OwnerID: "owner", Adapter: "comfy", Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"Video","inputs":{"ckpt_name":"video.safetensors"}}}}`), Disruption: domain.DisruptionCheckpointable, Recoverable: true}
	row, _, err := mgr.Submit(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	for {
		current, getErr := mgr.Get(waitCtx, row.Request.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.Plan != nil {
			if current.Plan.TargetID != "managed" {
				t.Fatalf("checkpointable request selected incapable target: %+v", current.Plan)
			}
			return
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("managed target was not selected: %+v", current)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRuntimeProtocolChangesPlanHash(t *testing.T) {
	request := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"Video","inputs":{}}}}`)}
	native := &domain.ExecutionPlan{AdapterVersion: "v1", TargetID: "video", RuntimeProtocol: "native", Material: request.Payload}
	managed := &domain.ExecutionPlan{AdapterVersion: "v1", TargetID: "video", RuntimeProtocol: managedComfyProtocol, Material: request.Payload}
	if hashPlan(request, native) == hashPlan(request, managed) {
		t.Fatal("runtime protocol change did not invalidate the execution plan hash")
	}
}

func TestManagedComfyChunksRequireManagedProtocolAndAggregateRequirements(t *testing.T) {
	payload := json.RawMessage(`{"managed_chunks":[{"id":"first","prompt":{"1":{"class_type":"LoaderA","inputs":{"ckpt_name":"a.safetensors"}}}},{"id":"second","prompt":{"2":{"class_type":"LoaderB","inputs":{"unet_name":"b.safetensors"}}}}]}`)
	adapter := NewHTTPAdapter("comfy", "comfy", nil)
	requirements, err := adapter.Requirements(context.Background(), domain.WorkloadRequest{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if requirements.RuntimeProtocol != managedComfyProtocol || strings.Join(requirements.RequiredModels, ",") != "a.safetensors,b.safetensors" || strings.Join(requirements.CustomNodes, ",") != "LoaderA,LoaderB" {
		t.Fatalf("managed chunk requirements were incomplete: %+v", requirements)
	}

	fixture := &managedComfyFixture{}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	mgr.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", server.Client()))
	models := []string{"a.safetensors", "b.safetensors"}
	nodes := []string{"LoaderA", "LoaderB"}
	mgr.RegisterTarget(Target{ID: "native", Adapter: "comfy", Endpoint: server.URL, RuntimeProtocol: "native", AcceleratorID: "gpu-native", Models: models, CustomNodes: nodes, Slots: 1, Enabled: true})
	mgr.RegisterTarget(Target{ID: "managed", Adapter: "comfy", Endpoint: server.URL, RuntimeProtocol: managedComfyProtocol, AcceleratorID: "gpu-managed", Models: models, CustomNodes: nodes, Slots: 1, Enabled: true})
	mgr.Start(ctx)
	row, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "comfy", Payload: payload, Recoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	for {
		current, getErr := mgr.Get(waitCtx, row.Request.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.Plan != nil {
			if current.Plan.TargetID != "managed" || current.Plan.RuntimeProtocol != managedComfyProtocol {
				t.Fatalf("managed chunks escaped to a native runtime: %+v", current.Plan)
			}
			return
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("managed chunks were not placed: %+v", current)
		case <-time.After(10 * time.Millisecond):
		}
	}
}
