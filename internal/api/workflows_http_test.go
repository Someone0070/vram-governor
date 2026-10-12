package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"vram-governor/internal/domain"
	"vram-governor/internal/workflowtpl"
)

const testWorkflow = `{
  "id": "image-test", "version": 1, "title": "Test image", "operation": "image.generate", "profile": "image-test@1",
  "outputs": ["image/png"], "typical_seconds": 20,
  "params": [
    {"name": "prompt", "type": "string", "required": true, "bind": [{"node": "4", "input": "prompt", "format": "l3n0v0, {value}"}]},
    {"name": "negative_prompt", "type": "string", "default": "blurry", "bind": [{"node": "4", "input": "negative_prompt"}]},
    {"name": "width", "type": "integer", "default": 1024, "min": 512, "max": 2048, "multiple_of": 16, "bind": [{"node": "7", "input": "width"}]},
    {"name": "seed", "type": "seed", "bind": [{"node": "8", "input": "seed"}]}
  ],
  "graph": {
    "4": {"class_type": "TextEncodeQwenImage21", "inputs": {"prompt": "", "negative_prompt": ""}},
    "7": {"class_type": "EmptyLatentImage", "inputs": {"width": 1024, "height": 1024, "batch_size": 1}},
    "8": {"class_type": "KSampler", "inputs": {"seed": 1}}
  }
}`

func withTestWorkflow(t *testing.T, srv *Server) {
	t.Helper()
	tpl := &workflowtpl.Template{}
	if err := json.Unmarshal([]byte(testWorkflow), tpl); err != nil {
		t.Fatal(err)
	}
	registry, err := workflowtpl.NewRegistry(tpl)
	if err != nil {
		t.Fatal(err)
	}
	srv.cfg.WorkflowTemplates = registry
}

func TestWorkflowDiscoveryHidesGraphAndBindings(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	withTestWorkflow(t, srv)
	for _, path := range []string{"/api/v1/workflows", "/api/v1/workflows/image-test", "/api/v1/workflows/image-test@1", "/api/v1/capabilities"} {
		response := request(t, srv.Handler(), http.MethodGet, path, "alice-token", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		body := response.Body.String()
		if !strings.Contains(body, `"image-test@1"`) || !strings.Contains(body, `"negative_prompt"`) || !strings.Contains(body, `"multiple_of":16`) {
			t.Fatalf("%s missing workflow detail: %s", path, body)
		}
		for _, private := range []string{"KSampler", `"bind"`, `"node"`, "l3n0v0"} {
			if strings.Contains(body, private) {
				t.Fatalf("%s leaked %s: %s", path, private, body)
			}
		}
	}
	if response := request(t, srv.Handler(), http.MethodGet, "/api/v1/workflows/nope", "alice-token", nil); response.Code != http.StatusNotFound {
		t.Fatalf("unknown workflow status=%d", response.Code)
	}
}

func TestWorkflowSubmissionCompilesParams(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	withTestWorkflow(t, srv)
	registerCreatorProfile(manager, "worker-a", "image-test", "1", "digest-1", []string{"image.generate"}, nil, true)

	response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", map[string]any{
		"workload_id": "wf-1", "workflow": "image-test", "params": map[string]any{"prompt": "a cat", "width": 1280, "seed": 42},
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("submit status=%d body=%s", response.Code, response.Body.String())
	}
	var created creatorWorkloadResponse
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Operation != "image.generate" || created.Workflow == nil || created.Workflow.Ref != "image-test@1" {
		t.Fatalf("response = %+v", created)
	}
	if created.Workflow.Params["negative_prompt"] != "blurry" || created.Workflow.Params["seed"] != float64(42) {
		t.Fatalf("echoed params = %v", created.Workflow.Params)
	}
	row, err := manager.Get(context.Background(), "wf-1")
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ManagedChunks []struct {
			ID     string                     `json:"id"`
			Prompt map[string]json.RawMessage `json:"prompt"`
		} `json:"managed_chunks"`
	}
	if err := json.Unmarshal(row.Request.Payload, &payload); err != nil || len(payload.ManagedChunks) != 1 || payload.ManagedChunks[0].ID != "wf-1" {
		t.Fatalf("payload = %s", row.Request.Payload)
	}
	graph := string(row.Request.Payload)
	for _, want := range []string{`"l3n0v0, a cat"`, `"width":1280`, `"seed":42`} {
		if !strings.Contains(graph, want) {
			t.Fatalf("compiled graph lacks %s: %s", want, graph)
		}
	}
	if row.Request.ProfilePreferences.Preferred[0] != "image-test@1" {
		t.Fatalf("profile preference = %+v", row.Request.ProfilePreferences)
	}
	polled := waitCreatorWorkload(t, srv, "alice-token", "wf-1", "succeeded", "queued", "running")
	if polled.Workflow == nil || polled.Workflow.Params["prompt"] != "a cat" {
		t.Fatalf("poll lost workflow echo: %+v", polled)
	}
}

func TestWorkflowSubmissionRejectsBadRequests(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	withTestWorkflow(t, srv)
	registerCreatorProfile(manager, "worker-a", "image-test", "1", "digest-1", []string{"image.generate"}, nil, true)
	cases := map[string]map[string]any{
		"bad params":       {"workload_id": "x1", "workflow": "image-test", "params": map[string]any{"width": 1000, "colour": "red"}},
		"unknown workflow": {"workload_id": "x2", "workflow": "nope", "params": map[string]any{"prompt": "a"}},
		"wrong operation":  {"workload_id": "x3", "workflow": "image-test", "operation": "video.generate_sequence", "params": map[string]any{"prompt": "a"}},
		"payload too":      {"workload_id": "x4", "workflow": "image-test", "params": map[string]any{"prompt": "a"}, "payload": map[string]any{"prompt": map[string]any{}}},
		"params alone":     {"workload_id": "x5", "operation": "image.generate", "params": map[string]any{"prompt": "a"}},
		"other profile":    {"workload_id": "x6", "workflow": "image-test", "params": map[string]any{"prompt": "a"}, "profile_preferences": map[string]any{"preferred": []string{"video_main@1"}}},
	}
	for name, body := range cases {
		response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", body)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
	response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", cases["bad params"])
	for _, want := range []string{"prompt is required", "width must be a multiple of 16", "colour is not a parameter"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("error lacks %q: %s", want, response.Body.String())
		}
	}
}

func TestWorkflowTemplatesMustMatchAConfiguredProfile(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	withTestWorkflow(t, srv)
	registry := srv.cfg.WorkflowTemplates
	target := func(ops ...string) []WorkloadTargetConfig {
		return []WorkloadTargetConfig{{ID: "comfy", Profiles: []domain.RuntimeProfile{{ProfileID: "image-test", Version: "1", Operations: ops}}}}
	}
	if err := validateWorkflowTemplates(registry, target("image.generate")); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkflowTemplates(registry, target("video.generate_sequence")); err == nil {
		t.Fatal("operation mismatch accepted")
	}
	if err := validateWorkflowTemplates(registry, nil); err == nil {
		t.Fatal("missing profile accepted")
	}
}
