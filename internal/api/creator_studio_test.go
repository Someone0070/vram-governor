package api

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

func registerCreatorProfile(manager *workloads.Manager, targetID, profileID, version, digest string, operations, features []string, enabled bool) {
	manager.RegisterTarget(workloads.Target{
		ID: targetID, Adapter: "mock", Endpoint: "in-process", Enabled: enabled, Slots: 1,
		Profiles: []domain.RuntimeProfile{{ProfileID: profileID, Version: version, Digest: digest, Operations: operations, Features: features, Model: profileID}},
	})
}

func waitCreatorWorkload(t *testing.T, srv *Server, token, id string, wanted ...string) creatorWorkloadResponse {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	var last creatorWorkloadResponse
	for time.Now().Before(deadline) {
		response := request(t, srv.Handler(), http.MethodGet, "/api/v1/workloads/"+id, token, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("poll %s status=%d body=%s", id, response.Code, response.Body.String())
		}
		var row creatorWorkloadResponse
		if err := json.Unmarshal(response.Body.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		last = row
		for _, state := range wanted {
			if row.Status == state {
				return row
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("workload %s did not reach %v; last=%+v", id, wanted, last)
	return creatorWorkloadResponse{}
}

func creatorSubmission(profile, operation string) map[string]any {
	return map[string]any{
		"workload_id": "studio-123", "idempotency_key": "studio-123-v1", "operation": operation,
		"quality_class": "final", "requirements": map[string]any{"features": []string{"multi_reference", "camera_control"}},
		"profile_preferences": map[string]any{"preferred": []string{profile}, "fallback_policy": "equivalent_or_better_only"},
		"inputs":              map[string]any{"artifact_refs": []string{}}, "priority": "production", "latency_class": "batch",
		"parallelism": map[string]any{"parallelizable": false},
	}
}

func TestCreatorStudioCapabilities(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	registerCreatorProfile(manager, "private-worker-a", "video_main", "17", "immutable-profile-digest-17", []string{"video.generate_sequence", "video.continue_sequence"}, []string{"multi_reference", "camera_control", "native_continuation"}, true)

	response := request(t, srv.Handler(), http.MethodGet, "/api/v1/capabilities", "alice-token", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, forbidden := range []string{"private-worker-a", "target_id", "accelerator_id", "endpoint", "vram", "gpu", "resident_models"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("hardware/private placement leaked through capabilities: %q in %s", forbidden, body)
		}
	}
	var envelope struct {
		Profiles []domain.RuntimeProfile `json:"profiles"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	var found *domain.RuntimeProfile
	for index := range envelope.Profiles {
		if envelope.Profiles[index].ProfileID == "video_main" {
			found = &envelope.Profiles[index]
		}
	}
	if found == nil || found.Version != "17" || found.Digest != "immutable-profile-digest-17" || found.Status != workloads.ProfileAvailable {
		t.Fatalf("logical profile missing or mutated: %+v", found)
	}
	if found.CapabilityRevision == "" || found.CapabilityDefinitionHash == "" || found.Modality != domain.ModalityVideo || found.ExecutionLocality != domain.ExecutionLocalityLBManaged || len(found.InputSchema) == 0 || len(found.OutputSchema) == 0 || len(found.AcceptedArtifactTypes) == 0 || len(found.ProducedArtifactTypes) == 0 || found.Availability == nil {
		t.Fatalf("execution implementation contract incomplete: %+v", found)
	}
	definitionHash := found.CapabilityDefinitionHash
	registerCreatorProfile(manager, "private-worker-a", "video_main", "17", "immutable-profile-digest-17", []string{"video.generate_sequence", "video.continue_sequence"}, []string{"multi_reference", "camera_control", "native_continuation"}, false)
	offline := request(t, srv.Handler(), http.MethodGet, "/api/v1/capabilities", "alice-token", nil)
	if offline.Code != http.StatusOK || !strings.Contains(offline.Body.String(), `"status":"offline"`) || !strings.Contains(offline.Body.String(), definitionHash) {
		t.Fatalf("availability mutated immutable definition: %s", offline.Body.String())
	}
	manager.RegisterTarget(workloads.Target{ID: "component-catalog", Adapter: "mock", Models: []string{"vae.safetensors", "text_encoder.safetensors"}, Enabled: true})
	components := request(t, srv.Handler(), http.MethodGet, "/api/v1/capabilities", "alice-token", nil)
	if strings.Contains(components.Body.String(), "vae.safetensors") || strings.Contains(components.Body.String(), "text_encoder.safetensors") {
		t.Fatalf("component inventory was exposed as runnable workflow: %s", components.Body.String())
	}
	manager.RegisterTarget(workloads.Target{ID: "hosted-director", Adapter: "mock", Cloud: true, Enabled: true, Profiles: []domain.RuntimeProfile{{ProfileID: "director_hosted", Version: "1", Digest: "director-hosted-digest", Operations: []string{"llm.inference"}}}})
	hosted := request(t, srv.Handler(), http.MethodGet, "/api/v1/capabilities", "alice-token", nil)
	if !strings.Contains(hosted.Body.String(), `"execution_locality":"HOSTED"`) {
		t.Fatalf("hosted implementation locality missing: %s", hosted.Body.String())
	}
	if strings.Contains(strings.ToLower(hosted.Body.String()), "calibration_status") {
		t.Fatalf("LB creative calibration leaked into capability contract: %s", hosted.Body.String())
	}

	backing := store.NewMemoryStore()
	original := &domain.RuntimeProfile{ProfileID: "immutable", Version: "1", Digest: "digest-a", Adapter: "mock", Operations: []string{"image.generate"}}
	if _, created, err := backing.UpsertRuntimeProfile(context.Background(), original); err != nil || !created {
		t.Fatalf("initial immutable profile insert: created=%v err=%v", created, err)
	}
	changed := *original
	changed.Digest = "digest-b"
	if _, _, err := backing.UpsertRuntimeProfile(context.Background(), &changed); err == nil {
		t.Fatal("same profile_id + version silently accepted a changed digest")
	}
}

func TestCreatorAsyncLLMOutputs(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "completion-1", "choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "director answer"}}}, "usage": map[string]any{"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}})
	}))
	defer backend.Close()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	manager.RegisterTarget(workloads.Target{ID: "local-director-route", Adapter: "llamacpp", Endpoint: backend.URL, Models: []string{"local-director-model"}, ResidentModels: []string{"local-director-model"}, Enabled: true, Slots: 1, Profiles: []domain.RuntimeProfile{{ProfileID: "director_local", Version: "3", Digest: "director-local-digest", Model: "local-director-model", Operations: []string{"llm.inference"}}}})
	body := map[string]any{"workload_id": "director-turn-local", "idempotency_key": "director-turn-local-v1", "operation": "llm.inference", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"director_local@3"}, "fallback_policy": "preferred_only"}, "payload": map[string]any{"model": "local-director-model", "messages": []any{map[string]any{"role": "user", "content": "hello"}}}}
	created := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("local async submit status=%d body=%s", created.Code, created.Body.String())
	}
	completed := waitCreatorWorkload(t, srv, "alice-token", "director-turn-local", "completed")
	if len(completed.Outputs) != 1 || completed.Outputs[0].MediaType != "application/vnd.creator-studio.agent-result+json" || completed.Outputs[0].Producer == nil || completed.Outputs[0].Producer.ProfileDigest != "director-local-digest" {
		t.Fatalf("local async result is not a provenance artifact: %+v", completed)
	}
	artifactID := stripArtifactScheme(completed.Outputs[0].ArtifactRef)
	metadata := request(t, srv.Handler(), http.MethodGet, "/api/v1/artifacts/"+artifactID, "alice-token", nil)
	if metadata.Code != http.StatusOK || !strings.Contains(metadata.Body.String(), `"profile_id":"director_local"`) || strings.Contains(metadata.Body.String(), "storage_ref") {
		t.Fatalf("artifact metadata status=%d body=%s", metadata.Code, metadata.Body.String())
	}
	content := request(t, srv.Handler(), http.MethodGet, "/api/v1/artifacts/"+artifactID+"/content", "alice-token", nil)
	if content.Code != http.StatusOK || !strings.Contains(content.Body.String(), "director answer") {
		t.Fatalf("artifact content status=%d body=%s", content.Code, content.Body.String())
	}
	replay := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", body)
	var replayed creatorWorkloadResponse
	_ = json.Unmarshal(replay.Body.Bytes(), &replayed)
	if replay.Code != http.StatusAccepted || len(replayed.Outputs) != 1 || replayed.Outputs[0].ArtifactRef != completed.Outputs[0].ArtifactRef {
		t.Fatalf("idempotent replay changed logical output: status=%d body=%s", replay.Code, replay.Body.String())
	}

	manager.RegisterAdapter(workloads.NewHTTPAdapter("openrouter", "openrouter", backend.Client()))
	manager.RegisterTarget(workloads.Target{ID: "hosted-director-route", Adapter: "openrouter", Endpoint: backend.URL, Models: []string{"hosted-director-model"}, Cloud: true, Enabled: true, Slots: 1, Profiles: []domain.RuntimeProfile{{ProfileID: "director_hosted", Version: "4", Digest: "director-hosted-digest", Model: "hosted-director-model", Operations: []string{"llm.inference"}}}})
	hostedBody := map[string]any{"workload_id": "director-turn-hosted", "operation": "llm.inference", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"director_hosted@4"}, "fallback_policy": "preferred_only"}, "payload": map[string]any{"model": "hosted-director-model", "messages": []any{map[string]any{"role": "user", "content": "hello hosted"}}}, "egress": "cloud_allowed"}
	hostedCreated := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "hosted-token", hostedBody)
	if hostedCreated.Code != http.StatusCreated {
		t.Fatalf("hosted async submit status=%d body=%s", hostedCreated.Code, hostedCreated.Body.String())
	}
	hostedCompleted := waitCreatorWorkload(t, srv, "hosted-token", "director-turn-hosted", "completed")
	if len(hostedCompleted.Outputs) != 1 || hostedCompleted.Outputs[0].MediaType != completed.Outputs[0].MediaType || hostedCompleted.Outputs[0].Producer == nil || hostedCompleted.Outputs[0].Producer.ProfileID != "director_hosted" {
		t.Fatalf("hosted result shape diverged from local result: %+v", hostedCompleted)
	}
}

func TestCreatorArtifactCompatibilityAndUpload(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	manager.RegisterTarget(workloads.Target{ID: "video-route", Adapter: "mock", Enabled: true, Slots: 1, Profiles: []domain.RuntimeProfile{{ProfileID: "video_impl", Version: "8", Digest: "video-digest", Operations: []string{"video.generate", "video.continue_sequence", "video.retake_region"}, AcceptedArtifactTypes: []string{"application/json", "video/*"}, ProducedArtifactTypes: []string{"video/mp4", "application/json"}, CompatibilityOperations: []string{"video.continue_sequence", "video.retake_region"}}}})
	generate := map[string]any{"workload_id": "video-source", "operation": "video.generate", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"video_impl@8"}, "fallback_policy": "preferred_only"}, "payload": map[string]any{"prompt": "source"}}
	if response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", generate); response.Code != http.StatusCreated {
		t.Fatalf("source submit status=%d body=%s", response.Code, response.Body.String())
	}
	source := waitCreatorWorkload(t, srv, "alice-token", "video-source", "completed")
	if len(source.Outputs) != 1 || source.Outputs[0].Compatibility == nil {
		t.Fatalf("source compatibility metadata missing: %+v", source)
	}
	token := source.Outputs[0].Compatibility.Tokens["video.continue_sequence"]
	compatible := map[string]any{"workload_id": "video-continuation", "operation": "video.continue_sequence", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"video_impl@8"}, "fallback_policy": "preferred_only"}, "artifact_refs": []string{source.Outputs[0].ArtifactRef}, "continuation_ref": token, "payload": map[string]any{"prompt": "continue"}}
	if response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", compatible); response.Code != http.StatusCreated {
		t.Fatalf("compatible continuation rejected status=%d body=%s", response.Code, response.Body.String())
	}

	manager.RegisterTarget(workloads.Target{ID: "other-video-route", Adapter: "mock", Enabled: true, Slots: 1, Profiles: []domain.RuntimeProfile{{ProfileID: "other_video_impl", Version: "1", Digest: "other-video-digest", Operations: []string{"video.continue_sequence"}, AcceptedArtifactTypes: []string{"application/json"}, ProducedArtifactTypes: []string{"video/mp4"}, CompatibilityOperations: []string{"video.continue_sequence"}}}})
	incompatible := compatible
	incompatible["workload_id"] = "video-incompatible"
	incompatible["profile_preferences"] = map[string]any{"preferred": []string{"other_video_impl@1"}, "fallback_policy": "preferred_only"}
	rejected := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", incompatible)
	if rejected.Code != http.StatusUnprocessableEntity || !strings.Contains(rejected.Body.String(), "SOURCE_ARTIFACT_INCOMPATIBLE") {
		t.Fatalf("incompatible implementation accepted status=%d body=%s", rejected.Code, rejected.Body.String())
	}

	var upload bytes.Buffer
	writer := multipart.NewWriter(&upload)
	headers := make(textproto.MIMEHeader)
	headers.Set("Content-Disposition", `form-data; name="file"; filename="video_impl-compatible-name.mp4"`)
	headers.Set("Content-Type", "video/mp4")
	part, _ := writer.CreatePart(headers)
	_, _ = part.Write([]byte("not compatibility metadata"))
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts", &upload)
	req.Header.Set("Authorization", "Bearer alice-token")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), "artifact://") {
		t.Fatalf("generic upload status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var uploaded creatorArtifactResponse
	_ = json.Unmarshal(recorder.Body.Bytes(), &uploaded)
	foreignRead := request(t, srv.Handler(), http.MethodGet, "/api/v1/artifacts/"+uploaded.ArtifactID, "bob-token", nil)
	if foreignRead.Code != http.StatusNotFound {
		t.Fatalf("another owner read uploaded artifact status=%d body=%s", foreignRead.Code, foreignRead.Body.String())
	}
	incompatible["workload_id"] = "filename-is-not-compatibility"
	incompatible["profile_preferences"] = map[string]any{"preferred": []string{"video_impl@8"}, "fallback_policy": "preferred_only"}
	incompatible["artifact_refs"] = []string{uploaded.ArtifactRef}
	filenameRejected := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", incompatible)
	if filenameRejected.Code != http.StatusUnprocessableEntity || !strings.Contains(filenameRejected.Body.String(), "SOURCE_ARTIFACT_INCOMPATIBLE") {
		t.Fatalf("filename established compatibility status=%d body=%s", filenameRejected.Code, filenameRejected.Body.String())
	}
}

func TestCreatorBlockingReasons(t *testing.T) {
	t.Run("missing implementation and expired deadline", func(t *testing.T) {
		srv, _, cancel := testServer(t)
		defer cancel()
		missing := map[string]any{"workload_id": "missing-implementation", "operation": "video.generate", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"absent@1"}, "fallback_policy": "preferred_only"}, "payload": map[string]any{}}
		response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", missing)
		if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "CAPABILITY_UNAVAILABLE") {
			t.Fatalf("missing implementation reason status=%d body=%s", response.Code, response.Body.String())
		}
		registerCreatorProfile(srv.workloads, "deadline-route", "deadline_impl", "1", "deadline-digest", []string{"image.generate"}, nil, true)
		expired := map[string]any{"workload_id": "expired", "operation": "image.generate", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"deadline_impl@1"}, "fallback_policy": "preferred_only"}, "deadline": time.Now().Add(-time.Second), "payload": map[string]any{}}
		response = request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", expired)
		if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "DEADLINE_EXPIRED") {
			t.Fatalf("expired deadline reason status=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("capacity unavailable", func(t *testing.T) {
		srv, manager, cancel := testServer(t)
		defer cancel()
		registerCreatorProfile(manager, "offline-route", "offline_impl", "1", "offline-digest", []string{"image.generate"}, nil, false)
		body := map[string]any{"workload_id": "offline-work", "operation": "image.generate", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"offline_impl@1"}, "fallback_policy": "preferred_only"}, "payload": map[string]any{}}
		created := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", body)
		if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), "CAPACITY_UNAVAILABLE") {
			t.Fatalf("offline capacity reason status=%d body=%s", created.Code, created.Body.String())
		}
	})

	t.Run("temporarily busy and no feasible route", func(t *testing.T) {
		srv, manager, cancel := testServer(t)
		defer cancel()
		delayed := workloads.NewMockAdapter()
		delayed.Delay = 700 * time.Millisecond
		manager.RegisterAdapter(delayed)
		registerCreatorProfile(manager, "busy-route", "busy_impl", "1", "busy-digest", []string{"image.generate"}, nil, true)
		item := func(id string) map[string]any {
			return map[string]any{"workload_id": id, "operation": "image.generate", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"busy_impl@1"}, "fallback_policy": "preferred_only"}, "payload": map[string]any{}}
		}
		if response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", item("busy-a")); response.Code != http.StatusCreated {
			t.Fatalf("first busy submit status=%d body=%s", response.Code, response.Body.String())
		}
		_ = waitCreatorWorkload(t, srv, "alice-token", "busy-a", "preparing", "running")
		if response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", item("busy-b")); response.Code != http.StatusCreated {
			t.Fatalf("second busy submit status=%d body=%s", response.Code, response.Body.String())
		}
		deadline := time.Now().Add(2 * time.Second)
		busyObserved := false
		for time.Now().Before(deadline) {
			poll := request(t, srv.Handler(), http.MethodGet, "/api/v1/workloads/busy-b", "alice-token", nil)
			var row creatorWorkloadResponse
			_ = json.Unmarshal(poll.Body.Bytes(), &row)
			if row.Reason == "TEMPORARILY_BUSY" {
				busyObserved = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !busyObserved {
			t.Fatal("busy route never reported TEMPORARILY_BUSY")
		}

		manager.RegisterTarget(workloads.Target{ID: "cloud-only-route", Adapter: "mock", Cloud: true, Enabled: true, Slots: 1, Profiles: []domain.RuntimeProfile{{ProfileID: "cloud_only", Version: "1", Digest: "cloud-only-digest", Operations: []string{"llm.inference"}}}})
		cloud := map[string]any{"workload_id": "local-policy-cloud-route", "operation": "llm.inference", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"cloud_only@1"}, "fallback_policy": "preferred_only"}, "payload": map[string]any{"messages": []any{map[string]any{"role": "user", "content": "hello"}}}}
		if response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", cloud); response.Code != http.StatusCreated {
			t.Fatalf("cloud-route submit status=%d body=%s", response.Code, response.Body.String())
		}
		blocked := waitCreatorWorkload(t, srv, "alice-token", "local-policy-cloud-route", "blocked")
		if blocked.Reason != "NO_FEASIBLE_ROUTE" {
			t.Fatalf("egress-ineligible route reason=%s row=%+v", blocked.Reason, blocked)
		}
	})

	t.Run("approval required", func(t *testing.T) {
		srv, _, cancel := testServer(t)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/workloads/approval", nil)
		row := &domain.Workload{Request: domain.WorkloadRequest{ID: "approval", Operation: "image.generate"}, Status: domain.WorkloadPendingApproval, Decision: domain.AdmissionDecision{Blocker: "transformation approval required for exact plan hash"}}
		if response := srv.creatorResponse(req, row); response.Status != "blocked" || response.Reason != "APPROVAL_REQUIRED" {
			t.Fatalf("approval reason mapping failed: %+v", response)
		}
	})
}

func TestCreatorBatchPartialAcceptance(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	registerCreatorProfile(manager, "batch-route", "batch_impl", "1", "batch-digest", []string{"image.generate"}, nil, true)
	item := func(id, profile string) map[string]any {
		return map[string]any{"workload_id": id, "idempotency_key": id + "-key", "operation": "image.generate", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{profile}, "fallback_policy": "preferred_only"}, "payload": map[string]any{}}
	}
	batch := map[string]any{"batch_id": "partial-batch", "ordered": false, "parallelizable": true, "items": []any{item("accepted-item", "batch_impl@1"), item("rejected-item", "missing@1")}}
	response := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads/batch", "alice-token", batch)
	if response.Code != http.StatusMultiStatus || !strings.Contains(response.Body.String(), `"workload_id":"accepted-item"`) || !strings.Contains(response.Body.String(), `"workload_id":"rejected-item"`) || !strings.Contains(response.Body.String(), "CAPABILITY_UNAVAILABLE") {
		t.Fatalf("partial batch response status=%d body=%s", response.Code, response.Body.String())
	}
	replay := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads/batch", "alice-token", batch)
	if replay.Code != http.StatusMultiStatus || !strings.Contains(replay.Body.String(), `"workload_id":"accepted-item"`) {
		t.Fatalf("partial batch replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	rows, _ := manager.List(context.Background())
	count := 0
	for _, row := range rows {
		if row.Request.ID == "accepted-item" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("partial batch idempotent replay created %d accepted workloads", count)
	}
}

func TestCreatorStudioWorkloads(t *testing.T) {
	t.Run("hardware-neutral submission and no silent downgrade", func(t *testing.T) {
		srv, manager, cancel := testServer(t)
		defer cancel()
		registerCreatorProfile(manager, "secret-gpu-route", "video_main", "17", "digest-17", []string{"video.generate_sequence"}, []string{"multi_reference", "camera_control"}, true)
		registerCreatorProfile(manager, "worse-route", "video_preview", "2", "digest-preview", []string{"video.generate_sequence"}, []string{"camera_control"}, true)

		created := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", creatorSubmission("video_main@17", "video.generate_sequence"))
		if created.Code != http.StatusCreated {
			t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
		}
		if strings.Contains(created.Body.String(), "secret-gpu-route") || strings.Contains(created.Body.String(), "accelerator_id") || strings.Contains(created.Body.String(), "target_id") {
			t.Fatalf("placement leaked in Creator Studio response: %s", created.Body.String())
		}
		var public creatorWorkloadResponse
		if err := json.Unmarshal(created.Body.Bytes(), &public); err != nil {
			t.Fatal(err)
		}
		if public.WorkloadID != "studio-123" || public.Operation != "video.generate_sequence" {
			t.Fatalf("unexpected public response: %+v", public)
		}

		duplicate := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", creatorSubmission("video_main@17", "video.generate_sequence"))
		if duplicate.Code != http.StatusAccepted {
			t.Fatalf("idempotent retry status=%d body=%s", duplicate.Code, duplicate.Body.String())
		}
		rows, _ := manager.List(context.Background())
		count := 0
		for _, row := range rows {
			if row.Request.ID == "studio-123" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("idempotent retry created %d workloads", count)
		}

		blockedBody := creatorSubmission("video_preview@2", "video.generate_sequence")
		blockedBody["workload_id"], blockedBody["idempotency_key"] = "studio-blocked", "studio-blocked-v1"
		blocked := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", blockedBody)
		if blocked.Code != http.StatusUnprocessableEntity || !strings.Contains(blocked.Body.String(), "CAPABILITY_UNAVAILABLE") {
			t.Fatalf("required features were silently downgraded: status=%d body=%s", blocked.Code, blocked.Body.String())
		}
	})

	t.Run("ordered batch dependencies and accepted creative output", func(t *testing.T) {
		srv, manager, cancel := testServer(t)
		defer cancel()
		registerCreatorProfile(manager, "render-route", "image_main", "4", "image-digest", []string{"image.generate"}, nil, true)
		item := func(id string, payload map[string]any) map[string]any {
			return map[string]any{"workload_id": id, "operation": "image.generate", "quality_class": "final", "profile_preferences": map[string]any{"preferred": []string{"image_main@4"}, "fallback_policy": "preferred_only"}, "payload": payload, "priority": "production", "latency_class": "batch"}
		}
		batch := map[string]any{"batch_id": "episode-assets", "affinity_key": "episode-14", "ordered": true, "parallelizable": false, "items": []any{item("asset-a", map[string]any{"creative_quality": "accepted"}), item("asset-b", map[string]any{"creative_quality": "bad_motion_but_valid_media"})}}
		created := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads/batch", "alice-token", batch)
		if created.Code != http.StatusCreated {
			t.Fatalf("batch status=%d body=%s", created.Code, created.Body.String())
		}
		rows, _ := manager.List(context.Background())
		var second *domain.Workload
		for _, row := range rows {
			if row.Request.ID == "asset-b" {
				second = row
			}
		}
		if second == nil || len(second.Request.Dependencies) != 1 || second.Request.Dependencies[0] != "asset-a" || second.Request.AffinityKey != "episode-14" {
			t.Fatalf("ordered batch semantics lost: %+v", second)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			row, _ := manager.Get(context.Background(), "asset-b")
			if row != nil && row.Status == domain.WorkloadSucceeded {
				if row.ExecutionAttempts != 1 {
					t.Fatalf("creative-quality metadata triggered infrastructure retries: attempts=%d", row.ExecutionAttempts)
				}
				batchStatus := request(t, srv.Handler(), http.MethodGet, "/api/v1/batches/episode-assets", "alice-token", nil)
				if batchStatus.Code != http.StatusOK || !strings.Contains(batchStatus.Body.String(), `"items_complete":2`) || strings.Contains(batchStatus.Body.String(), "target_id") {
					t.Fatalf("batch progress was incomplete or leaked placement: status=%d body=%s", batchStatus.Code, batchStatus.Body.String())
				}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("ordered dependent item did not complete")
	})

	t.Run("offline profile becomes runnable when capacity appears", func(t *testing.T) {
		srv, manager, cancel := testServer(t)
		defer cancel()
		registerCreatorProfile(manager, "rental-route", "rental_video", "1", "rental-digest", []string{"video.generate"}, nil, false)
		body := creatorSubmission("rental_video@1", "video.generate")
		body["requirements"] = map[string]any{"features": []string{}}
		body["workload_id"], body["idempotency_key"] = "rental-pending", "rental-pending-v1"
		created := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", body)
		if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"status":"blocked"`) || !strings.Contains(created.Body.String(), "CAPACITY_UNAVAILABLE") {
			t.Fatalf("offline capability did not produce abstract blocked state: status=%d body=%s", created.Code, created.Body.String())
		}
		registerCreatorProfile(manager, "rental-route", "rental_video", "1", "rental-digest", []string{"video.generate"}, nil, true)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			row, _ := manager.Get(context.Background(), "rental-pending")
			if row != nil && row.Status == domain.WorkloadSucceeded {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("pending workload did not late-bind after compatible capacity appeared")
	})
}

func TestCreatorStudioWorkingSet(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	registerCreatorProfile(manager, "image-route", "show_image", "9", "show-image-digest", []string{"image.generate", "image.edit"}, []string{"multi_reference"}, true)
	workingSet := map[string]any{"phase_type": "image_refinement", "affinity_key": "greep_design_session", "desired_profiles": []string{"show_image@9"}, "likely_next_profiles": []string{"show_image@9"}, "unlikely_profiles": []string{}}
	created := request(t, srv.Handler(), http.MethodPut, "/api/v1/sessions/show-14/working-set/greep-refinement", "alice-token", workingSet)
	if created.Code != http.StatusOK {
		t.Fatalf("working-set create status=%d body=%s", created.Code, created.Body.String())
	}
	for _, forbidden := range []string{"gpu", "target_id", "accelerator_id", "residency", "worker_address"} {
		if strings.Contains(strings.ToLower(created.Body.String()), forbidden) {
			t.Fatalf("working-set response leaked control detail %q: %s", forbidden, created.Body.String())
		}
	}
	listed := request(t, srv.Handler(), http.MethodGet, "/api/v1/sessions/show-14/working-set", "alice-token", nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "greep-refinement") {
		t.Fatalf("working-set list status=%d body=%s", listed.Code, listed.Body.String())
	}
	released := request(t, srv.Handler(), http.MethodDelete, "/api/v1/sessions/show-14/working-set/greep-refinement", "alice-token", nil)
	if released.Code != http.StatusOK || !strings.Contains(released.Body.String(), "released_at") {
		t.Fatalf("working-set release status=%d body=%s", released.Code, released.Body.String())
	}
	listed = request(t, srv.Handler(), http.MethodGet, "/api/v1/sessions/show-14/working-set", "alice-token", nil)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "greep-refinement") {
		t.Fatalf("released phase remained active: %s", listed.Body.String())
	}

	directHardware := map[string]any{"session_id": "show-14", "phase_id": "bad", "desired_profiles": []string{"show_image@9"}, "gpu_id": "must-be-rejected"}
	bad := request(t, srv.Handler(), http.MethodPost, "/api/v1/working-set", "alice-token", directHardware)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "gpu_id") {
		t.Fatalf("direct hardware control field was accepted: status=%d body=%s", bad.Code, bad.Body.String())
	}
	invalid := map[string]any{"session_id": "show-14", "phase_id": "bad", "desired_profiles": []string{"show_image"}}
	bad = request(t, srv.Handler(), http.MethodPost, "/api/v1/working-set", "alice-token", invalid)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "@version") {
		t.Fatalf("mutable working-set profile identity was accepted: status=%d body=%s", bad.Code, bad.Body.String())
	}
}

func TestCreatorBlockingReasonReportsGPUContentionAsTemporarilyBusy(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workloads/x", nil)
	for _, blocker := range []string{
		"cmp170-node-cmp170-llm: accelerator is busy and newcomer policy does not allow sharing",
		"cmp170-video-managed: accelerator is busy; higher-priority work is waiting for it",
		"cmp170-video-managed: all execution slots are busy",
		"cmp170-video-managed: accelerator residency transition in progress",
	} {
		row := &domain.Workload{Decision: domain.AdmissionDecision{Blocker: blocker}}
		if got := (&Server{}).creatorBlockingReason(request, row); got != "TEMPORARILY_BUSY" {
			t.Fatalf("%q classified as %s", blocker, got)
		}
	}
}
