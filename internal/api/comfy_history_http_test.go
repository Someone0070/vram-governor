package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

func comfyHistoryRow(t *testing.T, srv *Server, owner, publicID, status, payload, output, executionID string, runtimeProtocol ...string) {
	t.Helper()
	plan := &domain.ExecutionPlan{TargetID: "target-a"}
	if len(runtimeProtocol) > 0 {
		plan.RuntimeProtocol = runtimeProtocol[0]
	}
	row, _, err := srv.workloadStore.CreateWorkload(context.Background(), &domain.Workload{
		Request: domain.WorkloadRequest{ID: "work-" + publicID, OwnerID: owner, Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: publicID, Payload: []byte(payload)},
		Status: domain.WorkloadStatus(status), InlineOutput: []byte(output),
		Plan: plan,
		Execution: &domain.ExecutionHandle{ExternalID: executionID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Request.ItemID != publicID {
		t.Fatalf("stored public prompt id %q, want %q", row.Request.ItemID, publicID)
	}
	if err := srv.workloadStore.SavePromptMapping(context.Background(), &domain.PromptMapping{PublicPromptID: publicID, WorkloadID: row.Request.ID, TargetID: "target-a", BackendPromptID: executionID}); err != nil {
		t.Fatal(err)
	}
}

func comfyHistoryRecord(backendID, output string) string {
	return `{"` + backendID + `":{"prompt":[7,"` + backendID + `",{"1":{"class_type":"SaveImage"}},{"client_id":"private-client"}],"outputs":{"9":{"images":[{"filename":"` + output + `","subfolder":"","type":"output"}]}},"status":{"status_str":"success","completed":true}}}`
}

func comfyHistoryRequest(t *testing.T, srv *Server, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	srv.mux.ServeHTTP(response, req)
	return response
}

func assertComfySingleRecord(t *testing.T, response *httptest.ResponseRecorder, publicID string, originalTuple []string, forbidden ...string) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", response.Code, response.Body.String())
	}
	var history map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil || len(history) != 1 {
		t.Fatalf("history is not an exact one-key object: keys=%d err=%v body=%s", len(history), err, response.Body.String())
	}
	publicValue, ok := history[publicID]
	if !ok {
		t.Fatalf("history key is not public id %q: %s", publicID, response.Body.String())
	}
	for _, privateID := range forbidden {
		if privateID != "" && strings.Contains(response.Body.String(), privateID) {
			t.Fatalf("private execution identifier %q leaked: %s", privateID, response.Body.String())
		}
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(publicValue, &record); err != nil || record == nil {
		t.Fatalf("public history value is not a record: err=%v value=%s", err, publicValue)
	}
	var outputs map[string]json.RawMessage
	if err := json.Unmarshal(record["outputs"], &outputs); err != nil || outputs == nil {
		t.Fatalf("public record omitted outputs object: err=%v value=%s", err, record["outputs"])
	}
	var status struct {
		StatusStr string `json:"status_str"`
		Completed bool   `json:"completed"`
	}
	if err := json.Unmarshal(record["status"], &status); err != nil || status.StatusStr != "success" || !status.Completed {
		t.Fatalf("public record status changed: status=%+v err=%v", status, err)
	}
	var tuple []json.RawMessage
	if err := json.Unmarshal(record["prompt"], &tuple); err != nil || len(tuple) != len(originalTuple) || len(tuple) < 2 {
		t.Fatalf("public prompt tuple changed shape: tuple=%s err=%v", record["prompt"], err)
	}
	if string(tuple[1]) != comfyHistoryMustJSON(t, publicID) {
		t.Fatalf("public prompt tuple identity=%s, want %q", tuple[1], publicID)
	}
	for index, expected := range originalTuple {
		if index == 1 {
			continue
		}
		if string(tuple[index]) != expected {
			t.Fatalf("prompt tuple element %d changed: got=%s want=%s", index, tuple[index], expected)
		}
	}
}

func comfyHistoryMustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

type comfyHistoryMappingOverride struct {
	store.WorkloadStore
	publicID string
	mutate   func(*domain.PromptMapping)
}

func (s comfyHistoryMappingOverride) GetPromptMapping(ctx context.Context, publicPromptID string) (*domain.PromptMapping, error) {
	mapping, err := s.WorkloadStore.GetPromptMapping(ctx, publicPromptID)
	if err != nil || mapping == nil || publicPromptID != s.publicID {
		return mapping, err
	}
	corrupt := *mapping
	s.mutate(&corrupt)
	return &corrupt, nil
}

func TestComfyHistorySingleGraphNativeShape(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	comfyHistoryRow(t, srv, "owner", "public-one", "succeeded", `{"prompt":{"1":{"class_type":"SaveImage","inputs":{}}}}`, comfyHistoryRecord("backend-one", "artifact-one"), "backend-one")
	response := comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/public-one")
	var publicHistory map[string]json.RawMessage
	decodeErr := json.Unmarshal(response.Body.Bytes(), &publicHistory)
	var nativeRecord map[string]json.RawMessage
	if decodeErr == nil {
		decodeErr = json.Unmarshal(publicHistory["public-one"], &nativeRecord)
	}
	_, hasPrompt := nativeRecord["prompt"]
	if response.Code != http.StatusOK || decodeErr != nil || len(publicHistory) != 1 || publicHistory["public-one"] == nil || nativeRecord == nil || !hasPrompt {
		t.Fatalf("single history did not use native public shape: status=%d err=%v body=%s", response.Code, decodeErr, response.Body.String())
	}
	assertComfySingleRecord(t, response, "public-one", []string{`7`, `"backend-one"`, `{"1":{"class_type":"SaveImage"}}`, `{"client_id":"private-client"}`}, "backend-one")
	var record map[string]json.RawMessage
	if err := json.Unmarshal(publicHistory["public-one"], &record); err != nil {
		t.Fatal(err)
	}
	var promptTuple []json.RawMessage
	if err := json.Unmarshal(record["prompt"], &promptTuple); err != nil {
		t.Fatal(err)
	}
	if len(promptTuple) != 4 || string(promptTuple[0]) != "7" || string(promptTuple[1]) != `"public-one"` || string(promptTuple[2]) != `{"1":{"class_type":"SaveImage"}}` || string(promptTuple[3]) != `{"client_id":"private-client"}` {
		t.Fatalf("normalization changed prompt tuple values beyond identity: %s", record["prompt"])
	}
	if !strings.Contains(response.Body.String(), `"filename":"artifact-one"`) || !strings.Contains(response.Body.String(), `"subfolder":""`) || !strings.Contains(response.Body.String(), `"type":"output"`) {
		t.Fatalf("artifact reference was changed: %s", response.Body.String())
	}
}

func TestComfyHistoryManagedExecutionIdentity(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	comfyHistoryRow(t, srv, "owner", "managed-public", "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("raw-execution-7", "artifact-managed"), "managed-execution-7", "managed_comfy_v1")
	response := comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/managed-public")
	assertComfySingleRecord(t, response, "managed-public", []string{`7`, `"raw-execution-7"`, `{"1":{"class_type":"SaveImage"}}`, `{"client_id":"private-client"}`}, "raw-execution-7", "managed-execution-7")
	if !strings.Contains(response.Body.String(), `"filename":"artifact-managed"`) {
		t.Fatalf("managed history lost its artifact reference: %s", response.Body.String())
	}
	// Admission may persist a public mapping before it has a backend prompt id.
	comfyHistoryRow(t, srv, "owner", "preadmission", "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("later-backend-id", "artifact-preadmission"), "")
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/preadmission")
	assertComfySingleRecord(t, response, "preadmission", []string{`7`, `"later-backend-id"`, `{"1":{"class_type":"SaveImage"}}`, `{"client_id":"private-client"}`}, "later-backend-id")
	if !strings.Contains(response.Body.String(), `"filename":"artifact-preadmission"`) {
		t.Fatalf("pre-admission history lost its artifact reference: %s", response.Body.String())
	}
}

func TestComfyHistoryMultiChunkPreservation(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	payload := `{"managed_chunks":[{"id":"a","prompt":{"1":{"class_type":"SaveImage"}}},{"id":"b","prompt":{"2":{"class_type":"SaveImage"}}}]}`
	output := `{"backend-a":{"prompt":[7,"backend-a",{"1":{"class_type":"SaveImage"}},{"client_id":"client-a"}],"outputs":{"9":{"images":[{"filename":"artifact-a","subfolder":"sub-a","type":"output"}]}},"status":{"status_str":"success","completed":true}},"backend-b":{"prompt":[8,"backend-b",{"2":{"class_type":"SaveImage"}},{"client_id":"client-b"}],"outputs":{"10":{"images":[{"filename":"artifact-b","subfolder":"sub-b","type":"output"}]}},"status":{"status_str":"success","completed":true}}}`
	comfyHistoryRow(t, srv, "owner", "multi-public", "succeeded", payload, output, "managed-execution")
	response := comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/multi-public")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"multi-public":{"backend-a"`) || !strings.Contains(response.Body.String(), `"backend-b"`) {
		t.Fatalf("multi-chunk extension shape lost a record: status=%d body=%s", response.Code, response.Body.String())
	}
	var history map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	var records map[string]json.RawMessage
	if err := json.Unmarshal(history["multi-public"], &records); err != nil || len(records) != 2 {
		t.Fatalf("multi-chunk public value is not the complete backend map: records=%d err=%v", len(records), err)
	}
	for backendID, expectedArtifact := range map[string]string{"backend-a": "artifact-a", "backend-b": "artifact-b"} {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(records[backendID], &record); err != nil {
			t.Fatal(err)
		}
		var tuple []json.RawMessage
		if err := json.Unmarshal(record["prompt"], &tuple); err != nil || len(tuple) != 4 || string(tuple[1]) != `"multi-public"` {
			t.Fatalf("chunk prompt identity was not normalized: %s err=%v", record["prompt"], err)
		}
		var outputs map[string]json.RawMessage
		if err := json.Unmarshal(record["outputs"], &outputs); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(record["outputs"], []byte(`"filename":"`+expectedArtifact+`"`)) {
			t.Fatalf("chunk %s artifact identity changed: %s", backendID, record["outputs"])
		}
	}
}

func TestComfyHistoryAuthorizationAndOwners(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	srv.cfg.Auth.Credentials = append(srv.cfg.Auth.Credentials,
		CredentialConfig{ID: "foreign-comfy-reader", Token: "foreign-comfy-reader", OwnerID: "foreign", Plane: "api", Scopes: []string{"comfy:read"}, Adapters: []string{"comfy"}},
		CredentialConfig{ID: "wrong-comfy-adapter", Token: "wrong-comfy-adapter", OwnerID: "owner", Plane: "api", Scopes: []string{"comfy:read"}, Adapters: []string{"llamacpp"}},
		CredentialConfig{ID: "wrong-comfy-plane", Token: "wrong-comfy-plane", OwnerID: "owner", Plane: "node", Scopes: []string{"comfy:read"}, Adapters: []string{"comfy"}},
	)
	srv.buildCredentials()
	comfyHistoryRow(t, srv, "owner", "owned-public", "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("backend-owned", "artifact-owned"), "backend-owned")
	comfyHistoryRow(t, srv, "foreign", "foreign-valid", "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("backend-foreign", "artifact-foreign"), "backend-foreign")
	response := comfyHistoryRequest(t, srv, "admin-token", "/history")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "owned-public") || !strings.Contains(response.Body.String(), "foreign-valid") {
		t.Fatalf("admin history-all did not include all owners: status=%d body=%s", response.Code, response.Body.String())
	}
	comfyHistoryRow(t, srv, "foreign", "foreign-public", "succeeded", `not-json`, `null`, "")
	for _, path := range []string{"/history/owned-public", "/history"} {
		for _, token := range []string{"foreign-comfy-reader", "wrong-comfy-adapter", "wrong-comfy-plane"} {
			response := comfyHistoryRequest(t, srv, token, path)
			want := http.StatusForbidden
			if path == "/history/owned-public" && token == "foreign-comfy-reader" {
				want = http.StatusNotFound
			}
			if path == "/history" && token == "foreign-comfy-reader" {
				want = http.StatusInternalServerError // Its own deliberately corrupt row fails closed.
			}
			if response.Code != want {
				t.Fatalf("unauthorized history request %s %s status=%d", token, path, response.Code)
			}
		}
	}
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "foreign-public") || !strings.Contains(response.Body.String(), "owned-public") {
		t.Fatalf("owner filter parsed or exposed foreign history: status=%d body=%s", response.Code, response.Body.String())
	}
	response = comfyHistoryRequest(t, srv, "admin-token", "/history")
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "not-json") {
		t.Fatalf("admin history did not fail closed on its corrupt owned row: status=%d body=%s", response.Code, response.Body.String())
	}
	response = comfyHistoryRequest(t, srv, "admin-token", "/history/owned-public")
	if response.Code != http.StatusOK {
		t.Fatalf("admin could not read owned history: status=%d body=%s", response.Code, response.Body.String())
	}
}

type comfyHistoryListFailure struct{ store.WorkloadStore }

func (s comfyHistoryListFailure) ListWorkloads(context.Context) ([]*domain.Workload, error) {
	return nil, context.DeadlineExceeded
}

func TestComfyHistoryInvalidAndStoreFailures(t *testing.T) {
	srv, manager, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	invalidUTF8 := `{"backend":{"outputs":{},"status":{"status_str":"success","completed":true},"extra":"` + string([]byte{0xff}) + `"}}`
	for index, invalid := range []string{
		`null`, `[]`, `{"backend":{"outputs":{},"status":{"status_str":"success","completed":true}}} trailing`,
		`{"backend":{"outputs":{},"outputs":{},"status":{"status_str":"success","completed":true}}}`,
		`{"backend-a":{"outputs":{},"status":{"status_str":"success","completed":true}},"backend-b":{"outputs":{},"status":{"status_str":"success","completed":true}}}`,
		`{"different-backend":{"outputs":{},"status":{"status_str":"success","completed":true}}}`,
		`{"backend":{"outputs":[],"status":{"status_str":"success","completed":true}}}`,
		`{"backend":{"outputs":{},"status":{"status_str":"failed","completed":false}}}`,
		`{"backend":{"prompt":[0,"different",{},{}],"outputs":{},"status":{"status_str":"success","completed":true}}}`,
		invalidUTF8,
	} {
		publicID := "invalid-" + string(rune('a'+index))
		comfyHistoryRow(t, srv, "owner", publicID, "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, invalid, "backend")
		response := comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/"+publicID)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "backend") {
			t.Fatalf("invalid history was not rejected generically: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	invalidPayload := `{"prompt":{"1":{"class_type":"` + string([]byte{0xff}) + `"}}}`
	comfyHistoryRow(t, srv, "owner", "invalid-payload-utf8", "succeeded", invalidPayload, comfyHistoryRecord("backend-payload-utf8", "artifact-payload-utf8"), "backend-payload-utf8")
	response := comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/invalid-payload-utf8")
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "backend-payload-utf8") {
		t.Fatalf("invalid UTF-8 payload was not rejected generically: status=%d body=%s", response.Code, response.Body.String())
	}
	comfyHistoryRow(t, srv, "owner", "missing-chunk", "succeeded", `{"managed_chunks":[{"prompt":{"1":{"class_type":"SaveImage"}}},{"prompt":{"2":{"class_type":"SaveImage"}}}]}`, comfyHistoryRecord("backend-chunk-a", "artifact-chunk-a"), "backend-chunk-a")
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/missing-chunk")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("missing managed chunk record was not rejected: status=%d body=%s", response.Code, response.Body.String())
	}
	comfyHistoryRow(t, srv, "owner", "invalid-payload", "succeeded", `{"prompt":{}}`, comfyHistoryRecord("backend-payload", "artifact-payload"), "backend-payload")
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/invalid-payload")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("unparseable graph count was not rejected: status=%d body=%s", response.Code, response.Body.String())
	}
	comfyHistoryRow(t, srv, "owner", "empty-managed-chunks", "succeeded", `{"managed_chunks":[],"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("backend-empty-chunks", "artifact-empty-chunks"), "backend-empty-chunks")
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/empty-managed-chunks")
	if response.Code != http.StatusOK {
		t.Fatalf("empty managed_chunks did not use standard prompt precedence: status=%d body=%s", response.Code, response.Body.String())
	}
	comfyHistoryRow(t, srv, "owner", "malformed-managed-chunks", "succeeded", `{"managed_chunks":{},"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("backend-bad-chunks", "artifact-bad-chunks"), "backend-bad-chunks")
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/malformed-managed-chunks")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("malformed managed_chunks count did not fail closed: status=%d", response.Code)
	}
	comfyHistoryRow(t, srv, "owner", "mixed-chunk-status", "succeeded", `{"managed_chunks":[{"prompt":{"1":{"class_type":"SaveImage"}}},{"prompt":{"2":{"class_type":"SaveImage"}}}]}`, `{"backend-ok":{"outputs":{},"status":{"status_str":"success","completed":true}},"backend-failed":{"outputs":{},"status":{"status_str":"failed","completed":false}}}`, "managed-execution")
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/mixed-chunk-status")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("mixed chunk statuses were partially accepted: status=%d", response.Code)
	}
	for _, invalidIdentity := range []struct {
		publicID string
		plane    domain.Plane
		adapter  string
		itemID   string
	}{
		{publicID: "wrong-plane", plane: domain.PlaneAPI, adapter: "comfy", itemID: "wrong-plane"},
		{publicID: "wrong-adapter", plane: domain.PlaneComfy, adapter: "llamacpp", itemID: "wrong-adapter"},
		{publicID: "wrong-item-id", plane: domain.PlaneComfy, adapter: "comfy", itemID: "different-public"},
	} {
		row, _, err := srv.workloadStore.CreateWorkload(context.Background(), &domain.Workload{
			Request: domain.WorkloadRequest{ID: "identity-" + invalidIdentity.publicID, OwnerID: "owner", Plane: invalidIdentity.plane, Adapter: invalidIdentity.adapter, ItemID: invalidIdentity.itemID, Payload: []byte(`{"prompt":{"1":{"class_type":"SaveImage"}}}`)},
			Status: domain.WorkloadSucceeded, Plan: &domain.ExecutionPlan{TargetID: "target-a"}, InlineOutput: []byte(comfyHistoryRecord("backend-identity", "artifact-identity")),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.workloadStore.SavePromptMapping(context.Background(), &domain.PromptMapping{PublicPromptID: invalidIdentity.publicID, WorkloadID: row.Request.ID, TargetID: "target-a", BackendPromptID: "backend-identity"}); err != nil {
			t.Fatal(err)
		}
		response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/"+invalidIdentity.publicID)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), invalidIdentity.publicID) {
			t.Fatalf("inconsistent persisted identity was not rejected generically: status=%d body=%s", response.Code, response.Body.String())
		}
	}

	backingStore := srv.workloadStore
	comfyHistoryRow(t, srv, "owner", "mapping-corruption", "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("backend-mapping", "artifact-mapping"), "backend-mapping")
	if _, _, err := backingStore.CreateWorkload(context.Background(), &domain.Workload{
		Request: domain.WorkloadRequest{ID: "mapping-sibling-workload", OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: "mapping-sibling"},
		Status: domain.WorkloadWaiting, Plan: &domain.ExecutionPlan{TargetID: "target-a"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []struct {
		name   string
		mutate func(*domain.PromptMapping)
	}{
		{name: "public-id", mutate: func(mapping *domain.PromptMapping) { mapping.PublicPromptID = "different-public-id" }},
		{name: "workload-id", mutate: func(mapping *domain.PromptMapping) { mapping.WorkloadID = "mapping-sibling-workload" }},
		{name: "target-id", mutate: func(mapping *domain.PromptMapping) { mapping.TargetID = "different-target" }},
		{name: "backend-id", mutate: func(mapping *domain.PromptMapping) { mapping.BackendPromptID = "different-backend" }},
	} {
		srv.workloadStore = comfyHistoryMappingOverride{WorkloadStore: backingStore, publicID: "mapping-corruption", mutate: fault.mutate}
		response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/mapping-corruption")
		srv.workloadStore = backingStore
		if response.Code != http.StatusInternalServerError || response.Body.String() != "{\"error\":\"history unavailable\"}\n" || strings.Contains(response.Body.String(), "different-") || strings.Contains(response.Body.String(), "backend-mapping") {
			t.Fatalf("corrupt persisted mapping field %s was not rejected generically: status=%d body=%s", fault.name, response.Code, response.Body.String())
		}
	}
	comfyHistoryRow(t, srv, "owner", "waiting-public", "waiting", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, `not-json`, "")
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history/waiting-public")
	if response.Code != http.StatusOK || response.Body.String() != "{}\n" {
		t.Fatalf("non-success history was not empty: status=%d body=%s", response.Code, response.Body.String())
	}
	failedStore := comfyHistoryListFailure{WorkloadStore: srv.workloadStore}
	failedManager := workloads.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), failedStore, time.Second)
	defer failedManager.Close()
	srv.workloads = failedManager
	response = comfyHistoryRequest(t, srv, "comfy-reader-token", "/history")
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "deadline") {
		t.Fatalf("List failure was not generic 500: status=%d body=%s", response.Code, response.Body.String())
	}
	srv.workloads = manager

	for _, rows := range [][]domain.WorkloadRequest{
		{
			{ID: "duplicate-public-a", OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: "duplicate-public"},
			{ID: "duplicate-public-b", OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: "duplicate-public"},
		},
		{{ID: "missing-public", OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: ""}},
	} {
		identityServer, _, identityCleanup := testServer(t)
		addComfyReadCredential(identityServer)
		for _, request := range rows {
			if _, _, err := identityServer.workloadStore.CreateWorkload(context.Background(), &domain.Workload{Request: request, Status: domain.WorkloadWaiting}); err != nil {
				t.Fatal(err)
			}
		}
		response = comfyHistoryRequest(t, identityServer, "comfy-reader-token", "/history")
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "duplicate-public") {
			t.Fatalf("missing or duplicate public ids were not rejected: status=%d body=%s", response.Code, response.Body.String())
		}
		identityCleanup()
	}

	boundedServer, _, boundedCleanup := testServer(t)
	defer boundedCleanup()
	addComfyReadCredential(boundedServer)
	for index := 0; index < comfyHistoryMaxRows+1; index++ {
		publicID := "bounded-row-" + strconv.Itoa(index)
		_, _, err := boundedServer.workloadStore.CreateWorkload(context.Background(), &domain.Workload{
			Request: domain.WorkloadRequest{ID: "bounded-work-" + strconv.Itoa(index), OwnerID: "owner", Plane: domain.PlaneComfy, Adapter: "comfy", ItemID: publicID},
			Status: domain.WorkloadWaiting,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	response = comfyHistoryRequest(t, boundedServer, "comfy-reader-token", "/history")
	if response.Code != http.StatusRequestEntityTooLarge || strings.Contains(response.Body.String(), "bounded-row") {
		t.Fatalf("owned row cap was not enforced generically: status=%d body=%s", response.Code, response.Body.String())
	}

	largeServer, _, largeCleanup := testServer(t)
	defer largeCleanup()
	addComfyReadCredential(largeServer)
	largePayload := strings.Repeat("x", 6<<20)
	for index := 0; index < 3; index++ {
		publicID := "bounded-output-" + strconv.Itoa(index)
		largeOutput := `{"backend-` + strconv.Itoa(index) + `":{"outputs":{"large":{"value":"` + largePayload + `"}},"status":{"status_str":"success","completed":true}}}`
		comfyHistoryRow(t, largeServer, "owner", publicID, "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, largeOutput, "backend-"+strconv.Itoa(index))
	}
	response = comfyHistoryRequest(t, largeServer, "comfy-reader-token", "/history")
	if response.Code != http.StatusRequestEntityTooLarge || strings.Contains(response.Body.String(), "large-output") {
		t.Fatalf("aggregate output bound was not enforced generically: status=%d", response.Code)
	}
}

func TestComfyHistoryArtifactViewContinuity(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	srv.cfg.Auth.Credentials = append(srv.cfg.Auth.Credentials,
		CredentialConfig{ID: "comfy-artifact-reader", Token: "comfy-artifact-reader", OwnerID: "owner", Plane: "api", Scopes: []string{"comfy:read", "artifacts:read"}, Adapters: []string{"comfy"}},
		CredentialConfig{ID: "other-artifact-reader", Token: "other-artifact-reader", OwnerID: "other", Plane: "api", Scopes: []string{"artifacts:read"}, Adapters: []string{"comfy"}},
		CredentialConfig{ID: "admin-artifact-reader", Token: "admin-artifact-reader", OwnerID: "admin", Plane: "admin", Scopes: []string{"artifacts:read", "admin"}, Adapters: []string{"comfy"}},
	)
	srv.buildCredentials()
	artifact, err := srv.artifacts.Put(context.Background(), "owner", "work-artifact", "image.png", "image/png", strings.NewReader("image-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	comfyHistoryRow(t, srv, "owner", "artifact-public", "succeeded", `{"prompt":{"1":{"class_type":"SaveImage"}}}`, comfyHistoryRecord("backend-artifact", artifact.ID), "backend-artifact")
	history := comfyHistoryRequest(t, srv, "comfy-artifact-reader", "/history/artifact-public")
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), artifact.ID) {
		t.Fatalf("history lost owner-bound artifact reference: status=%d body=%s", history.Code, history.Body.String())
	}
	trackingStore := &comfyHistoryTrackedArtifactStore{Store: srv.artifacts}
	srv.SetArtifactStore(trackingStore)
	assertClosedReader := func(before int, label string) {
		t.Helper()
		if len(trackingStore.readers) != before+1 {
			t.Fatalf("%s opened %d readers, want exactly one", label, len(trackingStore.readers)-before)
		}
		reader := trackingStore.readers[len(trackingStore.readers)-1]
		if reader.closeCount != 1 || trackingStore.openReaders != 0 {
			t.Fatalf("%s reader closure mismatch: closeCount=%d openReaders=%d", label, reader.closeCount, trackingStore.openReaders)
		}
	}
	before := len(trackingStore.readers)
	view := comfyHistoryRequest(t, srv, "comfy-artifact-reader", "/view?filename="+artifact.ID)
	if view.Code != http.StatusOK || view.Body.String() != "image-bytes" {
		t.Fatalf("owner artifact view failed: status=%d body=%s", view.Code, view.Body.String())
	}
	assertClosedReader(before, "owner view")
	before = len(trackingStore.readers)
	view = comfyHistoryRequest(t, srv, "admin-artifact-reader", "/view?filename="+artifact.ID)
	if view.Code != http.StatusOK || view.Body.String() != "image-bytes" {
		t.Fatalf("admin artifact view failed: status=%d body=%s", view.Code, view.Body.String())
	}
	assertClosedReader(before, "admin view")
	before = len(trackingStore.readers)
	view = comfyHistoryRequest(t, srv, "other-artifact-reader", "/view?filename="+artifact.ID)
	if view.Code != http.StatusNotFound {
		t.Fatalf("foreign owner could view artifact: status=%d", view.Code)
	}
	assertClosedReader(before, "foreign-owner view")

	trackingStore.mode = "error-with-reader"
	before = len(trackingStore.readers)
	view = comfyHistoryRequest(t, srv, "comfy-artifact-reader", "/view?filename="+artifact.ID)
	if view.Code != http.StatusNotFound {
		t.Fatalf("artifact open error did not remain generic 404: status=%d", view.Code)
	}
	assertClosedReader(before, "error-with-reader view")

	trackingStore.mode = "nil-artifact"
	before = len(trackingStore.readers)
	view = comfyHistoryRequest(t, srv, "comfy-artifact-reader", "/view?filename="+artifact.ID)
	if view.Code != http.StatusNotFound {
		t.Fatalf("nil artifact metadata did not remain generic 404: status=%d", view.Code)
	}
	assertClosedReader(before, "nil-artifact view")

	trackingStore.mode = "nil-reader"
	before = len(trackingStore.readers)
	view = comfyHistoryRequest(t, srv, "comfy-artifact-reader", "/view?filename="+artifact.ID)
	if view.Code != http.StatusNotFound {
		t.Fatalf("nil artifact reader did not remain generic 404: status=%d", view.Code)
	}
	assertClosedReader(before, "nil-reader view")
}

type comfyHistoryTrackedArtifactStore struct {
	artifacts.Store
	mode        string
	readers     []*comfyHistoryTrackedReadCloser
	openReaders int
}

type comfyHistoryTrackedReadCloser struct {
	io.ReadCloser
	store      *comfyHistoryTrackedArtifactStore
	closeCount int
}

func (r *comfyHistoryTrackedReadCloser) Close() error {
	r.closeCount++
	r.store.openReaders--
	return r.ReadCloser.Close()
}

func (s *comfyHistoryTrackedArtifactStore) Open(ctx context.Context, id string) (*domain.Artifact, io.ReadCloser, error) {
	artifact, reader, err := s.Store.Open(ctx, id)
	var tracked *comfyHistoryTrackedReadCloser
	if reader != nil {
		tracked = &comfyHistoryTrackedReadCloser{ReadCloser: reader, store: s}
		s.readers = append(s.readers, tracked)
		s.openReaders++
		reader = tracked
	}
	switch s.mode {
	case "error-with-reader":
		return artifact, reader, context.DeadlineExceeded
	case "nil-artifact":
		return nil, reader, err
	case "nil-reader":
		if tracked != nil {
			_ = tracked.Close()
		}
		return artifact, nil, err
	default:
		return artifact, reader, err
	}
}
