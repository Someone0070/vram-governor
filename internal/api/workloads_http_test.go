package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
	"vram-governor/internal/wsproto"
)

func testServer(t *testing.T) (*Server, *workloads.Manager, context.CancelFunc) {
	t.Helper()
	cfg := &Config{}
	cfg.Auth.AdminPrivateCIDRs = []string{"127.0.0.0/8"}
	cfg.Auth.Credentials = []CredentialConfig{
		{ID: "alice", Token: "alice-token", OwnerID: "alice-owner", Plane: "ui", Scopes: []string{"workloads:submit", "workloads:read", "workloads:cancel", "workloads:reprioritize", "workloads:approve"}, Adapters: []string{"mock"}, MaxPriority: 10, EgressPolicy: "local_only", ConcurrencyLimit: 2, BudgetCents: 5, PreemptionBudget: 1},
		{ID: "bob", Token: "bob-token", OwnerID: "bob-owner", Plane: "ui", Scopes: []string{"workloads:read", "workloads:submit"}, Adapters: []string{"mock"}, MaxPriority: 10},
		{ID: "admin", Token: "admin-token", OwnerID: "ops", Plane: "admin", Scopes: []string{"*"}, Adapters: []string{"*"}, MaxPriority: 100},
		{ID: "monitor", Token: "monitor-token", OwnerID: "home", Plane: "agent", Scopes: []string{"incidents:create", "incidents:read", "incidents:propose", "incidents:escalate", "agent:events"}, Adapters: []string{"mock", "openrouter"}, MaxPriority: 0, MaxIncidentSeverity: "S1", EgressPolicy: "local_only"},
		{ID: "node-a", Token: "node-a-token", OwnerID: "system", Plane: "node", NodeID: "node-a", Scopes: []string{"node:connect", "node:report"}, Adapters: []string{"mock"}},
	}
	cfg.Agents.LocalVerifierModels = []string{"verifier-9b"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	manager := workloads.NewManager(logger, backing, time.Second)
	manager.RegisterAdapter(workloads.NewMockAdapter())
	manager.RegisterTarget(workloads.Target{ID: "mock", Adapter: "mock", Endpoint: "in-process", Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	srv := NewServer(cfg, logger, backing, nil, nil)
	srv.SetWorkloadManager(manager)
	return srv, manager, cancel
}

func request(t *testing.T, handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestWorkloadAuthPriorityClampAndOwnership(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	handler := srv.Handler()
	body := map[string]any{"adapter": "mock", "workload_type": "test", "priority": 99, "plane": "admin", "concurrency_limit": 999, "budget_limit_cents": 999, "preemption_budget": 999, "payload": map[string]any{"prompt": "hello"}}
	if got := request(t, handler, http.MethodPost, "/api/v1/workloads", "", body); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", got.Code, got.Body.String())
	}
	created := request(t, handler, http.MethodPost, "/api/v1/workloads", "alice-token", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var row struct {
		Request struct {
			ID               string       `json:"id"`
			OwnerID          string       `json:"owner_id"`
			Priority         int          `json:"priority"`
			Plane            domain.Plane `json:"plane"`
			ConcurrencyLimit int          `json:"concurrency_limit"`
			BudgetLimitCents int64        `json:"budget_limit_cents"`
			PreemptionBudget int          `json:"preemption_budget"`
		} `json:"request"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row.Request.OwnerID != "alice-owner" || row.Request.Priority != 10 || row.Request.Plane != domain.PlaneAPI || row.Request.ConcurrencyLimit != 2 || row.Request.BudgetLimitCents != 5 || row.Request.PreemptionBudget != 1 {
		t.Fatalf("identity policy not applied: %+v", row.Request)
	}
	other := request(t, handler, http.MethodGet, "/api/v1/workloads/"+row.Request.ID, "bob-token", nil)
	if other.Code != http.StatusNotFound {
		t.Fatalf("cross-owner read status=%d body=%s", other.Code, other.Body.String())
	}
}

func TestSecurityPlaneCannotBeBypassedWithWildcardScope(t *testing.T) {
	if planeAllowsScope(Principal{Plane: "agent"}, "admin") {
		t.Fatal("agent plane acquired administrative authority through scopes")
	}
	if planeAllowsScope(Principal{Plane: "node"}, "workloads:submit") {
		t.Fatal("node plane acquired workload submission authority")
	}
	if !planeAllowsScope(Principal{Plane: "admin"}, "admin") {
		t.Fatal("admin plane lost administrative authority")
	}

	cfg := &Config{}
	cfg.Auth.Credentials = []CredentialConfig{{ID: "local", Token: "secret", Plane: "api", OwnerID: "owner"}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	srv := NewServer(cfg, logger, backing, nil, nil)
	principal, ok := srv.authenticateToken("secret")
	if !ok || principal.EgressPolicy != string(domain.EgressLocalOnly) {
		t.Fatalf("unspecified credential egress must default local-only: %+v", principal)
	}
}

func TestNodeReportCredentialCannotWriteAnotherNode(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	body := map[string]any{"id": "engine-a", "state": "active"}
	if denied := request(t, srv.Handler(), http.MethodPost, "/nodes/node-b/engines", "node-a-token", body); denied.Code != http.StatusForbidden {
		t.Fatalf("node credential wrote another node: status=%d body=%s", denied.Code, denied.Body.String())
	}
	if own := request(t, srv.Handler(), http.MethodPost, "/nodes/node-a/engines", "node-a-token", body); own.Code != http.StatusOK {
		t.Fatalf("node credential could not report its own runtime: status=%d body=%s", own.Code, own.Body.String())
	}
}

func TestArtifactReferencesAreOwnerScopedBeforeAdmission(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	artifactStore, err := artifacts.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv.SetArtifactStore(artifactStore)
	artifact, err := artifactStore.Put(context.Background(), "alice-owner", "", "private.bin", "application/octet-stream", strings.NewReader("private"))
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"adapter": "mock", "payload": map[string]any{"artifact": artifact.ID}, "artifact_refs": []string{artifact.ID}}
	if own := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "alice-token", body); own.Code != http.StatusCreated {
		t.Fatalf("owner artifact submission=%d body=%s", own.Code, own.Body.String())
	}
	if cross := request(t, srv.Handler(), http.MethodPost, "/api/v1/workloads", "bob-token", body); cross.Code != http.StatusForbidden {
		t.Fatalf("cross-owner artifact reference=%d body=%s", cross.Code, cross.Body.String())
	}
}

func TestAdminCanIssueIdempotentResidencyTransition(t *testing.T) {
	var loads atomic.Int32
	loaded := atomic.Bool{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/models/load":
			loads.Add(1)
			loaded.Store(true)
			w.WriteHeader(http.StatusOK)
		case "/v1/models":
			status := "unloaded"
			if loaded.Load() {
				status = "loaded"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": status}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	srv, manager, cancel := testServer(t)
	defer cancel()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	manager.RegisterTarget(workloads.Target{ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"model"}, SupportsModelLifecycle: true, MaxResidentModels: 1, Enabled: true})

	body := bytes.NewBufferString(`{"target_id":"router","model":"model","desired_tier":"hot_vram","policy":"pinned"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/residency/transition", body)
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "load-model-once")
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("transition status=%d body=%s", response.Code, response.Body.String())
	}
	if loads.Load() != 1 {
		t.Fatalf("router load calls=%d", loads.Load())
	}
	missingKey := httptest.NewRequest(http.MethodPost, "/admin/api/residency/transition", bytes.NewBufferString(`{"target_id":"router","model":"model","desired_tier":"cold_disk"}`))
	missingKey.RemoteAddr = "127.0.0.1:5000"
	missingKey.Header.Set("Authorization", "Bearer admin-token")
	missingResponse := httptest.NewRecorder()
	srv.Handler().ServeHTTP(missingResponse, missingKey)
	if missingResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing idempotency key status=%d", missingResponse.Code)
	}
}

func TestAdminNodeCommandIsSignedDurableAndIdempotent(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	_, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-1", Name: "node", Observed: domain.Observed{Connectivity: domain.ConnectivityConnected}})
	if err != nil {
		t.Fatal(err)
	}
	issue := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-1/commands", bytes.NewBufferString(`{"command":"refresh_capabilities"}`))
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer admin-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "refresh-once")
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
		return response
	}
	first := issue()
	second := issue()
	if first.Code != http.StatusAccepted || second.Code != http.StatusAccepted {
		t.Fatalf("command responses: first=%d %s second=%d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	var firstCommand, secondCommand domain.NodeCommand
	_ = json.Unmarshal(first.Body.Bytes(), &firstCommand)
	_ = json.Unmarshal(second.Body.Bytes(), &secondCommand)
	if firstCommand.ID == "" || firstCommand.ID != secondCommand.ID || firstCommand.Signature == "" || firstCommand.Status != domain.NodeCommandQueued {
		t.Fatalf("command was not durable/idempotent: first=%+v second=%+v", firstCommand, secondCommand)
	}
	wire := nodeCommandPayload(&firstCommand)
	if !wsproto.VerifyCommand(wire, srv.commandSecret) {
		t.Fatal("stored node command signature is invalid")
	}
	srv.handleNodeCommandResult(context.Background(), wsproto.CommandResultPayload{ID: firstCommand.ID, NodeID: "node-1", OK: true, Result: map[string]any{"refreshed": true}, CompletedAt: time.Now().UTC()})
	completed, _ := srv.workloadStore.GetNodeCommand(context.Background(), firstCommand.ID)
	if completed.Status != domain.NodeCommandSucceeded {
		t.Fatalf("command result was not persisted: %+v", completed)
	}
}

func TestBrowserSessionRequiresCSRFForMutations(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	handler := srv.Handler()
	login := request(t, handler, http.MethodPost, "/auth/session", "", map[string]string{"token": "alice-token"})
	if login.Code != 200 {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	cookies := login.Result().Cookies()
	if len(cookies) == 0 || session.CSRF == "" {
		t.Fatal("session cookie or CSRF missing")
	}
	body := []byte(`{"adapter":"mock","payload":{"prompt":"hello"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workloads", bytes.NewReader(body))
	req.AddCookie(cookies[0])
	req.Header.Set("Content-Type", "application/json")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, req)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", denied.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/workloads", bytes.NewReader(body))
	req.AddCookie(cookies[0])
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", session.CSRF)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusCreated {
		t.Fatalf("valid CSRF status=%d body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestAdminRequiresScopeAndPrivateNetwork(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	handler := srv.Handler()
	nonAdmin := request(t, handler, http.MethodGet, "/admin/api/overview", "alice-token", nil)
	if nonAdmin.Code != http.StatusForbidden {
		t.Fatalf("non-admin status=%d", nonAdmin.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	req.RemoteAddr = "203.0.113.8:1234"
	remote := httptest.NewRecorder()
	handler.ServeHTTP(remote, req)
	if remote.Code != http.StatusForbidden {
		t.Fatalf("public admin status=%d", remote.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	req.RemoteAddr = "127.0.0.1:1234"
	local := httptest.NewRecorder()
	handler.ServeHTTP(local, req)
	if local.Code != http.StatusOK {
		t.Fatalf("private admin status=%d body=%s", local.Code, local.Body.String())
	}
}

func TestAdminOverviewUsesArraysForEmptyCollections(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	req.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"nodes", "targets", "workloads", "events", "model_residencies", "residency_transitions", "notifications", "budget_reservations", "scheduler_learning_samples", "interference_profiles", "transition_plans", "incidents"} {
		value := bytes.TrimSpace(body[field])
		if len(value) == 0 || value[0] != '[' {
			t.Fatalf("overview field %q must be a JSON array, got %s", field, value)
		}
	}
}

func TestAdminOverviewReportsDeploymentGapsWithoutPromotingSimulatorCoverage(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	req.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Readiness struct {
			StateBackend string `json:"state_backend"`
			ReleaseGate  string `json:"release_gate"`
			Checks       []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"checks"`
		} `json:"readiness"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Readiness.StateBackend != "memory (restart-ephemeral)" || body.Readiness.ReleaseGate != "not ready" {
		t.Fatalf("development deployment was overstated: %+v", body.Readiness)
	}
	statuses := map[string]string{}
	for _, check := range body.Readiness.Checks {
		statuses[check.ID] = check.Status
	}
	if statuses["durable_state"] != "missing" || statuses["comfy"] != "missing" || statuses["checkpoint"] != "missing" {
		t.Fatalf("known release gaps not reported: %+v", statuses)
	}
}

func TestOpenAIModelsExposeRouteContextMetadata(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	manager.RegisterTarget(workloads.Target{ID: "short", Adapter: "llamacpp", Models: []string{"same-model"}, ResidentModels: []string{"same-model"}, ContextLimit: 4096, Enabled: true})
	manager.RegisterTarget(workloads.Target{ID: "long", Adapter: "llamacpp", Models: []string{"same-model"}, ContextLimit: 32768, SupportsModelLifecycle: true, Enabled: true})
	response := request(t, srv.Handler(), http.MethodGet, "/v1/models", "admin-token", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("models status=%d body=%s", response.Code, response.Body.String())
	}
	var catalog struct {
		Data []struct {
			ID       string `json:"id"`
			Governor struct {
				MaxContextTokens       int   `json:"max_context_tokens"`
				AvailableContextLimits []int `json:"available_context_limits"`
				TargetCount            int   `json:"target_count"`
				Resident               bool  `json:"resident"`
				LifecycleCapable       bool  `json:"lifecycle_capable"`
			} `json:"governor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	for _, model := range catalog.Data {
		if model.ID == "same-model" {
			if model.Governor.MaxContextTokens != 32768 || model.Governor.TargetCount != 2 || !model.Governor.Resident || !model.Governor.LifecycleCapable || len(model.Governor.AvailableContextLimits) != 2 || model.Governor.AvailableContextLimits[0] != 4096 || model.Governor.AvailableContextLimits[1] != 32768 {
				t.Fatalf("unexpected governor metadata: %+v", model.Governor)
			}
			return
		}
	}
	t.Fatal("same-model missing from catalog")
}

func TestAdminCanDrainNodeWithoutClobberingObservedState(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	now := time.Now().UTC()
	_, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-a", Name: "node-a", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastHeartbeat: now}, Accelerators: []domain.Accelerator{{ID: "gpu-a", VRAMTotalMB: 24_000, VRAMFreeMB: 20_000}}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-a/scheduling", strings.NewReader(`{"state":"draining"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "drain-node-a")
	req.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("drain status=%d body=%s", response.Code, response.Body.String())
	}
	node, err := srv.nodes.GetNode(context.Background(), "node-a")
	if err != nil || node.SchedulingState != domain.SchedulingDraining || node.Desired.SchedulingEnabled || node.Observed.Connectivity != domain.ConnectivityConnected || len(node.Accelerators) != 1 {
		t.Fatalf("desired-state update clobbered observed inventory: %+v err=%v", node, err)
	}
}

func TestMonitoringAgentSeverityIsClampedWithoutAdminAuthority(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	created := request(t, srv.Handler(), http.MethodPost, "/api/agent/v1/incidents", "monitor-token", map[string]any{"severity": "S4", "confidence": 0.8, "summary": "thermal anomaly", "evidence_refs": []string{"art-local"}})
	if created.Code != http.StatusCreated {
		t.Fatalf("incident create=%d body=%s", created.Code, created.Body.String())
	}
	var incident struct{ ID, Severity, Status string }
	if err := json.Unmarshal(created.Body.Bytes(), &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Severity != "S1" {
		t.Fatalf("severity ceiling bypassed: %+v", incident)
	}
	admin := request(t, srv.Handler(), http.MethodGet, "/admin/api/overview", "monitor-token", nil)
	if admin.Code != http.StatusForbidden {
		t.Fatalf("monitor gained admin authority: %d", admin.Code)
	}
	proposal := request(t, srv.Handler(), http.MethodPost, "/api/agent/v1/incidents/"+incident.ID+"/proposal", "monitor-token", map[string]any{"action": "reduce_power_limit", "requires_approval": true})
	if proposal.Code != http.StatusOK {
		t.Fatalf("proposal=%d body=%s", proposal.Code, proposal.Body.String())
	}
	escalated := request(t, srv.Handler(), http.MethodPost, "/api/agent/v1/incidents/"+incident.ID+"/escalate", "monitor-token", map[string]any{"adapter": "mock", "provider": "local", "model": "verifier-9b", "requested_model_tier": "large-local", "evidence_classification": "sensitive"})
	if escalated.Code != http.StatusAccepted {
		t.Fatalf("local verifier escalation=%d body=%s", escalated.Code, escalated.Body.String())
	}
	var analyzed domain.Incident
	if err := json.Unmarshal(escalated.Body.Bytes(), &analyzed); err != nil {
		t.Fatal(err)
	}
	if analyzed.ActualModel != "verifier-9b" || analyzed.ActualProvider != "local" || analyzed.AnalysisWorkloadID == "" || analyzed.Severity != "S1" {
		t.Fatalf("model escalation changed authority or omitted execution identity: %+v", analyzed)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer waitCancel()
	if _, err := manager.Wait(waitCtx, analyzed.AnalysisWorkloadID); err != nil {
		t.Fatal(err)
	}
	refreshed := request(t, srv.Handler(), http.MethodGet, "/api/agent/v1/incidents/"+incident.ID, "monitor-token", nil)
	if refreshed.Code != http.StatusOK {
		t.Fatalf("incident refresh=%d body=%s", refreshed.Code, refreshed.Body.String())
	}
	if err := json.Unmarshal(refreshed.Body.Bytes(), &analyzed); err != nil {
		t.Fatal(err)
	}
	if analyzed.Status != "verified" || analyzed.ActualProvider != "mock" {
		t.Fatalf("completed verifier did not durably record the actual selected route: %+v", analyzed)
	}
	cloudDenied := request(t, srv.Handler(), http.MethodPost, "/api/agent/v1/incidents/"+incident.ID+"/escalate", "monitor-token", map[string]any{"adapter": "openrouter", "provider": "openrouter", "model": "cloud-model", "requested_model_tier": "cloud", "evidence_classification": "internal_sanitized", "evidence_sanitized": true, "sanitized_summary": "safe"})
	if cloudDenied.Code != http.StatusForbidden {
		t.Fatalf("local-only monitor escaped to cloud: %d body=%s", cloudDenied.Code, cloudDenied.Body.String())
	}
}

func TestOpenAIStreamingRoutesTwoSameModelProfilesAndHoldsStickySlot(t *testing.T) {
	shortRelease := make(chan struct{})
	shortStarted := make(chan struct{})
	var shortHits atomic.Int32
	var longHits atomic.Int32
	shortBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shortHits.Add(1)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode short request: %v", err)
		}
		if stream, _ := body["stream"].(bool); !stream {
			t.Errorf("short backend did not receive stream=true: %+v", body)
		}
		if _, leaked := body["governor"]; leaked {
			t.Errorf("governor metadata leaked to backend: %+v", body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"short-1\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n")
		w.(http.Flusher).Flush()
		close(shortStarted)
		<-shortRelease
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
	}))
	defer shortBackend.Close()
	longBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		longHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"long-1\",\"choices\":[{\"delta\":{\"content\":\"long\"}}]}\n\ndata: [DONE]\n\n")
		w.(http.Flusher).Flush()
	}))
	defer longBackend.Close()

	cfg := &Config{}
	cfg.Auth.Credentials = []CredentialConfig{{ID: "client", Token: "client-token", OwnerID: "owner", Plane: "api", Scopes: []string{"inference:submit"}, Adapters: []string{"llamacpp"}, MaxPriority: 10, EgressPolicy: "local_only"}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	manager := workloads.NewManager(logger, backing, time.Second)
	manager.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", nil))
	manager.RegisterTarget(workloads.Target{ID: "same-model-short", Adapter: "llamacpp", Endpoint: shortBackend.URL, AcceleratorID: "gpu-0", Models: []string{"same-model"}, ContextLimit: 8192, Slots: 1, CapacityVerified: true, Enabled: true})
	manager.RegisterTarget(workloads.Target{ID: "same-model-long", Adapter: "llamacpp", Endpoint: longBackend.URL, AcceleratorID: "gpu-1", Models: []string{"same-model"}, ContextLimit: 32768, Slots: 1, CapacityVerified: true, Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)
	srv := NewServer(cfg, logger, backing, nil, nil)
	srv.SetWorkloadManager(manager)
	gateway := httptest.NewServer(srv.Handler())
	defer gateway.Close()

	shortRequest := []byte(`{"model":"same-model","stream":true,"max_completion_tokens":1000,"messages":[{"role":"user","content":"short"}],"governor":{"context_tokens":3000,"placement_key":"client-a","placement_policy":"sticky"}}`)
	firstReq, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", bytes.NewReader(shortRequest))
	firstReq.Header.Set("Authorization", "Bearer client-token")
	firstReq.Header.Set("Content-Type", "application/json")
	firstResponse, err := gateway.Client().Do(firstReq)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-shortStarted:
	case <-time.After(time.Second):
		t.Fatal("short stream did not produce its first chunk")
	}
	if firstResponse.StatusCode != http.StatusOK {
		t.Fatalf("short stream status=%d", firstResponse.StatusCode)
	}

	blockedReq, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", bytes.NewReader(shortRequest))
	blockedReq.Header.Set("Authorization", "Bearer client-token")
	blockedReq.Header.Set("Content-Type", "application/json")
	blockedResponse, err := gateway.Client().Do(blockedReq)
	if err != nil {
		t.Fatal(err)
	}
	blockedBody, _ := io.ReadAll(blockedResponse.Body)
	_ = blockedResponse.Body.Close()
	if blockedResponse.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(blockedBody), "all execution slots are busy") {
		t.Fatalf("sticky client should wait on its short target: status=%d body=%s", blockedResponse.StatusCode, blockedBody)
	}
	if longHits.Load() != 0 {
		t.Fatal("sticky short client spilled into the long-context target")
	}

	close(shortRelease)
	streamBody, err := io.ReadAll(firstResponse.Body)
	_ = firstResponse.Body.Close()
	if err != nil || !strings.Contains(string(streamBody), "short-1") || !strings.Contains(string(streamBody), "[DONE]") {
		t.Fatalf("stream was not proxied intact: body=%s err=%v", streamBody, err)
	}

	longRequest := []byte(`{"model":"same-model","stream":true,"max_completion_tokens":1000,"messages":[{"role":"user","content":"long"}],"governor":{"context_tokens":16000,"placement_key":"client-b","placement_policy":"sticky"}}`)
	longReq, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", bytes.NewReader(longRequest))
	longReq.Header.Set("Authorization", "Bearer client-token")
	longReq.Header.Set("Content-Type", "application/json")
	longResponse, err := gateway.Client().Do(longReq)
	if err != nil {
		t.Fatal(err)
	}
	longBody, _ := io.ReadAll(longResponse.Body)
	_ = longResponse.Body.Close()
	if longResponse.StatusCode != http.StatusOK || !strings.Contains(string(longBody), "long-1") {
		t.Fatalf("long stream status=%d body=%s", longResponse.StatusCode, longBody)
	}
	if shortHits.Load() != 1 || longHits.Load() != 1 {
		t.Fatalf("unexpected backend routing: short=%d long=%d", shortHits.Load(), longHits.Load())
	}
}

func TestOpenAIStreamingDisconnectCancelsBackendAndReleasesSlot(t *testing.T) {
	backendCancelled := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"partial\",\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(backendCancelled)
	}))
	defer backend.Close()

	cfg := &Config{}
	cfg.Auth.Credentials = []CredentialConfig{{ID: "client", Token: "client-token", OwnerID: "owner", Plane: "api", Scopes: []string{"inference:submit"}, Adapters: []string{"llamacpp"}, EgressPolicy: "local_only"}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	manager := workloads.NewManager(logger, backing, time.Second)
	manager.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", nil))
	manager.RegisterTarget(workloads.Target{ID: "stream-target", Adapter: "llamacpp", Endpoint: backend.URL, AcceleratorID: "gpu-0", Models: []string{"same-model"}, ContextLimit: 8192, Slots: 1, Enabled: true})
	managerCtx, stopManager := context.WithCancel(context.Background())
	defer stopManager()
	manager.Start(managerCtx)
	srv := NewServer(cfg, logger, backing, nil, nil)
	srv.SetWorkloadManager(manager)
	gateway := httptest.NewServer(srv.Handler())
	defer gateway.Close()

	requestCtx, disconnect := context.WithCancel(context.Background())
	body := []byte(`{"model":"same-model","stream":true,"max_completion_tokens":100,"messages":[{"role":"user","content":"hello"}],"governor":{"context_tokens":1000}}`)
	req, _ := http.NewRequestWithContext(requestCtx, http.MethodPost, gateway.URL+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set("Content-Type", "application/json")
	response, err := gateway.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	disconnect()
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	select {
	case <-backendCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("client disconnect was not propagated to llama.cpp backend")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, err := manager.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 && rows[0].Status == "cancelled" && manager.Targets()[0].Active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream cancellation did not release scheduler state: workloads=%+v targets=%+v", rows, manager.Targets())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNodeCapabilityRefreshUpdatesNamespacedTarget(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	srv.registerAdapterAdvertisements("node-a", []wsproto.AdapterAdvertisement{{
		ID: "llm", Adapter: "llamacpp", Endpoint: "http://node-a:8081", AcceleratorIndex: 0,
		Models: []string{"same-model"}, ContextLimit: 8192, Slots: 4,
		Version: "cap-v1", CapacitySource: "runtime:/slots", CapabilitiesVerified: true,
	}})
	srv.registerAdapterAdvertisements("node-a", []wsproto.AdapterAdvertisement{{
		ID: "llm", Adapter: "llamacpp", Endpoint: "http://node-a:8081", AcceleratorIndex: 0,
		Models: []string{"same-model"}, ContextLimit: 32768, Slots: 1,
		Version: "cap-v2", CapacitySource: "runtime:/slots", CapabilitiesVerified: true,
	}})
	srv.registerAdapterAdvertisements("node-b", []wsproto.AdapterAdvertisement{{
		ID: "llm", Adapter: "llamacpp", Endpoint: "http://node-b:8081", AcceleratorIndex: 0,
		Models: []string{"same-model"}, ContextLimit: 4096, Slots: 8,
	}})

	byID := make(map[string]workloads.Target)
	for _, target := range manager.Targets() {
		byID[target.ID] = target
	}
	refreshed := byID["node-a-llm"]
	if refreshed.ContextLimit != 32768 || refreshed.Slots != 1 || refreshed.CapabilityVersion != "cap-v2" || !refreshed.CapacityVerified {
		t.Fatalf("capability refresh did not replace target profile: %+v", refreshed)
	}
	if other := byID["node-b-llm"]; other.ContextLimit != 4096 || other.Slots != 8 {
		t.Fatalf("node-scoped target identity collided: %+v", other)
	}
}
