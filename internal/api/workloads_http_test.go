package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	checkpointRuntime "vram-governor/internal/runtime"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
	"vram-governor/internal/wsproto"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func testServer(t *testing.T) (*Server, *workloads.Manager, context.CancelFunc) {
	t.Helper()
	cfg := &Config{}
	cfg.Auth.AdminPrivateCIDRs = []string{"127.0.0.0/8"}
	cfg.Auth.Credentials = []CredentialConfig{
		{ID: "alice", Token: "alice-token", OwnerID: "alice-owner", Plane: "ui", Scopes: []string{"workloads:submit", "workloads:read", "workloads:cancel", "workloads:reprioritize", "workloads:approve", "inference:submit", "artifacts:write", "artifacts:read"}, Adapters: []string{"mock", "llamacpp"}, MaxPriority: 10, EgressPolicy: "local_only", ConcurrencyLimit: 2, BudgetCents: 5, PreemptionBudget: 1},
		{ID: "bob", Token: "bob-token", OwnerID: "bob-owner", Plane: "ui", Scopes: []string{"workloads:read", "workloads:submit", "artifacts:read"}, Adapters: []string{"mock"}, MaxPriority: 10},
		{ID: "hosted", Token: "hosted-token", OwnerID: "alice-owner", Plane: "workflow", Scopes: []string{"workloads:submit", "workloads:read", "artifacts:read"}, Adapters: []string{"mock", "openrouter"}, MaxPriority: 10, EgressPolicy: "cloud_allowed"},
		{ID: "admin", Token: "admin-token", OwnerID: "ops", Plane: "admin", Scopes: []string{"*"}, Adapters: []string{"*"}, MaxPriority: 100},
		{ID: "monitor", Token: "monitor-token", OwnerID: "home", Plane: "agent", Scopes: []string{"incidents:create", "incidents:read", "incidents:propose", "incidents:escalate", "agent:events"}, Adapters: []string{"mock", "openrouter"}, MaxPriority: 0, MaxIncidentSeverity: "S1", EgressPolicy: "local_only"},
		{ID: "node-a", Token: "node-a-token", OwnerID: "system", Plane: "node", NodeID: "node-a", Scopes: []string{"node:connect", "node:report"}, Adapters: []string{"mock"}},
	}
	cfg.Agents.LocalVerifierModels = []string{"verifier-9b"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	manager := workloads.NewManager(logger, backing, time.Second)
	artifactStore, err := artifacts.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager.SetArtifactStore(artifactStore)
	manager.RegisterAdapter(workloads.NewMockAdapter())
	manager.RegisterTarget(workloads.Target{ID: "mock", Adapter: "mock", Endpoint: "in-process", Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	srv := NewServer(cfg, logger, backing, nil, nil)
	srv.SetWorkloadManager(manager)
	srv.SetArtifactStore(artifactStore)
	return srv, manager, func() {
		cancel()
		manager.Close()
		srv.Close()
	}
}

func TestControllerResidencyInverseEvidenceAllActions(t *testing.T) {
	actions := []struct{ name, desired, inverse string }{
		{"load_model", "hot_vram", "cold_disk"}, {"unload_model", "cold_disk", "hot_vram"},
		{"warm_model", "warm_ram", "hot_vram"}, {"offload_model", "warm_ram", "cold_disk"},
		{"demote_model", "warm_ram", "hot_vram"}, {"protect_warm_model", "warm_ram", "cold_disk"},
		{"cleanup_warm_model", "cold_disk", "hot_vram"}, {"reverify_warm_model", "warm_ram", "cold_disk"},
	}
	proof := func(action, tier string) map[string]any {
		result := map[string]any{"action": action, "target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": "node-a-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "tier": tier, "resident": tier == "hot_vram", "warm_ram": tier == "warm_ram", "changed": false, "expected_fence": int64(7), "fencing_token": int64(7), "observed_after_fence": int64(7), "original_command_id": "inverse-original-" + action, "original_idempotency_key": "inverse-key-" + action}
		if tier == "cold_disk" {
			result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
			result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
		}
		if tier == "warm_ram" {
			result["warm_model_bytes_verified"], result["released_vram"], result["oracle"] = true, true, "mincore+mlock"
			result["warm_model_bytes"], result["locked_bytes"] = int64(4096), int64(4096)
			if action == "protect_warm_model" {
				result["protected"], result["active_references"] = true, int64(2)
			}
		}
		return result
	}
	for _, action := range actions {
		for _, tier := range []string{action.desired, action.inverse} {
			t.Run(action.name+"-"+tier, func(t *testing.T) {
				args := map[string]any{"target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": "node-a-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": action.desired, "fencing_token": int64(7)}
				if action.name == "protect_warm_model" {
					args["active_references"], args["protected"] = int64(2), true
				}
				original := &domain.NodeCommand{ID: "inverse-original-" + action.name, IdempotencyKey: "inverse-key-" + action.name, NodeID: "node-a", Command: action.name, Args: args}
				if err := validateResidencyMutationEvidence(original, proof(action.name, tier)); err != nil {
					t.Fatalf("controller rejected exact %s proof for %s: %v", tier, action.name, err)
				}
			})
		}
	}
}

func TestControllerResidencyInverseSettleUncertainAllActions(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	actions := []struct{ name, desired, inverse string }{
		{"load_model", "hot_vram", "cold_disk"}, {"unload_model", "cold_disk", "hot_vram"},
		{"warm_model", "warm_ram", "hot_vram"}, {"offload_model", "warm_ram", "cold_disk"},
		{"demote_model", "warm_ram", "hot_vram"}, {"protect_warm_model", "warm_ram", "cold_disk"},
		{"cleanup_warm_model", "cold_disk", "hot_vram"}, {"reverify_warm_model", "warm_ram", "cold_disk"},
	}
	for _, action := range actions {
		for _, tier := range []string{action.desired, action.inverse} {
			t.Run(action.name+"-"+tier, func(t *testing.T) {
				ctx := context.Background()
				args := map[string]any{"target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": "node-a-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": action.desired, "fencing_token": int64(7)}
				if action.name == "protect_warm_model" {
					args["active_references"], args["protected"] = int64(2), true
				}
				now := time.Now().UTC()
				original := &domain.NodeCommand{ID: "settle-" + action.name + "-" + tier, IdempotencyKey: "settle-key-" + action.name + "-" + tier, NodeID: "node-a", Command: action.name, Args: args, Status: domain.NodeCommandSent, Uncertain: true, Attempts: 1, CreatedAt: now, SentAt: &now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
				var err error
				original.Signature, err = wsproto.SignCommand(nodeCommandPayload(original), srv.commandSecret)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err = srv.workloadStore.CreateNodeCommand(ctx, original); err != nil {
					t.Fatal(err)
				}
				observed := map[string]any{"action": action.name, "target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": args["runtime_identity"], "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "tier": tier, "resident": tier == "hot_vram", "warm_ram": tier == "warm_ram", "changed": false, "expected_fence": int64(7), "fencing_token": int64(7), "observed_after_fence": int64(7), "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey}
				if tier == "cold_disk" {
					observed["cleaned"], observed["warm_entry_absent"], observed["warm_release_verified"] = true, true, true
					observed["warm_model_bytes"], observed["locked_bytes"] = int64(0), int64(0)
				}
				if tier == "warm_ram" {
					observed["warm_model_bytes_verified"], observed["released_vram"], observed["oracle"] = true, true, "mincore+mlock"
					observed["warm_model_bytes"], observed["locked_bytes"] = int64(4096), int64(4096)
					if action.name == "protect_warm_model" {
						observed["protected"], observed["active_references"] = true, int64(2)
					}
				}
				_, settleErr := srv.settleUncertainOriginal(ctx, original.ID, observed)
				settled, getErr := srv.workloadStore.GetNodeCommand(ctx, original.ID)
				if getErr != nil || settled == nil || settled.Uncertain || (settled.Status != domain.NodeCommandSucceeded && settled.Status != domain.NodeCommandFailed) {
					t.Fatalf("terminal settle did not converge: err=%v row=%+v settleErr=%v", getErr, settled, settleErr)
				}
				if tier == action.desired {
					if settleErr != nil || settled.Status != domain.NodeCommandSucceeded {
						t.Fatalf("desired proof did not settle success: err=%v row=%+v", settleErr, settled)
					}
				} else if settleErr == nil || settled.Status != domain.NodeCommandFailed {
					t.Fatalf("inverse proof did not settle terminal failure: err=%v row=%+v", settleErr, settled)
				}
			})
		}
	}
}

func TestControllerResidencySettleRejectsBindingAndProofDrift(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"third-tier", func(observed map[string]any) {
			observed["tier"], observed["resident"], observed["warm_ram"] = "warm_ram", false, true
			observed["warm_model_bytes_verified"], observed["released_vram"], observed["oracle"] = true, true, "mincore+mlock"
			observed["warm_model_bytes"], observed["locked_bytes"] = int64(4096), int64(4096)
		}},
		{"resource", func(observed map[string]any) { observed["target_id"] = "other-runtime" }},
		{"runtime", func(observed map[string]any) {
			observed["runtime_identity"] = "other-runtime|llamacpp||runtime-v1|fingerprint"
		}},
		{"original-id", func(observed map[string]any) { observed["original_command_id"] = "other" }},
		{"original-key", func(observed map[string]any) { observed["original_idempotency_key"] = "other" }},
		{"fence", func(observed map[string]any) { observed["expected_fence"] = int64(8) }},
		{"mixed-proof", func(observed map[string]any) {
			observed["tier"], observed["resident"], observed["warm_ram"] = "warm_ram", false, true
			observed["warm_model_bytes_verified"], observed["released_vram"], observed["oracle"] = true, true, "mincore+mlock"
			observed["warm_model_bytes"], observed["locked_bytes"] = int64(4096), int64(4096)
			observed["cleaned"], observed["warm_entry_absent"], observed["warm_release_verified"] = true, true, true
		}},
		{"changed", func(observed map[string]any) { observed["changed"] = true }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			srv, _, cancel := testServer(t)
			defer cancel()
			srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
			now := time.Now().UTC()
			args := map[string]any{"target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": "node-a-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(7)}
			original := &domain.NodeCommand{ID: "drift-original-" + testCase.name, IdempotencyKey: "drift-key-" + testCase.name, NodeID: "node-a", Command: "load_model", Args: args, Status: domain.NodeCommandSent, Uncertain: true, Attempts: 1, CreatedAt: now, SentAt: &now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
			var err error
			original.Signature, err = wsproto.SignCommand(nodeCommandPayload(original), srv.commandSecret)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = srv.workloadStore.CreateNodeCommand(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			observed := map[string]any{"action": "load_model", "target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": args["runtime_identity"], "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": false, "expected_fence": int64(7), "fencing_token": int64(7), "observed_after_fence": int64(7), "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey}
			testCase.edit(observed)
			if _, err := srv.settleUncertainOriginal(context.Background(), original.ID, observed); err == nil {
				t.Fatalf("drifted authoritative observation was accepted: %+v", observed)
			}
			row, getErr := srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
			if getErr != nil || row == nil || !row.Uncertain || row.Status != domain.NodeCommandSent {
				t.Fatalf("rejected observation changed durable uncertainty: err=%v row=%+v", getErr, row)
			}
		})
	}
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
	srv.handleNodeCommandResult(context.Background(), wsproto.CommandResultPayload{ID: firstCommand.ID, NodeID: "node-1", OK: true, Result: map[string]any{"adapters": []wsproto.AdapterAdvertisement{{
		ID: "comfy", Adapter: "comfy", Endpoint: "http://node-1:8188", AcceleratorIndex: 0,
		Models: []string{"video.safetensors"}, Version: "0.34.0", SupportsAcceleratorReclaim: true,
	}}}, CompletedAt: time.Now().UTC()})
	completed, _ := srv.workloadStore.GetNodeCommand(context.Background(), firstCommand.ID)
	if completed.Status != domain.NodeCommandSucceeded {
		t.Fatalf("command result was not persisted: %+v", completed)
	}
	var refreshed *workloads.Target
	for _, target := range srv.workloads.Targets() {
		if target.ID == "node-1-comfy" {
			candidate := target
			refreshed = &candidate
			break
		}
	}
	if refreshed == nil || refreshed.CapabilityVersion != "0.34.0" || len(refreshed.Models) != 1 || len(refreshed.ResidentModels) != 0 {
		t.Fatalf("successful refresh did not immediately apply adapter inventory: %+v", refreshed)
	}
}

func TestAdminNodeCommandUsesCanonicalResidencyEnvelope(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	if _, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-envelope", Name: "node", Observed: domain.Observed{Connectivity: domain.ConnectivityConnected}}); err != nil {
		t.Fatal(err)
	}
	args := wsproto.CanonicalResidencyCommandArgs("node-envelope-runtime", "model", "node-envelope-runtime|llamacpp||runtime-v1|fingerprint", "runtime-v1", domain.CapabilityContractVersion, "hot_vram", 7)
	issue := func(arguments map[string]any) *httptest.ResponseRecorder {
		body := map[string]any{"command": "load_model", "args": arguments}
		req := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-envelope/commands", bytes.NewReader(mustJSON(body)))
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer admin-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "canonical-envelope")
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
		return response
	}
	response := issue(args)
	if response.Code != http.StatusAccepted {
		t.Fatalf("canonical lifecycle command was rejected: %d %s", response.Code, response.Body.String())
	}
	var command domain.NodeCommand
	if err := json.Unmarshal(response.Body.Bytes(), &command); err != nil {
		t.Fatal(err)
	}
	if command.Args["target_kind"] != "llamacpp" || command.Args["max_accelerators_per_workload"] != nil || !wsproto.VerifyCommand(nodeCommandPayload(&command), srv.commandSecret) {
		t.Fatalf("controller did not persist the canonical signed envelope: %+v", command)
	}
	incomplete := map[string]any{}
	for key, value := range args {
		if key != "target_kind" {
			incomplete[key] = value
		}
	}
	if rejected := issue(incomplete); rejected.Code != http.StatusBadRequest {
		t.Fatalf("incomplete lifecycle envelope was accepted: %d %s", rejected.Code, rejected.Body.String())
	}
}

func TestAdminNodeCommandRejectsIrrelevantResidencyArgs(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	if _, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-schema", Name: "node", Observed: domain.Observed{Connectivity: domain.ConnectivityConnected}}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, command, tier, forbidden string
	}{
		{"load-path", "load_model", "hot_vram", "path"},
		{"unload-protection", "unload_model", "cold_disk", "protected"},
		{"warm-unknown", "warm_model", "warm_ram", "unexpected"},
		{"offload-profile", "offload_model", "warm_ram", "profile_id"},
		{"demote-query-fence", "demote_model", "warm_ram", "expected_fence"},
		{"protect-path", "protect_warm_model", "warm_ram", "path"},
		{"cleanup-path", "cleanup_warm_model", "cold_disk", "model_path"},
		{"reverify-protection", "reverify_warm_model", "warm_ram", "protected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := wsproto.CanonicalResidencyCommandArgs("node-schema-runtime", "model", "node-schema-runtime|llamacpp||runtime-v1|fingerprint", "runtime-v1", domain.CapabilityContractVersion, tc.tier, 11)
			args[tc.forbidden] = true
			body := map[string]any{"command": tc.command, "args": args}
			req := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-schema/commands", bytes.NewReader(mustJSON(body)))
			req.RemoteAddr = "127.0.0.1:5000"
			req.Header.Set("Authorization", "Bearer admin-token")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "schema-"+tc.name)
			response := httptest.NewRecorder()
			srv.Handler().ServeHTTP(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("irrelevant %s argument was accepted: %d %s", tc.forbidden, response.Code, response.Body.String())
			}
		})
	}
}

func TestAdminQueryRequiresDurableOriginalCommandLinkage(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	if _, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-query-link", Name: "node", Observed: domain.Observed{Connectivity: domain.ConnectivityConnected}}); err != nil {
		t.Fatal(err)
	}
	args := wsproto.CanonicalResidencyCommandArgs("node-query-runtime", "model", "node-query-runtime|llamacpp||runtime-v1|fingerprint", "runtime-v1", domain.CapabilityContractVersion, "query", 17)
	args["expected_fence"] = int64(17)
	args["observed_after_fence"] = int64(17)
	args["original_command_id"] = "invented-command"
	args["original_idempotency_key"] = "invented-key"
	req := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-query-link/commands", bytes.NewReader(mustJSON(map[string]any{"command": "query_model_state", "args": args})))
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "invented-query")
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invented query linkage was accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestAdminNodeCommandUncertainReplayUsesQueryRecovery(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	if _, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-replay", Name: "node", Observed: domain.Observed{Connectivity: domain.ConnectivityConnected}}); err != nil {
		t.Fatal(err)
	}
	issue := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-replay/commands", bytes.NewBufferString(`{"command":"load_model","args":{"target_kind":"llamacpp","target_id":"target","model":"model","runtime_identity":"node-a|llamacpp|runtime|v1|fingerprint","capability_version":"runtime-v1","capability_revision":"fleet-residency.v1","expected_tier":"hot_vram","fencing_token":7}}`))
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer admin-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "uncertain-http-replay")
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
		return response
	}
	first := issue()
	if first.Code != http.StatusAccepted {
		t.Fatalf("initial command status=%d body=%s", first.Code, first.Body.String())
	}
	var original domain.NodeCommand
	if err := json.Unmarshal(first.Body.Bytes(), &original); err != nil {
		t.Fatal(err)
	}
	observation, _ := json.Marshal(map[string]any{"state": "unknown"})
	if _, err := srv.workloadStore.PromoteNodeCommandUncertain(context.Background(), original.ID, original.NodeID, observation, "side effect uncertain"); err != nil {
		t.Fatal(err)
	}
	replay := issue()
	if replay.Code != http.StatusAccepted {
		t.Fatalf("uncertain replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	var replayed domain.NodeCommand
	if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.ID != original.ID || !replayed.Uncertain || replayed.Status != domain.NodeCommandSent || replayed.Attempts != original.Attempts {
		t.Fatalf("uncertain replay changed durable mutation: original=%+v replay=%+v", original, replayed)
	}
	deadline := time.Now().Add(time.Second)
	firstRecoveryAttempts := 0
	for time.Now().Before(deadline) {
		current, _ := srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
		if current != nil && current.RecoveryAttempts > 0 {
			firstRecoveryAttempts = current.RecoveryAttempts
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	current, _ := srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
	if firstRecoveryAttempts == 0 {
		t.Fatalf("uncertain replay did not trigger autonomous durable recovery: %+v", current)
	}
	backing, ok := srv.nodes.(store.Store)
	if !ok {
		t.Fatal("test backing store is not restartable")
	}
	srv.Close()
	restarted := NewServer(srv.cfg, srv.log, backing, nil, nil)
	defer restarted.Close()
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		current, _ = backing.GetNodeCommand(context.Background(), original.ID)
		if current != nil && current.RecoveryAttempts > firstRecoveryAttempts {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("restart did not resume durable uncertain recovery: %+v", current)
}

func TestControllerRejectsForgedAuthoritativeObservation(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	wsCtx, cancelWS := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWS()
	connection, _, err := websocket.Dial(wsCtx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	ready := true
	if err := wsjson.Write(wsCtx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(wsproto.RegisterPayload{NodeID: "node-a", Ready: &ready})}); err != nil {
		t.Fatal(err)
	}
	for {
		var ack wsproto.Envelope
		if err := wsjson.Read(wsCtx, connection, &ack); err != nil {
			t.Fatalf("node websocket registration: %v", err)
		}
		if ack.Type == wsproto.MsgAck {
			break
		}
	}
	commandBody := map[string]any{"command": "load_model", "args": map[string]any{
		"target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": "node-a-runtime|llamacpp||runtime-v1|fingerprint",
		"capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion,
		"expected_tier": "hot_vram", "fencing_token": int64(7),
	}}
	request := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-a/commands", bytes.NewBuffer(mustJSON(commandBody)))
	request.RemoteAddr = "127.0.0.1:5000"
	request.Header.Set("Authorization", "Bearer admin-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "forged-original-key")
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("controller command creation status=%d body=%s", response.Code, response.Body.String())
	}
	var originalValue domain.NodeCommand
	if err := json.Unmarshal(response.Body.Bytes(), &originalValue); err != nil {
		t.Fatal(err)
	}
	original := &originalValue
	if !wsproto.VerifyCommand(nodeCommandPayload(original), srv.commandSecret) {
		t.Fatalf("controller-created original command signature is invalid: %+v", original)
	}
	// The original must cross the real controller websocket before uncertainty
	// is introduced. Read the signed frame as a node client and verify its
	// exact command payload/args rather than fabricating a durable row.
	commandReadCtx, commandReadCancel := context.WithTimeout(wsCtx, time.Second)
	defer commandReadCancel()
	var originalFrame wsproto.CommandPayload
	for {
		var frame wsproto.Envelope
		if err := wsjson.Read(commandReadCtx, connection, &frame); err != nil {
			t.Fatalf("read controller-delivered original command: %v", err)
		}
		if frame.Type != wsproto.MsgCommand {
			continue
		}
		if err := json.Unmarshal(frame.Payload, &originalFrame); err != nil {
			t.Fatal(err)
		}
		if originalFrame.ID != original.ID {
			continue
		}
		if !wsproto.VerifyCommand(originalFrame, srv.commandSecret) || !reflect.DeepEqual(originalFrame.Args, original.Args) {
			t.Fatalf("controller-delivered original command was altered or unsigned: %+v", originalFrame)
		}
		break
	}
	if err := wsjson.Write(wsCtx, connection, wsproto.Envelope{Type: wsproto.MsgCommandResult, Payload: mustJSON(wsproto.CommandResultPayload{
		ID: original.ID, NodeID: original.NodeID, OK: false, Uncertain: true,
		Result: map[string]any{"state": "unknown"}, Error: "side effect crossed boundary; state uncertain", CompletedAt: time.Now().UTC(),
	})}); err != nil {
		t.Fatalf("uncertain node result did not cross websocket: %v", err)
	}
	uncertainDeadline := time.Now().Add(time.Second)
	for time.Now().Before(uncertainDeadline) {
		current, getErr := srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
		if getErr == nil && current.Uncertain {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	uncertainOriginal, getErr := srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
	if getErr != nil || !uncertainOriginal.Uncertain {
		t.Fatalf("real uncertain node result was not retained: row=%+v err=%v", uncertainOriginal, getErr)
	}
	readSignedCommand := func(expected *domain.NodeCommand) {
		t.Helper()
		readCtx, readCancel := context.WithTimeout(wsCtx, time.Second)
		defer readCancel()
		for {
			var frame wsproto.Envelope
			if err := wsjson.Read(readCtx, connection, &frame); err != nil {
				t.Fatalf("read controller-delivered %s query: %v", expected.Command, err)
			}
			if frame.Type != wsproto.MsgCommand {
				continue
			}
			var wire wsproto.CommandPayload
			if err := json.Unmarshal(frame.Payload, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.ID != expected.ID {
				continue
			}
			var canonicalExpected map[string]any
			encodedExpected, _ := json.Marshal(expected.Args)
			_ = json.Unmarshal(encodedExpected, &canonicalExpected)
			if !wsproto.VerifyCommand(wire, srv.commandSecret) || !reflect.DeepEqual(wire.Args, canonicalExpected) {
				t.Fatalf("delivered %s query was altered or unsigned: %+v", expected.Command, wire)
			}
			return
		}
	}
	originalFence, fenceErr := observationFence(original.Args["fencing_token"])
	if fenceErr != nil {
		t.Fatal(fenceErr)
	}
	queryArgs := map[string]any{"target_kind": "llamacpp", "target_id": original.Args["target_id"], "model": original.Args["model"], "runtime_identity": original.Args["runtime_identity"], "capability_version": original.Args["capability_version"], "capability_revision": original.Args["capability_revision"], "expected_tier": "query", "fencing_token": originalFence, "expected_fence": originalFence, "observed_after_fence": originalFence, "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey}
	baseObserved := map[string]any{"action": "load_model", "changed": false, "target_kind": queryArgs["target_kind"], "target_id": queryArgs["target_id"], "model": queryArgs["model"], "runtime_identity": queryArgs["runtime_identity"], "capability_version": queryArgs["capability_version"], "capability_revision": queryArgs["capability_revision"], "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey, "expected_fence": originalFence, "fencing_token": originalFence, "observed_after_fence": originalFence, "resident": true, "warm_ram": false, "tier": "hot_vram"}
	variants := []struct {
		name   string
		result func(map[string]any) map[string]any
	}{
		{name: "target-kind", result: func(value map[string]any) map[string]any { value["target_kind"] = "comfy"; return value }},
		{name: "target-id", result: func(value map[string]any) map[string]any { value["target_id"] = "other-runtime"; return value }},
		{name: "model", result: func(value map[string]any) map[string]any { value["model"] = "other-model"; return value }},
		{name: "runtime", result: func(value map[string]any) map[string]any { value["runtime_identity"] = "drifted-runtime"; return value }},
		{name: "capability", result: func(value map[string]any) map[string]any { value["capability_version"] = "runtime-drift"; return value }},
		{name: "capability-revision", result: func(value map[string]any) map[string]any { value["capability_revision"] = "future.v9"; return value }},
		{name: "original-id", result: func(value map[string]any) map[string]any {
			value["original_command_id"] = "other-command"
			return value
		}},
		{name: "original-key", result: func(value map[string]any) map[string]any {
			value["original_idempotency_key"] = "other-key"
			return value
		}},
		{name: "fencing-token-higher", result: func(value map[string]any) map[string]any { value["fencing_token"] = int64(8); return value }},
		{name: "fencing-token-lower", result: func(value map[string]any) map[string]any { value["fencing_token"] = int64(6); return value }},
		{name: "fencing-token-missing", result: func(value map[string]any) map[string]any { delete(value, "fencing_token"); return value }},
		{name: "observed-fence-higher", result: func(value map[string]any) map[string]any { value["observed_after_fence"] = int64(8); return value }},
		{name: "observed-fence-lower", result: func(value map[string]any) map[string]any { value["observed_after_fence"] = int64(6); return value }},
		{name: "observed-fence-missing", result: func(value map[string]any) map[string]any { delete(value, "observed_after_fence"); return value }},
		{name: "tier", result: func(value map[string]any) map[string]any { value["tier"] = "unknown"; return value }},
		{name: "tier-missing", result: func(value map[string]any) map[string]any { delete(value, "tier"); return value }},
	}
	for _, variant := range variants {
		observed := cloneTestMap(baseObserved)
		if variant.result != nil {
			observed = variant.result(observed)
		}
		query, err := srv.issueAuthoritativeQuery(context.Background(), original)
		if err != nil {
			t.Fatal(err)
		}
		if !wsproto.VerifyCommand(nodeCommandPayload(query), srv.commandSecret) || !reflect.DeepEqual(query.Args, queryArgs) {
			t.Fatalf("controller-issued query was not a valid unchanged signed linkage: %+v", query)
		}
		queryFingerprint := wsproto.ResidencyCommandFingerprint(query.NodeID, query.Command, query.IdempotencyKey, query.Args)
		observed["node_id"], observed["command_id"], observed["idempotency_key"] = query.NodeID, query.ID, query.IdempotencyKey
		observed["command_fingerprint"], observed["fingerprint"], observed["reconciled"] = queryFingerprint, queryFingerprint, false
		readSignedCommand(query)
		if err := wsjson.Write(wsCtx, connection, wsproto.Envelope{Type: wsproto.MsgCommandResult, Payload: mustJSON(wsproto.CommandResultPayload{ID: query.ID, NodeID: query.NodeID, OK: true, Result: observed, CompletedAt: time.Now().UTC()})}); err != nil {
			t.Fatalf("forged %s result did not cross node websocket: %v", variant.name, err)
		}
		var storedQuery *domain.NodeCommand
		var queryErr error
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			storedQuery, queryErr = srv.workloadStore.GetNodeCommand(context.Background(), query.ID)
			if queryErr == nil && storedQuery.Status == domain.NodeCommandFailed {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if queryErr != nil || storedQuery.Status != domain.NodeCommandFailed {
			t.Fatalf("forged %s observation was not rejected as recoverable query failure: row=%+v err=%v", variant.name, storedQuery, queryErr)
		}
		storedOriginal, getErr := srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
		if getErr != nil || !storedOriginal.Uncertain {
			t.Fatalf("forged %s observation settled original: row=%+v err=%v", variant.name, storedOriginal, getErr)
		}
	}
	// A fully valid linked query settles the same pending original. Replay the
	// exact result afterward and prove the durable observation/revision is
	// unchanged, exercising idempotency rather than a forged query envelope.
	exactQuery, err := srv.issueAuthoritativeQuery(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	if !wsproto.VerifyCommand(nodeCommandPayload(exactQuery), srv.commandSecret) || !reflect.DeepEqual(exactQuery.Args, queryArgs) {
		t.Fatalf("exact controller-issued query was not a valid unchanged signed linkage: %+v", exactQuery)
	}
	readSignedCommand(exactQuery)
	exactObserved := cloneTestMap(baseObserved)
	exactFingerprint := wsproto.ResidencyCommandFingerprint(exactQuery.NodeID, exactQuery.Command, exactQuery.IdempotencyKey, exactQuery.Args)
	exactObserved["node_id"], exactObserved["command_id"], exactObserved["idempotency_key"] = exactQuery.NodeID, exactQuery.ID, exactQuery.IdempotencyKey
	exactObserved["command_fingerprint"], exactObserved["fingerprint"], exactObserved["reconciled"] = exactFingerprint, exactFingerprint, false
	exactResult := wsproto.CommandResultPayload{ID: exactQuery.ID, NodeID: exactQuery.NodeID, OK: true, Result: exactObserved, CompletedAt: time.Now().UTC()}
	if err := wsjson.Write(wsCtx, connection, wsproto.Envelope{Type: wsproto.MsgCommandResult, Payload: mustJSON(exactResult)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	var settledOriginal, settledQuery *domain.NodeCommand
	for time.Now().Before(deadline) {
		settledOriginal, _ = srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
		settledQuery, _ = srv.workloadStore.GetNodeCommand(context.Background(), exactQuery.ID)
		if settledOriginal != nil && !settledOriginal.Uncertain && settledOriginal.Status == domain.NodeCommandSucceeded && settledQuery != nil && settledQuery.Status == domain.NodeCommandSucceeded {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if settledOriginal == nil || settledOriginal.Uncertain || settledOriginal.Status != domain.NodeCommandSucceeded || settledQuery == nil || settledQuery.Status != domain.NodeCommandSucceeded {
		t.Fatalf("valid authoritative result did not settle pending original: original=%+v query=%+v", settledOriginal, settledQuery)
	}
	settledRevision := settledOriginal.Revision
	if err := wsjson.Write(wsCtx, connection, wsproto.Envelope{Type: wsproto.MsgCommandResult, Payload: mustJSON(exactResult)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	replayedOriginal, err := srv.workloadStore.GetNodeCommand(context.Background(), original.ID)
	if err != nil || replayedOriginal.Revision != settledRevision || replayedOriginal.Status != domain.NodeCommandSucceeded || replayedOriginal.Uncertain {
		t.Fatalf("exact authoritative replay changed durable settlement: row=%+v err=%v", replayedOriginal, err)
	}
}

func cloneTestMap(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
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

func TestOpenAIModelsReportsRuntimeCapacityWithinModelCardLimit(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	now := time.Now().UTC()
	for _, node := range []*domain.Node{
		{ID: "node-a", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now}, Accelerators: []domain.Accelerator{{ID: "gpu-a", NodeID: "node-a"}}},
		{ID: "node-b", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now}, Accelerators: []domain.Accelerator{{ID: "gpu-b", NodeID: "node-b"}}},
	} {
		if _, err := srv.nodes.UpsertNode(context.Background(), node); err != nil {
			t.Fatal(err)
		}
	}
	manager.RegisterTarget(workloads.Target{
		ID: "card-a", Adapter: "llamacpp", AcceleratorID: "gpu-a", Models: []string{"capacity-model"}, ResidentModels: []string{"capacity-model"},
		ContextLimit: 8192, Slots: 4, Active: 1, ActiveRuntimeProfile: "ctx-8k", SupportsRuntimeProfileSwitch: true, Enabled: true,
		RuntimeProfiles: []workloads.RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}},
	})
	manager.RegisterTarget(workloads.Target{
		ID: "card-b", Adapter: "llamacpp", AcceleratorID: "gpu-b", Models: []string{"capacity-model"}, ResidentModels: []string{"capacity-model"},
		ContextLimit: 16384, Slots: 2, ActiveRuntimeProfile: "ctx-16k", Enabled: true,
	})
	response := request(t, srv.Handler(), http.MethodGet, "/v1/models", "admin-token", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("models status=%d body=%s", response.Code, response.Body.String())
	}
	var catalog struct {
		Data []struct {
			ID       string `json:"id"`
			Governor struct {
				AvailableContextLimits  []int                              `json:"available_context_limits"`
				ActiveContextLimits     []int                              `json:"active_context_limits"`
				CapacityProfiles        []workloads.RuntimeCapacityProfile `json:"capacity_profiles"`
				CurrentSlots            int                                `json:"current_slots"`
				CurrentlyAvailableSlots int                                `json:"currently_available_slots"`
				MaximumParallelSlots    int                                `json:"maximum_parallel_slots"`
				MaxAccelerators         int                                `json:"max_accelerators"`
				ProfileSwitchSupported  bool                               `json:"profile_switch_supported"`
			} `json:"governor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	for _, model := range catalog.Data {
		if model.ID != "capacity-model" {
			continue
		}
		g := model.Governor
		if g.MaxAccelerators != 1 || g.CurrentSlots != 4 || g.CurrentlyAvailableSlots != 4 || g.MaximumParallelSlots != 4 || !g.ProfileSwitchSupported {
			t.Fatalf("capacity is not constrained to the configured one-card ceiling: %+v", g)
		}
		if fmt.Sprint(g.AvailableContextLimits) != "[8192 16384 32768]" || fmt.Sprint(g.ActiveContextLimits) != "[8192 16384]" || len(g.CapacityProfiles) != 3 {
			t.Fatalf("runtime profiles were not disclosed: %+v", g)
		}
		return
	}
	t.Fatal("capacity-model missing from catalog")
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

func TestDiscoveredTargetReceivesLiveAcceleratorCapacity(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	_, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{
		ID:           "node-capacity",
		Accelerators: []domain.Accelerator{{ID: "node-capacity-gpu0", NodeID: "node-capacity", VRAMTotalMB: 24576}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.registerAdapterAdvertisements("node-capacity", []wsproto.AdapterAdvertisement{{
		ID: "short", Adapter: "llamacpp", Endpoint: "http://node-capacity:11435", AcceleratorIndex: 0,
		Models: []string{"same-model"}, ContextLimit: 2048, Slots: 4,
	}})
	for _, target := range manager.Targets() {
		if target.ID == "node-capacity-short" {
			if target.AcceleratorVRAMMB != 24576 {
				t.Fatalf("target did not inherit physical VRAM capacity: %+v", target)
			}
			return
		}
	}
	t.Fatal("discovered target was not registered")
}

func TestCapabilityRefreshRetiresRemovedNodeRoute(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	srv.registerAdapterAdvertisements("node-a", []wsproto.AdapterAdvertisement{
		{ID: "old", Adapter: "llamacpp", Endpoint: "http://node-a:11434", AcceleratorIndex: 0},
		{ID: "current", Adapter: "llamacpp", Endpoint: "http://node-a:11435", AcceleratorIndex: 0},
	})
	srv.registerAdapterAdvertisements("node-a", []wsproto.AdapterAdvertisement{
		{ID: "current", Adapter: "llamacpp", Endpoint: "http://node-a:11435", AcceleratorIndex: 0},
	})
	for _, target := range manager.Targets() {
		if target.ID == "node-a-old" {
			t.Fatalf("removed node route survived capability reconciliation: %+v", target)
		}
	}
}

type publicCheckpointPolicyFixture struct {
	target    workloads.Target
	backing   *store.MemoryStore
	manager   *workloads.Manager
	server    *Server
	gateway   *httptest.Server
	backend   *httptest.Server
	backendMu sync.Mutex
	bodies    []map[string]any
}

func publicCheckpointProof(target workloads.Target) checkpointRuntime.CheckpointCapabilityProof {
	now := time.Now().UTC()
	return checkpointRuntime.CheckpointCapabilityProof{
		ProofVersion: checkpointRuntime.CheckpointCapabilityProofVersion, ModelAlias: "matrix-model-alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true,
		BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true,
		ProvenAt: now, ExpiresAt: now.Add(time.Hour), NodeID: target.NodeID, TargetID: target.ID,
		ModelFingerprint: target.ModelFingerprint, RuntimeIdentity: target.RuntimeIdentity,
		ProfileFingerprint: "matrix-profile", ContextLimit: target.ContextLimit, SlotID: 0,
		Generation: target.CapabilityGeneration, OldFence: 1, NewFence: 2, SavedTokens: 8,
		ReusedTokens: 7, EvidenceID: "matrix-evidence", Signature: "matrix-signature",
		Digest: "matrix-digest", SnapshotDigest: "sha256:matrix-snapshot", SnapshotBytes: 1,
		AcceleratorID: target.AcceleratorID, Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef",
	}
}

func newPublicCheckpointPolicyFixture(t *testing.T, proof checkpointRuntime.CheckpointCapabilityProof, policy domain.ResidencyPolicyMode) *publicCheckpointPolicyFixture {
	t.Helper()
	fixture := &publicCheckpointPolicyFixture{}
	fixture.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fixture.backendMu.Lock()
		fixture.bodies = append(fixture.bodies, body)
		fixture.backendMu.Unlock()
		if stream, _ := body["stream"].(bool); stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"id\":\"matrix\",\"choices\":[{\"delta\":{\"content\":\"matrix\"}}]}\n\ndata: [DONE]\n\n")
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "matrix", "choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": "matrix"}, "finish_reason": "stop"}},
			"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	}))
	backing := store.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := workloads.NewManager(logger, backing, time.Second)
	adapter := workloads.NewHTTPAdapter("llamacpp", "llama", fixture.backend.Client())
	snapshotStore, err := workloads.NewSnapshotStore(t.TempDir(), 1<<20, 16)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := workloads.NewCheckpointCoordinator(nil, snapshotStore, proof)
	coordinator.Operations = backing
	adapter.SetLLMCheckpointCoordinator(coordinator)
	manager.RegisterAdapter(adapter)
	manager.SetNodeStore(backing)
	if _, err := backing.UpsertNode(context.Background(), &domain.Node{ID: "matrix-node", Accelerators: []domain.Accelerator{{ID: "matrix-gpu", NodeID: "matrix-node", VRAMFreeMB: 16384}}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: time.Now().UTC()}, Desired: domain.Desired{SchedulingEnabled: true}, SchedulingState: domain.SchedulingEnabled}); err != nil {
		t.Fatal(err)
	}
	matrixControl := func(_ context.Context, _ string, command string, _ map[string]any, _ string) (map[string]any, error) {
		if command == "checkpoint_slot_assign" {
			return map[string]any{"slot_id": 0}, nil
		}
		return map[string]any{}, nil
	}
	manager.SetNodeControl(matrixControl)
	target := workloads.Target{
		ID: "matrix-target", NodeID: "matrix-node", Adapter: "llamacpp", Endpoint: fixture.backend.URL,
		AcceleratorID: "matrix-gpu", Models: []string{"matrix-model"}, ResidentModels: []string{"matrix-model"},
		ContextLimit: 4096, Slots: 4, CapabilityVersion: "matrix-runtime-v1", RuntimeIdentity: "matrix-runtime",
		CapabilityRevision: domain.CapabilityContractVersion, CapabilityGeneration: 1, ModelFingerprint: "matrix-model-fp",
		ActiveRuntimeProfile: "matrix-profile", CapacitySource: "test:/slots", CapacityVerified: true, Enabled: true, ResidencyPolicy: policy,
		CheckpointProof: proof,
	}
	fixture.target, fixture.backing, fixture.manager = target, backing, manager
	manager.RegisterTarget(target)
	cfg := &Config{}
	cfg.Auth.Credentials = []CredentialConfig{{
		ID: "matrix", Token: "matrix-token", OwnerID: "matrix-owner", Plane: "api",
		Scopes:   []string{"inference:submit", "workloads:submit", "workloads:read", "workloads:cancel"},
		Adapters: []string{"llamacpp"}, MaxPriority: 20, PreemptionBudget: 2, EgressPolicy: "local_only",
	}}
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	fixture.server = NewServer(cfg, logger, backing, nil, nil)
	fixture.server.SetWorkloadManager(manager)
	// SetWorkloadManager wires the production signed controller channel; this
	// matrix fixture supplies a deterministic in-process command result while
	// the native E2E covers the real websocket/auth/signature path.
	manager.SetNodeControl(matrixControl)
	fixture.gateway = httptest.NewServer(fixture.server.Handler())
	t.Cleanup(func() {
		cancel()
		manager.Close()
		fixture.server.Close()
		fixture.gateway.Close()
		fixture.backend.Close()
	})
	return fixture
}

func (f *publicCheckpointPolicyFixture) setTargetProof(proof checkpointRuntime.CheckpointCapabilityProof, policy domain.ResidencyPolicyMode) {
	target := f.target
	target.CheckpointProof = proof
	target.ResidencyPolicy = policy
	f.target = target
	f.manager.RegisterTarget(target)
}

func publicCheckpointChatBody(stream bool, controls map[string]any) map[string]any {
	governor := map[string]any{"adapter": "llamacpp", "context_tokens": 3000}
	for key, value := range controls {
		governor[key] = value
	}
	return map[string]any{
		"model": "matrix-model", "messages": []map[string]string{{"role": "user", "content": "matrix"}},
		"stream": stream, "max_tokens": 16, "governor": governor,
	}
}

func publicCheckpointControls(missing string, budget int) map[string]any {
	controls := map[string]any{
		"checkpointable": true, "interruption_consent": true, "recoverable": true,
		"preemption_budget": budget,
	}
	if missing == "preemption_budget" {
		controls[missing] = 0
	} else if missing != "" {
		controls[missing] = false
	}
	return controls
}

func publicCheckpointNewestRow(t *testing.T, backing *store.MemoryStore, before int) *domain.Workload {
	t.Helper()
	rows, err := backing.ListWorkloads(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) <= before {
		t.Fatalf("expected a new public workload: before=%d rows=%d", before, len(rows))
	}
	var newest *domain.Workload
	for _, row := range rows {
		if newest == nil || row.CreatedAt.After(newest.CreatedAt) {
			newest = row
		}
	}
	if newest == nil {
		t.Fatal("newest public workload is nil")
	}
	return newest
}

func publicCheckpointPOST(t *testing.T, fixture *publicCheckpointPolicyFixture, path string, body any) (int, []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, fixture.gateway.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer matrix-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := fixture.gateway.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func TestOpenAIPublicCheckpointPolicyMatrix(t *testing.T) {
	baseTarget := workloads.Target{ID: "matrix-target", NodeID: "matrix-node", Adapter: "llamacpp", AcceleratorID: "matrix-gpu", ContextLimit: 4096, CapabilityGeneration: 1, ModelFingerprint: "matrix-model-fp", RuntimeIdentity: "matrix-runtime"}
	validProof := publicCheckpointProof(baseTarget)
	fixture := newPublicCheckpointPolicyFixture(t, validProof, domain.ResidencyAuto)

	for _, missing := range []string{"checkpointable", "interruption_consent", "recoverable", "preemption_budget"} {
		t.Run("missing-"+missing+"-locks", func(t *testing.T) {
			beforeRows, err := fixture.backing.ListWorkloads(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			status, body := publicCheckpointPOST(t, fixture, "/v1/chat/completions", publicCheckpointChatBody(false, publicCheckpointControls(missing, 1)))
			if status != http.StatusOK {
				t.Fatalf("public nonstream missing %s status=%d body=%s", missing, status, body)
			}
			row := publicCheckpointNewestRow(t, fixture.backing, len(beforeRows))
			if row.Request.Disruption != domain.DisruptionLocked || row.Request.InterruptionConsent || row.Request.Recoverable || row.Request.InteractiveStream {
				t.Fatalf("missing %s was not locked/nonpreemptible: %+v", missing, row.Request)
			}
		})
	}

	status, body := publicCheckpointPOST(t, fixture, "/v1/chat/completions", publicCheckpointChatBody(false, publicCheckpointControls("", 1)))
	if status != http.StatusOK {
		t.Fatalf("all-controls nonstream status=%d body=%s", status, body)
	}
	rows, err := fixture.backing.ListWorkloads(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	allControls := publicCheckpointNewestRow(t, fixture.backing, len(rows)-1)
	if allControls.Request.Disruption != domain.DisruptionCheckpointable || !allControls.Request.InterruptionConsent || !allControls.Request.Recoverable || allControls.Request.PreemptionBudget != 1 {
		t.Fatalf("valid proof did not preserve checkpointable opt-in: %+v", allControls.Request)
	}

	streamBefore, err := fixture.backing.ListWorkloads(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status, body = publicCheckpointPOST(t, fixture, "/v1/chat/completions", publicCheckpointChatBody(true, publicCheckpointControls("", 1)))
	if status != http.StatusOK || !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("all-controls stream status=%d body=%s", status, body)
	}
	streamRow := publicCheckpointNewestRow(t, fixture.backing, len(streamBefore))
	if streamRow.Request.Disruption != domain.DisruptionCheckpointable || !streamRow.Request.InteractiveStream {
		t.Fatalf("stream policy was not checkpointable: %+v", streamRow.Request)
	}

	status, body = publicCheckpointPOST(t, fixture, "/v1/chat/completions", publicCheckpointChatBody(false, publicCheckpointControls("", 99)))
	if status != http.StatusOK {
		t.Fatalf("principal budget request status=%d body=%s", status, body)
	}
	rows, err = fixture.backing.ListWorkloads(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	budgetRow := rows[len(rows)-1]
	if budgetRow.Request.Disruption != domain.DisruptionCheckpointable || budgetRow.Request.PreemptionBudget != 2 {
		t.Fatalf("principal max budget was not enforced without widening opt-in: %+v", budgetRow.Request)
	}

	directPayload := map[string]any{
		"adapter": "llamacpp", "workload_type": "llm.chat", "payload": publicCheckpointChatBody(false, map[string]any{}),
		"disruption": "checkpointable", "interruption_consent": true, "recoverable": true,
		"preemption_budget": 1, "queue_policy": "wait", "egress": "local_only",
		"bounds": map[string]any{"context_tokens": 3000, "max_output": 16},
	}
	status, body = publicCheckpointPOST(t, fixture, "/api/v1/workloads", directPayload)
	if status != http.StatusCreated && status != http.StatusAccepted {
		t.Fatalf("direct workload status=%d body=%s", status, body)
	}
	var directRow domain.Workload
	if err := json.Unmarshal(body, &directRow); err != nil {
		t.Fatal(err)
	}
	if directRow.Request.Disruption != domain.DisruptionCheckpointable || !directRow.Request.InterruptionConsent || !directRow.Request.Recoverable {
		t.Fatalf("direct route lost checkpointable controls: %+v", directRow.Request)
	}

	status, body = publicCheckpointPOST(t, fixture, "/api/v1/workloads/preview", directPayload)
	if status != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", status, body)
	}
	var preview domain.PlacementPreview
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if len(preview.Candidates) != 1 || preview.Recommended != fixture.target.ID || !preview.Candidates[0].SessionCheckpointable {
		t.Fatalf("valid proof was not surfaced by preview: %+v", preview)
	}

	fixture.backendMu.Lock()
	for _, backendBody := range fixture.bodies {
		if _, leaked := backendBody["governor"]; leaked {
			fixture.backendMu.Unlock()
			t.Fatalf("backend received governor controls: %+v", backendBody)
		}
	}
	fixture.backendMu.Unlock()

	invalidProofs := []struct {
		name  string
		proof checkpointRuntime.CheckpointCapabilityProof
	}{
		{name: "stale", proof: func() checkpointRuntime.CheckpointCapabilityProof {
			p := validProof
			p.ExpiresAt = time.Now().Add(-time.Minute)
			return p
		}()},
		{name: "revoked", proof: func() checkpointRuntime.CheckpointCapabilityProof { p := validProof; p.Verified = false; return p }()},
		{name: "mismatched", proof: func() checkpointRuntime.CheckpointCapabilityProof {
			p := validProof
			p.TargetID = "other-target"
			return p
		}()},
	}
	for _, invalid := range invalidProofs {
		t.Run("proof-"+invalid.name, func(t *testing.T) {
			fixture.setTargetProof(invalid.proof, domain.ResidencyAuto)
			status, body := publicCheckpointPOST(t, fixture, "/v1/chat/completions", publicCheckpointChatBody(false, publicCheckpointControls("", 1)))
			if status != http.StatusBadRequest || !strings.Contains(strings.ToLower(string(body)), "checkpoint") {
				t.Fatalf("invalid %s proof was accepted: status=%d body=%s", invalid.name, status, body)
			}
			status, body = publicCheckpointPOST(t, fixture, "/api/v1/workloads/preview", directPayload)
			if status != http.StatusOK {
				t.Fatalf("invalid %s preview status=%d body=%s", invalid.name, status, body)
			}
			var preview domain.PlacementPreview
			if err := json.Unmarshal(body, &preview); err != nil {
				t.Fatal(err)
			}
			if len(preview.Candidates) != 1 || preview.Candidates[0].Eligible || preview.Candidates[0].SessionCheckpointable {
				t.Fatalf("invalid %s proof remained eligible/checkpointable in preview: %+v", invalid.name, preview)
			}
		})
	}

	fixture.setTargetProof(validProof, domain.ResidencyAuto)
	for _, policy := range []domain.ResidencyPolicyMode{domain.ResidencyPinned, domain.ResidencyManual, domain.ResidencyOff} {
		t.Run("residency-"+string(policy), func(t *testing.T) {
			fixture.setTargetProof(validProof, policy)
			status, body := publicCheckpointPOST(t, fixture, "/v1/chat/completions", publicCheckpointChatBody(false, publicCheckpointControls("", 1)))
			if status != http.StatusOK {
				t.Fatalf("%s policy status=%d body=%s", policy, status, body)
			}
			rows, err := fixture.backing.ListWorkloads(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			row := rows[len(rows)-1]
			if row.Request.Disruption != domain.DisruptionCheckpointable {
				t.Fatalf("%s policy changed explicit caller consent unexpectedly: %+v", policy, row.Request)
			}
		})
	}
}
