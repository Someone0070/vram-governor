package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/wsproto"
)

func TestRuntimeManifestFingerprintExcludesMutableResidencyStatus(t *testing.T) {
	first := json.RawMessage(`{"data":[{"id":"alpha","status":"loaded","meta":{"build":"x"}},{"id":"beta","status":"unloaded"}]}`)
	second := json.RawMessage(`{"data":[{"id":"beta","status":"loaded","meta":{"build":"different-runtime-state"}},{"id":"alpha","status":"unloaded"}]}`)
	_, _, _, materialA, err := llamaModels(first)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, materialB, err := llamaModels(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(materialA, materialB) {
		t.Fatalf("mutable model status changed runtime identity: %s != %s", materialA, materialB)
	}
}

func TestLlamaModelStatusRequiresAuthoritativeString(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		raw   string
		state llamaState
	}{
		{"loaded", `"loaded"`, llamaStateLoaded},
		{"unloaded", `"unloaded"`, llamaStateUnloaded},
		{"loading", `"loading"`, llamaStateTransitional},
		{"unknown", `"mystery"`, llamaStateUnknown},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			state, _, err := llamaModelState(json.RawMessage(fixture.raw))
			if err != nil || state != fixture.state {
				t.Fatalf("status classification mismatch: state=%q err=%v", state, err)
			}
		})
	}
	if _, _, err := llamaModelState(json.RawMessage(`{"value":"loaded"}`)); err == nil {
		t.Fatal("object status was accepted as authoritative")
	}
	if state, err := llamaModelStateFromBody(json.RawMessage(`{"data":[]}`), "missing"); err != nil || state != llamaStateUnloaded {
		t.Fatalf("valid absent model was not treated as unloaded: state=%q err=%v", state, err)
	}
}

func TestLlamaRouterAbsentModelIsAuthoritativeUnloaded(t *testing.T) {
	state, err := llamaModelStateFromBody(json.RawMessage(`{"data":[{"id":"other","status":"unloaded"}]}`), "missing")
	if err != nil || state != llamaStateUnloaded {
		t.Fatalf("valid nonmatching model list did not prove absence as unloaded: state=%q err=%v", state, err)
	}
}

func TestLlamaRouterRejectsMalformedNonmatchingEntry(t *testing.T) {
	for _, body := range []string{
		`{"data":[{"id":"other","status":123}]}`,
		`{"data":[{"status":"unloaded"}]}`,
		`{"data":[{"id":"other","status":"ready"}]}`,
		`{"data":[{"id":"other","status":"Loaded"}]}`,
		`{"data":[{"id":"other","status":" unloaded"}]}`,
	} {
		if _, err := llamaModelStateFromBody(json.RawMessage(body), "missing"); err == nil {
			t.Fatalf("malformed/noncanonical nonmatching model entry was accepted: %s", body)
		}
	}
}

func TestSignedUnloadAcceptsAbsentModelAsCold(t *testing.T) {
	var unloadCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "other", "status": "unloaded"}}})
		case "/models/unload":
			unloadCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := strings.Repeat("u", 32)
	cfg := &Config{NodeID: "node-a", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{
		ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 1, RouterManaged: true,
		ModelPaths: map[string]string{"missing": filepath.Join(t.TempDir(), "missing.gguf")},
	}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "absent-unload", IdempotencyKey: "absent-unload", NodeID: cfg.NodeID, Command: "unload_model", Args: map[string]any{"target_id": "node-a-runtime", "model": "missing", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result := p.Handle(context.Background(), command)
	if !result.OK || result.Result["tier"] != "cold_disk" || unloadCalls != 0 {
		t.Fatalf("signed absent unload was not an authoritative cold no-op: result=%+v unload_calls=%d", result, unloadCalls)
	}
}

func TestSignedLoadRejectsAbsentModelAfterMutation(t *testing.T) {
	var loadCalls, unloadCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case "/models/load":
			loadCalls++
			w.WriteHeader(http.StatusOK)
		case "/models/unload":
			unloadCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := strings.Repeat("l", 32)
	modelDir := t.TempDir()
	cfg := &Config{NodeID: "node-a", CommandSigningSecret: secret, CommandStatePath: filepath.Join(modelDir, "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{
		ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 1, RouterManaged: true,
		ModelPaths: map[string]string{"missing": filepath.Join(modelDir, "missing.gguf")},
	}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	command := wsproto.CommandPayload{ID: "absent-load", IdempotencyKey: "absent-load", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_id": "node-a-runtime", "model": "missing", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result := p.Handle(ctx, command)
	if result.OK || loadCalls == 0 || unloadCalls == 0 {
		t.Fatalf("load absence was not rejected after authoritative mismatch/rollback: result=%+v load_calls=%d unload_calls=%d", result, loadCalls, unloadCalls)
	}
}

func TestDiscoverLlamaCPPUsesRuntimeContextAndSlots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "same-model", "status": "loaded", "meta": map[string]any{"n_ctx_train": 32768, "n_params": 8_000_000_000}}, map[string]any{"id": "cold-model", "status": "unloaded"}}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]any{
				map[string]any{"id": 0, "n_ctx": 8192, "is_processing": true},
				map[string]any{"id": 1, "n_ctx": 8192, "is_processing": false},
				map[string]any{"id": 2, "n_ctx": 8192, "is_processing": false},
				map[string]any{"id": 3, "n_ctx": 8192, "is_processing": false},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	advertisement, err := DiscoverLlamaCPP(context.Background(), "node-a", LlamaCPPServerConfig{
		ID: "short", Endpoint: server.URL, PublicEndpoint: "http://node-a:8081", AcceleratorIndex: 1, MaxResidentModels: 1,
		RouterManaged: true,
		ContextLimit:  999, Slots: 99, RuntimeArgs: []string{"--ctx-size", "8192", "--parallel", "4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if advertisement.ContextLimit != 8192 || advertisement.Slots != 4 || advertisement.QueueRunning != 1 {
		t.Fatalf("runtime capacity was not discovered: %+v", advertisement)
	}
	if !advertisement.CapabilitiesVerified || advertisement.CapacitySource != "runtime:/slots" {
		t.Fatalf("runtime capacity should be verified: %+v", advertisement)
	}
	if len(advertisement.Models) != 2 || len(advertisement.ResidentModels) != 1 || advertisement.ResidentModels[0] != "same-model" || !advertisement.SupportsModelLifecycle || advertisement.MaxResidentModels != 1 || advertisement.ModelFingerprint == "" || advertisement.Version == "" {
		t.Fatalf("model identity is incomplete: %+v", advertisement)
	}
}

func TestDiscoverLlamaCPPPublishesOnlyAuthoritativePerModelCapacity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			// The catalog is intentionally stale; /api/ps is the authoritative
			// runtime visibility/capacity source for the loaded model.
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "stale-model", "status": "loaded"}, map[string]any{"id": "cold", "status": "unloaded"}}})
		case "/api/ps":
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{map[string]any{"model": "model", "size_vram": int64(4096 * 1024 * 1024)}}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"n_ctx": 4096, "is_processing": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	advertisement, err := DiscoverLlamaCPP(context.Background(), "node-a", LlamaCPPServerConfig{ID: "runtime", Endpoint: server.URL, AcceleratorIndex: 2, RouterManaged: true, RuntimeProfiles: []RuntimeProfileConfig{{ID: "default", ContextLimit: 4096, Slots: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(advertisement.ModelCapacityObservations) != 1 {
		t.Fatalf("expected one authoritative model observation, got %+v", advertisement.ModelCapacityObservations)
	}
	observation := advertisement.ModelCapacityObservations[0]
	if observation.Model != "model" || observation.ModelBytes != 4096*1024*1024 || observation.AcceleratorID != "node-a-gpu2" || !observation.Verified || observation.Source != "runtime:/api/ps:size_vram" || observation.ObservedAt.IsZero() || observation.ModelFingerprint == "" || observation.RuntimeIdentity == "" {
		t.Fatalf("incomplete authoritative capacity observation: %+v", observation)
	}
}

func TestDiscoverLlamaCPPSuppressesAmbiguousCapacityRowsButPreservesVisibility(t *testing.T) {
	fixtures := []struct {
		name             string
		ps               string
		expectedResident []string
	}{
		{name: "zero", ps: `{"models":[]}`, expectedResident: []string{}},
		{name: "multiple-distinct", ps: `{"models":[{"model":"model-a","size_vram":1048576},{"model":"model-b","size_vram":1048576}]}`, expectedResident: []string{"model-a", "model-b"}},
		{name: "duplicate", ps: `{"models":[{"model":"model-a","size_vram":1048576},{"model":"model-a","size_vram":1048576}]}`, expectedResident: []string{"model-a"}},
		{name: "partial", ps: `{"models":[{"model":"model-a"}]}`, expectedResident: []string{"model-a"}},
		{name: "invalid-json", ps: `{"models":[`, expectedResident: []string{"stale-model"}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/models":
					_, _ = w.Write([]byte(`{"data":[{"id":"stale-model","status":"loaded"}]}`))
				case "/api/ps":
					_, _ = w.Write([]byte(fixture.ps))
				case "/slots":
					_, _ = w.Write([]byte(`[{"n_ctx":4096,"is_processing":false}]`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			advertisement, err := DiscoverLlamaCPP(context.Background(), "node-ambiguous", LlamaCPPServerConfig{ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 1})
			if err != nil {
				t.Fatal(err)
			}
			if len(advertisement.ModelCapacityObservations) != 0 || advertisement.StandaloneVRAMVerified {
				t.Fatalf("ambiguous runtime rows emitted capacity evidence: %+v", advertisement)
			}
			if !reflect.DeepEqual(advertisement.ResidentModels, fixture.expectedResident) {
				t.Fatalf("ambiguous runtime rows erased visibility catalog: %+v", advertisement.ResidentModels)
			}
		})
	}
}

func TestLlamaSlotsRejectsMalformedRowsAndMixedCapacity(t *testing.T) {
	for _, fixture := range []struct {
		name string
		body string
	}{
		{"null-row", `[{"n_ctx":4096},null]`},
		{"zero-context", `[{"n_ctx":4096},{"n_ctx":0}]`},
		{"missing-context", `[{"n_ctx":4096},{}]`},
		{"wrong-context-type", `[{"n_ctx":4096},{"n_ctx":"8192"}]`},
		{"missing-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192}]`},
		{"numeric-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192,"is_processing":0}]`},
		{"null-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192,"is_processing":null}]`},
		{"wrong-processing-type", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192,"is_processing":"no"}]`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			contextLimit, slots, running := llamaSlots(json.RawMessage(fixture.body))
			if contextLimit != 0 || slots != 0 || running != 0 {
				t.Fatalf("malformed/mixed slots were treated as authoritative: context=%d slots=%d running=%d", contextLimit, slots, running)
			}
		})
	}
	contextLimit, slots, running := llamaSlots(json.RawMessage(`[{"n_ctx":4096,"is_processing":true},{"n_ctx":8192,"is_processing":false}]`))
	if contextLimit != 4096 || slots != 2 || running != 1 {
		t.Fatalf("valid slots were not counted exactly: context=%d slots=%d running=%d", contextLimit, slots, running)
	}
}

func TestDiscoverLlamaCPPMixedSlotsNeverVerifiesCapacity(t *testing.T) {
	for _, fixture := range []struct {
		name string
		body string
	}{
		{"null-row", `[{"n_ctx":4096},null]`},
		{"zero-context", `[{"n_ctx":4096},{"n_ctx":0}]`},
		{"missing-context", `[{"n_ctx":4096},{}]`},
		{"missing-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192}]`},
		{"numeric-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192,"is_processing":0}]`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/models":
					_, _ = io.WriteString(w, `{"data":[{"id":"model","status":"unloaded"}]}`)
				case "/slots":
					_, _ = io.WriteString(w, fixture.body)
				case "/props":
					_, _ = io.WriteString(w, `{"default_generation_settings":{"n_ctx":4096}}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			advertisement, err := DiscoverLlamaCPP(context.Background(), "node-a", LlamaCPPServerConfig{ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 2})
			if err != nil {
				t.Fatal(err)
			}
			if advertisement.CapabilitiesVerified || advertisement.CapacitySource == "runtime:/slots" {
				t.Fatalf("mixed-invalid slots became verified capacity: %+v", advertisement)
			}
		})
	}
}

func TestDiscoverLlamaCPPPassiveStatusDoesNotAdvertiseLifecycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_, _ = io.WriteString(w, `{"data":[{"id":"model","status":"loaded"}]}`)
		case "/slots":
			_, _ = io.WriteString(w, `[{"n_ctx":4096,"is_processing":false}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	advertisement, err := DiscoverLlamaCPP(context.Background(), "node-a", LlamaCPPServerConfig{ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 1, RouterManaged: false})
	if err != nil {
		t.Fatal(err)
	}
	if !advertisement.CapabilitiesVerified || advertisement.CapacitySource != "runtime:/slots" || advertisement.Models[0] != "model" || advertisement.ResidentModels[0] != "model" {
		t.Fatalf("passive runtime visibility was not preserved: %+v", advertisement)
	}
	if advertisement.SupportsModelLifecycle {
		t.Fatalf("passive loaded status advertised unsupported lifecycle mutation: %+v", advertisement)
	}
}

func TestDiscoverLlamaCPPRouterUsesResidentModelForMonitoring(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{
				map[string]any{"id": "folder/model one.gguf", "status": "loaded"},
				map[string]any{"id": "cold.gguf", "status": "unloaded"},
			}})
		case "/slots":
			if r.URL.Query().Get("model") != "folder/model one.gguf" {
				http.Error(w, "model query required", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"n_ctx": 32768, "is_processing": false}, map[string]any{"n_ctx": 32768, "is_processing": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	advertisement, err := DiscoverLlamaCPP(context.Background(), "node-a", LlamaCPPServerConfig{Endpoint: server.URL, RouterManaged: true})
	if err != nil {
		t.Fatal(err)
	}
	if !advertisement.CapabilitiesVerified || advertisement.ContextLimit != 32768 || advertisement.Slots != 2 {
		t.Fatalf("router-scoped monitoring was not verified: %+v", advertisement)
	}
}

func TestDiscoverLlamaCPPFallsBackConservatively(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "same-model", "status": "loaded"}}})
		case "/props":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 32768}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	advertisement, err := DiscoverLlamaCPP(context.Background(), "node-a", LlamaCPPServerConfig{Endpoint: server.URL, AcceleratorIndex: 0})
	if err != nil {
		t.Fatal(err)
	}
	if advertisement.ContextLimit != 32768 || advertisement.Slots != 1 || advertisement.CapabilitiesVerified {
		t.Fatalf("fallback should use props plus one conservative slot: %+v", advertisement)
	}
	if advertisement.CapacitySource != "runtime:/props+conservative-slot" {
		t.Fatalf("unexpected fallback source: %s", advertisement.CapacitySource)
	}
}

func TestDiscoverLlamaCPPUsesOllamaRunningModelsForResidency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "small", "status": "unloaded"}, map[string]any{"id": "large", "status": "unloaded"}}})
		case "/api/ps":
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{map[string]any{"name": "small", "model": "small", "size_vram": 2 * 1024 * 1024 * 1024}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	advertisement, err := DiscoverLlamaCPP(context.Background(), "node-a", LlamaCPPServerConfig{Endpoint: server.URL, ContextLimit: 4096, Slots: 1, RuntimeArgs: []string{"ollama"}, MaxResidentModels: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !advertisement.SupportsModelLifecycle || len(advertisement.Models) != 2 || len(advertisement.ResidentModels) != 1 || advertisement.ResidentModels[0] != "small" {
		t.Fatalf("Ollama catalog/residency discovery is incorrect: %+v", advertisement)
	}
	if advertisement.StandaloneVRAMMB != 2048 || !advertisement.StandaloneVRAMVerified || advertisement.StandaloneVRAMSource != "runtime:/api/ps:size_vram" {
		t.Fatalf("Ollama runtime VRAM envelope is incomplete: %+v", advertisement)
	}
}
