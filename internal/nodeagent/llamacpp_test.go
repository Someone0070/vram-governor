package nodeagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverLlamaCPPUsesRuntimeContextAndSlots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "same-model", "status": map[string]any{"value": "loaded"}, "meta": map[string]any{"n_ctx_train": 32768, "n_params": 8_000_000_000}}, map[string]any{"id": "cold-model", "status": map[string]any{"value": "unloaded"}}}})
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
		ContextLimit: 999, Slots: 99, RuntimeArgs: []string{"--ctx-size", "8192", "--parallel", "4"},
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

func TestDiscoverLlamaCPPFallsBackConservatively(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "same-model"}}})
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
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "small"}, map[string]any{"id": "large"}}})
		case "/api/ps":
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{map[string]any{"name": "small", "model": "small"}}})
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
}
