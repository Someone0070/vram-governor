package nodeagent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/wsproto"
)

func TestSignedModelCommandIsAllowlistedAndDurablyIdempotent(t *testing.T) {
	var mu sync.Mutex
	loaded := false
	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/models":
			status := "unloaded"
			if loaded {
				status = "loaded"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": status}}})
		case "/models/load":
			loads++
			loaded = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: t.TempDir() + "/commands.json"}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "router", Endpoint: server.URL, PublicEndpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	command := wsproto.CommandPayload{ID: "cmd-1", IdempotencyKey: "load-model", NodeID: "node-1", Command: "load_model", Args: map[string]any{"target_id": "node-1-router", "model": "model"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	first := newCommandProcessor(cfg, log).Handle(context.Background(), command)
	if !first.OK {
		t.Fatalf("signed command failed: %+v", first)
	}
	second := newCommandProcessor(cfg, log).Handle(context.Background(), command)
	if !second.OK || second.CompletedAt != first.CompletedAt {
		t.Fatalf("persisted result was not reused: first=%+v second=%+v", first, second)
	}
	mu.Lock()
	defer mu.Unlock()
	if loads != 1 {
		t.Fatalf("idempotent command executed %d times", loads)
	}
}

func TestNodeCommandRejectsTamperingAndUnknownActions(t *testing.T) {
	secret := "0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: t.TempDir() + "/commands.json"}
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "cmd-bad", IdempotencyKey: "bad", NodeID: "node-1", Command: "run_shell", Args: map[string]any{"command": "anything"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	command.Args["command"] = "tampered"
	result := processor.Handle(context.Background(), command)
	if result.OK || result.Error != "invalid command signature" {
		t.Fatalf("tampered command accepted: %+v", result)
	}
	command.ID = "cmd-unknown"
	command.IdempotencyKey = "unknown"
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result = processor.Handle(context.Background(), command)
	if result.OK || result.Error != "command is not allowlisted" {
		t.Fatalf("unknown command accepted: %+v", result)
	}
}

func TestSignedOllamaAndComfyCommandsExecuteOnOwningNode(t *testing.T) {
	var mu sync.Mutex
	loaded := false
	comfyFreed := 0
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "local-model"}}})
		case "/api/ps":
			models := []map[string]string{}
			if loaded {
				models = append(models, map[string]string{"model": "local-model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"models": models})
		case "/api/generate":
			var body struct {
				KeepAlive int `json:"keep_alive"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			loaded = body.KeepAlive != 0
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ollama.Close()
	comfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/free" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		comfyFreed++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer comfy.Close()
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: t.TempDir() + "/commands.json"}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "ollama", Endpoint: ollama.URL, PublicEndpoint: ollama.URL, RuntimeArgs: []string{"ollama"}, ContextLimit: 4096, Slots: 1}}
	cfg.ComfyUI.Endpoint = comfy.URL
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "cmd-ollama", IdempotencyKey: "load-ollama", NodeID: "node-1", Command: "load_model", Args: map[string]any{"target_id": "node-1-ollama", "model": "local-model"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if result := processor.Handle(context.Background(), command); !result.OK {
		t.Fatalf("Ollama command failed: %+v", result)
	}
	command = wsproto.CommandPayload{ID: "cmd-comfy", IdempotencyKey: "free-comfy", NodeID: "node-1", Command: "reclaim_accelerator", Args: map[string]any{"target_id": "node-1-comfy"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if result := processor.Handle(context.Background(), command); !result.OK {
		t.Fatalf("Comfy command failed: %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if !loaded || comfyFreed != 1 {
		t.Fatalf("node-local mutations missing: loaded=%t comfy_freed=%d", loaded, comfyFreed)
	}
}
