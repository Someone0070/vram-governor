package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/domain"
	"vram-governor/internal/logging"
	"vram-governor/internal/wsproto"
)

func TestSignedReverifyRejectsNonUnloadedRuntimeStates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileFingerprint := strings.Repeat("a", 64)
	runtimeSum := sha256.Sum256([]byte(`["model"]`))
	runtimeFingerprint := hex.EncodeToString(runtimeSum[:])
	for _, fixture := range []struct {
		name   string
		status string
		model  string
	}{
		{"loaded", "loaded", "model"},
		{"transitional", "loading", "model"},
		{"unknown", "mystery", "model"},
		{"missing", "loaded", "model"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			pinCalls := 0
			statusRequests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/models" {
					statusRequests++
					id := "model"
					status := fixture.status
					if fixture.name == "missing" {
						id = "other"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": id, "status": status}}})
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("s", 32)}
			cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, ModelPaths: map[string]string{"model": path}, ModelFingerprints: map[string]string{"model": fileFingerprint}, RuntimeFingerprints: map[string]string{"model": runtimeFingerprint}, ContextLimit: 4096, Slots: 1}}
			manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 1024, RAMReserveBytes: 1, MaxWarmBytes: 1024, OpenIdentity: func(string, []string) (warmFileIdentity, error) {
				return warmFileIdentity{Size: 5, Hash: fileFingerprint}, nil
			}, PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
				pinCalls++
				return &testWarmPin{resident: 5, locked: 5}, warmFileIdentity{Size: 5, Hash: fileFingerprint}, nil
			}, Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 900, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 1024, nil }, Oracle: func() string { return "mincore+mlock" }})
			p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			p.warmRAM = manager
			command := wsproto.CommandPayload{ID: "reverify-" + fixture.name, IdempotencyKey: "reverify-" + fixture.name, NodeID: cfg.NodeID, Command: "reverify_warm_model", Args: map[string]any{"target_id": "node-1-runtime", "model": fixture.model, "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
			command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
			result := p.Handle(context.Background(), command)
			if result.OK || pinCalls != 0 {
				t.Fatalf("non-unloaded status was accepted or pinned: result=%+v pinCalls=%d", result, pinCalls)
			}
			if fixture.name == "missing" && statusRequests == 0 {
				t.Fatal("configured model status was not queried before refusing the missing-model fixture")
			}
		})
	}
}

func respondComfyDiscovery(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/object_info":
		_, _ = io.WriteString(w, `{}`)
	case "/system_stats":
		_, _ = io.WriteString(w, `{"system":{"comfyui_version":"0.0-test"}}`)
	case "/queue":
		_, _ = io.WriteString(w, `{"queue_running":[],"queue_pending":[]}`)
	default:
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	return true
}

func TestProductionHandlerRejectsResidencyWithoutCapabilitySchema(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": "unloaded"}}})
			return
		}
		if r.URL.Path == "/props" {
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
			return
		}
		if r.URL.Path == "/slots" {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	secret := strings.Repeat("x", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 1}}
	command := wsproto.CommandPayload{ID: "missing-schema", IdempotencyKey: "missing-schema", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "fencing_token": int64(1), "runtime_identity": "node-1-runtime|llamacpp||v1|", "capability_version": "v1", "capability_revision": "", "expected_tier": "hot_vram"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result := NewCommandHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))).Handle(context.Background(), command)
	if result.OK || !strings.Contains(result.Error, "unsupported") {
		t.Fatalf("empty production capability schema was accepted: %+v", result)
	}
}

func TestReadOnlyQuerySettlesExactPendingMutation(t *testing.T) {
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("q", 32)}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	identity := "node-1-runtime|llamacpp||v1|fingerprint"
	mutationArgs := map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(7)}
	mutation := wsproto.CommandPayload{ID: "mutation-id", NodeID: cfg.NodeID, Command: "load_model", IdempotencyKey: "mutation-key", Args: mutationArgs}
	intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: "load_model", Token: 7, RuntimeIdentity: identity, CommandID: "mutation-id", IdempotencyKey: "mutation-key", Fingerprint: commandFingerprint(mutation)}
	manifest, err := pendingManifestFor(mutation, mutationArgs, intent.TargetID, intent.Model, intent.Token, intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.ManifestJSON = string(manifest)
	p.pending["mutation-id"] = intent
	p.stateBlocked = true
	p.stateBlockReason = blockReasonWarmTransient
	query := wsproto.CommandPayload{ID: "query-id", IdempotencyKey: "query-key", NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7), "original_command_id": "mutation-id", "original_idempotency_key": "mutation-key"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	p.settlePendingFromQuery(query, wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, OK: true, Result: map[string]any{"action": "load_model", "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "resident": true, "warm_ram": false, "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "changed": false, "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7), "original_command_id": "mutation-id", "original_idempotency_key": "mutation-key"}, CompletedAt: time.Now().UTC()})
	if len(p.pending) != 0 || p.stateBlocked {
		t.Fatalf("exact query did not settle pending mutation: pending=%+v blocked=%v", p.pending, p.stateBlocked)
	}
	if result := p.results["mutation-id"]; !result.OK || result.Error != "" {
		t.Fatalf("correlated mutation result was not persisted: %+v", result)
	}
}

func TestReadOnlyQueryRejectsPendingRuntimeIdentityDrift(t *testing.T) {
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("q", 32)}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	p.pending["mutation-id"] = pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: "load_model", Token: 7, RuntimeIdentity: "node-1-runtime|llamacpp||v1|authoritative", CommandID: "mutation-id", IdempotencyKey: "mutation-key", Fingerprint: "mutation-fingerprint"}
	p.stateBlocked = true
	p.stateBlockReason = blockReasonWarmTransient
	query := wsproto.CommandPayload{ID: "query-id", IdempotencyKey: "query-key", NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "node-1-runtime|llamacpp||v1|drifted", "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7), "original_command_id": "mutation-id", "original_idempotency_key": "mutation-key"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	p.settlePendingFromQuery(query, wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, OK: true, Result: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "node-1-runtime|llamacpp||v1|drifted", "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7), "original_command_id": "mutation-id", "original_idempotency_key": "mutation-key"}, CompletedAt: time.Now().UTC()})
	if len(p.pending) != 1 || !p.stateBlocked {
		t.Fatalf("identity-drift query settled or unblocked pending mutation: pending=%+v blocked=%v", p.pending, p.stateBlocked)
	}
}

func TestSignedQueryRejectsInventedOriginalLinkage(t *testing.T) {
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("q", 32)}
	query := wsproto.CommandPayload{ID: "invented-query", IdempotencyKey: "invented-query-key", NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "node-1-runtime|llamacpp||v1|fingerprint",
		"capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7),
		"original_command_id": "invented-original", "original_idempotency_key": "invented-original-key",
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	query.Signature, _ = wsproto.SignCommand(query, []byte(cfg.CommandSigningSecret))
	result := NewCommandHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))).Handle(context.Background(), query)
	if result.OK || !strings.Contains(result.Error, "not a durable pending or completed command") {
		t.Fatalf("invented query linkage was accepted: %+v", result)
	}
}

func TestQueryCannotSettleResidencyFromTierOnlyEvidence(t *testing.T) {
	for _, action := range []string{"load_model", "unload_model", "warm_model", "offload_model", "demote_model", "protect_warm_model", "cleanup_warm_model", "reverify_warm_model"} {
		t.Run(action, func(t *testing.T) {
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("q", 32)}
			p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			identity := "node-1-runtime|llamacpp||v1|fingerprint"
			pending := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: action, Token: 7, RuntimeIdentity: identity, CommandID: "mutation-" + action, IdempotencyKey: "key-" + action, Fingerprint: "fingerprint-" + action, Protected: true}
			p.pending[pending.CommandID] = pending
			p.stateBlocked = true
			p.stateBlockReason = blockReasonWarmTransient
			query := wsproto.CommandPayload{ID: "query-" + action, IdempotencyKey: "query-" + action, NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": pending.TargetID, "model": pending.Model, "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7), "original_command_id": pending.CommandID, "original_idempotency_key": pending.IdempotencyKey}}
			p.settlePendingFromQuery(query, wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, OK: true, Result: map[string]any{"target_kind": "llamacpp", "target_id": pending.TargetID, "model": pending.Model, "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "tier": "warm_ram", "resident": false, "warm_ram": true, "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7), "original_command_id": pending.CommandID, "original_idempotency_key": pending.IdempotencyKey}, CompletedAt: time.Now().UTC()})
			if !p.HasPending() || !p.stateBlocked {
				t.Fatalf("tier-only query synthesized %s success: pending=%v blocked=%v", action, p.HasPending(), p.stateBlocked)
			}
		})
	}
}

func TestHandleCachedAuthoritativeObservationReplayAllResidencyActions(t *testing.T) {
	actions := []struct {
		name, desired, inverse, third string
	}{
		{"load_model", "hot_vram", "cold_disk", "warm_ram"}, {"unload_model", "cold_disk", "hot_vram", "warm_ram"},
		{"warm_model", "warm_ram", "hot_vram", "cold_disk"}, {"offload_model", "warm_ram", "cold_disk", "hot_vram"},
		{"demote_model", "warm_ram", "hot_vram", "cold_disk"}, {"protect_warm_model", "warm_ram", "cold_disk", "hot_vram"},
		{"cleanup_warm_model", "cold_disk", "hot_vram", "warm_ram"}, {"reverify_warm_model", "warm_ram", "cold_disk", "hot_vram"},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			secret := strings.Repeat("s", 32)
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CapabilityVersion: "runtime-v1"}
			cfg.Capabilities.Version = domain.CapabilityContractVersion
			identity := "node-1-runtime|llamacpp||runtime-v1|fingerprint"
			args := map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": action.desired, "fencing_token": int64(12)}
			if action.name == "protect_warm_model" {
				args["active_references"], args["protected"] = int64(3), true
			}
			mutation := wsproto.CommandPayload{ID: "original-" + action.name, IdempotencyKey: "original-key-" + action.name, NodeID: cfg.NodeID, Command: action.name, Args: args}
			mutation.Signature, _ = wsproto.SignCommand(mutation, []byte(secret))
			queryArgs := map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(12), "expected_fence": int64(12), "observed_after_fence": int64(12), "original_command_id": mutation.ID, "original_idempotency_key": mutation.IdempotencyKey}
			makeProcessor := func() (*commandProcessor, wsproto.CommandPayload) {
				p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
				intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: action.name, Token: 12, RuntimeIdentity: identity, CommandID: mutation.ID, IdempotencyKey: mutation.IdempotencyKey, Fingerprint: p.semanticFingerprint(mutation), Protected: action.name == "protect_warm_model", ActiveReferences: 3}
				manifest, err := pendingManifestFor(mutation, args, intent.TargetID, intent.Model, intent.Token, intent)
				if err != nil {
					t.Fatal(err)
				}
				intent.ManifestJSON = string(manifest)
				p.pending[intent.CommandID] = intent
				p.fences[fenceKey(intent.TargetID, intent.Model)] = intent.Token
				p.stateBlocked, p.stateBlockReason = true, blockReasonWarmTransient
				query := wsproto.CommandPayload{ID: "query-" + action.name, IdempotencyKey: "query-key-" + action.name, NodeID: cfg.NodeID, Command: "query_model_state", Args: queryArgs, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
				query.Signature, _ = wsproto.SignCommand(query, []byte(secret))
				return p, query
			}
			proof := func(p *commandProcessor, query wsproto.CommandPayload, tier string, complete bool) map[string]any {
				result := map[string]any{"action": action.name, "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "node_id": cfg.NodeID, "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "tier": tier, "resident": tier == "hot_vram", "warm_ram": tier == "warm_ram", "changed": false, "original_command_id": mutation.ID, "original_idempotency_key": mutation.IdempotencyKey, "command_id": query.ID, "idempotency_key": query.IdempotencyKey, "command_fingerprint": p.semanticFingerprint(query), "fingerprint": p.semanticFingerprint(query), "expected_fence": int64(12), "fencing_token": int64(12), "observed_after_fence": int64(12)}
				if tier == "cold_disk" {
					result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
					result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
				}
				if tier == "warm_ram" && complete {
					result["warm_model_bytes_verified"], result["released_vram"], result["oracle"] = true, true, "mincore+mlock"
					result["warm_model_bytes"], result["locked_bytes"] = int64(10), int64(10)
					if action.name == "protect_warm_model" {
						result["protected"], result["active_references"] = true, int64(3)
					}
				}
				return result
			}
			// A signed query carrying only a canonical tier must remain blocked.
			p, query := makeProcessor()
			invalid := proof(p, query, "warm_ram", false)
			payload := wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: invalid, CompletedAt: time.Now().UTC()}
			p.results[query.ID], p.results["key:"+query.IdempotencyKey] = payload, payload
			p.commandFingerprints["id:"+query.ID], p.commandFingerprints[query.IdempotencyKey] = p.semanticFingerprint(query), p.semanticFingerprint(query)
			if rejected := p.Handle(context.Background(), query); rejected.OK || !p.HasPending() || !p.stateBlocked {
				t.Fatalf("tier-only signed query was accepted: %+v pending=%v blocked=%v", rejected, p.HasPending(), p.stateBlocked)
			}
			// A complete proof for the third canonical tier is also rejected;
			// action identity, not tier shape, chooses the only valid pair.
			p, query = makeProcessor()
			invalid = proof(p, query, action.third, true)
			payload = wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: invalid, CompletedAt: time.Now().UTC()}
			p.results[query.ID], p.results["key:"+query.IdempotencyKey] = payload, payload
			p.commandFingerprints["id:"+query.ID], p.commandFingerprints[query.IdempotencyKey] = p.semanticFingerprint(query), p.semanticFingerprint(query)
			if rejected := p.Handle(context.Background(), query); rejected.OK || !p.HasPending() || !p.stateBlocked {
				t.Fatalf("third-tier signed query was accepted: %+v pending=%v blocked=%v", rejected, p.HasPending(), p.stateBlocked)
			}
			// A helper-only cached proof has no authoritative configured runtime
			// behind it. Handle must therefore fail closed even when the proof is
			// otherwise internally well formed; positive replay is covered by the
			// signed live-runtime matrix.
			p, query = makeProcessor()
			valid := proof(p, query, action.desired, true)
			payload = wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: valid, CompletedAt: time.Now().UTC()}
			p.results[query.ID], p.results["key:"+query.IdempotencyKey] = payload, payload
			p.commandFingerprints["id:"+query.ID], p.commandFingerprints[query.IdempotencyKey] = p.semanticFingerprint(query), p.semanticFingerprint(query)
			replayed := p.Handle(context.Background(), query)
			if replayed.OK || !strings.Contains(replayed.Error, "cached residency result") || !p.HasPending() || !p.stateBlocked {
				t.Fatalf("unbound exact signed query was not rejected: %+v pending=%v blocked=%v", replayed, p.HasPending(), p.stateBlocked)
			}
		})
	}
}

// TestLiveHandleCanonicalResidencyQueryMatrixAllActions exercises the real
// signed query path. Results are produced by queryModelState and canonicalized
// by Handle before the second invocation replays the durable envelope.
func TestLiveHandleCanonicalResidencyQueryMatrixAllActions(t *testing.T) {
	actions := []struct{ name, desired, inverse string }{
		{"load_model", "hot_vram", "cold_disk"}, {"unload_model", "cold_disk", "hot_vram"},
		{"warm_model", "warm_ram", "hot_vram"}, {"offload_model", "warm_ram", "cold_disk"},
		{"demote_model", "warm_ram", "hot_vram"}, {"protect_warm_model", "warm_ram", "cold_disk"},
		{"cleanup_warm_model", "cold_disk", "hot_vram"}, {"reverify_warm_model", "warm_ram", "cold_disk"},
	}
	for _, action := range actions {
		for _, tier := range []string{action.desired, action.inverse} {
			t.Run(action.name+"/"+tier, func(t *testing.T) {
				secret := strings.Repeat("l", 32)
				loaded := tier == "hot_vram"
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/v1/models":
						status := "unloaded"
						if loaded {
							status = "loaded"
						}
						_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": status}}})
					case "/props":
						_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
					case "/slots":
						_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
					default:
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret}
				cfg.CommandStatePath = filepath.Join(t.TempDir(), "commands.json")
				cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
				discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
				if err != nil {
					t.Fatal(err)
				}
				cfg.CapabilityVersion, cfg.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
				identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
				p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
				if tier == "warm_ram" {
					root := t.TempDir()
					modelPath := filepath.Join(root, "model.bin")
					if err := os.WriteFile(modelPath, []byte("model"), 0o600); err != nil {
						t.Fatal(err)
					}
					identity := warmFileIdentity{Size: 8, Hash: "hash"}
					manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 1024, RAMReserveBytes: 1, MaxWarmBytes: 1024, MemlockLimitBytes: 1024, OpenIdentity: func(string, []string) (warmFileIdentity, error) { return identity, nil }, PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
						return &testWarmPin{resident: 8, locked: 8}, identity, nil
					}, Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 1023, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 1024, nil }, Oracle: func() string { return "mincore+mlock" }})
					if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "node-1-runtime", Model: "model", Path: modelPath, ExpectedFingerprint: "hash", RuntimeFingerprint: discovery.ModelFingerprint, RuntimeEndpoint: server.URL, RuntimeVersion: discovery.Version, RuntimeProfile: discovery.ActiveRuntimeProfile, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }, ActiveReferences: 2, Protected: action.name == "protect_warm_model"}); err != nil {
						t.Fatal(err)
					}
					p.warmRAM = manager
				}
				original := wsproto.CommandPayload{ID: "live-original-" + action.name + tier, IdempotencyKey: "live-original-key-" + action.name + tier, NodeID: cfg.NodeID, Command: action.name, Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": action.desired, "fencing_token": int64(41)}}
				if action.name == "protect_warm_model" {
					original.Args["active_references"], original.Args["protected"] = int64(2), true
				}
				originalResult := map[string]any{"action": action.name, "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "node_id": cfg.NodeID, "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "tier": action.desired, "resident": action.desired == "hot_vram", "warm_ram": action.desired == "warm_ram", "changed": true, "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey, "command_id": original.ID, "idempotency_key": original.IdempotencyKey, "fencing_token": int64(41), "observed_after_fence": int64(41), "reconciled": false}
				if action.desired == "cold_disk" {
					originalResult["cleaned"], originalResult["warm_entry_absent"], originalResult["warm_release_verified"] = true, true, true
					originalResult["warm_model_bytes"], originalResult["locked_bytes"] = int64(0), int64(0)
				}
				if action.desired == "warm_ram" {
					originalResult["warm_model_bytes_verified"], originalResult["released_vram"], originalResult["oracle"] = true, true, "mincore+mlock"
					originalResult["warm_model_bytes"], originalResult["locked_bytes"] = int64(8), int64(8)
					if action.name == "protect_warm_model" {
						originalResult["protected"], originalResult["active_references"] = true, int64(2)
					}
				}
				originalFP := p.semanticFingerprint(original)
				originalResult["command_fingerprint"], originalResult["fingerprint"] = originalFP, originalFP
				originalPayload := wsproto.CommandResultPayload{ID: original.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: originalResult, CompletedAt: time.Now().UTC()}
				p.results[original.ID], p.results["key:"+original.IdempotencyKey] = originalPayload, originalPayload
				p.commandFingerprints["id:"+original.ID], p.commandFingerprints[original.IdempotencyKey] = originalFP, originalFP
				p.fences[fenceKey("node-1-runtime", "model")] = 41
				if err := p.save(); err != nil {
					t.Fatal(err)
				}
				fresh := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
				if tier == "warm_ram" {
					fresh.warmRAM = p.warmRAM
				}
				p = fresh
				query := wsproto.CommandPayload{ID: "live-query-" + action.name + tier, IdempotencyKey: "live-query-key-" + action.name + tier, NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(41), "expected_fence": int64(41), "observed_after_fence": int64(41), "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
				query.Signature, _ = wsproto.SignCommand(query, []byte(secret))
				live := p.Handle(context.Background(), query)
				if !live.OK {
					t.Fatalf("live signed query failed: %+v", live)
				}
				for _, key := range []string{"node_id", "action", "original_command_id", "original_idempotency_key", "command_id", "idempotency_key", "command_fingerprint", "fingerprint"} {
					if live.Result[key] == nil {
						t.Fatalf("live canonical result missing %s: %+v", key, live.Result)
					}
				}
				if live.Result["action"] != action.name || live.Result["tier"] != tier {
					t.Fatalf("live action/tier mismatch: %+v", live.Result)
				}
				expectedQueryFP := p.semanticFingerprint(query)
				if live.Result["command_fingerprint"] != expectedQueryFP || live.Result["fingerprint"] != expectedQueryFP || live.Result["command_fingerprint"] != live.Result["fingerprint"] || live.Result["command_id"] != query.ID || live.Result["idempotency_key"] != query.IdempotencyKey {
					t.Fatalf("live canonical aliases/fingerprint drifted: %+v", live.Result)
				}
				replay := p.Handle(context.Background(), query)
				if !replay.OK || !reflect.DeepEqual(replay.Result, live.Result) || replay.CompletedAt != live.CompletedAt {
					t.Fatalf("live canonical replay drifted: first=%+v replay=%+v", live, replay)
				}
				// A single mixed-proof mutation cannot be replayed; fence drift keeps
				// the blocked production path from silently replacing it from cache.
				bad := live
				bad.Result = make(map[string]any, len(live.Result)+1)
				for k, v := range live.Result {
					bad.Result[k] = v
				}
				bad.Result["cleaned"] = true
				p.results[query.ID], p.results["key:"+query.IdempotencyKey] = bad, bad
				p.stateBlocked, p.stateBlockReason = true, blockReasonWarmTransient
				p.fences[fenceKey("node-1-runtime", "model")] = 42
				if rejected := p.Handle(context.Background(), query); rejected.OK {
					t.Fatalf("mixed-proof live cache was accepted: %+v", rejected)
				}
			})
		}
	}
}

// TestLiveHandleAllEightResidencyActionsDurableMatrix executes every original
// mutation and its correlated query through Handle.  Each case writes the
// command journal, constructs a fresh processor, replays the original from
// disk, and then proves the query aliases/fingerprint are stable.  The three
// negative observations are isolated below so a mixed proof cannot mask a
// fence or unrelated-tier failure.
func TestLiveHandleAllEightResidencyActionsDurableMatrix(t *testing.T) {
	actions := []struct{ name, desired string }{
		{"load_model", "hot_vram"}, {"unload_model", "cold_disk"},
		{"warm_model", "warm_ram"}, {"offload_model", "warm_ram"},
		{"demote_model", "warm_ram"}, {"protect_warm_model", "warm_ram"},
		{"cleanup_warm_model", "cold_disk"}, {"reverify_warm_model", "warm_ram"},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			root := t.TempDir()
			modelPath := filepath.Join(root, "model.bin")
			if err := os.WriteFile(modelPath, []byte("model"), 0o600); err != nil {
				t.Fatal(err)
			}
			secret := strings.Repeat("m", 32)
			var loaded atomic.Bool
			var mutations atomic.Int64
			loaded.Store(action.name == "unload_model" || action.name == "warm_model" || action.name == "offload_model" || action.name == "demote_model")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/models":
					status := "unloaded"
					if loaded.Load() {
						status = "loaded"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": status}}})
				case "/props":
					_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
				case "/slots":
					_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
				case "/models/load":
					mutations.Add(1)
					loaded.Store(true)
					w.WriteHeader(http.StatusOK)
				case "/models/unload":
					mutations.Add(1)
					loaded.Store(false)
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(root, "commands.json")}
			cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
			discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
			if err != nil {
				t.Fatal(err)
			}
			cfg.CapabilityVersion, cfg.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
			cfg.LlamaCPP.Servers[0].ModelPaths = map[string]string{"model": modelPath}
			cfg.LlamaCPP.Servers[0].ModelFingerprints = map[string]string{"model": "hash"}
			cfg.LlamaCPP.Servers[0].RuntimeFingerprints = map[string]string{"model": discovery.ModelFingerprint}
			identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
			processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			if action.name == "warm_model" || action.name == "offload_model" || action.name == "demote_model" || action.name == "protect_warm_model" || action.name == "cleanup_warm_model" || action.name == "reverify_warm_model" {
				warmIdentity := warmFileIdentity{Size: 8, Hash: "hash"}
				processor.warmRAM = NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 1024, RAMReserveBytes: 1, MaxWarmBytes: 1024, MemlockLimitBytes: 1024, OpenIdentity: func(string, []string) (warmFileIdentity, error) { return warmIdentity, nil }, PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
					return &testWarmPin{resident: 8, locked: 8}, warmIdentity, nil
				}, Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 1023, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 1024, nil }, Oracle: func() string { return "mincore+mlock" }})
				if _, err := processor.warmRAM.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "node-1-runtime", Model: "model", Path: modelPath, ExpectedFingerprint: "hash", RuntimeFingerprint: discovery.ModelFingerprint, RuntimeEndpoint: server.URL, RuntimeVersion: discovery.Version, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }, ActiveReferences: 2, Protected: action.name == "protect_warm_model"}); err != nil {
					t.Fatal(err)
				}
			}
			args := map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": action.desired, "fencing_token": int64(1)}
			if action.name == "protect_warm_model" {
				args["active_references"], args["protected"] = int64(2), true
			}
			original := wsproto.CommandPayload{ID: "matrix-original-" + action.name, IdempotencyKey: "matrix-original-key-" + action.name, NodeID: cfg.NodeID, Command: action.name, Args: args, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
			original.Signature, err = wsproto.SignCommand(original, []byte(secret))
			if err != nil {
				t.Fatal(err)
			}
			live := processor.Handle(context.Background(), original)
			if !live.OK || live.Result["tier"] != action.desired || live.Result["action"] != action.name {
				t.Fatalf("original did not execute through Handle with exact desired proof: %+v", live)
			}
			fresh := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			if processor.warmRAM != nil {
				fresh.warmRAM = processor.warmRAM
			}
			replayedOriginal := fresh.Handle(context.Background(), original)
			liveJSON, _ := json.Marshal(live.Result)
			replayJSON, _ := json.Marshal(replayedOriginal.Result)
			if !replayedOriginal.OK || !bytes.Equal(replayJSON, liveJSON) || !replayedOriginal.CompletedAt.Equal(live.CompletedAt) {
				t.Fatalf("fresh disk replay changed original: live=%+v replay=%+v", live, replayedOriginal)
			}
			fence := fresh.fences[fenceKey("node-1-runtime", "model")]
			query := wsproto.CommandPayload{ID: "matrix-query-" + action.name, IdempotencyKey: "matrix-query-key-" + action.name, NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": fence, "expected_fence": fence, "observed_after_fence": fence, "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
			query.Signature, err = wsproto.SignCommand(query, []byte(secret))
			if err != nil {
				t.Fatal(err)
			}
			observed := fresh.Handle(context.Background(), query)
			if !observed.OK || observed.Result["action"] != action.name || observed.Result["tier"] != action.desired || observed.Result["changed"] != false {
				t.Fatalf("signed correlated query did not prove unchanged desired state: %+v", observed)
			}
			queryReplay := fresh.Handle(context.Background(), query)
			observedJSON, _ := json.Marshal(observed.Result)
			queryReplayJSON, _ := json.Marshal(queryReplay.Result)
			if !queryReplay.OK || !bytes.Equal(queryReplayJSON, observedJSON) || !queryReplay.CompletedAt.Equal(observed.CompletedAt) {
				t.Fatalf("fresh query replay changed canonical aliases/fingerprint: first=%+v replay=%+v", observed, queryReplay)
			}
			secondFresh := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			if processor.warmRAM != nil {
				secondFresh.warmRAM = processor.warmRAM
			}
			mutationsBeforeDiskQueryReplay := mutations.Load()
			secondQueryReplay := secondFresh.Handle(context.Background(), query)
			secondQueryJSON, _ := json.Marshal(secondQueryReplay.Result)
			if !secondQueryReplay.OK || !bytes.Equal(secondQueryJSON, observedJSON) || !secondQueryReplay.CompletedAt.Equal(observed.CompletedAt) {
				t.Fatalf("second fresh processor did not replay exact query from disk: first=%+v replay=%+v", observed, secondQueryReplay)
			}
			if mutations.Load() != mutationsBeforeDiskQueryReplay {
				t.Fatalf("second fresh query replay crossed the runtime mutation boundary: before=%d after=%d", mutationsBeforeDiskQueryReplay, mutations.Load())
			}
			// Isolate the three negative proof classes against the durable query
			// record: mixed tier fields, fence drift, and an unrelated third tier.
			for name, edit := range map[string]func(map[string]any){
				"mixed": func(result map[string]any) {
					if action.desired == "cold_disk" {
						result["warm_model_bytes_verified"] = true
					} else {
						result["cleaned"] = true
					}
				},
				"fence": func(result map[string]any) { result["observed_after_fence"] = fence + 1 },
				"third-tier": func(result map[string]any) {
					result["tier"] = map[string]string{"hot_vram": "warm_ram", "warm_ram": "cold_disk", "cold_disk": "hot_vram"}[action.desired]
				},
			} {
				bad := observed
				bad.Result = make(map[string]any, len(observed.Result)+1)
				for key, value := range observed.Result {
					bad.Result[key] = value
				}
				edit(bad.Result)
				fresh.results[query.ID], fresh.results["key:"+query.IdempotencyKey] = bad, bad
				if accepted := fresh.cachedAuthoritativeObservation(query); accepted {
					t.Fatalf("%s negative query proof was accepted", name)
				}
				rejected := fresh.Handle(context.Background(), query)
				if rejected.OK || (!strings.Contains(rejected.Error, "cached residency result") && !strings.Contains(rejected.Error, "reconciliation")) {
					t.Fatalf("%s negative query proof crossed the Handle path: %+v", name, rejected)
				}
			}
		})
	}
}

func TestQuerySettlesExactInverseAsFailedForAllResidencyActions(t *testing.T) {
	actions := []struct {
		name, desired, inverse string
	}{
		{"load_model", "hot_vram", "cold_disk"}, {"unload_model", "cold_disk", "hot_vram"},
		{"warm_model", "warm_ram", "hot_vram"}, {"offload_model", "warm_ram", "cold_disk"},
		{"demote_model", "warm_ram", "hot_vram"}, {"protect_warm_model", "warm_ram", "cold_disk"},
		{"cleanup_warm_model", "cold_disk", "hot_vram"}, {"reverify_warm_model", "warm_ram", "cold_disk"},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("i", 32)}
			p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			identity := "node-1-runtime|llamacpp||v1|fingerprint"
			args := map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": action.desired, "fencing_token": int64(7)}
			if action.name == "protect_warm_model" {
				args["active_references"], args["protected"] = int64(2), true
			}
			mutation := wsproto.CommandPayload{ID: "inverse-" + action.name, NodeID: cfg.NodeID, Command: action.name, IdempotencyKey: "inverse-key-" + action.name, Args: args, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
			mutation.Signature, _ = wsproto.SignCommand(mutation, []byte(cfg.CommandSigningSecret))
			intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: action.name, Token: 7, RuntimeIdentity: identity, CommandID: mutation.ID, IdempotencyKey: mutation.IdempotencyKey, Fingerprint: commandFingerprint(mutation), Protected: action.name == "protect_warm_model", ActiveReferences: 2}
			manifest, err := pendingManifestFor(mutation, args, intent.TargetID, intent.Model, intent.Token, intent)
			if err != nil {
				t.Fatal(err)
			}
			intent.ManifestJSON = string(manifest)
			p.pending[intent.CommandID], p.fences[fenceKey(intent.TargetID, intent.Model)] = intent, intent.Token
			p.stateBlocked, p.stateBlockReason = true, blockReasonWarmTransient
			query := wsproto.CommandPayload{ID: "inverse-query-" + action.name, NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": intent.TargetID, "model": intent.Model, "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(7), "expected_fence": int64(7), "observed_after_fence": int64(7), "original_command_id": intent.CommandID, "original_idempotency_key": intent.IdempotencyKey}}
			proof := map[string]any{"action": action.name, "target_kind": "llamacpp", "target_id": intent.TargetID, "model": intent.Model, "node_id": cfg.NodeID, "runtime_identity": identity, "capability_version": "v1", "capability_revision": domain.CapabilityContractVersion, "tier": action.inverse, "resident": action.inverse == "hot_vram", "warm_ram": false, "changed": false, "expected_fence": int64(7), "fencing_token": int64(7), "observed_after_fence": int64(7), "original_command_id": intent.CommandID, "original_idempotency_key": intent.IdempotencyKey}
			if action.inverse == "cold_disk" {
				proof["cleaned"], proof["warm_entry_absent"], proof["warm_release_verified"] = true, true, true
				proof["warm_model_bytes"], proof["locked_bytes"] = int64(0), int64(0)
			}
			p.settlePendingFromQuery(query, wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, OK: true, Result: proof, CompletedAt: time.Now().UTC()})
			if p.HasPending() || p.stateBlocked {
				t.Fatalf("exact inverse proof did not clear pending state: pending=%v blocked=%v", p.HasPending(), p.stateBlocked)
			}
			result := p.results[intent.CommandID]
			if result.OK || result.Status != "failed" || result.Error == "" || result.Result["rolled_back"] != true {
				t.Fatalf("inverse proof did not produce terminal failed result: %+v", result)
			}
			// This fixture intentionally has no configured live runtime. The
			// settled failure remains durable, but Handle must not treat the
			// helper-only envelope as an authoritative replay.
			replay := p.Handle(context.Background(), mutation)
			if replay.OK || !strings.Contains(replay.Error, "cached residency result") {
				t.Fatalf("unbound failed inverse result was replayed: %+v", replay)
			}
		})
	}
}

func TestSignedReverifyValidationCloseFailureRetainsPendingAcrossRestart(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileFingerprint := strings.Repeat("r", 64)
	runtimeSum := sha256.Sum256([]byte(`["model"]`))
	runtimeFingerprint := hex.EncodeToString(runtimeSum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": "unloaded"}}})
			return
		}
		if r.URL.Path == "/slots" {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	secret := strings.Repeat("q", 32)
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
	cfg.WarmRAM = WarmRAMConfig{Enabled: true, ModelRoots: []string{root}, RAMTotalBytes: 100, RAMReserveBytes: 1, RAMHardCapBytes: 100, MaxWarmBytes: 100, MemlockLimitBytes: 100, CgroupLimitBytes: 100, PressureRefusalPercent: 90}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, PublicEndpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1,
		ModelPaths: map[string]string{"model": path}, ModelFingerprints: map[string]string{"model": fileFingerprint}, RuntimeFingerprints: map[string]string{"model": runtimeFingerprint}}}
	identity := warmFileIdentity{Size: 5, Hash: fileFingerprint}
	pin := &testWarmPin{resident: 5, locked: 0, closeErr: errors.New("reverify validation close sentinel")}
	policy := WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100, MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) { return identity, nil }, PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return pin, identity, nil
		},
		Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 99, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" }}
	manager := NewWarmRAMManager(policy)
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.warmRAM = manager
	command := wsproto.CommandPayload{ID: "reverify-close", IdempotencyKey: "reverify-close", NodeID: cfg.NodeID, Command: "reverify_warm_model", Args: map[string]any{"target_id": "node-1-runtime", "model": "model", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if result := p.Handle(context.Background(), command); result.OK || !p.HasPending() || p.Ready() || !manager.HasEntryFor("node-1-runtime", "model") || manager.IsVerifiedFor("node-1-runtime", "model") {
		t.Fatalf("reverify validation close failure was not retained: result=%+v pending=%v ready=%v entry=%v verified=%v", result, p.HasPending(), p.Ready(), manager.HasEntryFor("node-1-runtime", "model"), manager.IsVerifiedFor("node-1-runtime", "model"))
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if q.Ready() || !q.HasPending() {
		t.Fatalf("fresh reverify processor was not blocked: ready=%v pending=%v", q.Ready(), q.HasPending())
	}
	fresh := NewWarmRAMManager(policy)
	fresh.RestoreManifests(q.persistedWarm)
	q.warmRAM = fresh
	cleanup := wsproto.CommandPayload{ID: "reverify-cleanup", IdempotencyKey: "reverify-cleanup", NodeID: cfg.NodeID, Command: "cleanup_warm_model", Args: map[string]any{"target_id": "node-1-runtime", "model": "model", "fencing_token": int64(2)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	cleanup.Signature, _ = wsproto.SignCommand(cleanup, []byte(secret))
	if result := q.Handle(context.Background(), cleanup); !result.OK || q.HasPending() || !q.Ready() || q.warmRAM.HasEntryFor("node-1-runtime", "model") {
		t.Fatalf("fresh reverify cleanup did not restore readiness: result=%+v pending=%v ready=%v entry=%v", result, q.HasPending(), q.Ready(), q.warmRAM.HasEntryFor("node-1-runtime", "model"))
	}
}

type failingCommandStateFile struct {
	name  string
	stage string
	file  *os.File
}

type countingWarmPin struct {
	closeCount       *int
	resident, locked int64
}

func (p *countingWarmPin) Close() error {
	if p.closeCount != nil {
		(*p.closeCount)++
	}
	return nil
}
func (p *countingWarmPin) ResidentBytes() int64 { return p.resident }
func (p *countingWarmPin) LockedBytes() int64   { return p.locked }

func (f *failingCommandStateFile) Name() string {
	if f.file != nil {
		return f.file.Name()
	}
	return f.name
}
func (f *failingCommandStateFile) Chmod(mode os.FileMode) error {
	if f.stage == "chmod" {
		return errors.New("chmod failure")
	}
	if f.file != nil {
		return f.file.Chmod(mode)
	}
	return nil
}
func (f *failingCommandStateFile) Write(body []byte) (int, error) {
	if f.stage == "write" {
		return 0, errors.New("write failure")
	}
	if f.file != nil {
		return f.file.Write(body)
	}
	return len(body), nil
}
func (f *failingCommandStateFile) Sync() error {
	if f.stage == "sync" {
		return errors.New("sync failure")
	}
	if f.file != nil {
		return f.file.Sync()
	}
	return nil
}
func (f *failingCommandStateFile) Close() error {
	if f.stage == "close" {
		if f.file != nil {
			_ = f.file.Close()
		}
		return errors.New("close failure")
	}
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

func TestCommandStatePersistenceFailuresRemainBlocked(t *testing.T) {
	for _, stage := range []string{"mkdir", "create", "chmod", "write", "sync", "close", "rename", "dir-sync"} {
		t.Run(stage, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "nested", "state.json")
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("s", 32), CommandStatePath: statePath}
			p := &commandProcessor{cfg: cfg, results: map[string]wsproto.CommandResultPayload{}, commandFingerprints: map[string]string{}, fences: map[string]int64{}, pending: map[string]pendingCommand{}, warmRAM: NewWarmRAMManager(WarmRAMPolicy{})}
			p.mkdirAll = func(dir string, mode os.FileMode) error {
				if stage == "mkdir" {
					return errors.New("mkdir failure")
				}
				return os.MkdirAll(dir, mode)
			}
			p.createTemp = func(dir, pattern string) (commandStateFile, error) {
				if stage == "create" {
					return nil, errors.New("create failure")
				}
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return &failingCommandStateFile{name: file.Name(), stage: stage, file: file}, nil
			}
			p.renameState = func(_, _ string) error {
				if stage == "rename" {
					return errors.New("rename failure")
				}
				return nil
			}
			p.syncDir = func(string) error {
				if stage == "dir-sync" {
					return errors.New("directory sync failure")
				}
				return nil
			}
			if err := p.save(); err == nil {
				t.Fatalf("save unexpectedly succeeded during injected %s failure", stage)
			}
			if p.stateBlockReason != blockReasonDurability {
				t.Fatalf("persistence failure did not set typed durable reason: %q", p.stateBlockReason)
			}
			q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			command := wsproto.CommandPayload{ID: "blocked-" + stage, IdempotencyKey: "blocked-" + stage, NodeID: cfg.NodeID, Command: "reclaim_accelerator", Args: map[string]any{"target_id": "node-1-comfy", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
			command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
			if result := q.Handle(context.Background(), command); !strings.Contains(result.Error, blockReasonDurability) {
				t.Fatalf("reloaded processor accepted durable failure: %+v", result)
			}
			if err := q.RecoverCommandState("operator-epoch-" + stage); err != nil {
				t.Fatalf("explicit recovery failed: %v", err)
			}
			if q.stateBlocked {
				t.Fatal("explicit recovery did not clear durable block")
			}
		})
	}
}

func TestRecoveryEpochPreservesFenceAndCompletedResult(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("r", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.fences[fenceKey("node-1-router", "model")] = 41
	completed := wsproto.CommandResultPayload{ID: "done", NodeID: cfg.NodeID, OK: true, CompletedAt: time.Now().UTC()}
	p.results["done"] = completed
	p.commandFingerprints["id:done"] = "fingerprint"
	if err := p.save(); err != nil {
		t.Fatalf("initial state save failed: %v", err)
	}
	// Simulate an uncertain mutation after the last trusted state. The
	// injected primary rename fails, but save's independent marker remains.
	p.renameState = func(string, string) error { return errors.New("primary rename unavailable") }
	p.pending["uncertain"] = pendingCommand{CommandID: "uncertain", TargetID: "node-1-router", Model: "model", Fingerprint: "pending"}
	if err := p.save(); err == nil {
		t.Fatal("injected persistence failure unexpectedly succeeded")
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q.stateBlocked || q.stateBlockReason != blockReasonDurability {
		t.Fatalf("fresh processor did not retain durable block: blocked=%v reason=%q", q.stateBlocked, q.stateBlockReason)
	}
	if q.fences[fenceKey("node-1-router", "model")] != 41 || q.results["done"].ID != "done" {
		t.Fatalf("durable fence/result high-water was lost: fences=%v results=%v", q.fences, q.results)
	}
	if err := q.RecoverCommandState("epoch-after-failure"); err != nil {
		t.Fatalf("explicit epoch recovery failed: %v", err)
	}
	if q.stateBlocked || q.fences[fenceKey("node-1-router", "model")] != 41 || q.results["done"].ID != "done" {
		t.Fatalf("recovery discarded trusted state: blocked=%v fences=%v results=%v", q.stateBlocked, q.fences, q.results)
	}
	oldCommand := wsproto.CommandPayload{ID: "old-after-recovery", IdempotencyKey: "old-after-recovery", NodeID: cfg.NodeID, Command: "refresh_capabilities", Args: map[string]any{}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	oldCommand.Signature, _ = wsproto.SignCommand(oldCommand, []byte(cfg.CommandSigningSecret))
	if result := q.Handle(context.Background(), oldCommand); !strings.Contains(result.Error, "recovery epoch") {
		t.Fatalf("old signed command was accepted after recovery: %+v", result)
	}
	if err := q.RecoverCommandState("epoch-after-failure"); err == nil {
		t.Fatal("recovery epoch was reusable")
	}
}

func TestRecoveryMarkerPhasesAndIdentityBinding(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("m", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.save(); err != nil {
		t.Fatalf("state setup failed: %v", err)
	}
	original := recoveryIdentity(statePath)
	if err := p.writeRecoveryMarker(blockReasonDurability, "prepared", original, recoveryFileIdentity{}); err != nil {
		t.Fatalf("prepared marker failed: %v", err)
	}
	var prepared recoveryMarkerEnvelope
	body, err := os.ReadFile(statePath + ".recovery")
	if err != nil || json.Unmarshal(body, &prepared) != nil || prepared.State.Phase != "prepared" {
		t.Fatalf("prepared recovery phase was not durable: err=%v state=%+v", err, prepared.State)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q.stateBlocked || q.stateBlockReason != blockReasonDurability {
		t.Fatalf("prepared marker did not fail closed: blocked=%v reason=%q", q.stateBlocked, q.stateBlockReason)
	}
	// Replacing the primary behind the marker must not be accepted as the
	// original identity, even though the marker checksum itself is valid.
	if err := os.WriteFile(statePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); !r.stateBlocked || r.stateBlockReason != blockReasonQuarantine {
		t.Fatalf("identity drift was not quarantined: blocked=%v reason=%q", r.stateBlocked, r.stateBlockReason)
	}
}

func TestPrimaryAndMarkerFailureLeavesPriorPendingAndNoRuntimeMutation(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	var runtimeMutations int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models/load" {
			runtimeMutations++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	secret := strings.Repeat("p", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "router", Endpoint: server.URL, RouterManaged: true, ModelPaths: map[string]string{"model": filepath.Join(t.TempDir(), "model.bin")}}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	prior := pendingCommand{CommandID: "prior", TargetID: "node-1-router", Model: "model", Fingerprint: "prior-fingerprint", ManifestJSON: `{"target_id":"node-1-router","model":"model"}`}
	p.pending[prior.CommandID] = prior
	if err := p.save(); err != nil {
		t.Fatalf("prior pending state save failed: %v", err)
	}
	p.pending["new"] = pendingCommand{CommandID: "new", TargetID: "node-1-router", Model: "model", Fingerprint: "new-fingerprint", ManifestJSON: `{"target_id":"node-1-router","model":"model"}`}
	p.renameState = func(string, string) error { return errors.New("primary save failure") }
	p.markerMkdirAll = func(string, os.FileMode) error { return errors.New("marker save failure") }
	command := wsproto.CommandPayload{ID: "mutate", IdempotencyKey: "mutate", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_id": "node-1-router", "model": "model", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result := p.Handle(context.Background(), command)
	if result.OK || runtimeMutations != 0 {
		t.Fatalf("external mutation ran after pre-save failure: result=%+v mutations=%d", result, runtimeMutations)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q.stateBlocked || !q.HasPending() {
		t.Fatalf("fresh processor lost prior pending block: blocked=%v pending=%v", q.stateBlocked, q.pending)
	}
}

func TestRecoveryMarkerPersistenceInjectionLeavesPriorStateBlocked(t *testing.T) {
	for _, stage := range []string{"mkdir", "create", "chmod", "write", "sync", "close", "rename", "dir-sync"} {
		t.Run(stage, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "commands.json")
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("i", 32), CommandStatePath: statePath}
			p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			p.pending["prior"] = pendingCommand{CommandID: "prior", TargetID: "node-1-router", Model: "model", Fingerprint: "prior", ManifestJSON: `{"target_id":"node-1-router","model":"model"}`}
			if err := p.save(); err != nil {
				t.Fatalf("prior state save failed: %v", err)
			}
			p.renameState = func(string, string) error { return errors.New("primary save failure") }
			p.markerMkdirAll = func(dir string, mode os.FileMode) error {
				if stage == "mkdir" {
					return errors.New("marker mkdir failure")
				}
				return os.MkdirAll(dir, mode)
			}
			p.markerCreateTemp = func(dir, pattern string) (commandStateFile, error) {
				if stage == "create" {
					return nil, errors.New("marker create failure")
				}
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return &failingCommandStateFile{name: file.Name(), stage: stage, file: file}, nil
			}
			p.markerRename = func(from, to string) error {
				if stage == "rename" {
					return errors.New("marker rename failure")
				}
				return os.Rename(from, to)
			}
			p.markerSyncDir = func(string) error {
				if stage == "dir-sync" {
					return errors.New("marker directory sync failure")
				}
				return nil
			}
			if err := p.save(); err == nil {
				t.Fatal("save unexpectedly succeeded during marker injection")
			}
			q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if !q.stateBlocked || !q.HasPending() {
				t.Fatalf("prior pending state did not remain blocked: blocked=%v pending=%v", q.stateBlocked, q.pending)
			}
		})
	}
}

func TestStartupRecoveryGenerationIsMonotonicAndAuditMarkerRemains(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	base := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("g", 32), CommandStatePath: statePath}
	p := newCommandProcessor(base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.pending["prior"] = pendingCommand{CommandID: "prior", TargetID: "node-1-router", Model: "model", Fingerprint: "prior", ManifestJSON: `{"target_id":"node-1-router","model":"model"}`}
	if err := p.save(); err != nil {
		t.Fatalf("initial state save failed: %v", err)
	}
	p.pending["uncertain"] = pendingCommand{CommandID: "uncertain", TargetID: "node-1-router", Model: "model", Fingerprint: "uncertain", ManifestJSON: `{"target_id":"node-1-router","model":"model"}`}
	p.renameState = func(string, string) error { return errors.New("save failure") }
	if err := p.save(); err == nil {
		t.Fatal("injected save failure unexpectedly succeeded")
	}
	startup := *base
	startup.CommandRecoveryGeneration = 1
	startup.CommandRecoveryEpoch = "startup-one"
	q := newCommandProcessor(&startup, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if q.stateBlocked || q.recoveryGeneration != 1 || q.recoveryEpoch != "startup-one" || q.HasPending() {
		t.Fatalf("startup recovery did not complete: blocked=%v generation=%d epoch=%q pending=%v", q.stateBlocked, q.recoveryGeneration, q.recoveryEpoch, q.pending)
	}
	markerBody, err := os.ReadFile(statePath + ".recovery")
	if err != nil {
		t.Fatal("committed recovery audit marker was removed")
	}
	if !strings.Contains(string(markerBody), recoveryMarkerPhaseRecoveryCommitted) {
		t.Fatalf("audit marker is not committed: %s", markerBody)
	}
	q.results["post-recovery"] = wsproto.CommandResultPayload{ID: "post-recovery", NodeID: startup.NodeID, OK: true, CompletedAt: time.Now().UTC()}
	if err := q.save(); err != nil {
		t.Fatalf("post-recovery state save failed: %v", err)
	}
	q2 := newCommandProcessor(&startup, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if q2.stateBlocked {
		t.Fatalf("matching committed audit marker re-blocked restart: %q", q2.stateBlockReason)
	}
	reused := startup
	reused.CommandRecoveryGeneration = 2
	q3 := newCommandProcessor(&reused, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q3.stateBlocked {
		t.Fatal("reused recovery epoch was accepted at a higher generation")
	}
}

func TestAgentRefusesControllerOnStartupRecoveryInitializationFailure(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	if err := os.WriteFile(statePath+".recovery", []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	connections := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { connections++ }))
	defer server.Close()
	cfg := &Config{ControllerURL: "ws" + strings.TrimPrefix(server.URL, "http"), NodeID: "node-1", CommandSigningSecret: strings.Repeat("a", 32), CommandStatePath: statePath, CommandRecoveryGeneration: 1, CommandRecoveryEpoch: "startup-failure"}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if p.initError == nil {
		t.Fatal("startup recovery corruption was not surfaced")
	}
	Run(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if connections != 0 {
		t.Fatalf("agent connected despite startup recovery failure: %d", connections)
	}
}

func TestAgentHeartbeatReportsNotReadyForDurableBlock(t *testing.T) {
	registration := make(chan wsproto.RegisterPayload, 1)
	heartbeat := make(chan wsproto.HeartbeatPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var register wsproto.Envelope
		if wsjson.Read(ctx, conn, &register) != nil {
			return
		}
		var registrationPayload wsproto.RegisterPayload
		if json.Unmarshal(register.Payload, &registrationPayload) == nil {
			registration <- registrationPayload
		}
		_ = wsjson.Write(ctx, conn, wsproto.Envelope{Type: wsproto.MsgAck})
		var envelope wsproto.Envelope
		if wsjson.Read(ctx, conn, &envelope) != nil || envelope.Type != wsproto.MsgHeartbeat {
			return
		}
		var payload wsproto.HeartbeatPayload
		if json.Unmarshal(envelope.Payload, &payload) == nil {
			heartbeat <- payload
		}
	}))
	defer server.Close()
	cfg := &Config{ControllerURL: "ws" + strings.TrimPrefix(server.URL, "http"), NodeID: "node-1", CommandSigningSecret: strings.Repeat("z", 32), CommandStatePath: filepath.Join(t.TempDir(), "commands.json"), ReconnectMinSeconds: 1, ReconnectMaxSeconds: 1, HeartbeatIntervalSeconds: 1}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.block(blockReasonDurability)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = runOnce(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &SystemSampler{}, func() []logging.Entry { return nil }, p)
	select {
	case payload := <-registration:
		if payload.Ready == nil || *payload.Ready {
			t.Fatalf("blocked processor registration readiness was not explicit false: %+v", payload.Ready)
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not receive registration payload")
	}
	select {
	case payload := <-heartbeat:
		if payload.Ready {
			t.Fatal("durably blocked processor advertised Ready=true")
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not receive heartbeat")
	}
}

func TestRecoveryEpochHistoryIsCompleteBeyondLegacyBound(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("h", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.pending["prior"] = pendingCommand{CommandID: "prior", TargetID: "node-1-router", Model: "model", Fingerprint: "prior", ManifestJSON: `{"target_id":"node-1-router","model":"model"}`}
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	p.renameState = func(string, string) error { return errors.New("save failure") }
	if err := p.save(); err == nil {
		t.Fatal("save failure was not injected")
	}
	p.renameState = os.Rename
	for generation := uint64(1); generation <= 33; generation++ {
		if err := p.RecoverCommandState(fmt.Sprintf("epoch-%d", generation)); err != nil {
			t.Fatalf("recovery %d failed: %v", generation, err)
		}
	}
	old := *cfg
	old.CommandRecoveryGeneration = 34
	old.CommandRecoveryEpoch = "epoch-1"
	q := newCommandProcessor(&old, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q.stateBlocked {
		t.Fatal("old epoch was accepted after more than 32 recoveries")
	}
}

func TestPreparedRecoveryResumesWithoutImportingProposedState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	base := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("j", 32), CommandStatePath: statePath}
	p := newCommandProcessor(base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	if err := p.writeRecoveryMarkerTarget(blockReasonDurability, recoveryMarkerPhaseRecoveryPrepared, recoveryIdentity(statePath), recoveryFileIdentity{}, "future-target", 1, "prepared-epoch"); err != nil {
		t.Fatal(err)
	}
	var old commandStateEnvelope
	oldBody, err := os.ReadFile(statePath)
	if err != nil || json.Unmarshal(oldBody, &old) != nil || old.State.RecoveryGeneration != 0 {
		t.Fatalf("prepared marker imported proposed generation into primary: err=%v state=%+v", err, old.State)
	}
	startup := *base
	startup.CommandRecoveryGeneration = 1
	startup.CommandRecoveryEpoch = "prepared-epoch"
	q := newCommandProcessor(&startup, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if q.initError != nil || q.stateBlocked || q.recoveryGeneration != 1 || q.recoveryEpoch != "prepared-epoch" {
		t.Fatalf("prepared recovery did not resume safely: init=%v blocked=%v generation=%d epoch=%q", q.initError, q.stateBlocked, q.recoveryGeneration, q.recoveryEpoch)
	}
}

func TestStateJournalRejectsPrimaryRollbackAfterLaterSave(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("k", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	p.results["later"] = wsproto.CommandResultPayload{ID: "later", NodeID: cfg.NodeID, OK: true, CompletedAt: time.Now().UTC()}
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, first, 0o600); err != nil {
		t.Fatal(err)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q.stateBlocked || q.stateBlockReason != blockReasonDurability {
		t.Fatalf("primary rollback was accepted: blocked=%v reason=%q", q.stateBlocked, q.stateBlockReason)
	}
}

func TestStartupCleanupIntentNeverRepinsWarmManifest(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinCalls := 0
	manager := NewWarmRAMManager(WarmRAMPolicy{
		AllowedRoots:    []string{root},
		RAMHardCapBytes: 1024, RAMReserveBytes: 1, MaxWarmBytes: 1024,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) { return warmFileIdentity{Size: 5, Hash: "hash"}, nil },
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			pinCalls++
			return &testWarmPin{resident: 5, locked: 5}, warmFileIdentity{Size: 5, Hash: "hash"}, nil
		},
		Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 900, 0, 0, 0, nil },
		MemlockLimit: func() (int64, error) { return 1024, nil },
		Oracle:       func() string { return "mincore+mlock" },
	})
	p := &commandProcessor{
		warmRAM:       manager,
		pending:       map[string]pendingCommand{"cleanup": {Command: "cleanup_warm_model", TargetID: "node-runtime", Model: "model"}},
		persistedWarm: []WarmRAMManifest{{TargetID: "node-runtime", Model: "model", CanonicalPath: path, FileFingerprint: "hash", Size: 5, Verified: true, VRAMReleased: true, LastUsed: time.Now().UTC()}},
	}
	p.restoreWarmManifests()
	if pinCalls != 0 || len(manager.Snapshot()) != 0 {
		t.Fatalf("pending cleanup restored a warm pin: calls=%d snapshot=%v", pinCalls, manager.Snapshot())
	}
}

func TestRestoredWarmManifestBlocksReadinessUntilReconciled(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100})
	p := &commandProcessor{warmRAM: manager, pending: map[string]pendingCommand{}, persistedWarm: []WarmRAMManifest{{TargetID: "node-runtime", Model: "model", CanonicalPath: path, FileFingerprint: "hash", Size: 5, RuntimeFingerprint: "runtime", RuntimeEndpoint: "endpoint", RuntimeVersion: "version", RuntimeProfile: "profile", RuntimeProfilePresent: true, Verified: true, VRAMReleased: true, LastUsed: time.Now().UTC()}}}
	p.restoreWarmManifests()
	if p.Ready() || !p.stateBlocked || p.stateBlockReason != blockReasonWarmTransient {
		t.Fatalf("restored warm claim did not block readiness: ready=%v blocked=%v reason=%q", p.Ready(), p.stateBlocked, p.stateBlockReason)
	}
}

func TestReconnectReconcileReducedBudgetPreservesRecency(t *testing.T) {
	root := t.TempDir()
	oldPath := filepath.Join(root, "old.bin")
	newPath := filepath.Join(root, "new.bin")
	if err := os.WriteFile(oldPath, []byte("old-model"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("new-model"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldHash := sha256.Sum256([]byte("old-model"))
	newHash := sha256.Sum256([]byte("new-model"))
	oldFingerprint, newFingerprint := hex.EncodeToString(oldHash[:]), hex.EncodeToString(newHash[:])
	var statusQueries int
	var queryMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			queryMu.Lock()
			statusQueries++
			queryMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "old", "status": "unloaded"}, map[string]any{"id": "new", "status": "unloaded"}}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverConfig := LlamaCPPServerConfig{ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 1, ModelPaths: map[string]string{"old": oldPath, "new": newPath}, ModelFingerprints: map[string]string{"old": oldFingerprint, "new": newFingerprint}}
	advertisement, err := DiscoverLlamaCPP(context.Background(), "node-1", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig.RuntimeFingerprints = map[string]string{"old": advertisement.ModelFingerprint, "new": advertisement.ModelFingerprint}
	cfg := &Config{NodeID: "node-1", CommandStatePath: filepath.Join(t.TempDir(), "commands.json"), WarmRAM: WarmRAMConfig{ModelRoots: []string{root}, RAMHardCapBytes: 20, RAMReserveBytes: 1, MaxWarmBytes: 10, MemlockLimitBytes: 20, PressureRefusalPercent: 90}}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{serverConfig}
	identities := map[string]warmFileIdentity{oldPath: {Size: 9, Hash: oldFingerprint}, newPath: {Size: 9, Hash: newFingerprint}}
	pinCalls, closeCalls := 0, 0
	managerFactory := func() *WarmRAMManager {
		return NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 20, RAMReserveBytes: 1, MaxWarmBytes: 10, MemlockLimitBytes: 20, PressureRefusalPercent: 90,
			OpenIdentity: func(path string, _ []string) (warmFileIdentity, error) { return identities[path], nil },
			PinFile: func(path string, _ []string, identity warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
				pinCalls++
				return &countingWarmPin{closeCount: &closeCalls, resident: identity.Size, locked: identity.Size}, identity, nil
			},
			Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 100, 0, 0, 0, nil },
			MemlockLimit: func() (int64, error) { return 20, nil }, Oracle: func() string { return "mincore+mlock" }})
	}
	manager := managerFactory()
	oldUsed := time.Now().UTC().Add(-2 * time.Hour)
	newUsed := oldUsed.Add(time.Hour)
	p := &commandProcessor{cfg: cfg, results: map[string]wsproto.CommandResultPayload{}, commandFingerprints: map[string]string{}, fences: map[string]int64{}, pending: map[string]pendingCommand{}, inflight: map[string]bool{}, warmRAM: manager, persistedWarm: []WarmRAMManifest{
		{TargetID: "node-1-runtime", Model: "old", CanonicalPath: oldPath, FileFingerprint: oldFingerprint, RuntimeFingerprint: advertisement.ModelFingerprint, RuntimeEndpoint: server.URL, RuntimeVersion: advertisement.Version, RuntimeProfile: advertisement.ActiveRuntimeProfile, RuntimeProfilePresent: true, Size: 9, LastUsed: oldUsed, Verified: true, VRAMReleased: true},
		{TargetID: "node-1-runtime", Model: "new", CanonicalPath: newPath, FileFingerprint: newFingerprint, RuntimeFingerprint: advertisement.ModelFingerprint, RuntimeEndpoint: server.URL, RuntimeVersion: advertisement.Version, RuntimeProfile: advertisement.ActiveRuntimeProfile, RuntimeProfilePresent: true, Size: 9, LastUsed: newUsed, Verified: true, VRAMReleased: true},
	}}
	p.restoreWarmManifests()
	if manager.reserved != 0 {
		t.Fatalf("metadata placeholders consumed reservation before reconciliation: %d", manager.reserved)
	}
	if err := p.save(); err != nil {
		t.Fatalf("initial warm manifest save failed: %v", err)
	}
	// Reconnect is exercised through a fresh processor and a fresh backend;
	// this catches accidental per-connection manager state and proves the
	// persisted recency/order is the source of the reduced-budget decision.
	queryMu.Lock()
	statusQueries = 0
	queryMu.Unlock()
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	q.warmRAM = managerFactory()
	q.restoreWarmManifests()
	if err := q.ReconcileWarmManifests(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !q.Ready() {
		t.Fatalf("successful runtime reconciliation did not restore readiness: blocked=%v reason=%q pending=%d", q.stateBlocked, q.stateBlockReason, len(q.pending))
	}
	queryMu.Lock()
	queries := statusQueries
	queryMu.Unlock()
	if queries < 4 || pinCalls != 2 || closeCalls != 1 {
		t.Fatalf("reconnect reconciliation did not query/admit deterministically: queries=%d pins=%d closes=%d", queries, pinCalls, closeCalls)
	}
	if q.warmRAM.IsVerifiedFor("node-1-runtime", "old") || !q.warmRAM.IsVerifiedFor("node-1-runtime", "new") {
		t.Fatal("reduced-budget reconnect admitted the wrong survivor")
	}
	manifest := q.warmRAM.ManifestSnapshot()
	if len(manifest) != 1 || manifest[0].Model != "new" || !manifest[0].LastUsed.Equal(newUsed) {
		t.Fatalf("survivor recency was not preserved: %+v", manifest)
	}
}

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
	command := wsproto.CommandPayload{ID: "cmd-1", IdempotencyKey: "load-model", NodeID: "node-1", Command: "load_model", Args: map[string]any{"target_id": "node-1-router", "model": "model", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
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

func TestStrictResidencyEnvelopeRejectsIrrelevantCrossActionArgs(t *testing.T) {
	root := t.TempDir()
	modelPath := filepath.Join(root, "model.gguf")
	if err := os.WriteFile(modelPath, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": "unloaded"}}})
		case "/props":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := strings.Repeat("e", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(root, "commands.json"), CapabilityVersion: "runtime-v1"}
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1, ModelPaths: map[string]string{"model": modelPath}, ModelFingerprints: map[string]string{"model": strings.Repeat("f", 64)}}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg.CapabilityVersion = discovery.Version
	cfg.LlamaCPP.Servers[0].RuntimeFingerprints = map[string]string{"model": discovery.ModelFingerprint}
	for _, tc := range []struct{ command, tier, forbidden string }{
		{"load_model", "hot_vram", "path"},
		{"unload_model", "cold_disk", "protected"},
		{"warm_model", "warm_ram", "unexpected"},
		{"offload_model", "warm_ram", "profile_id"},
		{"demote_model", "warm_ram", "expected_fence"},
		{"protect_warm_model", "warm_ram", "path"},
		{"cleanup_warm_model", "cold_disk", "model_path"},
		{"reverify_warm_model", "warm_ram", "protected"},
	} {
		t.Run(tc.command+"-"+tc.forbidden, func(t *testing.T) {
			args := wsproto.CanonicalResidencyCommandArgs("node-1-runtime", "model", canonicalCommandRuntimeIdentity("node-1-runtime", discovery), discovery.Version, domain.CapabilityContractVersion, tc.tier, 9)
			if tc.command == "protect_warm_model" {
				args["active_references"] = int64(0)
				args["protected"] = true
			}
			args[tc.forbidden] = true
			command := wsproto.CommandPayload{ID: "schema-" + tc.command, IdempotencyKey: "schema-" + tc.command, NodeID: cfg.NodeID, Command: tc.command, Args: args, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
			command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
			result := NewCommandHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))).Handle(context.Background(), command)
			if result.OK || !strings.Contains(result.Error, "not allowed") {
				t.Fatalf("irrelevant %s argument crossed node boundary: %+v", tc.forbidden, result)
			}
		})
	}
}

func TestCommandStateRejectsCorruptionAndRequiresReconciliation(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	statePath := filepath.Join(t.TempDir(), "commands.json")
	if err := os.WriteFile(statePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "corrupt", IdempotencyKey: "corrupt", NodeID: "node-1", Command: "unknown", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if result := p.Handle(context.Background(), command); !strings.Contains(result.Error, "command state blocked: corrupt_state") {
		t.Fatalf("corrupt state was not blocked: %+v", result)
	}
	if _, err := os.Stat(statePath + ".corrupt"); err != nil {
		t.Fatalf("corrupt state was not quarantined: %v", err)
	}
}

func TestDurableStateBlockSurvivesWarmReconcile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	if err := os.WriteFile(statePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("s", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if p.stateBlockReason != blockReasonCorrupt {
		t.Fatalf("unexpected durable block reason: %q", p.stateBlockReason)
	}
	if err := p.ReconcileWarmManifests(context.Background()); err == nil {
		t.Fatal("warm reconciliation cleared a durable corrupt-state block")
	}
	if p.stateBlockReason != blockReasonCorrupt || !p.stateBlocked {
		t.Fatalf("durable block was cleared: blocked=%v reason=%q", p.stateBlocked, p.stateBlockReason)
	}
	if _, err := os.Stat(statePath + ".corrupt"); err != nil {
		t.Fatalf("quarantined state was not retained: %v", err)
	}
}

func TestNodeCommandRejectsIdempotencyKeyReuse(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: t.TempDir() + "/commands.json"}
	comfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if respondComfyDiscovery(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer comfy.Close()
	cfg.ComfyUI.Endpoint = comfy.URL
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	first := wsproto.CommandPayload{ID: "cmd-a", IdempotencyKey: "same-key", NodeID: "node-1", Command: "reclaim_accelerator", Args: map[string]any{"target_id": "node-1-comfy", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	first.Signature, _ = wsproto.SignCommand(first, []byte(secret))
	if result := processor.Handle(context.Background(), first); result.OK || !result.Uncertain {
		t.Fatalf("unobservable reclaim did not retain uncertainty: %+v", result)
	}
	second := first
	second.ID = "cmd-b"
	second.Command = "drain_runtimes"
	second.Signature, _ = wsproto.SignCommand(second, []byte(secret))
	result := processor.Handle(context.Background(), second)
	if result.OK || !strings.Contains(result.Error, "command state blocked") {
		t.Fatalf("blocked legacy reclaim was not held for reconciliation: %+v", result)
	}
}

func TestCommandReplayAndMismatchPreserveReadiness(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	comfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if respondComfyDiscovery(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer comfy.Close()
	cfg.ComfyUI.Endpoint = comfy.URL
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	first := wsproto.CommandPayload{ID: "replay-a", IdempotencyKey: "replay-key", NodeID: cfg.NodeID, Command: "reclaim_accelerator", Args: map[string]any{"target_id": "node-1-comfy", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	first.Signature, _ = wsproto.SignCommand(first, []byte(secret))
	if result := p.Handle(context.Background(), first); result.OK || !result.Uncertain || p.Ready() {
		t.Fatalf("initial unobservable reclaim was not retained: result=%+v ready=%v", result, p.Ready())
	}
	// An uncertain native reclaim is not a cached success and must remain
	// blocked until a managed, correlated reconciliation path exists.
	if replay := p.Handle(context.Background(), first); replay.OK || !strings.Contains(replay.Error, "command state blocked") || p.Ready() {
		t.Fatalf("uncertain replay escaped reconciliation: result=%+v ready=%v", replay, p.Ready())
	}
	// A reused idempotency key and a reused command ID are rejected before any
	// mutation, while preserving the last durable readiness snapshot.
	keyMismatch := first
	keyMismatch.ID, keyMismatch.Command = "replay-b", "drain_runtimes"
	keyMismatch.Signature, _ = wsproto.SignCommand(keyMismatch, []byte(secret))
	if result := p.Handle(context.Background(), keyMismatch); result.OK || !strings.Contains(result.Error, "command state blocked") || p.Ready() {
		t.Fatalf("idempotency mismatch changed readiness: result=%+v ready=%v", result, p.Ready())
	}
	idMismatch := first
	idMismatch.IdempotencyKey, idMismatch.Command = "replay-other", "refresh_capabilities"
	idMismatch.Signature, _ = wsproto.SignCommand(idMismatch, []byte(secret))
	if result := p.Handle(context.Background(), idMismatch); result.OK || !strings.Contains(result.Error, "command state blocked") || p.Ready() {
		t.Fatalf("command ID mismatch changed readiness: result=%+v ready=%v", result, p.Ready())
	}
}

func TestLifecycleFencingRequiresExactInteger(t *testing.T) {
	if _, err := exactFenceToken(float64(1.5)); err == nil {
		t.Fatal("fractional fencing token accepted")
	}
	if token, err := exactFenceToken(json.Number("42")); err != nil || token != 42 {
		t.Fatalf("json integer token rejected: %d %v", token, err)
	}
}

func TestRuntimeErrorsRedactExternalSecrets(t *testing.T) {
	sentinel := "node-secret-sentinel"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, sentinel, http.StatusBadGateway) }))
	defer server.Close()
	err := postRuntimeJSON(context.Background(), server.URL+"/secret-token", nil, "runtime operation")
	if err == nil || strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("external response leaked into error: %v", err)
	}
}

func TestAdapterDiscoveryLogsRedactExternalIdentityAndErrors(t *testing.T) {
	sentinel := "adapter-secret-path-and-body"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, sentinel, http.StatusBadGateway)
	}))
	defer server.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := &Config{NodeID: "node-1"}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: sentinel, Endpoint: server.URL}}
	_ = discoverAdapters(context.Background(), cfg, logger, nil)
	if strings.Contains(logs.String(), sentinel) || strings.Contains(logs.String(), server.URL) {
		t.Fatalf("adapter discovery log leaked external data: %s", logs.String())
	}
}

func TestSignedWarmCleanupIsIdempotentAndTargetScoped(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "state.json")}
	cfg.CapabilityVersion = "runtime-v1"
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: "", ContextLimit: 4096, Slots: 1, ModelPaths: map[string]string{"model": filepath.Join(t.TempDir(), "model.bin")}, ModelFingerprints: map[string]string{"model": strings.Repeat("0", 64)}}}
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"model","status":"unloaded"}]}`)
	}))
	defer router.Close()
	cfg.LlamaCPP.Servers[0].Endpoint = router.URL
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	command := wsproto.CommandPayload{ID: "cleanup-1", IdempotencyKey: "cleanup-key", NodeID: cfg.NodeID, Command: "cleanup_warm_model", Args: map[string]any{"target_id": "node-1-runtime", "model": "model", "runtime_identity": canonicalCommandRuntimeIdentity("node-1-runtime", discovery), "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "cold_disk", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	first := p.Handle(context.Background(), command)
	if !first.OK {
		t.Fatalf("signed cleanup was rejected: %+v", first)
	}
	second := p.Handle(context.Background(), command)
	if !second.OK || second.CompletedAt != first.CompletedAt {
		t.Fatalf("cleanup was not idempotent: first=%+v second=%+v", first, second)
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
			status := "unloaded"
			if loaded {
				status = "loaded"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "local-model", "status": status}}})
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
		if r.URL.Path == "/free" {
			mu.Lock()
			comfyFreed++
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		if respondComfyDiscovery(w, r) {
			return
		}
		if r.URL.Path != "/free" {
			http.NotFound(w, r)
			return
		}
	}))
	defer comfy.Close()
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: t.TempDir() + "/commands.json"}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "ollama", Endpoint: ollama.URL, PublicEndpoint: ollama.URL, RuntimeArgs: []string{"ollama"}, ContextLimit: 4096, Slots: 1}}
	cfg.ComfyUI.Endpoint = comfy.URL
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "cmd-ollama", IdempotencyKey: "load-ollama", NodeID: "node-1", Command: "load_model", Args: map[string]any{"target_id": "node-1-ollama", "model": "local-model", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if result := processor.Handle(context.Background(), command); !result.OK {
		t.Fatalf("Ollama command failed: %+v", result)
	}
	command = wsproto.CommandPayload{ID: "cmd-comfy", IdempotencyKey: "free-comfy", NodeID: "node-1", Command: "reclaim_accelerator", Args: map[string]any{"target_id": "node-1-comfy", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if result := processor.Handle(context.Background(), command); result.OK || !result.Uncertain || !strings.Contains(result.Error, "observation_unavailable") {
		t.Fatalf("Comfy command was falsely authoritative: %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if !loaded || comfyFreed != 1 {
		t.Fatalf("node-local mutations missing: loaded=%t comfy_freed=%d", loaded, comfyFreed)
	}
}

func TestComfyReclaimRequiresAuthoritativeStatus(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	var frees atomic.Int32
	comfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/free" {
			frees.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		if respondComfyDiscovery(w, r) {
			return
		}
		http.NotFound(w, r)
	}))
	defer comfy.Close()
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	cfg.ComfyUI.Endpoint = comfy.URL
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "cmd-comfy-uncertain", IdempotencyKey: "free-comfy-uncertain", NodeID: cfg.NodeID, Command: "reclaim_accelerator", Args: map[string]any{"target_id": "node-1-comfy", "fencing_token": int64(9)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result := processor.Handle(context.Background(), command)
	if result.OK || !result.Uncertain || !strings.Contains(result.Error, "observation_unavailable") {
		t.Fatalf("unobservable Comfy reclaim was falsely terminalized: %+v", result)
	}
	if frees.Load() != 1 || len(processor.pending) != 1 {
		t.Fatalf("reclaim intent was not retained after side effect: frees=%d pending=%d", frees.Load(), len(processor.pending))
	}
	if got := processor.fences[fenceKey("node-1-comfy", "reclaim_accelerator")]; got != 9 {
		t.Fatalf("reclaim fence was not durably committed: %d", got)
	}
}

func TestRuntimeProfileCommandUsesAllowlistAndConfirmsReportedCapacity(t *testing.T) {
	var mu sync.Mutex
	contextLimit, slots := 8192, 4
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": "loaded"}}})
		case "/slots":
			rows := make([]map[string]any, slots)
			for index := range rows {
				rows[index] = map[string]any{"id": index, "n_ctx": contextLimit, "is_processing": false}
			}
			_ = json.NewEncoder(w).Encode(rows)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: t.TempDir() + "/commands.json"}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "llm", Endpoint: server.URL, PublicEndpoint: server.URL, ContextLimit: 8192, Slots: 4, RuntimeProfiles: []RuntimeProfileConfig{
		{ID: "short-8k", ContextLimit: 8192, Slots: 4, SwitchCommand: []string{"/fixed/switch", "short-8k"}},
		{ID: "long-32k", ContextLimit: 32768, Slots: 1, SwitchCommand: []string{"/fixed/switch", "long-32k"}},
	}}}
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var executed []string
	processor.runProfileCommand = func(_ context.Context, command []string) error {
		executed = append([]string(nil), command...)
		mu.Lock()
		contextLimit, slots = 32768, 1
		mu.Unlock()
		return nil
	}
	command := wsproto.CommandPayload{ID: "cmd-profile", IdempotencyKey: "profile-long", NodeID: "node-1", Command: "switch_runtime_profile", Args: map[string]any{"target_id": "node-1-llm", "profile_id": "long-32k", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result := processor.Handle(context.Background(), command)
	if !result.OK || len(executed) != 2 || executed[0] != "/fixed/switch" || executed[1] != "long-32k" {
		t.Fatalf("fixed profile command failed: result=%+v executed=%v", result, executed)
	}
	encoded, _ := json.Marshal(result.Result["adapters"])
	var advertisements []wsproto.AdapterAdvertisement
	if err := json.Unmarshal(encoded, &advertisements); err != nil || len(advertisements) != 1 || advertisements[0].ActiveRuntimeProfile != "long-32k" || advertisements[0].ContextLimit != 32768 || advertisements[0].Slots != 1 {
		t.Fatalf("switched capacity was not advertised: %+v err=%v", advertisements, err)
	}
	command.ID, command.IdempotencyKey = "cmd-unknown-profile", "unknown-profile"
	command.Args["profile_id"] = "not-configured"
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if rejected := processor.Handle(context.Background(), command); rejected.OK || !strings.Contains(rejected.Error, "not allowlisted") {
		t.Fatalf("unknown profile was accepted: %+v", rejected)
	}
}

func TestSignedRuntimeProfileSwitchDefersManagedProofUntilSerializedRefresh(t *testing.T) {
	secret := strings.Repeat("s", 32)
	root := t.TempDir()
	state, server := newFaithfulCheckpointServer(t, root)
	defer server.Close()
	state.mu.Lock()
	state.contextLimit = 8192
	state.mu.Unlock()
	cfg := &Config{
		NodeID: "node-profile-proof", CommandSigningSecret: secret,
		CommandStatePath: filepath.Join(root, "commands.json"), CommandRecoveryGeneration: 4,
		Checkpoint: CheckpointConfig{
			Enabled: true, ProofExerciseEnabled: true, Root: root,
			MaxBytes: 1 << 20, MaxFiles: 8, PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 8,
			MaxMetadataBytes: 1 << 20, MaxOutputBytes: 1 << 20,
			ExpirySeconds: 3600, CleanupIntervalSeconds: 60, ProofPath: filepath.Join(root, "proof.json"),
		},
	}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{
		ID: "runtime", Endpoint: server.URL, PublicEndpoint: server.URL,
		AcceleratorIndex: 0, ContextLimit: 8192, Slots: 1, RouterManaged: true,
		RuntimeProfiles: []RuntimeProfileConfig{{ID: "ctx-8k", ContextLimit: 8192, Slots: 1}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}},
	}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	checkpointProofExerciseAttempts = sync.Map{}
	checkpointProofSessionIssued = sync.Map{}
	t.Cleanup(func() {
		checkpointProofExerciseAttempts = sync.Map{}
		checkpointProofSessionIssued = sync.Map{}
	})
	p := newCommandProcessor(cfg, log, true)
	initial := discoverAdapters(context.Background(), cfg, log, p)
	if len(initial) != 1 || initial[0].CheckpointProof.Complete() || initial[0].Capabilities.SupportsSessionCheckpoint || initial[0].ActiveRuntimeProfile != "ctx-8k" {
		t.Fatalf("missing local authority must leave the initial profile unproved: %+v", initial)
	}
	proofPath := checkpointProofPath(cfg.Checkpoint.ProofPath, "node-profile-proof-runtime")
	if _, err := os.Stat(proofPath); !os.IsNotExist(err) {
		t.Fatalf("discovery without local authority must not persist proof material; stat err=%v", err)
	}
	p.runProfileCommand = func(_ context.Context, _ []string) error {
		state.mu.Lock()
		state.contextLimit = 32768
		state.mu.Unlock()
		return nil
	}
	makeCommand := func(id, commandName string, args map[string]any) wsproto.CommandPayload {
		command := wsproto.CommandPayload{ID: id, IdempotencyKey: id, NodeID: cfg.NodeID, Command: commandName, Args: args, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(2 * time.Minute)}
		command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
		return command
	}
	switchCommand := makeCommand("switch-to-32k", "switch_runtime_profile", map[string]any{
		"target_id": "node-profile-proof-runtime", "profile_id": "ctx-32k", "fencing_token": int64(1),
	})
	resultCh := make(chan wsproto.CommandResultPayload, 1)
	go func() { resultCh <- p.Handle(context.Background(), switchCommand) }()
	var switched wsproto.CommandResultPayload
	select {
	case switched = <-resultCh:
	case <-time.After(3 * time.Second):
		t.Fatal("signed runtime profile switch deadlocked while refreshing its advertisement")
	}
	if !switched.OK {
		t.Fatalf("signed runtime profile switch failed: %+v", switched)
	}
	encoded, _ := json.Marshal(switched.Result["adapters"])
	var switchedAds []wsproto.AdapterAdvertisement
	if err := json.Unmarshal(encoded, &switchedAds); err != nil || len(switchedAds) != 1 || switchedAds[0].ActiveRuntimeProfile != "ctx-32k" || switchedAds[0].ContextLimit != 32768 || switchedAds[0].Capabilities.SupportsSessionCheckpoint || switchedAds[0].CheckpointProof.Complete() {
		t.Fatalf("profile switch did not return current facts with the changed binding unproved: %+v err=%v", switchedAds, err)
	}
	if _, err := os.Stat(proofPath); !os.IsNotExist(err) {
		t.Fatalf("profile switch without local authority must not persist proof material; stat err=%v", err)
	}

	refresh := makeCommand("refresh-after-profile", "refresh_capabilities", map[string]any{})
	refreshed := p.Handle(context.Background(), refresh)
	if !refreshed.OK {
		t.Fatalf("serialized capability refresh after profile switch failed: %+v", refreshed)
	}
	encoded, _ = json.Marshal(refreshed.Result["adapters"])
	var refreshedAds []wsproto.AdapterAdvertisement
	if err := json.Unmarshal(encoded, &refreshedAds); err != nil || len(refreshedAds) != 1 || refreshedAds[0].CheckpointProof.Complete() || refreshedAds[0].Capabilities.SupportsSessionCheckpoint || refreshedAds[0].ContextLimit != 32768 || refreshedAds[0].ActiveRuntimeProfile != "ctx-32k" {
		t.Fatalf("serialized refresh must return current facts without minting an unbound proof: %+v err=%v", refreshedAds, err)
	}
	if _, err := os.Stat(proofPath); !os.IsNotExist(err) {
		t.Fatalf("serialized refresh without local authority must not persist proof material; stat err=%v", err)
	}
}

func TestCommandBlockingDoesNotBlockHeartbeatReadiness(t *testing.T) {
	var stateMu sync.Mutex
	profileSwitched := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": "loaded"}}})
		case "/slots":
			stateMu.Lock()
			contextLimit := 4096
			if profileSwitched {
				contextLimit = 8192
			}
			stateMu.Unlock()
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": contextLimit, "is_processing": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "llm", Endpoint: server.URL, PublicEndpoint: server.URL, ContextLimit: 4096, Slots: 1, RuntimeProfiles: []RuntimeProfileConfig{
		{ID: "default", ContextLimit: 4096, Slots: 1, SwitchCommand: []string{"/fixed/switch", "default"}},
		{ID: "long", ContextLimit: 8192, Slots: 1, SwitchCommand: []string{"/fixed/switch", "long"}},
	}}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	entered := make(chan struct{})
	release := make(chan struct{})
	enteredOnce := sync.Once{}
	p.runProfileCommand = func(context.Context, []string) error {
		enteredOnce.Do(func() { close(entered) })
		<-release
		stateMu.Lock()
		profileSwitched = true
		stateMu.Unlock()
		return nil
	}
	command := wsproto.CommandPayload{ID: "blocking-profile", IdempotencyKey: "blocking-profile", NodeID: cfg.NodeID, Command: "switch_runtime_profile", Args: map[string]any{"target_id": "node-1-llm", "profile_id": "long", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(10 * time.Second)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	resultCh := make(chan wsproto.CommandResultPayload, 1)
	go func() { resultCh <- p.Handle(context.Background(), command) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking lifecycle command did not reach side effect boundary")
	}
	// Handle holds its serialization mutex across the runtime call. Ready must
	// nevertheless be a lock-free heartbeat snapshot and report the in-flight
	// mutation as non-ready after multiple heartbeat intervals.
	for i := 0; i < 3; i++ {
		if p.Ready() {
			t.Fatalf("in-flight lifecycle mutation advertised Ready=true at interval %d", i)
		}
		time.Sleep(25 * time.Millisecond)
	}
	// A second external command must remain behind handleMu while the first
	// runtime call is in flight. It must not cross the live boundary or expose
	// a stale Ready=true heartbeat during that interval.
	concurrent := command
	concurrent.ID, concurrent.IdempotencyKey = "concurrent-profile", "concurrent-profile"
	concurrent.Args = map[string]any{"target_id": "node-1-llm", "profile_id": "long", "fencing_token": int64(2)}
	concurrent.Signature, _ = wsproto.SignCommand(concurrent, []byte(secret))
	concurrentResult := make(chan wsproto.CommandResultPayload, 1)
	go func() { concurrentResult <- p.Handle(context.Background(), concurrent) }()
	select {
	case result := <-concurrentResult:
		t.Fatalf("concurrent external command crossed serialized boundary: %+v", result)
	case <-time.After(100 * time.Millisecond):
		if p.Ready() {
			t.Fatal("concurrent external command exposed a stale Ready=true window")
		}
	}
	close(release)
	select {
	case result := <-resultCh:
		if !result.OK || !p.Ready() {
			t.Fatalf("readiness did not recover after lifecycle completion: result=%+v ready=%v", result, p.Ready())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking lifecycle command did not complete")
	}
	select {
	case result := <-concurrentResult:
		if !result.OK || !p.Ready() {
			t.Fatalf("serialized concurrent lifecycle command did not recover readiness: result=%+v ready=%v", result, p.Ready())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serialized concurrent lifecycle command did not complete")
	}
}

func TestResourceFenceMonotonicAndCollisionFree(t *testing.T) {
	p := &commandProcessor{fences: map[string]int64{}}
	high := wsproto.CommandPayload{Args: map[string]any{"fencing_token": json.Number("100")}}
	if err := p.checkFence(high, "node-ab", "runtime_profile"); err != nil {
		t.Fatal(err)
	}
	p.commitFence(high, "node-ab", "runtime_profile")
	lower := wsproto.CommandPayload{Args: map[string]any{"fencing_token": int64(1)}}
	if err := p.checkFence(lower, "node-ab", "runtime_profile"); err == nil {
		t.Fatal("lower desired-profile fence was accepted")
	}
	// Length-prefixing prevents (target="ab", resource="c") from
	// colliding with (target="a", resource="bc").
	if fenceKey("ab", "c") == fenceKey("a", "bc") {
		t.Fatal("resource fence tuple key collided")
	}
	if fenceKey("node", "runtime_profile") == fenceKey("node", "gpu_profile") {
		t.Fatal("distinct resource fences collided")
	}
}

func TestPartialResourceIntentRetainedAfterSideEffectError(t *testing.T) {
	var unloadAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": "loaded"}}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
		case "/models/unload":
			unloadAttempts++
			http.Error(w, "upstream sentinel", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := strings.Repeat("p", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, ContextLimit: 4096, Slots: 1, RouterManaged: true}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "drain-partial", IdempotencyKey: "drain-partial", NodeID: cfg.NodeID, Command: "drain_runtimes", Args: map[string]any{"target_id": "node-1-runtimes", "fencing_token": int64(7)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	result := p.Handle(context.Background(), command)
	if result.OK || !result.Uncertain || unloadAttempts == 0 {
		t.Fatalf("partial drain unexpectedly succeeded: %+v attempts=%d", result, unloadAttempts)
	}
	if _, ok := p.pending[command.ID]; !ok || !p.stateBlocked || p.stateBlockReason != blockReasonWarmTransient {
		t.Fatalf("post-side-effect intent was discarded: pending=%v blocked=%v reason=%q", p.pending, p.stateBlocked, p.stateBlockReason)
	}
}

func TestWarmIdentityDriftCloseFailurePersistsPendingAcrossRestartAndCleanupRetry(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileFingerprint := strings.Repeat("c", 64)
	runtimeSum := sha256.Sum256([]byte(`["model"]`))
	runtimeFingerprint := hex.EncodeToString(runtimeSum[:])
	var stateMu sync.Mutex
	loaded := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			stateMu.Lock()
			status := "unloaded"
			if loaded {
				status = "loaded"
			}
			stateMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": status}}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
		case "/models/unload":
			stateMu.Lock()
			loaded = false
			stateMu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/models/load":
			stateMu.Lock()
			loaded = true
			stateMu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := strings.Repeat("d", 32)
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
	cfg.WarmRAM = WarmRAMConfig{Enabled: true, ModelRoots: []string{root}, RAMTotalBytes: 100, RAMReserveBytes: 1, RAMHardCapBytes: 100, MaxWarmBytes: 100, MemlockLimitBytes: 100, CgroupLimitBytes: 100, PressureRefusalPercent: 90}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, PublicEndpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1,
		ModelPaths: map[string]string{"model": path}, ModelFingerprints: map[string]string{"model": fileFingerprint}, RuntimeFingerprints: map[string]string{"model": runtimeFingerprint}}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg.CapabilityVersion = discovery.Version
	cfg.Capabilities = domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, SupportsWarmRAM: true, WarmRAMVerified: true}
	runtimeIdentity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
	identity := warmFileIdentity{Dev: 1, Ino: 2, Size: 5, Mtime: 3, Hash: fileFingerprint}
	drift := identity
	drift.Ino = 99
	identityCalls := 0
	pin := &testWarmPin{resident: 5, locked: 5, closeErr: errors.New("close sentinel")}
	manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100, MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) {
			identityCalls++
			if identityCalls > 1 {
				return drift, nil
			}
			return identity, nil
		}, PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return pin, identity, nil
		},
		Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 99, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" }})
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	p.warmRAM = manager
	command := wsproto.CommandPayload{ID: "drift-offload", IdempotencyKey: "drift-offload", NodeID: cfg.NodeID, Command: "offload_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": runtimeIdentity, "capability_version": cfg.CapabilityVersion, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "warm_ram", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	if result := p.Handle(context.Background(), command); result.OK || !p.HasPending() || p.Ready() {
		t.Fatalf("identity drift did not retain durable transition: result=%+v pending=%v ready=%v", result, p.HasPending(), p.Ready())
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if q.Ready() || !q.HasPending() {
		t.Fatalf("fresh processor lost retained cleanup state: ready=%v pending=%v", q.Ready(), q.HasPending())
	}
	q.warmRAM = manager
	query := wsproto.CommandPayload{ID: "drift-query", IdempotencyKey: "drift-query", NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": runtimeIdentity, "capability_version": cfg.CapabilityVersion, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(1), "expected_fence": int64(1), "observed_after_fence": int64(1), "original_command_id": "drift-offload", "original_idempotency_key": "drift-offload"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	// While the reconstructed processor is still blocked on the genuine
	// pending intent, wrong-resource and runtime-identity queries must be
	// rejected at the signed Handle boundary without changing its fence.
	pendingFence := q.fences[fenceKey("node-1-runtime", "model")]
	crossResource := query
	crossResource.ID, crossResource.IdempotencyKey = "drift-query-cross", "drift-query-cross"
	crossResource.Args = map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "other-model", "runtime_identity": runtimeIdentity, "capability_version": cfg.CapabilityVersion, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(1), "expected_fence": int64(1), "observed_after_fence": int64(1), "original_command_id": "drift-offload", "original_idempotency_key": "drift-offload"}
	crossResource.Signature, _ = wsproto.SignCommand(crossResource, []byte(secret))
	if result := q.Handle(context.Background(), crossResource); result.Error == "" || !strings.Contains(result.Error, "allowlisted") || !q.HasPending() || q.fences[fenceKey("node-1-runtime", "model")] != pendingFence {
		t.Fatalf("cross-resource query changed live pending state: result=%+v pending=%v fence=%d", result, q.HasPending(), q.fences[fenceKey("node-1-runtime", "model")])
	}
	driftQuery := query
	driftQuery.ID, driftQuery.IdempotencyKey = "drift-query-identity", "drift-query-identity"
	driftQuery.Args = map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": runtimeIdentity + "|drift", "capability_version": cfg.CapabilityVersion, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(1), "expected_fence": int64(1), "observed_after_fence": int64(1), "original_command_id": "drift-offload", "original_idempotency_key": "drift-offload"}
	driftQuery.Signature, _ = wsproto.SignCommand(driftQuery, []byte(secret))
	if result := q.Handle(context.Background(), driftQuery); result.Error == "" || !strings.Contains(result.Error, "identity") || !q.HasPending() || q.fences[fenceKey("node-1-runtime", "model")] != pendingFence {
		t.Fatalf("runtime-identity drift query changed live pending state: result=%+v pending=%v fence=%d", result, q.HasPending(), q.fences[fenceKey("node-1-runtime", "model")])
	}
	// offload_model's only accepted inverse is exact cold-disk state; a hot
	// observation remains blocked rather than being treated as success.
	stateMu.Lock()
	loaded = false
	stateMu.Unlock()
	pin.closeErr = nil
	if err := manager.ReleaseModelFor("node-1-runtime", "model"); err != nil {
		t.Fatalf("failed to prepare exact cold inverse observation: %v", err)
	}
	query.Signature, _ = wsproto.SignCommand(query, []byte(secret))
	if result := q.Handle(context.Background(), query); !result.OK || q.HasPending() || !q.Ready() {
		t.Fatalf("signed authoritative query did not settle retained post-side-effect intent: result=%+v pending=%v ready=%v", result, q.HasPending(), q.Ready())
	}
	t.Log("live pending wrong-resource query rejected")
	t.Log("live pending runtime-identity query rejected")
	correlated, ok := q.results[command.ID]
	if !ok || correlated.OK || !strings.Contains(correlated.Error, "rolled back") {
		t.Fatalf("query settlement did not preserve exact inverse observation: correlated=%+v", correlated)
	}
	storedQuery, queryStored := q.results[query.ID]
	if !queryStored || storedQuery.Result["node_id"] != cfg.NodeID || storedQuery.Result["command_id"] != query.ID || storedQuery.Result["idempotency_key"] != query.IdempotencyKey || storedQuery.Result["command_fingerprint"] == nil || storedQuery.Result["fingerprint"] == nil {
		t.Fatalf("live query was not stored as a canonical replay envelope: %+v", storedQuery)
	}
	queryReplay := q.Handle(context.Background(), query)
	if !queryReplay.OK || queryReplay.CompletedAt != storedQuery.CompletedAt || queryReplay.Result["command_fingerprint"] != storedQuery.Result["command_fingerprint"] {
		t.Fatalf("live query canonical result did not replay through Handle: stored=%+v replay=%+v", storedQuery, queryReplay)
	}
	restarted := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	restarted.warmRAM = manager
	replayed := restarted.Handle(context.Background(), command)
	if replayed.OK != correlated.OK || replayed.Error != correlated.Error || !strings.EqualFold(fmt.Sprint(replayed.Result["tier"]), fmt.Sprint(correlated.Result["tier"])) {
		t.Fatalf("post-restart same-key replay did not return durable authoritative observation: correlated=%+v replay=%+v", correlated, replayed)
	}
	stateMu.Lock()
	loaded = false
	stateMu.Unlock()
	pin.closeErr = nil
	cleanup := wsproto.CommandPayload{ID: "drift-cleanup", IdempotencyKey: "drift-cleanup", NodeID: cfg.NodeID, Command: "cleanup_warm_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": runtimeIdentity, "capability_version": cfg.CapabilityVersion, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "cold_disk", "fencing_token": int64(2)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	cleanup.Signature, _ = wsproto.SignCommand(cleanup, []byte(secret))
	if result := q.Handle(context.Background(), cleanup); !result.OK || q.HasPending() || !q.Ready() || q.warmRAM.HasEntryFor("node-1-runtime", "model") {
		t.Fatalf("cleanup retry did not resolve retained transition: result=%+v pending=%v ready=%v entry=%v", result, q.HasPending(), q.Ready(), q.warmRAM.HasEntryFor("node-1-runtime", "model"))
	}
}

// These named product oracles keep the verifier's wrong-resource and runtime
// identity controls independently addressable while sharing the complete
// reconstructed live-pending boundary scenario above.
func TestLivePendingWrongResourceQueryThroughHandle(t *testing.T) {
	TestWarmIdentityDriftCloseFailurePersistsPendingAcrossRestartAndCleanupRetry(t)
}

func TestLivePendingRuntimeIdentityDriftThroughHandle(t *testing.T) {
	TestWarmIdentityDriftCloseFailurePersistsPendingAcrossRestartAndCleanupRetry(t)
}

func TestWarmCommandFailedLRUVictimCleanupRestoresReadiness(t *testing.T) {
	root := t.TempDir()
	victimPath, victim2Path, requestedPath := filepath.Join(root, "victim.bin"), filepath.Join(root, "victim2.bin"), filepath.Join(root, "requested.bin")
	for _, path := range []string{victimPath, victim2Path, requestedPath} {
		if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	victimFingerprint, victim2Fingerprint, requestedFingerprint := strings.Repeat("1", 64), strings.Repeat("3", 64), strings.Repeat("2", 64)
	runtimeSum := sha256.Sum256([]byte(`["requested","victim","victim2"]`))
	runtimeFingerprint := hex.EncodeToString(runtimeSum[:])
	unloadCalls := 0
	requestedLoaded := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			status := "unloaded"
			if requestedLoaded {
				status = "loaded"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "requested", "status": status}, {"id": "victim", "status": "unloaded"}, {"id": "victim2", "status": "unloaded"}}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
		case "/models/unload":
			unloadCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := strings.Repeat("l", 32)
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
	cfg.WarmRAM = WarmRAMConfig{Enabled: true, ModelRoots: []string{root}, RAMTotalBytes: 100, RAMReserveBytes: 1, RAMHardCapBytes: 100, MaxWarmBytes: 5, MemlockLimitBytes: 100, CgroupLimitBytes: 100, PressureRefusalPercent: 90}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, PublicEndpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1,
		ModelPaths: map[string]string{"requested": requestedPath, "victim": victimPath, "victim2": victim2Path}, ModelFingerprints: map[string]string{"requested": requestedFingerprint, "victim": victimFingerprint, "victim2": victim2Fingerprint}, RuntimeFingerprints: map[string]string{"requested": runtimeFingerprint, "victim": runtimeFingerprint, "victim2": runtimeFingerprint}}}
	identities := map[string]warmFileIdentity{victimPath: {Size: 5, Hash: victimFingerprint}, victim2Path: {Size: 5, Hash: victim2Fingerprint}, requestedPath: {Size: 5, Hash: requestedFingerprint}}
	victimPin := &testWarmPin{resident: 5, locked: 5}
	victim2Pin := &testWarmPin{resident: 5, locked: 5}
	manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 10, MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(path string, _ []string) (warmFileIdentity, error) { return identities[path], nil },
		PinFile: func(path string, _ []string, identity warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			if path == victimPath {
				return victimPin, identity, nil
			}
			if path == victim2Path {
				return victim2Pin, identity, nil
			}
			return &testWarmPin{resident: 5, locked: 5}, identity, nil
		},
		Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 99, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" }})
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "node-1-runtime", Model: "victim", Path: victimPath, ExpectedFingerprint: victimFingerprint, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
		t.Fatalf("victim setup failed: %v", err)
	}
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "node-1-runtime", Model: "victim2", Path: victim2Path, ExpectedFingerprint: victim2Fingerprint, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
		t.Fatalf("second victim setup failed: %v", err)
	}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetRuntimeManifest("node-1-runtime", "victim", runtimeFingerprint, server.URL, discovery.Version, discovery.ActiveRuntimeProfile); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetRuntimeManifest("node-1-runtime", "victim2", runtimeFingerprint, server.URL, discovery.Version, discovery.ActiveRuntimeProfile); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.entries[warmEntryKey("node-1-runtime", "victim")].lastUsed = time.Unix(1, 0).UTC()
	manager.entries[warmEntryKey("node-1-runtime", "victim2")].lastUsed = time.Unix(2, 0).UTC()
	manager.policy.MaxWarmBytes = 5
	manager.mu.Unlock()
	victimPin.closeErr = errors.New("LRU victim close sentinel")
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.warmRAM = manager
	request := wsproto.CommandPayload{ID: "lru-request", IdempotencyKey: "lru-request", NodeID: cfg.NodeID, Command: "offload_model", Args: map[string]any{"target_id": "node-1-runtime", "model": "requested", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	request.Signature, _ = wsproto.SignCommand(request, []byte(secret))
	if result := p.Handle(context.Background(), request); result.OK || !p.HasPending() || p.Ready() || !manager.HasEntryFor("node-1-runtime", "victim") || !manager.IsVerifiedFor("node-1-runtime", "victim2") || unloadCalls != 0 {
		t.Fatalf("failed first LRU victim did not block before later eviction/runtime mutation: result=%+v pending=%v ready=%v victim=%v victim2=%v unload=%d", result, p.HasPending(), p.Ready(), manager.HasEntryFor("node-1-runtime", "victim"), manager.IsVerifiedFor("node-1-runtime", "victim2"), unloadCalls)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if q.Ready() || !q.HasPending() {
		t.Fatalf("restart did not preserve LRU cleanup block: ready=%v pending=%v blocked=%v reason=%q pending_map=%+v", q.Ready(), q.HasPending(), q.stateBlocked, q.stateBlockReason, q.pending)
	}
	freshManager := NewWarmRAMManager(manager.policy)
	freshManager.RestoreManifests(q.persistedWarm)
	q.warmRAM = freshManager
	if q.warmRAM == manager || !q.warmRAM.HasEntryFor("node-1-runtime", "victim") {
		t.Fatal("restart test reused the in-memory manager or lost the persisted victim")
	}
	cleanup := wsproto.CommandPayload{ID: "lru-cleanup", IdempotencyKey: "lru-cleanup", NodeID: cfg.NodeID, Command: "cleanup_warm_model", Args: map[string]any{"target_id": "node-1-runtime", "model": "victim", "fencing_token": int64(2)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	cleanup.Signature, _ = wsproto.SignCommand(cleanup, []byte(secret))
	if result := q.Handle(context.Background(), cleanup); !result.OK || q.HasPending() == false || q.Ready() || q.warmRAM.HasEntryFor("node-1-runtime", "victim") {
		t.Fatalf("victim cleanup did not remove the failed handle before reconciliation: result=%+v pending=%v ready=%v victim=%v", result, q.HasPending(), q.Ready(), q.warmRAM.HasEntryFor("node-1-runtime", "victim"))
	}
	if err := q.ReconcileWarmManifests(context.Background()); err != nil {
		t.Fatalf("fresh-state manifest reconciliation failed: %v", err)
	}
	if q.Ready() || !q.HasPending() || !q.warmRAM.IsVerifiedFor("node-1-runtime", "victim2") {
		t.Fatalf("manifest reconciliation did not preserve pending request until runtime proof: ready=%v pending=%v victim2=%v", q.Ready(), q.HasPending(), q.warmRAM.IsVerifiedFor("node-1-runtime", "victim2"))
	}
	requestedLoaded = false
	if err := q.ReconcilePending(context.Background()); err != nil || !q.Ready() || q.HasPending() {
		t.Fatalf("fresh-state pending reconciliation did not restore readiness: err=%v ready=%v pending=%v", err, q.Ready(), q.HasPending())
	}
}

func TestPreflightFailuresDoNotRetainPendingOrBlock(t *testing.T) {
	makeServer := func(model, status string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/models":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": model, "status": status}}})
			case "/slots":
				_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
			default:
				http.NotFound(w, r)
			}
		}))
	}
	newCommand := func(cfg *Config, id, commandName, model string) wsproto.CommandPayload {
		command := wsproto.CommandPayload{ID: id, IdempotencyKey: id, NodeID: cfg.NodeID, Command: commandName, Args: map[string]any{"target_id": "node-1-runtime", "model": model, "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
		command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
		return command
	}
	t.Run("unknown model", func(t *testing.T) {
		server := makeServer("other", "loaded")
		defer server.Close()
		cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("u", 32), CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
		cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true}}
		p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		result := p.Handle(context.Background(), newCommand(cfg, "unknown-model", "load_model", "missing"))
		if result.OK || p.HasPending() || !p.Ready() {
			t.Fatalf("unknown model retained mutation state: result=%+v pending=%v ready=%v", result, p.pending, p.Ready())
		}
	})
	t.Run("unsupported runtime", func(t *testing.T) {
		server := makeServer("model", "loaded")
		defer server.Close()
		cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("v", 32), CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
		cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL}}
		p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		result := p.Handle(context.Background(), newCommand(cfg, "unsupported-runtime", "load_model", "model"))
		if result.OK || p.HasPending() || !p.Ready() {
			t.Fatalf("unsupported runtime retained mutation state: result=%+v pending=%v ready=%v", result, p.pending, p.Ready())
		}
	})
	t.Run("missing protection entry", func(t *testing.T) {
		server := makeServer("model", "unloaded")
		defer server.Close()
		cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("w", 32), CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
		cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL}}
		p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		result := p.Handle(context.Background(), newCommand(cfg, "missing-protection", "protect_warm_model", "model"))
		if result.OK || p.HasPending() || !p.Ready() {
			t.Fatalf("missing protection entry retained mutation state: result=%+v pending=%v ready=%v", result, p.pending, p.Ready())
		}
	})
}

func TestLegacyPrimaryWithExistingJournalIsBlocked(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("l", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope commandStateEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	// Make a valid-looking legacy primary while retaining the non-empty
	// journal. The journal's existence makes sequence zero a rollback.
	envelope.State.JournalSequence = 0
	envelope.State.JournalPrevHash = ""
	envelope.Checksum = checksumForStatePayload(envelope.State)
	legacy, _ := json.Marshal(envelope)
	if err := os.WriteFile(statePath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q.stateBlocked || q.stateBlockReason != blockReasonDurability {
		t.Fatalf("sequence-zero primary beside journal was accepted: blocked=%v reason=%q", q.stateBlocked, q.stateBlockReason)
	}
}

func TestJournalMismatchCannotBeDowngradedByPersistedWarmBlock(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("j", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.save(); err != nil {
		t.Fatalf("initial anchored state save failed: %v", err)
	}
	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope commandStateEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	// Keep the authenticated journal unchanged, but make a validly checksummed
	// primary claim only a transient warm-reconciliation block. Journal
	// validation must detect that this primary is not the anchored state, and
	// restoring its weaker reason must not erase the durability finding.
	envelope.State.BlockReason = blockReasonWarmTransient
	envelope.Checksum = checksumForStatePayload(envelope.State)
	rewritten, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if loaded.initError != nil {
		t.Fatalf("validly checksummed primary was rejected before journal validation: %v", loaded.initError)
	}
	if loaded.Ready() || !loaded.stateBlocked || loaded.stateBlockReason != blockReasonDurability {
		t.Fatalf("persisted warm reason downgraded journal mismatch: ready=%v blocked=%v reason=%q", loaded.Ready(), loaded.stateBlocked, loaded.stateBlockReason)
	}
}

func TestMissingPrimaryWithJournalOrMarkerIsBlocked(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("m", 32), CommandStatePath: statePath}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if q.Ready() || !q.stateBlocked || q.stateBlockReason != blockReasonDurability {
		t.Fatalf("missing primary beside journal was accepted: ready=%v blocked=%v reason=%q", q.Ready(), q.stateBlocked, q.stateBlockReason)
	}
	command := wsproto.CommandPayload{ID: "missing-primary", IdempotencyKey: "missing-primary", NodeID: cfg.NodeID, Command: "refresh_capabilities", Args: map[string]any{}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
	if result := q.Handle(context.Background(), command); result.OK || !strings.Contains(result.Error, "durability_failure") {
		t.Fatalf("command executed with missing durable primary: %+v", result)
	}
	emptyCfg := &Config{NodeID: "node-empty", CommandSigningSecret: strings.Repeat("e", 32), CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	if err := os.WriteFile(emptyCfg.CommandStatePath+".journal", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	empty := newCommandProcessor(emptyCfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if empty.Ready() || !empty.stateBlocked {
		t.Fatal("empty journal beside missing primary was treated as first boot")
	}
	markerCfg := &Config{NodeID: "node-marker", CommandSigningSecret: strings.Repeat("n", 32), CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	marker := newCommandProcessor(markerCfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := marker.writeRecoveryMarker(blockReasonDurability, recoveryMarkerPhasePrepared, recoveryFileIdentity{}, recoveryFileIdentity{}); err != nil {
		t.Fatal(err)
	}
	markerReloaded := newCommandProcessor(markerCfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if markerReloaded.Ready() || !markerReloaded.stateBlocked {
		t.Fatal("recovery marker beside missing primary was treated as first boot")
	}
}

func TestBlockedProcessorDoesNotReplayCachedSuccess(t *testing.T) {
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("b", 32), CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	command := wsproto.CommandPayload{ID: "cached-success", IdempotencyKey: "cached-success", NodeID: cfg.NodeID, Command: "refresh_capabilities", Args: map[string]any{}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
	p.results[command.ID] = wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, OK: true, Result: map[string]any{"cached": true}}
	p.commandFingerprints["id:"+command.ID] = p.semanticFingerprint(command)
	p.block(blockReasonDurability)
	result := p.Handle(context.Background(), command)
	if result.OK || !strings.Contains(result.Error, blockReasonDurability) {
		t.Fatalf("blocked processor replayed cached success: %+v", result)
	}
}

func TestProductFenceRejectsLowerRuntimeProfileTokenAcrossAliases(t *testing.T) {
	currentContext, sideEffects := 4096, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": "loaded"}}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": currentContext, "is_processing": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := strings.Repeat("r", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "llm", Endpoint: server.URL, ContextLimit: 4096, Slots: 1, RuntimeProfiles: []RuntimeProfileConfig{{ID: "profile-a", ContextLimit: 8192, Slots: 1}, {ID: "profile-b", ContextLimit: 16384, Slots: 1}}}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.runProfileCommand = func(_ context.Context, _ []string) error { sideEffects++; currentContext = 8192; return nil }
	makeCommand := func(id, target, profile string, token int64) wsproto.CommandPayload {
		command := wsproto.CommandPayload{ID: id, IdempotencyKey: id, NodeID: cfg.NodeID, Command: "switch_runtime_profile", Args: map[string]any{"target_id": target, "profile_id": profile, "fencing_token": token}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
		command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
		return command
	}
	if result := p.Handle(context.Background(), makeCommand("profile-a", "llm", "profile-a", 100)); !result.OK {
		t.Fatalf("high-fence runtime profile command failed: %+v", result)
	}
	result := p.Handle(context.Background(), makeCommand("profile-b", "node-1-llm", "profile-b", 1))
	if result.OK || !strings.Contains(result.Error, "stale fencing token") || sideEffects != 1 {
		t.Fatalf("lower profile fence reached side effect: result=%+v side_effects=%d", result, sideEffects)
	}
}

func TestProductFenceRejectsLowerGPUProfileToken(t *testing.T) {
	secret := strings.Repeat("g", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	cfg.GPUPerformance.Accelerators = []GPUPerformanceConfig{{Index: 0, IdleCommand: []string{"idle"}, ActiveCommand: []string{"active"}}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sideEffects := 0
	p.runProfileCommand = func(_ context.Context, _ []string) error { sideEffects++; return nil }
	makeCommand := func(id, profile string, token int64) wsproto.CommandPayload {
		command := wsproto.CommandPayload{ID: id, IdempotencyKey: id, NodeID: cfg.NodeID, Command: "set_gpu_performance_profile", Args: map[string]any{"accelerator_id": "node-1-gpu0", "profile": profile, "fencing_token": token}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
		command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
		return command
	}
	if result := p.Handle(context.Background(), makeCommand("gpu-active", "active", 100)); !result.OK {
		t.Fatalf("high-fence GPU profile command failed: %+v", result)
	}
	result := p.Handle(context.Background(), makeCommand("gpu-idle", "idle", 1))
	if result.OK || !strings.Contains(result.Error, "stale fencing token") || sideEffects != 1 {
		t.Fatalf("lower GPU profile fence reached side effect: result=%+v side_effects=%d", result, sideEffects)
	}
}

func TestProductionFenceKeysKeepCollisionShapedModelTargetsDistinct(t *testing.T) {
	makeRuntime := func(model string, sideEffects *int) *httptest.Server {
		loaded := false
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/models":
				status := "unloaded"
				if loaded {
					status = "loaded"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": model, "status": status}}})
			case "/slots":
				_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
			case "/api/ps":
				http.NotFound(w, r)
			case "/models/load":
				loaded = true
				*sideEffects++
				w.WriteHeader(http.StatusOK)
			case "/models/unload":
				loaded = false
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
	}
	firstEffects, secondEffects := 0, 0
	firstServer := makeRuntime("b:c", &firstEffects)
	defer firstServer.Close()
	secondServer := makeRuntime("c", &secondEffects)
	defer secondServer.Close()
	secret := strings.Repeat("x", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(t.TempDir(), "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "a", Endpoint: firstServer.URL, RouterManaged: true}, {ID: "a:b", Endpoint: secondServer.URL, RouterManaged: true}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	makeCommand := func(id, target, model string) wsproto.CommandPayload {
		command := wsproto.CommandPayload{ID: id, IdempotencyKey: id, NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_id": target, "model": model, "fencing_token": int64(100)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
		command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
		return command
	}
	if result := p.Handle(context.Background(), makeCommand("collision-one", "a", "b:c")); !result.OK {
		t.Fatalf("first collision-shaped lifecycle command failed: %+v", result)
	}
	if result := p.Handle(context.Background(), makeCommand("collision-two", "a:b", "c")); !result.OK {
		t.Fatalf("second collision-shaped lifecycle command was incorrectly fenced: %+v", result)
	}
	if firstEffects != 1 || secondEffects != 1 {
		t.Fatalf("structured production keys did not isolate side effects: first=%d second=%d fences=%v", firstEffects, secondEffects, p.fences)
	}
}

func TestReconcilePendingLoadTransitionalRemainsPendingAfterRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "model", "status": "loading"}}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("r", 32), CommandStatePath: statePath}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1, ModelPaths: map[string]string{"model": filepath.Join(t.TempDir(), "model.gguf")}}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manifest, _ := json.Marshal(map[string]any{"target_id": "node-1-runtime", "model": "model"})
	p.pending["load-transitional"] = pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: "load_model", Token: 7, CommandID: "load-transitional", IdempotencyKey: "load-transitional", Fingerprint: "fixture", ManifestJSON: string(manifest)}
	p.inflight[fenceKey("node-1-runtime", "model")] = true
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !q.HasPending() {
		t.Fatal("restart did not restore transitional lifecycle intent")
	}
	if err := q.ReconcilePending(context.Background()); err == nil {
		t.Fatal("transitional lifecycle state was incorrectly terminalized")
	}
	if !q.HasPending() {
		t.Fatal("transitional lifecycle intent was discarded after failed reconciliation")
	}
}

func TestReconcilePendingWarmTransitionalRemainsPendingAfterRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "model", "status": "unloading"}}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	root := t.TempDir()
	modelPath := filepath.Join(root, "model.gguf")
	_ = os.WriteFile(modelPath, []byte("model"), 0o600)
	fileFingerprint := strings.Repeat("a", 64)
	runtimeFingerprint := strings.Repeat("b", 64)
	statePath := filepath.Join(root, "commands.json")
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("w", 32), CommandStatePath: statePath}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1, ModelPaths: map[string]string{"model": modelPath}, ModelFingerprints: map[string]string{"model": fileFingerprint}, RuntimeFingerprints: map[string]string{"model": runtimeFingerprint}}}
	cfg.WarmRAM = WarmRAMConfig{Enabled: true, ModelRoots: []string{root}, RAMTotalBytes: 1024, RAMReserveBytes: 1, RAMHardCapBytes: 1024, MaxWarmBytes: 1024, MemlockLimitBytes: 1024}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manifest, _ := json.Marshal(map[string]any{"target_id": "node-1-runtime", "model": "model"})
	p.pending["warm-transitional"] = pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: "warm_model", Token: 8, CommandID: "warm-transitional", IdempotencyKey: "warm-transitional", Fingerprint: "fixture", RuntimeIdentity: "runtime", ManifestJSON: string(manifest), Path: modelPath, FileFingerprint: fileFingerprint, RuntimeFingerprint: runtimeFingerprint}
	p.inflight[fenceKey("node-1-runtime", "model")] = true
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := q.ReconcilePending(context.Background()); err == nil {
		t.Fatal("transitional warm state was incorrectly converted into a warm proof")
	}
	if !q.HasPending() {
		t.Fatal("transitional warm intent was discarded after failed reconciliation")
	}
}

func TestReconcilePendingPersistsCanonicalReplayForAllResidencyActions(t *testing.T) {
	for _, action := range []string{"load_model", "unload_model", "warm_model", "cleanup_warm_model", "offload_model", "demote_model", "protect_warm_model", "reverify_warm_model"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			modelPath := filepath.Join(root, "model.gguf")
			if err := os.WriteFile(modelPath, []byte("model"), 0o600); err != nil {
				t.Fatal(err)
			}
			var mutations atomic.Int32
			status := "unloaded"
			if action == "load_model" {
				status = "loaded"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/models":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": status}}})
				case "/slots":
					_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
				case "/models/load", "/models/unload":
					mutations.Add(1)
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			secret := strings.Repeat("c", 32)
			statePath := filepath.Join(root, "commands.json")
			fileFingerprint := strings.Repeat("f", 64)
			cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
			cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1,
				ModelPaths: map[string]string{"model": modelPath}, ModelFingerprints: map[string]string{"model": fileFingerprint}}}
			discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
			if err != nil {
				t.Fatal(err)
			}
			cfg.CapabilityVersion = discovery.Version
			cfg.Capabilities.Version = domain.CapabilityContractVersion
			cfg.LlamaCPP.Servers[0].RuntimeFingerprints = map[string]string{"model": discovery.ModelFingerprint}

			var warmManagerFactory func() *WarmRAMManager
			var pinCalls atomic.Int32
			if action == "warm_model" {
				identity := warmFileIdentity{Size: int64(len("model")), Hash: fileFingerprint}
				policy := WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 1024, RAMReserveBytes: 1, MaxWarmBytes: 1024, MemlockLimitBytes: 1024,
					OpenIdentity: func(string, []string) (warmFileIdentity, error) { return identity, nil },
					PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
						pinCalls.Add(1)
						return &testWarmPin{resident: identity.Size, locked: identity.Size}, identity, nil
					},
					Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 1023, 0, 0, 0, nil },
					MemlockLimit: func() (int64, error) { return 1024, nil }, Oracle: func() string { return "mincore+mlock" }}
				warmManagerFactory = func() *WarmRAMManager { return NewWarmRAMManager(policy) }
				cfg.WarmRAM = WarmRAMConfig{Enabled: true, ModelRoots: []string{root}, RAMTotalBytes: 1024, RAMReserveBytes: 1, RAMHardCapBytes: 1024, MaxWarmBytes: 1024, MemlockLimitBytes: 1024}
			} else if action == "offload_model" || action == "demote_model" || action == "protect_warm_model" || action == "reverify_warm_model" {
				identity := warmFileIdentity{Size: int64(len("model")), Hash: fileFingerprint}
				policy := WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 1024, RAMReserveBytes: 1, MaxWarmBytes: 1024, MemlockLimitBytes: 1024,
					OpenIdentity: func(string, []string) (warmFileIdentity, error) { return identity, nil },
					PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
						pinCalls.Add(1)
						return &testWarmPin{resident: identity.Size, locked: identity.Size}, identity, nil
					},
					Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 1023, 0, 0, 0, nil },
					MemlockLimit: func() (int64, error) { return 1024, nil }, Oracle: func() string { return "mincore+mlock" }}
				warmManagerFactory = func() *WarmRAMManager { return NewWarmRAMManager(policy) }
				cfg.WarmRAM = WarmRAMConfig{Enabled: true, ModelRoots: []string{root}, RAMTotalBytes: 1024, RAMReserveBytes: 1, RAMHardCapBytes: 1024, MaxWarmBytes: 1024, MemlockLimitBytes: 1024}
			}

			p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if warmManagerFactory != nil {
				p.warmRAM = warmManagerFactory()
				p.warmRAM.RestoreManifests([]WarmRAMManifest{{TargetID: "node-1-runtime", Model: "model", CanonicalPath: modelPath, FileFingerprint: fileFingerprint, RuntimeFingerprint: discovery.ModelFingerprint, RuntimeEndpoint: server.URL, RuntimeVersion: discovery.Version, RuntimeProfile: discovery.ActiveRuntimeProfile, RuntimeProfilePresent: true, Size: identitySizeForTest(modelPath), Verified: true, VRAMReleased: true, LastUsed: time.Now().UTC()}})
			}
			expectedTier := expectedResidencyTier(action)
			command := wsproto.CommandPayload{ID: "reconcile-" + action, IdempotencyKey: "reconcile-" + action, NodeID: cfg.NodeID, Command: action,
				Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": canonicalCommandRuntimeIdentity("node-1-runtime", discovery), "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": expectedTier, "fencing_token": int64(17)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
			if action == "protect_warm_model" {
				command.Args["active_references"] = int64(0)
				command.Args["protected"] = true
			}
			command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
			intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: action, Token: 17, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: p.semanticFingerprint(command), Path: modelPath, FileFingerprint: fileFingerprint, RuntimeFingerprint: discovery.ModelFingerprint, Protected: true}
			manifest, _ := pendingManifestFor(command, command.Args, intent.TargetID, intent.Model, intent.Token, intent)
			intent.ManifestJSON = string(manifest)
			p.pending[command.ID] = intent
			p.inflight[fenceKey("node-1-runtime", "model")] = true
			if err := p.save(); err != nil {
				t.Fatal(err)
			}

			q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			crashAfterJournal := action == "protect_warm_model"
			if warmManagerFactory != nil {
				q.warmRAM = warmManagerFactory()
				q.restoreWarmManifests()
			}
			if crashAfterJournal {
				q.afterReconciledJournal = func() error { return errors.New("simulated local crash after result journal") }
			}
			reconcileErr := q.ReconcilePending(context.Background())
			if crashAfterJournal && reconcileErr == nil {
				t.Fatal("local crash hook did not interrupt before pending deletion")
			}
			if !crashAfterJournal && reconcileErr != nil {
				t.Fatalf("reconciliation failed: %v", reconcileErr)
			}
			if q.HasPending() != crashAfterJournal {
				t.Fatal("successful reconciliation left the intent pending")
			}
			cached := q.results[command.ID]
			for _, key := range []string{"target_id", "model", "runtime_identity", "capability_version", "capability_revision", "tier", "fencing_token", "observed_after_fence"} {
				if cached.Result[key] == nil {
					t.Fatalf("reconciled result omitted canonical field %q: %+v", key, cached.Result)
				}
			}
			allowed := cachedResidencyResultAllowedKeys(action)
			for key := range cached.Result {
				if !allowed[key] {
					t.Fatalf("%s result contains non-canonical field %q: %+v", action, key, cached.Result)
				}
			}
			resident, residentOK := cached.Result["resident"].(bool)
			warm, warmOK := cached.Result["warm_ram"].(bool)
			if !residentOK || !warmOK {
				t.Fatalf("%s result omitted typed residency proof: %+v", action, cached.Result)
			}
			if action == "load_model" && (!resident || warm) || (action == "unload_model" || action == "cleanup_warm_model") && (resident || warm) || (action == "warm_model" || action == "offload_model" || action == "demote_model" || action == "protect_warm_model" || action == "reverify_warm_model") && (resident || !warm) {
				t.Fatalf("%s result has invalid resident/warm_ram proof: %+v", action, cached.Result)
			}
			wantTier := expectedResidencyTier(action)
			if cached.Result["tier"] != wantTier {
				t.Fatalf("reconciled result reported tier %v, want %s", cached.Result["tier"], wantTier)
			}
			if action == "warm_model" && cached.Result["warm_model_bytes_verified"] != true {
				t.Fatalf("warm reconciliation omitted verified proof: %+v", cached.Result)
			}
			if action == "offload_model" || action == "demote_model" || action == "protect_warm_model" || action == "reverify_warm_model" {
				if pinCalls.Load() == 0 {
					t.Fatalf("%s reconciliation did not perform the local pin verification", action)
				}
			}
			if action == "protect_warm_model" {
				manifests := q.warmRAM.ManifestSnapshot()
				if len(manifests) != 1 || !manifests[0].Protected {
					t.Fatalf("protection reconciliation did not persist local protection state: %+v", manifests)
				}
			}
			if action == "cleanup_warm_model" && (cached.Result["warm_entry_absent"] != true || cached.Result["warm_release_verified"] != true || cached.Result["locked_bytes"] != int64(0)) {
				t.Fatalf("cleanup reconciliation omitted release proof: %+v", cached.Result)
			}
			if action == "cleanup_warm_model" && cached.Result["warm_model_bytes"] != int64(0) {
				t.Fatalf("cleanup reconciliation reported nonzero warm bytes: %+v", cached.Result)
			}
			before := cached.Result
			restarted := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if warmManagerFactory != nil {
				// The fixture intentionally uses a deterministic file identity. Rebuild
				// the same verified backend before replaying its durable recovery intent.
				restarted.warmRAM = warmManagerFactory()
				restarted.restoreWarmManifests()
			}
			r := restarted.Handle(context.Background(), command)
			if !r.OK || r.Uncertain || !cached.OK || cached.Uncertain {
				t.Fatalf("restart replay failed: %+v", r)
			}
			if got, want := jsonMarshalForTest(r.Result), jsonMarshalForTest(before); got != want {
				t.Fatalf("restart replay changed authoritative result: got=%s want=%s", got, want)
			}
			if mutations.Load() != 0 {
				t.Fatalf("reconciliation replay issued a runtime mutation: %d", mutations.Load())
			}
			if crashAfterJournal {
				if err := restarted.ReconcilePending(context.Background()); err != nil || restarted.HasPending() {
					t.Fatalf("local journaled result was not safely retired: err=%v pending=%v", err, restarted.HasPending())
				}
			}
		})
	}
}

func identitySizeForTest(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func jsonMarshalForTest(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestReconcilePendingRejectsManifestOperationMismatch(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "commands.json")
	cfg := &Config{NodeID: "node-1", CommandStatePath: statePath}
	cfg.CapabilityVersion = "runtime-v1"
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: "http://127.0.0.1:1", ContextLimit: 4096, Slots: 1}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	command := wsproto.CommandPayload{ID: "manifest-op", IdempotencyKey: "manifest-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "node-1-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(9)}}
	intent := pendingCommand{TargetID: command.Args["target_id"].(string), Model: "model", Command: command.Command, Token: 9, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: p.semanticFingerprint(command)}
	manifest, err := pendingManifestFor(command, command.Args, intent.TargetID, intent.Model, intent.Token, intent)
	if err != nil {
		t.Fatal(err)
	}
	var encoded pendingOperationManifest
	if err := json.Unmarshal(manifest, &encoded); err != nil {
		t.Fatal(err)
	}
	encoded.Action = "unload_model"
	manifest, _ = json.Marshal(encoded)
	intent.ManifestJSON = string(manifest)
	p.pending[intent.CommandID] = intent
	p.inflight[fenceKey(intent.TargetID, intent.Model)] = true
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if err := q.ReconcilePending(context.Background()); err == nil || !strings.Contains(err.Error(), "operation binding") {
		t.Fatalf("manifest mismatch was not rejected: %v", err)
	}
	if !q.HasPending() {
		t.Fatal("manifest mismatch discarded the durable pending operation")
	}
}

func TestReconcilePendingManifestMismatchMatrix(t *testing.T) {
	mutations := []struct {
		name string
		edit func(map[string]any)
	}{
		{"action", func(m map[string]any) { m["action"] = "unload_model" }},
		{"target_kind", func(m map[string]any) { m["target_kind"] = "other" }},
		{"target_id", func(m map[string]any) { m["target_id"] = "node-1-other" }},
		{"model", func(m map[string]any) { m["model"] = "other" }},
		{"runtime_identity", func(m map[string]any) { m["runtime_identity"] = "runtime-drift" }},
		{"capability_version", func(m map[string]any) { m["capability_version"] = "runtime-drift" }},
		{"capability_revision", func(m map[string]any) { m["capability_revision"] = "schema-drift" }},
		{"expected_tier", func(m map[string]any) { m["expected_tier"] = "cold_disk" }},
		{"fencing_token", func(m map[string]any) { m["fencing_token"] = float64(10) }},
		{"idempotency", func(m map[string]any) { m["idempotency_key"] = "other-key" }},
		{"sparse", func(m map[string]any) { delete(m, "runtime_identity") }},
		{"extra_manifest", func(m map[string]any) { m["unexpected"] = true }},
		{"extra_argument", func(m map[string]any) { m["args"].(map[string]any)["unexpected"] = true }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			root := t.TempDir()
			cfg := &Config{NodeID: "node-1", CommandStatePath: filepath.Join(root, "commands.json")}
			cfg.CapabilityVersion = "runtime-v1"
			cfg.Capabilities.Version = domain.CapabilityContractVersion
			p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			command := wsproto.CommandPayload{ID: "matrix-id", IdempotencyKey: "matrix-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "node-1-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(9)}}
			intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: command.Command, Token: 9, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: p.semanticFingerprint(command)}
			manifestBytes, err := pendingManifestFor(command, command.Args, intent.TargetID, intent.Model, intent.Token, intent)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				t.Fatal(err)
			}
			mutation.edit(manifest)
			manifestBytes, _ = json.Marshal(manifest)
			intent.ManifestJSON = string(manifestBytes)
			p.pending[intent.CommandID] = intent
			p.inflight[fenceKey(intent.TargetID, intent.Model)] = true
			if err := p.save(); err != nil {
				t.Fatal(err)
			}
			q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			if err := q.ReconcilePending(context.Background()); err == nil {
				t.Fatal("manifest mismatch was accepted")
			}
			if !q.HasPending() {
				t.Fatal("manifest mismatch discarded durable pending state")
			}
		})
	}
}

func TestReconcilePendingRejectsCachedResultEnvelopeDrift(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{NodeID: "node-1", CommandStatePath: filepath.Join(root, "commands.json")}
	cfg.CapabilityVersion = "runtime-v1"
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: "http://127.0.0.1:1", RouterManaged: true}}
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	command := wsproto.CommandPayload{ID: "cached-drift", IdempotencyKey: "cached-drift-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "node-1-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(9)}}
	intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: command.Command, Token: 9, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: p.semanticFingerprint(command), RuntimeIdentity: command.Args["runtime_identity"].(string)}
	manifest, err := pendingManifestFor(command, command.Args, intent.TargetID, intent.Model, intent.Token, intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.ManifestJSON = string(manifest)
	p.pending[command.ID] = intent
	p.inflight[fenceKey(intent.TargetID, intent.Model)] = true
	cached := p.reconciledResidencyResult(intent, wsproto.AdapterAdvertisement{ID: "runtime", Adapter: "llamacpp", Version: "runtime-v1", ModelFingerprint: "fingerprint"}, "hot_vram", true, nil, nil)
	manifestValue, err := p.validatePendingManifest(intent)
	if err != nil {
		t.Fatal(err)
	}
	basePayload := wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: cached, CompletedAt: time.Now().UTC()}
	mutations := []struct {
		name string
		edit func(*wsproto.CommandResultPayload, map[string]any)
	}{
		{"outer-id", func(payload *wsproto.CommandResultPayload, _ map[string]any) { payload.ID = "other" }},
		{"outer-node", func(payload *wsproto.CommandResultPayload, _ map[string]any) { payload.NodeID = "other-node" }},
		{"outer-status", func(payload *wsproto.CommandResultPayload, _ map[string]any) { payload.Status = "failed" }},
		{"outer-uncertain", func(payload *wsproto.CommandResultPayload, _ map[string]any) { payload.Uncertain = true }},
		{"action", func(_ *wsproto.CommandResultPayload, result map[string]any) { result["action"] = "unload_model" }},
		{"idempotency-alias", func(_ *wsproto.CommandResultPayload, result map[string]any) { result["idempotency_key"] = "other" }},
		{"original-id-alias", func(_ *wsproto.CommandResultPayload, result map[string]any) { result["original_command_id"] = "other" }},
		{"command-id-alias", func(_ *wsproto.CommandResultPayload, result map[string]any) { result["command_id"] = "other" }},
		{"fingerprint-alias", func(_ *wsproto.CommandResultPayload, result map[string]any) { result["fingerprint"] = "other" }},
		{"command-fingerprint-alias", func(_ *wsproto.CommandResultPayload, result map[string]any) { result["command_fingerprint"] = "other" }},
		{"proof", func(_ *wsproto.CommandResultPayload, result map[string]any) { delete(result, "resident") }},
		{"unknown", func(_ *wsproto.CommandResultPayload, result map[string]any) { result["unexpected"] = true }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			payload := basePayload
			result := make(map[string]any, len(cached))
			for key, value := range cached {
				result[key] = value
			}
			mutation.edit(&payload, result)
			payload.Result = result
			if cachedReconciledResultMatches(intent, manifestValue, payload) {
				t.Fatal("cached result drift was accepted")
			}
		})
	}
	// A journaled success is only replayable when both durable result aliases
	// survived the crash. Removing the idempotency alias must retain pending.
	basePayload.Result = cached
	p.results[command.ID] = basePayload
	p.commandFingerprints["id:"+command.ID] = intent.Fingerprint
	p.commandFingerprints[intent.IdempotencyKey] = intent.Fingerprint
	delete(p.results, "key:"+intent.IdempotencyKey)
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	missingAlias := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if err := missingAlias.ReconcilePending(context.Background()); err == nil || !missingAlias.HasPending() {
		t.Fatal("cached result missing its idempotency alias was accepted or pending was discarded")
	}
	// Both durable fingerprint aliases are independently required. A journal
	// containing only one alias, or one with a drifted value, must remain
	// pending even when both result aliases are intact.
	p.results["key:"+intent.IdempotencyKey] = basePayload
	delete(p.commandFingerprints, "id:"+command.ID)
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	missingFingerprintAlias := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if err := missingFingerprintAlias.ReconcilePending(context.Background()); err == nil || !missingFingerprintAlias.HasPending() {
		t.Fatal("cached result missing its command fingerprint alias was accepted or pending was discarded")
	}
	p.commandFingerprints["id:"+command.ID] = intent.Fingerprint
	p.commandFingerprints[intent.IdempotencyKey] = "drifted"
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	driftedFingerprintAlias := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if err := driftedFingerprintAlias.ReconcilePending(context.Background()); err == nil || !driftedFingerprintAlias.HasPending() {
		t.Fatal("cached result with a drifted command fingerprint alias was accepted or pending was discarded")
	}
	p.commandFingerprints[intent.IdempotencyKey] = intent.Fingerprint
	p.results["key:"+intent.IdempotencyKey] = basePayload
	cached["unexpected"] = true
	basePayload.Result = cached
	p.results[command.ID] = basePayload
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	restarted := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if err := restarted.ReconcilePending(context.Background()); err == nil {
		t.Fatal("cached result with an unknown field was accepted")
	}
	if !restarted.HasPending() {
		t.Fatal("invalid cached result discarded the durable pending intent")
	}
}

func TestHandleCachedMutationReplayRejectsAliasBindingAndProofDrift(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("h", 32), CommandStatePath: filepath.Join(root, "commands.json"), CapabilityVersion: "runtime-v1"}
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	identity := "node-1-runtime|llamacpp||runtime-v1|fingerprint"
	command := wsproto.CommandPayload{ID: "handle-cache", IdempotencyKey: "handle-cache-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(9)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
	base := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: command.Command, Token: 9, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: base.semanticFingerprint(command), RuntimeIdentity: identity}
	manifest, err := pendingManifestFor(command, command.Args, intent.TargetID, intent.Model, intent.Token, intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.ManifestJSON = string(manifest)
	canonical := base.reconciledResidencyResult(intent, wsproto.AdapterAdvertisement{ID: "runtime", Adapter: "llamacpp", Version: "runtime-v1", ModelFingerprint: "fingerprint"}, "hot_vram", true, nil, nil)
	clone := func(input map[string]any) map[string]any {
		output := make(map[string]any, len(input))
		for key, value := range input {
			output[key] = value
		}
		return output
	}
	cases := []struct {
		name string
		edit func(map[string]any, *map[string]any)
	}{
		{"missing-id-alias", func(_ map[string]any, aliases *map[string]any) { *aliases = nil }},
		{"missing-fingerprint-alias", func(result map[string]any, _ *map[string]any) { delete(result, "fingerprint") }},
		{"divergent-alias", func(_ map[string]any, _ *map[string]any) {}},
		{"target-kind", func(result map[string]any, _ *map[string]any) { result["target_kind"] = "wrong" }},
		{"target-id", func(result map[string]any, _ *map[string]any) { result["target_id"] = "other-runtime" }},
		{"model", func(result map[string]any, _ *map[string]any) { result["model"] = "other-model" }},
		{"runtime-identity", func(result map[string]any, _ *map[string]any) { result["runtime_identity"] = "drift" }},
		{"capability-version", func(result map[string]any, _ *map[string]any) { result["capability_version"] = "drift" }},
		{"capability-revision", func(result map[string]any, _ *map[string]any) { result["capability_revision"] = "drift" }},
		{"fence", func(result map[string]any, _ *map[string]any) { result["fencing_token"] = int64(8) }},
		{"observed-fence", func(result map[string]any, _ *map[string]any) { result["observed_after_fence"] = int64(8) }},
		{"action", func(result map[string]any, _ *map[string]any) { result["action"] = "unload_model" }},
		{"changed-missing", func(result map[string]any, _ *map[string]any) { delete(result, "changed") }},
		{"changed-type", func(result map[string]any, _ *map[string]any) { result["changed"] = "false" }},
		{"proof-missing", func(result map[string]any, _ *map[string]any) { delete(result, "resident") }},
		{"unknown-proof", func(result map[string]any, _ *map[string]any) { result["unexpected"] = true }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			q.stateBlocked, q.stateBlockReason = true, blockReasonWarmTransient
			result := clone(canonical)
			var alternate map[string]any = clone(canonical)
			missingAlias := false
			if testCase.name == "missing-id-alias" {
				missingAlias = true
			}
			testCase.edit(result, &alternate)
			if testCase.name == "divergent-alias" {
				alternateResult := clone(canonical)
				alternateResult["target_id"] = "other-runtime"
				q.results["key:"+command.IdempotencyKey] = wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: alternateResult, CompletedAt: time.Now().UTC()}
			} else if !missingAlias {
				q.results["key:"+command.IdempotencyKey] = wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: alternate, CompletedAt: time.Now().UTC()}
			}
			q.results[command.ID] = wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: result, CompletedAt: time.Now().UTC()}
			q.commandFingerprints["id:"+command.ID] = intent.Fingerprint
			q.commandFingerprints[command.IdempotencyKey] = intent.Fingerprint
			replay := q.Handle(context.Background(), command)
			if replay.OK || !strings.Contains(replay.Error, "blocked") {
				t.Fatalf("drifted cached result was replayed: %+v", replay)
			}
		})
	}
}

// TestHandleCachedResidencyDriftFailsClosedLiveCausal proves that a result
// which was first created by the signed Handle path cannot be replaced by a
// fresh runtime observation after restart. Discovery remains available so the
// live capability binding is exercised, while mutation is counted to prove no
// fallback side effect occurs.
func TestHandleCachedResidencyDriftFailsClosedLiveCausal(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "commands.json")
	secret := strings.Repeat("c", 32)
	var loaded atomic.Bool
	var requests atomic.Int64
	var mutations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/v1/models":
			status := "unloaded"
			if loaded.Load() {
				status = "loaded"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": status}}})
		case "/props":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
		case "/models/load":
			mutations.Add(1)
			loaded.Store(true)
			w.WriteHeader(http.StatusOK)
		case "/models/unload":
			mutations.Add(1)
			loaded.Store(false)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg.CapabilityVersion, cfg.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
	identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
	command := wsproto.CommandPayload{ID: "live-cache-baseline", IdempotencyKey: "live-cache-baseline-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity,
		"capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion,
		"expected_tier": "hot_vram", "fencing_token": int64(1),
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, err = wsproto.SignCommand(command, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	baselineProcessor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	baseline := baselineProcessor.Handle(context.Background(), command)
	if !baseline.OK || baseline.Result["tier"] != "hot_vram" {
		t.Fatalf("signed baseline did not execute through Handle: %+v", baseline)
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	baselineRequests := requests.Load()

	cloneResult := func(input map[string]any) map[string]any {
		output := make(map[string]any, len(input))
		for key, value := range input {
			output[key] = value
		}
		return output
	}
	drifts := []struct {
		name string
		edit func(map[string]any)
	}{
		{"runtime", func(result map[string]any) { result["runtime_identity"] = "drifted-runtime" }},
		{"capability-version", func(result map[string]any) { result["capability_version"] = "drifted-capability" }},
		{"capability-revision", func(result map[string]any) { result["capability_revision"] = "drifted-revision" }},
		{"fence", func(result map[string]any) { result["fencing_token"] = int64(2) }},
		{"observed-fence", func(result map[string]any) { result["observed_after_fence"] = int64(2) }},
		{"action", func(result map[string]any) { result["action"] = "unload_model" }},
		{"changed", func(result map[string]any) { result["changed"] = "true" }},
	}
	for _, drift := range drifts {
		t.Run(drift.name, func(t *testing.T) {
			cfg.CommandStatePath = filepath.Join(root, "drift-"+drift.name+".json")
			if err := os.WriteFile(cfg.CommandStatePath, stateBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			cached, ok := q.results[command.ID]
			if !ok || cached.Result == nil || !q.cachedMutationReplay(command) {
				t.Fatal("fresh processor did not recover the signed baseline cache")
			}
			mutated := cloneResult(cached.Result)
			drift.edit(mutated)
			cached.Result = mutated
			q.results[command.ID] = cached
			alias := cached
			alias.Result = cloneResult(mutated)
			q.results["key:"+command.IdempotencyKey] = alias
			if err := q.save(); err != nil {
				t.Fatal(err)
			}
			q = newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			if q.cachedMutationReplay(command) {
				t.Fatal("single-field drift was accepted by the production replay validator")
			}
			before := requests.Load()
			mutationBefore := mutations.Load()
			result := q.Handle(context.Background(), command)
			if result.OK || (!strings.Contains(result.Error, "cached residency result") && !strings.Contains(result.Error, blockReasonDurability)) {
				t.Fatalf("drift was not failed closed by Handle: %+v", result)
			}
			if mutations.Load() != mutationBefore {
				t.Fatalf("Handle crossed live mutation boundary after cache drift: requests_before=%d requests_after=%d baseline=%d mutations_before=%d mutations_after=%d", before, requests.Load(), baselineRequests, mutationBefore, mutations.Load())
			}
		})
	}
}

func TestHandleCachedReplayRejectsLiveCapabilityContextDrift(t *testing.T) {
	root := t.TempDir()
	secret := strings.Repeat("r", 32)
	var contextLimit atomic.Int64
	contextLimit.Store(4096)
	var requests atomic.Int64
	var loaded atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/v1/models":
			status := "unloaded"
			if loaded.Load() {
				status = "loaded"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": status}}})
		case "/props":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": contextLimit.Load()}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": contextLimit.Load(), "is_processing": false}})
		case "/models/load":
			loaded.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(root, "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg.CapabilityVersion, cfg.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
	identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
	command := wsproto.CommandPayload{ID: "context-drift", IdempotencyKey: "context-drift-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	baseline := processor.Handle(context.Background(), command)
	if !baseline.OK {
		t.Fatalf("baseline Handle failed: %+v", baseline)
	}
	before := requests.Load()
	contextLimit.Store(8192)
	cfg.LlamaCPP.Servers[0].ContextLimit = 8192
	restarted := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	rejected := restarted.Handle(context.Background(), command)
	if rejected.OK || !strings.Contains(rejected.Error, "cached residency result") {
		t.Fatalf("old cache was accepted after live context/capability drift: %+v", rejected)
	}
	if requests.Load() <= before {
		t.Fatalf("cache validator did not perform live capability discovery after restart: before=%d after=%d", before, requests.Load())
	}
}

func TestHandleCurrentCacheRejectsSlotsProofLossAndChange(t *testing.T) {
	root := t.TempDir()
	secret := strings.Repeat("p", 32)
	var loaded atomic.Bool
	var mode atomic.Int32
	var requests atomic.Int64
	var mutations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/v1/models":
			status := "unloaded"
			if loaded.Load() {
				status = "loaded"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": status}}})
		case "/props":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
		case "/slots":
			switch mode.Load() {
			case 1:
				http.Error(w, "slots unavailable", http.StatusNotFound)
			case 2:
				_, _ = io.WriteString(w, `{"malformed":true}`)
			case 3:
				_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}, {"n_ctx": 4096, "is_processing": false}})
			default:
				_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
			}
		case "/models/load":
			mutations.Add(1)
			loaded.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(root, "commands.json")}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil || !discovery.CapabilitiesVerified || discovery.CapacitySource != "runtime:/slots" {
		t.Fatalf("baseline discovery lacked authoritative slots proof: discovery=%+v err=%v", discovery, err)
	}
	cfg.CapabilityVersion, cfg.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
	identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
	command := wsproto.CommandPayload{ID: "slots-proof-cache", IdempotencyKey: "slots-proof-cache-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	baselineProcessor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if baseline := baselineProcessor.Handle(context.Background(), command); !baseline.OK {
		t.Fatalf("baseline slots-proof Handle failed: %+v", baseline)
	}
	stateBytes, err := os.ReadFile(cfg.CommandStatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name  string
		mode  int32
		slots int
	}{
		{"slots-disappear", 1, 1}, {"slots-malformed", 2, 1}, {"slots-change", 3, 2},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if err := os.WriteFile(cfg.CommandStatePath, stateBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			mode.Store(scenario.mode)
			cfg.LlamaCPP.Servers[0].Slots = scenario.slots
			beforeRequests, beforeMutations := requests.Load(), mutations.Load()
			restarted := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			rejected := restarted.Handle(context.Background(), command)
			if rejected.OK || !strings.Contains(rejected.Error, "cached residency result") {
				t.Fatalf("cache was accepted without authoritative slots proof: %+v", rejected)
			}
			if requests.Load() <= beforeRequests || mutations.Load() != beforeMutations {
				t.Fatalf("slots drift did not cause live validation without mutation: requests=%d->%d mutations=%d->%d", beforeRequests, requests.Load(), beforeMutations, mutations.Load())
			}
		})
	}
}

// TestHandleCurrentCacheRejectsRemovedAndDisabledRuntimeTargets proves that
// a current-envelope cache is bound to an authoritative configured server,
// not merely to the target string retained in the signed command.  Both the
// mutation and its correlated query are replayed from the durable journal
// after restart under each configuration loss case.
func TestHandleCurrentCacheRejectsRemovedAndDisabledRuntimeTargets(t *testing.T) {
	root := t.TempDir()
	secret := strings.Repeat("e", 32)
	var mutations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": "loaded"}}})
		case "/props":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
		case "/models/load":
			mutations.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	statePath := filepath.Join(root, "commands.json")
	base := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: statePath}
	base.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), base.NodeID, base.LlamaCPP.Servers[0])
	if err != nil || !discovery.CapabilitiesVerified || discovery.CapacitySource != "runtime:/slots" {
		t.Fatalf("baseline runtime did not provide authoritative slots proof: discovery=%+v err=%v", discovery, err)
	}
	base.CapabilityVersion, base.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
	identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
	mutation := wsproto.CommandPayload{ID: "removed-target-original", IdempotencyKey: "removed-target-original-key", NodeID: base.NodeID, Command: "load_model", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity,
		"capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion,
		"expected_tier": "hot_vram", "fencing_token": int64(1),
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	mutation.Signature, err = wsproto.SignCommand(mutation, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	processor := newCommandProcessor(base, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	baseline := processor.Handle(context.Background(), mutation)
	if !baseline.OK || baseline.Result["action"] != "load_model" {
		t.Fatalf("signed baseline mutation did not execute through Handle: %+v", baseline)
	}
	query := wsproto.CommandPayload{ID: "removed-target-query", IdempotencyKey: "removed-target-query-key", NodeID: base.NodeID, Command: "query_model_state", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity,
		"capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion,
		"expected_tier": "query", "fencing_token": int64(1), "expected_fence": int64(1), "observed_after_fence": int64(1),
		"original_command_id": mutation.ID, "original_idempotency_key": mutation.IdempotencyKey,
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	query.Signature, err = wsproto.SignCommand(query, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	observed := processor.Handle(context.Background(), query)
	if !observed.OK || observed.Result["action"] != "load_model" || observed.Result["changed"] != false {
		t.Fatalf("signed baseline query did not produce an unchanged canonical observation: %+v", observed)
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	journalBytes, err := os.ReadFile(statePath + ".journal")
	if err != nil {
		t.Fatal(err)
	}
	baselineMutations := mutations.Load()

	for _, scenario := range []struct {
		name    string
		servers func() []LlamaCPPServerConfig
	}{
		{name: "all-servers-removed", servers: func() []LlamaCPPServerConfig { return nil }},
		{name: "exact-target-removed-among-others", servers: func() []LlamaCPPServerConfig {
			return []LlamaCPPServerConfig{{ID: "other", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
		}},
		{name: "exact-target-disabled", servers: func() []LlamaCPPServerConfig {
			return []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: false, ContextLimit: 4096, Slots: 1}}
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			path := filepath.Join(root, scenario.name+".json")
			if err := os.WriteFile(path, stateBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".journal", journalBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := *base
			cfg.CommandStatePath = path
			cfg.LlamaCPP.Servers = scenario.servers()
			fresh := newCommandProcessor(&cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			before := mutations.Load()
			mutationReplay := fresh.Handle(context.Background(), mutation)
			if mutationReplay.OK || !strings.Contains(mutationReplay.Error, "cached residency result") {
				t.Fatalf("removed/disabled runtime replayed cached mutation: %+v", mutationReplay)
			}
			if mutations.Load() != before || mutations.Load() != baselineMutations {
				t.Fatalf("mutation crossed runtime boundary after %s: before=%d after=%d baseline=%d", scenario.name, before, mutations.Load(), baselineMutations)
			}
			queryReplay := fresh.Handle(context.Background(), query)
			if queryReplay.OK || !strings.Contains(queryReplay.Error, "cached residency result") {
				t.Fatalf("removed/disabled runtime replayed cached query: %+v", queryReplay)
			}
			if mutations.Load() != baselineMutations {
				t.Fatalf("query replay mutated runtime after %s: baseline=%d after=%d", scenario.name, baselineMutations, mutations.Load())
			}
		})
	}
}

// TestHandleCurrentCacheRejectsMixedInvalidSlotsForMutationAndQuery proves
// that a durable current-envelope cache cannot be replayed when /slots
// contains even one malformed row. Both signed mutation and correlated query
// replay must re-run live capability validation and fail closed.
func TestHandleCurrentCacheRejectsMixedInvalidSlotsForMutationAndQuery(t *testing.T) {
	root := t.TempDir()
	secret := strings.Repeat("h", 32)
	var slotsBody atomic.Value
	var mutations atomic.Int64
	slotsBody.Store(`[{"n_ctx":4096,"is_processing":false}]`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": "loaded"}}})
		case "/slots":
			_, _ = io.WriteString(w, slotsBody.Load().(string))
		case "/models/load":
			mutations.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: filepath.Join(root, "baseline.json")}
	base.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), base.NodeID, base.LlamaCPP.Servers[0])
	if err != nil || !discovery.CapabilitiesVerified {
		t.Fatalf("baseline discovery was not verified: discovery=%+v err=%v", discovery, err)
	}
	base.CapabilityVersion, base.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
	identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
	mutation := wsproto.CommandPayload{ID: "mixed-slots-original", IdempotencyKey: "mixed-slots-original-key", NodeID: base.NodeID, Command: "load_model", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity,
		"capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion,
		"expected_tier": "hot_vram", "fencing_token": int64(1),
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	mutation.Signature, err = wsproto.SignCommand(mutation, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	processor := newCommandProcessor(base, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if result := processor.Handle(context.Background(), mutation); !result.OK {
		t.Fatalf("baseline signed mutation failed: %+v", result)
	}
	query := wsproto.CommandPayload{ID: "mixed-slots-query", IdempotencyKey: "mixed-slots-query-key", NodeID: base.NodeID, Command: "query_model_state", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity,
		"capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion,
		"expected_tier": "query", "fencing_token": int64(1), "expected_fence": int64(1), "observed_after_fence": int64(1),
		"original_command_id": mutation.ID, "original_idempotency_key": mutation.IdempotencyKey,
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	query.Signature, err = wsproto.SignCommand(query, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if result := processor.Handle(context.Background(), query); !result.OK || result.Result["changed"] != false {
		t.Fatalf("baseline signed query failed: %+v", result)
	}
	stateBytes, err := os.ReadFile(base.CommandStatePath)
	if err != nil {
		t.Fatal(err)
	}
	journalBytes, err := os.ReadFile(base.CommandStatePath + ".journal")
	if err != nil {
		t.Fatal(err)
	}
	baselineMutations := mutations.Load()
	for _, fixture := range []struct {
		name string
		body string
	}{
		{"null-row", `[{"n_ctx":4096},null]`},
		{"zero-context", `[{"n_ctx":4096},{"n_ctx":0}]`},
		{"missing-context", `[{"n_ctx":4096},{}]`},
		{"missing-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192}]`},
		{"numeric-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192,"is_processing":0}]`},
		{"null-processing", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192,"is_processing":null}]`},
		{"wrong-processing-type", `[{"n_ctx":4096,"is_processing":false},{"n_ctx":8192,"is_processing":"no"}]`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			slotsBody.Store(fixture.body)
			beforeSameProcess := mutations.Load()
			sameMutation := processor.Handle(context.Background(), mutation)
			if sameMutation.OK || !strings.Contains(sameMutation.Error, "cached residency result") {
				t.Fatalf("same-process mixed-invalid slots replayed cached mutation: %+v", sameMutation)
			}
			sameQuery := processor.Handle(context.Background(), query)
			if sameQuery.OK || !strings.Contains(sameQuery.Error, "cached residency result") {
				t.Fatalf("same-process mixed-invalid slots replayed cached query: %+v", sameQuery)
			}
			if mutations.Load() != beforeSameProcess {
				t.Fatalf("same-process mixed-invalid slots crossed mutation boundary: before=%d after=%d", beforeSameProcess, mutations.Load())
			}
			path := filepath.Join(root, fixture.name+".json")
			if err := os.WriteFile(path, stateBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".journal", journalBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := *base
			cfg.CommandStatePath = path
			fresh := newCommandProcessor(&cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			before := mutations.Load()
			mutationReplay := fresh.Handle(context.Background(), mutation)
			if mutationReplay.OK || !strings.Contains(mutationReplay.Error, "cached residency result") {
				t.Fatalf("mixed-invalid slots replayed cached mutation: %+v", mutationReplay)
			}
			queryReplay := fresh.Handle(context.Background(), query)
			if queryReplay.OK || !strings.Contains(queryReplay.Error, "cached residency result") {
				t.Fatalf("mixed-invalid slots replayed cached query: %+v", queryReplay)
			}
			if mutations.Load() != before || mutations.Load() != baselineMutations {
				t.Fatalf("mixed-invalid slots crossed mutation boundary: before=%d after=%d baseline=%d", before, mutations.Load(), baselineMutations)
			}
		})
	}
}

func TestSignedLlamaCPPCommandRejectsPassiveRuntimeLifecycle(t *testing.T) {
	secret := strings.Repeat("q", 32)
	var mutations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_, _ = io.WriteString(w, `{"data":[{"id":"model","status":"loaded"}]}`)
		case "/slots":
			_, _ = io.WriteString(w, `[{"n_ctx":4096,"is_processing":false}]`)
		case "/models/load":
			mutations.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: false, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil || !discovery.CapabilitiesVerified || discovery.SupportsModelLifecycle {
		t.Fatalf("passive runtime discovery was not capability truthful: discovery=%+v err=%v", discovery, err)
	}
	cfg.CapabilityVersion, cfg.Capabilities.Version = discovery.Version, domain.CapabilityContractVersion
	command := wsproto.CommandPayload{ID: "passive-lifecycle", IdempotencyKey: "passive-lifecycle-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": canonicalCommandRuntimeIdentity("node-1-runtime", discovery),
		"capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(1),
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, err = wsproto.SignCommand(command, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	result := NewCommandHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))).Handle(context.Background(), command)
	if result.OK || !strings.Contains(result.Error, "lifecycle") || mutations.Load() != 0 {
		t.Fatalf("passive loaded runtime crossed lifecycle command boundary: result=%+v mutations=%d", result, mutations.Load())
	}
}

func TestHandleCachedSuccessNeverBypassesBlockedResidencyState(t *testing.T) {
	secret := strings.Repeat("b", 32)
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CapabilityVersion: "runtime-v1"}
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	identity := "node-1-runtime|llamacpp||runtime-v1|fingerprint"
	command := wsproto.CommandPayload{ID: "blocked-cache", IdempotencyKey: "blocked-cache-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(7)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	for _, reason := range []string{blockReasonCorrupt, blockReasonRead, blockReasonQuarantine, blockReasonDurability} {
		t.Run(reason, func(t *testing.T) {
			processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			fingerprint := processor.semanticFingerprint(command)
			result := map[string]any{"action": "load_model", "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "node_id": cfg.NodeID, "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": true, "original_command_id": command.ID, "original_idempotency_key": command.IdempotencyKey, "command_id": command.ID, "idempotency_key": command.IdempotencyKey, "command_fingerprint": fingerprint, "fingerprint": fingerprint, "fencing_token": int64(7), "observed_after_fence": int64(7), "reconciled": false}
			payload := wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: result}
			processor.results[command.ID], processor.results["key:"+command.IdempotencyKey] = payload, payload
			processor.commandFingerprints["id:"+command.ID], processor.commandFingerprints[command.IdempotencyKey] = fingerprint, fingerprint
			processor.stateBlocked, processor.stateBlockReason = true, reason
			blocked := processor.Handle(context.Background(), command)
			if blocked.OK || !strings.Contains(blocked.Error, reason) {
				t.Fatalf("cached residency success bypassed blocked state %q: %+v", reason, blocked)
			}
		})
	}
	t.Run("initialization-error", func(t *testing.T) {
		processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
		fingerprint := processor.semanticFingerprint(command)
		result := map[string]any{"action": "load_model", "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "node_id": cfg.NodeID, "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": true, "original_command_id": command.ID, "original_idempotency_key": command.IdempotencyKey, "command_id": command.ID, "idempotency_key": command.IdempotencyKey, "command_fingerprint": fingerprint, "fingerprint": fingerprint, "fencing_token": int64(7), "observed_after_fence": int64(7), "reconciled": false}
		payload := wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: result}
		processor.results[command.ID], processor.results["key:"+command.IdempotencyKey] = payload, payload
		processor.commandFingerprints["id:"+command.ID], processor.commandFingerprints[command.IdempotencyKey] = fingerprint, fingerprint
		processor.initError = errors.New("journal read failed")
		blocked := processor.Handle(context.Background(), command)
		if blocked.OK || !strings.Contains(blocked.Error, "initialization failed") {
			t.Fatalf("cached residency success bypassed initialization error: %+v", blocked)
		}
	})
}

func TestCachedAuthoritativeObservationRejectsAliasBindingAndProofDrift(t *testing.T) {
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("a", 32)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": "unloaded"}}})
		case "/props":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg.CapabilityVersion = discovery.Version
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	identity := canonicalCommandRuntimeIdentity("node-1-runtime", discovery)
	original := wsproto.CommandPayload{ID: "original", IdempotencyKey: "original-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(9)}}
	query := wsproto.CommandPayload{ID: "query-cache", IdempotencyKey: "query-cache-key", NodeID: cfg.NodeID, Command: "query_model_state", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "query", "fencing_token": int64(9), "expected_fence": int64(9), "observed_after_fence": int64(9), "original_command_id": "original", "original_idempotency_key": "original-key"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	query.Signature, _ = wsproto.SignCommand(query, []byte(cfg.CommandSigningSecret))
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	originalFingerprint := p.semanticFingerprint(original)
	originalResult := map[string]any{"action": "load_model", "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "node_id": cfg.NodeID, "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": true, "original_command_id": original.ID, "original_idempotency_key": original.IdempotencyKey, "command_id": original.ID, "idempotency_key": original.IdempotencyKey, "command_fingerprint": originalFingerprint, "fingerprint": originalFingerprint, "fencing_token": int64(9), "observed_after_fence": int64(9), "reconciled": false}
	originalPayload := wsproto.CommandResultPayload{ID: original.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: originalResult, CompletedAt: time.Now().UTC()}
	p.results[original.ID], p.results["key:"+original.IdempotencyKey] = originalPayload, originalPayload
	p.commandFingerprints["id:"+original.ID], p.commandFingerprints[original.IdempotencyKey] = originalFingerprint, originalFingerprint
	p.fences[fenceKey("node-1-runtime", "model")] = 9
	fingerprint := p.semanticFingerprint(query)
	base := map[string]any{"action": "load_model", "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "node_id": cfg.NodeID, "runtime_identity": identity, "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": false, "original_command_id": "original", "original_idempotency_key": "original-key", "command_id": query.ID, "idempotency_key": query.IdempotencyKey, "command_fingerprint": fingerprint, "fingerprint": fingerprint, "expected_fence": int64(9), "fencing_token": int64(9), "observed_after_fence": int64(9), "reconciled": false}
	cases := []struct {
		name string
		edit func(map[string]any, *bool)
	}{
		{"missing-id-alias", func(_ map[string]any, missing *bool) { *missing = true }},
		{"missing-fingerprint", func(result map[string]any, _ *bool) { delete(result, "fingerprint") }},
		{"fingerprint-drift", func(result map[string]any, _ *bool) { result["command_fingerprint"] = "drift" }},
		{"action", func(result map[string]any, _ *bool) { result["action"] = "unload_model" }},
		{"original-link", func(result map[string]any, _ *bool) { result["original_command_id"] = "other" }},
		{"target", func(result map[string]any, _ *bool) { result["target_id"] = "other-runtime" }},
		{"runtime-identity", func(result map[string]any, _ *bool) { result["runtime_identity"] = "other-runtime|llamacpp|" }},
		{"capability", func(result map[string]any, _ *bool) { result["capability_revision"] = "drift" }},
		{"fence", func(result map[string]any, _ *bool) { result["observed_after_fence"] = int64(8) }},
		{"changed-missing", func(result map[string]any, _ *bool) { delete(result, "changed") }},
		{"changed-type", func(result map[string]any, _ *bool) { result["changed"] = "false" }},
		{"proof-missing", func(result map[string]any, _ *bool) { delete(result, "resident") }},
		{"unknown", func(result map[string]any, _ *bool) { result["unexpected"] = true }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			q.results[original.ID], q.results["key:"+original.IdempotencyKey] = originalPayload, originalPayload
			q.commandFingerprints["id:"+original.ID], q.commandFingerprints[original.IdempotencyKey] = originalFingerprint, originalFingerprint
			q.fences[fenceKey("node-1-runtime", "model")] = 9
			baseline := make(map[string]any, len(base))
			for key, value := range base {
				baseline[key] = value
			}
			baselinePayload := wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: baseline, CompletedAt: time.Now().UTC()}
			q.results[query.ID], q.results["key:"+query.IdempotencyKey] = baselinePayload, baselinePayload
			q.commandFingerprints["id:"+query.ID] = fingerprint
			q.commandFingerprints[query.IdempotencyKey] = fingerprint
			if !q.cachedAuthoritativeObservation(query) {
				t.Fatal("baseline authoritative observation was not accepted")
			}
			result := make(map[string]any, len(base))
			for key, value := range base {
				result[key] = value
			}
			missingAlias := false
			testCase.edit(result, &missingAlias)
			payload := wsproto.CommandResultPayload{ID: query.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: result, CompletedAt: time.Now().UTC()}
			q.results[query.ID] = payload
			if !missingAlias {
				q.results["key:"+query.IdempotencyKey] = payload
			} else {
				delete(q.results, "key:"+query.IdempotencyKey)
			}
			if q.cachedAuthoritativeObservation(query) {
				t.Fatal("drifted authoritative observation was accepted")
			}
			replay := q.Handle(context.Background(), query)
			if replay.OK && reflect.DeepEqual(replay.Result, result) {
				t.Fatalf("drifted authoritative observation was returned from cache: %+v", replay)
			}
		})
	}
}

func TestCachedLegacyMutationReplayExactHotColdSchema(t *testing.T) {
	cfg := &Config{NodeID: "node-1"}
	baseCommand := func(id, action string) wsproto.CommandPayload {
		return wsproto.CommandPayload{ID: id, IdempotencyKey: id + "-key", NodeID: cfg.NodeID, Command: action, Args: map[string]any{"target_id": "node-1-runtime", "model": "model", "fencing_token": int64(3)}}
	}
	baseResult := func(command wsproto.CommandPayload, cold bool) map[string]any {
		result := map[string]any{"action": command.Command, "target_id": "node-1-runtime", "model": "model", "resident": !cold, "warm_ram": false, "changed": false, "runtime_identity": "runtime", "capability_revision": "v1", "fencing_token": int64(3), "observed_after_fence": int64(3), "tier": "hot_vram"}
		if cold {
			result["tier"] = "cold_disk"
			result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
			result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
		}
		return result
	}
	for _, tc := range []struct {
		name    string
		command wsproto.CommandPayload
		cold    bool
	}{
		{"load-hot", baseCommand("legacy-load", "load_model"), false},
		{"unload-cold", baseCommand("legacy-unload", "unload_model"), true},
		{"cleanup-cold", baseCommand("legacy-cleanup", "cleanup_warm_model"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			fingerprint := p.semanticFingerprint(tc.command)
			payload := wsproto.CommandResultPayload{ID: tc.command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: baseResult(tc.command, tc.cold)}
			p.results[tc.command.ID], p.results["key:"+tc.command.IdempotencyKey] = payload, payload
			p.commandFingerprints["id:"+tc.command.ID], p.commandFingerprints[tc.command.IdempotencyKey] = fingerprint, fingerprint
			if !p.cachedLegacyMutationReplay(tc.command) {
				t.Fatal("exact legacy hot/cold result was rejected")
			}
			for name, mutate := range map[string]func(map[string]any){
				"extra":          func(r map[string]any) { r["unexpected"] = true },
				"missing-action": func(r map[string]any) { delete(r, "action") },
				"warm":           func(r map[string]any) { r["tier"], r["warm_ram"], r["resident"] = "warm_ram", true, false },
				"wrong-type":     func(r map[string]any) { r["changed"] = "false" },
				"missing-target": func(r map[string]any) { delete(r, "target_id") },
				"missing-fence":  func(r map[string]any) { delete(r, "fencing_token") },
				"fence-type":     func(r map[string]any) { r["observed_after_fence"] = "3" },
			} {
				t.Run(name, func(t *testing.T) {
					mutated := baseResult(tc.command, tc.cold)
					mutate(mutated)
					bad := payload
					bad.Result = mutated
					p.results[tc.command.ID], p.results["key:"+tc.command.IdempotencyKey] = bad, bad
					if p.cachedLegacyMutationReplay(tc.command) {
						t.Fatal("invalid legacy compatibility result replayed")
					}
				})
			}
		})
	}
}

// TestResidencyCacheLegacyCurrentBranchMatrix keeps compatibility and current
// envelope admission disjoint.  Legacy accepts only the explicitly versioned
// hot/cold contract; any current argument or incomplete current proof is
// rejected instead of guessing missing bindings.
func TestResidencyCacheLegacyCurrentBranchMatrix(t *testing.T) {
	secret := strings.Repeat("v", 32)
	legacyCfg := &Config{NodeID: "node-1", CommandSigningSecret: secret}
	legacyCommand := wsproto.CommandPayload{ID: "legacy-matrix", IdempotencyKey: "legacy-matrix-key", NodeID: legacyCfg.NodeID, Command: "load_model", Args: map[string]any{"target_id": "node-1-runtime", "model": "model", "fencing_token": int64(4)}}
	legacyCommand.Signature, _ = wsproto.SignCommand(legacyCommand, []byte(secret))
	legacyProcessor := newCommandProcessor(legacyCfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	legacyFingerprint := legacyProcessor.semanticFingerprint(legacyCommand)
	legacyResult := map[string]any{"action": "load_model", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "node-1-runtime|legacy|v1", "capability_revision": "legacy-authoritative-v1", "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": true, "fencing_token": int64(4), "observed_after_fence": int64(4)}
	legacyPayload := wsproto.CommandResultPayload{ID: legacyCommand.ID, NodeID: legacyCfg.NodeID, Status: "succeeded", OK: true, Result: legacyResult}
	legacyProcessor.results[legacyCommand.ID], legacyProcessor.results["key:"+legacyCommand.IdempotencyKey] = legacyPayload, legacyPayload
	legacyProcessor.commandFingerprints["id:"+legacyCommand.ID], legacyProcessor.commandFingerprints[legacyCommand.IdempotencyKey] = legacyFingerprint, legacyFingerprint
	if !legacyProcessor.cachedMutationReplay(legacyCommand) {
		t.Fatal("explicitly versioned authoritative legacy hot proof was not accepted")
	}
	legacyCases := []struct {
		name string
		edit func(map[string]any, map[string]any)
	}{
		{"missing-version", func(result, _ map[string]any) { delete(result, "capability_revision") }},
		{"warm-tier", func(result, _ map[string]any) {
			result["tier"], result["resident"], result["warm_ram"] = "warm_ram", false, true
		}},
		{"unknown-field", func(result, _ map[string]any) { result["unexpected"] = true }},
		{"current-argument", func(_, args map[string]any) { args["target_kind"] = "llamacpp" }},
	}
	for _, testCase := range legacyCases {
		t.Run("legacy/"+testCase.name, func(t *testing.T) {
			processor := newCommandProcessor(legacyCfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			command := legacyCommand
			command.Args = make(map[string]any, len(legacyCommand.Args))
			for key, value := range legacyCommand.Args {
				command.Args[key] = value
			}
			result := make(map[string]any, len(legacyResult))
			for key, value := range legacyResult {
				result[key] = value
			}
			testCase.edit(result, command.Args)
			fingerprint := processor.semanticFingerprint(command)
			payload := wsproto.CommandResultPayload{ID: command.ID, NodeID: processor.cfg.NodeID, Status: "succeeded", OK: true, Result: result}
			processor.results[command.ID], processor.results["key:"+command.IdempotencyKey] = payload, payload
			processor.commandFingerprints["id:"+command.ID], processor.commandFingerprints[command.IdempotencyKey] = fingerprint, fingerprint
			if processor.cachedMutationReplay(command) {
				t.Fatal("unsafe legacy/current compatibility proof was accepted")
			}
		})
	}

	currentCfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CapabilityVersion: "runtime-v1"}
	currentCfg.Capabilities.Version = domain.CapabilityContractVersion
	currentProcessor := newCommandProcessor(currentCfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	identity := "node-1-runtime|llamacpp||runtime-v1|fingerprint"
	currentCommand := wsproto.CommandPayload{ID: "current-matrix", IdempotencyKey: "current-matrix-key", NodeID: currentCfg.NodeID, Command: "load_model", Args: map[string]any{
		"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": identity,
		"capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(8),
	}}
	currentCommand.Signature, _ = wsproto.SignCommand(currentCommand, []byte(secret))
	currentFingerprint := currentProcessor.semanticFingerprint(currentCommand)
	currentResult := map[string]any{"action": "load_model", "target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "node_id": "node-1", "runtime_identity": identity, "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": true, "original_command_id": currentCommand.ID, "original_idempotency_key": currentCommand.IdempotencyKey, "command_id": currentCommand.ID, "idempotency_key": currentCommand.IdempotencyKey, "command_fingerprint": currentFingerprint, "fingerprint": currentFingerprint, "fencing_token": int64(8), "observed_after_fence": int64(8), "reconciled": false}
	currentPayload := wsproto.CommandResultPayload{ID: currentCommand.ID, NodeID: currentCfg.NodeID, Status: "succeeded", OK: true, Result: currentResult}
	currentProcessor.results[currentCommand.ID], currentProcessor.results["key:"+currentCommand.IdempotencyKey] = currentPayload, currentPayload
	currentProcessor.commandFingerprints["id:"+currentCommand.ID], currentProcessor.commandFingerprints[currentCommand.IdempotencyKey] = currentFingerprint, currentFingerprint
	currentProcessor.fences[fenceKey("node-1-runtime", "model")] = 8
	if !currentProcessor.cachedMutationReplay(currentCommand) {
		t.Fatal("complete current residency proof was not accepted")
	}
	currentCases := []struct {
		name string
		edit func(map[string]any, map[string]any)
	}{
		{"runtime-drift", func(result, _ map[string]any) { result["runtime_identity"] = "drift" }},
		{"capability-drift", func(result, _ map[string]any) { result["capability_version"] = "drift" }},
		{"revision-drift", func(result, _ map[string]any) { result["capability_revision"] = "drift" }},
		{"fence-drift", func(result, _ map[string]any) { result["fencing_token"] = int64(7) }},
		{"missing-current-binding", func(result, _ map[string]any) { delete(result, "target_kind") }},
		{"wrong-changed-type", func(result, _ map[string]any) { result["changed"] = "true" }},
	}
	for _, testCase := range currentCases {
		t.Run("current/"+testCase.name, func(t *testing.T) {
			processor := newCommandProcessor(currentCfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			result := make(map[string]any, len(currentResult))
			for key, value := range currentResult {
				result[key] = value
			}
			command := currentCommand
			command.Args = make(map[string]any, len(currentCommand.Args))
			for key, value := range currentCommand.Args {
				command.Args[key] = value
			}
			testCase.edit(result, command.Args)
			payload := wsproto.CommandResultPayload{ID: command.ID, NodeID: processor.cfg.NodeID, Status: "succeeded", OK: true, Result: result}
			processor.results[command.ID], processor.results["key:"+command.IdempotencyKey] = payload, payload
			processor.commandFingerprints["id:"+command.ID], processor.commandFingerprints[command.IdempotencyKey] = currentFingerprint, currentFingerprint
			processor.fences[fenceKey("node-1-runtime", "model")] = 8
			if processor.cachedMutationReplay(command) {
				t.Fatal("drifted or incomplete current proof was accepted")
			}
		})
	}
}

func TestHandleLegacyCacheRejectsMismatchedFenceProof(t *testing.T) {
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("z", 32)}
	command := wsproto.CommandPayload{ID: "legacy-fence-handle", IdempotencyKey: "legacy-fence-handle-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_id": "node-1-runtime", "model": "model", "fencing_token": int64(4)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
	for _, mismatch := range []struct {
		name          string
		resultFence   any
		observedFence any
		commandFence  any
	}{
		{"result-equal-observed-command-drift", int64(99), int64(99), int64(4)},
		{"result-not-observed", int64(4), int64(99), int64(4)},
		{"command-drift", int64(4), int64(4), int64(100)},
		{"observed-type", int64(4), "99", int64(4)},
		{"missing-observed", int64(4), nil, int64(4)},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			command.Args["fencing_token"] = mismatch.commandFence
			command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
			fingerprint := processor.semanticFingerprint(command)
			result := map[string]any{"action": "load_model", "target_id": "node-1-runtime", "model": "model", "runtime_identity": "legacy-runtime", "capability_revision": "legacy-authoritative-v1", "tier": "hot_vram", "resident": true, "warm_ram": false, "changed": true, "fencing_token": mismatch.resultFence, "observed_after_fence": mismatch.observedFence}
			payload := wsproto.CommandResultPayload{ID: command.ID, NodeID: cfg.NodeID, Status: "succeeded", OK: true, Result: result}
			processor.results[command.ID], processor.results["key:"+command.IdempotencyKey] = payload, payload
			processor.commandFingerprints["id:"+command.ID], processor.commandFingerprints[command.IdempotencyKey] = fingerprint, fingerprint
			if replay := processor.Handle(context.Background(), command); replay.OK || !strings.Contains(replay.Error, "cached residency result") {
				t.Fatalf("mismatched legacy fence was accepted by Handle: %+v", replay)
			}
		})
	}
}

func TestReconcilePendingJournalCrashReplaysWithoutMutation(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "commands.json")
	var runtimeMutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": "loaded"}}})
		case "/slots":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"n_ctx": 4096, "is_processing": false}})
		case "/models/load", "/models/unload":
			runtimeMutations.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: strings.Repeat("j", 32), CommandStatePath: statePath}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "runtime", Endpoint: server.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1}}
	discovery, err := DiscoverLlamaCPP(context.Background(), cfg.NodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	command := wsproto.CommandPayload{ID: "journal-crash", IdempotencyKey: "journal-crash-key", NodeID: cfg.NodeID, Command: "load_model", Args: map[string]any{"target_kind": "llamacpp", "target_id": "node-1-runtime", "model": "model", "runtime_identity": canonicalCommandRuntimeIdentity("node-1-runtime", discovery), "capability_version": discovery.Version, "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(21)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	command.Signature, _ = wsproto.SignCommand(command, []byte(cfg.CommandSigningSecret))
	p := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	intent := pendingCommand{TargetID: "node-1-runtime", Model: "model", Command: command.Command, Token: 21, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: p.semanticFingerprint(command)}
	manifest, _ := pendingManifestFor(command, command.Args, intent.TargetID, intent.Model, intent.Token, intent)
	intent.ManifestJSON = string(manifest)
	p.pending[command.ID] = intent
	p.inflight[fenceKey(intent.TargetID, intent.Model)] = true
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	q := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	q.afterReconciledJournal = func() error { return errors.New("simulated crash after result journal") }
	if err := q.ReconcilePending(context.Background()); err == nil {
		t.Fatalf("journal crash hook did not interrupt before deletion: %v", err)
	}
	if !q.HasPending() {
		t.Fatal("crash window unexpectedly deleted pending intent in memory")
	}
	restarted := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	replay := restarted.Handle(context.Background(), command)
	if !replay.OK || replay.Uncertain || runtimeMutations.Load() != 0 {
		t.Fatalf("restart replay was not cached/no-side-effect: result=%+v mutations=%d", replay, runtimeMutations.Load())
	}
	if err := restarted.ReconcilePending(context.Background()); err != nil {
		t.Fatalf("startup cleanup of journaled result failed: %v", err)
	}
	if restarted.HasPending() || runtimeMutations.Load() != 0 {
		t.Fatalf("journaled result cleanup reissued mutation: pending=%v mutations=%d", restarted.HasPending(), runtimeMutations.Load())
	}
}

func TestOwnedStopAcceleratorWideFenceAndOperationLedger(t *testing.T) {
	processor := &commandProcessor{
		cfg:                 &Config{NodeID: "node-a"},
		fences:              map[string]int64{ownedStopFenceKey("GPU-A"): 10},
		ownedStopOperations: map[string]ownedStopOperationState{},
	}
	makeCommand := func(op, step, accelerator string, fence int64) wsproto.CommandPayload {
		return wsproto.CommandPayload{ID: op + "-" + step, IdempotencyKey: op + "-key-" + step, NodeID: "node-a", Command: "llm_displacement_stop", Args: map[string]any{
			"operation_id": op, "step_id": step, "target_id": "node-a-victim", "model": "model-victim", "accelerator_id": accelerator, "recovery_epoch": "epoch-a", "fencing_token": fence,
		}}
	}
	victim := makeCommand("op-a", "victim_stop", "GPU-A", 11)
	if err := processor.checkOwnedStopTransition(victim); err != nil {
		t.Fatalf("fresh victim fence rejected: %v", err)
	}
	original := []byte(`{"id":"op-a-victim_stop"}`)
	intent := pendingCommand{Token: 11, CommandID: victim.ID, IdempotencyKey: victim.IdempotencyKey, OriginalEnvelope: original, StopRecoveryEpoch: "epoch-a"}
	if err := processor.recordOwnedStopStep(victim, intent, "pending", ""); err != nil {
		t.Fatal(err)
	}
	processor.fences[ownedStopFenceKey("GPU-A")] = 11
	urgent := makeCommand("op-a", "urgent_stop", "GPU-A", 11)
	if err := processor.checkOwnedStopTransition(urgent); err == nil {
		t.Fatal("urgent same-fence step bypassed an unresolved victim stop")
	}
	if err := processor.recordOwnedStopStep(victim, intent, "acknowledged", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := processor.checkOwnedStopTransition(urgent); err != nil {
		t.Fatalf("urgent same-operation same-accelerator fence was not linked to victim acknowledgement: %v", err)
	}
	urgent.Args["target_id"], urgent.Args["model"] = "node-a-urgent", "model-urgent"
	if err := processor.checkOwnedStopTransition(urgent); err != nil {
		t.Fatalf("urgent linked step on a different target/model of the same physical accelerator was rejected: %v", err)
	}
	restartedAfterVictim := &commandProcessor{cfg: processor.cfg, fences: map[string]int64{ownedStopFenceKey("GPU-A"): 11}, ownedStopOperations: map[string]ownedStopOperationState{}}
	serializedVictim, err := json.Marshal(processor.ownedStopOperations)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(serializedVictim, &restartedAfterVictim.ownedStopOperations); err != nil {
		t.Fatal(err)
	}
	if err := restartedAfterVictim.checkOwnedStopTransition(urgent); err != nil {
		t.Fatalf("restart lost the exact acknowledged victim-to-urgent same-fence link: %v", err)
	}
	urgentIntent := pendingCommand{Token: 11, CommandID: urgent.ID, IdempotencyKey: urgent.IdempotencyKey, OriginalEnvelope: []byte(`{"id":"op-a-urgent_stop"}`), StopRecoveryEpoch: "epoch-a"}
	if err := processor.recordOwnedStopStep(urgent, urgentIntent, "pending", ""); err != nil {
		t.Fatal(err)
	}
	if err := processor.recordOwnedStopStep(urgent, urgentIntent, "acknowledged", strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}

	otherTargetVictim := makeCommand("op-b", "victim_stop", "GPU-A", 11)
	if err := processor.checkOwnedStopTransition(otherTargetVictim); err == nil {
		t.Fatal("different target/operation bypassed the physical accelerator fence")
	}
	newOperation := makeCommand("op-b", "victim_stop", "GPU-A", 12)
	if err := processor.checkOwnedStopTransition(newOperation); err != nil {
		t.Fatalf("new settled operation with a higher accelerator fence rejected: %v", err)
	}
	independent := makeCommand("op-independent", "victim_stop", "GPU-B", 1)
	if err := processor.checkOwnedStopTransition(independent); err != nil {
		t.Fatalf("independent accelerator fence was coupled to GPU-A: %v", err)
	}
	restarted := &commandProcessor{cfg: processor.cfg, fences: map[string]int64{ownedStopFenceKey("GPU-A"): 11}, ownedStopOperations: map[string]ownedStopOperationState{}}
	serialized, err := json.Marshal(processor.ownedStopOperations)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(serialized, &restarted.ownedStopOperations); err != nil {
		t.Fatal(err)
	}
	if err := restarted.checkOwnedStopTransition(makeCommand("op-a", "victim_stop", "GPU-A", 12)); err == nil {
		t.Fatal("durable restart allowed reusing an earlier operation identity")
	}

	// The wire envelope intentionally has no resource field. Its semantic
	// fingerprint must nevertheless match the root/manifest-derived resource
	// used by commandIntentWithPlanSpec, and must remain stable across target
	// aliases while binding the physical accelerator.
	fingerprintProcessor := &commandProcessor{cfg: &Config{NodeID: "node-a"}}
	fingerprintProcessor.cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "victim"}}
	stop := makeCommand("op-fingerprint", "victim_stop", "GPU-A", 11)
	stop.Args = map[string]any{
		"operation_id": "op-fingerprint", "step_id": "victim_stop", "target_id": "victim", "model": "model-victim",
		"accelerator_id": "GPU-A", "recovery_epoch": "epoch-a", "fencing_token": int64(11),
	}
	gotFingerprint := fingerprintProcessor.semanticFingerprint(stop)
	rootNormalized := stop
	rootArgs := make(map[string]any, len(stop.Args)+1)
	for key, value := range stop.Args {
		rootArgs[key] = value
	}
	rootArgs["target_id"] = "node-a-victim"
	rootArgs["resource"] = "owned-stop:GPU-A"
	rootNormalized.Args = rootArgs
	if want := commandFingerprint(rootNormalized); gotFingerprint != want {
		t.Fatalf("owned-stop semantic fingerprint differs from independently derived durable resource: got=%s want=%s", gotFingerprint, want)
	}
	canonicalTarget := stop
	canonicalArgs := make(map[string]any, len(stop.Args))
	for key, value := range stop.Args {
		canonicalArgs[key] = value
	}
	canonicalArgs["target_id"] = "node-a-victim"
	canonicalTarget.Args = canonicalArgs
	if got := fingerprintProcessor.semanticFingerprint(canonicalTarget); got != gotFingerprint {
		t.Fatalf("short and node-qualified owned-stop targets do not share one canonical fingerprint: %s != %s", got, gotFingerprint)
	}
	driftedAccelerator := stop
	driftedArgs := make(map[string]any, len(stop.Args))
	for key, value := range stop.Args {
		driftedArgs[key] = value
	}
	driftedArgs["accelerator_id"] = "GPU-B"
	driftedAccelerator.Args = driftedArgs
	if got := fingerprintProcessor.semanticFingerprint(driftedAccelerator); got == gotFingerprint {
		t.Fatal("owned-stop accelerator drift retained the original semantic fingerprint")
	}
	ordinary := wsproto.CommandPayload{NodeID: "node-a", Command: "load_model", IdempotencyKey: "load-key", Args: map[string]any{"target_id": "victim", "model": "model-victim"}}
	ordinaryNormalized := ordinary
	ordinaryNormalized.Args = map[string]any{"target_id": "node-a-victim", "model": "model-victim"}
	if got, want := fingerprintProcessor.semanticFingerprint(ordinary), commandFingerprint(ordinaryNormalized); got != want {
		t.Fatalf("owned-stop fingerprint derivation changed unrelated command semantics: got=%s want=%s", got, want)
	}

	// Startup reconciliation has no authority to infer terminal stop state
	// from a residency observation. Even an intentionally incomplete manifest
	// remains pending for the exact signed receipt-query path.
	stopID := "restart-stop"
	reconcile := &commandProcessor{
		cfg:      &Config{NodeID: "node-a"},
		pending:  map[string]pendingCommand{stopID: {Command: "llm_displacement_stop", CommandID: stopID, IdempotencyKey: "restart-stop-key", ManifestJSON: "not-a-residency-manifest"}},
		inflight: map[string]bool{ownedStopFenceKey("GPU-A"): true},
	}
	if err := reconcile.ReconcilePending(context.Background()); err == nil || !strings.Contains(err.Error(), "exact signed root receipt query") {
		t.Fatalf("startup reconciliation did not retain owned stop for authenticated receipt query: %v", err)
	}
	if _, remains := reconcile.pending[stopID]; !remains || !reconcile.inflight[ownedStopFenceKey("GPU-A")] {
		t.Fatal("startup reconciliation cleared owned-stop intent or accelerator fence without root receipt")
	}
}

func TestOwnedStopReceiptRequiresRootSignatureAndExactIntentJoin(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("fixture-command-secret-at-least-16")
	command := wsproto.CommandPayload{ID: "stop-1", IdempotencyKey: "idem-1", NodeID: "node-a", Command: "llm_displacement_stop", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute), Args: map[string]any{
		"operation_id": "op-1", "step_id": "victim_stop", "target_kind": "llamacpp", "target_id": "node-a-server", "accelerator_id": "GPU-01234567-89ab-cdef-0123-456789abcdef",
		"workload_id": "workload-a", "workload_revision": int64(3), "model": "catalog/model-a", "model_alias": "fixed-alias", "local_checkpoint_binding": "sha256:" + strings.Repeat("a", 64),
		"snapshot_name": "snapshot-1.kv", "snapshot_digest": strings.Repeat("b", 64), "recovery_epoch": "epoch-1", "fencing_token": int64(7),
	}}
	command.Signature, err = wsproto.SignCommand(command, secret)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil {
		t.Fatal(err)
	}
	material, err := wsproto.CommandSigningMaterialForOwnedStop(command)
	if err != nil {
		t.Fatal(err)
	}
	receipt := ownedStopReceipt{Version: 1, NodeID: command.NodeID, OperationID: "op-1", StepID: "victim_stop", CommandID: command.ID, IdempotencyKey: command.IdempotencyKey,
		OriginalEnvelopeSHA256: sha256Hex(wire), SigningMaterialSHA256: sha256Hex(material), RecoveryEpoch: "epoch-1", AcceleratorID: command.Args["accelerator_id"].(string), FencingToken: 7,
		TargetID: command.Args["target_id"].(string), WorkloadID: "workload-a", WorkloadRevision: 3, Model: "catalog/model-a", ModelAlias: "fixed-alias", LocalCheckpointBinding: strings.Repeat("a", 64), ManagedCurrentIncarnation: strings.Repeat("a", 64), ManagedPlanSHA256: strings.Repeat("d", 64), CustodyBindingSHA256: strings.Repeat("e", 64), SnapshotName: "snapshot-1.kv", SnapshotDigest: strings.Repeat("b", 64),
		SupervisorPID: 101, SupervisorStartTicks: 102, WorkerPID: 202, WorkerStartTicks: 303, InvocationID: strings.Repeat("c", 32), ControlGroup: "/system.slice/llama-server.service", SignalSent: true, ReleaseTerminal: true, SignedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(unsigned)))
	valid, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedStopReceipt(valid, public, wire, string(secret)); err != nil {
		t.Fatalf("valid root durable acknowledgement rejected: %v", err)
	}
	mutants := map[string]func(*ownedStopReceipt){
		"wrong target":       func(r *ownedStopReceipt) { r.TargetID = "node-a-other" },
		"release not proven": func(r *ownedStopReceipt) { r.ReleaseTerminal = false },
		"signal not proven":  func(r *ownedStopReceipt) { r.SignalSent = false },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			bad := receipt
			mutate(&bad)
			bad.Signature = ""
			body, _ := json.Marshal(bad)
			bad.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(body)))
			body, _ = json.Marshal(bad)
			if err := verifyOwnedStopReceipt(body, public, wire, string(secret)); err == nil {
				t.Fatal("invalid root receipt was accepted")
			}
		})
	}
	forged := append([]byte(nil), valid...)
	forged[len(forged)-3] ^= 1
	if err := verifyOwnedStopReceipt(forged, public, wire, string(secret)); err == nil {
		t.Fatal("receipt modified after signing was accepted")
	}
}
