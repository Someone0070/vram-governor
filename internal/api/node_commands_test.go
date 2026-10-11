package api

import (
	"bytes"
	"context"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/domain"
	"vram-governor/internal/nodeagent"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
	"vram-governor/internal/wsproto"
)

// signedBoundaryRuntime is a small, stateful HTTP runtime used only by the
// signed controller/node boundary tests below. It implements the same
// discovery and allowlisted router mutation endpoints consumed by
// nodeagent.NewCommandHandler; it does not bypass that command processor.
type signedBoundaryRuntime struct {
	mu                 sync.Mutex
	state              string
	loadCalls          atomic.Int32
	unloadCalls        atomic.Int32
	holdNextLoad       bool
	mismatchNextUnload bool
}

func (r *signedBoundaryRuntime) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/v1/models":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model", "status": r.state}}})
	case req.Method == http.MethodGet && req.URL.Path == "/slots":
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": false}})
	case req.Method == http.MethodGet && req.URL.Path == "/props":
		_ = json.NewEncoder(w).Encode(map[string]any{"default_generation_settings": map[string]any{"n_ctx": 4096}})
	case req.Method == http.MethodPost && req.URL.Path == "/models/load":
		r.loadCalls.Add(1)
		if r.holdNextLoad {
			r.holdNextLoad = false
			r.state = "loading"
		} else {
			r.state = "loaded"
		}
		w.WriteHeader(http.StatusOK)
	case req.Method == http.MethodPost && req.URL.Path == "/models/unload":
		r.unloadCalls.Add(1)
		if r.mismatchNextUnload {
			r.mismatchNextUnload = false
			r.state = "loaded"
		} else {
			r.state = "unloaded"
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, req)
	}
}

func (r *signedBoundaryRuntime) currentState() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

type signedBoundaryNode struct {
	cfg       *nodeagent.Config
	handler   nodeagent.CommandHandler
	runtime   *signedBoundaryRuntime
	endpoint  *httptest.Server
	modelPath string
	version   string
	identity  string
	advertise wsproto.AdapterAdvertisement
}

func newSignedBoundaryNode(t *testing.T, nodeID, initialState, statePath string) *signedBoundaryNode {
	t.Helper()
	root := t.TempDir()
	modelPath := filepath.Join(root, "model.gguf")
	modelBytes := bytes.Repeat([]byte("m"), 4096)
	if err := os.WriteFile(modelPath, modelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &signedBoundaryRuntime{state: initialState}
	endpoint := httptest.NewServer(runtime)
	fileSum := sha256.Sum256(modelBytes)
	const secret = "signed-controller-node-boundary-secret-32"
	cfg := &nodeagent.Config{NodeID: nodeID, CommandSigningSecret: secret, CommandStatePath: statePath, CapabilityVersion: domain.CapabilityContractVersion}
	cfg.LlamaCPP.Servers = []nodeagent.LlamaCPPServerConfig{{
		ID: "runtime", Endpoint: endpoint.URL, PublicEndpoint: endpoint.URL, RouterManaged: true, ContextLimit: 4096, Slots: 1,
		ModelPaths: map[string]string{"model": modelPath}, ModelFingerprints: map[string]string{"model": hex.EncodeToString(fileSum[:])},
	}}
	cfg.WarmRAM = nodeagent.WarmRAMConfig{
		Enabled: true, ModelRoots: []string{root}, RAMHardCapBytes: 64 << 20, MaxWarmBytes: 64 << 20,
		MemlockLimitBytes: 64 << 20, CgroupLimitBytes: 1 << 40, CgroupCurrentPath: "/sys/fs/cgroup/memory.current", PressurePath: "/proc/pressure/memory", PressureRefusalPercent: 100,
	}
	discovery, err := nodeagent.DiscoverLlamaCPP(context.Background(), nodeID, cfg.LlamaCPP.Servers[0])
	if err != nil {
		endpoint.Close()
		t.Fatalf("discover signed-boundary runtime: %v", err)
	}
	cfg.Capabilities.Version = domain.CapabilityContractVersion
	cfg.CapabilityVersion = discovery.Version
	cfg.LlamaCPP.Servers[0].RuntimeFingerprints = map[string]string{"model": discovery.ModelFingerprint}
	identity := strings.Join([]string{nodeID + "-runtime", "llamacpp", "", discovery.Version, discovery.ModelFingerprint}, "|")
	return &signedBoundaryNode{cfg: cfg, handler: nodeagent.NewCommandHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))), runtime: runtime, endpoint: endpoint, modelPath: modelPath, version: discovery.Version, identity: identity, advertise: discovery}
}

func signedBoundaryCommandResultJSONEqual(before, after wsproto.CommandResultPayload) bool {
	if !before.OK || !after.OK || before.Uncertain || after.Uncertain ||
		before.ID == "" || before.ID != after.ID || before.NodeID == "" || before.NodeID != after.NodeID ||
		before.Status != after.Status || before.Error != after.Error ||
		before.CompletedAt.IsZero() || after.CompletedAt.IsZero() || !before.CompletedAt.Equal(after.CompletedAt) {
		return false
	}
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		return false
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		return false
	}
	return bytes.Equal(beforeJSON, afterJSON)
}

func assertSignedBoundaryCommandResultComparatorControls(t *testing.T, original wsproto.CommandResultPayload) {
	t.Helper()
	originalJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal original cleanup result for comparator controls: %v", err)
	}
	var roundTrip wsproto.CommandResultPayload
	if err := json.Unmarshal(originalJSON, &roundTrip); err != nil {
		t.Fatalf("round-trip cleanup result for comparator controls: %v", err)
	}
	if !signedBoundaryCommandResultJSONEqual(original, roundTrip) {
		t.Fatal("complete cleanup payload JSON round-trip did not compare equal")
	}
	if _, ok := original.Result["locked_bytes"].(int64); !ok {
		t.Fatalf("original cleanup locked_bytes lost its integer schema: %T", original.Result["locked_bytes"])
	}
	if _, ok := original.Result["warm_model_bytes"].(int64); !ok {
		t.Fatalf("original cleanup warm_model_bytes lost its integer schema: %T", original.Result["warm_model_bytes"])
	}
	if _, ok := roundTrip.Result["locked_bytes"].(float64); !ok {
		t.Fatalf("JSON cleanup locked_bytes did not exercise interface-number decoding: %T", roundTrip.Result["locked_bytes"])
	}
	if _, ok := roundTrip.Result["warm_model_bytes"].(float64); !ok {
		t.Fatalf("JSON cleanup warm_model_bytes did not exercise interface-number decoding: %T", roundTrip.Result["warm_model_bytes"])
	}
	if _, ok := roundTrip.Result["fencing_token"].(float64); !ok {
		t.Fatalf("JSON cleanup fencing_token did not exercise interface-number decoding: %T", roundTrip.Result["fencing_token"])
	}
	if _, ok := roundTrip.Result["observed_after_fence"].(float64); !ok {
		t.Fatalf("JSON cleanup observed_after_fence did not exercise interface-number decoding: %T", roundTrip.Result["observed_after_fence"])
	}
	for _, key := range []string{"action", "fingerprint", "fencing_token", "observed_after_fence"} {
		if _, ok := original.Result[key]; !ok {
			t.Fatalf("original cleanup result omitted comparator field %q", key)
		}
	}

	clone := func() wsproto.CommandResultPayload {
		candidate := roundTrip
		candidate.Result = make(map[string]any, len(roundTrip.Result))
		for key, value := range roundTrip.Result {
			candidate.Result[key] = value
		}
		return candidate
	}
	reject := func(name string, mutate func(*wsproto.CommandResultPayload)) {
		t.Helper()
		candidate := clone()
		mutate(&candidate)
		if signedBoundaryCommandResultJSONEqual(original, candidate) {
			t.Errorf("cleanup result comparator accepted %s mutation", name)
		}
	}
	reject("OK", func(p *wsproto.CommandResultPayload) { p.OK = false })
	reject("uncertainty", func(p *wsproto.CommandResultPayload) { p.Uncertain = true })
	reject("ID", func(p *wsproto.CommandResultPayload) { p.ID += "-changed" })
	reject("NodeID", func(p *wsproto.CommandResultPayload) { p.NodeID += "-changed" })
	reject("status", func(p *wsproto.CommandResultPayload) { p.Status += "-changed" })
	reject("error", func(p *wsproto.CommandResultPayload) { p.Error = "changed" })
	reject("completion timestamp", func(p *wsproto.CommandResultPayload) { p.CompletedAt = p.CompletedAt.Add(time.Nanosecond) })
	reject("numeric value", func(p *wsproto.CommandResultPayload) { p.Result["locked_bytes"] = int64(1) })
	reject("numeric string type", func(p *wsproto.CommandResultPayload) { p.Result["locked_bytes"] = "0" })
	reject("numeric boolean type", func(p *wsproto.CommandResultPayload) { p.Result["locked_bytes"] = true })
	reject("missing result key", func(p *wsproto.CommandResultPayload) { delete(p.Result, "locked_bytes") })
	reject("extra result key", func(p *wsproto.CommandResultPayload) { p.Result["unexpected"] = true })
	reject("action", func(p *wsproto.CommandResultPayload) { p.Result["action"] = "unload_model" })
	reject("fingerprint", func(p *wsproto.CommandResultPayload) { p.Result["fingerprint"] = "changed" })
	reject("fence value", func(p *wsproto.CommandResultPayload) { p.Result["fencing_token"] = p.Result["fencing_token"].(float64) + 1 })
	reject("observed fence value", func(p *wsproto.CommandResultPayload) { p.Result["observed_after_fence"] = p.Result["observed_after_fence"].(float64) + 1 })
	reject("marshal error", func(p *wsproto.CommandResultPayload) { p.Result["unmarshalable"] = make(chan int) })
	afterControls, err := json.Marshal(original)
	if err != nil || !bytes.Equal(originalJSON, afterControls) {
		t.Fatal("comparator controls mutated the original cleanup result map")
	}
}

func (n *signedBoundaryNode) command(t *testing.T, id, key, action, tier string, fence int64) wsproto.CommandPayload {
	t.Helper()
	args := wsproto.CanonicalResidencyCommandArgs(n.cfg.NodeID+"-runtime", "model", n.identity, n.version, domain.CapabilityContractVersion, tier, fence)
	command := wsproto.CommandPayload{ID: id, IdempotencyKey: key, NodeID: n.cfg.NodeID, Command: action, Args: args, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	resignBoundaryCommand(t, &command, []byte(n.cfg.CommandSigningSecret))
	return command
}

func resignBoundaryCommand(t *testing.T, command *wsproto.CommandPayload, secret []byte) {
	t.Helper()
	signature, err := wsproto.SignCommand(*command, secret)
	if err != nil {
		t.Fatal(err)
	}
	command.Signature = signature
}

func boundaryEvent(t *testing.T, name string) {
	t.Helper()
	t.Logf("boundary pass: %s", name)
}

func runControllerResidencySignedNodeBoundary(t *testing.T) {
	t.Helper()
	runSignedNodeLifecycleBoundary(t)
	runSignedControllerWebsocketBoundary(t)
	runSignedNodeRecoveryBoundary(t)
	runSignedOfflineBoundary(t)
	runControllerResidencyQueryIntegration(t)
}

func runSignedNodeLifecycleBoundary(t *testing.T) {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "node-command-state.json")
	node := newSignedBoundaryNode(t, "node-a", "unloaded", statePath)
	t.Cleanup(node.endpoint.Close)
	handler := node.handler
	load := node.command(t, "boundary-load", "boundary-load-key", "load_model", "hot_vram", 1)
	loaded := handler.Handle(context.Background(), load)
	if !loaded.OK || loaded.Result["tier"] != "hot_vram" || loaded.Result["resident"] != true || node.runtime.currentState() != "loaded" {
		t.Fatalf("signed node load did not prove hot residency: result=%+v state=%q", loaded, node.runtime.currentState())
	}
	replayedLoad := handler.Handle(context.Background(), load)
	if !replayedLoad.OK || replayedLoad.CompletedAt != loaded.CompletedAt || !reflect.DeepEqual(replayedLoad.Result, loaded.Result) || node.runtime.loadCalls.Load() != 1 {
		t.Fatalf("node command replay changed the exact load result or repeated its side effect: first=%+v replay=%+v loads=%d", loaded, replayedLoad, node.runtime.loadCalls.Load())
	}
	boundaryEvent(t, "node_handle_replay_exact")

	unload := node.command(t, "boundary-unload", "boundary-unload-key", "unload_model", "cold_disk", 2)
	unloaded := handler.Handle(context.Background(), unload)
	if !unloaded.OK || unloaded.Result["tier"] != "cold_disk" || unloaded.Result["resident"] != false || node.runtime.currentState() != "unloaded" {
		t.Fatalf("signed node unload did not prove cold residency: result=%+v state=%q", unloaded, node.runtime.currentState())
	}
	loadForWarm := node.command(t, "boundary-load-warm", "boundary-load-warm-key", "load_model", "hot_vram", 3)
	if result := handler.Handle(context.Background(), loadForWarm); !result.OK || result.Result["resident"] != true {
		t.Fatalf("warm fixture could not establish loaded runtime state: %+v", result)
	}
	warm := node.command(t, "boundary-warm", "boundary-warm-key", "warm_model", "warm_ram", 4)
	warmed := handler.Handle(context.Background(), warm)
	if !warmed.OK || warmed.Result["tier"] != "warm_ram" || warmed.Result["warm_model_bytes_verified"] != true || warmed.Result["released_vram"] != true || warmed.Result["oracle"] != "mincore+mlock" || node.runtime.currentState() != "unloaded" {
		t.Fatalf("signed warm transition lacks real resident-and-locked proof or released runtime state: %+v runtime=%q", warmed, node.runtime.currentState())
	}
	boundaryEvent(t, "warm_verified")
	beforeWarmReplayUnloads := node.runtime.unloadCalls.Load()
	warmReplay := handler.Handle(context.Background(), warm)
	if !warmReplay.OK || warmReplay.CompletedAt != warmed.CompletedAt || !reflect.DeepEqual(warmReplay.Result, warmed.Result) || node.runtime.unloadCalls.Load() != beforeWarmReplayUnloads {
		t.Fatalf("warm replay was not exact and side-effect free: first=%+v replay=%+v unloads=%d", warmed, warmReplay, node.runtime.unloadCalls.Load())
	}
	boundaryEvent(t, "warm_replay_exact")

	cleanup := node.command(t, "boundary-cleanup", "boundary-cleanup-key", "cleanup_warm_model", "cold_disk", 5)
	cleaned := handler.Handle(context.Background(), cleanup)
	if !cleaned.OK || cleaned.Result["tier"] != "cold_disk" || cleaned.Result["warm_entry_absent"] != true || cleaned.Result["warm_release_verified"] != true || cleaned.Result["locked_bytes"] != int64(0) {
		t.Fatalf("signed warm cleanup lacks exact released-state evidence: %+v", cleaned)
	}
	boundaryEvent(t, "cleanup_cold")

	beforeRestartLoads := node.runtime.loadCalls.Load()
	beforeRestartUnloads := node.runtime.unloadCalls.Load()
	restarted := nodeagent.NewCommandHandler(node.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	restartReplay := restarted.Handle(context.Background(), cleanup)
	if !signedBoundaryCommandResultJSONEqual(cleaned, restartReplay) ||
		restartReplay.Result["tier"] != "cold_disk" || restartReplay.Result["warm_ram"] != false ||
		restartReplay.Result["cleaned"] != true || restartReplay.Result["warm_entry_absent"] != true ||
		restartReplay.Result["warm_release_verified"] != true || restartReplay.Result["warm_model_bytes"] != float64(0) ||
		restartReplay.Result["locked_bytes"] != float64(0) || node.runtime.currentState() != "unloaded" ||
		node.runtime.loadCalls.Load() != beforeRestartLoads || node.runtime.unloadCalls.Load() != beforeRestartUnloads {
		t.Fatalf("node restart did not replay the exact durable result: before=%+v after=%+v", cleaned, restartReplay)
	}
	assertSignedBoundaryCommandResultComparatorControls(t, cleaned)
	boundaryEvent(t, "restart_replay_exact")

	mutationCount := node.runtime.loadCalls.Load() + node.runtime.unloadCalls.Load()
	expired := node.command(t, "boundary-expired", "boundary-expired-key", "load_model", "hot_vram", 6)
	expired.IssuedAt = time.Now().UTC().Add(-2 * time.Minute)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Second)
	resignBoundaryCommand(t, &expired, []byte(node.cfg.CommandSigningSecret))
	expiredResult := handler.Handle(context.Background(), expired)
	if expiredResult.OK || !strings.Contains(expiredResult.Error, "expired") || mutationCount != node.runtime.loadCalls.Load()+node.runtime.unloadCalls.Load() || node.runtime.currentState() != "unloaded" {
		t.Fatalf("expired signed command crossed the mutation boundary: result=%+v before=%d after=%d state=%q", expiredResult, mutationCount, node.runtime.loadCalls.Load()+node.runtime.unloadCalls.Load(), node.runtime.currentState())
	}
	boundaryEvent(t, "signed_expiry_zero_mutation")

	stale := node.command(t, "boundary-stale", "boundary-stale-key", "load_model", "hot_vram", 4)
	beforeStale := node.runtime.loadCalls.Load()
	staleResult := handler.Handle(context.Background(), stale)
	if staleResult.OK || !strings.Contains(staleResult.Error, "stale") || node.runtime.loadCalls.Load() != beforeStale {
		t.Fatalf("stale fence reached the runtime: result=%+v loads=%d before=%d", staleResult, node.runtime.loadCalls.Load(), beforeStale)
	}
	boundaryEvent(t, "stale_rejected")

	badEnvelope := node.command(t, "boundary-envelope", "boundary-envelope-key", "load_model", "hot_vram", 6)
	badEnvelope.Args["runtime_identity"] = "node-a-other|llamacpp||runtime-v1|other"
	resignBoundaryCommand(t, &badEnvelope, []byte(node.cfg.CommandSigningSecret))
	beforeEnvelope := node.runtime.loadCalls.Load()
	envelopeResult := handler.Handle(context.Background(), badEnvelope)
	if envelopeResult.OK || node.runtime.loadCalls.Load() != beforeEnvelope {
		t.Fatalf("runtime-identity envelope mismatch was accepted or mutated runtime: result=%+v", envelopeResult)
	}
	boundaryEvent(t, "envelope_rejected")

	emptyCapability := node.command(t, "boundary-empty-capability", "boundary-empty-capability-key", "load_model", "hot_vram", 6)
	emptyCapability.Args["capability_version"] = ""
	resignBoundaryCommand(t, &emptyCapability, []byte(node.cfg.CommandSigningSecret))
	beforeEmpty := node.runtime.loadCalls.Load()
	emptyResult := handler.Handle(context.Background(), emptyCapability)
	if emptyResult.OK || node.runtime.loadCalls.Load() != beforeEmpty {
		t.Fatalf("empty capability envelope was accepted or mutated runtime: result=%+v", emptyResult)
	}
	boundaryEvent(t, "empty_capability_rejected")

	runSignedRollbackBoundary(t)
}

func runSignedRollbackBoundary(t *testing.T) {
	t.Helper()
	node := newSignedBoundaryNode(t, "node-a", "unloaded", filepath.Join(t.TempDir(), "rollback-state.json"))
	t.Cleanup(node.endpoint.Close)
	node.runtime.mu.Lock()
	node.runtime.holdNextLoad = true
	node.runtime.mu.Unlock()
	load := node.command(t, "boundary-rollback", "boundary-rollback-key", "load_model", "hot_vram", 1)
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	rolledBack := node.handler.Handle(short, load)
	cancel()
	if rolledBack.OK || !rolledBack.Uncertain || !strings.Contains(rolledBack.Error, "inverse state restored") || node.runtime.currentState() != "unloaded" || node.runtime.unloadCalls.Load() != 1 {
		t.Fatalf("canceled load did not observe its signed inverse rollback: result=%+v state=%q unloads=%d", rolledBack, node.runtime.currentState(), node.runtime.unloadCalls.Load())
	}
	boundaryEvent(t, "rollback_observed")

	mismatch := newSignedBoundaryNode(t, "node-a", "unloaded", filepath.Join(t.TempDir(), "mismatch-state.json"))
	t.Cleanup(mismatch.endpoint.Close)
	mismatch.runtime.mu.Lock()
	mismatch.runtime.holdNextLoad = true
	mismatch.runtime.mismatchNextUnload = true
	mismatch.runtime.mu.Unlock()
	mismatchLoad := mismatch.command(t, "boundary-mismatch-rollback", "boundary-mismatch-rollback-key", "load_model", "hot_vram", 1)
	mismatchCtx, mismatchCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	mismatchResult := mismatch.handler.Handle(mismatchCtx, mismatchLoad)
	mismatchCancel()
	if mismatchResult.OK || !mismatchResult.Uncertain || !strings.Contains(mismatchResult.Error, "reconciliation required") || mismatch.runtime.currentState() != "loaded" || mismatch.runtime.unloadCalls.Load() != 1 {
		t.Fatalf("mismatched inverse observation was not held uncertain: result=%+v state=%q unloads=%d", mismatchResult, mismatch.runtime.currentState(), mismatch.runtime.unloadCalls.Load())
	}
	boundaryEvent(t, "mismatch_rollback_observed")
}

func runSignedNodeRecoveryBoundary(t *testing.T) {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "uncertain-state.json")
	node := newSignedBoundaryNode(t, "node-a", "unloaded", statePath)
	t.Cleanup(node.endpoint.Close)
	node.runtime.mu.Lock()
	node.runtime.holdNextLoad = true
	node.runtime.mu.Unlock()
	original := node.command(t, "boundary-uncertain", "boundary-uncertain-key", "load_model", "hot_vram", 1)
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	uncertain := node.handler.Handle(short, original)
	cancel()
	if uncertain.OK || !uncertain.Uncertain {
		t.Fatalf("side-effecting load did not retain an uncertain intent: %+v", uncertain)
	}

	restarted := nodeagent.NewCommandHandler(node.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if node.runtime.loadCalls.Load() != 1 {
		t.Fatalf("node restart replayed an uncertain mutation before a query: loads=%d", node.runtime.loadCalls.Load())
	}
	boundaryEvent(t, "uncertain_restart_query_first")
	wrongTarget := node.command(t, "boundary-query-wrong-target", "boundary-query-wrong-target-key", "query_model_state", "query", 1)
	wrongTarget.Args["expected_fence"], wrongTarget.Args["observed_after_fence"] = int64(1), int64(1)
	wrongTarget.Args["original_command_id"], wrongTarget.Args["original_idempotency_key"] = original.ID, original.IdempotencyKey
	wrongTarget.Args["target_id"] = "node-a-other"
	resignBoundaryCommand(t, &wrongTarget, []byte(node.cfg.CommandSigningSecret))
	wrongTargetResult := restarted.Handle(context.Background(), wrongTarget)
	if wrongTargetResult.OK || !strings.Contains(wrongTargetResult.Error, "target") {
		t.Fatalf("live pending query for another resource was not rejected: %+v", wrongTargetResult)
	}
	boundaryEvent(t, "live_pending_wrong_resource_rejected")

	wrongIdentity := node.command(t, "boundary-query-wrong-identity", "boundary-query-wrong-identity-key", "query_model_state", "query", 1)
	wrongIdentity.Args["expected_fence"], wrongIdentity.Args["observed_after_fence"] = int64(1), int64(1)
	wrongIdentity.Args["original_command_id"], wrongIdentity.Args["original_idempotency_key"] = original.ID, original.IdempotencyKey
	wrongIdentity.Args["runtime_identity"] = "node-a-runtime|llamacpp||different-runtime|different-model"
	resignBoundaryCommand(t, &wrongIdentity, []byte(node.cfg.CommandSigningSecret))
	wrongIdentityResult := restarted.Handle(context.Background(), wrongIdentity)
	if wrongIdentityResult.OK || !strings.Contains(wrongIdentityResult.Error, "runtime") {
		t.Fatalf("live pending query with drifted runtime identity was not rejected: %+v", wrongIdentityResult)
	}
	boundaryEvent(t, "live_pending_runtime_identity_rejected")

	// The query is issued before any retry of the mutation and uses the exact
	// durable pending linkage restored by the new node command handler.
	query := node.command(t, "boundary-query-exact", "boundary-query-exact-key", "query_model_state", "query", 1)
	query.Args["expected_fence"], query.Args["observed_after_fence"] = int64(1), int64(1)
	query.Args["original_command_id"], query.Args["original_idempotency_key"] = original.ID, original.IdempotencyKey
	resignBoundaryCommand(t, &query, []byte(node.cfg.CommandSigningSecret))
	observed := restarted.Handle(context.Background(), query)
	if !observed.OK || observed.Result["tier"] != "cold_disk" || observed.Result["original_command_id"] != original.ID {
		t.Fatalf("exact linked query did not return authoritative cold state: %+v", observed)
	}
	boundaryEvent(t, "query_authoritative")
	if replay := restarted.Handle(context.Background(), query); !replay.OK || replay.CompletedAt != observed.CompletedAt || !reflect.DeepEqual(replay.Result, observed.Result) {
		t.Fatalf("settled query replay changed authoritative result: first=%+v replay=%+v", observed, replay)
	}
	boundaryEvent(t, "uncertain_intent_reconciled")
}

func runSignedControllerWebsocketBoundary(t *testing.T) {
	t.Helper()
	node := newSignedBoundaryNode(t, "node-a", "unloaded", filepath.Join(t.TempDir(), "websocket-state.json"))
	t.Cleanup(node.endpoint.Close)
	srv, _, cancelServer := testServer(t)
	t.Cleanup(cancelServer)
	srv.commandSecret = []byte(node.cfg.CommandSigningSecret)
	gateway := httptest.NewServer(srv.Handler())
	t.Cleanup(gateway.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(gateway.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatalf("dial signed controller node websocket: %v", err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	ready := true
	register := wsproto.RegisterPayload{NodeID: "node-a", NodeName: "signed boundary node", Ready: &ready, AgentVersion: nodeagent.AgentVersion, CapabilityVersion: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, Adapters: []wsproto.AdapterAdvertisement{node.advertise}}
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(register)}); err != nil {
		t.Fatalf("register signed boundary node: %v", err)
	}
	var ack wsproto.Envelope
	if err := wsjson.Read(ctx, connection, &ack); err != nil || ack.Type != wsproto.MsgAck {
		t.Fatalf("signed node registration was not acknowledged: type=%q err=%v", ack.Type, err)
	}
	nodeDone := make(chan error, 1)
	go func() {
		for {
			var envelope wsproto.Envelope
			if readErr := wsjson.Read(ctx, connection, &envelope); readErr != nil {
				nodeDone <- readErr
				return
			}
			if envelope.Type != wsproto.MsgCommand {
				continue
			}
			var command wsproto.CommandPayload
			if decodeErr := json.Unmarshal(envelope.Payload, &command); decodeErr != nil {
				nodeDone <- decodeErr
				return
			}
			result := node.handler.Handle(ctx, command)
			if result.CompletedAt.IsZero() {
				result.CompletedAt = time.Now().UTC()
			}
			if writeErr := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgCommandResult, Payload: mustJSON(result)}); writeErr != nil {
				nodeDone <- writeErr
				return
			}
		}
	}()

	issue := func(id, key, action, tier string, fence int64) *domain.NodeCommand {
		t.Helper()
		args := wsproto.CanonicalResidencyCommandArgs("node-a-runtime", "model", node.identity, node.version, domain.CapabilityContractVersion, tier, fence)
		body := map[string]any{"command": action, "args": args}
		request, _ := http.NewRequest(http.MethodPost, gateway.URL+"/admin/api/nodes/node-a/commands", bytes.NewReader(mustJSON(body)))
		request.RemoteAddr = "127.0.0.1:5000"
		request.Header.Set("Authorization", "Bearer admin-token")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response, requestErr := gateway.Client().Do(request)
		if requestErr != nil {
			t.Fatalf("issue signed %s command: %v", action, requestErr)
		}
		defer response.Body.Close()
		var row domain.NodeCommand
		if response.StatusCode != http.StatusAccepted {
			t.Fatalf("issue signed %s status=%d", action, response.StatusCode)
		}
		if decodeErr := json.NewDecoder(response.Body).Decode(&row); decodeErr != nil {
			t.Fatalf("decode signed %s row: %v", action, decodeErr)
		}
		if row.ID == "" || !wsproto.VerifyCommand(nodeCommandPayload(&row), srv.commandSecret) {
			t.Fatalf("controller did not persist a verifiable signed %s command: %+v", action, row)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			current, getErr := srv.workloadStore.GetNodeCommand(context.Background(), row.ID)
			if getErr == nil && current != nil && (current.Status == domain.NodeCommandSucceeded || current.Status == domain.NodeCommandFailed) {
				return current
			}
			select {
			case nodeErr := <-nodeDone:
				t.Fatalf("signed node loop stopped: %v", nodeErr)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("signed %s result did not settle in the controller", action)
		return nil
	}

	beforeLoadCalls := node.runtime.loadCalls.Load()
	loaded := issue("controller-boundary-load", "controller-boundary-load-key", "load_model", "hot_vram", 1)
	if loaded.Status != domain.NodeCommandSucceeded || node.runtime.currentState() != "loaded" || node.runtime.loadCalls.Load() != beforeLoadCalls+1 {
		t.Fatalf("signed controller/node load did not prove one real loaded-state mutation: row=%+v state=%q loads_before=%d loads_after=%d", loaded, node.runtime.currentState(), beforeLoadCalls, node.runtime.loadCalls.Load())
	}
	boundaryEvent(t, "load_hot")
	beforeUnloadCalls := node.runtime.unloadCalls.Load()
	unloaded := issue("controller-boundary-unload", "controller-boundary-unload-key", "unload_model", "cold_disk", 2)
	if unloaded.Status != domain.NodeCommandSucceeded || node.runtime.currentState() != "unloaded" || node.runtime.unloadCalls.Load() != beforeUnloadCalls+1 {
		t.Fatalf("signed controller/node unload did not prove one real unloaded-state mutation: row=%+v state=%q unloads_before=%d unloads_after=%d", unloaded, node.runtime.currentState(), beforeUnloadCalls, node.runtime.unloadCalls.Load())
	}
	boundaryEvent(t, "unload_cold")

	backing, ok := srv.nodes.(store.Store)
	if !ok {
		t.Fatal("signed boundary backing store cannot survive controller restart")
	}
	connection.CloseNow()
	cancel()
	cancelServer()
	gateway.Close()
	restarted := NewServer(srv.cfg, srv.log, backing, nil, nil)
	restarted.commandSecret = []byte(node.cfg.CommandSigningSecret)
	restartedGateway := httptest.NewServer(restarted.Handler())
	t.Cleanup(func() {
		restartedGateway.Close()
		restarted.Close()
	})
	replayBody := map[string]any{"command": unloaded.Command, "args": unloaded.Args}
	replayRequest, err := http.NewRequest(http.MethodPost, restartedGateway.URL+"/admin/api/nodes/node-a/commands", bytes.NewReader(mustJSON(replayBody)))
	if err != nil {
		t.Fatal(err)
	}
	replayRequest.Header.Set("Authorization", "Bearer admin-token")
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.Header.Set("Idempotency-Key", unloaded.IdempotencyKey)
	replayResponse, err := restartedGateway.Client().Do(replayRequest)
	if err != nil {
		t.Fatalf("replay completed command after controller restart: %v", err)
	}
	defer replayResponse.Body.Close()
	var replayed domain.NodeCommand
	if replayResponse.StatusCode != http.StatusAccepted || json.NewDecoder(replayResponse.Body).Decode(&replayed) != nil {
		t.Fatalf("controller restart replay status=%d", replayResponse.StatusCode)
	}
	if replayed.ID != unloaded.ID || replayed.Status != domain.NodeCommandSucceeded || replayed.Signature != unloaded.Signature || !bytes.Equal(replayed.Result, unloaded.Result) || !reflect.DeepEqual(replayed.Args, unloaded.Args) {
		t.Fatalf("controller restart changed the exact signed successful result: before=%+v after=%+v", unloaded, replayed)
	}
	boundaryEvent(t, "controller_restart_replay_exact")
}

func runControllerNativeComfyBoundary(t *testing.T) {
	t.Helper()
	srv, manager, cancel := testServer(t)
	defer cancel()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("comfy", "comfy", http.DefaultClient))
	manager.SetNodeStore(srv.nodes)
	srv.commandSecret = []byte("signed-controller-node-boundary-secret-32")
	var freeCalls atomic.Int32
	comfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/free" {
			freeCalls.Add(1)
		}
		http.NotFound(w, r)
	}))
	defer comfy.Close()
	gateway := httptest.NewServer(srv.Handler())
	defer gateway.Close()
	ctx, cancelWS := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelWS()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(gateway.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatalf("dial Comfy capability boundary websocket: %v", err)
	}
	defer connection.CloseNow()
	ready := true
	register := wsproto.RegisterPayload{NodeID: "node-a", NodeName: "native Comfy node", Ready: &ready, AgentVersion: nodeagent.AgentVersion, CapabilityVersion: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, Adapters: []wsproto.AdapterAdvertisement{{ID: "comfy", Adapter: "comfy", Endpoint: comfy.URL, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsAcceleratorReclaim: false}, SupportsAcceleratorReclaim: false}}}
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(register)}); err != nil {
		t.Fatalf("register native Comfy capability: %v", err)
	}
	var ack wsproto.Envelope
	if err := wsjson.Read(ctx, connection, &ack); err != nil || ack.Type != wsproto.MsgAck {
		t.Fatalf("native Comfy registration was not acknowledged: type=%q err=%v", ack.Type, err)
	}
	if _, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-a", Name: "native Comfy node", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true}, Accelerators: []domain.Accelerator{{ID: "node-a-gpu0", VRAMTotalMB: 16_000, VRAMFreeMB: 16_000}}}); err != nil {
		t.Fatalf("seed native Comfy controller node: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, target := range manager.Targets() {
			if target.Adapter == "comfy" {
				if target.SupportsAcceleratorReclaim {
					t.Fatalf("native Comfy was advertised as an authoritative reclaim capability: target=%+v", target)
				}
				drainResult, drainErr := manager.DrainNode(context.Background(), "node-a", "boundary", "native-comfy-forbidden-reclaim")
				if drainErr != nil || drainResult == nil || len(drainResult.TransitionIDs) != 0 {
					t.Fatalf("controller native Comfy reclaim attempt was not denied before transition: result=%+v err=%v", drainResult, drainErr)
				}
				if target.SupportsAcceleratorReclaim || freeCalls.Load() != 0 {
					t.Fatalf("native Comfy was advertised or exercised as an authoritative reclaim capability: target=%+v free_calls=%d", target, freeCalls.Load())
				}
				boundaryEvent(t, "native_comfy_reclaim_denied_zero_free")
				boundaryEvent(t, "native_comfy_capability_false_zero_free")
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("native Comfy target was not projected from the registered node; free calls=%d", freeCalls.Load())
}

func runSignedOfflineBoundary(t *testing.T) {
	t.Helper()
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("signed-controller-node-boundary-secret-32")
	now := time.Now().UTC()
	if _, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-offline", Name: "offline node", Observed: domain.Observed{Connectivity: domain.ConnectivityOffline}}); err != nil {
		t.Fatal(err)
	}
	command := &domain.NodeCommand{ID: "offline-command", IdempotencyKey: "offline-command-key", NodeID: "node-offline", Command: "refresh_capabilities", Args: map[string]any{}, Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
	command.Signature, _ = wsproto.SignCommand(nodeCommandPayload(command), srv.commandSecret)
	stored, _, err := srv.workloadStore.CreateNodeCommand(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.sendNodeCommand(context.Background(), stored); err == nil {
		t.Fatal("offline node command crossed an absent websocket connection")
	}
	after, err := srv.workloadStore.GetNodeCommand(context.Background(), command.ID)
	if err != nil || after == nil || after.Status != domain.NodeCommandQueued || after.Attempts != 0 {
		t.Fatalf("offline delivery changed the durable command before a node connection: row=%+v err=%v", after, err)
	}
	boundaryEvent(t, "offline_rejected")
}

func runControllerResidencyQueryIntegration(t *testing.T) {
	t.Helper()
	if !t.Run("uncertain-controller-query", TestControllerRejectsForgedAuthoritativeObservation) {
		t.Fatal("signed controller query boundary failed")
	}
	for _, event := range []string{"late_result_reconciled", "live_pending_wrong_resource_rejected", "live_pending_runtime_identity_rejected", "query_authoritative"} {
		boundaryEvent(t, event)
	}
	if !t.Run("controller-restart-query-first", TestAdminNodeCommandUncertainReplayUsesQueryRecovery) {
		t.Fatal("controller restart recovery boundary failed")
	}
	boundaryEvent(t, "uncertain_restart_query_first")
}

func TestControllerNativeComfyBoundaryIsFailClosed(t *testing.T) {
	runControllerNativeComfyBoundary(t)
}

func profileGuardServer(t *testing.T, backing *store.MemoryStore) *Server {
	t.Helper()
	manager := workloads.NewManager(slog.Default(), store.NewMemoryStore(), time.Second)
	t.Cleanup(manager.Close)
	profiles := []workloads.RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}
	for _, id := range []string{"node-a-runtime", "node-a-runtime-alias", "node-a-runtime-gpu1"} {
		index := 0
		if strings.HasSuffix(id, "gpu1") {
			index = 1
		}
		target := workloads.Target{
			ID: id, NodeID: "node-a", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-a-gpu" + strconv.Itoa(index),
			CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
			ContextLimit: 32768, Slots: 1, ActiveRuntimeProfile: "ctx-32k", CapacitySource: "runtime:/slots", CapacityVerified: true,
			RuntimeProfiles: profiles, Enabled: true,
		}
		manager.RegisterTarget(target)
	}
	return &Server{workloadStore: backing, workloads: manager}
}

type profileResultCASConflictStore struct {
	store.WorkloadStore
}

type profileResultCASBlockingStore struct {
	store.WorkloadStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type profileResidencySnapshotBarrierStore struct {
	store.WorkloadStore
	mu      sync.Mutex
	armed   bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type profileResidencySnapshotBarrierContextKey struct{}

func (s *profileResidencySnapshotBarrierStore) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *profileResidencySnapshotBarrierStore) releaseSnapshot() {
	s.once.Do(func() { close(s.release) })
}

func (s *profileResidencySnapshotBarrierStore) GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error) {
	row, err := s.WorkloadStore.GetModelResidency(ctx, targetID, model)
	owner, _ := ctx.Value(profileResidencySnapshotBarrierContextKey{}).(bool)
	s.mu.Lock()
	block := s.armed && owner && err == nil && row != nil && targetID == "node-a-runtime" && model == "model"
	if block {
		s.armed = false
	}
	s.mu.Unlock()
	if block {
		close(s.entered)
		<-s.release
	}
	return row, err
}

func profileResidencyBarrierServer(t *testing.T) (*Server, *workloads.Manager, *profileResidencySnapshotBarrierStore, func()) {
	t.Helper()
	backing := store.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	residencyStore := &profileResidencySnapshotBarrierStore{
		WorkloadStore: backing, entered: make(chan struct{}), release: make(chan struct{}),
	}
	manager := workloads.NewManager(logger, residencyStore, time.Second)
	manager.RegisterAdapter(workloads.NewMockAdapter())
	manager.RegisterTarget(workloads.Target{ID: "mock", Adapter: "mock", Endpoint: "in-process", Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	server := NewServer(&Config{}, logger, backing, nil, nil)
	server.SetWorkloadManager(manager, residencyStore)
	manager.SetNodeStore(server.nodes)
	manager.Start(ctx)
	return server, manager, residencyStore, func() {
		residencyStore.releaseSnapshot()
		cancel()
		manager.Close()
		server.Close()
	}
}

func (s *profileResultCASBlockingStore) CompareAndSwapNodeCommandRevision(ctx context.Context, command *domain.NodeCommand, expectedRevision uint64, expectedAttempts int, expectedUncertain bool, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error) {
	if command != nil && command.Command == "switch_runtime_profile" && command.Status == domain.NodeCommandSucceeded {
		s.once.Do(func() {
			close(s.entered)
			<-s.release
		})
	}
	return s.WorkloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision, expectedAttempts, expectedUncertain, expected...)
}

func (s *profileResultCASConflictStore) CompareAndSwapNodeCommandRevision(ctx context.Context, command *domain.NodeCommand, expectedRevision uint64, expectedAttempts int, expectedUncertain bool, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error) {
	if command != nil && command.Command == "switch_runtime_profile" && command.Status == domain.NodeCommandSucceeded {
		return nil, store.ErrNodeCommandConflict
	}
	return s.WorkloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision, expectedAttempts, expectedUncertain, expected...)
}

func TestValidateNodeCommandCheckpointEnvelope(t *testing.T) {
	args := map[string]any{"target_kind": "llamacpp", "target_id": "node-llama", "accelerator_id": "node-llama-gpu0", "model": "m", "runtime_identity": "r", "capability_version": "v", "capability_revision": "rev", "profile_fingerprint": "p", "context_fingerprint": "c", "owner_id": "owner", "workload_id": "w", "generation": uint64(1), "fencing_token": uint64(2), "context_limit": 4096, "checkpoint_action": "save", "checkpoint_operation_id": "op", "idempotency_key": "op:save"}
	if err := validateNodeCommand("checkpoint_save", args); err != nil {
		t.Fatal(err)
	}
	args["unexpected"] = true
	if err := validateNodeCommand("checkpoint_save", args); err == nil {
		t.Fatal("unexpected checkpoint envelope field accepted")
	}
}

func TestUnresolvedRuntimeProfileCommandGuardBlocksRepeatSwitch(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   domain.NodeCommandStatus
		attempts int
		blocked  bool
	}{
		{name: "queued before send", status: domain.NodeCommandQueued, attempts: 0, blocked: true},
		{name: "sent after delivery attempt", status: domain.NodeCommandSent, attempts: 1, blocked: true},
		{name: "expired without delivery", status: domain.NodeCommandExpired, attempts: 0},
		{name: "failed without delivery", status: domain.NodeCommandFailed, attempts: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			backing := store.NewMemoryStore()
			server := profileGuardServer(t, backing)
			args := map[string]any{"target_id": "node-a-runtime", "profile_id": "ctx-32k"}
			prior := &domain.NodeCommand{
				ID: "profile-command-1", IdempotencyKey: "profile-key-1", NodeID: "node-a",
				Command: "switch_runtime_profile", Args: args, Attempts: test.attempts, Status: test.status,
			}
			if _, _, err := backing.CreateNodeCommand(context.Background(), prior); err != nil {
				t.Fatal(err)
			}
			err := server.rejectUnresolvedRuntimeProfileCommand(context.Background(), "node-a", args, "profile-key-2")
			if test.blocked && (err == nil || !strings.Contains(err.Error(), "observation_unavailable")) {
				t.Fatalf("new physical switch bypassed unresolved command: %v", err)
			}
			if !test.blocked && err != nil {
				t.Fatalf("proven undelivered command still blocked a switch: %v", err)
			}
			otherRoute := map[string]any{"target_id": "node-a-runtime-alias", "profile_id": "ctx-8k"}
			otherErr := server.rejectUnresolvedRuntimeProfileCommand(context.Background(), "node-a", otherRoute, "profile-key-other-route")
			if test.blocked && (otherErr == nil || !strings.Contains(otherErr.Error(), "observation_unavailable")) {
				t.Fatalf("unresolved profile effect did not quarantine an aliased/same-node route: %v", otherErr)
			}
			if err := server.rejectUnresolvedRuntimeProfileCommand(context.Background(), "node-a", args, "profile-key-1"); err != nil {
				t.Fatalf("exact idempotent replay was rejected: %v", err)
			}
		})
	}
}

func TestRuntimeProfileCommandGuardUsesAcceptedObservationForSucceededHistory(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  json.RawMessage
		target  string
		blocked bool
	}{
		{name: "profile id only legacy success", result: json.RawMessage(`{"profile_id":"ctx-32k"}`), target: "runtime-alias", blocked: true},
		{name: "accepted correlated slot observation", result: json.RawMessage(`{"adapters":[{"id":"runtime","adapter":"mock","endpoint":"http://runtime","accelerator_index":0,"version":"runtime-v1","model_fingerprint":"model-fp","capability_version":"runtime-v1","capability_revision":"cap-v1","context_limit":32768,"slots":1,"capacity_source":"runtime:/slots","capabilities_verified":true,"active_runtime_profile":"ctx-32k","runtime_profiles":[{"id":"ctx-8k","context_limit":8192,"slots":4},{"id":"ctx-32k","context_limit":32768,"slots":1}]}]}`), target: "runtime"},
	} {
		t.Run(test.name, func(t *testing.T) {
			backing := store.NewMemoryStore()
			server := profileGuardServer(t, backing)
			prior := &domain.NodeCommand{
				ID: "profile-command-accepted", IdempotencyKey: "profile-key-old", NodeID: "node-a",
				Command: "switch_runtime_profile", Args: map[string]any{"target_id": "runtime", "profile_id": "ctx-32k"},
				Attempts: 1, Status: domain.NodeCommandSucceeded, Result: test.result,
			}
			if _, _, err := backing.CreateNodeCommand(context.Background(), prior); err != nil {
				t.Fatal(err)
			}
			err := server.rejectUnresolvedRuntimeProfileCommand(context.Background(), "node-a", map[string]any{"target_id": test.target, "profile_id": "ctx-8k"}, "profile-key-new")
			if test.blocked && (err == nil || !strings.Contains(err.Error(), "observation_unavailable")) {
				t.Fatalf("malformed succeeded history failed open: %v", err)
			}
			if !test.blocked && err != nil {
				t.Fatalf("accepted correlated observation remained blocked: %v", err)
			}
		})
	}
}

func TestRuntimeProfileCommandGuardRejectsAmbiguousAcceptedOrdering(t *testing.T) {
	backing := store.NewMemoryStore()
	server := profileGuardServer(t, backing)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, profile := range []struct {
		id      string
		context int
		slots   int
	}{{"ctx-8k", 8192, 4}, {"ctx-32k", 32768, 1}} {
		result := json.RawMessage(`{"adapters":[{"id":"runtime","adapter":"mock","endpoint":"http://runtime","accelerator_index":0,"version":"runtime-v1","model_fingerprint":"model-fp","capability_version":"runtime-v1","capability_revision":"cap-v1","context_limit":` + strconv.Itoa(profile.context) + `,"slots":` + strconv.Itoa(profile.slots) + `,"capacity_source":"runtime:/slots","capabilities_verified":true,"active_runtime_profile":"` + profile.id + `","runtime_profiles":[{"id":"ctx-8k","context_limit":8192,"slots":4},{"id":"ctx-32k","context_limit":32768,"slots":1}]}]}`)
		row := &domain.NodeCommand{
			ID: "profile-" + profile.id, IdempotencyKey: "key-" + profile.id, NodeID: "node-a", Command: "switch_runtime_profile",
			Args: map[string]any{"target_id": "runtime", "profile_id": profile.id}, Attempts: 1, Status: domain.NodeCommandSucceeded,
			Result: result, CreatedAt: base, UpdatedAt: base,
		}
		if _, _, err := backing.CreateNodeCommand(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	err := server.rejectUnresolvedRuntimeProfileCommand(context.Background(), "node-a", map[string]any{"target_id": "runtime", "profile_id": "ctx-8k"}, "profile-key-new")
	if err == nil || !strings.Contains(err.Error(), "ambiguous durable ordering") {
		t.Fatalf("conflicting same-time accepted observations selected arbitrary history: %v", err)
	}
}

func TestRuntimeProfileRawHTTPAndWebsocketDispatchFailClosedWithoutCurrentTicket(t *testing.T) {
	server, _, cleanup := testServer(t)
	defer cleanup()
	server.commandSecret = []byte("runtime-profile-raw-dispatch-test-secret")
	if _, err := server.nodes.UpsertNode(context.Background(), &domain.Node{ID: "node-a"}); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"target_id": "node-a-runtime", "profile_id": "ctx-32k"}
	body, err := json.Marshal(map[string]any{"command": "switch_runtime_profile", "args": args})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-a/commands", bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:5000"
	request.Header.Set("Authorization", "Bearer admin-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "raw-http-profile-key")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "exact current manager transition ticket") {
		t.Fatalf("raw HTTP switch without a scheduler ticket was not rejected: status=%d body=%s", response.Code, response.Body.String())
	}
	rows, err := server.workloadStore.ListNodeCommandRecovery(context.Background(), "node-a", "")
	if err != nil || len(rows) != 0 {
		t.Fatalf("raw HTTP switch was persisted before ticket authorization: rows=%+v err=%v", rows, err)
	}

	if _, err := server.ExecuteNodeCommand(context.Background(), "node-a", "switch_runtime_profile", args, "direct-controller-profile-key"); err == nil || !strings.Contains(err.Error(), "exact current manager transition ticket") {
		t.Fatalf("direct controller switch without a scheduler ticket was not rejected: %v", err)
	}
	rows, err = server.workloadStore.ListNodeCommandRecovery(context.Background(), "node-a", "")
	if err != nil || len(rows) != 0 {
		t.Fatalf("direct controller switch was persisted before ticket authorization: rows=%+v err=%v", rows, err)
	}
	writes := 0
	connection := &nodeConnection{conn: &websocket.Conn{}, nodeID: "node-a", generation: 1, done: make(chan struct{})}
	connection.writeHook = func(context.Context, wsproto.Envelope) error { writes++; return nil }
	server.nodeConnMu.Lock()
	server.nodeConnections[connection.nodeID] = connection
	server.nodeConnMu.Unlock()
	defer func() { connection.conn = nil }()
	command := &domain.NodeCommand{ID: "raw-websocket-profile", IdempotencyKey: "direct-websocket-profile-key", NodeID: "node-a", Command: "switch_runtime_profile", Args: args, Status: domain.NodeCommandQueued, ExpiresAt: time.Now().Add(time.Minute)}
	if err := server.sendNodeCommand(context.Background(), command); err == nil || !strings.Contains(err.Error(), "exact current manager transition ticket") {
		t.Fatalf("websocket mutation without a scheduler ticket was not rejected: %v", err)
	}
	if writes != 0 {
		t.Fatalf("unauthorized switch reached the websocket transport %d times", writes)
	}
}

func TestExecuteNodeCommandHonorsExpiryOnConnectedSilentNode(t *testing.T) {
	backing := store.NewMemoryStore()
	cfg := &Config{}
	cfg.Auth.CommandSigningSecret = "connected-silent-node-test-secret-32"
	server := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), backing, nil, nil)
	var connection *nodeConnection
	defer func() {
		if connection != nil {
			connection.conn = nil
		}
		server.Close()
	}()
	server.nodeCommandExpiry = 25 * time.Millisecond
	if _, err := backing.UpsertNode(context.Background(), &domain.Node{ID: "silent-node"}); err != nil {
		t.Fatal(err)
	}
	connection = &nodeConnection{
		conn:       &websocket.Conn{},
		nodeID:     "silent-node",
		generation: 1,
		done:       make(chan struct{}),
		writeHook: func(context.Context, wsproto.Envelope) error {
			// Delivery succeeds, but this connected peer never reports a result.
			return nil
		},
	}
	server.nodeConnMu.Lock()
	server.nodeConnections[connection.nodeID] = connection
	server.nodeConnMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := server.executeNodeCommand(ctx, connection.nodeID, "refresh_capabilities", nil, "silent-node-command")
	if err == nil || !strings.Contains(err.Error(), "expired; recovery is pending") {
		rows, _ := backing.ListNodeCommands(ctx, connection.nodeID, 0)
		t.Fatalf("silent connected command did not take bounded expiry path: %v rows=%+v", err, rows)
	}
	rows, listErr := backing.ListNodeCommands(ctx, connection.nodeID, 0)
	if listErr != nil || len(rows) != 1 {
		t.Fatalf("silent command was not durably recorded: rows=%+v err=%v", rows, listErr)
	}
	if !rows[0].Uncertain || rows[0].Status != domain.NodeCommandSent {
		t.Fatalf("silent command was not promoted to uncertainty: %+v", rows[0])
	}
}

func TestRuntimeProfileRepeatedSchedulerSwitchesUsePretransitionHistoryBasis(t *testing.T) {
	for _, acceleratorIndex := range []int{0, 1} {
		t.Run(strconv.Itoa(acceleratorIndex), func(t *testing.T) {
			server, manager, cleanup := testServer(t)
			defer cleanup()
			server.commandSecret = []byte("repeated-runtime-profile-switch-test-secret")
			manager.SetNodeStore(server.nodes)
			manager.RegisterTarget(workloads.Target{ID: "mock", Adapter: "mock", Enabled: false})
			now := time.Now().UTC()
			if _, err := server.nodes.UpsertNode(context.Background(), &domain.Node{
				ID: "node-a", SchedulingState: domain.SchedulingEnabled,
				Desired:  domain.Desired{SchedulingEnabled: true},
				Observed: domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now},
				Accelerators: []domain.Accelerator{
					{ID: "node-a-gpu0", NodeID: "node-a", VRAMTotalMB: 24_000, VRAMFreeMB: 24_000},
					{ID: "node-a-gpu1", NodeID: "node-a", VRAMTotalMB: 24_000, VRAMFreeMB: 24_000},
				},
			}); err != nil {
				t.Fatal(err)
			}
			routeID := "node-a-runtime-gpu" + strconv.Itoa(acceleratorIndex)
			acceleratorID := "node-a-gpu" + strconv.Itoa(acceleratorIndex)
			target := workloads.Target{
				ID: routeID, NodeID: "node-a", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: acceleratorID,
				CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
				ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
				SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []workloads.RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
			}
			manager.RegisterTarget(target)
			connection := &nodeConnection{conn: &websocket.Conn{}, nodeID: "node-a", generation: 1, done: make(chan struct{})}
			defer func() { connection.conn = nil }()
			dispatchedProfiles := make(chan string, 3)
			connection.writeHook = func(ctx context.Context, envelope wsproto.Envelope) error {
				var command wsproto.CommandPayload
				if err := json.Unmarshal(envelope.Payload, &command); err != nil {
					return err
				}
				if command.Command != "switch_runtime_profile" {
					return nil
				}
				profileID, _ := command.Args["profile_id"].(string)
				var profile workloads.RuntimeCapacityProfile
				for _, candidate := range target.RuntimeProfiles {
					if candidate.ID == profileID {
						profile = candidate
					}
				}
				if profile.ID == "" {
					return fmt.Errorf("unexpected physical profile request %q", profileID)
				}
				id := strings.TrimPrefix(routeID, "node-a-")
				result := map[string]any{"adapters": []any{map[string]any{
					"id": id, "adapter": target.Adapter, "endpoint": target.Endpoint, "accelerator_index": acceleratorIndex,
					"version": target.RuntimeIdentity, "model_fingerprint": target.ModelFingerprint,
					"capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision,
					"context_limit": profile.ContextLimit, "slots": profile.Slots, "capacity_source": "runtime:/slots", "capabilities_verified": true,
					"active_runtime_profile": profile.ID, "runtime_profiles": []any{
						map[string]any{"id": "ctx-8k", "context_limit": 8192, "slots": 4},
						map[string]any{"id": "ctx-32k", "context_limit": 32768, "slots": 1},
					},
				}}}
				dispatchedProfiles <- profileID
				server.handleNodeCommandResult(ctx, wsproto.CommandResultPayload{ID: command.ID, NodeID: "node-a", OK: true, Result: result, CompletedAt: time.Now().UTC()})
				return nil
			}
			server.nodeConnMu.Lock()
			server.nodeConnections["node-a"] = connection
			server.nodeConnMu.Unlock()

			for index, tokens := range []int{30_000, 5_000, 20_000} {
				id := "repeated-profile-switch-" + strconv.Itoa(acceleratorIndex) + "-" + strconv.Itoa(index)
				request := domain.WorkloadRequest{ID: id, OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{}`), Bounds: domain.WorkloadBounds{ContextTokens: tokens, MaxOutput: 1_000}}
				if _, _, err := manager.Submit(context.Background(), request); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(4 * time.Second)
				var workload *domain.Workload
				for time.Now().Before(deadline) {
					workload, _ = server.workloadStore.GetWorkload(context.Background(), id)
					if workload != nil && workload.Status != domain.WorkloadQueued && workload.Status != domain.WorkloadWaiting && workload.Status != domain.WorkloadRunning {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if workload == nil || workload.Status != domain.WorkloadSucceeded {
					t.Fatalf("scheduler request %d did not finish through its observed profile: %+v", index, workload)
				}
			}
			wantProfiles := []string{"ctx-32k", "ctx-8k", "ctx-32k"}
			for _, want := range wantProfiles {
				select {
				case got := <-dispatchedProfiles:
					if got != want {
						t.Fatalf("physical profile dispatch sequence %v, want %v", got, wantProfiles)
					}
				case <-time.After(time.Second):
					t.Fatalf("scheduler did not dispatch all three physical switches; want %v", wantProfiles)
				}
			}
			rows, err := server.workloadStore.ListNodeCommandRecovery(context.Background(), "node-a", "")
			if err != nil {
				t.Fatal(err)
			}
			completed := 0
			for _, row := range rows {
				if row.Command == "switch_runtime_profile" {
					completed++
					if row.Status != domain.NodeCommandSucceeded {
						t.Fatalf("repeated switch %s did not durably succeed: %+v", row.ID, row)
					}
				}
			}
			if completed != 3 {
				t.Fatalf("durable history contains %d successful physical switches, want 3", completed)
			}
		})
	}
}

func TestRuntimeProfileProjectionBeforeWaiterAdmission(t *testing.T) {
	cases := []struct {
		name                      string
		registerBeforeResult      bool
		registerAfterResult       bool
		invalidObservation        bool
		resultCASConflict         bool
		lateKnownCompletion       bool
		lateUnknownResult         bool
		retireDuringWrite         bool
		replaceRouteDuringWrite   bool
		resultCASLifecycleBarrier bool
		residencyWriterCASBarrier bool
	}{
		{name: "registration before result", registerBeforeResult: true},
		{name: "registration after result", registerAfterResult: true},
		{name: "missing observation", invalidObservation: true},
		{name: "durable result CAS conflict", resultCASConflict: true},
		{name: "late known completion", lateKnownCompletion: true},
		{name: "late unknown result", lateUnknownResult: true},
		{name: "retirement during claimed websocket write", retireDuringWrite: true},
		{name: "route replacement during claimed websocket write", replaceRouteDuringWrite: true},
		{name: "registration waits for durable result commit", resultCASLifecycleBarrier: true},
		{name: "residency high-water writer waits for result projection", resultCASLifecycleBarrier: true, residencyWriterCASBarrier: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			barrierCase := testCase.resultCASLifecycleBarrier
			type submitCompletion struct {
				workload *domain.Workload
				admitted bool
				err      error
			}
			var barrierSubmitResult chan submitCompletion
			var barrierSubmitJoined chan struct{}
			var resultDone chan struct{}
			var registrationDone chan struct{}
			var configureDone chan error
			var configureJoined chan struct{}
			var barrierSubmitStarted, resultHandlerStarted, registrationStarted, configureStarted bool
			var cancelBarrierSubmit context.CancelFunc
			var cancelConfigure context.CancelFunc
			barrierCleanupSafe := true
			if barrierCase {
				barrierSubmitResult = make(chan submitCompletion, 1)
				barrierSubmitJoined = make(chan struct{})
				resultDone = make(chan struct{})
				registrationDone = make(chan struct{})
				configureDone = make(chan error, 1)
				configureJoined = make(chan struct{})
			}
			var server *Server
			var manager *workloads.Manager
			var cleanup func()
			var residencySnapshotStore *profileResidencySnapshotBarrierStore
			if testCase.residencyWriterCASBarrier || testCase.resultCASLifecycleBarrier {
				server, manager, residencySnapshotStore, cleanup = profileResidencyBarrierServer(t)
			} else {
				server, manager, cleanup = testServer(t)
			}
			var connection *nodeConnection
			defer func() {
				if barrierCase && !barrierCleanupSafe {
					t.Errorf("barrier worker join was uncertain; preserving isolated manager/server fixture instead of closing it")
					return
				}
				if connection != nil {
					connection.conn = nil
				}
				cleanup()
			}()
			server.commandSecret = []byte("runtime-profile-projection-test-secret")
			if testCase.resultCASConflict {
				server.workloadStore = &profileResultCASConflictStore{WorkloadStore: server.workloadStore}
			}
			var resultCASStore *profileResultCASBlockingStore
			var releaseResult func()
			if testCase.resultCASLifecycleBarrier {
				resultCASStore = &profileResultCASBlockingStore{WorkloadStore: server.workloadStore, entered: make(chan struct{}), release: make(chan struct{})}
				var releaseResultOnce sync.Once
				releaseResult = func() {
					releaseResultOnce.Do(func() { close(resultCASStore.release) })
				}
				server.workloadStore = resultCASStore
			}
			settleBarrierWorkers := func() bool {
				if !barrierCase {
					return true
				}
				if releaseResult != nil {
					releaseResult()
				}
				if residencySnapshotStore != nil {
					residencySnapshotStore.releaseSnapshot()
				}
				if cancelBarrierSubmit != nil {
					cancelBarrierSubmit()
				}
				if cancelConfigure != nil {
					cancelConfigure()
				}
				deadline := time.Now().Add(3 * time.Second)
				join := func(done <-chan struct{}, started bool) bool {
					if !started {
						return true
					}
					remaining := time.Until(deadline)
					if remaining <= 0 {
						return false
					}
					timer := time.NewTimer(remaining)
					defer timer.Stop()
					select {
					case <-done:
						return true
					case <-timer.C:
						return false
					}
				}
				resultJoined := join(resultDone, resultHandlerStarted)
				registrationJoined := join(registrationDone, registrationStarted)
				configureWorkerJoined := join(configureJoined, configureStarted)
				submitJoined := join(barrierSubmitJoined, barrierSubmitStarted)
				return resultJoined && registrationJoined && configureWorkerJoined && submitJoined
			}
			defer func() {
				if barrierCase && !barrierCleanupSafe {
					barrierCleanupSafe = settleBarrierWorkers()
					if !barrierCleanupSafe {
						t.Errorf("barrier worker did not join before cleanup deadline")
					}
				}
			}()
			manager.SetNodeStore(server.nodes)
			manager.RegisterTarget(workloads.Target{ID: "mock", Adapter: "mock", Enabled: false})
			now := time.Now().UTC()
			if _, err := server.nodes.UpsertNode(context.Background(), &domain.Node{
				ID: "node-a", SchedulingState: domain.SchedulingEnabled,
				Desired:      domain.Desired{SchedulingEnabled: true},
				Observed:     domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastSeenAt: now},
				Accelerators: []domain.Accelerator{{ID: "node-a-gpu0", NodeID: "node-a", VRAMTotalMB: 24_000, VRAMFreeMB: 24_000}},
			}); err != nil {
				t.Fatal(err)
			}
			target := workloads.Target{
				ID: "node-a-runtime", NodeID: "node-a", Adapter: "mock", Endpoint: "http://runtime", AcceleratorID: "node-a-gpu0",
				Models:            []string{"model"},
				CapabilityVersion: "runtime-v1", RuntimeIdentity: "runtime-v1", CapabilityRevision: "cap-v1", ModelFingerprint: "model-fp",
				ContextLimit: 8192, Slots: 4, ActiveRuntimeProfile: "ctx-8k", CapacitySource: "runtime:/slots", CapacityVerified: true,
				SupportsRuntimeProfileSwitch: true, RuntimeProfiles: []workloads.RuntimeCapacityProfile{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}}, Enabled: true,
			}
			manager.RegisterTarget(target)
			observation := map[string]any{"adapters": []any{map[string]any{
				"id": "runtime", "adapter": "mock", "endpoint": "http://runtime", "accelerator_index": 0,
				"version": "runtime-v1", "model_fingerprint": "model-fp", "capability_version": "runtime-v1", "capability_revision": "cap-v1",
				"context_limit": 32768, "slots": 1, "capacity_source": "runtime:/slots", "capabilities_verified": true, "active_runtime_profile": "ctx-32k",
				"runtime_profiles": []any{map[string]any{"id": "ctx-8k", "context_limit": 8192, "slots": 4}, map[string]any{"id": "ctx-32k", "context_limit": 32768, "slots": 1}},
			}}}
			if testCase.invalidObservation {
				observation = map[string]any{"profile_id": "ctx-32k"}
			}
			resultStatus := make(chan string, 1)
			delayedCommand := make(chan wsproto.CommandPayload, 1)
			lifecycleDone := make(chan struct{}, 3)
			lifecycleStarted := make(chan struct{})
			lifecycleCount := 0
			startLifecycle := func(fn func()) {
				lifecycleCount++
				go func() { fn(); lifecycleDone <- struct{}{} }()
			}
			hasLifecycle := testCase.registerBeforeResult || testCase.registerAfterResult || testCase.retireDuringWrite || testCase.replaceRouteDuringWrite
			connection = &nodeConnection{conn: &websocket.Conn{}, nodeID: "node-a", generation: 1, done: make(chan struct{})}
			connection.writeHook = func(ctx context.Context, envelope wsproto.Envelope) error {
				var command wsproto.CommandPayload
				if err := json.Unmarshal(envelope.Payload, &command); err != nil {
					return err
				}
				if command.Command != "switch_runtime_profile" {
					return nil
				}
				if testCase.resultCASLifecycleBarrier {
					delayedCommand <- command
					return nil
				}
				if hasLifecycle {
					close(lifecycleStarted)
					if testCase.registerBeforeResult {
						startLifecycle(func() { manager.RegisterTarget(target) })
					} else if testCase.retireDuringWrite {
						startLifecycle(func() { manager.ReconcileNodeTargets("node-a", map[string]struct{}{}) })
					} else if testCase.replaceRouteDuringWrite {
						startLifecycle(func() {
							replacement := target
							replacement.Endpoint = "http://replacement-route"
							manager.RegisterTarget(replacement)
						})
					}
					select {
					case <-lifecycleStarted:
					case <-time.After(time.Second):
						t.Fatal("lifecycle race did not start while websocket dispatch claim was held")
					}
					time.Sleep(20 * time.Millisecond)
				}
				completedAt := time.Now().UTC()
				if testCase.lateKnownCompletion || testCase.lateUnknownResult {
					stored, getErr := server.workloadStore.GetNodeCommand(ctx, command.ID)
					if getErr != nil {
						t.Fatal(getErr)
					}
					stored.ExpiresAt = time.Now().UTC().Add(-time.Second)
					if _, updateErr := server.workloadStore.UpdateNodeCommand(ctx, stored); updateErr != nil {
						t.Fatal(updateErr)
					}
					if testCase.lateKnownCompletion {
						completedAt = stored.ExpiresAt.Add(-time.Millisecond)
					} else {
						completedAt = stored.ExpiresAt.Add(time.Millisecond)
					}
				}
				server.handleNodeCommandResult(ctx, wsproto.CommandResultPayload{
					ID: command.ID, NodeID: "node-a", OK: true, Result: observation, CompletedAt: completedAt,
				})
				if testCase.registerAfterResult {
					observed := target
					observed.ContextLimit, observed.Slots, observed.ActiveRuntimeProfile = 32768, 1, "ctx-32k"
					startLifecycle(func() { manager.RegisterTarget(observed) })
				}
				if testCase.invalidObservation || testCase.resultCASConflict || testCase.lateUnknownResult {
					row, _ := server.workloadStore.GetNodeCommand(ctx, command.ID)
					if row != nil {
						select {
						case resultStatus <- string(row.Status):
						default:
						}
					}
				}
				return nil
			}
			server.nodeConnMu.Lock()
			server.nodeConnections["node-a"] = connection
			server.nodeConnMu.Unlock()

			request := domain.WorkloadRequest{
				ID: "profile-order", OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{}`),
				Bounds: domain.WorkloadBounds{ContextTokens: 30_000, MaxOutput: 1_000},
			}
			submitCtx := context.Background()
			submitCancel := func() {}
			if testCase.resultCASLifecycleBarrier {
				barrierSubmitCtx, cancel := context.WithCancel(context.Background())
				cancelBarrierSubmit = cancel
				barrierCleanupSafe = false
				barrierSubmitStarted = true
				go func() {
					defer close(barrierSubmitJoined)
					workload, admitted, submitErr := manager.Submit(barrierSubmitCtx, request)
					barrierSubmitResult <- submitCompletion{workload: workload, admitted: admitted, err: submitErr}
				}()
			} else {
				if testCase.resultCASConflict {
					submitCtx, submitCancel = context.WithTimeout(context.Background(), 2*time.Second)
				}
				_, _, submitErr := manager.Submit(submitCtx, request)
				submitContextErr := submitCtx.Err()
				submitCancel()
				if testCase.resultCASConflict {
					if submitErr != nil && (!errors.Is(submitErr, context.DeadlineExceeded) || submitContextErr != context.DeadlineExceeded) {
						t.Fatalf("bounded CAS-conflict submission returned before its caller deadline: err=%v context_err=%v", submitErr, submitContextErr)
					}
				} else if submitErr != nil {
					t.Fatal(submitErr)
				}
			}
			if testCase.resultCASLifecycleBarrier {
				var command wsproto.CommandPayload
				select {
				case command = <-delayedCommand:
				case <-time.After(3 * time.Second):
					t.Fatal("scheduler did not dispatch the profile command")
				}
				resultHandlerStarted = true
				go func() {
					defer close(resultDone)
					server.handleNodeCommandResult(context.Background(), wsproto.CommandResultPayload{ID: command.ID, NodeID: "node-a", OK: true, Result: observation, CompletedAt: time.Now().UTC()})
				}()
				select {
				case <-resultCASStore.entered:
				case <-time.After(time.Second):
					t.Fatal("result handler did not reach the durable success CAS barrier")
				}
				var residencyDone <-chan error
				if testCase.residencyWriterCASBarrier {
					pending := manager.Targets()
					var pendingTarget workloads.Target
					for _, candidate := range pending {
						if candidate.ID == target.ID {
							pendingTarget = candidate
							break
						}
					}
					if pendingTarget.CapacityVerified || pendingTarget.Slots != 0 || pendingTarget.CapacitySource != "runtime-profile:pending" {
						t.Fatalf("profile transition was not pending at the success CAS barrier: %+v", pendingTarget)
					}
					if _, upsertErr := server.workloadStore.UpsertModelResidency(context.Background(), &domain.ModelResidency{
						TargetID: target.ID, AcceleratorID: target.AcceleratorID, Adapter: target.Adapter, Model: "model",
						DesiredTier: domain.ResidencyColdDisk, ObservedTier: domain.ResidencyColdDisk, Policy: domain.ResidencyAuto,
						TargetGeneration: 100, UpdatedAt: time.Now().UTC(),
					}); upsertErr != nil {
						t.Fatal(upsertErr)
					}
					residencySnapshotStore.arm()
					if _, readErr := residencySnapshotStore.GetModelResidency(context.Background(), target.ID, "model"); readErr != nil {
						t.Fatalf("unrelated reader could not observe the durable snapshot: %v", readErr)
					}
					select {
					case <-residencySnapshotStore.entered:
						t.Fatal("unrelated reader consumed the ConfigureResidency snapshot barrier")
					default:
					}
					configureOwnerCtx := context.WithValue(context.Background(), profileResidencySnapshotBarrierContextKey{}, true)
					configureCtx, cancel := context.WithCancel(configureOwnerCtx)
					cancelConfigure = cancel
					configureStarted = true
					go func() {
						defer close(configureJoined)
						_, _, configureErr := manager.ConfigureResidency(configureCtx, target.ID, "model", domain.ResidencyColdDisk, "", "operator", "profile-cas-high-water")
						configureDone <- configureErr
					}()
					residencyDone = configureDone
					select {
					case <-residencySnapshotStore.entered:
					case <-time.After(time.Second):
						t.Fatal("ConfigureResidency did not capture its target/generation snapshot before the store barrier")
					}
					current := manager.Targets()
					for _, candidate := range current {
						if candidate.ID == target.ID && (candidate.CapacityVerified || candidate.Slots != 0 || candidate.CapacitySource != "runtime-profile:pending") {
							t.Fatalf("residency high-water writer changed pending capacity during success CAS: %+v", candidate)
						}
					}
				} else {
					started := make(chan struct{})
					registrationStarted = true
					go func() {
						close(started)
						defer close(registrationDone)
						replacement := target
						replacement.Endpoint = "http://replacement-during-result-cas"
						manager.RegisterTarget(replacement)
					}()
					<-started
					time.Sleep(20 * time.Millisecond)
					var current workloads.Target
					for _, candidate := range manager.Targets() {
						if candidate.ID == target.ID {
							current = candidate
							break
						}
					}
					if current.Endpoint != target.Endpoint {
						t.Fatalf("route identity changed while success CAS held the result lifecycle claim: %+v", current)
					}
				}
				releaseResult()
				select {
				case <-resultDone:
				case <-time.After(time.Second):
					t.Fatal("result CAS/projection did not finish after releasing its barrier")
				}
				if testCase.residencyWriterCASBarrier {
					residencySnapshotStore.releaseSnapshot()
					select {
					case configureErr := <-residencyDone:
						if configureErr == nil || !strings.Contains(configureErr.Error(), "target changed during durable high-water recovery") {
							t.Fatalf("writer using its preprojection snapshot did not fail closed: %v", configureErr)
						}
					case <-time.After(time.Second):
						t.Fatal("stale residency writer did not finish after releasing the snapshot barrier")
					}
					residencyDone = nil
					staleRow, readErr := server.workloadStore.GetModelResidency(context.Background(), target.ID, "model")
					if readErr != nil || staleRow.TargetGeneration != 100 || staleRow.Revision != 1 {
						t.Fatalf("stale writer changed durable high-water state: row=%+v err=%v", staleRow, readErr)
					}
					fresh, _, freshErr := manager.ConfigureResidency(context.Background(), target.ID, "model", domain.ResidencyColdDisk, "", "operator", "profile-cas-high-water-fresh")
					if freshErr != nil {
						t.Fatalf("new writer snapshot after result projection did not recover settled high-water: %v", freshErr)
					}
					settled, readErr := server.workloadStore.GetModelResidency(context.Background(), target.ID, "model")
					if readErr != nil || settled.TargetGeneration != 101 || settled.Revision != 2 || fresh.TargetGeneration != 101 {
						t.Fatalf("fresh settled writer did not advance durable generation once: result=%+v row=%+v err=%v", fresh, settled, readErr)
					}
				}
				if registrationStarted {
					select {
					case <-registrationDone:
					case <-time.After(time.Second):
						t.Fatal("registration did not resume after result lifecycle claim release")
					}
				}
				if residencyDone != nil {
					select {
					case configureErr := <-residencyDone:
						if configureErr == nil {
							t.Fatal("stale residency snapshot unexpectedly mutated after profile projection")
						}
					case <-time.After(time.Second):
						t.Fatal("residency writer did not resume after result lifecycle claim release")
					}
				}
				select {
				case completion := <-barrierSubmitResult:
					if completion.err != nil {
						t.Fatalf("asynchronous barrier Submit failed after result projection: %v", completion.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("asynchronous barrier Submit did not return after result projection")
				}
				select {
				case <-barrierSubmitJoined:
				case <-time.After(time.Second):
					t.Fatal("asynchronous barrier Submit goroutine did not join")
				}
				barrierCleanupSafe = settleBarrierWorkers()
				if !barrierCleanupSafe {
					t.Fatal("barrier workers did not settle before manager/server cleanup")
				}
			}
			deadline := time.Now().Add(3 * time.Second)
			var row *domain.Workload
			for time.Now().Before(deadline) {
				row, _ = server.workloadStore.GetWorkload(context.Background(), request.ID)
				if row != nil && row.Status != domain.WorkloadQueued && row.Status != domain.WorkloadWaiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if testCase.invalidObservation || testCase.lateUnknownResult {
				select {
				case status := <-resultStatus:
					wantStatus := domain.NodeCommandFailed
					if testCase.lateUnknownResult {
						wantStatus = domain.NodeCommandExpired
					}
					if status != string(wantStatus) {
						t.Fatalf("rejected/unknown profile result had status %q, want %s", status, wantStatus)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("profile result handler did not report command completion")
				}
				pending := manager.Targets()
				foundPending := false
				for _, current := range pending {
					if current.ID == target.ID {
						foundPending = true
						if current.CapacityVerified || current.ContextLimit != 0 || current.Slots != 0 || current.CapacitySource != "runtime-profile:pending" {
							t.Fatalf("failed result left capacity exposed: %+v", current)
						}
					}
				}
				if !foundPending {
					t.Fatal("failed result retired the runtime target unexpectedly")
				}
				if row != nil && (row.Status == domain.WorkloadRunning || row.Status == domain.WorkloadSucceeded) {
					t.Fatalf("workload was admitted after rejected/unknown profile evidence: %+v", row)
				}
				return
			}
			if testCase.resultCASConflict {
				select {
				case status := <-resultStatus:
					if status != string(domain.NodeCommandSent) {
						t.Fatalf("durable CAS conflict changed command state: %q", status)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("result handler did not reach the competing durable CAS")
				}
				current := manager.Targets()
				foundPending := false
				for _, projected := range current {
					if projected.ID == target.ID {
						foundPending = true
						if projected.CapacityVerified || projected.ContextLimit != 0 || projected.Slots != 0 || projected.CapacitySource != "runtime-profile:pending" {
							t.Fatalf("CAS-losing result published capacity: %+v", projected)
						}
					}
				}
				if !foundPending {
					t.Fatal("CAS-losing result retired the pending runtime target unexpectedly")
				}
				if row != nil && (row.Status == domain.WorkloadRunning || row.Status == domain.WorkloadSucceeded) {
					t.Fatalf("workload was admitted after durable result CAS conflict: %+v", row)
				}
				return
			}
			if row == nil || (row.Status != domain.WorkloadRunning && row.Status != domain.WorkloadSucceeded) {
				if testCase.retireDuringWrite {
					select {
					case <-lifecycleDone:
					case <-time.After(time.Second):
						t.Fatal("retirement did not resume after websocket dispatch claim release")
					}
					for _, current := range manager.Targets() {
						if current.ID == target.ID {
							t.Fatalf("retired route was republished after a correlated result: %+v", current)
						}
					}
					return
				}
				t.Fatalf("workload did not reach admission after observed projection: row=%+v", row)
			}
			if hasLifecycle {
				select {
				case <-lifecycleDone:
				case <-time.After(time.Second):
					t.Fatal("route lifecycle mutation did not resume after websocket dispatch claim release")
				}
				for _, current := range manager.Targets() {
					if current.ID == target.ID && (current.Endpoint != target.Endpoint || !current.CapacityVerified || current.ActiveRuntimeProfile != "ctx-32k") {
						t.Fatalf("stale route replacement committed over the current correlated profile result: %+v", current)
					}
				}
			}
			if row.Decision.ContextLimit != 32768 || row.Decision.TargetSlots != 1 || !row.Decision.CapacityVerified || row.Decision.CapacitySource != "runtime:/slots" {
				t.Fatalf("admission did not use the observed profile capacity: %+v", row.Decision)
			}
		})
	}
}
