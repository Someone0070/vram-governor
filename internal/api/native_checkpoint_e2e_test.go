package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/domain"
	"vram-governor/internal/nodeagent"
	checkpointRuntime "vram-governor/internal/runtime"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
	"vram-governor/internal/wsproto"
)

const nativeCheckpointSecret = "native-e2e-command-signing-secret-32-bytes"

type nativeLlamaBackend struct {
	root                 string
	blockResumed         bool
	completeInitial      bool
	repeatResumed        bool
	omitDoneResumed      bool
	duplicateDoneResumed bool
	postDoneResumed      bool
	toolEventResumed     bool
	mu                   sync.Mutex
	slotProcessing       bool
	streams              map[string]*nativeBackendStream
	history              map[string][]byte
	requests             []nativeBackendRequest
	snapshotSaved        bool
	snapshotRestored     bool
	cancelCount          int
	deleteCount          int
	prefixOnce           sync.Once
	resumedOnce          sync.Once
	prefixSent           chan struct{}
	resumedStarted       chan struct{}
	resumedFinished      chan struct{}
}

type nativeBackendStream struct {
	stop     chan struct{}
	stopOnce sync.Once
}

type nativeBackendRequest struct {
	Body         map[string]any
	Conversation string
	Stream       bool
	Resumed      bool
}

func newNativeLlamaBackend(root string, blockResumed bool) *nativeLlamaBackend {
	return &nativeLlamaBackend{
		root: root, blockResumed: blockResumed, repeatResumed: true,
		streams: make(map[string]*nativeBackendStream), history: make(map[string][]byte),
		prefixSent: make(chan struct{}), resumedStarted: make(chan struct{}), resumedFinished: make(chan struct{}),
	}
}

func (b *nativeLlamaBackend) streamLine(id, content string, cached int, resumed bool) []byte {
	line := nativeSSE(id, content, cached)
	b.mu.Lock()
	omitDone := resumed && b.omitDoneResumed
	duplicateDone := resumed && b.duplicateDoneResumed
	postDone := resumed && b.postDoneResumed
	toolEvent := resumed && b.toolEventResumed
	b.mu.Unlock()
	if toolEvent {
		tool, _ := json.Marshal(map[string]any{"id": id, "choices": []map[string]any{{"delta": map[string]any{"tool_calls": []map[string]any{{"index": 0, "id": "tool-1", "type": "function"}}}}}})
		toolLine := []byte(fmt.Sprintf("data: %s\n\n", tool))
		done := []byte("data: [DONE]\n\n")
		if at := bytes.Index(line, done); at >= 0 {
			line = append(append(append([]byte(nil), line[:at]...), toolLine...), line[at:]...)
		}
	}
	if omitDone {
		line = bytes.Replace(line, []byte("data: [DONE]\n\n"), nil, 1)
	}
	if duplicateDone {
		line = append(line, []byte("data: [DONE]\n\n")...)
	}
	if postDone {
		line = append(line, []byte("data: {\"choices\":[{\"delta\":{\"content\":\"POST_DONE\"}}]}\n\n")...)
	}
	return line
}

func (b *nativeLlamaBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/slots":
		b.mu.Lock()
		processing := b.slotProcessing
		b.mu.Unlock()
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 0, "n_ctx": 4096, "is_processing": processing, "n_prompt_tokens": 7, "n_prompt_tokens_cached": 3, "n_past": 7}})
	case r.Method == http.MethodPost && r.URL.Path == "/slots/0":
		b.handleSlotAction(w, r)
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/stream":
		b.handleStreamDelete(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/stream":
		b.handleStreamHistory(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "model", "status": "loaded"}}})
	case r.Method == http.MethodGet && r.URL.Path == "/props":
		_ = json.NewEncoder(w).Encode(map[string]any{"default_n_ctx": 4096})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		b.handleCompletion(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (b *nativeLlamaBackend) handleSlotAction(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("action") {
	case "save":
		var body struct {
			Filename string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Filename == "" || filepath.Base(body.Filename) != body.Filename {
			http.Error(w, "bad save", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(filepath.Join(b.root, body.Filename), []byte("native-kv-snapshot"), 0o600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b.mu.Lock()
		b.snapshotSaved = true
		b.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"filename": body.Filename, "n_saved": 7, "n_written": 7})
	case "restore":
		var body struct {
			Filename string `json:"filename"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, err := os.Stat(filepath.Join(b.root, body.Filename)); err != nil {
			http.Error(w, "snapshot missing", http.StatusNotFound)
			return
		}
		b.mu.Lock()
		b.snapshotRestored = true
		b.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"n_restored": 7})
	default:
		http.Error(w, "unsupported slot action", http.StatusBadRequest)
	}
}

func (b *nativeLlamaBackend) handleStreamDelete(w http.ResponseWriter, r *http.Request) {
	conversation := r.URL.Query().Get("conv_id")
	b.mu.Lock()
	stream := b.streams[conversation]
	b.slotProcessing = false
	b.cancelCount++
	b.deleteCount++
	b.mu.Unlock()
	if stream != nil {
		stream.stopOnce.Do(func() { close(stream.stop) })
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"stopped":true}`)
}

func (b *nativeLlamaBackend) handleStreamHistory(w http.ResponseWriter, r *http.Request) {
	conversation := r.URL.Query().Get("conv_id")
	b.mu.Lock()
	history := append([]byte(nil), b.history[conversation]...)
	b.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	if len(history) == 0 {
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		return
	}
	_, _ = w.Write(history)
}

func nativeSSE(id, content string, cached int) []byte {
	event, _ := json.Marshal(map[string]any{"id": id, "choices": []map[string]any{{"delta": map[string]string{"content": content}}}})
	usage, _ := json.Marshal(map[string]any{"id": id, "choices": []any{}, "usage": map[string]any{"prompt_tokens": 7, "completion_tokens": 1, "total_tokens": 8, "prompt_tokens_cached": cached}})
	return []byte(fmt.Sprintf("data: %s\n\ndata: %s\n\ndata: [DONE]\n\n", event, usage))
}

func (b *nativeLlamaBackend) handleCompletion(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	stream, _ := body["stream"].(bool)
	resumed, _ := body["continue_final_message"].(bool)
	conversation := r.Header.Get("X-Conversation-Id")
	b.mu.Lock()
	b.requests = append(b.requests, nativeBackendRequest{Body: body, Conversation: conversation, Stream: stream, Resumed: resumed})
	b.mu.Unlock()
	if !stream {
		b.mu.Lock()
		b.slotProcessing = true
		b.mu.Unlock()
		defer func() { b.mu.Lock(); b.slotProcessing = false; b.mu.Unlock() }()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "urgent-completion", "choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": "URGENT_DONE"}}}, "usage": map[string]any{"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}})
		return
	}

	b.mu.Lock()
	b.slotProcessing = true
	backendStream := &nativeBackendStream{stop: make(chan struct{})}
	if conversation == "" {
		conversation = "missing-conversation"
	}
	b.streams[conversation] = backendStream
	b.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	if resumed {
		b.mu.Lock()
		repeatResumed := b.repeatResumed
		b.mu.Unlock()
		content := "VICTIM_SUFFIX"
		if repeatResumed {
			content = "VICTIM_PREFIX" + content
		}
		line := b.streamLine("resumed-completion", content, 3, true)
		b.mu.Lock()
		b.history[conversation] = append([]byte(nil), line...)
		b.mu.Unlock()
		_, _ = w.Write(line)
		if flusher != nil {
			flusher.Flush()
		}
		// Signal only after the repeated-prefix event is committed to backend
		// history. A disconnect test can then exercise signed cancel/release
		// without racing the node's history boundary and manufacturing an
		// empty-prefix cancellation failure.
		b.resumedOnce.Do(func() { close(b.resumedStarted) })
		if b.blockResumed {
			select {
			case <-backendStream.stop:
			case <-r.Context().Done():
			}
		} else {
			b.mu.Lock()
			b.slotProcessing = false
			b.mu.Unlock()
		}
		return
	}

	line := b.streamLine("victim-completion", "VICTIM_PREFIX", 0, false)
	b.mu.Lock()
	b.history[conversation] = append([]byte(nil), line...)
	b.mu.Unlock()
	// Emit only the first event at the victim boundary; the remainder is
	// intentionally committed to history and delivered by the resumed call.
	parts := bytes.Split(line, []byte("\n\ndata:"))
	prefix := parts[0]
	if len(parts) > 0 {
		prefix = append(append([]byte(nil), parts[0]...), '\n', '\n')
	}
	_, _ = w.Write(prefix)
	if flusher != nil {
		flusher.Flush()
	}
	b.prefixOnce.Do(func() { close(b.prefixSent) })
	b.mu.Lock()
	completeInitial := b.completeInitial
	b.mu.Unlock()
	if completeInitial {
		// Normal completion emits the remaining history and EOF without a
		// controller-side cancel. This keeps the native lifecycle test distinct
		// from preemption, while the same backend slot remains reusable.
		remainder := line[len(prefix):]
		_, _ = w.Write(remainder)
		if flusher != nil {
			flusher.Flush()
		}
		b.mu.Lock()
		b.slotProcessing = false
		b.mu.Unlock()
		return
	}
	select {
	case <-backendStream.stop:
		b.mu.Lock()
		b.slotProcessing = false
		b.mu.Unlock()
		<-r.Context().Done()
	case <-r.Context().Done():
		b.mu.Lock()
		b.slotProcessing = false
		b.mu.Unlock()
	}
}

func (b *nativeLlamaBackend) requestsSnapshot() []nativeBackendRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]nativeBackendRequest, len(b.requests))
	for i, req := range b.requests {
		out[i] = nativeBackendRequest{Conversation: req.Conversation, Stream: req.Stream, Resumed: req.Resumed, Body: make(map[string]any, len(req.Body))}
		for key, value := range req.Body {
			out[i].Body[key] = value
		}
	}
	return out
}

type nativeCheckpointFixture struct {
	root        string
	backing     *store.MemoryStore
	manager     *workloads.Manager
	adapter     *workloads.HTTPAdapter
	server      *Server
	gateway     *httptest.Server
	backend     *nativeLlamaBackend
	backendHTTP *httptest.Server
	nodeDone    chan error
	registered  chan struct{}
	cancel      context.CancelFunc
	// prefixRelayed closes once the public client has received the victim's
	// first content. Preempting earlier races the controller's own read of
	// the prefix: the backend has flushed it, but under load the gateway may
	// not have parsed it, and the node then rejects the boundary as empty.
	prefixRelayed chan struct{}
	relayOnce     sync.Once
}

// readPublicStream copies a public response body, closing the fixture's
// prefixRelayed signal when the victim prefix reaches the client.
func (fixture *nativeCheckpointFixture) readPublicStream(body io.Reader) []byte {
	var data []byte
	buf := make([]byte, 4096)
	for {
		n, err := body.Read(buf)
		data = append(data, buf[:n]...)
		if bytes.Contains(data, []byte("VICTIM_PREFIX")) {
			fixture.relayOnce.Do(func() { close(fixture.prefixRelayed) })
		}
		if err != nil {
			return data
		}
	}
}

func (fixture *nativeCheckpointFixture) waitPrefixRelayed(t *testing.T) {
	t.Helper()
	select {
	case <-fixture.prefixRelayed:
	case <-time.After(10 * time.Second):
		t.Fatal("victim prefix did not reach the public client")
	}
}

func nativeCheckpointProof(nodeID, targetID string) checkpointRuntime.CheckpointCapabilityProof {
	now := time.Now().UTC()
	nonceSeed := sha256.Sum256([]byte("native-proof-nonce"))
	proof := checkpointRuntime.CheckpointCapabilityProof{
		ProofVersion: checkpointRuntime.CheckpointCapabilityProofVersion, ModelAlias: "model", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true,
		BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true,
		ProvenAt: now, ExpiresAt: now.Add(2 * time.Hour), NodeID: nodeID, TargetID: targetID,
		AcceleratorID: nodeID + "-gpu0", ModelFingerprint: "model-fp", RuntimeIdentity: "runtime-v1",
		ProfileFingerprint: "profile-fp", ContextLimit: 4096, SlotID: 0, Generation: 1,
		OldFence: 1, NewFence: 2, SavedTokens: 7, ReusedTokens: 3, SnapshotBytes: 16,
		SnapshotDigest: "sha256:native-proof-snapshot", EvidenceID: "native-proof-evidence",
		Nonce: fmt.Sprintf("%020d-e%020d-%x", now.UnixNano(), uint64(1), nonceSeed[:16]),
	}
	proof.Digest = checkpointRuntime.CheckpointProofDigest(proof)
	mac := hmac.New(sha256.New, []byte(nativeCheckpointSecret))
	_, _ = mac.Write([]byte(proof.Digest))
	proof.Signature = hex.EncodeToString(mac.Sum(nil))
	return proof
}

func newNativeCheckpointFixture(t *testing.T, blockResumed bool) *nativeCheckpointFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	backend := newNativeLlamaBackend(root, blockResumed)
	backendHTTP := httptest.NewServer(backend)
	backing := store.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := workloads.NewManager(logger, backing, time.Second)
	adapter := workloads.NewHTTPAdapter("llamacpp", "llama", backendHTTP.Client())
	snapshotStore, err := workloads.NewSnapshotStore(root, 1<<20, 32)
	if err != nil {
		t.Fatal(err)
	}
	proof := nativeCheckpointProof("native-node", "native-node-runtime")
	coordinator := workloads.NewCheckpointCoordinator(nil, snapshotStore, proof)
	coordinator.Operations = backing
	adapter.SetLLMCheckpointCoordinator(coordinator)
	manager.RegisterAdapter(adapter)
	manager.SetNodeStore(backing)
	ctx, cancel := context.WithCancel(context.Background())

	cfg := &Config{}
	cfg.Auth.CommandSigningSecret = nativeCheckpointSecret
	cfg.Auth.Credentials = []CredentialConfig{
		{ID: "victim", Token: "victim-token", OwnerID: "victim-owner", Plane: "ui", Scopes: []string{"inference:submit", "workloads:read", "workloads:cancel"}, Adapters: []string{"llamacpp"}, MaxPriority: 10, PreemptionBudget: 1, EgressPolicy: "local_only"},
		{ID: "urgent", Token: "urgent-token", OwnerID: "urgent-owner", Plane: "ui", Scopes: []string{"workloads:submit", "workloads:read"}, Adapters: []string{"llamacpp"}, MaxPriority: 100, PreemptionBudget: 1, EgressPolicy: "local_only"},
		{ID: "native-node", Token: "native-node-token", OwnerID: "system", Plane: "node", NodeID: "native-node", Scopes: []string{"node:connect", "node:report"}, Adapters: []string{"llamacpp"}},
	}
	cfg.Workloads.Checkpoint = CheckpointConfig{Enabled: true, Root: root, MaxBytes: 1 << 20, MaxFiles: 32, PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 8, MaxMetadataBytes: 1 << 16, MaxOutputBytes: 1 << 16, ExpirySeconds: 3600, LockStaleSeconds: 60, ProofJournalRetentionSeconds: 3600}
	server := NewServer(cfg, logger, backing, nil, nil)
	server.SetWorkloadManager(manager)
	manager.Start(ctx)
	gateway := httptest.NewServer(server.Handler())

	nodeRoot := filepath.Join(root, "node")
	if err := os.MkdirAll(nodeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	nodeCfg := &nodeagent.Config{
		ControllerURL: "ws" + strings.TrimPrefix(gateway.URL, "http") + "/ws/node", Token: "native-node-token", NodeID: "native-node", NodeName: "native node", AgentVersion: nodeagent.AgentVersion,
		CapabilityVersion: domain.CapabilityContractVersion, CommandSigningSecret: nativeCheckpointSecret, CommandStatePath: filepath.Join(nodeRoot, "command-state.json"),
		Checkpoint: nodeagent.CheckpointConfig{Enabled: true, Root: root, MaxBytes: 1 << 20, MaxFiles: 32, PerOwnerMaxBytes: 1 << 20, PerOwnerMaxFiles: 8, MaxMetadataBytes: 1 << 16, MaxOutputBytes: 1 << 16, ExpirySeconds: 3600, CleanupIntervalSeconds: 60, ProofPath: filepath.Join(nodeRoot, "proof.json")},
	}
	nodeCfg.LlamaCPP.Servers = []nodeagent.LlamaCPPServerConfig{{ID: "runtime", Endpoint: backendHTTP.URL, AcceleratorIndex: 0, ContextLimit: 4096, Slots: 1, ModelFingerprints: map[string]string{"model": "model-fp"}, RuntimeFingerprints: map[string]string{"runtime-v1": "runtime-v1"}, RuntimeProfiles: []nodeagent.RuntimeProfileConfig{{ID: "profile-fp", ContextLimit: 4096, Slots: 1}}}}
	commandHandler := nodeagent.NewCommandHandler(nodeCfg, logger)
	registered := make(chan struct{})
	nodeDone := make(chan error, 1)
	nodeCtx, nodeCancel := context.WithCancel(ctx)
	go func() {
		defer nodeCancel()
		conn, _, dialErr := websocket.Dial(nodeCtx, nodeCfg.ControllerURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer native-node-token"}}})
		if dialErr != nil {
			nodeDone <- dialErr
			return
		}
		defer conn.CloseNow()
		ready := true
		proof := nativeCheckpointProof("native-node", "native-node-runtime")
		register := wsproto.RegisterPayload{NodeID: "native-node", NodeName: "native node", Ready: &ready, AgentVersion: nodeagent.AgentVersion, CapabilityVersion: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsSessionCheckpoint: true, SessionCheckpointVerified: true, SessionCheckpointProof: proof.Digest, MaxAcceleratorsPerWorkload: 1}, Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, MaxAcceleratorsPerWorkload: 1, Adapters: []wsproto.AdapterAdvertisement{{ID: "runtime", Adapter: "llamacpp", Endpoint: backendHTTP.URL, AcceleratorIndex: 0, Models: []string{"model"}, ResidentModels: []string{"model"}, Version: "runtime-v1", ModelFingerprint: "model-fp", ContextLimit: 4096, Slots: 1, CapacitySource: "runtime:/slots", Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, CapabilitiesVerified: true, CapabilityVersion: domain.CapabilityContractVersion, CapabilityRevision: domain.CapabilityContractVersion, CapabilityGeneration: 1, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsSessionCheckpoint: true, SessionCheckpointVerified: true, SessionCheckpointProof: proof.Digest, MaxAcceleratorsPerWorkload: 1}, ActiveRuntimeProfile: "profile-fp", RuntimeProfiles: []wsproto.RuntimeProfileAdvertisement{{ID: "profile-fp", ContextLimit: 4096, Slots: 1}}, MaxAcceleratorsPerWorkload: 1, CheckpointProof: proof, ModelCapacityObservations: []wsproto.ModelCapacityObservationAdvertisement{{AcceleratorID: "native-node-gpu0", Model: "model", ProfileID: "profile-fp", ModelFingerprint: "model-fp", RuntimeIdentity: "native-node-runtime|llamacpp||runtime-v1|model-fp", CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelBytes: 128 << 20, ProfileBytes: 64 << 20, VRAMTotalBytes: 16 << 30, Source: "runtime:/api/ps:size_vram", Verified: true, ObservedAt: time.Now().UTC()}}}}}
		if err := wsjson.Write(nodeCtx, conn, wsproto.Envelope{Type: wsproto.MsgRegister, Time: time.Now().UTC(), Payload: mustJSON(register)}); err != nil {
			nodeDone <- err
			return
		}
		var ack wsproto.Envelope
		if err := wsjson.Read(nodeCtx, conn, &ack); err != nil {
			nodeDone <- err
			return
		}
		if ack.Type != wsproto.MsgAck {
			nodeDone <- fmt.Errorf("node registration ack type %q", ack.Type)
			return
		}
		_ = wsjson.Write(nodeCtx, conn, wsproto.Envelope{Type: wsproto.MsgHeartbeat, Time: time.Now().UTC(), Payload: mustJSON(wsproto.HeartbeatPayload{NodeID: "native-node", Ready: true})})
		_ = wsjson.Write(nodeCtx, conn, wsproto.Envelope{Type: wsproto.MsgTelemetry, Time: time.Now().UTC(), Payload: mustJSON(wsproto.TelemetryPayload{NodeID: "native-node", Accelerators: []wsproto.AcceleratorTelemetry{{Index: 0, Name: "native-test-gpu", Vendor: "nvidia", VRAMTotalMB: 16384, VRAMFreeMB: 16384}}})})
		close(registered)
		for {
			var env wsproto.Envelope
			if err := wsjson.Read(nodeCtx, conn, &env); err != nil {
				nodeDone <- err
				return
			}
			if env.Type != wsproto.MsgCommand {
				continue
			}
			var command wsproto.CommandPayload
			if err := json.Unmarshal(env.Payload, &command); err != nil {
				continue
			}
			result := commandHandler.Handle(nodeCtx, command)
			if result.CompletedAt.IsZero() {
				result.CompletedAt = time.Now().UTC()
			}
			if err := wsjson.Write(nodeCtx, conn, wsproto.Envelope{Type: wsproto.MsgCommandResult, Time: time.Now().UTC(), Payload: mustJSON(result)}); err != nil {
				nodeDone <- err
				return
			}
		}
	}()
	fixture := &nativeCheckpointFixture{root: root, backing: backing, manager: manager, adapter: adapter, server: server, gateway: gateway, backend: backend, backendHTTP: backendHTTP, nodeDone: nodeDone, registered: registered, prefixRelayed: make(chan struct{}), cancel: func() {
		cancel()
		nodeCancel()
		manager.Close()
		server.Close()
		gateway.Close()
		backendHTTP.Close()
	}}
	t.Cleanup(fixture.cancel)
	select {
	case <-registered:
	case err := <-nodeDone:
		t.Fatalf("native node failed to register: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("native node registration timed out")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		nodes, _ := backing.ListNodes(ctx)
		if len(nodes) == 1 && len(nodes[0].Accelerators) == 1 && len(manager.Targets()) == 1 && manager.Targets()[0].ID == "native-node-runtime" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native target/accelerator registration timed out: nodes=%+v targets=%+v", nodes, manager.Targets())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fixture
}

func nativeVictimBody() map[string]any {
	return map[string]any{
		"model":      "model",
		"messages":   []map[string]string{{"role": "user", "content": "native checkpoint victim"}},
		"stream":     true,
		"max_tokens": 16,
		"governor": map[string]any{
			"adapter": "llamacpp",
			// Admission adds max_tokens to context_tokens.  Keep the exact
			// total at the native 4096-token target limit.
			"context_tokens":       4080,
			"checkpointable":       true,
			"interruption_consent": true,
			"recoverable":          true,
			"preemption_budget":    1,
			"queue_policy":         "wait",
		},
	}
}

func nativeUrgentRequest() map[string]any {
	return map[string]any{
		"adapter":           "llamacpp",
		"workload_type":     "native.urgent",
		"item_id":           "native-urgent",
		"payload":           map[string]any{"model": "model", "messages": []map[string]string{{"role": "user", "content": "urgent"}}, "stream": false, "max_tokens": 4},
		"qos":               "interactive",
		"queue_policy":      "wait",
		"disruption":        "locked",
		"priority":          90,
		"recoverable":       true,
		"preemption_budget": 1,
	}
}

func nativeStartPublicStream(t *testing.T, fixture *nativeCheckpointFixture, body map[string]any) (*http.Response, chan []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, fixture.gateway.URL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer victim-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := fixture.gateway.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		for _, row := range rows {
			t.Logf("victim row status=%s decision=%+v plan=%+v execution=%+v error=%q", row.Status, row.Decision, row.Plan, row.Execution, row.Error)
		}
		t.Logf("victim admission/runtime targets=%+v", fixture.manager.Targets())
		t.Fatalf("victim stream status=%d body=%s", resp.StatusCode, bodyBytes)
	}
	chunks := make(chan []byte, 1)
	go func() {
		data := fixture.readPublicStream(resp.Body)
		resp.Body.Close()
		chunks <- data
	}()
	return resp, chunks
}

func nativeSubmitUrgent(t *testing.T, fixture *nativeCheckpointFixture) *domain.Workload {
	t.Helper()
	payload, err := json.Marshal(nativeUrgentRequest())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, fixture.gateway.URL+"/api/v1/workloads", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer urgent-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := fixture.gateway.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("urgent submit status=%d body=%s", resp.StatusCode, body)
	}
	var row domain.Workload
	if err := json.NewDecoder(resp.Body).Decode(&row); err != nil {
		t.Fatal(err)
	}
	return &row
}

func nativeWaitFor(t *testing.T, timeout time.Duration, name string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", name)
}

// nativeRunCheckpointedResumedStream drives the same preemption path as the
// primary checkpoint E2E.  The backend protocol fault is enabled only after
// the initial prefix is live, so the body returned to the public client has
// to pass through checkpoint save, restore, continuation, and reuse before
// the fault is observed.
func nativeRunCheckpointedResumedStream(t *testing.T, fixture *nativeCheckpointFixture, configure func(*nativeLlamaBackend)) []byte {
	t.Helper()
	_, body := nativeStartPublicStream(t, fixture, nativeVictimBody())
	select {
	case <-fixture.backend.prefixSent:
	case <-time.After(10 * time.Second):
		t.Fatal("victim did not emit the preemption prefix")
	}
	fixture.waitPrefixRelayed(t)
	nativeWaitFor(t, 10*time.Second, "checkpointed victim running execution", func() bool {
		rows, err := fixture.backing.ListWorkloads(context.Background())
		if err != nil {
			return false
		}
		for _, row := range rows {
			if row.Request.OwnerID == "victim-owner" && row.Status == domain.WorkloadRunning && row.Execution != nil {
				return true
			}
		}
		return false
	})
	fixture.backend.mu.Lock()
	fixture.backend.repeatResumed = true
	configure(fixture.backend)
	fixture.backend.mu.Unlock()
	urgent := nativeSubmitUrgent(t, fixture)
	urgentCtx, urgentCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer urgentCancel()
	urgentDone, err := fixture.manager.Wait(urgentCtx, urgent.Request.ID)
	if err != nil || urgentDone == nil || urgentDone.Status != domain.WorkloadSucceeded {
		t.Fatalf("urgent preemption did not free the checkpointed slot: row=%+v err=%v", urgentDone, err)
	}
	var response []byte
	select {
	case response = <-body:
	case <-time.After(15 * time.Second):
		t.Fatal("checkpointed resumed public stream did not terminate")
	}
	fixture.backend.mu.Lock()
	saved, restored := fixture.backend.snapshotSaved, fixture.backend.snapshotRestored
	fixture.backend.mu.Unlock()
	if !saved || !restored {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		var states []string
		for _, row := range rows {
			states = append(states, fmt.Sprintf("%s %s err=%q blocker=%q", row.Request.OwnerID, row.Status, row.Error, row.Decision.Blocker))
		}
		ops, _ := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
		t.Fatalf("public stream did not use checkpoint save/restore: saved=%v restored=%v response=%q workloads=%v operations=%d", saved, restored, response, states, len(ops))
	}
	requests := fixture.backend.requestsSnapshot()
	var initial, resumed *nativeBackendRequest
	for index := range requests {
		request := &requests[index]
		if request.Stream && request.Resumed {
			resumed = request
		} else if request.Stream {
			initial = request
		}
	}
	if initial == nil || resumed == nil {
		t.Fatalf("public stream did not include initial and resumed backend requests: %+v RESPONSE=%q", requests, response)
	}
	if resumed.Body["cache_prompt"] != true || resumed.Body["continue_final_message"] != true {
		t.Fatalf("resumed backend request omitted continuation controls: %+v", resumed.Body)
	}
	messages, ok := resumed.Body["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("resumed backend request omitted saved assistant prefix: %+v", resumed.Body["messages"])
	}
	assistant, ok := messages[len(messages)-1].(map[string]any)
	if !ok || assistant["role"] != "assistant" || assistant["content"] != "VICTIM_PREFIX" {
		t.Fatalf("resumed backend request did not repeat the saved prefix: %+v", messages)
	}
	return response
}

func TestHTTPAdapterNodeCommandCheckpointContinuationE2E(t *testing.T) {
	fixture := newNativeCheckpointFixture(t, false)
	_, victimBody := nativeStartPublicStream(t, fixture, nativeVictimBody())
	select {
	case <-fixture.backend.prefixSent:
	case <-time.After(10 * time.Second):
		t.Fatal("victim did not emit the preemption prefix")
	}
	fixture.waitPrefixRelayed(t)
	nativeWaitFor(t, 10*time.Second, "victim running execution", func() bool {
		rows, err := fixture.backing.ListWorkloads(context.Background())
		if err != nil {
			return false
		}
		for _, row := range rows {
			if row.Request.OwnerID == "victim-owner" && row.Status == domain.WorkloadRunning && row.Execution != nil {
				return true
			}
		}
		return false
	})
	urgent := nativeSubmitUrgent(t, fixture)
	urgentCtx, urgentCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer urgentCancel()
	urgentDone, err := fixture.manager.Wait(urgentCtx, urgent.Request.ID)
	if err != nil {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		transitions, _ := fixture.backing.ListTransitionPlans(context.Background(), urgent.Request.ID, 100)
		commands, _ := fixture.backing.ListNodeCommands(context.Background(), "native-node", 0)
		operations, _ := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
		for _, row := range rows {
			t.Logf("timeout workload status=%s owner=%s priority=%d qos=%s budget=%d consent=%v recoverable=%v disruption=%s preemptions=%d decision=%+v error=%q execution=%+v", row.Status, row.Request.OwnerID, row.Request.Priority, row.Request.QoS, row.Request.PreemptionBudget, row.Request.InterruptionConsent, row.Request.Recoverable, row.Request.Disruption, row.PreemptionCount, row.Decision, row.Error, row.Execution)
		}
		for _, transition := range transitions {
			t.Logf("timeout transition id=%s workload=%s victim=%s status=%s error=%q steps=%+v", transition.ID, transition.WorkloadID, transition.VictimWorkloadID, transition.Status, transition.Error, transition.Steps)
		}
		for _, command := range commands {
			t.Logf("timeout command id=%s name=%s status=%s err=%q args=%+v", command.ID, command.Command, command.Status, command.Error, command.Args)
		}
		fixture.backend.mu.Lock()
		deleteCount, slotProcessing := fixture.backend.deleteCount, fixture.backend.slotProcessing
		fixture.backend.mu.Unlock()
		t.Logf("timeout capability=%+v backend delete_count=%d slot_processing=%v", fixture.adapter.DisruptionCapabilitiesForTarget(fixture.manager.Targets()[0]), deleteCount, slotProcessing)
		for _, operation := range operations {
			t.Logf("timeout operation id=%s key=%s gen=%d fence=%d runtime=%s model=%s profile=%s ctx=%s conv=%s continuation=%s phase=%s err=%q", operation.ID, operation.IdempotencyKey, operation.Generation, operation.Fence, operation.RuntimeIdentity, operation.ModelFingerprint, operation.ProfileFingerprint, operation.ContextFingerprint, operation.ConversationID, operation.ContinuationConversationID, operation.Phase, operation.Error)
		}
		t.Fatalf("urgent wait: %v", err)
	}
	if urgentDone.Status != domain.WorkloadSucceeded {
		t.Fatalf("urgent status=%s error=%q decision=%+v", urgentDone.Status, urgentDone.Error, urgentDone.Decision)
	}
	var victimBytes []byte
	select {
	case victimBytes = <-victimBody:
	case <-time.After(15 * time.Second):
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		transitions, _ := fixture.backing.ListTransitionPlans(context.Background(), "", 100)
		commands, _ := fixture.backing.ListNodeCommands(context.Background(), "native-node", 0)
		operations, _ := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
		for _, row := range rows {
			t.Logf("victim timeout row status=%s owner=%s checkpoint=%q decision=%+v error=%q execution=%+v", row.Status, row.Request.OwnerID, row.CheckpointRef, row.Decision, row.Error, row.Execution)
		}
		for _, transition := range transitions {
			t.Logf("victim timeout transition id=%s workload=%s victim=%s status=%s error=%q", transition.ID, transition.WorkloadID, transition.VictimWorkloadID, transition.Status, transition.Error)
		}
		for _, command := range commands {
			t.Logf("victim timeout command name=%s status=%s err=%q args=%+v", command.Command, command.Status, command.Error, command.Args)
		}
		for _, operation := range operations {
			t.Logf("victim timeout operation id=%s key=%s phase=%s err=%q", operation.ID, operation.IdempotencyKey, operation.Phase, operation.Error)
		}
		fixture.backend.mu.Lock()
		t.Logf("victim timeout backend requests=%+v slot=%v deletes=%d", fixture.backend.requests, fixture.backend.slotProcessing, fixture.backend.deleteCount)
		fixture.backend.mu.Unlock()
		t.Fatal("victim response did not resume and complete")
	}
	response := string(victimBytes)
	if got := strings.Count(response, "VICTIM_PREFIX"); got != 1 {
		t.Fatalf("victim prefix count=%d response=%q", got, response)
	}
	if got := strings.Count(response, "VICTIM_SUFFIX"); got != 1 {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		commands, _ := fixture.backing.ListNodeCommands(context.Background(), "native-node", 0)
		operations, _ := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
		for _, row := range rows {
			t.Logf("suffix failure row status=%s checkpoint=%q error=%q decision=%+v execution=%+v", row.Status, row.CheckpointRef, row.Error, row.Decision, row.Execution)
		}
		for _, command := range commands {
			t.Logf("suffix failure command name=%s status=%s err=%q args=%+v", command.Command, command.Status, command.Error, command.Args)
		}
		for _, operation := range operations {
			t.Logf("suffix failure operation id=%s phase=%s err=%q conv=%s cont=%s", operation.ID, operation.Phase, operation.Error, operation.ConversationID, operation.ContinuationConversationID)
		}
		t.Logf("suffix failure backend requests=%+v", fixture.backend.requestsSnapshot())
		t.Fatalf("victim suffix count=%d response=%q", got, response)
	}
	if got := strings.Count(response, "[DONE]"); got != 1 {
		t.Fatalf("victim done count=%d response=%q", got, response)
	}
	requests := fixture.backend.requestsSnapshot()
	if len(requests) < 3 {
		t.Fatalf("expected initial, urgent, and resumed backend requests, got %d: %+v", len(requests), requests)
	}
	var initial, resumed, urgentBackend *nativeBackendRequest
	for i := range requests {
		request := &requests[i]
		if request.Resumed {
			resumed = request
		} else if !request.Stream {
			urgentBackend = request
		} else {
			initial = request
		}
		if _, present := request.Body["governor"]; present {
			t.Fatalf("backend request leaked governor fields: %+v", request.Body)
		}
	}
	if initial == nil || resumed == nil || urgentBackend == nil {
		t.Fatalf("missing backend request roles: %+v", requests)
	}
	if resumed.Conversation == "" || resumed.Conversation == initial.Conversation || !strings.HasPrefix(resumed.Conversation, "continuation-") || resumed.Body["cache_prompt"] != true || resumed.Body["continue_final_message"] != true {
		t.Fatalf("resumed request did not bind a fresh continuation/cache conversation: initial=%+v resumed=%+v", initial, resumed)
	}
	messages, ok := resumed.Body["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("resumed request omitted stitched assistant prefix: %+v", resumed.Body["messages"])
	}
	if fixture.backend.snapshotSaved == false || fixture.backend.snapshotRestored == false || fixture.backend.cancelCount == 0 {
		t.Fatalf("backend lifecycle evidence incomplete: saved=%v restored=%v cancels=%d", fixture.backend.snapshotSaved, fixture.backend.snapshotRestored, fixture.backend.cancelCount)
	}
	commands, err := fixture.backing.ListNodeCommands(context.Background(), "native-node", 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, command := range commands {
		if command == nil || command.Status != domain.NodeCommandSucceeded {
			t.Fatalf("node command did not terminalize: %+v", command)
		}
		wire := nodeCommandPayload(command)
		if !wsproto.VerifyCommand(wire, []byte(nativeCheckpointSecret)) {
			t.Fatalf("node command signature failed: %+v", command)
		}
		seen[command.Command] = true
	}
	for _, required := range []string{"checkpoint_slot_assign", "checkpoint_start", "checkpoint_pause", "checkpoint_save", "checkpoint_stop_confirm", "checkpoint_release", "checkpoint_reload", "checkpoint_restore", "checkpoint_resume", "checkpoint_continue", "checkpoint_reuse_verify"} {
		if !seen[required] {
			t.Fatalf("missing signed durable command %q in %+v", required, commands)
		}
	}
	operations, err := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
	if err != nil {
		t.Fatal(err)
	}
	nativeWaitFor(t, 5*time.Second, "checkpoint operations terminal", func() bool {
		rows, listErr := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
		if listErr != nil || len(rows) == 0 {
			return false
		}
		for _, row := range rows {
			if row == nil || row.Phase != "completed" {
				return false
			}
		}
		return true
	})
	operations, err = fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) == 0 {
		t.Fatal("no durable checkpoint operation was persisted")
	}
	for _, operation := range operations {
		if operation.Phase != "completed" {
			t.Fatalf("checkpoint operation did not terminalize completed: %+v", operation)
		}
	}
	if _, err := os.Stat(filepath.Join(fixture.root, ".owner-victim-owner.manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("checkpoint owner manifest remains active: err=%v", err)
	}
}

// TestNativeCheckpointNormalCompletionReleasesDurableSlot proves the
// non-preempted native path independently of the checkpoint/restore path. A
// completed stream must record started -> stopped -> released -> completed,
// surface every cleanup error, and leave the same physical slot reusable.
func TestNativeCheckpointNormalCompletionReleasesDurableSlot(t *testing.T) {
	fixture := newNativeCheckpointFixture(t, false)
	fixture.backend.mu.Lock()
	fixture.backend.completeInitial = true
	fixture.backend.mu.Unlock()

	_, firstBody := nativeStartPublicStream(t, fixture, nativeVictimBody())
	var first []byte
	select {
	case first = <-firstBody:
	case <-time.After(10 * time.Second):
		t.Fatal("normal native stream did not complete")
	}
	if got := strings.Count(string(first), "[DONE]"); got != 1 {
		t.Fatalf("normal native stream emitted DONE=%d body=%q", got, first)
	}
	nativeWaitFor(t, 10*time.Second, "first normal workload terminal", func() bool {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		for _, row := range rows {
			if row.Request.OwnerID == "victim-owner" && row.Status == domain.WorkloadSucceeded {
				return true
			}
		}
		return false
	})

	// A second ordinary stream exercises the exact same target/slot after the
	// first operation's durable release; a stale live-slot row would keep it
	// queued indefinitely.
	_, secondBody := nativeStartPublicStream(t, fixture, nativeVictimBody())
	select {
	case second := <-secondBody:
		if got := strings.Count(string(second), "[DONE]"); got != 1 {
			t.Fatalf("reused native slot emitted DONE=%d body=%q", got, second)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("same native slot was not reusable after normal completion")
	}
	nativeWaitFor(t, 10*time.Second, "second normal workload terminal", func() bool {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		succeeded := 0
		for _, row := range rows {
			if row.Request.OwnerID == "victim-owner" && row.Status == domain.WorkloadSucceeded {
				succeeded++
			}
		}
		return succeeded >= 2
	})
	operations, err := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) < 2 {
		t.Fatalf("normal completion did not persist both operations: %+v", operations)
	}
	for _, operation := range operations {
		if operation.Phase != "completed" {
			t.Fatalf("normal operation was not durably terminalized: %+v", operation)
		}
	}
	fixture.backend.mu.Lock()
	cancelCount := fixture.backend.cancelCount
	fixture.backend.mu.Unlock()
	if cancelCount != 0 {
		t.Fatalf("normal completion unexpectedly used backend cancel: %d", cancelCount)
	}
}

func TestNativeCheckpointPublicStreamMissingDoneFailsWithoutSuccess(t *testing.T) {
	fixture := newNativeCheckpointFixture(t, false)
	response := nativeRunCheckpointedResumedStream(t, fixture, func(backend *nativeLlamaBackend) {
		backend.omitDoneResumed = true
	})
	if strings.Contains(string(response), "[DONE]") {
		t.Fatalf("missing-DONE resumed backend was given a synthetic terminal marker: %q", response)
	}
	nativeWaitFor(t, 10*time.Second, "missing-DONE workload failure", func() bool {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		for _, row := range rows {
			if row.Request.OwnerID == "victim-owner" {
				return row.Status == domain.WorkloadFailed
			}
		}
		return false
	})
	operations, err := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) == 0 {
		t.Fatal("missing-DONE resumed stream left no durable checkpoint operation")
	}
	for _, operation := range operations {
		if operation.Phase == "completed" {
			t.Fatalf("missing-DONE resumed stream was durably completed: %+v", operation)
		}
	}
	cancelledRestore, releasedRestore := make(map[string]bool), make(map[string]bool)
	nativeWaitFor(t, 5*time.Second, "missing-DONE resumed failure cleanup", func() bool {
		commands, listErr := fixture.backing.ListNodeCommands(context.Background(), "native-node", 0)
		if listErr != nil {
			return false
		}
		for _, command := range commands {
			if command == nil || command.Status != domain.NodeCommandSucceeded {
				continue
			}
			operationID, _ := command.Args["checkpoint_operation_id"].(string)
			if !strings.HasPrefix(operationID, "restore:") {
				continue
			}
			switch command.Command {
			case "checkpoint_cancel":
				cancelledRestore[operationID] = true
			case "checkpoint_release":
				releasedRestore[operationID] = true
			}
		}
		return len(cancelledRestore) > 0
	})
	if len(cancelledRestore) == 0 {
		t.Fatal("missing-DONE resumed stream did not take the failure cancel path")
	}
	for operationID := range releasedRestore {
		if !cancelledRestore[operationID] {
			t.Fatalf("missing-DONE resumed stream used success release without cancellation: operation=%s", operationID)
		}
	}
}

func TestNativeCheckpointPublicStreamIgnoresDuplicateDoneAndPostDoneContent(t *testing.T) {
	fixture := newNativeCheckpointFixture(t, false)
	response := nativeRunCheckpointedResumedStream(t, fixture, func(backend *nativeLlamaBackend) {
		backend.duplicateDoneResumed = true
		backend.postDoneResumed = true
		backend.toolEventResumed = true
	})
	if got := strings.Count(string(response), "[DONE]"); got != 1 {
		t.Fatalf("duplicate-DONE resumed backend produced %d public terminals: %q", got, response)
	}
	if strings.Contains(string(response), "POST_DONE") {
		t.Fatalf("post-DONE content was accepted by the resumed public stream: %q", response)
	}
	if !strings.Contains(string(response), "tool_calls") || !strings.Contains(string(response), "prompt_tokens") {
		t.Fatalf("duplicate-DONE resumed stream dropped tool/usage events: %q", response)
	}
	nativeWaitFor(t, 10*time.Second, "duplicate-DONE workload success", func() bool {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		for _, row := range rows {
			if row.Request.OwnerID == "victim-owner" {
				return row.Status == domain.WorkloadSucceeded
			}
		}
		return false
	})
	operations, err := fixture.backing.ListLLMCheckpointOperations(context.Background(), "victim-owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) == 0 {
		t.Fatal("duplicate-DONE resumed stream left no durable checkpoint operation")
	}
	for _, operation := range operations {
		if operation == nil || operation.Phase != "completed" {
			t.Fatalf("duplicate-DONE resumed stream did not terminalize successfully: %+v", operation)
		}
	}
}

func TestNativeNodeCheckpointResumedDisconnectSignsCancelAndRelease(t *testing.T) {
	fixture := newNativeCheckpointFixture(t, true)
	reqBody := nativeVictimBody()
	payload, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, fixture.gateway.URL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer victim-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := fixture.gateway.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseDone := make(chan struct{})
	go func() { fixture.readPublicStream(response.Body); _ = response.Body.Close(); close(responseDone) }()
	select {
	case <-fixture.backend.prefixSent:
	case <-time.After(10 * time.Second):
		t.Fatal("victim did not emit a prefix before disconnect test")
	}
	fixture.waitPrefixRelayed(t)
	nativeWaitFor(t, 10*time.Second, "victim running execution", func() bool {
		rows, _ := fixture.backing.ListWorkloads(context.Background())
		for _, row := range rows {
			if row.Request.OwnerID == "victim-owner" && row.Status == domain.WorkloadRunning && row.Execution != nil {
				return true
			}
		}
		return false
	})
	urgent := nativeSubmitUrgent(t, fixture)
	urgentCtx, urgentCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer urgentCancel()
	if urgentDone, err := fixture.manager.Wait(urgentCtx, urgent.Request.ID); err != nil || urgentDone.Status != domain.WorkloadSucceeded {
		t.Fatalf("urgent did not complete during disconnect test: row=%+v err=%v", urgentDone, err)
	}
	select {
	case <-fixture.backend.resumedStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("resumed backend stream did not start")
	}
	_ = response.Body.Close()
	select {
	case <-responseDone:
	case <-time.After(10 * time.Second):
		t.Fatal("disconnected response did not terminate")
	}
	nativeWaitFor(t, 10*time.Second, "signed resumed cancel/release", func() bool {
		rows, _ := fixture.backing.ListNodeCommands(context.Background(), "native-node", 0)
		cancelledRestore := make(map[string]struct{})
		releasedRestore := make(map[string]struct{})
		for _, row := range rows {
			if row == nil || row.Status != domain.NodeCommandSucceeded {
				continue
			}
			op, _ := row.Args["checkpoint_operation_id"].(string)
			if !strings.HasPrefix(op, "restore:") {
				continue
			}
			if row.Command == "checkpoint_cancel" {
				cancelledRestore[op] = struct{}{}
			}
			if row.Command == "checkpoint_release" {
				releasedRestore[op] = struct{}{}
			}
		}
		for op := range cancelledRestore {
			if _, ok := releasedRestore[op]; ok {
				return true
			}
		}
		return false
	})
}
