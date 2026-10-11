package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

func TestNodeCapabilityAdvertisementIsVersionedAndSeparatesResidencyProofs(t *testing.T) {
	message := wsproto.RegisterPayload{
		NodeID: "node-a", CapabilityVersion: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{
			Version: domain.CapabilityContractVersion, SupportsWarmRAM: true,
			WarmRAMVerified: true, WarmRAMVerification: "mincore",
			SupportsSessionCheckpoint: false, SessionCheckpointVerified: false,
		},
		Capacity:                   domain.CapacityBudget{VRAMTotalBytes: 8 << 30, VRAMReserveBytes: 512 << 20},
		MaxAcceleratorsPerWorkload: 1,
	}
	body, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded wsproto.RegisterPayload
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CapabilityVersion != domain.CapabilityContractVersion || !decoded.Capabilities.WarmRAMVerified || decoded.Capabilities.SessionCheckpointVerified || decoded.MaxAcceleratorsPerWorkload != 1 {
		t.Fatalf("capability contract was not preserved: %+v", decoded)
	}
}

func TestRegisterRejectsInvalidNestedAdapterBeforeStore(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	counting := &countingNodeStore{NodeStore: srv.nodes}
	srv.nodes = counting
	reg := wsproto.RegisterPayload{
		NodeID: "node-invalid-adapter", CapabilityVersion: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion},
		Capacity:     domain.CapacityBudget{VRAMTotalBytes: 1024}, MaxAcceleratorsPerWorkload: 1,
		Adapters: []wsproto.AdapterAdvertisement{
			{ID: "valid-first", Adapter: "llama.cpp", Endpoint: "http://runtime"},
			{ID: "invalid-second", Adapter: "llama.cpp", Endpoint: "http://runtime", RuntimeProfiles: []wsproto.RuntimeProfileAdvertisement{{ID: "", ContextLimit: 4096, Slots: 1}}},
		},
	}
	if _, err := srv.registerNode(context.Background(), reg); err == nil {
		t.Fatal("registration with an invalid nested runtime profile was accepted")
	}
	if counting.upserts != 0 {
		t.Fatalf("invalid registration attempted node persistence %d times", counting.upserts)
	}
	if got := len(manager.Targets()); got != 1 || manager.Targets()[0].ID != "mock" {
		t.Fatalf("invalid registration projected targets before validation completed: %+v", manager.Targets())
	}
	if _, err := srv.nodes.GetNode(context.Background(), reg.NodeID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("invalid registration mutated node store: %v", err)
	}
}

func TestRegisterQuarantinesRuntimeCapacityAfterManagerRestart(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := workloads.NewManager(logger, backing, time.Second)
	manager.RegisterAdapter(workloads.NewMockAdapter())
	server := NewServer(&Config{}, logger, backing, nil, nil)
	server.SetWorkloadManager(manager)
	defer func() {
		manager.Close()
		server.Close()
	}()

	prior := &domain.NodeCommand{
		ID: "old-profile-switch", IdempotencyKey: "old-profile-key", NodeID: "node-restarted",
		Command: "switch_runtime_profile", Args: map[string]any{"target_id": "old-alias", "profile_id": "ctx-32k"},
		Attempts: 1, Status: domain.NodeCommandSent,
	}
	if _, _, err := backing.CreateNodeCommand(ctx, prior); err != nil {
		t.Fatal(err)
	}
	if _, err := server.registerNode(ctx, wsproto.RegisterPayload{
		NodeID: "node-restarted", CapabilityVersion: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, MaxAcceleratorsPerWorkload: 1},
		Capacity:     domain.CapacityBudget{VRAMTotalBytes: 8 << 30}, MaxAcceleratorsPerWorkload: 1,
	}); err != nil {
		t.Fatal(err)
	}
	advertisement := func(id string) wsproto.AdapterAdvertisement {
		return wsproto.AdapterAdvertisement{
			ID: id, Adapter: "mock", Endpoint: "http://runtime", AcceleratorIndex: 0,
			Version: "runtime-v1", CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
			ModelFingerprint: "model-fp", Models: []string{"model"}, ResidentModels: []string{"model"},
			ContextLimit: 8192, Slots: 4, CapacitySource: "runtime:/slots", CapabilitiesVerified: true,
			ActiveRuntimeProfile: "ctx-8k", SupportsRuntimeProfileSwitch: true,
			RuntimeProfiles: []wsproto.RuntimeProfileAdvertisement{{ID: "ctx-8k", ContextLimit: 8192, Slots: 4}, {ID: "ctx-32k", ContextLimit: 32768, Slots: 1}},
		}
	}
	server.registerAdapterAdvertisements("node-restarted", []wsproto.AdapterAdvertisement{advertisement("runtime-a"), advertisement("runtime-b")})
	manager.Start(ctx)

	seen := map[string]bool{}
	for _, target := range manager.Targets() {
		if target.NodeID != "node-restarted" {
			continue
		}
		seen[target.ID] = true
		if target.CapacityVerified || target.Slots != 0 || target.ContextLimit != 0 || target.ActiveRuntimeProfile != "" || target.CapacitySource != "runtime-profile:observation_unavailable" {
			t.Fatalf("fresh websocket registration restored capacity despite unresolved durable profile command: %+v", target)
		}
		if got := manager.CurrentlyAvailableSlotsForModel(ctx, target, "model"); got != 0 {
			t.Fatalf("unresolved profile command exposed %d immediately available slots for %s", got, target.ID)
		}
	}
	if !seen["node-restarted-runtime-a"] || !seen["node-restarted-runtime-b"] {
		t.Fatalf("same-card routes were not both registered and quarantined: %v", seen)
	}
	queued, _, err := manager.Submit(ctx, domain.WorkloadRequest{OwnerID: "owner", Adapter: "mock", Payload: json.RawMessage(`{"ok":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		latest, getErr := backing.GetWorkload(ctx, queued.Request.ID)
		if getErr == nil && latest.Status != domain.WorkloadQueued {
			queued = latest
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if queued.Status != domain.WorkloadWaiting || strings.Contains(queued.Decision.Blocker, "admitted") {
		t.Fatalf("public scheduler admission did not remain fail-closed after restart: %+v", queued)
	}
}

func TestRegisterPayloadStrictlyRejectsUnknownAndNullNestedFields(t *testing.T) {
	for _, payload := range []string{
		`{"node_id":"node-a","capabilities":{"supports_warm_ram":false,"UnknownProof":true}}`,
		`{"node_id":"node-a","capacity":{"vram_total_bytes":null}}`,
		`{"node_id":"node-a","adapters":[{"id":"a","adapter":"llamacpp","endpoint":"http://runtime","runtime_profiles":[{"id":"p","context_limit":null,"slots":1}]}]}`,
	} {
		var decoded wsproto.RegisterPayload
		if err := json.Unmarshal([]byte(payload), &decoded); err == nil {
			t.Fatalf("strict register payload was accepted: %s", payload)
		}
	}
}

func TestSupersededNodeSessionCannotMutateOrSend(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	old := &nodeConnection{nodeID: "node-a", generation: 1}
	current := &nodeConnection{nodeID: "node-a", generation: 2}
	srv.nodeConnMu.Lock()
	srv.nodeConnections["node-a"] = current
	srv.nodeConnMu.Unlock()
	if srv.isCurrentNodeConnection("node-a", old) {
		t.Fatal("superseded websocket session was still current")
	}
	if err := srv.sendAck(context.Background(), old, true, "stale"); err == nil {
		t.Fatal("superseded websocket session was allowed to send")
	}
	if !srv.isCurrentNodeConnection("node-a", current) {
		t.Fatal("current websocket session was not recognized")
	}
}

func TestNodeConnectionWriteGateHonorsContextAndClose(t *testing.T) {
	serverExited := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverExited)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		var ignored wsproto.Envelope
		_ = wsjson.Read(context.Background(), conn, &ignored)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	connection := &nodeConnection{conn: client, done: make(chan struct{})}
	activeStarted := make(chan struct{})
	connection.writeHook = func(ctx context.Context, _ wsproto.Envelope) error {
		select {
		case <-activeStarted:
		default:
			close(activeStarted)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-connection.done:
			return errors.New("transport closed")
		}
	}
	activeDone := make(chan error, 1)
	go func() {
		activeDone <- connection.write(context.Background(), wsproto.Envelope{Type: wsproto.MsgAck})
	}()
	select {
	case <-activeStarted:
	case <-time.After(time.Second):
		t.Fatal("active writer did not reach the transport boundary")
	}
	// The active transport owns the gate. A queued short-deadline writer must
	// return from the gate without reaching socket I/O.
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer shortCancel()
	shortDone := make(chan error, 1)
	go func() {
		shortDone <- connection.write(shortCtx, wsproto.Envelope{Type: wsproto.MsgAck})
	}()
	select {
	case err := <-shortDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued writer returned wrong error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued writer ignored its context deadline")
	}
	// A second queued writer is released by Close, while Close also unblocks the
	// active transport and causes the real websocket handler to exit.
	blockedDone := make(chan error, 1)
	go func() {
		blockedDone <- connection.write(context.Background(), wsproto.Envelope{Type: wsproto.MsgAck})
	}()
	time.Sleep(10 * time.Millisecond)
	connection.close()
	select {
	case err := <-blockedDone:
		if err == nil {
			t.Fatal("closed connection writer unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release queued writer")
	}
	select {
	case err := <-activeDone:
		if err == nil {
			t.Fatal("closed active transport unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock active writer")
	}
	select {
	case <-connection.writeGate:
		connection.writeGate <- struct{}{}
	case <-time.After(time.Second):
		t.Fatal("writer gate leaked its token after active Close")
	}
	select {
	case <-serverExited:
	case <-time.After(time.Second):
		t.Fatal("websocket handler did not exit after Close")
	}
}

func TestNodeConnectionRealBackpressureCloseAndGateReuse(t *testing.T) {
	serverExited := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverExited)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		var ignored wsproto.Envelope
		_ = wsjson.Read(context.Background(), conn, &ignored)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	connection := &nodeConnection{conn: client, done: make(chan struct{})}
	activeStarted := make(chan struct{})
	connection.writeStartHook = func() {
		select {
		case <-activeStarted:
		default:
			close(activeStarted)
		}
	}
	largePayload := append([]byte{'"'}, bytes.Repeat([]byte{'x'}, 64<<20)...)
	largePayload = append(largePayload, '"')
	activeDone := make(chan error, 1)
	go func() {
		activeDone <- connection.write(context.Background(), wsproto.Envelope{Type: wsproto.MsgEvent, Payload: largePayload})
	}()
	select {
	case <-activeStarted:
	case <-time.After(time.Second):
		t.Fatal("real websocket writer did not reach transport")
	}
	select {
	case err := <-activeDone:
		t.Fatalf("peer stopped reading but large websocket write completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer shortCancel()
	queuedDone := make(chan error, 1)
	go func() {
		queuedDone <- connection.write(shortCtx, wsproto.Envelope{Type: wsproto.MsgAck})
	}()
	select {
	case err := <-queuedDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued real writer returned wrong error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued real writer ignored deadline while active transport was blocked")
	}
	connection.close()
	select {
	case err := <-activeDone:
		if err == nil {
			t.Fatal("Close unexpectedly reported success for blocked real write")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock blocked real websocket write")
	}
	select {
	case <-connection.writeGate:
		connection.writeGate <- struct{}{}
	case <-time.After(time.Second):
		t.Fatal("real writer gate leaked token after Close")
	}
	select {
	case <-serverExited:
	case <-time.After(time.Second):
		t.Fatal("real websocket handler did not exit after Close")
	}
	// A closed transport must not poison the gate or the controller's next
	// session. Recreate a legitimate websocket peer and complete registration
	// plus an ACK write over the real transport.
	restartServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		var registration wsproto.Envelope
		if err := wsjson.Read(context.Background(), conn, &registration); err != nil || registration.Type != wsproto.MsgRegister {
			return
		}
		_ = wsjson.Write(context.Background(), conn, wsproto.Envelope{Type: wsproto.MsgAck, Payload: mustJSON(wsproto.AckPayload{OK: true})})
	}))
	defer restartServer.Close()
	restartClient, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(restartServer.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restartClient.CloseNow()
	if err := wsjson.Write(ctx, restartClient, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(wsproto.RegisterPayload{NodeID: "node-restarted"})}); err != nil {
		t.Fatalf("restarted registration write: %v", err)
	}
	var restartAck wsproto.Envelope
	if err := wsjson.Read(ctx, restartClient, &restartAck); err != nil || restartAck.Type != wsproto.MsgAck {
		t.Fatalf("restarted registration ACK: type=%v err=%v", restartAck.Type, err)
	}
}

func TestProductionWebsocketRestartAndCommandReplay(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.commandSecret = []byte("0123456789abcdef0123456789abcdef")
	backing, ok := srv.workloadStore.(store.Store)
	if !ok {
		t.Fatal("test server store is not reusable across controller reconstruction")
	}
	serve := func(server *Server) (*httptest.Server, *websocket.Conn) {
		httpServer := httptest.NewServer(server.Handler())
		ctx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dialCancel()
		connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
		if err != nil {
			httpServer.Close()
			t.Fatal(err)
		}
		ready := true
		if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(wsproto.RegisterPayload{NodeID: "node-a", Ready: &ready})}); err != nil {
			connection.CloseNow()
			httpServer.Close()
			t.Fatal(err)
		}
		var ack wsproto.Envelope
		if err := wsjson.Read(ctx, connection, &ack); err != nil || ack.Type != wsproto.MsgAck {
			connection.CloseNow()
			httpServer.Close()
			t.Fatalf("production registration ACK: type=%v err=%v", ack.Type, err)
		}
		return httpServer, connection
	}
	firstHTTP, firstConn := serve(srv)
	commandArgs := map[string]any{"target_kind": "llamacpp", "target_id": "node-a-runtime", "model": "model", "runtime_identity": "node-a-runtime|llamacpp||runtime-v1|fingerprint", "capability_version": "runtime-v1", "capability_revision": domain.CapabilityContractVersion, "expected_tier": "hot_vram", "fencing_token": int64(7)}
	issue := func(server *Server, key string) *domain.NodeCommand {
		body := map[string]any{"command": "load_model", "args": commandArgs}
		req := httptest.NewRequest(http.MethodPost, "/admin/api/nodes/node-a/commands", bytes.NewReader(mustJSON(body)))
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer admin-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, req)
		if response.Code != http.StatusAccepted {
			t.Fatalf("production command status=%d body=%s", response.Code, response.Body.String())
		}
		var command domain.NodeCommand
		if err := json.Unmarshal(response.Body.Bytes(), &command); err != nil {
			t.Fatal(err)
		}
		return &command
	}
	readCommand := func(connection *websocket.Conn, expected *domain.NodeCommand) {
		ctx, readCancel := context.WithTimeout(context.Background(), time.Second)
		defer readCancel()
		for {
			var frame wsproto.Envelope
			if err := wsjson.Read(ctx, connection, &frame); err != nil {
				t.Fatalf("read production command: %v", err)
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
			if !wsproto.VerifyCommand(wire, srv.commandSecret) || !reflect.DeepEqual(wire.Args, expected.Args) {
				t.Fatalf("production command was altered or unsigned: %+v", wire)
			}
			return
		}
	}
	waitSucceeded := func(command *domain.NodeCommand) {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			stored, err := backing.GetNodeCommand(context.Background(), command.ID)
			if err == nil && stored.Status == domain.NodeCommandSucceeded {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		stored, _ := backing.GetNodeCommand(context.Background(), command.ID)
		t.Fatalf("production command did not persist success: %+v", stored)
	}
	first := issue(srv, "production-restart-command")
	readCommand(firstConn, first)
	ctx, writeCancel := context.WithTimeout(context.Background(), time.Second)
	if err := wsjson.Write(ctx, firstConn, wsproto.Envelope{Type: wsproto.MsgCommandResult, Payload: mustJSON(wsproto.CommandResultPayload{ID: first.ID, NodeID: first.NodeID, OK: true, Result: map[string]any{"tier": "hot_vram"}, CompletedAt: time.Now().UTC()})}); err != nil {
		writeCancel()
		t.Fatal(err)
	}
	writeCancel()
	waitSucceeded(first)
	firstConn.CloseNow()
	firstHTTP.Close()
	srv.Close()
	restarted := NewServer(srv.cfg, srv.log, backing, nil, nil)
	defer restarted.Close()
	restarted.commandSecret = append([]byte(nil), srv.commandSecret...)
	secondHTTP, secondConn := serve(restarted)
	defer secondHTTP.Close()
	defer secondConn.CloseNow()
	second := issue(restarted, "production-restart-command-2")
	readCommand(secondConn, second)
	if second.ID == first.ID {
		t.Fatal("reconstructed controller reused the prior command identity")
	}
	if err := wsjson.Write(context.Background(), secondConn, wsproto.Envelope{Type: wsproto.MsgCommandResult, Payload: mustJSON(wsproto.CommandResultPayload{ID: second.ID, NodeID: second.NodeID, OK: true, Result: map[string]any{"tier": "hot_vram"}, CompletedAt: time.Now().UTC()})}); err != nil {
		t.Fatal(err)
	}
	waitSucceeded(second)
	if node, err := backing.GetNode(context.Background(), "node-a"); err != nil || node.Observed.Connectivity != domain.ConnectivityConnected || !node.Observed.Ready {
		t.Fatalf("reconstructed production WS did not persist ready registry state: node=%+v err=%v", node, err)
	}
}

func TestSupersededWebsocketInboundCannotOverwriteCurrentSession(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	ctx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelDial()
	dial := func(label string) *websocket.Conn {
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
		if err != nil {
			t.Fatal(err)
		}
		ready := true
		if err := wsjson.Write(ctx, conn, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(wsproto.RegisterPayload{NodeID: "node-a", Ready: &ready})}); err != nil {
			t.Fatal(err)
		}
		var ack wsproto.Envelope
		if err := wsjson.Read(ctx, conn, &ack); err != nil || ack.Type != wsproto.MsgAck {
			t.Fatalf("%s registration ack: type=%v err=%v", label, ack.Type, err)
		}
		return conn
	}
	old := dial("old")
	defer old.CloseNow()
	current := dial("current")
	defer current.CloseNow()
	if err := wsjson.Write(ctx, old, wsproto.Envelope{Type: wsproto.MsgHeartbeat, Payload: mustJSON(wsproto.HeartbeatPayload{NodeID: "node-a", Ready: false})}); err == nil {
		// The superseded handler may have already closed the socket; if it has
		// not, the controller must reject the frame at the generation check.
		var ignored wsproto.Envelope
		_ = wsjson.Read(ctx, old, &ignored)
	}
	time.Sleep(100 * time.Millisecond)
	node, err := srv.nodes.GetNode(ctx, "node-a")
	if err != nil || !node.Observed.Ready || node.Observed.Connectivity != domain.ConnectivityConnected {
		t.Fatalf("stale inbound heartbeat overwrote current session state: node=%+v err=%v", node, err)
	}
}

func TestDelayedLowerGenerationRegistrationHasNoStoreSideEffect(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	srv.nodeSessionSeq.Store(20)
	srv.nodeConnMu.Lock()
	srv.nodeConnections["node-a"] = &nodeConnection{nodeID: "node-a", generation: 30}
	srv.nodeConnMu.Unlock()
	ctx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	ready := true
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(wsproto.RegisterPayload{NodeID: "node-a", Ready: &ready})}); err != nil {
		t.Fatal(err)
	}
	var ack wsproto.Envelope
	_ = wsjson.Read(ctx, connection, &ack)
	if _, err := srv.nodes.GetNode(ctx, "node-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delayed lower-generation registration mutated node store: err=%v", err)
	}
}

func TestSessionMutationAndReplacementInterleaveWithoutDeadlock(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	connection := &nodeConnection{nodeID: "node-a", generation: 1}
	srv.nodeConnMu.Lock()
	srv.nodeConnections["node-a"] = connection
	srv.nodeConnMu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		if !srv.withCurrentNodeSession("node-a", connection, func() {
			close(entered)
			<-release
		}) {
			t.Errorf("current session was rejected")
		}
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("session mutation did not enter")
	}
	replaced := make(chan struct{})
	go func() {
		srv.sessionMutationMu.Lock()
		srv.nodeConnMu.Lock()
		srv.nodeConnections["node-a"] = &nodeConnection{nodeID: "node-a", generation: 2}
		srv.nodeConnMu.Unlock()
		srv.sessionMutationMu.Unlock()
		close(replaced)
	}()
	select {
	case <-replaced:
		t.Fatal("replacement overtook an active session mutation")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session mutation/replacement deadlocked")
	}
	select {
	case <-replaced:
	case <-time.After(time.Second):
		t.Fatal("replacement did not complete after mutation release")
	}
}

func TestServerCloseTracksPreRegisterWebsocket(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	ctx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		srv.connectionLifecycleMu.Lock()
		tracked := len(srv.activeConnections)
		srv.connectionLifecycleMu.Unlock()
		if tracked == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() {
		srv.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Server.Close waited on an unregistered websocket")
	}
	if _, err := srv.nodes.GetNode(context.Background(), "node-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pre-register websocket unexpectedly persisted a node after close: %v", err)
	}
}

func TestRecoveryTimerReplacementIdentityAndFutureClose(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	old := &nodeRecoveryTimer{generation: 1}
	newer := &nodeRecoveryTimer{generation: 2}
	srv.nodeRecoveryMu.Lock()
	srv.nodeRecoveryTimers["cmd"] = newer
	srv.nodeRecoveryMu.Unlock()
	if srv.releaseNodeRecoveryTimer("cmd", old) {
		t.Fatal("late recovery callback removed a replacement timer")
	}
	srv.nodeRecoveryMu.Lock()
	if srv.nodeRecoveryTimers["cmd"] != newer {
		t.Fatal("replacement timer ownership was lost")
	}
	srv.nodeRecoveryMu.Unlock()
	entry := &nodeRecoveryTimer{generation: 3}
	entry.timer = time.AfterFunc(time.Hour, func() { t.Error("future recovery timer fired") })
	srv.recoveryLifecycleMu.Lock()
	srv.nodeRecoveryMu.Lock()
	srv.recoveryWG.Add(1)
	srv.nodeRecoveryTimers["future"] = entry
	srv.nodeRecoveryMu.Unlock()
	srv.recoveryLifecycleMu.Unlock()
	started := time.Now()
	srv.Close()
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Close waited for a future recovery timer: %s", elapsed)
	}
	if len(srv.nodeRecoveryTimers) != 0 {
		t.Fatal("Close left recovery timer ownership behind")
	}
}

func TestNodeRegistrationReadinessIsPersistedBeforeHeartbeat(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	ctx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	ready := false
	register := wsproto.RegisterPayload{NodeID: "node-a", NodeName: "blocked", Ready: &ready}
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(register)}); err != nil {
		t.Fatal(err)
	}
	var ack wsproto.Envelope
	if err := wsjson.Read(ctx, connection, &ack); err != nil || ack.Type != wsproto.MsgAck {
		t.Fatalf("registration was not acknowledged: type=%v err=%v", ack.Type, err)
	}
	node, err := srv.nodes.GetNode(ctx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if node.Observed.Ready {
		t.Fatalf("blocked node was transiently persisted Ready=true: %+v", node.Observed)
	}
}

func TestLegacyNodeRegistrationReadinessOmittedPreservesCompatibility(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	node, err := srv.registerNode(context.Background(), wsproto.RegisterPayload{NodeID: "legacy-node"})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Observed.Ready {
		t.Fatalf("omitted legacy readiness was not defaulted safely: %+v", node.Observed)
	}
}

func mustJSON(value any) []byte {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return body
}

type failingNodeRegistrationStore struct{ store.NodeStore }

type countingNodeStore struct {
	store.NodeStore
	upserts int
}

func (s *countingNodeStore) UpsertNode(ctx context.Context, node *domain.Node) (*domain.Node, error) {
	s.upserts++
	return s.NodeStore.UpsertNode(ctx, node)
}

func (s *failingNodeRegistrationStore) UpsertNode(context.Context, *domain.Node) (*domain.Node, error) {
	return nil, errors.New("injected registration persistence failure")
}

type failingHeartbeatStore struct{ store.NodeStore }

func (s *failingHeartbeatStore) UpdateObserved(context.Context, string, func(*domain.Observed, *[]domain.Accelerator)) error {
	return errors.New("injected heartbeat persistence failure")
}

func TestNodeRegistrationStoreFailureSendsNoAckOrConnection(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.nodes = &failingNodeRegistrationStore{NodeStore: srv.nodes}
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	ctx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(wsproto.RegisterPayload{NodeID: "node-a"})}); err != nil {
		t.Fatal(err)
	}
	var response wsproto.Envelope
	if err := wsjson.Read(ctx, connection, &response); err == nil {
		t.Fatalf("registration persistence failure unexpectedly returned an envelope: %+v", response)
	}
	if _, err := srv.nodes.GetNode(ctx, "node-a"); err == nil {
		t.Fatal("failed registration published a node state")
	}
}

func TestHeartbeatReadinessDowngradePersistsNonReadyLifecycle(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	ctx := context.Background()
	ready := true
	if _, err := srv.registerNode(ctx, wsproto.RegisterPayload{NodeID: "node-a", Ready: &ready}); err != nil {
		t.Fatal(err)
	}
	srv.handleHeartbeat(ctx, "node-a", wsproto.HeartbeatPayload{NodeID: "node-a", Ready: false})
	node, err := srv.nodes.GetNode(ctx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if node.Observed.Ready || node.Observed.Lifecycle != domain.LifecycleConnected {
		t.Fatalf("heartbeat downgrade left node schedulable: %+v", node.Observed)
	}
	srv.handleHeartbeat(ctx, "node-a", wsproto.HeartbeatPayload{NodeID: "node-a", Ready: true})
	node, err = srv.nodes.GetNode(ctx, "node-a")
	if err != nil || !node.Observed.Ready || node.Observed.Lifecycle != domain.LifecycleReady {
		t.Fatalf("heartbeat readiness upgrade was not persisted: node=%+v err=%v", node.Observed, err)
	}
}

func TestHeartbeatStoreFailureDoesNotAcknowledgeOrKeepConnection(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	if _, err := srv.registerNode(context.Background(), wsproto.RegisterPayload{NodeID: "node-a"}); err != nil {
		t.Fatal(err)
	}
	srv.nodes = &failingHeartbeatStore{NodeStore: srv.nodes}
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	ctx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelDial()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ws/node", &websocket.DialOptions{HTTPHeader: map[string][]string{"Authorization": {"Bearer node-a-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: mustJSON(wsproto.RegisterPayload{NodeID: "node-a"})}); err != nil {
		t.Fatal(err)
	}
	var ack wsproto.Envelope
	if err := wsjson.Read(ctx, connection, &ack); err != nil || ack.Type != wsproto.MsgAck {
		t.Fatalf("registration was not acknowledged: type=%v err=%v", ack.Type, err)
	}
	heartbeat, _ := json.Marshal(wsproto.HeartbeatPayload{NodeID: "node-a", Ready: false})
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgHeartbeat, Payload: heartbeat}); err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Read(ctx, connection, &ack); err == nil {
		t.Fatalf("heartbeat persistence failure returned success ACK: %+v", ack)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		srv.nodeConnMu.RLock()
		_, connected := srv.nodeConnections["node-a"]
		srv.nodeConnMu.RUnlock()
		if !connected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("heartbeat persistence failure left a live controller connection")
}

func TestAdmissionBlockerCodesRemainStable(t *testing.T) {
	decision := domain.AdmissionDecision{Admitted: false, Blocker: "capacity", BlockerCode: domain.BlockerCapacity}
	body, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == "" || decision.BlockerCode != domain.BlockerCapacity {
		t.Fatalf("invalid blocker contract: %s", body)
	}
}

func TestWireCapabilityValidationRejectsKnownBrokenFixture(t *testing.T) {
	broken := wsproto.AdapterAdvertisement{
		ID: "broken", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{
			Version: domain.CapabilityContractVersion, SupportsWarmRAM: true,
			WarmRAMVerified: true, WarmRAMVerification: "guessed",
		},
		Capacity: domain.CapacityBudget{VRAMTotalBytes: 10, VRAMReserveBytes: 11},
	}
	if _, _, _, err := normalizeAdapterCapabilities(broken); err == nil {
		t.Fatal("known-broken capability fixture was accepted")
	}
}

func TestWireCapabilityValidationPreservesLegacyAdvertisement(t *testing.T) {
	legacy := wsproto.AdapterAdvertisement{
		ID: "legacy", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		Version: "runtime-legacy", WarmRAMSupported: true,
	}
	revision, capabilities, _, err := normalizeAdapterCapabilities(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if revision != domain.CapabilityContractVersion || capabilities.Version != revision || !capabilities.SupportsWarmRAM || capabilities.WarmRAMVerified {
		t.Fatalf("legacy advertisement was not safely upgraded: revision=%q capabilities=%+v", revision, capabilities)
	}
}

func TestWireCapabilityValidationPreservesVerifiedFalseTargetCapabilities(t *testing.T) {
	defaults := domain.ResidencyCapabilities{
		Version:                    domain.CapabilityContractVersion,
		SupportsModelLifecycle:     true,
		SupportsAcceleratorReclaim: true,
		SupportsWarmRAM:            true,
		WarmRAMVerified:            true,
		WarmRAMVerification:        "mincore+lock",
	}
	native := wsproto.AdapterAdvertisement{
		ID: "native-comfy", Adapter: "comfy", Endpoint: "http://node.invalid", Version: "comfy-native-1",
	}
	_, capabilities, _, _, err := normalizeAdapterCapabilitiesWithDefaultsAndIdentity(native, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.SupportsAcceleratorReclaim || capabilities.SupportsWarmRAM || capabilities.WarmRAMVerified || capabilities.SupportsModelLifecycle {
		t.Fatalf("verified false target capabilities were widened by node defaults: %+v", capabilities)
	}
}

func TestWireCapabilityValidationRejectsVersionAndBudgetMismatches(t *testing.T) {
	versionMismatch := wsproto.AdapterAdvertisement{
		ID: "mismatch", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities:       domain.ResidencyCapabilities{Version: "future.v9"},
	}
	if _, _, _, err := normalizeAdapterCapabilities(versionMismatch); err == nil {
		t.Fatal("capability version mismatch was accepted")
	}
	badBudget := wsproto.AdapterAdvertisement{
		ID: "budget", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		CapabilityRevision: domain.CapabilityContractVersion,
		Capacity:           domain.CapacityBudget{RAMTotalBytes: 10, RAMReserveBytes: 11},
	}
	if _, _, _, err := normalizeAdapterCapabilities(badBudget); err == nil {
		t.Fatal("invalid byte budget was accepted")
	}
	negativeBudget := wsproto.AdapterAdvertisement{
		ID: "negative-budget", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		Capacity: domain.CapacityBudget{VRAMReserveBytes: -1},
	}
	if _, _, _, err := normalizeAdapterCapabilities(negativeBudget); err == nil {
		t.Fatal("negative byte budget was accepted")
	}
	negativeCeiling := wsproto.AdapterAdvertisement{ID: "negative", Adapter: "llamacpp", Endpoint: "http://node.invalid", MaxAcceleratorsPerWorkload: -1}
	if _, _, _, err := normalizeAdapterCapabilities(negativeCeiling); err == nil {
		t.Fatal("negative placement ceiling was accepted")
	}
	contradictoryCeiling := wsproto.AdapterAdvertisement{ID: "contradictory", Adapter: "llamacpp", Endpoint: "http://node.invalid", MaxAcceleratorsPerWorkload: 2, Capabilities: domain.ResidencyCapabilities{MaxAcceleratorsPerWorkload: 1}}
	if _, _, _, err := normalizeAdapterCapabilities(contradictoryCeiling); err == nil {
		t.Fatal("contradictory placement ceilings were accepted")
	}
}

func TestWireCapabilityValidationRejectsUnverifiedYield(t *testing.T) {
	fixture := wsproto.AdapterAdvertisement{
		ID: "yield", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		Capabilities: domain.ResidencyCapabilities{SupportsYield: true},
	}
	if _, _, _, err := normalizeAdapterCapabilities(fixture); err == nil || !strings.Contains(err.Error(), "supports_yield requires verified runtime proof") {
		t.Fatalf("unverified yield capability was accepted: %v", err)
	}
}

func TestWireCapabilityValidationReconcilesMixedAliasesAndResidentConflict(t *testing.T) {
	mixed := wsproto.AdapterAdvertisement{
		ID: "mixed", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		SupportsModelLifecycle: true,
		Capabilities:           domain.ResidencyCapabilities{SupportsWarmRAM: true, MaxResidentModels: 3},
	}
	_, capabilities, _, err := normalizeAdapterCapabilities(mixed)
	if err != nil || !capabilities.SupportsModelLifecycle || !capabilities.SupportsWarmRAM || capabilities.MaxResidentModels != 3 {
		t.Fatalf("compatible mixed aliases were not merged: %+v err=%v", capabilities, err)
	}
	conflict := mixed
	conflict.MaxResidentModels = 4
	if _, _, _, err := normalizeAdapterCapabilities(conflict); err == nil || !strings.Contains(err.Error(), "max_resident_models values conflict") {
		t.Fatalf("conflicting mixed max resident aliases were accepted: %v", err)
	}
}

func TestWireCapabilityValidationRejectsDanglingResidencyEvidence(t *testing.T) {
	fixtures := []wsproto.AdapterAdvertisement{
		{ID: "warm-proof", Adapter: "llamacpp", Endpoint: "http://node.invalid", Capabilities: domain.ResidencyCapabilities{SupportsWarmRAM: true, WarmRAMVerification: "mincore"}},
		{ID: "checkpoint-proof", Adapter: "llamacpp", Endpoint: "http://node.invalid", Capabilities: domain.ResidencyCapabilities{SupportsSessionCheckpoint: true, SessionCheckpointProof: "runtime"}},
		{ID: "yield-proof", Adapter: "llamacpp", Endpoint: "http://node.invalid", Capabilities: domain.ResidencyCapabilities{YieldProof: "runtime"}},
		{ID: "checkpoint-support", Adapter: "llamacpp", Endpoint: "http://node.invalid", Capabilities: domain.ResidencyCapabilities{SupportsSessionCheckpoint: true}},
	}
	for _, fixture := range fixtures {
		if _, _, _, err := normalizeAdapterCapabilities(fixture); err == nil {
			t.Fatalf("dangling evidence fixture %q was accepted", fixture.ID)
		}
	}
}

func TestCapabilityRefreshPresenceDistinguishesLegacyOmissionAndRevocation(t *testing.T) {
	var legacy wsproto.CapabilitiesPayload
	if err := json.Unmarshal([]byte(`{"node_id":"node-a","adapters":[]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.EnvelopePresent {
		t.Fatal("legacy adapters-only refresh was treated as an authoritative envelope")
	}
	var authoritative wsproto.CapabilitiesPayload
	if err := json.Unmarshal([]byte(`{"node_id":"node-a","capabilities":{},"capacity":{},"max_accelerators_per_workload":1,"adapters":[]}`), &authoritative); err != nil {
		t.Fatal(err)
	}
	if !authoritative.EnvelopePresent {
		t.Fatal("explicit empty capability envelope was not detected")
	}
	stored := &domain.Node{CapabilityVersion: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsWarmRAM: true, WarmRAMVerified: true, WarmRAMVerification: "mincore", SupportsModelLifecycle: true}, Capacity: domain.CapacityBudget{VRAMTotalBytes: 2048, VRAMHardCapBytes: 1800}, MaxAcceleratorsPerWorkload: 2}
	_, inherited, inheritedCapacity, inheritedMax, err := mergeNodeCapabilityRefresh(stored, wsproto.CapabilitiesPayload{})
	if err != nil || !inherited.SupportsWarmRAM || inheritedCapacity.VRAMHardCapBytes != 1800 || inheritedMax != 2 {
		t.Fatalf("legacy omission did not inherit stored envelope: caps=%+v capacity=%+v max=%d err=%v", inherited, inheritedCapacity, inheritedMax, err)
	}
	_, capacityOnly, capacityOnlyBudget, capacityOnlyMax, err := mergeNodeCapabilityRefresh(stored, wsproto.CapabilitiesPayload{CapacityPresent: true, Capacity: domain.CapacityBudget{VRAMTotalBytes: 4096}})
	if err != nil || !capacityOnly.SupportsWarmRAM || capacityOnlyBudget.VRAMTotalBytes != 4096 || capacityOnlyMax != 2 {
		t.Fatalf("capacity-only refresh did not preserve omitted facts: caps=%+v capacity=%+v max=%d err=%v", capacityOnly, capacityOnlyBudget, capacityOnlyMax, err)
	}
	_, capabilitiesOnly, capabilitiesOnlyBudget, capabilitiesOnlyMax, err := mergeNodeCapabilityRefresh(stored, wsproto.CapabilitiesPayload{CapabilitiesPresent: true, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}})
	if err != nil || capabilitiesOnly.SupportsWarmRAM || capabilitiesOnlyBudget.VRAMHardCapBytes != 1800 || capabilitiesOnlyMax != 2 {
		t.Fatalf("capabilities-only refresh did not revoke/retain by field: caps=%+v capacity=%+v max=%d err=%v", capabilitiesOnly, capabilitiesOnlyBudget, capabilitiesOnlyMax, err)
	}
	_, ceilingOnly, ceilingOnlyBudget, ceilingOnlyMax, err := mergeNodeCapabilityRefresh(stored, wsproto.CapabilitiesPayload{MaxAcceleratorsPerWorkloadPresent: true, MaxAcceleratorsPerWorkload: 1})
	if err != nil || !ceilingOnly.SupportsWarmRAM || ceilingOnlyBudget.VRAMHardCapBytes != 1800 || ceilingOnlyMax != 1 {
		t.Fatalf("ceiling-only refresh did not preserve omitted facts: caps=%+v capacity=%+v max=%d err=%v", ceilingOnly, ceilingOnlyBudget, ceilingOnlyMax, err)
	}
	_, revoked, revokedCapacity, revokedMax, err := mergeNodeCapabilityRefresh(stored, wsproto.CapabilitiesPayload{CapabilitiesPresent: true, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}})
	if err != nil || revoked.SupportsWarmRAM || revoked.WarmRAMVerified || revokedCapacity.VRAMHardCapBytes != 1800 || revokedMax != 2 {
		t.Fatalf("explicit empty capability envelope did not revoke prior facts: caps=%+v capacity=%+v max=%d err=%v", revoked, revokedCapacity, revokedMax, err)
	}
}

func TestCapabilityRefreshPartialCapacityPreservesStoredBudgetFacts(t *testing.T) {
	stored := &domain.Node{
		CapabilityVersion: domain.CapabilityContractVersion,
		Capabilities:      domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, MaxAcceleratorsPerWorkload: 2},
		Capacity: domain.CapacityBudget{
			VRAMTotalBytes: 8192, VRAMReserveBytes: 512, VRAMHardCapBytes: 7168,
			RAMTotalBytes: 32768, RAMReserveBytes: 2048, RAMHardCapBytes: 28672, DiskAvailableBytes: 123456,
		},
		MaxAcceleratorsPerWorkload: 2,
	}
	var partial wsproto.CapabilitiesPayload
	if err := json.Unmarshal([]byte(`{"node_id":"node-a","capacity":{"vram_total_bytes":12288}}`), &partial); err != nil {
		t.Fatal(err)
	}
	_, _, capacity, _, err := mergeNodeCapabilityRefresh(stored, partial)
	if err != nil {
		t.Fatal(err)
	}
	if capacity.VRAMTotalBytes != 12288 || capacity.VRAMReserveBytes != 512 || capacity.VRAMHardCapBytes != 7168 || capacity.RAMTotalBytes != 32768 || capacity.RAMReserveBytes != 2048 || capacity.RAMHardCapBytes != 28672 || capacity.DiskAvailableBytes != 123456 {
		t.Fatalf("partial vram refresh erased stored budget facts: %+v", capacity)
	}

	var explicitZero wsproto.CapabilitiesPayload
	if err := json.Unmarshal([]byte(`{"node_id":"node-a","capacity":{"vram_reserve_bytes":0,"ram_hard_cap_bytes":0}}`), &explicitZero); err != nil {
		t.Fatal(err)
	}
	_, _, capacity, _, err = mergeNodeCapabilityRefresh(stored, explicitZero)
	if err != nil {
		t.Fatal(err)
	}
	if capacity.VRAMReserveBytes != 0 || capacity.RAMHardCapBytes != 0 || capacity.VRAMHardCapBytes != 7168 || capacity.RAMReserveBytes != 2048 {
		t.Fatalf("explicit zero capacity updates were not applied without erasing other facts: %+v", capacity)
	}
}

func TestCapabilityRefreshRejectsNoncanonicalCapacityFields(t *testing.T) {
	for _, payload := range []string{
		`{"node_id":"node-a","capacity":{"VRAMTotalBytes":1024}}`,
		`{"node_id":"node-a","capacity":{"vram_total":1024}}`,
		`{"node_id":"node-a","capacity":{"vram_total_bytes":null}}`,
		`{"node_id":"node-a","capacity":null}`,
	} {
		var refresh wsproto.CapabilitiesPayload
		if err := json.Unmarshal([]byte(payload), &refresh); err == nil {
			t.Fatalf("noncanonical/null capacity payload was accepted: %s", payload)
		}
	}
	var explicitZero wsproto.CapabilitiesPayload
	if err := json.Unmarshal([]byte(`{"node_id":"node-a","capacity":{"vram_total_bytes":0}}`), &explicitZero); err != nil {
		t.Fatalf("explicit numeric zero was rejected: %v", err)
	}
	if !explicitZero.CapacityFieldsPresent["vram_total_bytes"] || explicitZero.Capacity.VRAMTotalBytes != 0 {
		t.Fatalf("explicit numeric zero lost presence metadata: %+v", explicitZero)
	}
}

func TestCapabilitiesPayloadRejectsNoncanonicalTopLevelAndNullSafetyFields(t *testing.T) {
	invalid := []string{
		`{"NodeID":"node-a"}`,
		`{"node_id":"node-a","CapabilityVersion":"fleet-residency.v1"}`,
		`{"node_id":"node-a","unknown_field":true}`,
		`{"node_id":"node-a","capabilities":null}`,
		`{"node_id":"node-a","capability_version":null}`,
		`{"node_id":"node-a","capability_revision":null}`,
		`{"node_id":"node-a","max_accelerators_per_workload":null}`,
		`{"node_id":"node-a","adapters":null}`,
	}
	for _, payload := range invalid {
		decoded := wsproto.CapabilitiesPayload{NodeID: "preserved"}
		if err := json.Unmarshal([]byte(payload), &decoded); err == nil {
			t.Fatalf("noncanonical/null capabilities payload was accepted: %s", payload)
		}
		if decoded.NodeID != "preserved" {
			t.Fatalf("failed decode mutated destination: payload=%s decoded=%+v", payload, decoded)
		}
	}
	var valid wsproto.CapabilitiesPayload
	if err := json.Unmarshal([]byte(`{"node_id":"node-a","capability_revision":"fleet-residency.v1","capabilities":{},"max_accelerators_per_workload":0,"adapters":[]}`), &valid); err != nil {
		t.Fatalf("valid complete capabilities payload was rejected: %v", err)
	}
}

func TestCapabilitiesPayloadRejectsNestedAdapterAndProfileAliases(t *testing.T) {
	invalid := []string{
		`{"node_id":"node-a","adapters":[{"id":"a","adapter":"llamacpp","endpoint":"http://runtime","capabilities":{"SupportsWarmRAM":true}}]}`,
		`{"node_id":"node-a","adapters":[{"id":"a","adapter":"llamacpp","endpoint":"http://runtime","capacity":{"vram_total_bytes":null}}]}`,
		`{"node_id":"node-a","adapters":[{"id":"a","adapter":"llamacpp","endpoint":"http://runtime","runtime_profiles":[{"ID":"p","context_limit":1,"slots":1}]}]}`,
		`{"node_id":"node-a","adapters":[{"id":"a","adapter":"llamacpp","endpoint":"http://runtime","runtime_profiles":null}]}`,
	}
	for _, payload := range invalid {
		decoded := wsproto.CapabilitiesPayload{NodeID: "preserved"}
		if err := json.Unmarshal([]byte(payload), &decoded); err == nil {
			t.Fatalf("nested adapter/profile alias was accepted: %s", payload)
		}
		if decoded.NodeID != "preserved" {
			t.Fatalf("failed nested decode mutated destination: payload=%s decoded=%+v", payload, decoded)
		}
	}
}

func TestWireCapabilityValidationReconcilesAdapterRuntimeIdentityAliases(t *testing.T) {
	valid := wsproto.AdapterAdvertisement{
		ID: "identity", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		Version: "runtime-v2", CapabilityVersion: "runtime-v2", CapabilityRevision: domain.CapabilityContractVersion,
	}
	_, _, _, identity, err := normalizeAdapterCapabilitiesWithDefaultsAndIdentity(valid, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, MaxAcceleratorsPerWorkload: 1})
	if err != nil || identity != "runtime-v2" {
		t.Fatalf("runtime identity aliases were not normalized separately: identity=%q err=%v", identity, err)
	}
	conflict := valid
	conflict.CapabilityVersion = "runtime-v3"
	if _, _, _, _, err := normalizeAdapterCapabilitiesWithDefaultsAndIdentity(conflict, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, MaxAcceleratorsPerWorkload: 1}); err == nil || !strings.Contains(err.Error(), "runtime identity") {
		t.Fatalf("conflicting runtime identity aliases were accepted: %v", err)
	}
}

func TestLegacyAdapterRefreshInheritsStoredNodeEnvelope(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	stored, err := srv.registerNode(context.Background(), wsproto.RegisterPayload{
		NodeID: "node-refresh", CapabilityVersion: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsWarmRAM: true, SupportsModelLifecycle: true},
		Capacity:     domain.CapacityBudget{VRAMTotalBytes: 2048, VRAMReserveBytes: 256}, MaxAcceleratorsPerWorkload: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	refresh := wsproto.CapabilitiesPayload{NodeID: stored.ID, Adapters: []wsproto.AdapterAdvertisement{{ID: "legacy", Adapter: "llamacpp", Endpoint: "http://node.invalid", Version: "runtime-v1"}}}
	version, capabilities, capacity, max, err := mergeNodeCapabilityRefresh(stored, refresh)
	if err != nil {
		t.Fatal(err)
	}
	stored.CapabilityVersion, stored.Capabilities, stored.Capacity, stored.MaxAcceleratorsPerWorkload = version, capabilities, capacity, max
	srv.registerAdapterAdvertisementsWithDefaults(stored.ID, refresh.Adapters, version, capabilities, capacity, max)
	for _, target := range manager.Targets() {
		if target.ID == "node-refresh-legacy" {
			if target.Capacity.VRAMReserveBytes != 256 || target.MaxAcceleratorsPerWorkload != 2 || !target.Capabilities.SupportsWarmRAM || !target.SupportsModelLifecycle || target.CapabilityVersion != "runtime-v1" {
				t.Fatalf("legacy refresh erased stored node envelope: %+v", target)
			}
			return
		}
	}
	t.Fatal("legacy refresh adapter was not registered")
}

func testPassiveLlamaAdvertisementRoundTripsFalseLifecycleThroughController(t *testing.T) {
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"model","status":"loaded"}]}`))
		case "/slots":
			_, _ = w.Write([]byte(`[{"n_ctx":4096,"is_processing":false}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer runtime.Close()
	discovery, err := nodeagent.DiscoverLlamaCPP(context.Background(), "node-roundtrip", nodeagent.LlamaCPPServerConfig{ID: "runtime", Endpoint: runtime.URL, ContextLimit: 4096, Slots: 1, RouterManaged: false})
	if err != nil {
		t.Fatal(err)
	}
	if discovery.SupportsModelLifecycle || discovery.CapabilityRevision != domain.CapabilityContractVersion || discovery.Capabilities.Version != domain.CapabilityContractVersion {
		t.Fatalf("passive discovery was not explicit/versioned: %+v", discovery)
	}
	wire, err := json.Marshal(discovery)
	if err != nil {
		t.Fatal(err)
	}
	var decoded wsproto.AdapterAdvertisement
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("passive advertisement did not survive wire validation: %v", err)
	}
	if decoded.SupportsModelLifecycle || decoded.CapabilityRevision != domain.CapabilityContractVersion || decoded.Capabilities.Version != domain.CapabilityContractVersion {
		t.Fatalf("passive false lifecycle fact was lost on the wire: %+v JSON=%s", decoded, wire)
	}
	srv, manager, cancel := testServer(t)
	defer cancel()
	if _, err := srv.registerNode(context.Background(), wsproto.RegisterPayload{
		NodeID: "node-roundtrip", CapabilityVersion: domain.CapabilityContractVersion,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true},
		Capacity:     domain.CapacityBudget{VRAMTotalBytes: 4096}, MaxAcceleratorsPerWorkload: 1,
	}); err != nil {
		t.Fatal(err)
	}
	srv.registerAdapterAdvertisements("node-roundtrip", []wsproto.AdapterAdvertisement{decoded})
	for _, target := range manager.Targets() {
		if target.ID != "node-roundtrip-runtime" {
			continue
		}
		if target.SupportsModelLifecycle || target.Capabilities.SupportsModelLifecycle {
			t.Fatalf("controller widened explicit passive lifecycle=false with node default=true: %+v", target)
		}
		if len(target.Models) != 1 || target.Models[0] != "model" || len(target.ResidentModels) != 1 || target.ResidentModels[0] != "model" {
			t.Fatalf("controller lost passive runtime visibility while preserving false lifecycle: %+v", target)
		}
		return
	}
	t.Fatalf("round-tripped passive runtime target was not registered: %+v", manager.Targets())
}

func TestPassiveLlamaAdvertisementRoundTripsFalseLifecycleThroughController(t *testing.T) {
	testPassiveLlamaAdvertisementRoundTripsFalseLifecycleThroughController(t)
}

func TestWireCapabilityValidationRejectsAdapterCeilingAboveNode(t *testing.T) {
	defaults := domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, MaxAcceleratorsPerWorkload: 1}
	fixture := wsproto.AdapterAdvertisement{ID: "too-wide", Adapter: "llamacpp", Endpoint: "http://node.invalid", MaxAcceleratorsPerWorkload: 2}
	if _, _, _, err := normalizeAdapterCapabilitiesWithDefaults(fixture, defaults); err == nil || !strings.Contains(err.Error(), "exceeds inherited ceiling") {
		t.Fatalf("adapter raised the inherited node ceiling: %v", err)
	}
}

func TestAdapterRegistrationRejectsCapacityAboveInheritedHardCaps(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	srv.registerAdapterAdvertisementsWithDefaults("node-budget", []wsproto.AdapterAdvertisement{{
		ID: "too-wide", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		Capacity: domain.CapacityBudget{VRAMHardCapBytes: 1001},
	}}, domain.CapabilityContractVersion, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, MaxAcceleratorsPerWorkload: 1}, domain.CapacityBudget{VRAMTotalBytes: 2000, VRAMHardCapBytes: 1000, RAMTotalBytes: 4000, RAMHardCapBytes: 3000}, 1)
	for _, target := range manager.Targets() {
		if target.ID == "node-budget-too-wide" {
			t.Fatalf("adapter capacity exceeded inherited hard cap: %+v", target)
		}
	}
}

func TestNodeEnvelopePlacementCeilingRejectsNegativeAndContradictoryValues(t *testing.T) {
	if _, err := validateNodeCapabilityEnvelope(domain.CapabilityContractVersion, domain.ResidencyCapabilities{}, domain.CapacityBudget{}, -1); err == nil {
		t.Fatal("negative register/refresh placement ceiling was accepted")
	}
	if _, err := validateNodeCapabilityEnvelope(domain.CapabilityContractVersion, domain.ResidencyCapabilities{MaxAcceleratorsPerWorkload: 2}, domain.CapacityBudget{}, 1); err == nil {
		t.Fatal("contradictory register/refresh placement ceilings were accepted")
	}
	if normalized, err := validateNodeCapabilityEnvelope(domain.CapabilityContractVersion, domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0); err != nil || normalized != 1 {
		t.Fatalf("legacy zero placement ceiling was not normalized: max=%d err=%v", normalized, err)
	}
}

func TestAdapterCapabilityValidationFencesStateBeforeRegistration(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	srv.registerAdapterAdvertisements("node-contract", []wsproto.AdapterAdvertisement{{
		ID: "broken", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities:       domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SessionCheckpointVerified: true},
	}})
	for _, target := range manager.Targets() {
		if target.ID == "node-contract-broken" {
			t.Fatalf("invalid capability advertisement changed target state: %+v", manager.Targets())
		}
	}
	if _, err := srv.registerNode(context.Background(), wsproto.RegisterPayload{NodeID: "node-contract", CapabilityVersion: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsWarmRAM: true, WarmRAMVerified: true, WarmRAMVerification: "mincore", SupportsModelLifecycle: true, SupportsAcceleratorReclaim: true, MaxResidentModels: 4}, Capacity: domain.CapacityBudget{VRAMTotalBytes: 1024, VRAMReserveBytes: 128}, MaxAcceleratorsPerWorkload: 2}); err != nil {
		t.Fatal(err)
	}
	srv.registerAdapterAdvertisements("node-contract", []wsproto.AdapterAdvertisement{{
		ID: "valid", Adapter: "llamacpp", Endpoint: "http://node.invalid",
	}})
	var valid *workloads.Target
	for _, target := range manager.Targets() {
		if target.ID == "node-contract-valid" {
			copy := target
			valid = &copy
		}
	}
	if valid == nil || valid.CapabilityRevision != domain.CapabilityContractVersion || valid.MaxAcceleratorsPerWorkload != 2 || !valid.Capabilities.WarmRAMVerified || !valid.SupportsModelLifecycle || !valid.SupportsAcceleratorReclaim || valid.MaxResidentModels != 4 || valid.Capacity.VRAMReserveBytes != 128 {
		t.Fatalf("valid capability advertisement was not registered safely: %+v", manager.Targets())
	}
	srv.registerAdapterAdvertisements("node-nested", []wsproto.AdapterAdvertisement{{
		ID: "nested", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true, SupportsAcceleratorReclaim: true, MaxResidentModels: 4, SupportsWarmRAM: true},
	}})
	for _, target := range manager.Targets() {
		if target.ID == "node-nested-nested" {
			if !target.SupportsModelLifecycle || !target.SupportsAcceleratorReclaim || target.MaxResidentModels != 4 || !target.WarmRAMSupported {
				t.Fatalf("nested advertisement was not canonicalized into legacy fields: %+v", target)
			}
		}
	}
	srv.registerAdapterAdvertisements("node-identity", []wsproto.AdapterAdvertisement{{
		ID: "runtime", Adapter: "llamacpp", Endpoint: "http://node.invalid",
		Version: "runtime-v2", CapabilityVersion: domain.CapabilityContractVersion,
	}})
	for _, target := range manager.Targets() {
		if target.ID == "node-identity-runtime" {
			if target.CapabilityVersion != "runtime-v2" || target.CapabilityRevision != domain.CapabilityContractVersion {
				t.Fatalf("runtime identity was conflated with capability revision: %+v", target)
			}
			return
		}
	}
	t.Fatal("nested or identity capability advertisement was not registered")
}

func TestModelCapacityObservationRoundTripsIntoControllerStore(t *testing.T) {
	srv, manager, cancel := testServer(t)
	defer cancel()
	now := time.Now().UTC()
	advertisement := wsproto.AdapterAdvertisement{
		ID: "runtime", Adapter: "llamacpp", Endpoint: "http://node.invalid", Version: "runtime-v1",
		CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Models: []string{"model"}, ResidentModels: []string{"model"}, ModelFingerprint: "model-fp",
		Capacity:     domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30},
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, MaxResidentModels: 2},
		ModelCapacityObservations: []wsproto.ModelCapacityObservationAdvertisement{{
			AcceleratorID: "node-observe-gpu0", Model: "model", ModelFingerprint: "model-fp",
			RuntimeIdentity:   "node-observe-runtime|llamacpp||runtime-v1|model-fp",
			CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
			ModelBytes: 4 << 30, VRAMTotalBytes: 16 << 30, RuntimeHardCapBytes: 16 << 30,
			ObservedAt: now, Source: "runtime:/api/ps:size_vram", Verified: true,
		}},
	}
	wire, err := json.Marshal(advertisement)
	if err != nil {
		t.Fatal(err)
	}
	var decoded wsproto.AdapterAdvertisement
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("authoritative observation failed JSON roundtrip: %v", err)
	}
	if _, err := srv.registerNode(context.Background(), wsproto.RegisterPayload{NodeID: "node-observe", CapabilityVersion: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, MaxAcceleratorsPerWorkload: 1}); err != nil {
		t.Fatal(err)
	}
	if err := srv.registerAdapterAdvertisementsWithDefaults("node-observe", []wsproto.AdapterAdvertisement{decoded}, domain.CapabilityContractVersion, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, domain.CapacityBudget{}, 1); err != nil {
		t.Fatalf("controller rejected authoritative observation: %v", err)
	}
	row, err := manager.ModelCapacity(context.Background(), "node-observe-runtime", "model", "")
	if err != nil {
		t.Fatalf("controller did not persist observation: %v", err)
	}
	if row.ModelBytes != 4<<30 || row.AcceleratorID != "node-observe-gpu0" || row.CapacitySource != "runtime:/api/ps:size_vram" || !row.Verified || row.ObservedAt.IsZero() {
		t.Fatalf("persisted observation lost authoritative fields: %+v", row)
	}
}

func TestModelCapacityObservationRejectsSpoofedAndStaleBindings(t *testing.T) {
	base := wsproto.AdapterAdvertisement{
		ID: "runtime", Adapter: "llamacpp", Endpoint: "http://node.invalid", Version: "runtime-v1",
		CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		Models: []string{"model"}, ResidentModels: []string{"model"}, ModelFingerprint: "model-fp",
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion},
	}
	valid := wsproto.ModelCapacityObservationAdvertisement{
		AcceleratorID: "node-spoof-gpu0", Model: "model", ModelFingerprint: "model-fp",
		RuntimeIdentity: "node-spoof-runtime|llamacpp||runtime-v1|model-fp", CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion,
		ModelBytes: 1, ObservedAt: time.Now().UTC(), Source: "runtime:/api/ps:size_vram", Verified: true,
	}
	for _, tc := range []struct {
		name   string
		mutate func(*wsproto.ModelCapacityObservationAdvertisement)
	}{
		{name: "spoofed-source", mutate: func(o *wsproto.ModelCapacityObservationAdvertisement) { o.Source = "configured:vram" }},
		{name: "unrecognized-runtime-source", mutate: func(o *wsproto.ModelCapacityObservationAdvertisement) { o.Source = "runtime:spoofed-bytes" }},
		{name: "spoofed-accelerator", mutate: func(o *wsproto.ModelCapacityObservationAdvertisement) { o.AcceleratorID = "other-gpu" }},
		{name: "stale", mutate: func(o *wsproto.ModelCapacityObservationAdvertisement) {
			o.ObservedAt = time.Now().UTC().Add(-25 * time.Hour)
		}},
		{name: "unverified", mutate: func(o *wsproto.ModelCapacityObservationAdvertisement) { o.Verified = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := valid
			tc.mutate(&observation)
			advertisement := base
			advertisement.ModelCapacityObservations = []wsproto.ModelCapacityObservationAdvertisement{observation}
			if _, err := buildAdapterPlans("node-spoof", []wsproto.AdapterAdvertisement{advertisement}, domain.CapabilityContractVersion, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, domain.CapacityBudget{}, 1); err == nil {
				t.Fatal("invalid observation was accepted")
			}
		})
	}
	multi := base
	multi.Models = []string{"model", "model-b"}
	multi.ResidentModels = []string{"model", "model-b"}
	second := valid
	second.Model = "model-b"
	multi.ModelCapacityObservations = []wsproto.ModelCapacityObservationAdvertisement{valid, second}
	if _, err := buildAdapterPlans("node-spoof", []wsproto.AdapterAdvertisement{multi}, domain.CapabilityContractVersion, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, domain.CapacityBudget{}, 1); err == nil {
		t.Fatal("multi-model capacity advertisement was accepted")
	}
}

func TestMultiRowRuntimeObservationFailsNodeWireControllerWithoutStoreWrites(t *testing.T) {
	const nodeID = "node-multi"
	const runtimeIdentity = nodeID + "-runtime|llamacpp||runtime-v1|fleet-fingerprint"
	now := time.Now().UTC()
	advertisement := wsproto.AdapterAdvertisement{ID: "runtime", Adapter: "llamacpp", Endpoint: "http://node.invalid", Version: "runtime-v1", CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, Models: []string{"model-a", "model-b"}, ResidentModels: []string{"model-a", "model-b"}, ModelFingerprint: "fleet-fingerprint", Capacity: domain.CapacityBudget{VRAMTotalBytes: 16 << 30, VRAMHardCapBytes: 16 << 30}, ModelCapacityObservations: []wsproto.ModelCapacityObservationAdvertisement{
		{AcceleratorID: nodeID + "-gpu0", Model: "model-a", ModelFingerprint: "fleet-fingerprint", RuntimeIdentity: runtimeIdentity, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelBytes: 1 << 30, ObservedAt: now, Source: "runtime:/api/ps:size_vram", Verified: true},
		{AcceleratorID: nodeID + "-gpu0", Model: "model-b", ModelFingerprint: "fleet-fingerprint", RuntimeIdentity: runtimeIdentity, CapabilityVersion: "runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, ModelBytes: 1 << 30, ObservedAt: now, Source: "runtime:/api/ps:size_vram", Verified: true},
	}}
	wire, err := json.Marshal(advertisement)
	if err != nil {
		t.Fatal(err)
	}
	var decoded wsproto.AdapterAdvertisement
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	srv, manager, cancel := testServer(t)
	defer cancel()
	if _, err := srv.registerNode(context.Background(), wsproto.RegisterPayload{NodeID: nodeID, CapabilityVersion: domain.CapabilityContractVersion, Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, MaxAcceleratorsPerWorkload: 1}); err != nil {
		t.Fatal(err)
	}
	if err := srv.registerAdapterAdvertisementsWithDefaults(nodeID, []wsproto.AdapterAdvertisement{decoded}, domain.CapabilityContractVersion, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion}, domain.CapacityBudget{}, 1); err == nil {
		t.Fatal("multi-row runtime observation crossed controller validation")
	}
	if _, err := manager.ModelCapacity(context.Background(), nodeID+"-runtime", "model-a", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rejected multi-row observation left durable store state: err=%v", err)
	}
}
