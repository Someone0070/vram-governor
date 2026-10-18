package workloads

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestLocalLLMInstantPerformanceIsAlwaysPublished(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"instant","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer backend.Close()
	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	request := domain.WorkloadRequest{Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hi"}]}`)}
	for i := 0; i < 1000; i++ {
		handle, err := adapter.Start(context.Background(), request, nil, Target{ID: "instant", Endpoint: backend.URL})
		if err != nil {
			t.Fatalf("instant local LLM request %d failed: %v", i, err)
		}
		if handle.Performance == nil || handle.Performance.DurationMS < 1 || handle.Performance.TotalTPS <= 0 {
			t.Fatalf("instant local LLM request %d published incomplete performance: %+v", i, handle.Performance)
		}
	}
}

type rawClockFixture struct {
	times []clockSample
	index int
	bad   bool
	calls int
	mu    sync.Mutex
}

func (c *rawClockFixture) now() clockSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.index >= len(c.times) {
		c.bad = true
		return c.times[len(c.times)-1]
	}
	value := c.times[c.index]
	c.index++
	return value
}

func (c *rawClockFixture) elapsed(start, end clockSample) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	expectedEnd := c.times[len(c.times)-1]
	if len(c.times) == 3 && end.token == c.times[1].token {
		expectedEnd = c.times[1]
	}
	if start.token != c.times[0].token || start.wall != c.times[0].wall || end.token != expectedEnd.token || end.wall != expectedEnd.wall {
		c.bad = true
	}
	if len(c.times) == 3 && end.token == c.times[1].token {
		return 40 * time.Millisecond
	}
	return 125 * time.Millisecond
}

func brokenUTCClockSample(sample clockSample) clockSample {
	return clockSample{wall: sample.wall.UTC(), token: sample.token}
}

func TestClockSampleRejectsUTCReconstruction(t *testing.T) {
	startLocation := time.FixedZone("known-broken-start", -7*60*60)
	finishLocation := time.FixedZone("known-broken-finish", 5*60*60)
	fixture := &rawClockFixture{times: []clockSample{{wall: time.Date(2026, time.January, 1, 12, 0, 0, 0, startLocation), token: 1}, {wall: time.Date(2026, time.January, 2, 6, 0, 0, 0, finishLocation), token: 2}}}
	_ = fixture.elapsed(fixture.times[0], brokenUTCClockSample(fixture.times[1]))
	if !fixture.bad {
		t.Fatal("known-broken UTC sample reconstruction was accepted by the elapsed hook")
	}
	dropped := &rawClockFixture{times: fixture.times}
	_ = dropped.elapsed(clockSample{wall: fixture.times[0].wall}, clockSample{wall: fixture.times[1].wall})
	if !dropped.bad {
		t.Fatal("known-broken opaque-token drop was accepted by the elapsed hook")
	}
}

func (c *rawClockFixture) valid(expectedCalls, expectedTimes int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.bad && c.calls == expectedCalls && c.index == expectedTimes
}

func TestLocalLLMInjectedClockReceivesRawTokensAcrossAllPaths(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "text/event-stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n"))
			_, _ = w.Write([]byte("data: {\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3,\"total_tokens\":5}}\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"clocked","usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}`))
	}))
	defer backend.Close()

	request := domain.WorkloadRequest{Payload: json.RawMessage(`{"model":"model","messages":[{"role":"user","content":"hi"}]}`)}
	for _, backward := range []bool{false, true} {
		startLoc := time.FixedZone("raw-start", -7*60*60)
		finishLoc := time.FixedZone("raw-finish", 5*60*60)
		startWall := time.Date(2026, time.January, 1, 12, 0, 0, 0, startLoc)
		finishDate := time.January
		finishDay := 2
		if backward {
			finishDay = 1
		}
		finishWall := time.Date(2026, finishDate, finishDay, 6, 0, 0, 0, finishLoc)
		if backward && !finishWall.UTC().Before(startWall.UTC()) {
			t.Fatalf("backward fixture is not backward in UTC: start=%v finish=%v", startWall.UTC(), finishWall.UTC())
		}
		if !backward && !finishWall.UTC().After(startWall.UTC()) {
			t.Fatalf("forward fixture is not forward in UTC: start=%v finish=%v", startWall.UTC(), finishWall.UTC())
		}
		start := clockSample{wall: startWall, token: 100}
		finish := clockSample{wall: finishWall, token: 101}
		first := clockSample{wall: startWall.Add(time.Minute), token: 102}

		runSync := func() {
			clock := &rawClockFixture{times: []clockSample{start, finish}}
			adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
			adapter.setClockForTest(clock.now, clock.elapsed)
			handle, err := adapter.Start(context.Background(), request, nil, Target{ID: "clocked", Endpoint: backend.URL})
			if err != nil || !exactLLMPerformance(handle.Performance, "gateway_wall_clock", false) || !clock.valid(1, 2) {
				t.Fatalf("sync path transformed raw clock tokens or measured wall time: handle=%+v err=%v", handle, err)
			}
		}
		runSync()

		runAsync := func() {
			clock := &rawClockFixture{times: []clockSample{start, finish}}
			adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
			adapter.setClockForTest(clock.now, clock.elapsed)
			handle, err := adapter.StartAsync(context.Background(), request, nil, Target{ID: "clocked", Endpoint: backend.URL})
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for {
				observation, observeErr := adapter.Observe(context.Background(), request, nil, handle, Target{})
				if observeErr != nil {
					t.Fatal(observeErr)
				}
				if observation.Status == domain.WorkloadSucceeded {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("async clocked request did not complete")
				}
				time.Sleep(time.Millisecond)
			}
			if !exactLLMPerformance(handle.Performance, "gateway_wall_clock_async", false) || !clock.valid(1, 2) {
				t.Fatalf("async path transformed raw clock tokens or measured wall time: handle=%+v", handle)
			}
		}
		runAsync()

		runStream := func() {
			clock := &rawClockFixture{times: []clockSample{start, first, finish}}
			adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
			adapter.setClockForTest(clock.now, clock.elapsed)
			handle, err := adapter.StartStream(context.Background(), request, nil, Target{ID: "clocked", Endpoint: backend.URL}, func([]byte) error { return nil })
			if err != nil || !exactLLMPerformance(handle.Performance, "gateway_wall_clock_stream", true) || !clock.valid(2, 3) {
				clock.mu.Lock()
				t.Fatalf("stream path transformed raw clock tokens or measured wall time: handle=%+v err=%v index=%d calls=%d bad=%v", handle, err, clock.index, clock.calls, clock.bad)
			}
		}
		runStream()
	}
}

func TestLiveStreamStitchesRepeatedPrefixAndCanonicalizesDone(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"resumed\",\"choices\":[{\"delta\":{\"content\":\"hello world\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"resumed\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0}]}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"resumed\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\ndata: [DONE]\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"post-done\"}}]}\n\n"))
	}))
	defer backend.Close()

	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	request := domain.WorkloadRequest{ID: "stream-stitch", Payload: json.RawMessage(`{"model":"model"}`)}
	base := &PartialOutput{
		Prefix:           []byte("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"),
		AssistantContent: []byte("hello"),
	}
	var mu sync.Mutex
	var chunks [][]byte
	handle, err := adapter.startLiveStream(context.Background(), request, nil, Target{ID: "target", Endpoint: backend.URL}, []byte(`{"model":"model","stream":true}`), func(chunk []byte) error {
		mu.Lock()
		chunks = append(chunks, append([]byte(nil), chunk...))
		mu.Unlock()
		return nil
	}, base.Prefix, -1, "continuation", base)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		observation, observeErr := adapter.Observe(context.Background(), request, nil, handle, Target{ID: "target", Endpoint: backend.URL})
		if observeErr != nil {
			t.Fatal(observeErr)
		}
		if observation.Status == domain.WorkloadSucceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live stream did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	body := append([]byte(nil), base.Prefix...)
	for _, chunk := range chunks {
		body = append(body, chunk...)
	}
	mu.Unlock()
	got := string(body)
	if strings.Count(got, "hello") != 1 || strings.Count(got, "world") != 1 {
		t.Fatalf("repeated assistant prefix was emitted or suffix lost: %q", got)
	}
	if strings.Count(got, "[DONE]") != 1 || strings.Contains(got, "post-done") {
		t.Fatalf("terminal stream was not canonicalized: %q", got)
	}
	if !strings.Contains(got, "tool_calls") || !strings.Contains(got, "prompt_tokens") {
		t.Fatalf("valid tool/usage events were not preserved: %q", got)
	}
	// PostgreSQL stores the workload row as JSON; raw SSE in the handle made
	// every finished stream unpersistable (stuck "running").
	if _, marshalErr := json.Marshal(handle); marshalErr != nil {
		t.Fatalf("completed stream handle is not JSON-serializable: %v", marshalErr)
	}
}

func TestLiveStreamMissingDoneIsVisibleFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"))
	}))
	defer backend.Close()
	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	request := domain.WorkloadRequest{ID: "stream-missing-done", Payload: json.RawMessage(`{"model":"model"}`)}
	handle, err := adapter.StartStreamLive(context.Background(), request, nil, Target{ID: "target", Endpoint: backend.URL}, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, observeErr := adapter.Observe(context.Background(), request, nil, handle, Target{ID: "target", Endpoint: backend.URL})
		if observeErr != nil {
			if !strings.Contains(observeErr.Error(), "[DONE]") {
				t.Fatalf("missing-DONE failure did not identify terminal marker: %v", observeErr)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("missing-DONE stream never became observable failure")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReleaseCheckpointBindingDoesNotReleaseAfterCancelFailure(t *testing.T) {
	adapter := NewHTTPAdapter("llamacpp", "llama", nil)
	var mu sync.Mutex
	var commands []string
	adapter.ConfigureCheckpointChannel(func(_ context.Context, _ Target) (NodeControl, string, bool) {
		return func(_ context.Context, _ string, command string, _ map[string]any, _ string) (map[string]any, error) {
			mu.Lock()
			commands = append(commands, command)
			mu.Unlock()
			switch command {
			case "checkpoint_cancel":
				return nil, errors.New("cancel-control-failed")
			case "checkpoint_release":
				return nil, errors.New("release-control-failed")
			default:
				return map[string]any{}, nil
			}
		}, "node", true
	})
	handle := &domain.ExecutionHandle{ExternalID: "cleanup", Opaque: json.RawMessage(`{"slot_id":0,"generation":1,"fence":2,"accelerator_id":"gpu","conversation_id":"continuation-op","operation_id":"op","owner_id":"owner","workload_id":"work","resumed":true}`)}
	adapter.checkpointMu.Lock()
	adapter.checkpointRuns[handle.ExternalID] = checkpointExecution{Request: domain.WorkloadRequest{ID: "work", OwnerID: "owner"}, Target: Target{ID: "target"}, OperationID: "op", Lease: SlotLease{TargetID: "target", NodeID: "node", AcceleratorID: "gpu", SlotID: 0, OwnerID: "owner", WorkloadID: "work", Generation: 1, Fence: 2}, Resumed: true, ConversationID: "continuation-op", OperationConversationID: "conversation-op"}
	adapter.checkpointMu.Unlock()
	err := adapter.releaseCheckpointBinding(context.Background(), handle, Target{ID: "target", RuntimeIdentity: "runtime"})
	if err == nil || !strings.Contains(err.Error(), "cancel-control-failed") || strings.Contains(err.Error(), "release-control-failed") {
		t.Fatalf("cleanup dropped signed failures: %v", err)
	}
	mu.Lock()
	gotCommands := append([]string(nil), commands...)
	mu.Unlock()
	if !hasCommand(gotCommands, "checkpoint_cancel") || hasCommand(gotCommands, "checkpoint_release") {
		t.Fatalf("cleanup released after an unconfirmed cancel: %v", gotCommands)
	}
}

func hasCommand(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestStartStreamMissingDoneReturnsProtocolError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[]}\n\n"))
	}))
	defer backend.Close()
	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	_, err := adapter.StartStream(context.Background(), domain.WorkloadRequest{Payload: json.RawMessage(`{"model":"model"}`)}, nil, Target{ID: "target", Endpoint: backend.URL}, func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "[DONE]") {
		t.Fatalf("blocking stream accepted EOF without DONE: %v", err)
	}
}

func TestStartStreamLiveReturnsTransportFailureAtStart(t *testing.T) {
	adapter := NewHTTPAdapter("llamacpp", "llama", nil)
	_, err := adapter.StartStreamLive(context.Background(), domain.WorkloadRequest{Payload: json.RawMessage(`{"model":"model"}`)}, nil, Target{ID: "target", Endpoint: "://invalid"}, func([]byte) error { return nil })
	if err == nil {
		t.Fatal("live stream hid a transport/startup failure in an unobservable goroutine")
	}
}

func exactLLMPerformance(performance *domain.ExecutionPerformance, source string, expectTTFT bool) bool {
	if performance == nil || performance.Source != source || performance.DurationMS != 125 || performance.PromptTokens != 2 || performance.CompletionTokens != 3 || performance.TotalTokens != 5 || performance.PromptTPS != 16 || performance.DecodeTPS != 24 || performance.TotalTPS != 40 {
		return false
	}
	if expectTTFT {
		return performance.TTFTMS == 40
	}
	return performance.TTFTMS == 0
}

func TestRouterModelStateTriStateAndMalformedEnvelope(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		state routerModelState
		err   bool
	}{
		{name: "absent_is_unloaded", body: `{"data":[]}`, state: routerModelUnloaded},
		{name: "explicit_unloaded", body: `{"data":[{"id":"model","status":"unloaded"}]}`, state: routerModelUnloaded},
		{name: "explicit_loaded", body: `{"data":[{"id":"model","status":"loaded"}]}`, state: routerModelLoadedState},
		{name: "transitional_is_unknown", body: `{"data":[{"id":"model","status":"loading"}]}`, state: routerModelUnknown},
		{name: "malformed_json", body: `{`, err: true},
		{name: "malformed_envelope", body: `{"data":null}`, err: true},
		{name: "malformed_entry", body: `{"data":[{}]}`, err: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := routerModelLoaded([]byte(test.body), "model")
			if test.err {
				if err == nil {
					t.Fatalf("malformed router response was accepted: state=%v", state)
				}
				return
			}
			if err != nil || state != test.state {
				t.Fatalf("router state=%v err=%v, want state=%v", state, err, test.state)
			}
		})
	}
}

func TestRouterModelStateRequiresByteExactStatus(t *testing.T) {
	for _, body := range []string{
		`{"data":[{"id":"model","status":"Loaded"}]}`,
		`{"data":[{"id":"model","status":" loaded"}]}`,
		`{"data":[{"id":"model","status":"loaded "}]}`,
	} {
		if _, err := routerModelLoaded([]byte(body), "model"); err == nil {
			t.Fatalf("noncanonical router status was accepted: %s", body)
		}
	}
}

func TestLlamaRouterTransitionalStateWaitsAndMalformedFails(t *testing.T) {
	transitional := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models/load" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"data":[{"id":"model","status":"loading"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer transitional.Close()
	adapter := NewHTTPAdapter("llamacpp", "llama", transitional.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	err := adapter.LoadModel(ctx, Target{ID: "router", Endpoint: transitional.URL, SupportsModelLifecycle: true}, "model")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("transitional model state should poll until timeout, got %v", err)
	}

	malformed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models/load" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"data":`))
			return
		}
		http.NotFound(w, r)
	}))
	defer malformed.Close()
	malformedAdapter := NewHTTPAdapter("llamacpp", "llama", malformed.Client())
	if err := malformedAdapter.LoadModel(context.Background(), Target{ID: "router", Endpoint: malformed.URL, SupportsModelLifecycle: true}, "model"); err == nil {
		t.Fatal("malformed model envelope was accepted")
	}
}

func controllerTarget() Target {
	return Target{
		ID: "node-1-llama", Adapter: "llamacpp", RuntimeProtocol: "ollama",
		AcceleratorID: "node-1-gpu0", Models: []string{"model"},
		CapabilityVersion: "ollama-runtime-v1", CapabilityRevision: domain.CapabilityContractVersion, SupportsModelLifecycle: true,
		Capabilities: domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: true,
			SupportsWarmRAM: true, WarmRAMVerified: true, WarmRAMVerification: "mincore+lock",
			MaxAcceleratorsPerWorkload: 1},
		MaxAcceleratorsPerWorkload: 1, Enabled: true,
	}
}

func TestControllerAdapterRejectsUnavailableCapability(t *testing.T) {
	target := controllerTarget()
	target.CapabilityRevision = "fleet-residency.v0"
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("unavailable capability reached command boundary")
		return nil, nil
	}})
	var got *ResidencyAdapterError
	if _, gotErr := adapter.Transition(context.Background(), target, "model", domain.ResidencyHotVRAM); !errors.As(gotErr, &got) || got.Code != ResidencyBlockerCapabilityUnavailable {
		t.Fatalf("expected capability blocker, got %v", gotErr)
	}
}

func TestControllerAdapterRejectsEmptyRuntimeCapabilityIdentity(t *testing.T) {
	target := controllerTarget()
	target.CapabilityVersion = ""
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("empty runtime identity reached node control")
		return nil, nil
	}})
	var got *ResidencyAdapterError
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerIdentityMismatch {
		t.Fatalf("expected empty runtime identity blocker, got %v", err)
	}
}

func TestControllerAdapterKnownBrokenCapabilityControl(t *testing.T) {
	target := controllerTarget()
	target.Capabilities = domain.ResidencyCapabilities{}
	target.WarmRAMSupported = true // support alone must never mint a warm promise.
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("support-only warm claim reached command boundary")
		return nil, nil
	}})
	var got *ResidencyAdapterError
	if err := adapter.OffloadModelToRAM(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerCapabilityUnavailable {
		t.Fatalf("expected verified warm capability blocker, got %v", err)
	}
}

func TestControllerAdapterUsesCanonicalIdentityAndFence(t *testing.T) {
	target := controllerTarget()
	var mu sync.Mutex
	var commands []string
	var fences []int64
	command := func(_ context.Context, nodeID, name string, args map[string]any, key string) (map[string]any, error) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, nodeID+":"+name+":"+key)
		fences = append(fences, args["fencing_token"].(int64))
		if args["target_kind"] != "llamacpp" || args["target_id"] != target.ID || args["model"] != "model" || args["runtime_identity"] != "node-1-llama|llamacpp|ollama|ollama-runtime-v1|" {
			t.Fatalf("non-canonical command args: %#v", args)
		}
		resident := name == "load_model"
		return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": map[bool]string{true: "hot_vram", false: "cold_disk"}[resident], "resident": resident, "warm_ram": false}, nil
	}
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: command})
	if err := adapter.LoadModel(context.Background(), target, "model"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.UnloadModel(context.Background(), target, "model"); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || fences[0] >= fences[1] || fences[0] != 1 || fences[1] != 2 || commands[0] == commands[1] {
		t.Fatalf("expected monotonic fenced idempotent commands, commands=%v fences=%v", commands, fences)
	}
}

func TestControllerAdapterBoundsPollingAndCancellation(t *testing.T) {
	target := controllerTarget()
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{TransitionTimeout: 20 * time.Millisecond, Command: func(ctx context.Context, _ string, _ string, _ map[string]any, _ string) (map[string]any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	var got *ResidencyAdapterError
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerTransitionTimeout || !got.IsIndeterminate() {
		t.Fatalf("expected bounded timeout, got %v", err)
	}
	if len(adapter.PendingTransitions()) != 1 {
		t.Fatal("timeout must retain an uncertain pending transition for reconciliation")
	}
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerTransitionBusy {
		t.Fatalf("expected pending blocker after timeout, got %v", err)
	}
}

func TestControllerAdapterReconcilesLateNodeResultBeforeNewCommand(t *testing.T) {
	target := controllerTarget()
	backing := store.NewMemoryStore()
	var calls int
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Store: backing, TransitionTimeout: 10 * time.Millisecond, PollInterval: time.Millisecond, Command: func(ctx context.Context, _ string, name string, args map[string]any, _ string) (map[string]any, error) {
		calls++
		if calls == 1 {
			time.Sleep(20 * time.Millisecond) // node completes after controller timeout
		}
		if ctx.Err() != nil && calls == 1 {
			return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "hot_vram", "resident": true, "warm_ram": false}, nil
		}
		if name != "load_model" && name != "query_model_state" {
			t.Fatalf("unexpected reconciliation command %s", name)
		}
		return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "fencing_token": args["fencing_token"], "tier": "hot_vram", "resident": true, "warm_ram": false}, nil
	}})
	_, err := adapter.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyHotVRAM, "late-key")
	var indeterminate *ResidencyAdapterError
	if !errors.As(err, &indeterminate) || !indeterminate.IsIndeterminate() {
		t.Fatalf("expected indeterminate timeout, got %v", err)
	}
	if _, err := adapter.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyColdDisk, "new-key"); err == nil {
		t.Fatal("new command crossed unresolved late result")
	}
	observation, err := adapter.TransitionWithIdempotency(context.Background(), target, "model", domain.ResidencyHotVRAM, "late-key")
	if err != nil || observation.Tier != domain.ResidencyHotVRAM || calls != 2 {
		t.Fatalf("late result was not reconciled exactly: observation=%+v calls=%d err=%v", observation, calls, err)
	}
}

func TestControllerAdapterRejectsStaleResults(t *testing.T) {
	target := controllerTarget()
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(_ context.Context, _ string, _ string, _ map[string]any, _ string) (map[string]any, error) {
		return map[string]any{"target_id": target.ID, "model": "model", "runtime_identity": "node-1-llama|llamacpp|ollama|ollama-runtime-v1|", "resident": true, "warm_ram": false, "tier": "hot_vram", "fencing_token": int64(0)}, nil
	}})
	var got *ResidencyAdapterError
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerStaleResult {
		t.Fatalf("expected stale result blocker, got %v", err)
	}
}

func TestControllerAdapterNodeReadinessAndSingleCardCeiling(t *testing.T) {
	target := controllerTarget()
	target.AcceleratorID = ""
	adapter := NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Command: func(context.Context, string, string, map[string]any, string) (map[string]any, error) {
		t.Fatal("target without owning node reached command boundary")
		return nil, nil
	}})
	var got *ResidencyAdapterError
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerNodeNotReady {
		t.Fatalf("expected node readiness blocker, got %v", err)
	}
	target = controllerTarget()
	target.MaxAcceleratorsPerWorkload = 2
	if err := adapter.LoadModel(context.Background(), target, "model"); !errors.As(err, &got) || got.Code != ResidencyBlockerRuntimeUnsupported {
		t.Fatalf("expected one-card ceiling blocker, got %v", err)
	}
}

func TestResponsesStreamEndsAtResponseCompleted(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("responses request went to %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: response.created\ndata: {\"type\":\"response.created\"}\n\n"))
		_, _ = w.Write([]byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n"))
		_, _ = w.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"))
	}))
	defer backend.Close()
	adapter := NewHTTPAdapter("llamacpp", "llama", backend.Client())
	request := domain.WorkloadRequest{ID: "responses-stream", WorkloadType: WorkloadTypeResponses, Payload: json.RawMessage(`{"model":"model","input":"hi","stream":true}`)}
	var mu sync.Mutex
	var body []byte
	handle, err := adapter.startLiveStream(context.Background(), request, nil, Target{ID: "target", Endpoint: backend.URL}, request.Payload, func(chunk []byte) error {
		mu.Lock()
		body = append(body, chunk...)
		mu.Unlock()
		return nil
	}, nil, -1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		observation, observeErr := adapter.Observe(context.Background(), request, nil, handle, Target{ID: "target", Endpoint: backend.URL})
		if observeErr != nil {
			t.Fatalf("a Responses stream without [DONE] must not fail: %v", observeErr)
		}
		if observation.Status == domain.WorkloadSucceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("responses stream did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	got := string(body)
	mu.Unlock()
	if !strings.Contains(got, "response.completed") || strings.Contains(got, "[DONE]") {
		t.Fatalf("responses events were not forwarded unchanged: %q", got)
	}
}
