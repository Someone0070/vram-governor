package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

type openAIBusyBody struct {
	Error struct {
		Message    string `json:"message"`
		Type       string `json:"type"`
		Code       string `json:"code"`
		WorkloadID string `json:"workload_id"`
	} `json:"error"`
	Admission         domain.AdmissionDecision `json:"admission"`
	RetryAfterSeconds int                      `json:"retry_after_seconds"`
	NotificationID    string                   `json:"notification_id"`
}

func TestOpenAIBusyResponseStatusFollowsBlockerCode(t *testing.T) {
	retry := time.Now().Add(90 * time.Second)
	cases := []struct {
		code   domain.AdmissionBlocker
		status int
	}{
		{domain.BlockerCapacity, http.StatusTooManyRequests},
		{domain.BlockerTransitionBusy, http.StatusTooManyRequests},
		{domain.BlockerPinnedResident, http.StatusTooManyRequests},
		{domain.BlockerLockedWorkload, http.StatusTooManyRequests},
		{domain.BlockerNodeOffline, http.StatusServiceUnavailable},
		{domain.BlockerRuntimeUnsupported, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		// The free text says "busy" on purpose: the old handler string-matched
		// it to 429. The code must win, so node_offline still answers 503.
		row := &domain.Workload{Request: domain.WorkloadRequest{ID: "wl-" + string(tc.code)}, Status: domain.WorkloadWaiting, Decision: domain.AdmissionDecision{Blocker: "gpu busy", BlockerCode: tc.code, RetryAfter: &retry, NotificationID: "wl-" + string(tc.code)}}
		recorder := httptest.NewRecorder()
		writeOpenAIBusy(recorder, row)
		if recorder.Code != tc.status {
			t.Fatalf("code %s: status=%d want %d", tc.code, recorder.Code, tc.status)
		}
		var body openAIBusyBody
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != string(tc.code) || body.Error.WorkloadID != row.Request.ID || body.NotificationID != row.Request.ID || body.Admission.BlockerCode != tc.code {
			t.Fatalf("code %s: body=%+v", tc.code, body)
		}
		header, _ := strconv.Atoi(recorder.Header().Get("Retry-After"))
		if body.RetryAfterSeconds < 85 || body.RetryAfterSeconds > 90 || header != body.RetryAfterSeconds {
			t.Fatalf("code %s: retry_after_seconds=%d header=%d", tc.code, body.RetryAfterSeconds, header)
		}
	}
	// Rows persisted before codes existed fall back to text classification.
	recorder := httptest.NewRecorder()
	writeOpenAIBusy(recorder, &domain.Workload{Request: domain.WorkloadRequest{ID: "legacy"}, Status: domain.WorkloadRejected, Decision: domain.AdmissionDecision{Blocker: "no eligible capacity (fail_fast)", Alternatives: []string{"t: node disconnected or not ready"}}})
	var legacy openAIBusyBody
	_ = json.Unmarshal(recorder.Body.Bytes(), &legacy)
	if recorder.Code != http.StatusServiceUnavailable || legacy.Error.Code != string(domain.BlockerNodeOffline) || legacy.NotificationID != "" || legacy.RetryAfterSeconds != 1 {
		t.Fatalf("legacy row: status=%d body=%+v", recorder.Code, legacy)
	}
}

func newOpenAIBlockerGateway(t *testing.T, credential CredentialConfig, backend http.Handler) (*workloads.Manager, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(backend)
	t.Cleanup(upstream.Close)
	cfg := &Config{}
	cfg.Auth.Credentials = []CredentialConfig{credential}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	manager := workloads.NewManager(logger, backing, time.Second)
	manager.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", nil))
	manager.RegisterTarget(workloads.Target{ID: "one-slot", Adapter: "llamacpp", Endpoint: upstream.URL, Models: []string{"m"}, ContextLimit: 4096, Slots: 1, CapacityVerified: true, Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager.Start(ctx)
	srv := NewServer(cfg, logger, backing, nil, nil)
	srv.SetWorkloadManager(manager)
	gateway := httptest.NewServer(srv.Handler())
	t.Cleanup(gateway.Close)
	return manager, gateway
}

func postOpenAIChat(t *testing.T, gateway *httptest.Server, body string) (int, openAIBusyBody) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := gateway.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var decoded openAIBusyBody
	_ = json.Unmarshal(raw, &decoded)
	return resp.StatusCode, decoded
}

func TestOpenAIUnservedModelIsModelNotFound(t *testing.T) {
	credential := CredentialConfig{ID: "client", Token: "client-token", OwnerID: "owner", Plane: "api", Scopes: []string{"inference:submit"}, Adapters: []string{"llamacpp"}, MaxPriority: 10, EgressPolicy: "local_only"}
	_, gateway := newOpenAIBlockerGateway(t, credential, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend must not be called for an unserved model")
	}))
	// OpenAI clients treat a misspelled model as a 404 model_not_found, not a
	// retryable capacity problem.
	status, body := postOpenAIChat(t, gateway, `{"model":"not-served","messages":[{"role":"user","content":"x"}],"governor":{"context_tokens":256}}`)
	if status != http.StatusNotFound || body.Error.Code != "model_not_found" || !strings.Contains(body.Error.Message, "not-served") {
		t.Fatalf("status=%d body=%+v", status, body)
	}
}

func TestOpenAIWaitTimeoutReportsLatestDecision(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	credential := CredentialConfig{ID: "client", Token: "client-token", OwnerID: "owner", Plane: "api", Scopes: []string{"inference:submit"}, Adapters: []string{"llamacpp"}, MaxPriority: 10, EgressPolicy: "local_only", DefaultQueuePolicy: "wait", MaxQueueWaitSeconds: 2}
	manager, gateway := newOpenAIBlockerGateway(t, credential, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}))
	defer close(release)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", bytes.NewReader([]byte(`{"model":"m","messages":[{"role":"user","content":"holder"}],"governor":{"context_tokens":256}}`)))
		req.Header.Set("Authorization", "Bearer client-token")
		if resp, err := gateway.Client().Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("holder request never reached the backend")
	}
	// While the second request waits, the route is quarantined. The submit-time
	// row said "slots busy" (429); the latest decision says the route is gone.
	go func() {
		time.Sleep(500 * time.Millisecond)
		target := manager.Targets()[0]
		target.Quarantined = true
		manager.RegisterTarget(target)
	}()
	status, body := postOpenAIChat(t, gateway, `{"model":"m","messages":[{"role":"user","content":"waiter"}],"governor":{"context_tokens":256}}`)
	if status != http.StatusServiceUnavailable || body.Error.Code != string(domain.BlockerNodeOffline) || !strings.Contains(body.Admission.Blocker, "quarantined") {
		t.Fatalf("timeout response used a stale decision: status=%d body=%+v", status, body)
	}
	if body.Error.WorkloadID == "" || body.RetryAfterSeconds < 1 {
		t.Fatalf("timeout response is missing identifiers: %+v", body)
	}
}

func TestOpenAISchedulingControlsPrecedence(t *testing.T) {
	request := func(headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		return r
	}
	bare := Principal{}
	credential := Principal{DefaultQueuePolicy: "fail_fast", MaxQueueWaitSeconds: 60}
	cases := []struct {
		name      string
		r         *http.Request
		p         Principal
		bodyQueue string
		bodyWait  int
		defQueue  string
		defWait   int
		queue     domain.QueuePolicy
		wait      time.Duration
	}{
		{"built-in fallback", request(nil), bare, "", 0, "", 0, domain.QueueFailFast, 120 * time.Second},
		{"workloads default", request(nil), bare, "", 0, "wait", 300, domain.QueueWait, 300 * time.Second},
		{"credential beats workloads default", request(nil), credential, "", 0, "wait", 300, domain.QueueFailFast, 60 * time.Second},
		{"header beats credential", request(map[string]string{"X-VRAM-Queue-Policy": "wait", "X-VRAM-Max-Wait-Seconds": "30"}), credential, "", 0, "fail_fast", 300, domain.QueueWait, 30 * time.Second},
		{"body beats header", request(map[string]string{"X-VRAM-Queue-Policy": "wait", "X-VRAM-Max-Wait-Seconds": "30"}), credential, "fail_fast", 10, "wait", 300, domain.QueueFailFast, 10 * time.Second},
		{"credential wait is a ceiling", request(map[string]string{"X-VRAM-Max-Wait-Seconds": "600"}), credential, "", 0, "", 0, domain.QueueFailFast, 60 * time.Second},
	}
	for _, tc := range cases {
		_, queue, wait := openAISchedulingControls(tc.r, tc.p, nil, tc.bodyQueue, tc.bodyWait, tc.defQueue, tc.defWait)
		if queue != tc.queue || wait != tc.wait {
			t.Fatalf("%s: queue=%s wait=%s want %s %s", tc.name, queue, wait, tc.queue, tc.wait)
		}
	}
}

func TestOpenAIQueueDefaultsConfigValidation(t *testing.T) {
	base := "auth:\n  credentials: []\nworkloads:\n  lease_ttl_seconds: 30\n"
	config, err := LoadConfig(writeConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if config.Workloads.OpenAIDefaultQueuePolicy != "fail_fast" || config.Workloads.OpenAIDefaultMaxWaitSeconds != 120 {
		t.Fatalf("backward-compatible defaults changed: %+v", config.Workloads)
	}
	config, err = LoadConfig(writeConfig(t, base+"  openai_default_queue_policy: wait\n  openai_default_max_wait_seconds: 900\n"))
	if err != nil || config.Workloads.OpenAIDefaultQueuePolicy != "wait" || config.Workloads.OpenAIDefaultMaxWaitSeconds != 900 {
		t.Fatalf("valid queue defaults rejected: %+v err=%v", config, err)
	}
	for _, bad := range []string{"  openai_default_queue_policy: forever\n", "  openai_default_max_wait_seconds: 901\n", "  openai_default_max_wait_seconds: -1\n"} {
		if _, err := LoadConfig(writeConfig(t, base+bad)); err == nil || !strings.Contains(err.Error(), "openai_default") {
			t.Fatalf("invalid queue default %q accepted: %v", bad, err)
		}
	}
}

func TestCreatorResponseCarriesAdmissionDetail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	srv := NewServer(&Config{}, logger, backing, nil, nil)
	srv.SetWorkloadManager(workloads.NewManager(logger, backing, time.Second))
	eta := time.Now().Add(2 * time.Minute).UTC()
	placeholder := time.Now().Add(30 * time.Second).UTC()
	row := &domain.Workload{Request: domain.WorkloadRequest{ID: "creator-1", Plane: domain.PlaneCreatorStudio}, Status: domain.WorkloadWaiting, Decision: domain.AdmissionDecision{Blocker: "gpu: accelerator residency transition in progress", BlockerCode: domain.BlockerTransitionBusy, EstimatedStart: &placeholder, ETA: &eta, RetryAfter: &eta, Alternatives: []string{"gpu: accelerator residency transition in progress"}}}
	response := srv.creatorResponse(httptest.NewRequest(http.MethodGet, "/", nil), row)
	if response.Reason == "" || response.BlockerCode != domain.BlockerTransitionBusy || len(response.Alternatives) != 1 || response.EstimatedStart == nil || !response.EstimatedStart.Equal(eta) || response.RetryAfterSeconds < 110 {
		t.Fatalf("creator response lost admission detail: %+v", response)
	}
	// Without a real ETA the placeholder estimate must not be published.
	row.Decision.ETA, row.Decision.RetryAfter = nil, nil
	response = srv.creatorResponse(httptest.NewRequest(http.MethodGet, "/", nil), row)
	if response.EstimatedStart != nil || response.RetryAfterSeconds != 0 {
		t.Fatalf("placeholder estimate leaked: %+v", response)
	}
	row.Status = domain.WorkloadRunning
	row.Execution = &domain.ExecutionHandle{}
	response = srv.creatorResponse(httptest.NewRequest(http.MethodGet, "/", nil), row)
	if response.BlockerCode != "" || response.Alternatives != nil {
		t.Fatalf("running workload reported admission blockers: %+v", response)
	}
}
