package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/workloads"
)

// fakeComfy records what the LB forwards to ComfyUI.
type fakeComfy struct {
	mu       sync.Mutex
	prompts  []map[string]any
	authSeen bool
	freed    bool
}

func (f *fakeComfy) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/prompt", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.prompts = append(f.prompts, body)
		f.mu.Unlock()
		if graph, _ := body["prompt"].(map[string]any); graph["bad"] != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"type":"prompt_outputs_failed_validation","message":"Prompt outputs failed validation"},"node_errors":{"bad":{"errors":[{"message":"Value not in list"}]}}}`))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"prompt_id": body["prompt_id"], "number": 1, "node_errors": map[string]any{}})
	})
	mux.HandleFunc("/history/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/history/")
		writeJSON(w, http.StatusOK, map[string]any{id: map[string]any{"status": map[string]any{"status_str": "success", "completed": true}, "outputs": map[string]any{}}})
	})
	mux.HandleFunc("/object_info", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authSeen = f.authSeen || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != ""
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"KSampler": map[string]any{}})
	})
	mux.HandleFunc("/free", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.freed = true
		f.mu.Unlock()
	})
	// Real ComfyUI serves every route both with and without the /api prefix.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
		mux.ServeHTTP(w, r)
	})
}

func comfyUITestServer(t *testing.T) (*Server, *fakeComfy, func()) {
	t.Helper()
	comfyUIPromptWait = 3 * time.Second
	fake := &fakeComfy{}
	upstream := httptest.NewServer(fake.handler())
	srv, manager, cancel := testServer(t)
	srv.cfg.ComfyUI.Upstream = upstream.URL
	srv.cfg.ComfyUI.TargetID = "comfy-ui"
	for i := range srv.credentials {
		if srv.credentials[i].principal.ID == "alice" {
			srv.credentials[i].principal.Scopes["comfy:read"] = struct{}{}
			srv.credentials[i].principal.Scopes["comfy:submit"] = struct{}{}
			srv.credentials[i].principal.Adapters["comfy"] = struct{}{}
		}
	}
	manager.RegisterAdapter(workloads.NewHTTPAdapter("comfy", "comfy", upstream.Client()))
	manager.RegisterTarget(workloads.Target{ID: "comfy-ui", Adapter: "comfy", Endpoint: upstream.URL, Slots: 1, Enabled: true, ComfyUI: true})
	return srv, fake, func() { cancel(); upstream.Close() }
}

func comfyUIRequest(srv *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice-token")
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestComfyUIAuthProxyAndBlockedRoutes(t *testing.T) {
	srv, fake, done := comfyUITestServer(t)
	defer done()
	if rec := comfyUIRequest(srv, http.MethodGet, "/comfy/", "", map[string]string{"Authorization": "", "Accept": "text/html"}); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/comfy/login" {
		t.Fatalf("unauthenticated page: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := comfyUIRequest(srv, http.MethodGet, "/comfy/login", "", map[string]string{"Authorization": ""}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/auth/session") {
		t.Fatalf("login page: %d", rec.Code)
	}
	if rec := comfyUIRequest(srv, http.MethodGet, "/comfy/api/object_info", "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "KSampler") {
		t.Fatalf("proxied object_info: %d %s", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/comfy/api/free", "/comfy/free", "/comfy/api/manager/queue/install", "/comfy/customnode/install"} {
		if rec := comfyUIRequest(srv, http.MethodPost, path, "{}", nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s not blocked: %d", path, rec.Code)
		}
	}
	if rec := comfyUIRequest(srv, http.MethodPost, "/comfy/api/prompt", `{"prompt":{"1":{}}}`, map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin prompt accepted: %d", rec.Code)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.authSeen || fake.freed || len(fake.prompts) != 0 {
		t.Fatalf("leaked to ComfyUI: auth=%v freed=%v prompts=%d", fake.authSeen, fake.freed, len(fake.prompts))
	}
}

func TestComfyUIPromptIsScheduledWithTheBrowsersIDs(t *testing.T) {
	srv, fake, done := comfyUITestServer(t)
	defer done()
	rec := comfyUIRequest(srv, http.MethodPost, "/comfy/api/prompt", `{"prompt":{"1":{"class_type":"SaveImage","inputs":{}}},"client_id":"browser-1","extra_data":{"extra_pnginfo":{"workflow":{}}}}`, map[string]string{"Origin": "http://example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("prompt: %d %s", rec.Code, rec.Body.String())
	}
	var accepted struct {
		PromptID string `json:"prompt_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &accepted)
	fake.mu.Lock()
	if len(fake.prompts) != 1 || fake.prompts[0]["prompt_id"] != accepted.PromptID || fake.prompts[0]["client_id"] != "browser-1" || fake.prompts[0]["extra_data"] == nil {
		t.Fatalf("ComfyUI got %v, browser got prompt_id %q", fake.prompts, accepted.PromptID)
	}
	fake.mu.Unlock()
	rows, _ := srv.workloads.List(context.Background())
	var row *domain.Workload
	for _, candidate := range rows {
		if candidate.Request.ItemID == accepted.PromptID {
			row = candidate
		}
	}
	if row == nil || row.Request.PinnedTargetID != "comfy-ui" || row.Request.Priority != 0 {
		t.Fatalf("workload not pinned to the UI target: %+v", row)
	}
	deadline := time.Now().Add(5 * time.Second)
	for row.Status != domain.WorkloadSucceeded && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		row, _ = srv.workloads.Get(context.Background(), row.Request.ID)
	}
	if row.Status != domain.WorkloadSucceeded {
		t.Fatalf("UI prompt did not complete through history: %s %s", row.Status, row.Error)
	}
}

func TestComfyUIValidationErrorsReachTheUI(t *testing.T) {
	srv, _, done := comfyUITestServer(t)
	defer done()
	rec := comfyUIRequest(srv, http.MethodPost, "/comfy/api/prompt", `{"prompt":{"bad":{"class_type":"KSampler","inputs":{}}},"client_id":"browser-1"}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"node_errors":{"bad"`) {
		t.Fatalf("validation error not passed through: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPinnedTargetCannotBeSetByClients(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	req := domain.WorkloadRequest{Adapter: "mock", PinnedTargetID: "comfy-ui"}
	p, _ := srv.authenticateToken("alice-token")
	if err := srv.prepareRequest(httptest.NewRequest(http.MethodPost, "/api/v1/workloads", nil), p, &req); err != nil {
		t.Fatal(err)
	}
	if req.PinnedTargetID != "" {
		t.Fatal("client-supplied pinned_target_id survived prepareRequest")
	}
}

func TestReservedComfyUITargetTakesOnlyPinnedWork(t *testing.T) {
	srv, fake, done := comfyUITestServer(t)
	defer done()
	// The API gateway's own /prompt is unpinned: with only the UI's ComfyUI
	// registered it must wait rather than run there.
	if rec := comfyUIRequest(srv, http.MethodPost, "/prompt", `{"prompt":{"1":{"class_type":"SaveImage","inputs":{}}}}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("gateway prompt: %d %s", rec.Code, rec.Body.String())
	}
	time.Sleep(500 * time.Millisecond)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.prompts) != 0 {
		t.Fatalf("unpinned work ran on the reserved UI target: %v", fake.prompts)
	}
}
