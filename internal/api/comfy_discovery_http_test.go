package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"vram-governor/internal/workloads"
)

func addComfyReadCredential(s *Server) {
	s.cfg.Auth.Credentials = append(s.cfg.Auth.Credentials, CredentialConfig{
		ID: "comfy-reader", Token: "comfy-reader-token", OwnerID: "owner", Plane: "api",
		Scopes: []string{"comfy:read"}, Adapters: []string{"comfy"}, EgressPolicy: "local_only",
	})
	s.buildCredentials()
}

func TestComfyFleetDiscoveryAuthorization(t *testing.T) {
	srv, manager, cleanup := testServer(t)
	defer cleanup()
	srv.cfg.Auth.Credentials = append(srv.cfg.Auth.Credentials, CredentialConfig{ID: "comfy-wrong-adapter", Token: "comfy-wrong-adapter-token", OwnerID: "owner", Plane: "api", Scopes: []string{"comfy:read"}, Adapters: []string{"llamacpp"}})
	srv.buildCredentials()
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/object_info" { _, _ = w.Write([]byte(`{"A":{"input":{"required":{}},"output":[]}}`)); return }
		_, _ = w.Write([]byte(`{"system":{},"devices":[]}`))
	}))
	defer backend.Close()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("comfy", "comfy", backend.Client()))
	manager.RegisterTarget(workloads.Target{ID: "comfy-a", Adapter: "comfy", Endpoint: backend.URL, Enabled: true})

	for _, tc := range []struct{ token string; want int }{{"", http.StatusUnauthorized}, {"alice-token", http.StatusForbidden}, {"comfy-wrong-adapter-token", http.StatusForbidden}} {
		req := httptest.NewRequest(http.MethodGet, "/object_info", nil)
		if tc.token != "" { req.Header.Set("Authorization", "Bearer "+tc.token) }
		recorder := httptest.NewRecorder()
		srv.mux.ServeHTTP(recorder, req)
		if recorder.Code != tc.want { t.Fatalf("status=%d want=%d", recorder.Code, tc.want) }
	}
	if calls.Load() != 0 { t.Fatalf("unauthorized discovery made %d backend calls", calls.Load()) }
}

func TestComfyFleetDiscoveryFixedRoutes(t *testing.T) {
	srv, manager, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/registered-prefix/object_info" && r.URL.Path != "/registered-prefix/system_stats" { t.Errorf("unexpected fixed route %q", r.URL.Path) }
		if r.Header.Get("Authorization") != "Bearer backend-only" { t.Errorf("backend credential isolation failed") }
		if r.Header.Get("Cookie") != "" { t.Errorf("incoming cookie was forwarded") }
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/registered-prefix/object_info" { _, _ = w.Write([]byte(`{"A":{"input":{},"output":[]}}`)); return }
		_, _ = w.Write([]byte(`{"system":{"hostname":"private-host"},"devices":[{"name":"GPU 0","vram_free":42,"path":"/secret"}]}`))
	}))
	defer backend.Close()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("comfy", "comfy", backend.Client()))
	manager.RegisterTarget(workloads.Target{ID: "comfy-a", Adapter: "comfy", Endpoint: backend.URL+"/registered-prefix", Authorization: "Bearer backend-only", Enabled: true})

	for _, target := range []string{"/object_info", "/system_stats?target=attacker", "/object_info?"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", "Bearer comfy-reader-token")
		req.Header.Set("Cookie", "session=secret")
		recorder := httptest.NewRecorder()
		srv.mux.ServeHTTP(recorder, req)
		if target == "/object_info" && recorder.Code != http.StatusOK { t.Fatalf("object_info status=%d body=%s", recorder.Code, recorder.Body.String()) }
		if target != "/object_info" && recorder.Code != http.StatusBadRequest { t.Fatalf("invalid request status=%d", recorder.Code) }
	}
	if calls.Load() != 2 { t.Fatalf("got %d calls, want only the two authenticated fixed reads", calls.Load()) }
	bodyReq := httptest.NewRequest(http.MethodGet, "/object_info", strings.NewReader("not-forwarded"))
	bodyReq.Header.Set("Authorization", "Bearer comfy-reader-token")
	bodyRecorder := httptest.NewRecorder()
	srv.mux.ServeHTTP(bodyRecorder, bodyReq)
	if bodyRecorder.Code != http.StatusBadRequest || calls.Load() != 2 { t.Fatalf("request body was not rejected before backend reads: status=%d calls=%d", bodyRecorder.Code, calls.Load()) }
	req := httptest.NewRequest(http.MethodGet, "/system_stats", nil)
	req.Header.Set("Authorization", "Bearer comfy-reader-token")
	recorder := httptest.NewRecorder()
	srv.mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK { t.Fatalf("stats status=%d body=%s", recorder.Code, recorder.Body.String()) }
	var body map[string]any
	if json.Unmarshal(recorder.Body.Bytes(), &body) != nil { t.Fatal("invalid stats JSON") }
	if body["system"].(map[string]any)["hostname"] != nil { t.Fatal("backend system host leaked") }
	if calls.Load() != 4 { t.Fatalf("stats request made unexpected backend call count %d", calls.Load()) }
	t.Run("caller credential is not forwarded to an uncredentialed route", func(t *testing.T) {
		isolatedServer, isolatedManager, isolatedCleanup := testServer(t)
		defer isolatedCleanup()
		addComfyReadCredential(isolatedServer)
		var sawHeader atomic.Bool
		isolatedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
			if r.Header.Get("Authorization") != "" { sawHeader.Store(true) }
			if r.URL.Path=="/object_info" { _,_=w.Write([]byte(`{"A":{"input":{"required":{}},"output":[]}}`)); return }
			_,_=w.Write([]byte(`{"system":{},"devices":[]}`))
		}))
		defer isolatedBackend.Close()
		isolatedManager.RegisterAdapter(workloads.NewHTTPAdapter("comfy","comfy",isolatedBackend.Client()))
		isolatedManager.RegisterTarget(workloads.Target{ID:"no-backend-credential",Adapter:"comfy",Endpoint:isolatedBackend.URL,Enabled:true})
		request:=httptest.NewRequest(http.MethodGet,"/object_info",nil)
		request.Header.Set("Authorization","Bearer comfy-reader-token")
		recorder:=httptest.NewRecorder(); isolatedServer.mux.ServeHTTP(recorder,request)
		if recorder.Code!=http.StatusOK || sawHeader.Load() { t.Fatalf("caller credential reached uncredentialed backend: status=%d saw=%v",recorder.Code,sawHeader.Load()) }
	})
	for _, method := range []string{http.MethodPost, http.MethodHead} {
		req = httptest.NewRequest(method, "/object_info", nil)
		req.Header.Set("Authorization", "Bearer comfy-reader-token")
		recorder = httptest.NewRecorder()
		srv.mux.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusMethodNotAllowed { t.Fatalf("method %s status=%d", method, recorder.Code) }
	}
}

func TestComfyFleetDiscoveryMixedProtocols(t *testing.T) {
	// Raw and managed targets share the same controller-facing JSON contract;
	// protocol behavior remains confined to each manager-registered endpoint.
	srv, manager, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	var requests atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/object_info" { _, _ = w.Write([]byte(`{"RawNode":{"input":{},"output":[]}}`)); return }
		_, _ = w.Write([]byte(`{"system":{},"devices":[]}`))
	}))
	defer backend.Close()
	managed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/object_info" { _, _ = w.Write([]byte(`{"ManagedNode":{"input":{},"output":[]}}`)); return }
		_, _ = w.Write([]byte(`{"system":{},"devices":[]}`))
	}))
	defer managed.Close()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("comfy", "comfy", backend.Client()))
	manager.RegisterTarget(workloads.Target{ID: "raw", Adapter: "comfy", Endpoint: backend.URL, Enabled: true})
	manager.RegisterTarget(workloads.Target{ID: "managed", Adapter: "comfy", Endpoint: managed.URL, RuntimeProtocol: "managed_comfy_v1", Enabled: true})
	req := httptest.NewRequest(http.MethodGet, "/object_info", nil)
	req.Header.Set("Authorization", "Bearer comfy-reader-token")
	recorder := httptest.NewRecorder()
	srv.mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !containsDiscoveryText(recorder.Body.String(), "RawNode") || !containsDiscoveryText(recorder.Body.String(), "ManagedNode") { t.Fatalf("mixed discovery failed: %d %s", recorder.Code, recorder.Body.String()) }
	if requests.Load() != 4 { t.Fatalf("metadata pair count=%d", requests.Load()) }
}

func TestComfyFleetDiscoveryConflictsAndStats(t *testing.T) {
	srv, manager, cleanup := testServer(t)
	defer cleanup()
	addComfyReadCredential(srv)
	makeBackend := func(class string, free int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/object_info" { _, _ = w.Write([]byte(`{"Conflict":{"input":{},"output":["`+class+`"]}}`)); return }
			_, _ = w.Write([]byte(`{"system":{},"devices":[{"name":"GPU","vram_free":`+json.Number(string(rune('0'+free))).String()+`}]}`))
		}))
	}
	first, second := makeBackend("IMAGE", 4), makeBackend("LATENT", 7)
	defer first.Close(); defer second.Close()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("comfy", "comfy", first.Client()))
	manager.RegisterTarget(workloads.Target{ID: "a", Adapter: "comfy", Endpoint: first.URL, Enabled: true})
	manager.RegisterTarget(workloads.Target{ID: "b", Adapter: "comfy", Endpoint: second.URL, Enabled: true})
	req := httptest.NewRequest(http.MethodGet, "/object_info", nil); req.Header.Set("Authorization", "Bearer comfy-reader-token")
	recorder := httptest.NewRecorder(); srv.mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict || !containsDiscoveryText(recorder.Body.String(), "schema_conflict") { t.Fatalf("expected conflict, got %d %s", recorder.Code, recorder.Body.String()) }
	req = httptest.NewRequest(http.MethodGet, "/system_stats", nil); req.Header.Set("Authorization", "Bearer comfy-reader-token")
	recorder = httptest.NewRecorder(); srv.mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !containsDiscoveryText(recorder.Body.String(), `"target_id":"a"`) || !containsDiscoveryText(recorder.Body.String(), `"target_id":"b"`) { t.Fatalf("stats lost per-device provenance: %d %s", recorder.Code, recorder.Body.String()) }
	t.Run("unsafe schema metadata is not relayed", func(t *testing.T) {
		unsafeServer,unsafeManager,unsafeCleanup:=testServer(t); defer unsafeCleanup(); addComfyReadCredential(unsafeServer)
		backend:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
			if r.URL.Path=="/object_info" { _,_=w.Write([]byte(`{"A":{"input":{"required":{}},"output":[],"private_path":"/var/secrets/backend-token"}}`)); return }
			_,_=w.Write([]byte(`{"system":{},"devices":[]}`))
		}))
		defer backend.Close()
		unsafeManager.RegisterAdapter(workloads.NewHTTPAdapter("comfy","comfy",backend.Client()))
		unsafeManager.RegisterTarget(workloads.Target{ID:"unsafe",Adapter:"comfy",Endpoint:backend.URL,Enabled:true})
		request:=httptest.NewRequest(http.MethodGet,"/object_info",nil); request.Header.Set("Authorization","Bearer comfy-reader-token")
		recorder:=httptest.NewRecorder(); unsafeServer.mux.ServeHTTP(recorder,request)
		if recorder.Code!=http.StatusServiceUnavailable || containsDiscoveryText(recorder.Body.String(),"backend-token") { t.Fatalf("unsafe schema metadata leaked or was accepted: %d %s",recorder.Code,recorder.Body.String()) }
	})
	t.Run("compatible live enum choices compose", func(t *testing.T) {
		unionServer, unionManager, unionCleanup := testServer(t)
		defer unionCleanup()
		addComfyReadCredential(unionServer)
		makeEnumBackend := func(targetName string) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/object_info" { _, _ = w.Write([]byte(`{"CheckpointLoader":{"input":{"required":{"ckpt_name":[["`+targetName+`"]] }},"output":["MODEL"]}}`)); return }
				_, _ = w.Write([]byte(`{"system":{},"devices":[]}`))
			}))
		}
		left, right := makeEnumBackend("left.safetensors"), makeEnumBackend("right.safetensors")
		defer left.Close(); defer right.Close()
		unionManager.RegisterAdapter(workloads.NewHTTPAdapter("comfy", "comfy", left.Client()))
		unionManager.RegisterTarget(workloads.Target{ID:"enum-a",Adapter:"comfy",Endpoint:left.URL,Enabled:true})
		unionManager.RegisterTarget(workloads.Target{ID:"enum-b",Adapter:"comfy",Endpoint:right.URL,Enabled:true})
		request := httptest.NewRequest(http.MethodGet, "/object_info", nil)
		request.Header.Set("Authorization", "Bearer comfy-reader-token")
		recorder := httptest.NewRecorder(); unionServer.mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || !containsDiscoveryText(recorder.Body.String(), "left.safetensors") || !containsDiscoveryText(recorder.Body.String(), "right.safetensors") { t.Fatalf("compatible enum choices did not compose: %d %s", recorder.Code, recorder.Body.String()) }
	})
}

func containsDiscoveryText(value, part string) bool { return len(part) == 0 || (len(value) >= len(part) && strings.Contains(value, part)) }
