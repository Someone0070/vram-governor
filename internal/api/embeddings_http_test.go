package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"vram-governor/internal/workloads"
)

func TestEmbeddingsRouteToRuntimeEmbeddings(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var bodies []map[string]any
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/embeddings":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "model": "emb", "data": []any{map[string]any{"object": "embedding", "index": 0, "embedding": []float64{0.25, -0.5}}}, "usage": map[string]any{"prompt_tokens": 2, "total_tokens": 2}})
		case "/v1/chat/completions":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "c", "choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": "hi"}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	srv, manager, cancel := testServer(t)
	defer cancel()
	manager.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", backend.Client()))
	manager.RegisterTarget(workloads.Target{ID: "router", Adapter: "llamacpp", Endpoint: backend.URL, Models: []string{"emb", "chat"}, ResidentModels: []string{"emb", "chat"}, Slots: 2, Enabled: true})

	response := request(t, srv.Handler(), http.MethodPost, "/v1/embeddings", "alice-token", map[string]any{"model": "emb", "input": []string{"hello world"}, "governor": map[string]any{"queue_policy": "wait"}})
	if response.Code != http.StatusOK {
		t.Fatalf("embeddings status=%d body=%s", response.Code, response.Body.String())
	}
	var out struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil || len(out.Data) != 1 || len(out.Data[0].Embedding) != 2 {
		t.Fatalf("embeddings body = %s", response.Body.String())
	}
	if response := request(t, srv.Handler(), http.MethodPost, "/v1/chat/completions", "alice-token", map[string]any{"model": "chat", "messages": []any{map[string]string{"role": "user", "content": "hi"}}}); response.Code != http.StatusOK {
		t.Fatalf("chat status=%d body=%s", response.Code, response.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(paths, ",") != "/v1/embeddings,/v1/chat/completions" {
		t.Fatalf("backend paths = %v", paths)
	}
	if _, has := bodies[0]["stream"]; has || bodies[0]["governor"] != nil || bodies[0]["input"] == nil {
		t.Fatalf("embeddings body forwarded as %v", bodies[0])
	}
	if response := request(t, srv.Handler(), http.MethodPost, "/v1/embeddings", "alice-token", map[string]any{"model": "emb"}); response.Code != http.StatusBadRequest {
		t.Fatalf("embeddings without input status=%d body=%s", response.Code, response.Body.String())
	}
}
