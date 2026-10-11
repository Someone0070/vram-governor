package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

func TestOpenAIQueuedRequestsAreAdmittedByPriority(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	order := make([]string, 0, 3)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		label := body.Messages[0].Content
		mu.Lock()
		order = append(order, label)
		mu.Unlock()
		if label == "first" {
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}))
	defer backend.Close()

	cfg := &Config{}
	cfg.Auth.Credentials = []CredentialConfig{{ID: "client", Token: "client-token", OwnerID: "owner", Plane: "api", Scopes: []string{"inference:submit"}, Adapters: []string{"llamacpp"}, MaxPriority: 10, EgressPolicy: "local_only", DefaultQueuePolicy: "wait", MaxQueueWaitSeconds: 30}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backing := store.NewMemoryStore()
	manager := workloads.NewManager(logger, backing, time.Second)
	manager.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", nil))
	manager.RegisterTarget(workloads.Target{ID: "one-slot", Adapter: "llamacpp", Endpoint: backend.URL, Models: []string{"m"}, ContextLimit: 4096, Slots: 1, CapacityVerified: true, Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)
	srv := NewServer(cfg, logger, backing, nil, nil)
	srv.SetWorkloadManager(manager)
	gateway := httptest.NewServer(srv.Handler())
	defer gateway.Close()

	send := func(label string, priority int, done chan<- int) {
		body := []byte(`{"model":"m","messages":[{"role":"user","content":"` + label + `"}],"governor":{"context_tokens":512,"priority":` + string(rune('0'+priority)) + `}}`)
		req, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer client-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := gateway.Client().Do(req)
		if err != nil {
			done <- 0
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		done <- resp.StatusCode
	}
	results := make(chan int, 3)
	go send("first", 1, results)
	waitFor := func(n int) {
		deadline := time.Now().Add(5 * time.Second)
		for {
			rows, _ := manager.List(context.Background())
			if len(rows) >= n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected %d submitted workloads", n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitFor(1)
	time.Sleep(200 * time.Millisecond)
	go send("low", 1, results)
	waitFor(2)
	go send("high", 9, results)
	waitFor(3)
	time.Sleep(300 * time.Millisecond)
	close(release)
	for i := 0; i < 3; i++ {
		select {
		case status := <-results:
			if status != http.StatusOK {
				t.Fatalf("queued request finished with status %d", status)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("queued requests did not complete")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "first,high,low" {
		t.Fatalf("backend dispatch order = %v, want first,high,low", order)
	}
}
