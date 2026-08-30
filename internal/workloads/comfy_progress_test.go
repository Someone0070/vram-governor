package workloads

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"vram-governor/internal/domain"
)

func TestComfyProgressObserverIgnoresBinaryPreviewFrames(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /prompt", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"prompt_id": "backend-progress"})
	})
	mux.HandleFunc("GET /history/backend-progress", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"executing","data":{"prompt_id":"backend-progress","node":"7"}}`))
		_ = conn.Write(ctx, websocket.MessageBinary, []byte{0, 1, 2, 3})
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"progress","data":{"prompt_id":"backend-progress","node":"7","value":2,"max":4}}`))
		<-ctx.Done()
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	adapter := NewHTTPAdapter("comfy", "comfy", server.Client())
	request := domain.WorkloadRequest{ID: "workload-progress", Payload: json.RawMessage(`{"prompt":{"7":{"class_type":"KSampler"}}}`)}
	handle, err := adapter.Start(context.Background(), request, nil, Target{ID: "comfy", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		observation, observeErr := adapter.Observe(context.Background(), request, nil, handle, Target{ID: "comfy", Endpoint: server.URL})
		if observeErr != nil {
			t.Fatal(observeErr)
		}
		if observation.ProgressCurrent == 2 && observation.ProgressTotal == 4 && observation.ProgressNode == "7" && observation.Progress == .5 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	adapter.progressMu.RLock()
	progress := adapter.comfyProgress[handle.ExternalID]
	adapter.progressMu.RUnlock()
	t.Fatalf("progress event after binary preview was not retained: %+v (%s)", progress, strings.TrimSpace(string(handle.Opaque)))
}
