package comfyharness

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeComfyMemory serves the endpoints reclaim uses; /free drops torch's
// reservation unless sticky is set.
func fakeComfyMemory(t *testing.T, queued bool, sticky bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var torch atomic.Int64
	torch.Store(7 << 30)
	mux := http.NewServeMux()
	mux.HandleFunc("/queue", func(w http.ResponseWriter, r *http.Request) {
		running := "[]"
		if queued {
			running = `[[0,"p",{},{},[]]]`
		}
		_, _ = w.Write([]byte(`{"queue_running":` + running + `,"queue_pending":[]}`))
	})
	mux.HandleFunc("/free", func(w http.ResponseWriter, r *http.Request) {
		if !sticky {
			go func() { time.Sleep(20 * time.Millisecond); torch.Store(200 << 20) }()
		}
	})
	mux.HandleFunc("/system_stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{{"type": "cuda", "vram_free": 11 << 30, "torch_vram_total": torch.Load()}}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &torch
}

func postReclaim(t *testing.T, harness *httptest.Server, body string) (int, reclaimResponse) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, harness.URL+"/v1/reclaim", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer harness-test")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var out reclaimResponse
	_ = json.NewDecoder(response.Body).Decode(&out)
	return response.StatusCode, out
}

func TestReclaimReportsMeasuredColdStateWithTheFence(t *testing.T) {
	comfy, torch := fakeComfyMemory(t, false, false)
	_, harness := newHarnessTestServer(t, comfy.URL, t.TempDir())
	status, out := postReclaim(t, harness, `{"fencing_token":42}`)
	if status != http.StatusOK || out.Tier != "cold_disk" || out.Model != "runtime-cache" || out.FencingToken != 42 || torch.Load() > reclaimColdBytes {
		t.Fatalf("reclaim: %d %+v torch=%d", status, out, torch.Load())
	}
	if status, _ := postReclaim(t, harness, `{}`); status != http.StatusBadRequest {
		t.Fatalf("reclaim without a fence: %d", status)
	}
}

func TestReclaimRefusesWhileComfyHasWork(t *testing.T) {
	comfy, torch := fakeComfyMemory(t, true, false)
	_, harness := newHarnessTestServer(t, comfy.URL, t.TempDir())
	if status, _ := postReclaim(t, harness, `{"fencing_token":1}`); status != http.StatusConflict || torch.Load() != 7<<30 {
		t.Fatalf("reclaim with queued work: %d torch=%d", status, torch.Load())
	}
}

func TestReclaimNeverClaimsColdWithoutMeasuringIt(t *testing.T) {
	previous := reclaimTimeout
	reclaimTimeout = 300 * time.Millisecond
	defer func() { reclaimTimeout = previous }()
	comfy, _ := fakeComfyMemory(t, false, true)
	_, harness := newHarnessTestServer(t, comfy.URL, t.TempDir())
	status, out := postReclaim(t, harness, `{"fencing_token":1}`)
	if status != http.StatusServiceUnavailable || !strings.HasPrefix(out.Error, "observation_unavailable") || out.Tier != "" {
		t.Fatalf("sticky memory: %d %+v", status, out)
	}
}
