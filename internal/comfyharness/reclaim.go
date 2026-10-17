package comfyharness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// reclaimColdBytes is the torch reservation below which ComfyUI's GPU cache
// counts as released (the CUDA context and small buffers remain).
const reclaimColdBytes = 1 << 30

var (
	reclaimTimeout      = 30 * time.Second
	reclaimPollInterval = 500 * time.Millisecond
)

type reclaimResponse struct {
	Model          string `json:"model"`
	Tier           string `json:"tier"`
	FencingToken   int64  `json:"fencing_token"`
	Protocol       string `json:"protocol"`
	TorchVRAMBytes int64  `json:"torch_vram_bytes"`
	VRAMFreeBytes  int64  `json:"vram_free_bytes"`
	Error          string `json:"error,omitempty"`
}

// handleReclaim frees ComfyUI's GPU cache for another runtime on the same
// accelerator and reports the measured post-state. ComfyUI's /free alone is
// asynchronous and returns nothing; the harness refuses while ComfyUI has
// work, then polls /system_stats until torch's reservation is released.
func (s *Server) handleReclaim(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FencingToken int64 `json:"fencing_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil || body.FencingToken <= 0 {
		writeReclaim(w, http.StatusBadRequest, reclaimResponse{Error: "fencing_token is required"})
		return
	}
	s.mu.Lock()
	busy := false
	for _, runs := range s.activeRuns {
		busy = busy || runs > 0
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), reclaimTimeout+10*time.Second)
	defer cancel()
	if !busy {
		var queue struct {
			Running []json.RawMessage `json:"queue_running"`
			Pending []json.RawMessage `json:"queue_pending"`
		}
		if err := s.comfyJSON(ctx, http.MethodGet, "/queue", nil, &queue); err != nil {
			writeReclaim(w, http.StatusBadGateway, reclaimResponse{Error: "observation_unavailable: ComfyUI queue: " + err.Error()})
			return
		}
		busy = len(queue.Running)+len(queue.Pending) > 0
	}
	if busy {
		writeReclaim(w, http.StatusConflict, reclaimResponse{Error: "ComfyUI has work in progress"})
		return
	}
	if err := s.comfyJSON(ctx, http.MethodPost, "/free", map[string]bool{"unload_models": true, "free_memory": true}, nil); err != nil {
		writeReclaim(w, http.StatusBadGateway, reclaimResponse{Error: "ComfyUI free: " + err.Error()})
		return
	}
	deadline := time.Now().Add(reclaimTimeout)
	for {
		torch, free, err := s.comfyVRAM(ctx)
		if err == nil && torch <= reclaimColdBytes {
			writeReclaim(w, http.StatusOK, reclaimResponse{Model: "runtime-cache", Tier: "cold_disk", FencingToken: body.FencingToken, Protocol: ProtocolVersion, TorchVRAMBytes: torch, VRAMFreeBytes: free})
			return
		}
		if time.Now().After(deadline) {
			message := "observation_unavailable: ComfyUI still reserves GPU memory after /free"
			if err != nil {
				message = "observation_unavailable: ComfyUI system_stats: " + err.Error()
			} else {
				message = fmt.Sprintf("%s (%d MiB)", message, torch>>20)
			}
			writeReclaim(w, http.StatusServiceUnavailable, reclaimResponse{Error: message})
			return
		}
		select {
		case <-ctx.Done():
			writeReclaim(w, http.StatusServiceUnavailable, reclaimResponse{Error: "observation_unavailable: " + ctx.Err().Error()})
			return
		case <-time.After(reclaimPollInterval):
		}
	}
}

func (s *Server) comfyVRAM(ctx context.Context) (torchBytes, freeBytes int64, err error) {
	var stats struct {
		Devices []struct {
			Type           string `json:"type"`
			VRAMFree       int64  `json:"vram_free"`
			TorchVRAMTotal int64  `json:"torch_vram_total"`
		} `json:"devices"`
	}
	if err := s.comfyJSON(ctx, http.MethodGet, "/system_stats", nil, &stats); err != nil {
		return 0, 0, err
	}
	for _, device := range stats.Devices {
		if device.Type == "cuda" {
			return device.TorchVRAMTotal, device.VRAMFree, nil
		}
	}
	return 0, 0, fmt.Errorf("no CUDA device reported")
}

func (s *Server) comfyJSON(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, _ := json.Marshal(body)
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.options.ComfyURL, "/")+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := s.options.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, maxSystemStatsBytes))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s %s returned %d", method, path, response.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func writeReclaim(w http.ResponseWriter, status int, body reclaimResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
