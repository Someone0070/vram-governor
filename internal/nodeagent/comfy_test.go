package nodeagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverComfyUIReportsExistingCapabilitiesOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/object_info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"CheckpointLoaderSimple": map[string]any{"input": map[string]any{"required": map[string]any{"ckpt_name": []any{[]any{"z.safetensors", "a.safetensors"}}}}},
				"UNETLoader":             map[string]any{"input": map[string]any{"required": map[string]any{"unet_name": []any{[]any{"modern.safetensors"}}}}},
				"VAELoader":              map[string]any{"input": map[string]any{"required": map[string]any{"vae_name": []any{[]any{"pixel_space", "ae.safetensors"}}}}},
				"KSampler":               map[string]any{}, "InstalledCustomNode": map[string]any{},
			})
		case "/system_stats":
			_ = json.NewEncoder(w).Encode(map[string]any{"system": map[string]any{"comfyui_version": "0.3.50"}})
		case "/queue":
			_ = json.NewEncoder(w).Encode(map[string]any{"queue_running": []any{1}, "queue_pending": []any{1, 2}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &Config{NodeID: "node-a"}
	cfg.ComfyUI.Endpoint = server.URL
	cfg.ComfyUI.PublicEndpoint = "http://node-a:8188"
	cfg.ComfyUI.AcceleratorIndex = 2
	advertisement, err := DiscoverComfyUI(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if advertisement.Endpoint != cfg.ComfyUI.PublicEndpoint || advertisement.AcceleratorIndex != 2 || advertisement.Version != "0.3.50" {
		t.Fatalf("bad advertisement: %+v", advertisement)
	}
	if len(advertisement.Models) != 4 || advertisement.Models[0] != "a.safetensors" || advertisement.Models[2] != "modern.safetensors" {
		t.Fatalf("models not discovered/sorted: %v", advertisement.Models)
	}
	if len(advertisement.CustomNodes) != 5 || advertisement.QueueRunning != 1 || advertisement.QueuePending != 2 {
		t.Fatalf("capabilities missing: %+v", advertisement)
	}
}
