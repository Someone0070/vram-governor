package nodeagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"vram-governor/internal/wsproto"
)

func DiscoverComfyUI(ctx context.Context, cfg *Config) (wsproto.AdapterAdvertisement, error) {
	endpoint := strings.TrimRight(cfg.ComfyUI.Endpoint, "/")
	objectInfo, err := getJSONObject(ctx, endpoint+"/object_info")
	if err != nil {
		return wsproto.AdapterAdvertisement{}, err
	}
	customNodes := make([]string, 0, len(objectInfo))
	for class := range objectInfo {
		customNodes = append(customNodes, class)
	}
	sort.Strings(customNodes)
	models := comfyModelArtifacts(objectInfo)
	version := "unknown"
	if stats, err := getJSONObject(ctx, endpoint+"/system_stats"); err == nil {
		if system, ok := stats["system"].(map[string]any); ok {
			if value, ok := system["comfyui_version"].(string); ok {
				version = value
			}
		}
	}
	running, pending := 0, 0
	if queue, err := getJSONObject(ctx, endpoint+"/queue"); err == nil {
		if values, ok := queue["queue_running"].([]any); ok {
			running = len(values)
		}
		if values, ok := queue["queue_pending"].([]any); ok {
			pending = len(values)
		}
	}
	publicEndpoint := cfg.ComfyUI.PublicEndpoint
	if publicEndpoint == "" {
		publicEndpoint = cfg.ComfyUI.Endpoint
	}
	return wsproto.AdapterAdvertisement{ID: cfg.NodeID + "-comfy", Adapter: "comfy", Endpoint: publicEndpoint, AcceleratorIndex: cfg.ComfyUI.AcceleratorIndex, Models: models, CustomNodes: customNodes, Version: version, SupportsAcceleratorReclaim: true, QueueRunning: running, QueuePending: pending}, nil
}

func getJSONObject(ctx context.Context, url string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	var value map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

var comfyModelInputNames = map[string]struct{}{
	"ckpt_name": {}, "unet_name": {}, "vae_name": {}, "lora_name": {},
	"clip_name": {}, "clip_name1": {}, "clip_name2": {}, "clip_name3": {}, "clip_name4": {},
	"control_net_name": {}, "upscale_model": {},
}

func comfyModelArtifacts(info map[string]any) []string {
	seen := map[string]struct{}{}
	for _, rawNode := range info {
		node, _ := rawNode.(map[string]any)
		input, _ := node["input"].(map[string]any)
		for _, sectionName := range []string{"required", "optional"} {
			section, _ := input[sectionName].(map[string]any)
			for field, rawOptions := range section {
				if _, supported := comfyModelInputNames[field]; !supported {
					continue
				}
				options, _ := rawOptions.([]any)
				if len(options) == 0 {
					continue
				}
				values, _ := options[0].([]any)
				for _, value := range values {
					if model, ok := value.(string); ok && model != "" && model != "pixel_space" {
						seen[model] = struct{}{}
					}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for model := range seen {
		out = append(out, model)
	}
	sort.Strings(out)
	return out
}
