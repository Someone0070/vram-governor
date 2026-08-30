package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"vram-governor/internal/wsproto"
)

// DiscoverLlamaCPP inspects official llama-server monitoring endpoints. The
// /slots response is authoritative for configured per-slot context and
// parallel capacity; /props and explicit configuration are conservative
// fallbacks for servers where slot monitoring is disabled.
func DiscoverLlamaCPP(ctx context.Context, nodeID string, cfg LlamaCPPServerConfig) (wsproto.AdapterAdvertisement, error) {
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if endpoint == "" {
		return wsproto.AdapterAdvertisement{}, fmt.Errorf("endpoint is required")
	}

	modelsBody, err := getJSON(ctx, endpoint+"/v1/models")
	if err != nil {
		return wsproto.AdapterAdvertisement{}, fmt.Errorf("discover models: %w", err)
	}
	models, residentModels, routerDetected, modelMaterial, err := llamaModels(modelsBody)
	if err != nil {
		return wsproto.AdapterAdvertisement{}, fmt.Errorf("discover models: %w", err)
	}
	if len(models) == 0 {
		return wsproto.AdapterAdvertisement{}, fmt.Errorf("discover models: server reported no loaded model")
	}
	ollamaDetected := false
	if runningBody, runningErr := getJSON(ctx, endpoint+"/api/ps"); runningErr == nil {
		if running, ok := ollamaRunningModels(runningBody); ok {
			residentModels = running
			ollamaDetected = true
		}
	}

	contextLimit, slots, running := 0, 0, 0
	capacitySource := ""
	verified := false
	if slotsBody, slotsErr := getJSON(ctx, endpoint+"/slots"); slotsErr == nil {
		contextLimit, slots, running = llamaSlots(slotsBody)
		if contextLimit > 0 && slots > 0 {
			capacitySource = "runtime:/slots"
			verified = true
		}
	}
	if contextLimit <= 0 {
		if propsBody, propsErr := getJSON(ctx, endpoint+"/props"); propsErr == nil {
			contextLimit = llamaPropsContext(propsBody)
			if contextLimit > 0 {
				capacitySource = "runtime:/props"
			}
		}
	}
	if contextLimit <= 0 {
		contextLimit = cfg.ContextLimit
		if contextLimit > 0 {
			capacitySource = "configured-fallback"
		}
	}
	if slots <= 0 {
		slots = cfg.Slots
	}
	if slots <= 0 {
		slots = 1
		if capacitySource == "runtime:/props" {
			capacitySource += "+conservative-slot"
		}
	}
	if contextLimit <= 0 {
		return wsproto.AdapterAdvertisement{}, fmt.Errorf("runtime did not report a context limit and no fallback is configured")
	}

	publicEndpoint := cfg.PublicEndpoint
	if publicEndpoint == "" {
		publicEndpoint = cfg.Endpoint
	}
	id := cfg.ID
	if id == "" {
		id = nodeID + "-llamacpp-" + fmt.Sprint(cfg.AcceleratorIndex)
	}
	modelHash := sha256.Sum256(modelMaterial)
	capabilityMaterial, _ := json.Marshal(struct {
		Models       []string `json:"models"`
		ModelHash    string   `json:"model_hash"`
		ContextLimit int      `json:"context_limit"`
		Slots        int      `json:"slots"`
		RuntimeArgs  []string `json:"runtime_args"`
	}{models, hex.EncodeToString(modelHash[:]), contextLimit, slots, cfg.RuntimeArgs})
	capabilityHash := sha256.Sum256(capabilityMaterial)
	return wsproto.AdapterAdvertisement{
		ID: id, Adapter: "llamacpp", Endpoint: publicEndpoint,
		AcceleratorIndex: cfg.AcceleratorIndex, Models: models, ResidentModels: residentModels,
		Version:          "llamacpp-" + hex.EncodeToString(capabilityHash[:8]),
		ModelFingerprint: hex.EncodeToString(modelHash[:]), ContextLimit: contextLimit, Slots: slots,
		CapacitySource: capacitySource, CapabilitiesVerified: verified, RuntimeArgs: append([]string(nil), cfg.RuntimeArgs...),
		SupportsModelLifecycle: cfg.RouterManaged || routerDetected || ollamaDetected, MaxResidentModels: cfg.MaxResidentModels,
		QueueRunning: running,
	}, nil
}

func ollamaRunningModels(body json.RawMessage) ([]string, bool) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false
	}
	raw, found := envelope["models"]
	if !found {
		return nil, false
	}
	var rows []struct {
		Name  string `json:"name"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, false
	}
	models := make([]string, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		name := row.Model
		if name == "" {
			name = row.Name
		}
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		models = append(models, name)
	}
	sort.Strings(models)
	return models, true
}

func getJSON(ctx context.Context, url string) (json.RawMessage, error) {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("GET %s returned invalid JSON", url)
	}
	return body, nil
}

func llamaModels(body json.RawMessage) ([]string, []string, bool, []byte, error) {
	var response struct {
		Data []struct {
			ID     string          `json:"id"`
			Meta   json.RawMessage `json:"meta"`
			Status json.RawMessage `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil, false, nil, err
	}
	models := make([]string, 0, len(response.Data))
	resident := make([]string, 0, len(response.Data))
	routerDetected := false
	for _, model := range response.Data {
		if model.ID != "" {
			models = append(models, model.ID)
			loaded, hasStatus := llamaModelLoaded(model.Status)
			routerDetected = routerDetected || hasStatus
			if loaded || !hasStatus {
				resident = append(resident, model.ID)
			}
		}
	}
	sort.Strings(models)
	sort.Strings(resident)
	material, _ := json.Marshal(response.Data)
	return models, resident, routerDetected, material, nil
}

func llamaModelLoaded(raw json.RawMessage) (bool, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, false
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.EqualFold(text, "loaded") || strings.EqualFold(text, "ready"), true
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) == nil {
		for _, key := range []string{"value", "status", "state"} {
			if value, ok := object[key].(string); ok {
				return strings.EqualFold(value, "loaded") || strings.EqualFold(value, "ready"), true
			}
		}
		return false, true
	}
	return false, true
}

func llamaSlots(body json.RawMessage) (contextLimit, slots, running int) {
	var response []struct {
		Context      int  `json:"n_ctx"`
		IsProcessing bool `json:"is_processing"`
	}
	if json.Unmarshal(body, &response) != nil {
		return 0, 0, 0
	}
	for _, slot := range response {
		if slot.Context > 0 && (contextLimit == 0 || slot.Context < contextLimit) {
			contextLimit = slot.Context
		}
		if slot.IsProcessing {
			running++
		}
	}
	return contextLimit, len(response), running
}

func llamaPropsContext(body json.RawMessage) int {
	var response struct {
		DefaultGenerationSettings struct {
			Context int `json:"n_ctx"`
		} `json:"default_generation_settings"`
	}
	_ = json.Unmarshal(body, &response)
	return response.DefaultGenerationSettings.Context
}
