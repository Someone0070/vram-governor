package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"vram-governor/internal/domain"
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
	ollamaDetected := false
	standaloneVRAMMB := int64(0)
	standaloneVRAMSource := ""
	standaloneVRAMVerified := false
	vramByModel := map[string]int64{}
	if runningBody, runningErr := getJSON(ctx, endpoint+"/api/ps"); runningErr == nil {
		if running, measuredVRAM, endpointOK, capacityOK := ollamaRunningModels(runningBody); endpointOK {
			ollamaDetected = true
			// /api/ps is authoritative for runtime visibility whenever its JSON
			// envelope is valid, including an explicit zero-row response. Capacity
			// attribution is deliberately narrower and remains empty unless one
			// complete positive row can be bound to exactly one model.
			residentModels = running
			if capacityOK {
				vramByModel = measuredVRAM
			}
			for _, vramBytes := range measuredVRAM {
				vramMB := vramBytes / (1 << 20)
				if vramBytes%(1<<20) != 0 {
					vramMB++
				}
				if vramMB > standaloneVRAMMB {
					standaloneVRAMMB = vramMB
				}
			}
			if standaloneVRAMMB > 0 {
				standaloneVRAMSource = "runtime:/api/ps:size_vram"
				standaloneVRAMVerified = true
			}
		}
	}

	contextLimit, slots, running := 0, 0, 0
	capacitySource := ""
	verified := false
	monitorQuery := ""
	// llama.cpp's router requires a model selector for model-scoped monitoring
	// endpoints.  Without it, a healthy single-resident router answers /slots
	// with 400 and the agent incorrectly downgrades verified capacity to its
	// configured fallback.
	if routerDetected && len(residentModels) == 1 {
		monitorQuery = "?model=" + url.QueryEscape(residentModels[0])
	}
	if slotsBody, slotsErr := getJSON(ctx, endpoint+"/slots"+monitorQuery); slotsErr == nil {
		contextLimit, slots, running = llamaSlots(slotsBody)
		if contextLimit > 0 && slots > 0 {
			capacitySource = "runtime:/slots"
			verified = true
		}
	}
	if contextLimit <= 0 {
		if propsBody, propsErr := getJSON(ctx, endpoint+"/props"+monitorQuery); propsErr == nil {
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
	// A passive /v1/models catalog is useful for visibility, but it is not a
	// lifecycle implementation. Only an explicitly managed router or a
	// discovered Ollama protocol can execute the mutation path below.
	supportsLifecycle := cfg.RouterManaged || ollamaDetected
	modelHash := sha256.Sum256(modelMaterial)
	capabilityMaterial, _ := json.Marshal(struct {
		Models               []string `json:"models"`
		ModelHash            string   `json:"model_hash"`
		ContextLimit         int      `json:"context_limit"`
		Slots                int      `json:"slots"`
		CapacitySource       string   `json:"capacity_source"`
		CapabilitiesVerified bool     `json:"capabilities_verified"`
		RuntimeArgs          []string `json:"runtime_args"`
		MeasurementSchema    string   `json:"measurement_schema"`
	}{models, hex.EncodeToString(modelHash[:]), contextLimit, slots, "", false, cfg.RuntimeArgs, "runtime-envelope-v2"})
	// Capacity provenance (configured fallback vs runtime /slots) changes
	// whenever a router loads or unloads a model; it is measurement metadata,
	// not runtime identity, so it is excluded from the capability version.
	capabilityHash := sha256.Sum256(capabilityMaterial)
	runtimeProfiles := make([]wsproto.RuntimeProfileAdvertisement, 0, len(cfg.RuntimeProfiles))
	activeRuntimeProfile := ""
	for _, profile := range cfg.RuntimeProfiles {
		runtimeProfiles = append(runtimeProfiles, wsproto.RuntimeProfileAdvertisement{ID: profile.ID, ContextLimit: profile.ContextLimit, Slots: profile.Slots})
		if profile.ContextLimit == contextLimit && profile.Slots == slots {
			activeRuntimeProfile = profile.ID
		}
	}
	modelCapacityObservations := make([]wsproto.ModelCapacityObservationAdvertisement, 0, len(vramByModel))
	// A configured profile set must identify the active mode before bytes can
	// be bound to a model/profile row. An empty profile is only the explicit
	// legacy/default mode when the runtime advertises no profile set.
	if standaloneVRAMVerified && (len(runtimeProfiles) == 0 || activeRuntimeProfile != "") {
		targetID := cfg.ID
		if !strings.HasPrefix(targetID, nodeID+"-") {
			targetID = nodeID + "-" + targetID
		}
		acceleratorID := fmt.Sprintf("%s-gpu%d", nodeID, cfg.AcceleratorIndex)
		for model, measuredBytes := range vramByModel {
			if measuredBytes <= 0 || !hasString(residentModels, model) {
				continue
			}
			modelCapacityObservations = append(modelCapacityObservations, wsproto.ModelCapacityObservationAdvertisement{
				AcceleratorID: acceleratorID, Model: model, ProfileID: activeRuntimeProfile,
				ModelFingerprint:  hex.EncodeToString(modelHash[:]),
				RuntimeIdentity:   strings.Join([]string{targetID, "llamacpp", "", "llamacpp-" + hex.EncodeToString(capabilityHash[:8]), hex.EncodeToString(modelHash[:])}, "|"),
				CapabilityVersion: "llamacpp-" + hex.EncodeToString(capabilityHash[:8]), CapabilityRevision: domain.CapabilityContractVersion,
				ModelBytes: measuredBytes, ObservedAt: time.Now().UTC(), Source: "runtime:/api/ps:size_vram", Verified: true,
			})
		}
	}
	return wsproto.AdapterAdvertisement{
		ID: id, Adapter: "llamacpp", Endpoint: publicEndpoint,
		AcceleratorIndex: cfg.AcceleratorIndex, Models: models, ResidentModels: residentModels,
		Version:          "llamacpp-" + hex.EncodeToString(capabilityHash[:8]),
		ModelFingerprint: hex.EncodeToString(modelHash[:]), ContextLimit: contextLimit, Slots: slots,
		CapacitySource: capacitySource, CapabilitiesVerified: verified, RuntimeArgs: append([]string(nil), cfg.RuntimeArgs...),
		SupportsModelLifecycle: supportsLifecycle, MaxResidentModels: cfg.MaxResidentModels,
		// A discovered advertisement is a versioned target document. Keep the
		// explicit false lifecycle fact on the wire so controller defaults from
		// the node envelope cannot widen a passive runtime back into support.
		CapabilityRevision: domain.CapabilityContractVersion,
		Capabilities:       domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion, SupportsModelLifecycle: supportsLifecycle},
		QueueRunning:       running, StandaloneVRAMMB: standaloneVRAMMB, StandaloneVRAMSource: standaloneVRAMSource, StandaloneVRAMVerified: standaloneVRAMVerified,
		RuntimeProfiles: runtimeProfiles, ActiveRuntimeProfile: activeRuntimeProfile, SupportsRuntimeProfileSwitch: len(runtimeProfiles) > 0,
		ModelCapacityObservations: modelCapacityObservations,
	}, nil
}

func hasString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func ollamaRunningModels(body json.RawMessage) ([]string, map[string]int64, bool, bool) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, false, false
	}
	raw, found := envelope["models"]
	if !found {
		return nil, nil, false, false
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, nil, false, false
	}
	models := make([]string, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	// size_vram is reported in bytes. Preserve it exactly for the durable
	// observation; only the legacy standalone_vram_mb advertisement rounds up.
	vramByModel := make(map[string]int64, len(rows))
	var completePositiveBytes int64
	completeRow := false
	for _, row := range rows {
		var modelName, aliasName string
		if value, ok := row["model"]; ok {
			_ = json.Unmarshal(value, &modelName)
		}
		if value, ok := row["name"]; ok {
			_ = json.Unmarshal(value, &aliasName)
		}
		name := modelName
		if name == "" {
			name = aliasName
		}
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		models = append(models, name)
		if len(rows) == 1 {
			var sizeVRAM int64
			if value, ok := row["size_vram"]; ok && json.Unmarshal(value, &sizeVRAM) == nil && sizeVRAM > 0 {
				completePositiveBytes = sizeVRAM
				completeRow = true
			}
		}
	}
	sort.Strings(models)
	capacityOK := len(rows) == 1 && len(models) == 1 && completeRow
	if !capacityOK {
		return models, nil, true, false
	}
	vramByModel[models[0]] = completePositiveBytes
	return models, vramByModel, true, true
}

func getJSON(ctx context.Context, url string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("runtime request could not be created")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.New("runtime request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("runtime discovery returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, errors.New("runtime response could not be read")
	}
	if !json.Valid(body) {
		return nil, errors.New("runtime response was not valid JSON")
	}
	return body, nil
}

func llamaModels(body json.RawMessage) ([]string, []string, bool, []byte, error) {
	entries, plain, err := wsproto.ParseLlamaModels(body)
	if err != nil {
		return nil, nil, false, nil, err
	}
	models := make([]string, 0, len(entries))
	resident := make([]string, 0, len(entries))
	routerDetected := false
	for _, model := range entries {
		models = append(models, model.ID)
		routerDetected = routerDetected || (!plain && model.State != wsproto.RouterModelUnknown)
		if model.State == wsproto.RouterModelLoaded {
			resident = append(resident, model.ID)
		}
	}
	sort.Strings(models)
	sort.Strings(resident)
	// RuntimeFingerprint is an identity fence, not a residency/status
	// snapshot.  Only the canonical model IDs participate; mutable fields
	// such as loaded/ready status must never invalidate a stable manifest.
	material, _ := json.Marshal(models)
	return models, resident, routerDetected, material, nil
}

type llamaState string

const (
	llamaStateLoaded       llamaState = "loaded"
	llamaStateUnloaded     llamaState = "unloaded"
	llamaStateTransitional llamaState = "transitional"
	llamaStateUnknown      llamaState = "unknown"
)

func llamaModelState(raw json.RawMessage) (llamaState, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return llamaStateUnknown, false, errors.New("runtime model status is not an authoritative string")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return llamaStateUnknown, false, errors.New("runtime model status is not an authoritative string")
	}
	switch text {
	case "loaded":
		return llamaStateLoaded, true, nil
	case "unloaded":
		return llamaStateUnloaded, true, nil
	case "loading", "unloading", "unknown":
		return llamaStateTransitional, true, nil
	default:
		return llamaStateUnknown, true, nil
	}
}

func llamaModelStateFromBody(body json.RawMessage, wanted string) (llamaState, error) {
	state, err := wsproto.ParseRouterModelState(body, wanted)
	if err != nil {
		return llamaStateUnknown, err
	}
	switch state {
	case wsproto.RouterModelLoaded:
		return llamaStateLoaded, nil
	case wsproto.RouterModelUnloaded:
		return llamaStateUnloaded, nil
	default:
		return llamaStateTransitional, nil
	}
}

func discoverLlamaModelState(ctx context.Context, cfg LlamaCPPServerConfig, wanted string) (llamaState, error) {
	body, err := getJSON(ctx, strings.TrimRight(cfg.Endpoint, "/")+"/v1/models")
	if err != nil {
		return llamaStateUnknown, errors.New("runtime model status could not be discovered")
	}
	return llamaModelStateFromBody(body, wanted)
}

func discoverLlamaRouterModels(ctx context.Context, cfg LlamaCPPServerConfig) ([]wsproto.RouterModelRecord, error) {
	body, err := getJSON(ctx, strings.TrimRight(cfg.Endpoint, "/")+"/v1/models")
	if err != nil {
		return nil, errors.New("runtime model status could not be discovered")
	}
	return wsproto.ParseRouterModels(body)
}

// waitLlamaModelState observes the shared router state vocabulary directly.
// Transitional states are never coerced to cold; callers get a bounded
// context-controlled wait and an indeterminate error on timeout.
func waitLlamaModelState(ctx context.Context, cfg LlamaCPPServerConfig, wanted string) (llamaState, error) {
	for {
		state, err := discoverLlamaModelState(ctx, cfg, wanted)
		if err != nil {
			return llamaStateUnknown, err
		}
		if state != llamaStateTransitional {
			return state, nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return llamaStateTransitional, ctx.Err()
		case <-timer.C:
		}
	}
}

func llamaSlots(body json.RawMessage) (contextLimit, slots, running int) {
	var response []json.RawMessage
	if json.Unmarshal(body, &response) != nil {
		return 0, 0, 0
	}
	for _, rawSlot := range response {
		if len(rawSlot) == 0 || string(rawSlot) == "null" {
			return 0, 0, 0
		}
		var slot map[string]json.RawMessage
		if json.Unmarshal(rawSlot, &slot) != nil || slot == nil {
			return 0, 0, 0
		}
		rawContext, present := slot["n_ctx"]
		if !present {
			return 0, 0, 0
		}
		var context int
		if json.Unmarshal(rawContext, &context) != nil || context <= 0 {
			return 0, 0, 0
		}
		rawProcessing, present := slot["is_processing"]
		if !present || len(rawProcessing) == 0 || string(rawProcessing) == "null" {
			return 0, 0, 0
		}
		var processing bool
		if json.Unmarshal(rawProcessing, &processing) != nil {
			return 0, 0, 0
		}
		if processing {
			running++
		}
		if contextLimit == 0 || context < contextLimit {
			contextLimit = context
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
