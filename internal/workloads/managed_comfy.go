package workloads

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

const managedComfyProtocol = "managed_comfy_v1"
const managedComfyWireVersion = "managed-comfy/v1"

type managedComfyStartRequest struct {
	ProtocolVersion string          `json:"protocol_version"`
	WorkloadID      string          `json:"workload_id"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Payload         json.RawMessage `json:"payload"`
	PlanHash        string          `json:"plan_hash,omitempty"`
	CheckpointRef   string          `json:"checkpoint_ref,omitempty"`
}

type managedComfyState struct {
	ProtocolVersion string          `json:"protocol_version"`
	ExecutionID     string          `json:"execution_id"`
	State           string          `json:"state"`
	CheckpointRef   string          `json:"checkpoint_ref,omitempty"`
	Progress        float64         `json:"progress,omitempty"`
	ProgressStage   string          `json:"progress_stage,omitempty"`
	ProgressNode    string          `json:"progress_node,omitempty"`
	ProgressCurrent int             `json:"progress_current,omitempty"`
	ProgressTotal   int             `json:"progress_total,omitempty"`
	Error           string          `json:"error,omitempty"`
	VRAMUsedMB      int64           `json:"vram_used_mb,omitempty"`
	Slowdown        float64         `json:"slowdown,omitempty"`
	TemperatureC    float64         `json:"temperature_c,omitempty"`
	Output          json.RawMessage `json:"output,omitempty"`
	ArtifactRefs    []string        `json:"artifact_refs,omitempty"`
}

func disruptionCapabilitiesForTarget(adapter Adapter, target Target) DisruptionCapabilities {
	if targeted, ok := adapter.(TargetDisruptionCapabilityAdapter); ok {
		return targeted.DisruptionCapabilitiesForTarget(target)
	}
	if capabilities, ok := adapter.(DisruptionCapabilityAdapter); ok {
		return capabilities.DisruptionCapabilities()
	}
	return DisruptionCapabilities{}
}

func targetSupportsDisruption(adapter Adapter, target Target, policy domain.DisruptionPolicy) bool {
	if _, targeted := adapter.(TargetDisruptionCapabilityAdapter); !targeted {
		if _, declared := adapter.(DisruptionCapabilityAdapter); !declared {
			// Preserve legacy/custom adapters whose behavior is validated by their
			// own implementation. Built-in HTTP adapters always declare support.
			return true
		}
	}
	capabilities := disruptionCapabilitiesForTarget(adapter, target)
	switch policy {
	case domain.DisruptionYieldable:
		return capabilities.Yield
	case domain.DisruptionCheckpointable:
		return capabilities.Checkpoint
	case domain.DisruptionCancelable:
		return capabilities.Cancel
	default:
		return true
	}
}

func (a *HTTPAdapter) startManagedComfy(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target, checkpoint string) (*domain.ExecutionHandle, error) {
	if err := a.stageComfyInputs(ctx, req, target); err != nil {
		return nil, err
	}
	payload := req.Payload
	planHash := ""
	if plan != nil {
		planHash = plan.PlanHash
		if len(plan.Material) > 0 {
			payload = plan.Material
		}
	}
	idempotencyKey := req.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = req.ID
	}
	body, err := json.Marshal(managedComfyStartRequest{
		ProtocolVersion: managedComfyWireVersion,
		WorkloadID:      req.ID, IdempotencyKey: idempotencyKey,
		Payload: payload, PlanHash: planHash, CheckpointRef: checkpoint,
	})
	if err != nil {
		return nil, err
	}
	state, err := a.managedComfyRequest(ctx, http.MethodPost, target, "/v1/executions", body, idempotencyKey)
	if err != nil {
		return nil, err
	}
	if state.ExecutionID == "" {
		return nil, fmt.Errorf("managed Comfy start returned no execution_id")
	}
	if !managedComfyStartState(state.State) {
		return nil, fmt.Errorf("managed Comfy start returned non-active state %q", state.State)
	}
	return &domain.ExecutionHandle{ExternalID: state.ExecutionID, StartedAt: time.Now().UTC()}, nil
}

func (a *HTTPAdapter) observeManagedComfy(ctx context.Context, h *domain.ExecutionHandle, target Target) (Observation, error) {
	if h == nil || h.ExternalID == "" {
		return Observation{}, fmt.Errorf("managed Comfy observe requires execution_id")
	}
	state, err := a.managedComfyRequest(ctx, http.MethodGet, target, managedComfyExecutionPath(h.ExternalID), nil, "")
	if err != nil {
		return Observation{}, err
	}
	observation := Observation{Progress: state.Progress, ProgressStage: state.ProgressStage, ProgressNode: state.ProgressNode, ProgressCurrent: state.ProgressCurrent, ProgressTotal: state.ProgressTotal, Error: state.Error, VRAMUsedMB: state.VRAMUsedMB, Slowdown: state.Slowdown, TemperatureC: state.TemperatureC}
	switch strings.ToLower(state.State) {
	case "queued", "preparing", "running":
		observation.Status = domain.WorkloadRunning
	case "completed", "succeeded":
		observation.Status, observation.Progress = domain.WorkloadSucceeded, 1
	case "failed":
		observation.Status = domain.WorkloadFailed
		if observation.Error == "" {
			observation.Error = "managed Comfy execution failed"
		}
	case "cancelled":
		observation.Status = domain.WorkloadCancelled
	case "yielded", "checkpointed":
		return Observation{}, fmt.Errorf("managed Comfy execution %s stopped outside a scheduler control operation", h.ExternalID)
	default:
		return Observation{}, fmt.Errorf("managed Comfy returned unknown state %q", state.State)
	}
	return observation, nil
}

func (a *HTTPAdapter) controlManagedComfy(ctx context.Context, h *domain.ExecutionHandle, target Target, operation, expected string) error {
	if h == nil || h.ExternalID == "" {
		return fmt.Errorf("managed Comfy %s requires execution_id", operation)
	}
	state, err := a.managedComfyRequest(ctx, http.MethodPost, target, managedComfyExecutionPath(h.ExternalID)+"/"+operation, []byte(`{}`), h.ExternalID+":"+operation)
	if err != nil {
		return err
	}
	if !strings.EqualFold(state.State, expected) {
		return fmt.Errorf("managed Comfy %s did not confirm %s state; got %q", operation, expected, state.State)
	}
	return nil
}

func (a *HTTPAdapter) checkpointManagedComfy(ctx context.Context, h *domain.ExecutionHandle, target Target) (string, error) {
	if err := a.controlManagedComfy(ctx, h, target, "checkpoint", "checkpointed"); err != nil {
		return "", err
	}
	state, err := a.managedComfyRequest(ctx, http.MethodGet, target, managedComfyExecutionPath(h.ExternalID), nil, "")
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(state.State, "checkpointed") || strings.TrimSpace(state.CheckpointRef) == "" {
		return "", fmt.Errorf("managed Comfy checkpoint lacks a confirmed checkpoint_ref")
	}
	return state.CheckpointRef, nil
}

func (a *HTTPAdapter) cancelManagedComfy(ctx context.Context, h *domain.ExecutionHandle, target Target) error {
	if h == nil || h.ExternalID == "" {
		return fmt.Errorf("managed Comfy cancel requires execution_id")
	}
	state, err := a.managedComfyRequest(ctx, http.MethodPost, target, managedComfyExecutionPath(h.ExternalID)+"/cancel", []byte(`{}`), h.ExternalID+":cancel")
	if err != nil {
		return err
	}
	switch strings.ToLower(state.State) {
	case "cancelled", "completed", "succeeded", "failed", "yielded", "checkpointed":
		return nil
	default:
		return fmt.Errorf("managed Comfy cancel did not confirm a stopped state; got %q", state.State)
	}
}

func (a *HTTPAdapter) collectManagedComfyOutputs(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, h *domain.ExecutionHandle, target Target) (json.RawMessage, []string, error) {
	if h == nil || h.ExternalID == "" {
		return nil, nil, fmt.Errorf("managed Comfy output collection requires execution_id")
	}
	state, err := a.managedComfyRequest(ctx, http.MethodGet, target, managedComfyExecutionPath(h.ExternalID)+"/outputs", nil, "")
	if err != nil {
		return nil, nil, err
	}
	if !strings.EqualFold(state.State, "completed") && !strings.EqualFold(state.State, "succeeded") {
		return nil, nil, fmt.Errorf("managed Comfy outputs are not terminal: %q", state.State)
	}
	if a.artifacts != nil && len(state.Output) > 0 {
		output, refs, collectErr := a.collectComfyOutputs(ctx, req, plan, state.Output, target)
		if collectErr != nil {
			return nil, nil, collectErr
		}
		refs = append(refs, state.ArtifactRefs...)
		return output, refs, nil
	}
	return append(json.RawMessage(nil), state.Output...), append([]string(nil), state.ArtifactRefs...), nil
}

func (a *HTTPAdapter) managedComfyRequest(ctx context.Context, method string, target Target, path string, body []byte, idempotencyKey string) (managedComfyState, error) {
	var state managedComfyState
	endpoint := strings.TrimRight(target.Endpoint, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return state, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if target.Authorization != "" {
		req.Header.Set("Authorization", target.Authorization)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := a.client.Do(req)
	if err != nil {
		return state, &BackendError{TargetID: target.ID, Retryable: true, RetryAfter: 5 * time.Second, Message: "managed Comfy transport failed: " + err.Error(), Cause: err}
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, fmt.Errorf("managed Comfy returned invalid state document: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := state.Error
		if message == "" {
			message = fmt.Sprintf("managed Comfy returned %d", response.StatusCode)
		}
		return state, &BackendError{TargetID: target.ID, Status: response.StatusCode, Retryable: response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After")), Message: message}
	}
	if state.ProtocolVersion != managedComfyWireVersion {
		return state, fmt.Errorf("managed Comfy protocol mismatch: got %q want %q", state.ProtocolVersion, managedComfyWireVersion)
	}
	return state, nil
}

func managedComfyExecutionPath(executionID string) string {
	return "/v1/executions/" + url.PathEscape(executionID)
}

func managedComfyStartState(state string) bool {
	switch strings.ToLower(state) {
	case "queued", "preparing", "running", "completed", "succeeded":
		return true
	default:
		return false
	}
}
