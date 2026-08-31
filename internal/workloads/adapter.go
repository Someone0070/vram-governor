// Package workloads owns the unified queue, placement decisions, adapter
// contract, and physical-accelerator leases used by every gateway plane.
package workloads

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"vram-governor/internal/domain"
)

var ErrUnsupported = errors.New("workload operation unsupported")

// BackendError carries enough structured provider state for the scheduler to
// make one deliberate fallback decision. Adapters never retry internally.
type BackendError struct {
	TargetID   string
	Status     int
	Retryable  bool
	RetryAfter time.Duration
	Message    string
	Cause      error
}

func (e *BackendError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Status != 0 {
		return fmt.Sprintf("backend returned %d", e.Status)
	}
	return "backend request failed"
}

func (e *BackendError) Unwrap() error { return e.Cause }

type Requirements struct {
	Model               string   `json:"model,omitempty"`
	RequiredModels      []string `json:"required_models,omitempty"`
	CustomNodes         []string `json:"custom_nodes,omitempty"`
	EstimatedVRAMMB     int64    `json:"estimated_vram_mb,omitempty"`
	ContextTokens       int      `json:"context_tokens,omitempty"`
	AcceleratorRequired bool     `json:"accelerator_required"`
}

type Target struct {
	ID                         string                     `json:"id" yaml:"id"`
	Adapter                    string                     `json:"adapter" yaml:"adapter"`
	Endpoint                   string                     `json:"endpoint" yaml:"endpoint"`
	AcceleratorID              string                     `json:"accelerator_id,omitempty" yaml:"accelerator_id"`
	Models                     []string                   `json:"models,omitempty" yaml:"models"`
	ResidentModels             []string                   `json:"resident_models,omitempty" yaml:"resident_models"`
	CustomNodes                []string                   `json:"custom_nodes,omitempty" yaml:"custom_nodes"`
	ContextLimit               int                        `json:"context_limit,omitempty" yaml:"context_limit"`
	Slots                      int                        `json:"slots" yaml:"slots"`
	Active                     int                        `json:"active" yaml:"-"`
	CapabilityVersion          string                     `json:"capability_version,omitempty" yaml:"capability_version"`
	ModelFingerprint           string                     `json:"model_fingerprint,omitempty" yaml:"model_fingerprint"`
	CapacitySource             string                     `json:"capacity_source,omitempty" yaml:"capacity_source"`
	CapacityVerified           bool                       `json:"capacity_verified" yaml:"capacity_verified"`
	RuntimeArgs                []string                   `json:"runtime_args,omitempty" yaml:"runtime_args"`
	SupportsModelLifecycle     bool                       `json:"supports_model_lifecycle" yaml:"supports_model_lifecycle"`
	SupportsAcceleratorReclaim bool                       `json:"supports_accelerator_reclaim" yaml:"supports_accelerator_reclaim"`
	MaxResidentModels          int                        `json:"max_resident_models,omitempty" yaml:"max_resident_models"`
	WarmRAMSupported           bool                       `json:"warm_ram_supported" yaml:"warm_ram_supported"`
	QueueRunning               int                        `json:"queue_running,omitempty" yaml:"-"`
	QueuePending               int                        `json:"queue_pending,omitempty" yaml:"-"`
	ResidencyPolicy            domain.ResidencyPolicyMode `json:"residency_policy" yaml:"residency_policy"`
	IdleUnloadAfter            time.Duration              `json:"idle_unload_after,omitempty" yaml:"-"`
	MinResidency               time.Duration              `json:"min_residency,omitempty" yaml:"-"`
	Cloud                      bool                       `json:"cloud" yaml:"cloud"`
	Enabled                    bool                       `json:"enabled" yaml:"enabled"`
	Authorization              string                     `json:"-" yaml:"authorization"`
	InputCentsPerMTok          int64                      `json:"input_cents_per_million_tokens,omitempty" yaml:"input_cents_per_million_tokens"`
	OutputCentsPerMTok         int64                      `json:"output_cents_per_million_tokens,omitempty" yaml:"output_cents_per_million_tokens"`
	CircuitState               string                     `json:"circuit_state,omitempty" yaml:"-"`
	CircuitOpenUntil           *time.Time                 `json:"circuit_open_until,omitempty" yaml:"-"`
	CircuitFailures            int                        `json:"circuit_failures,omitempty" yaml:"-"`
	WorkloadClass              string                     `json:"workload_class,omitempty" yaml:"workload_class"`
	StandaloneVRAMMB           int64                      `json:"standalone_vram_mb,omitempty" yaml:"standalone_vram_mb"`
	StandaloneVRAMSource       string                     `json:"standalone_vram_source,omitempty" yaml:"-"`
	StandaloneVRAMVerified     bool                       `json:"standalone_vram_verified" yaml:"-"`
	AcceleratorVRAMMB          int64                      `json:"accelerator_vram_mb,omitempty" yaml:"accelerator_vram_mb"`
	VRAMReserveMB              int64                      `json:"vram_reserve_mb,omitempty" yaml:"vram_reserve_mb"`
	SharingEnabled             bool                       `json:"sharing_enabled" yaml:"sharing_enabled"`
	GuardedExploration         bool                       `json:"guarded_exploration" yaml:"guarded_exploration"`
	PredictedSlowdown          float64                    `json:"predicted_slowdown,omitempty" yaml:"predicted_slowdown"`
	MaxSlowdown                float64                    `json:"max_slowdown,omitempty" yaml:"max_slowdown"`
	SafetyCritical             bool                       `json:"safety_critical" yaml:"safety_critical"`
	Provider                   string                     `json:"provider,omitempty" yaml:"provider"`
	Quarantined                bool                       `json:"quarantined" yaml:"quarantined"`
}

type Observation struct {
	Status          domain.WorkloadStatus `json:"status"`
	Progress        float64               `json:"progress,omitempty"`
	ProgressStage   string                `json:"progress_stage,omitempty"`
	ProgressNode    string                `json:"progress_node,omitempty"`
	ProgressCurrent int                   `json:"progress_current,omitempty"`
	ProgressTotal   int                   `json:"progress_total,omitempty"`
	Error           string                `json:"error,omitempty"`
	VRAMUsedMB      int64                 `json:"vram_used_mb,omitempty"`
	Slowdown        float64               `json:"slowdown,omitempty"`
	TemperatureC    float64               `json:"temperature_c,omitempty"`
}

// Adapter deliberately exposes lifecycle operations beyond Execute. Adapters
// may return ErrUnsupported, but the scheduler can only advertise disruption
// behavior that the selected adapter actually implements.
type Adapter interface {
	Name() string
	Version() string
	Validate(context.Context, domain.WorkloadRequest) error
	Requirements(context.Context, domain.WorkloadRequest) (Requirements, error)
	Plan(context.Context, domain.WorkloadRequest, Target) (*domain.ExecutionPlan, error)
	Start(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, Target) (*domain.ExecutionHandle, error)
	Observe(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (Observation, error)
	Yield(context.Context, *domain.ExecutionHandle, Target) error
	Checkpoint(context.Context, *domain.ExecutionHandle, Target) (string, error)
	Resume(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, string, Target) (*domain.ExecutionHandle, error)
	Cancel(context.Context, *domain.ExecutionHandle, Target) error
	CollectOutputs(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (json.RawMessage, []string, error)
}

// StreamingAdapter is an optional extension for adapters that can preserve
// backend streaming semantics. emit applies client backpressure directly to
// the backend response body and must return promptly on client cancellation.
type StreamingAdapter interface {
	StartStream(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, Target, func([]byte) error) (*domain.ExecutionHandle, error)
}

// AsyncStartAdapter lets a polling runtime return control to the scheduler
// while the backend request is still executing. This is required for live
// guardrails and cancellation; a synchronous Start cannot be observed until
// after the risky work has already finished.
type AsyncStartAdapter interface {
	StartAsync(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, Target) (*domain.ExecutionHandle, error)
}

// DisruptionCapabilities makes preemption promises explicit. Built-in
// adapters implement this so a request cannot claim resumability that its
// selected runtime does not actually provide.
type DisruptionCapabilities struct {
	Yield      bool `json:"yield"`
	Checkpoint bool `json:"checkpoint"`
	Cancel     bool `json:"cancel"`
}

type DisruptionCapabilityAdapter interface {
	DisruptionCapabilities() DisruptionCapabilities
}

// ModelLifecycleAdapter controls models already known to an allowlisted
// runtime router. It never downloads or installs a model.
type ModelLifecycleAdapter interface {
	LoadModel(context.Context, Target, string) error
	UnloadModel(context.Context, Target, string) error
}

// AcceleratorReclaimer releases runtime caches that are not represented as
// individually loadable models. External ComfyUI implements this with its
// local /free operation; it never downloads, installs, or removes artifacts.
type AcceleratorReclaimer interface {
	ReclaimAccelerator(context.Context, Target) error
}

// WarmRAMLifecycleAdapter is a separate capability because stock llama.cpp
// router unloads weights rather than guaranteeing host-RAM retention.
type WarmRAMLifecycleAdapter interface {
	OffloadModelToRAM(context.Context, Target, string) error
}

func containsString(values []string, wanted string) bool {
	if wanted == "" {
		return true
	}
	for _, value := range values {
		if value == wanted || value == "*" {
			return true
		}
	}
	return false
}
