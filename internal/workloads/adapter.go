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
	checkpointRuntime "vram-governor/internal/runtime"
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
	Model                     string   `json:"model,omitempty"`
	RequiredModels            []string `json:"required_models,omitempty"`
	CustomNodes               []string `json:"custom_nodes,omitempty"`
	EstimatedVRAMMB           int64    `json:"estimated_vram_mb,omitempty"`
	ContextTokens             int      `json:"context_tokens,omitempty"`
	RuntimeProtocol           string   `json:"runtime_protocol,omitempty"`
	AcceleratorRequired       bool     `json:"accelerator_required"`
	WarmModelBytesRequired    bool     `json:"warm_model_bytes_required,omitempty"`
	SessionCheckpointRequired bool     `json:"session_checkpoint_required,omitempty"`
}

// RequestVRAMIncrementObservation is an identity-bound, runtime-authoritative
// upper bound for bytes allocated in addition to the already measured model
// and runtime-profile footprint. Generic request estimates are deliberately
// not accepted here.
type RequestVRAMIncrementObservation struct {
	TargetID           string    `json:"target_id"`
	AcceleratorID      string    `json:"accelerator_id"`
	RequestID          string    `json:"request_id"`
	Model              string    `json:"model"`
	ProfileID          string    `json:"profile_id"`
	RuntimeIdentity    string    `json:"runtime_identity"`
	CapabilityVersion  string    `json:"capability_version"`
	CapabilityRevision string    `json:"capability_revision"`
	ModelFingerprint   string    `json:"model_fingerprint"`
	TargetGeneration   uint64    `json:"target_generation"`
	ContextTokens      int       `json:"context_tokens"`
	Bytes              int64     `json:"bytes"`
	Source             string    `json:"source"`
	Verified           bool      `json:"verified"`
	ObservedAt         time.Time `json:"observed_at"`
}

// RequestVRAMIncrementObserver is optional. Implementations must obtain the
// bound from the selected runtime, not from client payload estimates.
type RequestVRAMIncrementObserver interface {
	ObserveRequestVRAMIncrement(context.Context, Target, domain.WorkloadRequest, Requirements) (RequestVRAMIncrementObservation, error)
}

type Target struct {
	ID                           string                                      `json:"id" yaml:"id"`
	NodeID                       string                                      `json:"node_id,omitempty" yaml:"node_id,omitempty"`
	Adapter                      string                                      `json:"adapter" yaml:"adapter"`
	Endpoint                     string                                      `json:"endpoint" yaml:"endpoint"`
	RuntimeProtocol              string                                      `json:"runtime_protocol,omitempty" yaml:"runtime_protocol"`
	AcceleratorID                string                                      `json:"accelerator_id,omitempty" yaml:"accelerator_id"`
	Models                       []string                                    `json:"models,omitempty" yaml:"models"`
	Profiles                     []domain.RuntimeProfile                     `json:"profiles,omitempty" yaml:"profiles"`
	ResidentModels               []string                                    `json:"resident_models,omitempty" yaml:"resident_models"`
	CustomNodes                  []string                                    `json:"custom_nodes,omitempty" yaml:"custom_nodes"`
	ContextLimit                 int                                         `json:"context_limit,omitempty" yaml:"context_limit"`
	Slots                        int                                         `json:"slots" yaml:"slots"`
	Active                       int                                         `json:"active" yaml:"-"`
	CapabilityVersion            string                                      `json:"capability_version,omitempty" yaml:"capability_version"`
	RuntimeIdentity              string                                      `json:"runtime_identity,omitempty" yaml:"runtime_identity"`
	CapabilityRevision           string                                      `json:"capability_revision,omitempty" yaml:"capability_revision"`
	CapabilityGeneration         uint64                                      `json:"capability_generation,omitempty" yaml:"capability_generation"`
	Capabilities                 domain.ResidencyCapabilities                `json:"capabilities" yaml:"capabilities"`
	Capacity                     domain.CapacityBudget                       `json:"capacity" yaml:"capacity"`
	MaxAcceleratorsPerWorkload   int                                         `json:"max_accelerators_per_workload" yaml:"max_accelerators_per_workload"`
	ModelFingerprint             string                                      `json:"model_fingerprint,omitempty" yaml:"model_fingerprint"`
	CapacitySource               string                                      `json:"capacity_source,omitempty" yaml:"capacity_source"`
	CapacityVerified             bool                                        `json:"capacity_verified" yaml:"capacity_verified"`
	RuntimeArgs                  []string                                    `json:"runtime_args,omitempty" yaml:"runtime_args"`
	SupportsModelLifecycle       bool                                        `json:"supports_model_lifecycle" yaml:"supports_model_lifecycle"`
	SupportsAcceleratorReclaim   bool                                        `json:"supports_accelerator_reclaim" yaml:"supports_accelerator_reclaim"`
	MaxResidentModels            int                                         `json:"max_resident_models,omitempty" yaml:"max_resident_models"`
	WarmRAMSupported             bool                                        `json:"warm_ram_supported" yaml:"warm_ram_supported"`
	QueueRunning                 int                                         `json:"queue_running,omitempty" yaml:"-"`
	QueuePending                 int                                         `json:"queue_pending,omitempty" yaml:"-"`
	ResidencyPolicy              domain.ResidencyPolicyMode                  `json:"residency_policy" yaml:"residency_policy"`
	IdleUnloadAfter              time.Duration                               `json:"idle_unload_after,omitempty" yaml:"-"`
	MinResidency                 time.Duration                               `json:"min_residency,omitempty" yaml:"-"`
	Cloud                        bool                                        `json:"cloud" yaml:"cloud"`
	Enabled                      bool                                        `json:"enabled" yaml:"enabled"`
	// ComfyUI marks a native ComfyUI that serves the LB-hosted web UI. Only
	// requests pinned to it run there, and it never opens its own websocket
	// with the browser's client id (that would take the browser's events).
	ComfyUI bool `json:"comfy_ui,omitempty" yaml:"comfy_ui"`
	Authorization                string                                      `json:"-" yaml:"authorization"`
	InputCentsPerMTok            int64                                       `json:"input_cents_per_million_tokens,omitempty" yaml:"input_cents_per_million_tokens"`
	OutputCentsPerMTok           int64                                       `json:"output_cents_per_million_tokens,omitempty" yaml:"output_cents_per_million_tokens"`
	CircuitState                 string                                      `json:"circuit_state,omitempty" yaml:"-"`
	CircuitOpenUntil             *time.Time                                  `json:"circuit_open_until,omitempty" yaml:"-"`
	CircuitFailures              int                                         `json:"circuit_failures,omitempty" yaml:"-"`
	WorkloadClass                string                                      `json:"workload_class,omitempty" yaml:"workload_class"`
	StandaloneVRAMMB             int64                                       `json:"standalone_vram_mb,omitempty" yaml:"standalone_vram_mb"`
	StandaloneVRAMSource         string                                      `json:"standalone_vram_source,omitempty" yaml:"-"`
	StandaloneVRAMVerified       bool                                        `json:"standalone_vram_verified" yaml:"-"`
	AcceleratorVRAMMB            int64                                       `json:"accelerator_vram_mb,omitempty" yaml:"accelerator_vram_mb"`
	VRAMReserveMB                int64                                       `json:"vram_reserve_mb,omitempty" yaml:"vram_reserve_mb"`
	SharingEnabled               bool                                        `json:"sharing_enabled" yaml:"sharing_enabled"`
	GuardedExploration           bool                                        `json:"guarded_exploration" yaml:"guarded_exploration"`
	PredictedSlowdown            float64                                     `json:"predicted_slowdown,omitempty" yaml:"predicted_slowdown"`
	MaxSlowdown                  float64                                     `json:"max_slowdown,omitempty" yaml:"max_slowdown"`
	SafetyCritical               bool                                        `json:"safety_critical" yaml:"safety_critical"`
	RuntimeProfiles              []RuntimeCapacityProfile                    `json:"runtime_profiles,omitempty" yaml:"runtime_profiles"`
	ActiveRuntimeProfile         string                                      `json:"active_runtime_profile,omitempty" yaml:"active_runtime_profile"`
	SupportsRuntimeProfileSwitch bool                                        `json:"supports_runtime_profile_switch" yaml:"supports_runtime_profile_switch"`
	Provider                     string                                      `json:"provider,omitempty" yaml:"provider"`
	Quarantined                  bool                                        `json:"quarantined" yaml:"quarantined"`
	CheckpointProof              checkpointRuntime.CheckpointCapabilityProof `json:"checkpoint_proof,omitempty" yaml:"-"`
}

// RuntimeCapacityProfile is a client-visible, finite context/concurrency mode.
// Executable switch commands remain private to the owning node.
type RuntimeCapacityProfile struct {
	ID           string `json:"id" yaml:"id"`
	ContextLimit int    `json:"context_limit" yaml:"context_limit"`
	Slots        int    `json:"slots" yaml:"slots"`
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

// LeaseAwareCheckpointAdapter is used by the scheduler for production
// preemption. A plain Adapter.Checkpoint cannot safely manufacture a fence.
type LeaseAwareCheckpointAdapter interface {
	CheckpointWithLease(context.Context, *domain.ExecutionHandle, Target, SlotLease, CheckpointCommand) (string, error)
	ResumeWithLease(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, string, Target, SlotLease, CheckpointCommand) (*domain.ExecutionHandle, error)
}

// StreamingAdapter is an optional extension for adapters that can preserve
// backend streaming semantics. emit applies client backpressure directly to
// the backend response body and must return promptly on client cancellation.
type StreamingAdapter interface {
	StartStream(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, Target, func([]byte) error) (*domain.ExecutionHandle, error)
}

// LiveStreamingAdapter publishes a handle before the backend stream finishes.
// The scheduler uses this boundary for cancellation and checkpointing while
// tokens are still being produced. StreamingAdapter remains synchronous for
// legacy callers.
type LiveStreamingAdapter interface {
	StartStreamLive(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, Target, func([]byte) error) (*domain.ExecutionHandle, error)
}

type LeaseAwareStreamingAdapter interface {
	StartStreamWithLease(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, Target, SlotLease, CheckpointCommand, func([]byte) error) (*domain.ExecutionHandle, error)
}

type LeaseAwareStreamingCapability interface{ LeaseStreamingEnabled() bool }

type TargetLeaseAwareStreamingCapability interface {
	LeaseStreamingEnabledForTarget(Target) bool
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

// TargetDisruptionCapabilityAdapter narrows disruption promises for adapters
// that can talk to more than one backend protocol. This prevents a managed
// checkpoint-capable Comfy harness from making native ComfyUI look resumable.
type TargetDisruptionCapabilityAdapter interface {
	DisruptionCapabilitiesForTarget(Target) DisruptionCapabilities
}

// ModelLifecycleAdapter controls models already known to an allowlisted
// runtime router. It never downloads or installs a model.
type ModelLifecycleAdapter interface {
	LoadModel(context.Context, Target, string) error
	UnloadModel(context.Context, Target, string) error
}

// ResidencyObserver is the legacy HTTP lifecycle observation boundary. It is
// deliberately separate from the signed node command path: legacy routers may
// report loaded/unloaded state, but they cannot advertise warm-RAM support.
type ResidencyObserver interface {
	ObserveResidency(context.Context, Target, string) (ResidencyObservation, error)
}

// AcceleratorReclaimer releases runtime caches that are not represented as
// individually loadable models. External ComfyUI implements this with its
// local /free operation; it never downloads, installs, or removes artifacts.
type AcceleratorReclaimer interface {
	ReclaimAccelerator(context.Context, Target) error
}

// AcceleratorReclaimObserver is the authoritative reclaim boundary. A bare
// HTTP success from ReclaimAccelerator is not sufficient to claim that the
// runtime cache is cold; implementations must return the exact post-state
// identity and fence used by the transition.
type AcceleratorReclaimObserver interface {
	ReclaimAcceleratorObserved(context.Context, Target, int64) (ResidencyObservation, error)
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
