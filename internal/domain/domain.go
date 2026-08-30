// Package domain contains the core data-model types shared by the controller
// and the node agent, per architecture.md §32 (Suggested Data Model) and the
// enums referenced in §4/§5/§14/§45.
//
// Phase 1 only implements the Node + Accelerator surface (registry, desired
// vs observed state, heartbeat/telemetry). The remaining §32 entities
// (ModelArtifact, ServingProfile, EngineInstance, WorkerPool, Session, Job,
// WorkItem, TransitionPlan, Event) are declared here as forward-looking
// struct stubs so later phases can slot storage/logic in without redefining
// the shape, but Phase 1 does not wire them into the store or API.
package domain

import "time"

// LocationClass answers "can the controller power-cycle this node?" (§45 #34).
// It is a capability flag, not an architectural split.
type LocationClass string

const (
	LocationLocal  LocationClass = "local"
	LocationRemote LocationClass = "remote"
)

// PowerControlMode per §32 / §4.2.
type PowerControlMode string

const (
	PowerModeAuto      PowerControlMode = "auto"
	PowerModeManual    PowerControlMode = "manual"
	PowerModeOff       PowerControlMode = "off"
	PowerModeDontTouch PowerControlMode = "dont_touch"
	PowerModeExternal  PowerControlMode = "external" // remote/rented nodes (§45 #11)
)

// SchedulingState per §32 ("Use for work" switch, independent of power).
type SchedulingState string

const (
	SchedulingEnabled  SchedulingState = "enabled"
	SchedulingDraining SchedulingState = "draining"
	SchedulingDisabled SchedulingState = "disabled"
)

// DesiredPower is the desired-state half of §5 local power hygiene.
type DesiredPower string

const (
	DesiredPowerOn      DesiredPower = "on"
	DesiredPowerOff     DesiredPower = "off"
	DesiredPowerUnknown DesiredPower = "unknown" // n/a for remote nodes
)

// ConnectivityState is the observed connectivity half of §14/§34A liveness.
type ConnectivityState string

const (
	ConnectivityConnected ConnectivityState = "connected" // heartbeats on time
	ConnectivitySuspect   ConnectivityState = "suspect"   // ~3 missed heartbeats (~6s)
	ConnectivityLost      ConnectivityState = "lost"      // ~15s since last heartbeat
	ConnectivityOffline   ConnectivityState = "offline"   // never connected / cleanly disconnected
)

// LifecycleState is the coarse observed lifecycle per §4.1/§5.1 (remote and
// local power-on sequences share the tail of this state machine). Phase 1
// only ever reports a subset (CONNECTED/READY/OFFLINE); the rest are declared
// for later phases (runtime reconciliation, power sequencing).
type LifecycleState string

const (
	LifecycleOffline     LifecycleState = "offline"
	LifecyclePoweringOn  LifecycleState = "powering_on"
	LifecycleBooting     LifecycleState = "booting"
	LifecycleConnected   LifecycleState = "connected"
	LifecycleProbing     LifecycleState = "probing"
	LifecycleReconciling LifecycleState = "reconciling"
	LifecycleLoading     LifecycleState = "loading"
	LifecycleWarming     LifecycleState = "warming"
	LifecycleReady       LifecycleState = "ready"
	LifecycleBusy        LifecycleState = "busy"
	LifecycleDraining    LifecycleState = "draining"
	LifecycleShuttingDwn LifecycleState = "shutting_down"
	LifecycleError       LifecycleState = "error"
)

// PriorityTier encodes §13 default capacity fill order.
type PriorityTier string

const (
	PriorityP0 PriorityTier = "P0" // connected+enabled remote/rented
	PriorityP1 PriorityTier = "P1" // connected+enabled local
	PriorityP2 PriorityTier = "P2" // eligible local, may be powered on
)

// Desired is the desired-state half of a Node record (§14, §32).
type Desired struct {
	SchedulingEnabled bool             `json:"scheduling_enabled"`
	Power             DesiredPower     `json:"power"`
	DesiredPool       string           `json:"desired_pool,omitempty"`
	AutoReconcile     bool             `json:"auto_reconcile"`
	PowerControlMode  PowerControlMode `json:"power_control_mode"`
}

// Observed is the observed-state half of a Node record (§14, §32).
type Observed struct {
	Connectivity  ConnectivityState `json:"connectivity"`
	Lifecycle     LifecycleState    `json:"lifecycle"`
	Power         DesiredPower      `json:"power"` // actual, best-known
	Ready         bool              `json:"ready"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	LastSeenAt    time.Time         `json:"last_seen_at"`
	AgentVersion  string            `json:"agent_version,omitempty"`
	System        SystemTelemetry   `json:"system"`
	AgentLogs     []LogEntry        `json:"agent_logs,omitempty"`
}

// SystemTelemetry is measured by the node agent from the host operating
// system. Rate fields are derived from consecutive samples, never guessed.
type SystemTelemetry struct {
	Hostname          string    `json:"hostname,omitempty"`
	OS                string    `json:"os,omitempty"`
	Kernel            string    `json:"kernel,omitempty"`
	Architecture      string    `json:"architecture,omitempty"`
	CPUModel          string    `json:"cpu_model,omitempty"`
	CPULogical        int       `json:"cpu_logical,omitempty"`
	CPUUtilizationPct float64   `json:"cpu_utilization_pct,omitempty"`
	Load1             float64   `json:"load_1,omitempty"`
	Load5             float64   `json:"load_5,omitempty"`
	Load15            float64   `json:"load_15,omitempty"`
	RAMTotalMB        int64     `json:"ram_total_mb,omitempty"`
	RAMUsedMB         int64     `json:"ram_used_mb,omitempty"`
	RAMAvailableMB    int64     `json:"ram_available_mb,omitempty"`
	SwapTotalMB       int64     `json:"swap_total_mb,omitempty"`
	SwapUsedMB        int64     `json:"swap_used_mb,omitempty"`
	RootDiskTotalMB   int64     `json:"root_disk_total_mb,omitempty"`
	RootDiskUsedMB    int64     `json:"root_disk_used_mb,omitempty"`
	RootDiskFreeMB    int64     `json:"root_disk_free_mb,omitempty"`
	NetworkAddresses  []string  `json:"network_addresses,omitempty"`
	NetworkRXBPS      float64   `json:"network_rx_bytes_per_second"`
	NetworkTXBPS      float64   `json:"network_tx_bytes_per_second"`
	UptimeSeconds     float64   `json:"uptime_seconds,omitempty"`
	SampledAt         time.Time `json:"sampled_at"`
}

type LogEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Node is the §32 Node entity plus the desired/observed split from §14.
type Node struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	LocationClass   LocationClass   `json:"location_class"`
	PriorityTier    PriorityTier    `json:"priority_tier"`
	SchedulingState SchedulingState `json:"scheduling_state"`

	Desired  Desired  `json:"desired"`
	Observed Observed `json:"observed"`

	Accelerators []Accelerator `json:"accelerators"`

	RegisteredAt time.Time `json:"registered_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RuntimeCapabilities per §6 — reported explicitly by a runtime driver.
// Phase 1 declares the shape; node agent does not populate it yet (no
// runtime driver exists until Phase 2).
type RuntimeCapabilities struct {
	SupportsContinuousBatching    bool `json:"supports_continuous_batching"`
	SupportsWeightSleepToRAM      bool `json:"supports_weight_sleep_to_ram"`
	SupportsKVOffloadCPU          bool `json:"supports_kv_offload_cpu"`
	SupportsKVRestore             bool `json:"supports_kv_restore"`
	SupportsStagedWake            bool `json:"supports_staged_wake"`
	SupportsHotKVResize           bool `json:"supports_hot_kv_resize"`
	SupportsRuntimeRestartProfile bool `json:"supports_runtime_restart_profile"`
	SupportsDrain                 bool `json:"supports_drain"`
	SupportsPrefillDecodeSplit    bool `json:"supports_prefill_decode_split"`
}

// Accelerator is the §32 Accelerator entity, extended with the live
// telemetry fields the node agent reports every heartbeat cycle (Phase 1
// gets these straight from nvidia-smi).
type Accelerator struct {
	ID          string `json:"id"`
	NodeID      string `json:"node_id"`
	Vendor      string `json:"vendor"`
	Model       string `json:"model"`
	VRAMTotalMB int64  `json:"vram_total_mb"`
	Driver      string `json:"driver,omitempty"`

	RuntimeCapabilities *RuntimeCapabilities `json:"runtime_capabilities,omitempty"`

	// Live telemetry (observed), refreshed on every heartbeat.
	VRAMUsedMB       int64   `json:"vram_used_mb"`
	VRAMFreeMB       int64   `json:"vram_free_mb"`
	UtilizationPct   float64 `json:"utilization_pct"`
	TemperatureC     float64 `json:"temperature_c"`
	PowerDrawW       float64 `json:"power_draw_w,omitempty"`
	PowerLimitW      float64 `json:"power_limit_w,omitempty"`
	FanSpeedPct      float64 `json:"fan_speed_pct,omitempty"`
	GraphicsClockMHz float64 `json:"graphics_clock_mhz,omitempty"`
	MemoryClockMHz   float64 `json:"memory_clock_mhz,omitempty"`
	PCIeGeneration   int     `json:"pcie_generation,omitempty"`
	PCIeWidth        int     `json:"pcie_width,omitempty"`
	PerformanceState string  `json:"performance_state,omitempty"`
}

// ---- Forward-declared §32 entities (not wired up until later phases) ----

type ModelArtifact struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Revision     string `json:"revision"`
	Quantization string `json:"quantization"`
	Format       string `json:"format"`
	Tokenizer    string `json:"tokenizer"`
	Source       string `json:"source"`
}

type ServingProfile struct {
	ID              string         `json:"id"`
	ModelArtifactID string         `json:"model_artifact_id"`
	Runtime         string         `json:"runtime"`
	ContextLimit    int            `json:"context_limit"`
	KVReservationMB int64          `json:"kv_reservation_mb"`
	MaxSequences    int            `json:"max_sequences"`
	RuntimeArgs     map[string]any `json:"runtime_args,omitempty"`
	ExpectedVRAMMB  int64          `json:"expected_vram_mb"`
}

type EngineInstance struct {
	ID                  string    `json:"id"`
	NodeID              string    `json:"node_id"`
	AcceleratorID       string    `json:"accelerator_id"`
	ProfileID           string    `json:"profile_id"`
	ManagedByController bool      `json:"managed_by_controller"`
	PID                 int       `json:"pid,omitempty"`
	State               string    `json:"state"`
	StartedAt           time.Time `json:"started_at"`
}

type WorkerPool struct {
	ID                 string `json:"id"`
	ModelArtifact      string `json:"model_artifact"`
	Policy             string `json:"policy"`
	DesiredMinShards   int    `json:"desired_min_shards"`
	DesiredMaxShards   int    `json:"desired_max_shards"`
	LogicalWorkerLimit int    `json:"logical_worker_limit"`
}

type Session struct {
	ID                string         `json:"id"`
	LeadModel         string         `json:"lead_model"`
	Bindings          map[string]any `json:"bindings,omitempty"`
	CanonicalStateRef string         `json:"canonical_state_ref"`
	TokenStateRef     string         `json:"token_state_ref"`
	ContinuationState map[string]any `json:"continuation_state,omitempty"`
	Version           int64          `json:"version"`
}

// JobStatus is the overall §29 job lifecycle status (distinct from the
// per-item §12 state machine below).
type JobStatus string

const (
	JobPending             JobStatus = "pending"
	JobRunning             JobStatus = "running"
	JobPaused              JobStatus = "paused"
	JobCancelled           JobStatus = "cancelled"
	JobCompleted           JobStatus = "completed"
	JobCompletedWithErrors JobStatus = "completed_with_errors"
)

// WorkItemState is the §12 Work Item Reliability state machine:
//
//	QUEUED -> LEASED -> RUNNING -> {SUCCESS, FAILED, LEASE_EXPIRED -> QUEUED}
type WorkItemState string

const (
	WorkItemQueued       WorkItemState = "queued"
	WorkItemLeased       WorkItemState = "leased"
	WorkItemRunning      WorkItemState = "running"
	WorkItemSuccess      WorkItemState = "success"
	WorkItemFailed       WorkItemState = "failed"
	WorkItemLeaseExpired WorkItemState = "lease_expired" // transient; reaper immediately requeues to QUEUED
	WorkItemCancelled    WorkItemState = "cancelled"     // job cancelled while item was still queued
)

// JobProgress carries the §29 Jobs View progress fields.
type JobProgress struct {
	Total   int `json:"total"`
	Queued  int `json:"queued"`
	Running int `json:"current"` // "current" per §29 ("Current 32")
	Success int `json:"processed"`
	Failed  int `json:"failed"`
	Retried int `json:"retried"`
}

// Job is the §32 Job entity, extended with Phase 3 progress tracking.
type Job struct {
	ID          string      `json:"id"`
	Operation   string      `json:"operation"`
	Pool        string      `json:"pool"`
	Status      JobStatus   `json:"status"`
	InputRef    string      `json:"input_ref,omitempty"`
	OutputRef   string      `json:"output_ref,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Priority    string      `json:"priority,omitempty"`
	MaxAttempts int         `json:"max_attempts"`
	Progress    JobProgress `json:"progress"`
}

// WorkItem is the §32 WorkItem entity. Unique identity per §12 is
// JobID+ItemID+OperationVersion. Payload carries the (mock, in this phase)
// completion request; TriedWorkers is the cross-worker-retry "tried" set
// (docs/gateway-and-queue.md "At-least-once + cross-backend retry").
type WorkItem struct {
	JobID            string         `json:"job_id"`
	ItemID           string         `json:"item_id"`
	OperationVersion string         `json:"operation_version"`
	State            WorkItemState  `json:"state"`
	LeaseOwner       string         `json:"lease_owner,omitempty"`
	LeaseExpiry      time.Time      `json:"lease_expiry,omitempty"`
	Attempt          int            `json:"attempt"`
	ResultRef        string         `json:"result_ref,omitempty"`
	Payload          map[string]any `json:"payload,omitempty"`
	TriedWorkers     []string       `json:"tried_workers,omitempty"`
	LastError        string         `json:"last_error,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	// Seq is the submission order within its job, used for FIFO dispatch.
	Seq int64 `json:"seq"`
}

type TransitionPlan struct {
	ID                      string               `json:"id"`
	WorkloadID              string               `json:"workload_id"`
	VictimWorkloadID        string               `json:"victim_workload_id,omitempty"`
	TargetID                string               `json:"target_id,omitempty"`
	AcceleratorID           string               `json:"accelerator_id,omitempty"`
	Reason                  string               `json:"reason"`
	Steps                   []TransitionStep     `json:"steps"`
	Rollback                []TransitionStep     `json:"rollback,omitempty"`
	EstimatedDuration       string               `json:"estimated_duration,omitempty"`
	EstimatedMemoryChangeMB int64                `json:"estimated_memory_change_mb,omitempty"`
	Status                  TransitionPlanStatus `json:"status"`
	Error                   string               `json:"error,omitempty"`
	CreatedAt               time.Time            `json:"created_at"`
	UpdatedAt               time.Time            `json:"updated_at"`
	FinishedAt              *time.Time           `json:"finished_at,omitempty"`
}

// ---- Phase 2: measured-performance data model (measurement.md) ----

// Stat is a small summary of a repeated measurement — mean/stdev/p95/min/max
// over N samples. Every timing/footprint number the prober persists carries
// one of these (or N=1) so variance is visible, never hidden behind a bare
// average (measurement.md §6 honesty rule).
type Stat struct {
	Mean  float64 `json:"mean"`
	Stdev float64 `json:"stdev"`
	P95   float64 `json:"p95"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	N     int     `json:"n"`
}

// HardwareIdentity is the hardware half of the §20/§1 performance-profile
// key. Fields the prober cannot determine are left zero/empty and the
// PerformanceProfile.Notes should say so explicitly rather than guessing.
type HardwareIdentity struct {
	GPUModel    string `json:"gpu_model"`
	VRAMTotalMB int64  `json:"vram_total_mb"`
	HostCPU     string `json:"host_cpu,omitempty"`
	HostRAMMB   int64  `json:"host_ram_mb,omitempty"`
	PCIeInfo    string `json:"pcie_info,omitempty"` // "unknown" if not probed
}

// EvictReloadStats is the §3 "Model residency" / "Evict/reload" row —
// ported from evict_reload_spike.py.
type EvictReloadStats struct {
	TSleepSeconds            Stat    `json:"t_sleep_seconds"`        // teardown -> VRAM released
	TWakeWeightsSeconds      Stat    `json:"t_wake_weights_seconds"` // relaunch -> READY
	TFirstTokenAfterWakeSecs Stat    `json:"t_first_token_after_wake_seconds"`
	VRAMFreedMB              Stat    `json:"vram_freed_mb"`
	ColdLoadSeconds          float64 `json:"cold_load_seconds"` // single sample: first-ever load (disk, not page cache)
}

// KVProbePoint is one context-length row from the §3 "KV cache" measurement
// — ported from kv_restore_spike.py, using the corrected extend-the-context
// resume methodology (never re-send the identical prompt).
type KVProbePoint struct {
	ContextTokens              int     `json:"context_tokens"`
	TReprefillRecomputeSeconds float64 `json:"t_reprefill_recompute_seconds"`
	TSlotSaveSeconds           float64 `json:"t_slot_save_seconds"`
	TSlotRestoreSeconds        float64 `json:"t_slot_restore_seconds"`
	TResumePrefillSeconds      float64 `json:"t_resume_prefill_seconds"`
	ResumePrefillTokens        int     `json:"resume_prefill_tokens"`
	KVFileMB                   float64 `json:"kv_file_mb"`
	KVReused                   bool    `json:"kv_reused"` // sanity check: resume prefill << context
}

// ThroughputPoint is one prefill-vs-context or decode-vs-concurrency sample
// (§3 "GPU compute — prefill/decode"; measurement.md §7 next-probe scope,
// kept minimal for Phase 2).
type ThroughputPoint struct {
	ContextTokens int     `json:"context_tokens,omitempty"` // prefill points
	Concurrency   int     `json:"concurrency,omitempty"`    // decode points
	TokPerSec     float64 `json:"tok_per_sec"`
}

// PerformanceProfile is the §1/§5 row: the full identity key plus every
// measured value the prober collected for it. The scheduler (later phases)
// reads only rows like this — never a hand-configured or model-name-
// inferred number (measurement.md, locked principle).
type PerformanceProfile struct {
	ID string `json:"id"`

	// ---- Identity (§1) — two profiles differing in any of these fields
	// are different rows; results are never shared across them. ----
	Hardware        HardwareIdentity `json:"hardware"`
	RuntimeName     string           `json:"runtime_name"`
	RuntimeVersion  string           `json:"runtime_version"`
	ModelArtifactID string           `json:"model_artifact_id"`
	Quantization    string           `json:"quantization"`
	ContextProfile  int              `json:"context_profile"` // ctx length band probed at
	ShardCount      int              `json:"shard_count"`
	Concurrency     int              `json:"concurrency"`

	// ---- Measured footprint ----
	VRAMFootprintMB       int64  `json:"vram_footprint_mb"`
	VRAMMeasurementMethod string `json:"vram_measurement_method"` // "per_pid" | "free_delta"
	HostRAMFootprintMB    int64  `json:"host_ram_footprint_mb,omitempty"`

	// ---- Measured residency / evict-reload ----
	EvictReload EvictReloadStats `json:"evict_reload"`

	// ---- Measured KV cache behavior ----
	KV []KVProbePoint `json:"kv"`

	// ---- Measured micro throughput (minimal, real; full curves later) ----
	Prefill []ThroughputPoint `json:"prefill"`
	Decode  []ThroughputPoint `json:"decode"`

	// ---- Detected capabilities (§2), verified empirically this run ----
	Capabilities RuntimeCapabilities `json:"capabilities"`

	MeasuredAt  time.Time `json:"measured_at"`
	SampleCount int       `json:"sample_count"`
	// Notes carries honesty disclosures: measurement-method fallbacks, low
	// free VRAM warnings, anything not measured (§6 honesty rules).
	Notes []string `json:"notes,omitempty"`
}

type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	NodeID    string         `json:"node_id,omitempty"`
	JobID     string         `json:"job_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Type      string         `json:"type"`
	Severity  string         `json:"severity"`
	Payload   map[string]any `json:"payload,omitempty"`
}
