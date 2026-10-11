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

import (
	"fmt"
	"strings"
	"time"
)

// CapabilityContractVersion is the additive wire/configuration contract for
// fleet residency. It is intentionally independent of a runtime or device
// product name; a node may advertise an older version and must then fail
// closed for fields it does not understand.
const CapabilityContractVersion = "fleet-residency.v1"

// CapabilityVersion validates the only contract versions understood by this
// binary. Empty is accepted for legacy records and is normalized by config
// loaders to CapabilityContractVersion.
func ValidateCapabilityVersion(version string) error {
	if version == "" || version == CapabilityContractVersion {
		return nil
	}
	return fmt.Errorf("unsupported capability contract version %q", version)
}

// CapacityBudget uses bytes internally. Display layers may convert to MiB,
// but admission must never make a decision from rounded display units.
type CapacityBudget struct {
	VRAMTotalBytes     int64 `json:"vram_total_bytes" yaml:"vram_total_bytes"`
	VRAMReserveBytes   int64 `json:"vram_reserve_bytes" yaml:"vram_reserve_bytes"`
	VRAMHardCapBytes   int64 `json:"vram_hard_cap_bytes" yaml:"vram_hard_cap_bytes"`
	RAMTotalBytes      int64 `json:"ram_total_bytes" yaml:"ram_total_bytes"`
	RAMReserveBytes    int64 `json:"ram_reserve_bytes" yaml:"ram_reserve_bytes"`
	RAMHardCapBytes    int64 `json:"ram_hard_cap_bytes" yaml:"ram_hard_cap_bytes"`
	DiskAvailableBytes int64 `json:"disk_available_bytes" yaml:"disk_available_bytes"`
}

func (b CapacityBudget) Validate() error {
	values := []struct {
		name  string
		value int64
	}{
		{"vram_total_bytes", b.VRAMTotalBytes}, {"vram_reserve_bytes", b.VRAMReserveBytes},
		{"vram_hard_cap_bytes", b.VRAMHardCapBytes}, {"ram_total_bytes", b.RAMTotalBytes},
		{"ram_reserve_bytes", b.RAMReserveBytes}, {"ram_hard_cap_bytes", b.RAMHardCapBytes},
		{"disk_available_bytes", b.DiskAvailableBytes},
	}
	for _, field := range values {
		if field.value < 0 {
			return fmt.Errorf("%s may not be negative", field.name)
		}
	}
	if b.VRAMTotalBytes > 0 && b.VRAMReserveBytes > b.VRAMTotalBytes {
		return fmt.Errorf("vram_reserve_bytes may not exceed vram_total_bytes")
	}
	if b.VRAMTotalBytes > 0 && b.VRAMHardCapBytes > b.VRAMTotalBytes {
		return fmt.Errorf("vram_hard_cap_bytes may not exceed vram_total_bytes")
	}
	if b.VRAMHardCapBytes > 0 && b.VRAMReserveBytes > b.VRAMHardCapBytes {
		return fmt.Errorf("vram_reserve_bytes may not exceed vram_hard_cap_bytes")
	}
	if b.RAMTotalBytes > 0 && b.RAMReserveBytes > b.RAMTotalBytes {
		return fmt.Errorf("ram_reserve_bytes may not exceed ram_total_bytes")
	}
	if b.RAMTotalBytes > 0 && b.RAMHardCapBytes > b.RAMTotalBytes {
		return fmt.Errorf("ram_hard_cap_bytes may not exceed ram_total_bytes")
	}
	if b.RAMHardCapBytes > 0 && b.RAMReserveBytes > b.RAMHardCapBytes {
		return fmt.Errorf("ram_reserve_bytes may not exceed ram_hard_cap_bytes")
	}
	return nil
}

// ValidateCapacityOverride checks a partial child budget before inheritance
// fills omitted fields. Parent non-zero hard caps are ceilings; a child may
// narrow them but cannot raise them.
func ValidateCapacityOverride(parent, override CapacityBudget) error {
	if err := override.Validate(); err != nil {
		return err
	}
	if parent.VRAMHardCapBytes > 0 && override.VRAMHardCapBytes > parent.VRAMHardCapBytes {
		return fmt.Errorf("vram_hard_cap_bytes %d exceeds inherited ceiling %d", override.VRAMHardCapBytes, parent.VRAMHardCapBytes)
	}
	if parent.RAMHardCapBytes > 0 && override.RAMHardCapBytes > parent.RAMHardCapBytes {
		return fmt.Errorf("ram_hard_cap_bytes %d exceeds inherited ceiling %d", override.RAMHardCapBytes, parent.RAMHardCapBytes)
	}
	return nil
}

// MergeCapacityBudget applies a partial target/adapter override over fleet
// defaults while retaining global reserves and hard caps when omitted. A
// smaller explicit total safely narrows an inherited hard cap.
func MergeCapacityBudget(defaults, override CapacityBudget) CapacityBudget {
	merged := defaults
	if override.VRAMTotalBytes > 0 {
		merged.VRAMTotalBytes = override.VRAMTotalBytes
	}
	if override.VRAMReserveBytes > 0 {
		merged.VRAMReserveBytes = override.VRAMReserveBytes
	}
	if override.VRAMHardCapBytes > 0 {
		merged.VRAMHardCapBytes = override.VRAMHardCapBytes
	}
	if override.RAMTotalBytes > 0 {
		merged.RAMTotalBytes = override.RAMTotalBytes
	}
	if override.RAMReserveBytes > 0 {
		merged.RAMReserveBytes = override.RAMReserveBytes
	}
	if override.RAMHardCapBytes > 0 {
		merged.RAMHardCapBytes = override.RAMHardCapBytes
	}
	if override.DiskAvailableBytes > 0 {
		merged.DiskAvailableBytes = override.DiskAvailableBytes
	}
	if merged.VRAMTotalBytes > 0 && (merged.VRAMHardCapBytes == 0 || merged.VRAMHardCapBytes > merged.VRAMTotalBytes) {
		merged.VRAMHardCapBytes = merged.VRAMTotalBytes
	}
	if merged.RAMTotalBytes > 0 && (merged.RAMHardCapBytes == 0 || merged.RAMHardCapBytes > merged.RAMTotalBytes) {
		merged.RAMHardCapBytes = merged.RAMTotalBytes
	}
	return merged
}

// ResidencyCapabilities deliberately separates warm model bytes from session
// checkpointing. WarmRAMVerified says model bytes were proven resident by an
// OS oracle; SessionCheckpointVerified is an independent proof of pause,
// snapshot, restore, and measured KV reuse.
type ResidencyCapabilities struct {
	Version                    string `json:"version" yaml:"version"`
	SupportsWarmRAM            bool   `json:"supports_warm_ram" yaml:"supports_warm_ram"`
	WarmRAMVerified            bool   `json:"warm_ram_verified" yaml:"warm_ram_verified"`
	WarmRAMVerification        string `json:"warm_ram_verification,omitempty" yaml:"warm_ram_verification"`
	SupportsSessionCheckpoint  bool   `json:"supports_session_checkpoint" yaml:"supports_session_checkpoint"`
	SessionCheckpointVerified  bool   `json:"session_checkpoint_verified" yaml:"session_checkpoint_verified"`
	SessionCheckpointProof     string `json:"session_checkpoint_proof,omitempty" yaml:"session_checkpoint_proof"`
	SupportsYield              bool   `json:"supports_yield" yaml:"supports_yield"`
	YieldVerified              bool   `json:"yield_verified" yaml:"yield_verified"`
	YieldProof                 string `json:"yield_proof,omitempty" yaml:"yield_proof"`
	SupportsModelLifecycle     bool   `json:"supports_model_lifecycle" yaml:"supports_model_lifecycle"`
	SupportsAcceleratorReclaim bool   `json:"supports_accelerator_reclaim" yaml:"supports_accelerator_reclaim"`
	MaxResidentModels          int    `json:"max_resident_models" yaml:"max_resident_models"`
	MaxAcceleratorsPerWorkload int    `json:"max_accelerators_per_workload" yaml:"max_accelerators_per_workload"`
}

func (c ResidencyCapabilities) Validate() error {
	if err := ValidateCapabilityVersion(c.Version); err != nil {
		return err
	}
	if c.MaxResidentModels < 0 || c.MaxAcceleratorsPerWorkload < 0 {
		return fmt.Errorf("capability ceilings may not be negative")
	}
	if err := validateResidencyEvidence(c); err != nil {
		return err
	}
	return nil
}

func validateResidencyEvidence(c ResidencyCapabilities) error {
	if strings.TrimSpace(c.WarmRAMVerification) != "" && (!c.SupportsWarmRAM || !c.WarmRAMVerified) {
		return fmt.Errorf("warm_ram_verification requires supported, verified warm RAM")
	}
	if c.SupportsWarmRAM && c.WarmRAMVerified && !isResidencyOracle(c.WarmRAMVerification) {
		return fmt.Errorf("warm_ram_verified requires an OS residency oracle")
	}
	if c.WarmRAMVerified && !c.SupportsWarmRAM {
		return fmt.Errorf("warm_ram_verified requires supports_warm_ram")
	}
	if strings.TrimSpace(c.SessionCheckpointProof) != "" && (!c.SupportsSessionCheckpoint || !c.SessionCheckpointVerified) {
		return fmt.Errorf("session_checkpoint_proof requires supported, verified checkpointing")
	}
	if c.SessionCheckpointVerified && (!c.SupportsSessionCheckpoint || strings.TrimSpace(c.SessionCheckpointProof) == "") {
		return fmt.Errorf("session_checkpoint_verified requires support and proof")
	}
	if c.SupportsSessionCheckpoint && !c.SessionCheckpointVerified {
		return fmt.Errorf("supports_session_checkpoint requires verified runtime proof")
	}
	if c.SupportsYield && !c.YieldVerified {
		return fmt.Errorf("supports_yield requires verified runtime proof")
	}
	if c.YieldVerified && (!c.SupportsYield || strings.TrimSpace(c.YieldProof) == "") {
		return fmt.Errorf("yield_verified requires supports_yield and proof")
	}
	if strings.TrimSpace(c.YieldProof) != "" && (!c.SupportsYield || !c.YieldVerified) {
		return fmt.Errorf("yield_proof requires supported, verified yield")
	}
	return nil
}

// ValidateOperatorCapabilities rejects claims that cannot originate from
// static YAML. Runtime probes are the only authority for verified residency
// and checkpoint status; configuration may request support, but may not mint
// proof strings or mark a capability verified.
func ValidateOperatorCapabilities(c ResidencyCapabilities) error {
	if c.WarmRAMVerified || c.SessionCheckpointVerified || c.SupportsSessionCheckpoint || c.SupportsYield || c.YieldVerified || strings.TrimSpace(c.WarmRAMVerification) != "" || strings.TrimSpace(c.SessionCheckpointProof) != "" || strings.TrimSpace(c.YieldProof) != "" {
		return fmt.Errorf("verified residency and checkpoint claims require authoritative runtime proof")
	}
	return nil
}

// CapabilityAliases are the legacy operational fields carried beside the
// versioned nested capability block. They are inputs to normalization only;
// callers should use the returned nested contract as the canonical value.
type CapabilityAliases struct {
	SupportsModelLifecycle     bool
	SupportsAcceleratorReclaim bool
	MaxResidentModels          int
	WarmRAMSupported           bool
}

// MergeResidencyCapabilities applies a partial nested capability block over
// inherited defaults, then reconciles legacy aliases. Compatible truths are
// preserved. A non-zero MaxResidentModels disagreement is rejected rather
// than silently choosing a value, because it changes admission semantics.
func MergeResidencyCapabilities(base, overlay ResidencyCapabilities, aliases CapabilityAliases) (ResidencyCapabilities, error) {
	if err := validateResidencyEvidence(base); err != nil {
		return ResidencyCapabilities{}, err
	}
	if err := validateResidencyEvidence(overlay); err != nil {
		return ResidencyCapabilities{}, err
	}
	merged := base
	if base.Version != "" && overlay.Version != "" && base.Version != overlay.Version {
		return ResidencyCapabilities{}, fmt.Errorf("capability versions %q and %q conflict", base.Version, overlay.Version)
	}
	if overlay.Version != "" {
		merged.Version = overlay.Version
	}
	merged.SupportsWarmRAM = base.SupportsWarmRAM || overlay.SupportsWarmRAM || aliases.WarmRAMSupported
	merged.SupportsModelLifecycle = base.SupportsModelLifecycle || overlay.SupportsModelLifecycle || aliases.SupportsModelLifecycle
	merged.SupportsAcceleratorReclaim = base.SupportsAcceleratorReclaim || overlay.SupportsAcceleratorReclaim || aliases.SupportsAcceleratorReclaim
	merged.SupportsYield = base.SupportsYield || overlay.SupportsYield
	merged.SupportsSessionCheckpoint = base.SupportsSessionCheckpoint || overlay.SupportsSessionCheckpoint

	resident := []int{}
	for _, value := range []int{base.MaxResidentModels, overlay.MaxResidentModels, aliases.MaxResidentModels} {
		if value < 0 {
			return ResidencyCapabilities{}, fmt.Errorf("max_resident_models may not be negative")
		}
		if value > 0 {
			resident = append(resident, value)
		}
	}
	if len(resident) > 0 {
		merged.MaxResidentModels = resident[0]
		for _, value := range resident[1:] {
			if value != merged.MaxResidentModels {
				return ResidencyCapabilities{}, fmt.Errorf("max_resident_models values conflict")
			}
		}
	}

	// Verified runtime facts are inherited until a new authoritative fact is
	// supplied. Static callers are rejected separately by ValidateOperatorCapabilities.
	if overlay.WarmRAMVerified || strings.TrimSpace(overlay.WarmRAMVerification) != "" {
		merged.WarmRAMVerified = overlay.WarmRAMVerified
		merged.WarmRAMVerification = overlay.WarmRAMVerification
	}
	if overlay.SessionCheckpointVerified || strings.TrimSpace(overlay.SessionCheckpointProof) != "" {
		merged.SessionCheckpointVerified = overlay.SessionCheckpointVerified
		merged.SessionCheckpointProof = overlay.SessionCheckpointProof
	}
	if overlay.YieldVerified || strings.TrimSpace(overlay.YieldProof) != "" {
		merged.YieldVerified = overlay.YieldVerified
		merged.YieldProof = overlay.YieldProof
	}
	return merged, nil
}

// NormalizeAcceleratorCeiling reconciles the legacy outer ceiling with the
// nested capability advertisement. Zero is the legacy single-accelerator
// default; a non-zero nested value must agree with the effective outer value.
func NormalizeAcceleratorCeiling(outer, nested int) (int, error) {
	if outer < 0 || nested < 0 {
		return 0, fmt.Errorf("max_accelerators_per_workload may not be negative")
	}
	effective := outer
	if effective == 0 && nested > 0 {
		effective = nested
	}
	if effective == 0 {
		effective = 1
	}
	if outer > 0 && nested != 0 && nested != effective {
		return 0, fmt.Errorf("max_accelerators_per_workload %d conflicts with nested capability ceiling %d", effective, nested)
	}
	return effective, nil
}

func isResidencyOracle(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "mincore", "os_residency_oracle", "mincore+lock":
		return true
	default:
		return false
	}
}

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
	ID                         string                `json:"id"`
	Name                       string                `json:"name"`
	CapabilityVersion          string                `json:"capability_version,omitempty"`
	Capabilities               ResidencyCapabilities `json:"capabilities"`
	Capacity                   CapacityBudget        `json:"capacity"`
	MaxAcceleratorsPerWorkload int                   `json:"max_accelerators_per_workload"`
	LocationClass              LocationClass         `json:"location_class"`
	PriorityTier               PriorityTier          `json:"priority_tier"`
	SchedulingState            SchedulingState       `json:"scheduling_state"`

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
// telemetry fields the node agent reports every heartbeat cycle.
type Accelerator struct {
	ID          string `json:"id"`
	NodeID      string `json:"node_id"`
	Vendor      string `json:"vendor"`
	Model       string `json:"model"`
	MemoryKind  string `json:"memory_kind,omitempty"`
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
