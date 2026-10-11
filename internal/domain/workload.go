package domain

import (
	"encoding/json"
	"time"
)

type Plane string

const (
	PlaneOpenAI        Plane = "openai"
	PlaneComfy         Plane = "comfy"
	PlaneAPI           Plane = "api"
	PlaneCreatorStudio Plane = "creator_studio"
	PlaneAgent         Plane = "agent"
	PlaneAdmin         Plane = "admin"
)

type WorkloadStatus string

const (
	WorkloadQueued          WorkloadStatus = "queued"
	WorkloadWaiting         WorkloadStatus = "waiting"
	WorkloadRejected        WorkloadStatus = "rejected"
	WorkloadPendingApproval WorkloadStatus = "pending_approval"
	WorkloadRunning         WorkloadStatus = "running"
	WorkloadSucceeded       WorkloadStatus = "succeeded"
	WorkloadFailed          WorkloadStatus = "failed"
	WorkloadCancelled       WorkloadStatus = "cancelled"
)

type QoSClass string

const (
	QoSInteractive QoSClass = "interactive"
	QoSNormal      QoSClass = "normal"
	QoSBackground  QoSClass = "background"
)

type DisruptionPolicy string

const (
	DisruptionLocked         DisruptionPolicy = "locked"
	DisruptionSlowdown       DisruptionPolicy = "slowdown_allowed"
	DisruptionYieldable      DisruptionPolicy = "yieldable"
	DisruptionCheckpointable DisruptionPolicy = "checkpointable"
	DisruptionCancelable     DisruptionPolicy = "cancelable"
)

type EgressPolicy string

const (
	EgressLocalOnly EgressPolicy = "local_only"
	EgressSanitized EgressPolicy = "sanitized_cloud"
	EgressAllowed   EgressPolicy = "cloud_allowed"
)

type QueuePolicy string

const (
	QueueWait     QueuePolicy = "wait"
	QueueFailFast QueuePolicy = "fail_fast"
)

type PlacementPolicy string

const (
	PlacementBestFit PlacementPolicy = "best_fit"
	PlacementSticky  PlacementPolicy = "sticky"
)

type TransformationPolicy string

const (
	TransformAsk                TransformationPolicy = "ask"
	TransformNever              TransformationPolicy = "never"
	TransformDelegateSafeReview TransformationPolicy = "delegate_safe_review"
)

type WorkloadBounds struct {
	ContextTokens int `json:"context_tokens,omitempty"`
	MaxOutput     int `json:"max_output,omitempty"`
	Frames        int `json:"frames,omitempty"`
	Width         int `json:"width,omitempty"`
	Height        int `json:"height,omitempty"`
	Steps         int `json:"steps,omitempty"`
}

// AdmissionBlocker is a stable machine-readable reason. Blocker on the
// legacy response remains populated for older clients.
type AdmissionBlocker string

const (
	BlockerCapacity           AdmissionBlocker = "capacity"
	BlockerPinnedResident     AdmissionBlocker = "pinned_resident"
	BlockerLockedWorkload     AdmissionBlocker = "locked_workload"
	BlockerRuntimeUnsupported AdmissionBlocker = "runtime_unsupported"
	BlockerNodeOffline        AdmissionBlocker = "node_offline"
	BlockerTransitionBusy     AdmissionBlocker = "transition_busy"
)

type NotificationPreferences struct {
	InApp    bool     `json:"in_app"`
	Webhooks []string `json:"webhooks,omitempty"`
	OnStart  bool     `json:"on_start,omitempty"`
	OnFinish bool     `json:"on_finish,omitempty"`
}

// WorkloadRequest is immutable after admission. Runtime state is kept in
// Workload; payloads large enough to be artifacts should be supplied by ref.
type WorkloadRequest struct {
	ID                     string                  `json:"id"`
	PrincipalID            string                  `json:"principal_id,omitempty"`
	OwnerID                string                  `json:"owner_id"`
	Plane                  Plane                   `json:"plane"`
	Adapter                string                  `json:"adapter"`
	WorkloadType           string                  `json:"workload_type"`
	Operation              string                  `json:"operation,omitempty"`
	QualityClass           string                  `json:"quality_class,omitempty"`
	CapabilityRequirements CapabilityRequirements  `json:"requirements,omitempty"`
	ProfilePreferences     ProfilePreferences      `json:"profile_preferences,omitempty"`
	SessionID              string                  `json:"session_id,omitempty"`
	BatchID                string                  `json:"batch_id,omitempty"`
	AffinityKey            string                  `json:"affinity_key,omitempty"`
	Ordered                bool                    `json:"ordered,omitempty"`
	Parallelism            ParallelismPolicy       `json:"parallelism,omitempty"`
	Dependencies           []string                `json:"dependencies,omitempty"`
	LatencyClass           string                  `json:"latency_class,omitempty"`
	PriorityClass          string                  `json:"priority_class,omitempty"`
	ContinuationRef        string                  `json:"continuation_ref,omitempty"`
	CompatibilityToken     string                  `json:"compatibility_token,omitempty"`
	Payload                json.RawMessage         `json:"payload,omitempty"`
	ArtifactRefs           []string                `json:"artifact_refs,omitempty"`
	ItemID                 string                  `json:"item_id"`
	OperationVersion       string                  `json:"operation_version"`
	IdempotencyKey         string                  `json:"idempotency_key"`
	QoS                    QoSClass                `json:"qos"`
	Priority               int                     `json:"priority"`
	Deadline               *time.Time              `json:"deadline,omitempty"`
	QueuePolicy            QueuePolicy             `json:"queue_policy"`
	Notifications          NotificationPreferences `json:"notifications"`
	Disruption             DisruptionPolicy        `json:"disruption"`
	// InterruptionConsent is an explicit opt-in for scheduler preemption of a
	// running workload. The zero value is deliberately fail-closed: legacy
	// clients remain runnable but are never checkpoint-preempted until they
	// opt in.
	InterruptionConsent      bool                 `json:"interruption_consent,omitempty"`
	Egress                   EgressPolicy         `json:"egress"`
	Bounds                   WorkloadBounds       `json:"bounds"`
	PlacementKey             string               `json:"placement_key,omitempty"`
	PlacementPolicy          PlacementPolicy      `json:"placement_policy,omitempty"`
	InteractiveStream        bool                 `json:"interactive_stream,omitempty"`
	Recoverable              bool                 `json:"recoverable"`
	ConcurrencyLimit         int                  `json:"concurrency_limit,omitempty"`
	BudgetLimitCents         int64                `json:"budget_limit_cents,omitempty"`
	TransformationPolicy     TransformationPolicy `json:"transformation_policy,omitempty"`
	Transformations          []string             `json:"transformations,omitempty"`
	TransformationParameters json.RawMessage      `json:"transformation_parameters,omitempty"`
	PreemptionBudget         int                  `json:"preemption_budget,omitempty"`
	CreatedAt                time.Time            `json:"created_at"`
}

type AdmissionDecision struct {
	Admitted                   bool             `json:"admitted"`
	Blocker                    string           `json:"blocker,omitempty"`
	BlockerCode                AdmissionBlocker `json:"blocker_code,omitempty"`
	EstimatedStart             *time.Time       `json:"estimated_start,omitempty"`
	EstimatedEnd               *time.Time       `json:"estimated_end,omitempty"`
	RetryAfter                 *time.Time       `json:"retry_after,omitempty"`
	ETA                        *time.Time       `json:"eta,omitempty"`
	NotificationID             string           `json:"notification_id,omitempty"`
	Confidence                 float64          `json:"confidence"`
	Alternatives               []string         `json:"alternatives,omitempty"`
	TargetID                   string           `json:"target_id,omitempty"`
	AcceleratorID              string           `json:"accelerator_id,omitempty"`
	ContextLimit               int              `json:"context_limit,omitempty"`
	TargetSlots                int              `json:"target_slots,omitempty"`
	CapacitySource             string           `json:"capacity_source,omitempty"`
	CapacityVerified           bool             `json:"capacity_verified,omitempty"`
	ProfileID                  string           `json:"profile_id,omitempty"`
	ProfileVersion             string           `json:"profile_version,omitempty"`
	ProfileDigest              string           `json:"profile_digest,omitempty"`
	CapabilityVersion          string           `json:"capability_version,omitempty"`
	WarmModelBytesVerified     bool             `json:"warm_model_bytes_verified"`
	SessionCheckpointable      bool             `json:"session_checkpointable"`
	MaxAcceleratorsPerWorkload int              `json:"max_accelerators_per_workload,omitempty"`
}

type PlacementCandidate struct {
	TargetID                   string           `json:"target_id"`
	AcceleratorID              string           `json:"accelerator_id,omitempty"`
	Eligible                   bool             `json:"eligible"`
	Blocker                    string           `json:"blocker,omitempty"`
	ContextLimit               int              `json:"context_limit,omitempty"`
	Slots                      int              `json:"slots"`
	AvailableSlots             int              `json:"available_slots"`
	CapacitySource             string           `json:"capacity_source,omitempty"`
	CapacityVerified           bool             `json:"capacity_verified"`
	Resident                   bool             `json:"resident"`
	ResidencyAction            string           `json:"residency_action,omitempty"`
	EstimatedStart             *time.Time       `json:"estimated_start,omitempty"`
	EstimatedEnd               *time.Time       `json:"estimated_end,omitempty"`
	Confidence                 float64          `json:"confidence"`
	Score                      float64          `json:"score"`
	BlockerCode                AdmissionBlocker `json:"blocker_code,omitempty"`
	RetryAfter                 *time.Time       `json:"retry_after,omitempty"`
	NotificationID             string           `json:"notification_id,omitempty"`
	WarmModelBytesVerified     bool             `json:"warm_model_bytes_verified"`
	SessionCheckpointable      bool             `json:"session_checkpointable"`
	MaxAcceleratorsPerWorkload int              `json:"max_accelerators_per_workload,omitempty"`
	Plan                       *ExecutionPlan   `json:"plan,omitempty"`
}

type PlacementPreview struct {
	Requirements RequirementsPreview  `json:"requirements"`
	Recommended  string               `json:"recommended_target,omitempty"`
	Candidates   []PlacementCandidate `json:"candidates"`
	GeneratedAt  time.Time            `json:"generated_at"`
}

type RequirementsPreview struct {
	Model           string   `json:"model,omitempty"`
	RequiredModels  []string `json:"required_models,omitempty"`
	CustomNodes     []string `json:"custom_nodes,omitempty"`
	EstimatedVRAMMB int64    `json:"estimated_vram_mb,omitempty"`
	ContextTokens   int      `json:"context_tokens,omitempty"`
}

type ExecutionPlan struct {
	ID                       string            `json:"id"`
	WorkloadID               string            `json:"workload_id"`
	PlanHash                 string            `json:"plan_hash"`
	Adapter                  string            `json:"adapter"`
	AdapterVersion           string            `json:"adapter_version"`
	TargetID                 string            `json:"target_id"`
	RuntimeProtocol          string            `json:"runtime_protocol,omitempty"`
	AcceleratorID            string            `json:"accelerator_id,omitempty"`
	CapabilityVersion        string            `json:"capability_version,omitempty"`
	CapabilityRevision       string            `json:"capability_revision,omitempty"`
	TargetContextLimit       int               `json:"target_context_limit,omitempty"`
	TargetSlots              int               `json:"target_slots,omitempty"`
	ModelFingerprint         string            `json:"model_fingerprint,omitempty"`
	CapacitySource           string            `json:"capacity_source,omitempty"`
	CapacityVerified         bool              `json:"capacity_verified,omitempty"`
	EstimatedCostCents       int64             `json:"estimated_cost_cents,omitempty"`
	InputCentsPerMTok        int64             `json:"input_cents_per_million_tokens,omitempty"`
	OutputCentsPerMTok       int64             `json:"output_cents_per_million_tokens,omitempty"`
	Provider                 string            `json:"provider,omitempty"`
	Model                    string            `json:"model,omitempty"`
	ProfileID                string            `json:"profile_id,omitempty"`
	ProfileVersion           string            `json:"profile_version,omitempty"`
	ProfileDigest            string            `json:"profile_digest,omitempty"`
	CapabilityDefinitionHash string            `json:"capability_definition_hash,omitempty"`
	WarmModelBytesVerified   bool              `json:"warm_model_bytes_verified"`
	SessionCheckpointable    bool              `json:"session_checkpointable"`
	ExecutionLocality        ExecutionLocality `json:"execution_locality,omitempty"`
	ResidencyTransitionIDs   []string          `json:"residency_transition_ids,omitempty"`
	Transformations          []string          `json:"transformations,omitempty"`
	CreatedAt                time.Time         `json:"created_at"`
	Material                 json.RawMessage   `json:"material,omitempty"`
}

type ExecutionHandle struct {
	ExternalID  string                `json:"external_id,omitempty"`
	Opaque      json.RawMessage       `json:"opaque,omitempty"`
	StartedAt   time.Time             `json:"started_at"`
	Performance *ExecutionPerformance `json:"performance,omitempty"`
}

// ExecutionPerformance contains only values measured on the actual request.
// Prompt/decode phase rates remain empty when the backend does not expose the
// phase timings separately.
type ExecutionPerformance struct {
	DurationMS       float64 `json:"duration_ms,omitempty"`
	TTFTMS           float64 `json:"ttft_ms,omitempty"`
	PromptTokens     int64   `json:"prompt_tokens,omitempty"`
	CompletionTokens int64   `json:"completion_tokens,omitempty"`
	TotalTokens      int64   `json:"total_tokens,omitempty"`
	PromptTPS        float64 `json:"prompt_tps,omitempty"`
	DecodeTPS        float64 `json:"decode_tps,omitempty"`
	TotalTPS         float64 `json:"total_tps,omitempty"`
	Source           string  `json:"source,omitempty"`
}

type Workload struct {
	Request WorkloadRequest `json:"request"`
	// Revision is the durable optimistic-concurrency version for this workload.
	// It is initialized on creation and advanced by every persisted mutation.
	Revision             uint64               `json:"revision"`
	Status               WorkloadStatus       `json:"status"`
	Decision             AdmissionDecision    `json:"decision"`
	Plan                 *ExecutionPlan       `json:"plan,omitempty"`
	Execution            *ExecutionHandle     `json:"execution,omitempty"`
	Progress             float64              `json:"progress,omitempty"`
	ProgressStage        string               `json:"progress_stage,omitempty"`
	ProgressNode         string               `json:"progress_node,omitempty"`
	ProgressCurrent      int                  `json:"progress_current,omitempty"`
	ProgressTotal        int                  `json:"progress_total,omitempty"`
	OutputRefs           []string             `json:"output_refs,omitempty"`
	InlineOutput         json.RawMessage      `json:"inline_output,omitempty"`
	Error                string               `json:"error,omitempty"`
	CreatedAt            time.Time            `json:"created_at"`
	StartedAt            *time.Time           `json:"started_at,omitempty"`
	UpdatedAt            time.Time            `json:"updated_at"`
	FinishedAt           *time.Time           `json:"finished_at,omitempty"`
	ExecutionAttempts    int                  `json:"execution_attempts,omitempty"`
	TargetRetryAfter     map[string]time.Time `json:"target_retry_after,omitempty"`
	CheckpointRef        string               `json:"checkpoint_ref,omitempty"`
	PreemptionCount      int                  `json:"preemption_count,omitempty"`
	RuntimePriority      *int                 `json:"runtime_priority,omitempty"`
	ActualCostCents      int64                `json:"actual_cost_cents,omitempty"`
	PreemptionsInitiated int                  `json:"preemptions_initiated,omitempty"`
	TransitionPlanIDs    []string             `json:"transition_plan_ids,omitempty"`
	// CancellationOwner is durable ownership of an in-flight cancellation. A
	// stale observer may not commit while this is set; the cancelling path owns
	// the row until it records either the terminal cancellation or releases the
	// request after a failed backend stop.
	CancellationOwner string `json:"cancellation_owner,omitempty"`
	// BudgetReservationToken binds settlement/release to the reservation claim
	// that was published by this workload CAS.
	BudgetReservationToken      string `json:"budget_reservation_token,omitempty"`
	BudgetReservationAttempt    uint64 `json:"budget_reservation_attempt,omitempty"`
	BudgetReservationCents      int64  `json:"budget_reservation_cents,omitempty"`
	BudgetReservationLimitCents int64  `json:"budget_reservation_limit_cents,omitempty"`
	BudgetReservationCurrency   string `json:"budget_reservation_currency,omitempty"`
	BudgetCleanupToken          string `json:"budget_cleanup_token,omitempty"`
	BudgetCleanupAttempt        uint64 `json:"budget_cleanup_attempt,omitempty"`
	BudgetSettlementPending     bool   `json:"budget_settlement_pending,omitempty"`
	BudgetSettlementAttempt     uint64 `json:"budget_settlement_attempt,omitempty"`
	BudgetSettlementActualCents int64  `json:"budget_settlement_actual_cents,omitempty"`
}

type TransitionPlanStatus string

const (
	TransitionPlanPlanned    TransitionPlanStatus = "planned"
	TransitionPlanExecuting  TransitionPlanStatus = "executing"
	TransitionPlanCompleted  TransitionPlanStatus = "completed"
	TransitionPlanFailed     TransitionPlanStatus = "failed"
	TransitionPlanRolledBack TransitionPlanStatus = "rolled_back"
)

type TransitionStep struct {
	Action     string `json:"action"`
	WorkloadID string `json:"workload_id,omitempty"`
	FromState  string `json:"from_state,omitempty"`
	ToState    string `json:"to_state,omitempty"`
	Policy     string `json:"policy,omitempty"`
}

type AcceleratorLease struct {
	AcceleratorID string    `json:"accelerator_id"`
	WorkloadID    string    `json:"workload_id"`
	FencingToken  int64     `json:"fencing_token"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// AcceleratorLeaseCleanupIntent is durable ownership of a lease release
// which could not be completed synchronously. The exact accelerator/owner/
// fencing tuple prevents a retry from releasing a later owner's lease.
type AcceleratorLeaseCleanupIntent struct {
	AcceleratorID            string     `json:"accelerator_id"`
	Owner                    string     `json:"owner"`
	FencingToken             int64      `json:"fencing_token"`
	WorkloadID               string     `json:"workload_id,omitempty"`
	ExpectedWorkloadRevision uint64     `json:"expected_workload_revision,omitempty"`
	TerminalDisposition      string     `json:"terminal_disposition,omitempty"`
	TerminalErrorCode        string     `json:"terminal_error_code,omitempty"`
	ReleaseConfirmed         bool       `json:"release_confirmed,omitempty"`
	TerminalPublished        bool       `json:"terminal_published,omitempty"`
	AuditPublished           bool       `json:"audit_published,omitempty"`
	NotificationPublished    bool       `json:"notification_published,omitempty"`
	BudgetSettled            bool       `json:"budget_settled,omitempty"`
	Attempts                 int        `json:"attempts"`
	LastError                string     `json:"last_error,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	NextRetryAt              *time.Time `json:"next_retry_at,omitempty"`
}

type ResidencyTier string

const (
	ResidencyRemote   ResidencyTier = "remote"
	ResidencyColdDisk ResidencyTier = "cold_disk"
	ResidencyWarmRAM  ResidencyTier = "warm_ram"
	ResidencyHotVRAM  ResidencyTier = "hot_vram"
)

type ResidencyPolicyMode string

const (
	ResidencyAuto   ResidencyPolicyMode = "auto"
	ResidencyPinned ResidencyPolicyMode = "pinned"
	ResidencyManual ResidencyPolicyMode = "manual"
	ResidencyOff    ResidencyPolicyMode = "off"
)

type ResidencyTransitionStatus string

const (
	ResidencyTransitionPlanned   ResidencyTransitionStatus = "planned"
	ResidencyTransitionRunning   ResidencyTransitionStatus = "running"
	ResidencyTransitionSucceeded ResidencyTransitionStatus = "succeeded"
	ResidencyTransitionFailed    ResidencyTransitionStatus = "failed"
	// ResidencyTransitionManualReconciliation is terminal for automatic
	// recovery, but intentionally distinct from failed: the side effect may
	// have happened and requires an operator/backend-specific resolution.
	ResidencyTransitionManualReconciliation ResidencyTransitionStatus = "manual_reconciliation_required"
)

// ModelResidency is the durable desired/observed state for one model on one
// runtime target. Predictions may update ReuseScore, but only queued demand or
// an authorized operator transition may move a model into hot VRAM.
type ModelResidency struct {
	ID                     string              `json:"id"`
	Revision               uint64              `json:"revision"`
	TargetGeneration       uint64              `json:"target_generation,omitempty"`
	ExecutionFingerprint   string              `json:"execution_fingerprint,omitempty"`
	TargetID               string              `json:"target_id"`
	AcceleratorID          string              `json:"accelerator_id,omitempty"`
	Adapter                string              `json:"adapter"`
	Model                  string              `json:"model"`
	DesiredTier            ResidencyTier       `json:"desired_tier"`
	ObservedTier           ResidencyTier       `json:"observed_tier"`
	Policy                 ResidencyPolicyMode `json:"policy"`
	CapacityVerified       bool                `json:"capacity_verified"`
	WarmRAMSupported       bool                `json:"warm_ram_supported"`
	WarmModelBytes         int64               `json:"warm_model_bytes,omitempty"`
	WarmModelBytesVerified bool                `json:"warm_model_bytes_verified"`
	SessionCheckpointable  bool                `json:"session_checkpointable"`
	ReuseScore             float64             `json:"reuse_score,omitempty"`
	UseCount               int64               `json:"use_count"`
	LastUsedAt             *time.Time          `json:"last_used_at,omitempty"`
	LastLoadedAt           *time.Time          `json:"last_loaded_at,omitempty"`
	MinResidentUntil       *time.Time          `json:"min_resident_until,omitempty"`
	IdleUnloadAfterSec     int                 `json:"idle_unload_after_seconds,omitempty"`
	LastError              string              `json:"last_error,omitempty"`
	UpdatedAt              time.Time           `json:"updated_at"`
}

type ResidencyTransition struct {
	ID                      string                    `json:"id"`
	IdempotencyKey          string                    `json:"idempotency_key"`
	TargetID                string                    `json:"target_id"`
	AcceleratorID           string                    `json:"accelerator_id,omitempty"`
	Model                   string                    `json:"model"`
	FromTier                ResidencyTier             `json:"from_tier"`
	ToTier                  ResidencyTier             `json:"to_tier"`
	Reason                  string                    `json:"reason"`
	RequestedBy             string                    `json:"requested_by"`
	WorkloadID              string                    `json:"workload_id,omitempty"`
	Status                  ResidencyTransitionStatus `json:"status"`
	Revision                uint64                    `json:"revision"`
	TargetGeneration        uint64                    `json:"target_generation,omitempty"`
	ExecutionFingerprint    string                    `json:"execution_fingerprint,omitempty"`
	FencingToken            int64                     `json:"fencing_token,omitempty"`
	LeaseOriginAcceleratorID string                   `json:"lease_origin_accelerator_id,omitempty"`
	LeaseOriginWorkloadID    string                   `json:"lease_origin_workload_id,omitempty"`
	LeaseOriginFencingToken  int64                    `json:"lease_origin_fencing_token,omitempty"`
	LeaseOriginAllocated     bool                     `json:"lease_origin_allocated,omitempty"`
	Error                   string                    `json:"error,omitempty"`
	ObservedTier            ResidencyTier             `json:"observed_tier,omitempty"`
	WarmModelBytes          int64                     `json:"warm_model_bytes,omitempty"`
	WarmModelBytesVerified  bool                      `json:"warm_model_bytes_verified,omitempty"`
	RuntimeIdentity         string                    `json:"runtime_identity,omitempty"`
	CapabilityVersion       string                    `json:"capability_version,omitempty"`
	CapabilityRevision      string                    `json:"capability_revision,omitempty"`
	ObservedFence           int64                     `json:"observed_fence,omitempty"`
	ProjectionRepairPending bool                      `json:"projection_repair_pending,omitempty"`
	CreatedAt               time.Time                 `json:"created_at"`
	StartedAt               *time.Time                `json:"started_at,omitempty"`
	FinishedAt              *time.Time                `json:"finished_at,omitempty"`
}

type NotificationDelivery struct {
	ID             string          `json:"id"`
	IdempotencyKey string          `json:"idempotency_key"`
	WorkloadID     string          `json:"workload_id"`
	OwnerID        string          `json:"owner_id"`
	EventType      string          `json:"event_type"`
	Destination    string          `json:"destination"`
	Payload        json.RawMessage `json:"payload"`
	Signature      string          `json:"signature,omitempty"`
	Attempts       int             `json:"attempts"`
	NextAttemptAt  time.Time       `json:"next_attempt_at"`
	DeliveredAt    *time.Time      `json:"delivered_at,omitempty"`
	FailedAt       *time.Time      `json:"failed_at,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type NodeCommandStatus string

const (
	NodeCommandQueued    NodeCommandStatus = "queued"
	NodeCommandSent      NodeCommandStatus = "sent"
	NodeCommandSucceeded NodeCommandStatus = "succeeded"
	NodeCommandFailed    NodeCommandStatus = "failed"
	NodeCommandExpired   NodeCommandStatus = "expired"
)

type NodeCommand struct {
	ID             string            `json:"id"`
	Revision       uint64            `json:"revision"`
	IdempotencyKey string            `json:"idempotency_key"`
	NodeID         string            `json:"node_id"`
	Command        string            `json:"command"`
	Args           map[string]any    `json:"args,omitempty"`
	IssuedBy       string            `json:"issued_by"`
	Signature      string            `json:"signature"`
	Status         NodeCommandStatus `json:"status"`
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	SentAt         *time.Time        `json:"sent_at,omitempty"`
	CompletedAt    *time.Time        `json:"completed_at,omitempty"`
	Attempts       int               `json:"attempts"`
	LastSentAt     *time.Time        `json:"last_sent_at,omitempty"`
	Result         json.RawMessage   `json:"result,omitempty"`
	Error          string            `json:"error,omitempty"`
	Uncertain      bool              `json:"uncertain,omitempty"`
	EvidenceKind   string            `json:"evidence_kind,omitempty"`
	// ReconcilesCommandID links a durable read-only authoritative query to
	// the mutation whose side-effect result was uncertain. It is persisted so
	// reconnect/restart can settle the original command without redispatching
	// the mutation.
	ReconcilesCommandID string     `json:"reconciles_command_id,omitempty"`
	RecoveryAttempts    int        `json:"recovery_attempts,omitempty"`
	RecoveryNextAt      *time.Time `json:"recovery_next_at,omitempty"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type BudgetReservationStatus string

const (
	BudgetReserved BudgetReservationStatus = "reserved"
	BudgetSettled  BudgetReservationStatus = "settled"
	BudgetReleased BudgetReservationStatus = "released"
)

type BudgetReservation struct {
	WorkloadID     string                  `json:"workload_id"`
	PrincipalID    string                  `json:"principal_id"`
	Revision       uint64                  `json:"revision"`
	Attempt        uint64                  `json:"attempt"`
	OwnershipToken string                  `json:"ownership_token"`
	ReservedCents  int64                   `json:"reserved_cents"`
	LimitCents     int64                   `json:"limit_cents,omitempty"`
	Currency       string                  `json:"currency,omitempty"`
	ActualCents    int64                   `json:"actual_cents"`
	Status         BudgetReservationStatus `json:"status"`
	CreatedAt      time.Time               `json:"created_at"`
	UpdatedAt      time.Time               `json:"updated_at"`
}

type TransformationApproval struct {
	WorkloadID   string    `json:"workload_id"`
	PlanHash     string    `json:"plan_hash"`
	ApproverID   string    `json:"approver_id"`
	ApprovalMode string    `json:"approval_mode"`
	CreatedAt    time.Time `json:"created_at"`
}

type SchedulerLearningSample struct {
	ID             int64           `json:"id"`
	AcceleratorID  string          `json:"accelerator_id"`
	RuntimeVersion string          `json:"runtime_version"`
	WorkloadClass  string          `json:"workload_class"`
	Fingerprint    string          `json:"fingerprint"`
	Predicted      json.RawMessage `json:"predicted"`
	Observed       json.RawMessage `json:"observed"`
	Outcome        string          `json:"outcome"`
	CreatedAt      time.Time       `json:"created_at"`
}

type InterferenceProfile struct {
	Key               string    `json:"key"`
	AcceleratorID     string    `json:"accelerator_id"`
	RuntimeVersion    string    `json:"runtime_version"`
	WorkloadClasses   []string  `json:"workload_classes"`
	P95VRAMMB         int64     `json:"p95_vram_mb"`
	P95DurationMS     int64     `json:"p95_duration_ms"`
	PredictedSlowdown float64   `json:"predicted_slowdown"`
	Samples           int       `json:"samples"`
	Successes         int       `json:"successes"`
	Rollbacks         int       `json:"rollbacks"`
	Confidence        float64   `json:"confidence"`
	Version           int       `json:"version"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// TargetPolicyOverride is the durable, operator-controlled portion of a
// runtime target. Endpoints, credentials, model allowlists, and accelerator
// identity remain deployment configuration and cannot be rewritten through
// the browser control plane.
type TargetPolicyOverride struct {
	TargetID           string    `json:"target_id"`
	Enabled            bool      `json:"enabled"`
	Quarantined        bool      `json:"quarantined"`
	SharingEnabled     bool      `json:"sharing_enabled"`
	GuardedExploration bool      `json:"guarded_exploration"`
	VRAMReserveMB      int64     `json:"vram_reserve_mb"`
	MaxSlowdown        float64   `json:"max_slowdown"`
	UpdatedBy          string    `json:"updated_by"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type PromptMapping struct {
	PublicPromptID  string `json:"public_prompt_id"`
	WorkloadID      string `json:"workload_id"`
	TargetID        string `json:"target_id,omitempty"`
	BackendPromptID string `json:"backend_prompt_id,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
}

type AuditEvent struct {
	ID         string          `json:"id"`
	Timestamp  time.Time       `json:"timestamp"`
	ActorID    string          `json:"actor_id,omitempty"`
	OwnerID    string          `json:"owner_id,omitempty"`
	WorkloadID string          `json:"workload_id,omitempty"`
	Type       string          `json:"type"`
	Severity   string          `json:"severity"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type ArtifactProducer struct {
	ProfileID                string `json:"profile_id"`
	ProfileVersion           string `json:"profile_version"`
	ProfileDigest            string `json:"profile_digest"`
	CapabilityRevision       string `json:"capability_revision"`
	CapabilityDefinitionHash string `json:"capability_definition_hash"`
	Operation                string `json:"operation"`
}

type ArtifactMedia struct {
	MediaType     string  `json:"media_type"`
	ByteSize      int64   `json:"byte_size"`
	SHA256        string  `json:"sha256"`
	Width         int     `json:"width,omitempty"`
	Height        int     `json:"height,omitempty"`
	FrameRate     float64 `json:"frame_rate,omitempty"`
	Timebase      string  `json:"timebase,omitempty"`
	SampleRate    int     `json:"sample_rate,omitempty"`
	ChannelLayout string  `json:"channel_layout,omitempty"`
	DurationMS    int64   `json:"duration_ms,omitempty"`
}

// ArtifactCompatibility contains opaque, operation-scoped bearer tokens.
// Tokens are meaningful only after the artifact owner supplies the artifact
// reference again; filenames and model-family strings are never considered.
type ArtifactCompatibility struct {
	ProducerImplementation   string            `json:"producer_implementation"`
	CapabilityRevision       string            `json:"capability_revision"`
	CapabilityDefinitionHash string            `json:"capability_definition_hash"`
	SourceArtifactID         string            `json:"source_artifact_id"`
	Tokens                   map[string]string `json:"tokens,omitempty"`
}

type Artifact struct {
	ID            string                 `json:"id"`
	OwnerID       string                 `json:"owner_id"`
	WorkloadID    string                 `json:"workload_id,omitempty"`
	Name          string                 `json:"name"`
	Producer      *ArtifactProducer      `json:"producer,omitempty"`
	Media         ArtifactMedia          `json:"media"`
	Compatibility *ArtifactCompatibility `json:"compatibility,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	StorageRef    string                 `json:"storage_ref"`
	// Flat fields are kept in persisted metadata and Go callers for backward
	// compatibility. Creator-facing JSON uses the structured Media object.
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

type Incident struct {
	ID                     string          `json:"id"`
	OwnerID                string          `json:"owner_id"`
	Severity               string          `json:"severity"`
	Confidence             float64         `json:"confidence"`
	Summary                string          `json:"summary"`
	EvidenceRefs           []string        `json:"evidence_refs,omitempty"`
	Status                 string          `json:"status"`
	Proposal               json.RawMessage `json:"proposal,omitempty"`
	RequestedModelTier     string          `json:"requested_model_tier,omitempty"`
	EvidenceClassification string          `json:"evidence_classification,omitempty"`
	EvidenceSanitized      bool            `json:"evidence_sanitized"`
	Egress                 EgressPolicy    `json:"egress_policy,omitempty"`
	AnalysisWorkloadID     string          `json:"analysis_workload_id,omitempty"`
	ActualProvider         string          `json:"actual_provider,omitempty"`
	ActualModel            string          `json:"actual_model,omitempty"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
}
