// Package store defines the controller's persistence interfaces. MemoryStore
// supports deterministic development; PostgresWorkloadStore implements the
// aggregate production store defined by migrations/0001 through 0014.
package store

import (
	"context"
	"errors"
	"time"

	"vram-governor/internal/domain"
)

var ErrNotFound = errors.New("store: not found")

// NodeStore persists desired and observed node inventory.
type NodeStore interface {
	// UpsertNode creates the node if it doesn't exist (by ID) or updates it
	// in place if it does. Returns the stored copy.
	UpsertNode(ctx context.Context, n *domain.Node) (*domain.Node, error)

	GetNode(ctx context.Context, id string) (*domain.Node, error)

	ListNodes(ctx context.Context) ([]*domain.Node, error)

	// UpdateObserved patches only the observed half of a node's state
	// (used by the heartbeat/telemetry path so it never clobbers desired
	// state set via the API).
	UpdateObserved(ctx context.Context, id string, fn func(o *domain.Observed, accels *[]domain.Accelerator)) error
	UpdateDesired(ctx context.Context, id string, fn func(d *domain.Desired, scheduling *domain.SchedulingState)) error

	// DeleteNode removes a node entirely (not exposed by the public API).
	DeleteNode(ctx context.Context, id string) error
}

// EngineStore persists domain.EngineInstance rows (Phase 2 §32). Engines
// are reported by a node agent after it launches/stops a managed runtime
// process via a runtime.Driver.
type EngineStore interface {
	UpsertEngine(ctx context.Context, e *domain.EngineInstance) (*domain.EngineInstance, error)
	ListEnginesForNode(ctx context.Context, nodeID string) ([]*domain.EngineInstance, error)
	DeleteEngine(ctx context.Context, id string) error
}

// ProfileStore persists domain.PerformanceProfile rows (measurement.md §5).
// Rows are keyed by their own ID but always carry the node that measured
// them so the API can scope a listing to one node.
type ProfileStore interface {
	SaveProfile(ctx context.Context, nodeID string, p *domain.PerformanceProfile) (*domain.PerformanceProfile, error)
	ListProfilesForNode(ctx context.Context, nodeID string) ([]*domain.PerformanceProfile, error)
	ListAllProfiles(ctx context.Context) ([]*domain.PerformanceProfile, error)
}

// JobStore persists domain.Job and domain.WorkItem rows (architecture.md
// §32 Job/WorkItem, §47 Phase 3). This is a plain data-CRUD surface — the
// same shape as EngineStore/ProfileStore. The queue engine's business logic
// (leases, dispatch, retries, reaper) lives in internal/jobs and treats this
// store purely as a durable write-through target/read source for the
// canonical row shape, mirroring how liveness logic in internal/api/server.go
// sits above the dumb NodeStore rather than inside it.
type JobStore interface {
	UpsertJob(ctx context.Context, j *domain.Job) (*domain.Job, error)
	GetJob(ctx context.Context, id string) (*domain.Job, error)
	ListJobs(ctx context.Context) ([]*domain.Job, error)

	UpsertWorkItem(ctx context.Context, wi *domain.WorkItem) (*domain.WorkItem, error)
	GetWorkItem(ctx context.Context, jobID, itemID, operationVersion string) (*domain.WorkItem, error)
	ListWorkItemsForJob(ctx context.Context, jobID string) ([]*domain.WorkItem, error)
}

// WorkloadStore is the authoritative state-machine and lease surface shared
// by every protocol plane. AcquireAcceleratorLease must be atomic in durable
// implementations; the fencing token monotonically increases per device.
type WorkloadStore interface {
	CreateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, bool, error)
	UpdateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, error)
	GetWorkload(ctx context.Context, id string) (*domain.Workload, error)
	ListWorkloads(ctx context.Context) ([]*domain.Workload, error)

	AcquireAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error)
	RenewAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64, ttl time.Duration) error
	ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error

	SavePromptMapping(ctx context.Context, mapping *domain.PromptMapping) error
	GetPromptMapping(ctx context.Context, publicPromptID string) (*domain.PromptMapping, error)
	AppendAuditEvent(ctx context.Context, event *domain.AuditEvent) error
	ListAuditEvents(ctx context.Context, ownerID string, limit int) ([]*domain.AuditEvent, error)

	UpsertModelResidency(ctx context.Context, residency *domain.ModelResidency) (*domain.ModelResidency, error)
	GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error)
	ListModelResidencies(ctx context.Context) ([]*domain.ModelResidency, error)
	CreateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, bool, error)
	UpdateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, error)
	ListResidencyTransitions(ctx context.Context, limit int) ([]*domain.ResidencyTransition, error)

	CreateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, bool, error)
	UpdateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, error)
	ListPendingNotifications(ctx context.Context, now time.Time, limit int) ([]*domain.NotificationDelivery, error)
	ListNotifications(ctx context.Context, ownerID string, limit int) ([]*domain.NotificationDelivery, error)

	CreateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, bool, error)
	UpdateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, error)
	GetNodeCommand(ctx context.Context, id string) (*domain.NodeCommand, error)
	ListNodeCommands(ctx context.Context, nodeID string, limit int) ([]*domain.NodeCommand, error)

	ReserveBudget(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64) (*domain.BudgetReservation, bool, error)
	SettleBudget(ctx context.Context, workloadID string, actualCents int64) (*domain.BudgetReservation, error)
	ReleaseBudget(ctx context.Context, workloadID string) error
	ListBudgetReservations(ctx context.Context, principalID string) ([]*domain.BudgetReservation, error)

	CreateTransformationApproval(ctx context.Context, approval *domain.TransformationApproval) (*domain.TransformationApproval, bool, error)
	GetTransformationApproval(ctx context.Context, workloadID, planHash string) (*domain.TransformationApproval, error)
	ListTransformationApprovals(ctx context.Context, workloadID string) ([]*domain.TransformationApproval, error)
	SaveSchedulerLearningSample(ctx context.Context, sample *domain.SchedulerLearningSample) (*domain.SchedulerLearningSample, error)
	ListSchedulerLearningSamples(ctx context.Context, acceleratorID string, limit int) ([]*domain.SchedulerLearningSample, error)
	UpsertInterferenceProfile(ctx context.Context, profile *domain.InterferenceProfile) (*domain.InterferenceProfile, error)
	GetInterferenceProfile(ctx context.Context, key string) (*domain.InterferenceProfile, error)
	ListInterferenceProfiles(ctx context.Context) ([]*domain.InterferenceProfile, error)
	CreateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error)
	UpdateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error)
	ListTransitionPlans(ctx context.Context, workloadID string, limit int) ([]*domain.TransitionPlan, error)
	UpsertTargetPolicyOverride(ctx context.Context, policy *domain.TargetPolicyOverride) (*domain.TargetPolicyOverride, error)
	ListTargetPolicyOverrides(ctx context.Context) ([]*domain.TargetPolicyOverride, error)
}

type IncidentStore interface {
	CreateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error)
	UpdateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error)
	GetIncident(ctx context.Context, id string) (*domain.Incident, error)
	ListIncidents(ctx context.Context, ownerID string) ([]*domain.Incident, error)
}

type BrowserSessionStore interface {
	CreateBrowserSession(ctx context.Context, session *domain.BrowserSession) error
	GetBrowserSession(ctx context.Context, idHash string) (*domain.BrowserSession, error)
	DeleteBrowserSession(ctx context.Context, idHash string) error
}

// Store is the aggregate persistence surface the controller wires up.
// Both development and PostgreSQL stores implement this aggregate surface so
// controller wiring never mixes durable and ephemeral authority.
type Store interface {
	NodeStore
	EngineStore
	ProfileStore
	JobStore
	WorkloadStore
	IncidentStore
	BrowserSessionStore
}
