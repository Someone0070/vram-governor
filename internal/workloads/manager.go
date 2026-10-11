package workloads

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

type Manager struct {
	log      *slog.Logger
	store    store.WorkloadStore
	nodes    store.NodeStore
	leaseTTL time.Duration

	mu       sync.RWMutex
	adapters map[string]Adapter
	targets  map[string]Target
	// retiredTargets retains immutable cleanup metadata after an authoritative
	// node refresh removes a route. Retired targets are never returned by
	// selection or targetByID, even while their old reservation is unwinding.
	retiredTargets    map[string]Target
	targetGenerations map[string]uint64
	cancels           map[string]context.CancelFunc
	cancelling        map[string]struct{}
	pendingStreams    map[string]*pendingStream
	// streamSessions outlive one backend segment.  An interactive HTTP/SSE
	// request owns the session until the client disconnects or the workload
	// reaches a terminal state; checkpoint preemption only replaces the
	// segment and never asks the caller to attach a second stream.
	streamSessions map[string]*streamSession
	subscribers    map[chan domain.AuditEvent]struct{}
	kick           chan struct{}

	placementMu                    sync.Mutex
	residencyAdmissionMu           sync.Mutex
	residencyOperationInFlightMu   sync.Mutex
	residencyOperationInFlight     chan struct{}
	targetActive                   map[string]int
	targetLeases                   map[string]*domain.AcceleratorLease
	activePlacements               map[string]activePlacement
	reservations                   map[string]*targetReservation
	powerProfileLocksMu            sync.Mutex
	powerProfileInFlight           map[string]chan struct{}
	reconcileMu                    sync.Mutex
	lifecycleMu                    sync.Mutex
	recoveryCtx                    context.Context
	recoveryCancel                 context.CancelFunc
	recoveryWG                     sync.WaitGroup
	asyncWG                        sync.WaitGroup
	managerCtx                     context.Context
	managerCancel                  context.CancelFunc
	loopWG                         sync.WaitGroup
	recoveryWake                   chan struct{}
	recoveryStarted                bool
	lifecycleStarting              bool
	lifecycleClosed                bool
	runtimeSwitchLocksMu           sync.Mutex
	runtimeSwitchLocks             map[string]*sync.Mutex
	runtimeSwitchInFlight          map[string]chan struct{}
	runtimeProfileTransitions      map[string]*runtimeProfileTransition
	runtimeProfileTransitionTarget map[string]string
	runtimeProfileBlockedNodes     map[string]string
	runtimeProfileBlockedCards     map[string]string
	runtimeProfileBlockedTargets   map[string]string
	runtimeProfileNodeEpochs       map[string]uint64
	runtimeProfileCardEpochs       map[string]uint64
	residency                      ResidencyOptions
	residencyObservationLocksMu    sync.Mutex
	residencyObservationLocks      map[string]*sync.Mutex
	residencyAdmissionLocksMu      sync.Mutex
	residencyAdmissionLocks        map[string]*sync.RWMutex
	residencyTransitionsMu         sync.Mutex
	residencyTransitions           map[string]struct{}
	pendingLeaseFinalizations      map[string]pendingLeaseFinalization
	lastResidencySweep             time.Time
	recoveryTransitions            map[string]struct{}
	pendingResidencyObservations   map[string]pendingResidencyObservation
	pendingObservationGeneration   uint64
	notificationMu                 sync.Mutex
	notifications                  NotificationOptions
	notificationNets               []*net.IPNet
	providerMu                     sync.Mutex
	providerCircuits               map[string]providerCircuit
	learningMu                     sync.RWMutex
	interferenceProfiles           map[string]*domain.InterferenceProfile
	nodeControl                    NodeControl
	controllerResidency            *ControllerResidencyAdapter
	gpuPowerControl                NodeControl
	managedGPUPerformance          map[string]struct{}
	pendingGPUIdleReconcile        map[string]bool
	gpuIdleReconcileInFlight       map[string]bool
	gpuIdleRetryAfter              map[string]time.Time
	gpuPowerGeneration             map[string]uint64
	gpuCommandFences               map[string]uint64
	artifacts                      artifacts.Store
	defaultMaxAcceleratorsPerModel int
	modelCapacityPolicies          map[string]int
}

// pendingResidencyObservation is versioned by target registration. A slower
// observation from an older node advertisement must never delete a retry that
// was queued for newer facts.
type pendingResidencyObservation struct {
	target     Target
	generation uint64
}

type pendingLeaseFinalization struct {
	workload    *domain.Workload
	disposition string
	message     string
}

// runtimeProfileTransition binds one profile switch to the target generation
// that was made unavailable before the external command was sent. A result is
// useful only once, for this exact command key and route.
type runtimeProfileTransition struct {
	dispatchMu         sync.Mutex
	resultMu           sync.Mutex
	commandKey         string
	nodeID             string
	targetID           string
	acceleratorID      string
	adapter            string
	endpoint           string
	capabilityVersion  string
	capabilityRevision string
	runtimeIdentity    string
	modelFingerprint   string
	profile            RuntimeCapacityProfile
	// historyBasis preserves the exact verified route/capacity observation
	// that was current immediately before this ticket revoked slot exposure.
	// Dispatch history may use it only while this exact ticket and generation
	// remain current; it is not a capacity source for admission or registration.
	historyBasis           Target
	historyBasisGeneration uint64
	resultFingerprint      string
	expectedGeneration     uint64
	projectedGeneration    uint64
	projected              bool
}

// RuntimeProfileResultClaim fences transition lifecycle changes while one
// correlated result crosses durable command CAS and manager projection.
type RuntimeProfileResultClaim struct {
	manager    *Manager
	transition *runtimeProfileTransition
	once       sync.Once
}

func (claim *RuntimeProfileResultClaim) Release() {
	if claim != nil && claim.transition != nil {
		claim.once.Do(claim.transition.resultMu.Unlock)
	}
}

func (claim *RuntimeProfileResultClaim) Project(result map[string]any) error {
	if claim == nil || claim.manager == nil || claim.transition == nil {
		return fmt.Errorf("runtime profile result claim is unavailable")
	}
	return claim.manager.applyRuntimeProfileCommandResult(claim.transition.commandKey, claim.transition.nodeID, result, true)
}

type runtimeProfileResult struct {
	Adapters []runtimeProfileResultAdapter `json:"adapters"`
}

type runtimeProfileResultAdapter struct {
	ID                   string                        `json:"id"`
	Adapter              string                        `json:"adapter"`
	Endpoint             string                        `json:"endpoint"`
	AcceleratorIndex     *int                          `json:"accelerator_index"`
	Version              string                        `json:"version"`
	ModelFingerprint     string                        `json:"model_fingerprint"`
	CapabilityVersion    string                        `json:"capability_version"`
	CapabilityRevision   string                        `json:"capability_revision"`
	ContextLimit         int                           `json:"context_limit"`
	Slots                int                           `json:"slots"`
	CapacitySource       string                        `json:"capacity_source"`
	CapabilitiesVerified bool                          `json:"capabilities_verified"`
	ActiveRuntimeProfile string                        `json:"active_runtime_profile"`
	RuntimeProfiles      []runtimeProfileResultProfile `json:"runtime_profiles"`
}

type runtimeProfileResultProfile struct {
	ID           string `json:"id"`
	ContextLimit int    `json:"context_limit"`
	Slots        int    `json:"slots"`
}

// NodeControl executes a fixed, signed operation on the node that owns a
// target. It is injected by the controller API so the scheduler never needs
// network access to a node-local runtime endpoint.
type NodeControl func(context.Context, string, string, map[string]any, string) (map[string]any, error)

type providerCircuit struct {
	Failures  int
	OpenUntil time.Time
}

const leaseCleanupTimeout = 10 * time.Second

// errLeaseCleanupRecorded distinguishes a release failure that has been
// durably handed to the cleanup worker from one whose cleanup could not be
// made durable. Admission rollback still surfaces the former to its caller,
// while terminal release treats it as a safe durable condition.
var errLeaseCleanupRecorded = errors.New("accelerator lease cleanup recorded")

const restartReconciliationBlocker = "controller restarted; reconciling prior backend execution"

func NewManager(log *slog.Logger, backing store.WorkloadStore, leaseTTL time.Duration) *Manager {
	if leaseTTL <= 0 {
		leaseTTL = 30 * time.Second
	}
	return &Manager{
		log: log, store: backing, leaseTTL: leaseTTL,
		adapters: make(map[string]Adapter), targets: make(map[string]Target), retiredTargets: make(map[string]Target), targetGenerations: make(map[string]uint64),
		cancels: make(map[string]context.CancelFunc), cancelling: make(map[string]struct{}), pendingStreams: make(map[string]*pendingStream), streamSessions: make(map[string]*streamSession), subscribers: make(map[chan domain.AuditEvent]struct{}),
		kick: make(chan struct{}, 1), targetActive: make(map[string]int), targetLeases: make(map[string]*domain.AcceleratorLease), activePlacements: make(map[string]activePlacement), reservations: make(map[string]*targetReservation),
		powerProfileInFlight:     make(map[string]chan struct{}),
		managedGPUPerformance:    make(map[string]struct{}),
		pendingGPUIdleReconcile:  make(map[string]bool),
		gpuIdleReconcileInFlight: make(map[string]bool),
		gpuIdleRetryAfter:        make(map[string]time.Time),
		gpuPowerGeneration:       make(map[string]uint64),
		gpuCommandFences:         make(map[string]uint64),
		residency:                DefaultResidencyOptions(), residencyObservationLocks: make(map[string]*sync.Mutex), residencyAdmissionLocks: make(map[string]*sync.RWMutex), residencyTransitions: make(map[string]struct{}), recoveryTransitions: make(map[string]struct{}), pendingResidencyObservations: make(map[string]pendingResidencyObservation),
		pendingLeaseFinalizations: make(map[string]pendingLeaseFinalization),
		notifications:             DefaultNotificationOptions(),
		providerCircuits:          make(map[string]providerCircuit),
		interferenceProfiles:      make(map[string]*domain.InterferenceProfile),
		runtimeSwitchLocks:        make(map[string]*sync.Mutex), runtimeSwitchInFlight: make(map[string]chan struct{}),
		runtimeProfileTransitions: make(map[string]*runtimeProfileTransition), runtimeProfileTransitionTarget: make(map[string]string),
		runtimeProfileBlockedNodes: make(map[string]string), runtimeProfileBlockedCards: make(map[string]string), runtimeProfileBlockedTargets: make(map[string]string),
		runtimeProfileNodeEpochs: make(map[string]uint64), runtimeProfileCardEpochs: make(map[string]uint64),
		defaultMaxAcceleratorsPerModel: 1,
		modelCapacityPolicies:          make(map[string]int),
		recoveryWake:                   make(chan struct{}, 1),
	}
}

func (m *Manager) RegisterAdapter(adapter Adapter) {
	m.mu.Lock()
	m.adapters[adapter.Name()] = adapter
	controlConfigured := m.nodeControl != nil
	m.mu.Unlock()
	if controlConfigured {
		if checkpointAdapter, ok := adapter.(*HTTPAdapter); ok {
			checkpointAdapter.ConfigureCheckpointChannel(m.nodeControlForTarget)
		}
	}
}

func (m *Manager) SetNodeStore(nodes store.NodeStore) { m.nodes = nodes }

func (m *Manager) SetArtifactStore(store artifacts.Store) {
	m.mu.Lock()
	m.artifacts = store
	m.mu.Unlock()
}

func (m *Manager) SetNodeControl(control NodeControl) {
	m.mu.Lock()
	m.nodeControl = control
	if control != nil {
		m.controllerResidency = NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Name: "controller-residency", Command: control, Store: m.store, TransitionTimeout: m.residency.TransitionTimeout})
	} else {
		m.controllerResidency = nil
	}
	adapters := make([]Adapter, 0, len(m.adapters))
	for _, adapter := range m.adapters {
		adapters = append(adapters, adapter)
	}
	m.mu.Unlock()
	for _, adapter := range adapters {
		if checkpointAdapter, ok := adapter.(*HTTPAdapter); ok {
			checkpointAdapter.ConfigureCheckpointChannel(m.nodeControlForTarget)
		}
	}
}

// SetGPUPerformanceControl enables the distinct workload power-control path.
// Tests and alternate deployments that do not opt in retain their prior node
// command behavior.
func (m *Manager) SetGPUPerformanceControl(control NodeControl) {
	m.mu.Lock()
	m.gpuPowerControl = control
	m.mu.Unlock()
}

// SetModelCapacityPolicies limits concurrent placement of one model across
// physical accelerators. Slot concurrency within an allowed accelerator is
// unaffected. The default is deliberately one card unless configured higher.
func (m *Manager) SetModelCapacityPolicies(defaultMax int, overrides map[string]int) {
	if defaultMax < 1 {
		defaultMax = 1
	}
	policies := make(map[string]int, len(overrides))
	for model, limit := range overrides {
		if model != "" && limit > 0 {
			policies[model] = limit
		}
	}
	m.mu.Lock()
	m.defaultMaxAcceleratorsPerModel = defaultMax
	m.modelCapacityPolicies = policies
	m.mu.Unlock()
}

func (m *Manager) MaxAcceleratorsForModel(model string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.modelLimitLocked(model)
}

// CurrentlyAvailableSlotsForModel reports immediately admissible slots, not
// merely configured runtime concurrency. It accounts for live node inventory,
// other adapters occupying the physical accelerator, and the model's
// cross-accelerator ceiling. Admission remains authoritative because this is
// an intentionally non-reserving snapshot.
func (m *Manager) CurrentlyAvailableSlotsForModel(ctx context.Context, target Target, model string) int {
	if target.CapacitySource == "runtime-profile:observation_unavailable" {
		return 0
	}
	if blocker := m.inventoryBlocker(ctx, target, Requirements{}); blocker != "" {
		return 0
	}
	m.residencyAdmissionMu.Lock()
	defer m.residencyAdmissionMu.Unlock()
	m.mu.RLock()
	currentTarget, targetRegistered := m.targets[target.ID]
	if !targetRegistered || !targetIdentityMatches(target, currentTarget) {
		m.mu.RUnlock()
		return 0
	}
	target = currentTarget
	if reason := m.runtimeProfileTargetBlockerLocked(target); reason != "" {
		m.mu.RUnlock()
		return 0
	}
	pendingKey := m.runtimeProfileTransitionTarget[target.ID]
	runtimeProfilePending := pendingKey != "" && m.runtimeProfileTransitions[pendingKey] != nil && !m.runtimeProfileTransitions[pendingKey].projected
	m.mu.RUnlock()
	if runtimeProfilePending {
		return 0
	}
	modelLimit := m.MaxAcceleratorsForModel(model)
	m.placementMu.Lock()
	defer m.placementMu.Unlock()
	slots := target.Slots
	if slots <= 0 {
		slots = 1
	}
	free := slots - m.targetActive[target.ID]
	if free <= 0 || model == "" || target.AcceleratorID == "" || target.Cloud {
		if free < 0 {
			return 0
		}
		return free
	}
	modelAccelerators := make(map[string]struct{})
	for _, active := range m.activePlacements {
		if active.model == model && active.acceleratorID != "" {
			modelAccelerators[active.acceleratorID] = struct{}{}
		}
		if active.acceleratorID == target.AcceleratorID && active.targetID != target.ID {
			// Co-scheduling depends on request-specific VRAM, slowdown, and
			// disruption consent. Do not promise those conditional slots.
			return 0
		}
	}
	if _, alreadyUsed := modelAccelerators[target.AcceleratorID]; !alreadyUsed && len(modelAccelerators) >= modelLimit {
		return 0
	}
	return free
}

func (m *Manager) modelLimitLocked(model string) int {
	if limit := m.modelCapacityPolicies[model]; limit > 0 {
		return limit
	}
	if m.defaultMaxAcceleratorsPerModel > 0 {
		return m.defaultMaxAcceleratorsPerModel
	}
	return 1
}

func (m *Manager) modelAcceleratorAllowed(target Target, model string) (bool, int) {
	if model == "" || target.AcceleratorID == "" || target.Cloud {
		return true, 0
	}
	limit := m.MaxAcceleratorsForModel(model)
	m.placementMu.Lock()
	defer m.placementMu.Unlock()
	activeAccelerators := make(map[string]struct{})
	for _, active := range m.activePlacements {
		if active.model == model && active.acceleratorID != "" {
			activeAccelerators[active.acceleratorID] = struct{}{}
		}
	}
	if _, used := activeAccelerators[target.AcceleratorID]; used {
		return true, limit
	}
	return len(activeAccelerators) < limit, limit
}

// rollbackAcceleratorLease releases an exact fenced lease with a fresh bounded
// context. If the release cannot complete, it durably records the exact tuple
// before allowing placement/terminal state to be cleared.
func (m *Manager) rollbackAcceleratorLease(ctx context.Context, lease *domain.AcceleratorLease, owner string) error {
	return m.rollbackAcceleratorLeaseWithIntent(ctx, lease, owner, false)
}

func (m *Manager) rollbackAcceleratorLeaseWithIntent(ctx context.Context, lease *domain.AcceleratorLease, owner string, retainIntent bool, terminal ...*domain.AcceleratorLeaseCleanupIntent) error {
	return m.rollbackAcceleratorLeaseWithIntentMode(ctx, lease, owner, retainIntent, false, terminal...)
}

func (m *Manager) rollbackAcceleratorLeaseWithPreparedIntent(ctx context.Context, lease *domain.AcceleratorLease, owner string, retainIntent bool, intent *domain.AcceleratorLeaseCleanupIntent) error {
	return m.rollbackAcceleratorLeaseWithIntentMode(ctx, lease, owner, retainIntent, true, intent)
}

func (m *Manager) rollbackAcceleratorLeaseWithIntentMode(ctx context.Context, lease *domain.AcceleratorLease, owner string, retainIntent, intentAlreadyAdvanced bool, terminal ...*domain.AcceleratorLeaseCleanupIntent) error {
	if lease == nil {
		return nil
	}
	cleanupCtx, cancel := leaseCleanupContext(ctx)
	defer cancel()
	err := m.store.ReleaseAcceleratorLease(cleanupCtx, lease.AcceleratorID, owner, lease.FencingToken)
	if err == nil {
		// Deleting an old intent is best effort after exact release; retaining it
		// is safe and the retry worker will confirm absence on its next pass.
		if !retainIntent {
			if len(terminal) > 0 && terminal[0] != nil {
				_ = m.deleteLeaseCleanupIntent(cleanupCtx, terminal[0])
			} else {
				_ = m.store.DeleteAcceleratorLeaseCleanupIntent(cleanupCtx, lease.AcceleratorID, owner, lease.FencingToken)
			}
		}
		return nil
	}
	if errors.Is(err, store.ErrNotFound) {
		current, getErr := m.store.GetAcceleratorLease(cleanupCtx, lease.AcceleratorID)
		if errors.Is(getErr, store.ErrNotFound) || (getErr == nil && (current == nil || !current.ExpiresAt.After(time.Now().UTC()))) {
			if !retainIntent {
				if len(terminal) > 0 && terminal[0] != nil {
					_ = m.deleteLeaseCleanupIntent(cleanupCtx, terminal[0])
				} else {
					_ = m.store.DeleteAcceleratorLeaseCleanupIntent(cleanupCtx, lease.AcceleratorID, owner, lease.FencingToken)
				}
			}
			return nil
		}
		if getErr != nil {
			err = fmt.Errorf("verify absent accelerator lease after fenced release: %w", getErr)
		} else {
			err = fmt.Errorf("fenced accelerator lease belongs to another live owner")
		}
	}
	if len(terminal) > 0 && terminal[0] != nil {
		continuation := *terminal[0]
		if !intentAlreadyAdvanced {
			scheduleLeaseCleanupRetry(&continuation, err)
		} else {
			// The retry loop already advanced attempts and backoff on this
			// exact row; refresh only the diagnostic failure without a second
			// increment or schedule shift.
			continuation.LastError = err.Error()
			if len(continuation.LastError) > 512 {
				continuation.LastError = continuation.LastError[:512]
			}
		}
		if _, persistErr := m.store.RecordAcceleratorLeaseCleanupIntent(cleanupCtx, &continuation); persistErr != nil {
			return fmt.Errorf("accelerator lease cleanup intent persistence failed: %w (release: %v)", persistErr, err)
		}
		return fmt.Errorf("%w: rollback pending reconciliation: %v", errLeaseCleanupRecorded, err)
	}
	if persistErr := m.recordLeaseCleanupIntent(cleanupCtx, lease, owner, err, 1); persistErr != nil {
		return fmt.Errorf("accelerator lease cleanup intent persistence failed: %w (release: %v)", persistErr, err)
	}
	return fmt.Errorf("%w: rollback pending reconciliation: %v", errLeaseCleanupRecorded, err)
}

func leaseCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), leaseCleanupTimeout)
}

// cancelAdapterBounded is the manager-wide terminal cleanup seam.  Backend
// cancellation is a physical ownership operation: a caller disconnect or a
// cancelled reconciliation context must not make the controller abandon the
// exact handle/lease while the adapter is still waiting on the node.  Keep the
// caller's cancellation for the diagnostic path, but give the cleanup a fresh,
// bounded context so every adapter follows the same fail-closed contract.
func cancelAdapterBounded(ctx context.Context, adapter Adapter, handle *domain.ExecutionHandle, target Target) error {
	if adapter == nil || handle == nil {
		return nil
	}
	cleanupCtx, cancel := leaseCleanupContext(ctx)
	defer cancel()
	return adapter.Cancel(cleanupCtx, handle, target)
}

// cancelAdapterStopConfirmed is the fail-closed variant used after a backend
// handle has crossed the manager's publication boundary.  ErrUnsupported is
// not a stop confirmation here: releasing the accelerator would otherwise let
// a live generation overlap a later owner.
func cancelAdapterStopConfirmed(ctx context.Context, adapter Adapter, handle *domain.ExecutionHandle, target Target) error {
	if handle == nil {
		return nil
	}
	if adapter == nil {
		return fmt.Errorf("backend stop unconfirmed: adapter is unavailable")
	}
	if err := cancelAdapterBounded(ctx, adapter, handle, target); err != nil {
		return fmt.Errorf("backend stop unconfirmed: %w", err)
	}
	return nil
}

func (m *Manager) rememberReservationBackend(reservation *targetReservation, adapter Adapter, target Target, handle *domain.ExecutionHandle) {
	if reservation == nil || handle == nil {
		return
	}
	m.placementMu.Lock()
	reservation.backendAdapter = adapter
	reservation.backendTarget = target
	reservation.backendHandle = handle
	reservation.backendStopPending = true
	reservation.backendStopConfirmed = false
	reservation.backendStopInFlight = false
	m.placementMu.Unlock()
}

func (m *Manager) confirmReservationBackendStopped(reservation *targetReservation) {
	if reservation == nil {
		return
	}
	m.placementMu.Lock()
	reservation.backendStopPending = false
	reservation.backendStopConfirmed = true
	reservation.backendStopInFlight = false
	m.placementMu.Unlock()
}

// cancelReservationBackend serializes physical stop attempts for one exact
// reservation. Manager.Cancel, an execution defer, and the retry loop can all
// observe the same handle concurrently; issuing a second adapter Cancel while
// the first is still in flight can itself race a non-idempotent backend. A
// waiter returns visibly after the first attempt completes without
// confirmation, leaving the reservation fenced for a later retry.
func (m *Manager) cancelReservationBackend(ctx context.Context, reservation *targetReservation, adapter Adapter, handle *domain.ExecutionHandle, target Target) error {
	if handle == nil {
		return nil
	}
	if reservation == nil {
		return cancelAdapterStopConfirmed(ctx, adapter, handle, target)
	}
	waitCtx, waitCancel := leaseCleanupContext(ctx)
	defer waitCancel()
	waiting := false
	for {
		m.placementMu.Lock()
		if reservation.released || reservation.backendStopConfirmed {
			m.placementMu.Unlock()
			return nil
		}
		if !reservation.backendStopInFlight {
			if waiting {
				m.placementMu.Unlock()
				return fmt.Errorf("backend stop attempt completed without confirmation")
			}
			reservation.backendStopInFlight = true
			m.placementMu.Unlock()
			break
		}
		m.placementMu.Unlock()
		waiting = true
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-waitCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("backend stop attempt remains in flight: %w", waitCtx.Err())
		case <-timer.C:
		}
	}
	stopErr := cancelAdapterStopConfirmed(waitCtx, adapter, handle, target)
	m.placementMu.Lock()
	reservation.backendStopInFlight = false
	if stopErr == nil {
		reservation.backendStopPending = false
		reservation.backendStopConfirmed = true
	}
	m.placementMu.Unlock()
	return stopErr
}

// resumeProtocolCleanupResult distinguishes a resume that was interrupted by
// a protocol failure after its live HTTP generation had already stopped.  The
// HTTP adapter normally discovers that failure from Observe, but a resumed
// stream performs its signed reuse proof before ResumeWithLease returns.  If
// the manager waits for that return, the node may terminalize the consumed
// snapshot before the cancel boundary runs; cancellation then becomes an
// uncertain cleanup rather than the one authoritative stop.  The watcher
// below cancels the resume context first and sends the signed cancel while the
// restore operation still owns its resumable reference.
type resumeProtocolCleanupResult struct {
	confirmed bool
	err       error
}

type resumedProtocolFailure struct {
	handle *domain.ExecutionHandle
	err    error
}

// resumeWithLeaseWatchingProtocol is intentionally narrow: only the native
// HTTP adapter owns a live resumed stream whose parser can report a malformed
// terminal protocol before ResumeWithLease has returned. Other lease-aware
// adapters keep their established synchronous contract.
func resumeWithLeaseWatchingProtocol(ctx context.Context, adapter LeaseAwareCheckpointAdapter, req domain.WorkloadRequest, plan *domain.ExecutionPlan, checkpoint string, target Target, lease SlotLease, command CheckpointCommand) (*domain.ExecutionHandle, error, resumeProtocolCleanupResult) {
	httpAdapter, watchable := adapter.(*HTTPAdapter)
	if !watchable {
		handle, err := adapter.ResumeWithLease(ctx, req, plan, checkpoint, target, lease, command)
		return handle, err, resumeProtocolCleanupResult{}
	}
	resumeCtx, stopResume := context.WithCancel(ctx)
	defer stopResume()
	resultCh := make(chan resumedProtocolFailure, 1)
	go func() {
		handle, err := adapter.ResumeWithLease(resumeCtx, req, plan, checkpoint, target, lease, command)
		resultCh <- resumedProtocolFailure{handle: handle, err: err}
	}()
	// The adapter's signed cleanup uses its own bounded context. Keep this
	// watcher bounded as well so a lost node cannot leave the manager goroutine
	// waiting forever after the backend parser has already failed.
	deadline := time.NewTimer(leaseCleanupTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	var cleanup resumeProtocolCleanupResult
	for {
		select {
		case result := <-resultCh:
			return result.handle, result.err, cleanup
		case <-deadline.C:
			stopResume()
			return nil, fmt.Errorf("checkpoint ResumeWithLease did not terminate after bounded protocol cleanup"), cleanup
		case <-ticker.C:
			if cleanup.err != nil || cleanup.confirmed {
				continue
			}
			handle, failed := httpAdapter.resumedProtocolFailure(req.ID, target, lease, command, checkpoint)
			if !failed {
				continue
			}
			// Stop the reuse/reconciliation calls first. They all use resumeCtx;
			// this prevents a concurrent VerifyKVReuse from winning the node
			// phase race and consuming the snapshot before cancellation.
			stopResume()
			cleanup.err = httpAdapter.Cancel(context.WithoutCancel(ctx), handle, target)
			if cleanup.err == nil {
				cleanup.confirmed = true
			}
		}
	}
}

// resumedProtocolFailure returns the newest resumed live run that has already
// ended with a stream/protocol error. The stitchBase marker excludes the
// original preempted stream, whose context cancellation is expected and must
// not be mistaken for a failed restore.
func (a *HTTPAdapter) resumedProtocolFailure(workloadID string, target Target, lease SlotLease, command CheckpointCommand, checkpoint string) (*domain.ExecutionHandle, bool) {
	if a == nil {
		return nil, false
	}
	a.checkpointMu.Lock()
	candidates := make(map[string]checkpointExecution)
	for externalID, execution := range a.checkpointRuns {
		if execution.Request.ID == workloadID && execution.Target.ID == target.ID {
			candidates[externalID] = execution
		}
	}
	a.checkpointMu.Unlock()
	var selectedID string
	var selectedRun *httpRun
	var selectedExecution checkpointExecution
	var selectedStartedAt time.Time
	a.runMu.Lock()
	for externalID, execution := range candidates {
		run := a.runs[externalID]
		if run == nil || run.stitchBase == nil || !run.done || run.err == nil {
			continue
		}
		if selectedRun == nil || run.startedAt.After(selectedRun.startedAt) {
			selectedID = externalID
			selectedRun = run
			selectedExecution = execution
			selectedStartedAt = run.startedAt
		}
	}
	a.runMu.Unlock()
	if selectedID == "" || selectedRun == nil {
		return nil, false
	}
	// ResumeWithLease publishes these immutable fields immediately after the
	// live request is created. A fast protocol failure can race that publication,
	// so fill only missing values from the signed resume envelope.
	if selectedExecution.OperationID == "" {
		selectedExecution.OperationID = command.ID
	}
	if selectedExecution.SnapshotName == "" {
		selectedExecution.SnapshotName = checkpoint
	}
	if selectedExecution.Lease.AcceleratorID == "" || selectedExecution.Lease.WorkloadID == "" {
		selectedExecution.Lease = lease
	}
	conversationID := selectedExecution.ConversationID
	if conversationID == "" {
		conversationID = command.ContinuationConversationID
	}
	if conversationID == "" {
		conversationID = command.ID
	}
	ownerID := command.OwnerID
	workloadID = command.WorkloadID
	if selectedExecution.Request.OwnerID != "" {
		ownerID = selectedExecution.Request.OwnerID
	}
	if selectedExecution.Request.ID != "" {
		workloadID = selectedExecution.Request.ID
	}
	slotID := selectedExecution.Lease.SlotID
	if slotID < 0 {
		slotID = lease.SlotID
	}
	acceleratorID := selectedExecution.Lease.AcceleratorID
	if acceleratorID == "" {
		acceleratorID = lease.AcceleratorID
	}
	generation := selectedExecution.Lease.Generation
	if generation == 0 {
		generation = lease.Generation
	}
	fence := selectedExecution.Lease.Fence
	if fence == 0 {
		fence = lease.Fence
	}
	opaque, _ := json.Marshal(map[string]any{
		"slot_id": slotID, "accelerator_id": acceleratorID, "generation": generation,
		"fence": fence, "conversation_id": conversationID, "operation_id": selectedExecution.OperationID,
		"owner_id": ownerID, "workload_id": workloadID, "snapshot_name": selectedExecution.SnapshotName,
		"resumed": true,
	})
	return &domain.ExecutionHandle{ExternalID: selectedID, Opaque: opaque, StartedAt: selectedStartedAt}, true
}

// retainReservationForBackendCleanup fences the exact in-memory placement
// while a stop is unconfirmed. A resumed checkpoint also records the exact
// backend custody in the durable operation journal before publishing the
// diagnostic; losing that journal must never turn a live handle into reusable
// capacity.
func (m *Manager) retainReservationForBackendCleanup(ctx context.Context, id string, reservation *targetReservation, adapter Adapter, target Target, handle *domain.ExecutionHandle, disposition, message string) error {
	var journalErr error
	if reservation != nil {
		if reservation.checkpointOperationID == "" {
			reservation.checkpointOperationID = checkpointOperationIDFromHandle(handle)
		}
		if reservation.checkpointOperationID != "" && reservation.lease != nil {
			cleanupState := "pending"
			if handle == nil && adapter == nil {
				// The caller has already confirmed the physical stop; only the
				// controller lease/release continuation remains outstanding.
				cleanupState = "stopped"
			}
			_, journalErr = m.recordCheckpointCleanupState(context.WithoutCancel(ctx), reservation.checkpointOperationID, cleanupState, handle, target, reservation.lease, disposition, message)
			if journalErr != nil {
				message = message + "; durable checkpoint cleanup journal failed: " + journalErr.Error()
			}
		}
		m.placementMu.Lock()
		reservation.backendAdapter = adapter
		reservation.backendTarget = target
		reservation.backendHandle = handle
		reservation.backendStopPending = handle != nil || adapter != nil
		reservation.backendStopConfirmed = handle == nil && adapter == nil
		reservation.backendStopInFlight = false
		reservation.releaseRequested = true
		reservation.backendCleanupMessage = message
		reservation.backendCleanupTerminal = disposition
		m.placementMu.Unlock()
	}
	if id == "" || message == "" {
		return journalErr
	}
	if current, err := m.store.GetWorkload(context.WithoutCancel(ctx), id); err == nil && !isTerminalWorkloadStatus(current.Status) {
		if _, updateErr := m.mutateWorkloadCAS(context.WithoutCancel(ctx), id, workloadStatuses(current.Status), current.CancellationOwner, func(candidate *domain.Workload) error {
			candidate.Error = message
			candidate.UpdatedAt = time.Now().UTC()
			return nil
		}); updateErr != nil {
			m.log.Warn("backend cleanup diagnostic persistence failed; placement remains fenced", "workload_id", id, "error", updateErr)
		}
	}
	m.audit(context.WithoutCancel(ctx), "", id, "workload.backend_cleanup_pending", "error", map[string]string{"error": message})
	return journalErr
}

func (m *Manager) recordLeaseCleanupIntent(ctx context.Context, lease *domain.AcceleratorLease, owner string, releaseErr error, attempts int) error {
	if lease == nil {
		return nil
	}
	if attempts <= 0 {
		attempts = 1
	}
	now := time.Now().UTC()
	next := now.Add(time.Second)
	_, err := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: lease.AcceleratorID, Owner: owner, FencingToken: lease.FencingToken, Attempts: attempts, LastError: releaseErr.Error(), CreatedAt: now, UpdatedAt: now, NextRetryAt: &next})
	return err
}

func scheduleLeaseCleanupRetry(intent *domain.AcceleratorLeaseCleanupIntent, failure error) {
	if intent == nil {
		return
	}
	if intent.Attempts < 1 {
		intent.Attempts = 1
	}
	intent.Attempts++
	if failure != nil {
		intent.LastError = failure.Error()
	}
	if len(intent.LastError) > 512 {
		intent.LastError = intent.LastError[:512]
	}
	now := time.Now().UTC()
	intent.UpdatedAt = now
	delay := time.Second * time.Duration(1<<min(intent.Attempts-1, 5))
	if delay > time.Minute {
		delay = time.Minute
	}
	next := now.Add(delay)
	intent.NextRetryAt = &next
}

type workloadLeaseCleanupIntentDeleter interface {
	DeleteAcceleratorLeaseCleanupIntentForWorkload(context.Context, string, string, int64, string) error
}

func (m *Manager) deleteLeaseCleanupIntent(ctx context.Context, intent *domain.AcceleratorLeaseCleanupIntent) error {
	if intent == nil {
		return nil
	}
	if intent.WorkloadID != "" {
		if deleter, ok := m.store.(workloadLeaseCleanupIntentDeleter); ok {
			return deleter.DeleteAcceleratorLeaseCleanupIntentForWorkload(ctx, intent.AcceleratorID, intent.Owner, intent.FencingToken, intent.WorkloadID)
		}
	}
	return m.store.DeleteAcceleratorLeaseCleanupIntent(ctx, intent.AcceleratorID, intent.Owner, intent.FencingToken)
}

func (m *Manager) finalizeTerminalLeaseIntent(ctx context.Context, intent *domain.AcceleratorLeaseCleanupIntent) error {
	if intent == nil || intent.TerminalDisposition == "" {
		return nil
	}
	workload, err := m.store.GetWorkload(ctx, intent.WorkloadID)
	if err != nil {
		return err
	}
	if !intent.ReleaseConfirmed {
		return errors.New("terminal continuation release is not confirmed")
	}
	terminalStatus := map[string]domain.WorkloadStatus{"success": domain.WorkloadSucceeded, "failure": domain.WorkloadFailed, "cancel": domain.WorkloadCancelled}[intent.TerminalDisposition]
	if terminalStatus == "" {
		return fmt.Errorf("unknown terminal lease disposition %q", intent.TerminalDisposition)
	}
	if !intent.TerminalPublished {
		if isTerminalWorkloadStatus(workload.Status) {
			if workload.Status != terminalStatus {
				return fmt.Errorf("%w: terminal continuation disposition mismatch", store.ErrWorkloadConflict)
			}
		} else {
			if intent.ExpectedWorkloadRevision == 0 || workload.Revision != intent.ExpectedWorkloadRevision {
				return fmt.Errorf("%w: terminal continuation revision drift expected=%d actual=%d", store.ErrWorkloadConflict, intent.ExpectedWorkloadRevision, workload.Revision)
			}
			now := time.Now().UTC()
			expectedOwner := workload.CancellationOwner
			workload.Status = terminalStatus
			workload.UpdatedAt = now
			workload.FinishedAt = &now
			if intent.TerminalDisposition == "cancel" {
				workload.CancellationOwner = ""
			}
			if _, err := m.replaceWorkloadCAS(ctx, workload, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadRunning, domain.WorkloadPendingApproval), expectedOwner); err != nil {
				return err
			}
		}
		intent.TerminalPublished = true
		if _, err := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, intent); err != nil {
			return err
		}
		workload, err = m.store.GetWorkload(ctx, intent.WorkloadID)
		if err != nil {
			return err
		}
	}
	eventType, severity := "workload.succeeded", "info"
	if intent.TerminalDisposition == "failure" {
		eventType, severity = "workload.failed", "error"
	}
	if intent.TerminalDisposition == "cancel" {
		eventType, severity = "workload.cancelled", "warn"
	}
	if !intent.AuditPublished {
		payload, _ := json.Marshal(map[string]string{"error_code": intent.TerminalErrorCode})
		event := &domain.AuditEvent{ID: "lease-terminal-audit-" + intent.WorkloadID + "-" + fmt.Sprint(intent.FencingToken), Timestamp: time.Now().UTC(), OwnerID: workload.Request.OwnerID, WorkloadID: workload.Request.ID, Type: eventType, Severity: severity, Payload: payload}
		if err := m.store.AppendAuditEvent(ctx, event); err != nil {
			return err
		}
		intent.AuditPublished = true
		if _, err := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, intent); err != nil {
			return err
		}
	}
	if !intent.NotificationPublished {
		if workload.Request.Notifications.OnFinish {
			if err := m.enqueueNotification(ctx, workload, eventType); err != nil {
				return err
			}
		}
		intent.NotificationPublished = true
		if _, err := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, intent); err != nil {
			return err
		}
	}
	if !intent.BudgetSettled {
		m.settleWorkloadBudget(ctx, workload)
		latest, err := m.store.GetWorkload(ctx, intent.WorkloadID)
		if err != nil {
			return err
		}
		if latest.BudgetSettlementPending {
			return errors.New("budget settlement remains pending")
		}
		intent.BudgetSettled = true
		if _, err := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, intent); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) releaseBeforeTerminal(ctx context.Context, workload *domain.Workload, reservation *targetReservation, disposition, message string) error {
	if reservation == nil {
		return nil
	}
	typedIntent, err := m.prepareTerminalLeaseIntent(ctx, workload, reservation, disposition, message)
	if err != nil {
		return err
	}
	releaseErr := m.releaseTargetWithIntent(ctx, reservation, typedIntent)
	if releaseErr != nil {
		return releaseErr
	}
	typedIntent.ReleaseConfirmed = true
	stored, phaseErr := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, typedIntent)
	if phaseErr != nil {
		scheduleLeaseCleanupRetry(typedIntent, phaseErr)
		recordCtx, recordCancel := leaseCleanupContext(ctx)
		_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, typedIntent)
		recordCancel()
		return phaseErr
	}
	if err := m.finalizeTerminalLeaseIntent(ctx, stored); err != nil {
		scheduleLeaseCleanupRetry(stored, err)
		recordCtx, recordCancel := leaseCleanupContext(ctx)
		_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, stored)
		recordCancel()
		return err
	}
	deleteCtx, deleteCancel := leaseCleanupContext(ctx)
	_ = m.deleteLeaseCleanupIntent(deleteCtx, typedIntent)
	deleteCancel()
	return nil
}

func (m *Manager) prepareTerminalLeaseIntent(ctx context.Context, workload *domain.Workload, reservation *targetReservation, disposition, message string) (*domain.AcceleratorLeaseCleanupIntent, error) {
	prepared, err := m.prepareTerminalWorkload(ctx, workload, disposition, message)
	if err != nil {
		return nil, err
	}
	recordCtx, cancel := leaseCleanupContext(ctx)
	now := time.Now().UTC()
	typedIntent := &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: reservation.lease.AcceleratorID, Owner: reservation.lease.WorkloadID, FencingToken: reservation.lease.FencingToken, WorkloadID: prepared.Request.ID, ExpectedWorkloadRevision: prepared.Revision, TerminalDisposition: disposition, TerminalErrorCode: "terminal_" + disposition, Attempts: 1, LastError: "terminal_" + disposition, CreatedAt: now, UpdatedAt: now, NextRetryAt: func() *time.Time { next := now.Add(time.Second); return &next }()}
	m.placementMu.Lock()
	reservation.cleanupIntent = typedIntent
	m.placementMu.Unlock()
	stored, recordErr := m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, typedIntent)
	cancel()
	if recordErr != nil {
		return nil, recordErr
	}
	if stored != nil {
		typedIntent = stored
	}
	m.placementMu.Lock()
	reservation.cleanupIntent = typedIntent
	m.placementMu.Unlock()
	return typedIntent, nil
}

func (m *Manager) prepareTerminalWorkload(ctx context.Context, workload *domain.Workload, disposition, message string) (*domain.Workload, error) {
	if workload == nil {
		return nil, errors.New("terminal continuation requires workload")
	}
	current, err := m.store.GetWorkload(ctx, workload.Request.ID)
	if err != nil {
		return nil, err
	}
	if isTerminalWorkloadStatus(current.Status) {
		return current, nil
	}
	snapshot := *workload
	snapshot.Status = current.Status
	snapshot.Revision = current.Revision
	snapshot.CancellationOwner = current.CancellationOwner
	if disposition == "failure" || disposition == "cancel" {
		snapshot.Error = message
	}
	snapshot.UpdatedAt = time.Now().UTC()
	return m.replaceWorkloadCAS(ctx, &snapshot, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadRunning, domain.WorkloadPendingApproval), current.CancellationOwner)
}

func (m *Manager) retryAcceleratorLeaseCleanupIntents(ctx context.Context) {
	listCtx, cancel := leaseCleanupContext(ctx)
	intents, err := m.store.ListAcceleratorLeaseCleanupIntents(listCtx, time.Now().UTC(), 100)
	cancel()
	if err != nil {
		m.log.Warn("accelerator lease cleanup intent scan failed", "error", err)
		return
	}
	for _, intent := range intents {
		if intent == nil {
			continue
		}
		lease := &domain.AcceleratorLease{AcceleratorID: intent.AcceleratorID, WorkloadID: intent.Owner, FencingToken: intent.FencingToken}
		var releaseErr error
		if intent.TerminalDisposition != "" {
			releaseErr = m.rollbackAcceleratorLeaseWithIntent(ctx, lease, intent.Owner, true, intent)
		} else {
			// Generic retries must advance and carry the exact existing row.  A
			// nil-intent call would create a fresh attempt-1 row on failure and
			// can race/overwrite the durable retry state.
			retryIntent := *intent
			scheduleLeaseCleanupRetry(&retryIntent, nil)
			releaseErr = m.rollbackAcceleratorLeaseWithPreparedIntent(ctx, lease, intent.Owner, false, &retryIntent)
		}
		if releaseErr != nil {
			// A durable intent means the exact release is still outstanding;
			// terminal continuation must wait for a later successful/confirmed
			// release rather than publishing while the lease may remain live.
			if errors.Is(releaseErr, errLeaseCleanupRecorded) {
				continue
			}
			recordCtx, recordCancel := leaseCleanupContext(ctx)
			if intent.TerminalDisposition != "" {
				scheduleLeaseCleanupRetry(intent, releaseErr)
				_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, intent)
			} else {
				// The prepared generic rollback already owns the incremented
				// immutable row; preserve it if persistence needs a retry here.
				retryIntent := *intent
				scheduleLeaseCleanupRetry(&retryIntent, releaseErr)
				_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, &retryIntent)
			}
			recordCancel()
			continue
		}
		if intent.TerminalDisposition == "" {
			m.mu.RLock()
			pendingReservation := m.reservations[intent.Owner]
			m.mu.RUnlock()
			if pendingReservation != nil {
				m.finishReleasedReservation(pendingReservation)
			}
		}
		if intent.TerminalDisposition != "" {
			intent.ReleaseConfirmed = true
			m.mu.RLock()
			pendingReservation := m.reservations[intent.WorkloadID]
			m.mu.RUnlock()
			if pendingReservation != nil {
				m.finishReleasedReservation(pendingReservation)
			}
			if _, phaseErr := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, intent); phaseErr != nil {
				scheduleLeaseCleanupRetry(intent, phaseErr)
				recordCtx, recordCancel := leaseCleanupContext(ctx)
				_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, intent)
				recordCancel()
				continue
			}
			finalizeCtx, finalizeCancel := leaseCleanupContext(ctx)
			finalizeErr := m.finalizeTerminalLeaseIntent(finalizeCtx, intent)
			finalizeCancel()
			if finalizeErr == nil {
				deleteCtx, deleteCancel := leaseCleanupContext(ctx)
				_ = m.deleteLeaseCleanupIntent(deleteCtx, intent)
				deleteCancel()
			} else {
				recordCtx, recordCancel := leaseCleanupContext(ctx)
				scheduleLeaseCleanupRetry(intent, finalizeErr)
				_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, intent)
				recordCancel()
			}
		} else {
			// The physical release may have become durable before the
			// terminal continuation itself could be recorded. Resume that
			// in-memory continuation at the same exact-owner fence.
			m.mu.Lock()
			pending, pendingOK := m.pendingLeaseFinalizations[intent.Owner]
			if pendingOK {
				delete(m.pendingLeaseFinalizations, intent.Owner)
			}
			m.mu.Unlock()
			if pendingOK && pending.workload != nil {
				if finalizeErr := m.finalizeTerminalLeaseIntent(ctx, &domain.AcceleratorLeaseCleanupIntent{WorkloadID: pending.workload.Request.ID, ExpectedWorkloadRevision: pending.workload.Revision, Owner: intent.Owner, TerminalDisposition: pending.disposition, TerminalErrorCode: "terminal_" + pending.disposition, ReleaseConfirmed: true}); finalizeErr != nil {
					m.mu.Lock()
					m.pendingLeaseFinalizations[intent.Owner] = pending
					m.mu.Unlock()
				}
			}
		}
	}
}

func (m *Manager) nodeControlForTarget(ctx context.Context, target Target) (NodeControl, string, bool) {
	m.mu.RLock()
	control := m.nodeControl
	m.mu.RUnlock()
	if control == nil || m.nodes == nil || target.AcceleratorID == "" || target.Cloud {
		return nil, "", false
	}
	nodes, err := m.nodes.ListNodes(ctx)
	if err != nil {
		return nil, "", false
	}
	for _, node := range nodes {
		for _, accelerator := range node.Accelerators {
			if accelerator.ID == target.AcceleratorID {
				return control, node.ID, true
			}
		}
	}
	return nil, "", false
}

func (m *Manager) RegisterTarget(target Target) {
	if err := validateCapacityByteFields(target); err != nil {
		m.log.Warn("rejecting target with invalid byte envelope", "target", target.ID, "error", err)
		return
	}
	if err := validateTargetMiBFields(target); err != nil {
		m.log.Warn("rejecting target with invalid MiB envelope", "target", target.ID, "error", err)
		return
	}
	// Profile persistence is a durable store operation and must not run under
	// the admission/target/state locks. Capture the generation first; after the
	// store round trip the short commit below discards a stale profile result if
	// a newer registration won the race.
	m.mu.RLock()
	registrationSnapshotGeneration := m.targetGenerations[target.ID]
	registrationNodeEpoch := m.runtimeProfileNodeEpochs[target.NodeID]
	registrationCardEpoch := m.runtimeProfileCardEpochs[target.AcceleratorID]
	m.mu.RUnlock()
	if target.Slots <= 0 {
		target.Slots = 1
	}
	registrationQuarantineReason := m.runtimeProfileQuarantineReason(context.Background(), target.NodeID, target)
	if registrationQuarantineReason != "" {
		target.ContextLimit = 0
		target.Slots = 0
		target.ActiveRuntimeProfile = ""
		target.CapacityVerified = false
		target.CapacitySource = "runtime-profile:observation_unavailable"
		m.log.Warn("withholding node capacity while a runtime profile outcome is unresolved", "node_id", target.NodeID, "target", target.ID, "reason", registrationQuarantineReason)
	}
	// A workload is confined to one accelerator unless a runtime explicitly
	// advertises a higher ceiling. Keep the legacy zero value compatible while
	// making the effective policy explicit to every placement caller.
	if ceiling, err := domain.NormalizeAcceleratorCeiling(target.MaxAcceleratorsPerWorkload, target.Capabilities.MaxAcceleratorsPerWorkload); err == nil {
		target.MaxAcceleratorsPerWorkload = ceiling
		target.Capabilities.MaxAcceleratorsPerWorkload = ceiling
	} else {
		m.log.Warn("invalid accelerator placement ceiling; using one", "target", target.ID, "error", err)
		target.MaxAcceleratorsPerWorkload = 1
		target.Capabilities.MaxAcceleratorsPerWorkload = 1
	}
	if target.ResidencyPolicy == "" {
		target.ResidencyPolicy = domain.ResidencyAuto
	} else if target.ResidencyPolicy != domain.ResidencyAuto && target.ResidencyPolicy != domain.ResidencyPinned && target.ResidencyPolicy != domain.ResidencyManual && target.ResidencyPolicy != domain.ResidencyOff {
		m.log.Warn("invalid target residency policy; protecting target as manual", "target", target.ID, "policy", target.ResidencyPolicy)
		target.ResidencyPolicy = domain.ResidencyManual
	}
	m.mu.RLock()
	_, adapterRegistered := m.adapters[target.Adapter]
	m.mu.RUnlock()
	target.Profiles = m.registerTargetProfiles(target, adapterRegistered)
	// External ComfyUI advertises the model files it can load, not the models
	// currently occupying VRAM. Treating that catalog as resident makes an
	// idle accelerator look full and defeats honest unload/offload telemetry.
	if len(target.ResidentModels) == 0 && !target.SupportsModelLifecycle && !strings.EqualFold(target.Adapter, "comfy") {
		target.ResidentModels = append([]string(nil), target.Models...)
	}
	// Target generations are controller-memory state, while residency rows
	// survive a restart. Recover the highest generation belonging to this exact
	// execution fingerprint before publishing the fresh advertisement; otherwise
	// an exact replay would look like an older transition and be rejected by the
	// durable CAS. The read is deliberately outside every manager lock.
	durableGeneration := uint64(0)
	durableGenerationAny := uint64(0)
	registrationFingerprint := targetExecutionFingerprint(target)
	if rows, err := m.store.ListModelResidencies(context.Background()); err == nil {
		for _, row := range rows {
			if row == nil || row.TargetID != target.ID {
				continue
			}
			if row.TargetGeneration > durableGenerationAny {
				durableGenerationAny = row.TargetGeneration
			}
			if row.ExecutionFingerprint == registrationFingerprint && row.TargetGeneration > durableGeneration {
				durableGeneration = row.TargetGeneration
			}
		}
	}
	if rows, err := m.store.ListResidencyTransitions(context.Background(), -1); err == nil {
		for _, row := range rows {
			if row == nil || row.TargetID != target.ID {
				continue
			}
			if row.TargetGeneration > durableGenerationAny {
				durableGenerationAny = row.TargetGeneration
			}
			if row.ExecutionFingerprint == registrationFingerprint && row.TargetGeneration > durableGeneration {
				durableGeneration = row.TargetGeneration
			}
		}
	}
	// Capability advertisements intentionally contain runtime facts, not the
	// controller's learned envelopes. Preserve the latter across the periodic
	// node refresh or every refresh would erase the evidence required for safe
	// sharing. Live accelerator capacity may also arrive slightly before or
	// after runtime discovery, so retain the last measured value when the new
	// advertisement has not populated it yet.
	// Serialize replacement of the target facts with any in-flight observation
	// commit. The observation path rechecks this snapshot while holding the
	// same per-target lock, so an older registration either commits before the
	// replacement or is rejected without a stale write.
	releaseProfileTicket := m.lockRuntimeProfileTransitionForTarget(target.ID)
	m.residencyAdmissionMu.Lock()
	admissionLock := m.residencyAdmissionLock(target.ID)
	admissionLock.Lock()
	observationLock := m.residencyObservationLock(target.ID)
	observationLock.Lock()
	m.mu.Lock()
	if m.targetGenerations[target.ID] != registrationSnapshotGeneration {
		m.mu.Unlock()
		observationLock.Unlock()
		admissionLock.Unlock()
		m.residencyAdmissionMu.Unlock()
		releaseProfileTicket()
		m.log.Info("discarding stale target registration after profile persistence", "target", target.ID)
		return
	}
	if m.runtimeProfileNodeEpochs[target.NodeID] != registrationNodeEpoch || m.runtimeProfileCardEpochs[target.AcceleratorID] != registrationCardEpoch {
		m.mu.Unlock()
		observationLock.Unlock()
		admissionLock.Unlock()
		m.residencyAdmissionMu.Unlock()
		releaseProfileTicket()
		m.log.Info("discarding target registration after a newer runtime profile transition", "target", target.ID)
		return
	}
	if pendingKey := m.runtimeProfileTransitionTarget[target.ID]; pendingKey != "" {
		if pending := m.runtimeProfileTransitions[pendingKey]; pending != nil {
			if !pending.projected {
				m.mu.Unlock()
				observationLock.Unlock()
				admissionLock.Unlock()
				m.residencyAdmissionMu.Unlock()
				releaseProfileTicket()
				m.log.Info("discarding target refresh during runtime profile transition", "target", target.ID)
				return
			}
			if target.ActiveRuntimeProfile != pending.profile.ID || target.ContextLimit != pending.profile.ContextLimit || target.Slots != pending.profile.Slots || !target.CapacityVerified || target.CapacitySource != "runtime:/slots" {
				m.mu.Unlock()
				observationLock.Unlock()
				admissionLock.Unlock()
				m.residencyAdmissionMu.Unlock()
				releaseProfileTicket()
				m.log.Info("discarding stale target refresh after runtime profile projection", "target", target.ID)
				return
			}
		}
	}
	prospectiveTargetBlocker := m.runtimeProfileBlockedTargets[target.ID]
	prospectiveNodeBlocker := m.runtimeProfileBlockedNodes[target.NodeID]
	prospectiveCardBlocker := m.runtimeProfileBlockedCards[target.AcceleratorID]
	if registrationQuarantineReason != "" {
		prospectiveTargetBlocker = registrationQuarantineReason
		if (strings.Contains(registrationQuarantineReason, "ambiguous durable ordering for card") || strings.Contains(registrationQuarantineReason, "delivery attempts on card")) && target.AcceleratorID != "" {
			prospectiveCardBlocker = registrationQuarantineReason
		} else if strings.Contains(registrationQuarantineReason, "requires reconciliation") && target.NodeID != "" {
			prospectiveNodeBlocker = registrationQuarantineReason
		}
	} else {
		prospectiveTargetBlocker = ""
		if target.NodeID != "" && !m.runtimeProfileHasPendingLocked(target.NodeID, "") {
			prospectiveNodeBlocker = ""
		}
		if target.AcceleratorID != "" && !m.runtimeProfileHasPendingLocked("", target.AcceleratorID) {
			prospectiveCardBlocker = ""
		}
	}
	registrationBlocked := prospectiveTargetBlocker != "" || prospectiveNodeBlocker != "" || prospectiveCardBlocker != ""
	if registrationBlocked {
		target.ContextLimit = 0
		target.Slots = 0
		target.ActiveRuntimeProfile = ""
		target.CapacityVerified = false
		target.CapacitySource = "runtime-profile:observation_unavailable"
	}
	if existing, found := m.targets[target.ID]; found {
		sameCapability := existing.CapabilityVersion == target.CapabilityVersion
		activeReservation := false
		for _, reservation := range m.reservations {
			if reservation != nil && !reservation.released && reservation.targetID == target.ID {
				activeReservation = true
				break
			}
		}
		// A node refresh can race an admission-owned load/reclaim command and
		// carry an empty resident list from the pre-transition observation. Keep
		// the in-flight projection until that fenced command publishes its own
		// authoritative result; an unrelated refresh must not invalidate the
		// runnable snapshot or erase a model mid-transition.
		if sameCapability && len(target.ResidentModels) == 0 && (m.residencyTransitionInFlight(existing.AcceleratorID) || activeReservation) {
			target.ResidentModels = append([]string(nil), existing.ResidentModels...)
		}
		if target.AcceleratorVRAMMB <= 0 {
			target.AcceleratorVRAMMB = existing.AcceleratorVRAMMB
		}
		if target.StandaloneVRAMMB <= 0 && sameCapability {
			target.StandaloneVRAMMB = existing.StandaloneVRAMMB
			target.StandaloneVRAMSource = existing.StandaloneVRAMSource
			target.StandaloneVRAMVerified = existing.StandaloneVRAMVerified
		}
		if target.WorkloadClass == "" {
			target.WorkloadClass = existing.WorkloadClass
		}
		if target.PredictedSlowdown <= 0 && sameCapability {
			target.PredictedSlowdown = existing.PredictedSlowdown
		}
	}
	previous, found := m.targets[target.ID]
	publishGeneration := m.targetGenerations[target.ID]
	if !found {
		if durableGeneration > 0 {
			// The exact durable fingerprint is still current: seed one below the
			// persisted fence because replaceTargetLocked increments on publish.
			// Preserve a higher in-process retirement fence rather than moving it
			// backward when this ID is re-advertised.
			if durableGeneration-1 > publishGeneration {
				publishGeneration = durableGeneration - 1
			}
		} else if durableGenerationAny > 0 {
			// A changed advertisement must advance beyond every durable row. This
			// prevents a restarted controller from reusing the old generation with
			// a different execution fingerprint; replaceTargetLocked increments on
			// publish, so seed at the durable maximum itself.
			if durableGenerationAny > publishGeneration {
				publishGeneration = durableGenerationAny
			}
		}
	}
	if (!found || targetExecutionFingerprint(previous) != targetExecutionFingerprint(target)) && publishGeneration == ^uint64(0) {
		invalidated := false
		if found {
			m.invalidateTargetAtExhaustedGenerationLocked(target.ID, previous)
			invalidated = true
		}
		m.mu.Unlock()
		observationLock.Unlock()
		admissionLock.Unlock()
		m.residencyAdmissionMu.Unlock()
		releaseProfileTicket()
		m.log.Error("rejecting target registration because its execution generation is exhausted", "target", target.ID)
		if invalidated {
			m.signal()
		}
		return
	}
	if !found && m.retiredTargets[target.ID].ID != "" && m.targetGenerations[target.ID] == ^uint64(0) {
		m.mu.Unlock()
		observationLock.Unlock()
		admissionLock.Unlock()
		m.residencyAdmissionMu.Unlock()
		releaseProfileTicket()
		m.log.Error("rejecting target resurrection because its exhausted generation is retired", "target", target.ID)
		return
	}
	if !found {
		m.targetGenerations[target.ID] = publishGeneration
	}
	// A refresh which preserves execution-sensitive route/runtime/capacity facts
	// is not a target-fact change. It must be allowed to complete while a
	// backend command is in flight; otherwise an ordinary node heartbeat would
	// make a valid reservation fail at the final execution fence. Changes to
	// those facts advance the generation and fence the in-flight operation.
	if err := m.replaceTargetLocked(target); err != nil {
		m.mu.Unlock()
		observationLock.Unlock()
		admissionLock.Unlock()
		m.residencyAdmissionMu.Unlock()
		releaseProfileTicket()
		m.log.Error("rejecting target registration after generation fence failure", "target", target.ID, "error", err)
		return
	}
	if prospectiveTargetBlocker == "" {
		delete(m.runtimeProfileBlockedTargets, target.ID)
	} else {
		m.runtimeProfileBlockedTargets[target.ID] = prospectiveTargetBlocker
	}
	if target.NodeID != "" {
		if prospectiveNodeBlocker == "" {
			delete(m.runtimeProfileBlockedNodes, target.NodeID)
		} else {
			m.runtimeProfileBlockedNodes[target.NodeID] = prospectiveNodeBlocker
		}
	}
	if target.AcceleratorID != "" {
		if prospectiveCardBlocker == "" {
			delete(m.runtimeProfileBlockedCards, target.AcceleratorID)
		} else {
			m.runtimeProfileBlockedCards[target.AcceleratorID] = prospectiveCardBlocker
		}
	}
	delete(m.retiredTargets, target.ID)
	if proofAdapter, ok := m.adapters[target.Adapter].(*HTTPAdapter); ok {
		proofAdapter.SetTargetCheckpointProof(target.ID, target.CheckpointProof)
	}
	m.pendingObservationGeneration++
	observationGeneration := m.pendingObservationGeneration
	m.mu.Unlock()
	observationLock.Unlock()
	admissionLock.Unlock()
	m.residencyAdmissionMu.Unlock()
	releaseProfileTicket()
	// A persisted learned envelope is authoritative over an empty or smaller
	// advertisement even after a controller or node restart.
	m.learningMu.RLock()
	profile := m.interferenceProfiles[standaloneProfileKey(target)]
	m.learningMu.RUnlock()
	if !target.StandaloneVRAMVerified && profile != nil && profile.Confidence >= .5 && profile.P95VRAMMB > target.StandaloneVRAMMB {
		releaseLearnedProfileTicket := m.lockRuntimeProfileTransitionForTarget(target.ID)
		m.residencyAdmissionMu.Lock()
		admissionLock := m.residencyAdmissionLock(target.ID)
		admissionLock.Lock()
		m.mu.Lock()
		current := m.targets[target.ID]
		pendingKey := m.runtimeProfileTransitionTarget[target.ID]
		pending := pendingKey != "" && m.runtimeProfileTransitions[pendingKey] != nil && !m.runtimeProfileTransitions[pendingKey].projected
		var generationErr error
		if !pending && targetExecutionGenerationEqual(target, current) && profile.P95VRAMMB > current.StandaloneVRAMMB {
			current.StandaloneVRAMMB = profile.P95VRAMMB
			generationErr = m.replaceTargetLocked(current)
		}
		m.mu.Unlock()
		admissionLock.Unlock()
		m.residencyAdmissionMu.Unlock()
		releaseLearnedProfileTicket()
		if generationErr != nil {
			m.log.Error("skipping learned capacity update because target generation is exhausted", "target", target.ID, "error", generationErr)
		}
	}
	// Node-discovered targets arrive after Manager.Start, so apply their
	// durable override at registration time as well as during startup recovery.
	// Before Start there is no lifecycle context; startup performs the same
	// operation for configured targets without inventing a Background call.
	m.lifecycleMu.Lock()
	recoveryCtx := m.recoveryCtx
	m.lifecycleMu.Unlock()
	registrationCtx := recoveryCtx
	if registrationCtx == nil {
		// A target may be configured before Start. TODO is deliberately local
		// to this synchronous registration compatibility path; all running
		// recovery work uses the manager-owned lifecycle context.
		registrationCtx = context.TODO()
	}
	if registrationCtx != nil {
		// Establish the durable resource row synchronously for a newly
		// discovered target; transition recovery itself remains owned by the
		// retrying recovery loop below.
		if !m.observeTargetResidencyLocked(registrationCtx, target) {
			m.mu.Lock()
			current, exists := m.pendingResidencyObservations[target.ID]
			if !exists || current.generation <= observationGeneration {
				m.pendingResidencyObservations[target.ID] = pendingResidencyObservation{target: target, generation: observationGeneration}
			}
			m.mu.Unlock()
		} else {
			m.mu.Lock()
			if current, exists := m.pendingResidencyObservations[target.ID]; exists && current.generation <= observationGeneration {
				delete(m.pendingResidencyObservations, target.ID)
			}
			m.mu.Unlock()
		}
		if policies, err := m.store.ListTargetPolicyOverrides(registrationCtx); err == nil {
			for _, policy := range policies {
				if policy.TargetID == target.ID {
					if _, applyErr := m.UpdateTargetPolicy(*policy); applyErr != nil {
						m.log.Warn("ignoring invalid stored target policy", "target", policy.TargetID, "error", applyErr)
					}
					break
				}
			}
		}
	}
	// Registration only schedules durable recovery. The recovery loop owns the
	// reconciler lock and retries store failures instead of dropping a one-shot
	// TryLock attempt during reconnect.
	if recoveryCtx != nil {
		select {
		case m.recoveryWake <- struct{}{}:
		default:
		}
	}
	m.signal()
}

// targetExecutionFingerprint is the one canonical equality boundary for
// dispatch, eligibility, policy, capacity, runtime/profile, model catalog,
// endpoint, provider, pricing, auth, queue, and custom-node facts. Only the
// controller's transient Active/circuit telemetry is excluded. Authorization
// is included in the hash but never emitted/logged.
// lifecycleRouteFingerprint identifies the physical route a lifecycle
// operation acted on. It deliberately omits facts the operation itself is
// expected to change (resident models, queue depth, capacity provenance) so
// a successful load/unload/reclaim does not invalidate its own result.
func lifecycleRouteFingerprint(target Target) string {
	models := append([]string(nil), target.Models...)
	sort.Strings(models)
	material, _ := json.Marshal(struct {
		ID, NodeID, Adapter, RuntimeProtocol, Endpoint, AcceleratorID, ModelFingerprint string
		Cloud, Enabled                                                               bool
		Models                                                                       []string
	}{target.ID, target.NodeID, target.Adapter, target.RuntimeProtocol, target.Endpoint, target.AcceleratorID, target.ModelFingerprint, target.Cloud, target.Enabled, models})
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:])
}

// lifecycleRouteStable reports whether the registered target is still the
// same physical route as the snapshot a lifecycle operation was issued for.
func (m *Manager) lifecycleRouteStable(expected Target) bool {
	current := m.targetByID(expected.ID)
	return current.ID != "" && lifecycleRouteFingerprint(current) == lifecycleRouteFingerprint(expected)
}

// refreshStableLifecycleTarget keeps a completed lifecycle operation bound to
// its route: when the advertisement changed only in facts the operation is
// expected to change, the snapshot and generation are refreshed in place.
func (m *Manager) refreshStableLifecycleTarget(target *Target, generation *uint64) bool {
	if m.targetFenceMatches(*target, *generation) {
		return true
	}
	if !m.lifecycleRouteStable(*target) {
		return false
	}
	*target = m.targetByID(target.ID)
	*generation = m.targetGeneration(target.ID)
	return true
}

func targetExecutionFingerprint(target Target) string {
	snapshot := target
	snapshot.Active = 0
	snapshot.CircuitState = ""
	snapshot.CircuitOpenUntil = nil
	snapshot.CircuitFailures = 0
	// ResidentModels participates in eligibility (a missing model requires a
	// lifecycle transition), so it is part of the execution fence just like
	// the advertised model catalog. Runtime active/circuit counters remain
	// ephemeral telemetry and are intentionally excluded above.
	snapshot.Models = append([]string(nil), target.Models...)
	snapshot.ResidentModels = append([]string(nil), target.ResidentModels...)
	snapshot.CustomNodes = append([]string(nil), target.CustomNodes...)
	snapshot.RuntimeArgs = append([]string(nil), target.RuntimeArgs...)
	snapshot.Profiles = append([]domain.RuntimeProfile(nil), target.Profiles...)
	snapshot.RuntimeProfiles = append([]RuntimeCapacityProfile(nil), target.RuntimeProfiles...)
	sort.Strings(snapshot.Models)
	sort.Strings(snapshot.ResidentModels)
	sort.Strings(snapshot.CustomNodes)
	sort.Slice(snapshot.Profiles, func(i, j int) bool {
		if snapshot.Profiles[i].ProfileID != snapshot.Profiles[j].ProfileID {
			return snapshot.Profiles[i].ProfileID < snapshot.Profiles[j].ProfileID
		}
		return snapshot.Profiles[i].Version < snapshot.Profiles[j].Version
	})
	sort.Slice(snapshot.RuntimeProfiles, func(i, j int) bool {
		return snapshot.RuntimeProfiles[i].ID < snapshot.RuntimeProfiles[j].ID
	})
	material, _ := json.Marshal(struct {
		Target                 Target `json:"target"`
		Authorization          string `json:"authorization"`
		StandaloneVRAMSource   string `json:"standalone_vram_source"`
		StandaloneVRAMVerified bool   `json:"standalone_vram_verified"`
		QueueRunning           int    `json:"queue_running"`
		QueuePending           int    `json:"queue_pending"`
		IdleUnloadAfter        int64  `json:"idle_unload_after_ns"`
		MinResidency           int64  `json:"min_residency_ns"`
	}{snapshot, target.Authorization, target.StandaloneVRAMSource, target.StandaloneVRAMVerified, target.QueueRunning, target.QueuePending, int64(target.IdleUnloadAfter), int64(target.MinResidency)})
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:])
}

func targetExecutionGenerationEqual(a, b Target) bool {
	return targetExecutionFingerprint(a) == targetExecutionFingerprint(b)
}

// targetExecutionFactsEqual compares the immutable dispatch/eligibility
// envelope while allowing an admission-owned residency transition to update
// ResidentModels. The full fingerprint still includes ResidentModels; this
// narrow helper is used only immediately after the transition whose mutation
// the admission path owns, before rebinding the reservation to the new fence.
func targetExecutionFactsEqual(a, b Target) bool {
	// Ignore the observations a model transition itself changes: residency,
	// queue depth and capacity provenance (configured fallback vs runtime
	// /slots flips when a router loads or unloads its only model).
	for _, t := range []*Target{&a, &b} {
		t.ResidentModels = nil
		t.QueueRunning, t.QueuePending = 0, 0
		t.CapacitySource, t.CapacityVerified = "", false
		t.StandaloneVRAMMB, t.StandaloneVRAMSource, t.StandaloneVRAMVerified = 0, "", false
	}
	return targetExecutionFingerprint(a) == targetExecutionFingerprint(b)
}

// snapshotAdmissionPlacement reads the active-placement side of the admission
// binding without holding manager or target locks. The caller later passes this
// exact snapshot to the guarded generation handoff after its owned load.
func (m *Manager) snapshotAdmissionPlacement(workloadID string) (activePlacement, bool) {
	if workloadID == "" {
		return activePlacement{}, false
	}
	m.placementMu.Lock()
	placement, found := m.activePlacements[workloadID]
	m.placementMu.Unlock()
	return placement, found
}

// handoffAdmissionOwnedPlacementGeneration rebinds only the live placement
// owned by this admission after the exact cold-to-hot model mutation it
// initiated. Manager and placement locks are deliberately acquired separately;
// no store, adapter, or other external operation runs in either critical
// section. Any failed post-check rolls back only this exact placement update.
func (m *Manager) handoffAdmissionOwnedPlacementGeneration(
	reservation *targetReservation,
	before, after Target,
	beforeGeneration, afterGeneration uint64,
	model string,
	ownerID, idempotencyKey string,
	transitionIDs []string,
	beforePlacement activePlacement,
) error {
	expectedAcceleratorID := before.AcceleratorID
	if expectedAcceleratorID == "" {
		expectedAcceleratorID = "virtual/" + before.ID
	}
	if reservation == nil || reservation.workloadID == "" || beforeGeneration == 0 ||
		before.ID == "" || before.ID != after.ID || beforePlacement.workloadID != reservation.workloadID ||
		beforePlacement.targetID != before.ID || beforePlacement.targetGeneration != beforeGeneration ||
		beforePlacement.acceleratorID != expectedAcceleratorID || beforePlacement.model != model ||
		beforePlacement.profileID != before.ActiveRuntimeProfile || beforePlacement.runtimeIdentity != residencyCapacityIdentity(before) ||
		ownerID == "" || model == "" || len(transitionIDs) == 0 {
		return fmt.Errorf("admission-owned placement handoff facts are incomplete or changed")
	}
	if m.store == nil {
		return fmt.Errorf("admission-owned placement handoff has no durable transition store")
	}
	// Accelerator leases and residency fences have different allocation
	// domains. Pin the live admission lease independently; transitionModel
	// proposes its fence to AllocateResidencyTransition, which may advance it
	// above that proposal using the target/model high-water mark.
	lease := reservation.lease
	if lease == nil || lease.AcceleratorID != expectedAcceleratorID || lease.WorkloadID == "" || lease.FencingToken <= 0 {
		return fmt.Errorf("admission-owned placement handoff has no live exact accelerator lease")
	}
	currentLease, leaseErr := m.store.GetAcceleratorLease(context.Background(), lease.AcceleratorID)
	if leaseErr != nil {
		return fmt.Errorf("read live admission accelerator lease: %w", leaseErr)
	}
	if currentLease == nil || currentLease.AcceleratorID != lease.AcceleratorID || currentLease.WorkloadID != lease.WorkloadID ||
		currentLease.FencingToken != lease.FencingToken || !currentLease.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("admission accelerator lease ownership, fence, or expiry changed")
	}
	// Read immutable receipts before acquiring any admission, target, manager,
	// or placement lock. Each row must extend the exact prior resident-set and
	// generation; caller facts alone cannot prove an admission-owned refresh.
	cursor := before
	cursorGeneration := beforeGeneration
	seenIDs := make(map[string]struct{}, len(transitionIDs))
	seenModels := make(map[string]struct{}, len(transitionIDs))
	loadedRequestedModel := false
	for _, transitionID := range transitionIDs {
		if loadedRequestedModel {
			return fmt.Errorf("admission-owned transition sequence continues after requested model load")
		}
		if transitionID == "" {
			return fmt.Errorf("admission-owned residency sequence contains an empty transition ID")
		}
		if _, duplicate := seenIDs[transitionID]; duplicate {
			return fmt.Errorf("admission-owned residency sequence repeats transition %s", transitionID)
		}
		seenIDs[transitionID] = struct{}{}
		transition, err := m.store.GetResidencyTransition(context.Background(), transitionID)
		if err != nil {
			return fmt.Errorf("read durable admission-owned transition %s: %w", transitionID, err)
		}
		if transition == nil {
			return fmt.Errorf("durable admission-owned transition %s is missing", transitionID)
		}
		if transition.ID != transitionID || transition.TargetID != cursor.ID || transition.AcceleratorID != cursor.AcceleratorID ||
			transition.WorkloadID != reservation.workloadID || transition.RequestedBy != ownerID || transition.TargetGeneration != cursorGeneration ||
			transition.ExecutionFingerprint != targetExecutionFingerprint(cursor) || transition.CapabilityVersion != cursor.CapabilityVersion ||
			transition.CapabilityRevision != cursor.CapabilityRevision || transition.FencingToken < lease.FencingToken ||
			!transition.LeaseOriginAllocated || transition.LeaseOriginAcceleratorID != lease.AcceleratorID ||
			transition.LeaseOriginWorkloadID != lease.WorkloadID || transition.LeaseOriginFencingToken != lease.FencingToken ||
			transition.Status != domain.ResidencyTransitionSucceeded || transition.Revision == 0 || transition.FinishedAt == nil || transition.ProjectionRepairPending {
			return fmt.Errorf("durable transition %s is not the exact successful admission-owned receipt", transitionID)
		}
		// Corroborate the immutable idempotency mapping and the allocator's
		// target/model high-water mark. The exact allocated row is authoritative;
		// a later allocation may raise the high-water mark, so equality is wrong.
		byKey, keyErr := m.store.GetResidencyTransitionByIdempotency(context.Background(), transition.IdempotencyKey)
		if keyErr != nil || byKey == nil || byKey.ID != transition.ID || byKey.FencingToken != transition.FencingToken {
			return fmt.Errorf("durable transition %s idempotency allocation binding is missing or changed", transitionID)
		}
		highwater, highwaterErr := m.store.MaxResidencyFencingToken(context.Background(), transition.TargetID, transition.Model)
		if highwaterErr != nil || highwater < transition.FencingToken {
			return fmt.Errorf("durable transition %s is outside its target/model allocation high-water mark", transitionID)
		}
		if cursorGeneration == ^uint64(0) {
			return fmt.Errorf("admission-owned target generation is exhausted")
		}
		switch {
		case transition.Reason == "capacity_for_demand runtime="+residencyCapacityIdentity(cursor) && transition.ToTier == domain.ResidencyColdDisk && transition.FromTier == domain.ResidencyHotVRAM && transition.Model != model:
			if _, duplicate := seenModels[transition.Model]; duplicate || transition.Model == "" || !hasExact(cursor.ResidentModels, transition.Model) {
				return fmt.Errorf("transition %s removes a nonresident or repeated victim", transitionID)
			}
			if transition.IdempotencyKey != "demand-evict:"+reservation.workloadID+":"+cursor.ID+":"+transition.Model {
				return fmt.Errorf("victim transition has an unexpected idempotency key")
			}
			if err := validateAuthoritativeTransitionEvidence(transition, cursor, transition.Model, domain.ResidencyColdDisk); err != nil {
				return fmt.Errorf("victim transition %s lacks authoritative evidence: %w", transitionID, err)
			}
			seenModels[transition.Model] = struct{}{}
			cursor.ResidentModels = withoutExact(cursor.ResidentModels, transition.Model)
		case transition.Reason == "workload_demand runtime="+residencyCapacityIdentity(cursor) && transition.ToTier == domain.ResidencyHotVRAM && transition.FromTier != domain.ResidencyHotVRAM && transition.Model == model && !loadedRequestedModel:
			if hasExact(cursor.ResidentModels, model) {
				return fmt.Errorf("requested model is already resident before its owned load")
			}
			wantKey := "demand-load:" + reservation.workloadID + ":" + cursor.ID + ":" + model
			if idempotencyKey != "" {
				wantKey = idempotencyKey
			}
			if transition.IdempotencyKey != wantKey {
				return fmt.Errorf("requested model transition has an unexpected idempotency key")
			}
			if err := validateAuthoritativeTransitionEvidence(transition, cursor, model, domain.ResidencyHotVRAM); err != nil {
				return fmt.Errorf("requested model transition lacks authoritative evidence: %w", err)
			}
			cursor.ResidentModels = append(cursor.ResidentModels, model)
			loadedRequestedModel = true
		default:
			return fmt.Errorf("transition %s is outside the permitted eviction/load sequence", transitionID)
		}
		cursorGeneration++
	}
	// The node re-advertises after a load (and a single-model router evicts
	// its previous model by itself), so the live target may have advanced by
	// more generations than the owned receipts, but never fewer, and must
	// now hold the requested model.
	if !loadedRequestedModel || cursorGeneration > afterGeneration || !targetExecutionFactsEqual(before, after) || !hasExact(after.ResidentModels, model) {
		return fmt.Errorf("admission-owned transition receipts do not reconstruct the current target")
	}
	// Receipt reads may span a store round trip. Reconfirm the lease after that
	// work and immediately before the in-memory ownership handoff; renewal may
	// change expiry timestamps, but not the exact accelerator/owner/fence tuple.
	currentLease, leaseErr = m.store.GetAcceleratorLease(context.Background(), lease.AcceleratorID)
	if leaseErr != nil || currentLease == nil || currentLease.AcceleratorID != lease.AcceleratorID || currentLease.WorkloadID != lease.WorkloadID ||
		currentLease.FencingToken != lease.FencingToken || !currentLease.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("admission accelerator lease changed before placement handoff")
	}
	updatedPlacement := beforePlacement
	updatedPlacement.targetGeneration = afterGeneration

	m.mu.RLock()
	current, targetFound := m.targets[after.ID]
	currentGeneration := m.targetGenerations[after.ID]
	liveReservation := m.reservations[reservation.workloadID] == reservation &&
		reservation.targetID == before.ID && reservation.workloadID == beforePlacement.workloadID &&
		reservation.targetGeneration == beforeGeneration
	m.mu.RUnlock()
	if !liveReservation || m.admissionReservationReleasing(reservation) || !targetFound || currentGeneration != afterGeneration || !targetExecutionFactsEqual(current, after) || !sameStringSet(current.ResidentModels, after.ResidentModels) {
		return fmt.Errorf("admission-owned placement handoff reservation or target fence changed")
	}

	m.placementMu.Lock()
	placement, found := m.activePlacements[reservation.workloadID]
	if !found || placement != beforePlacement {
		m.placementMu.Unlock()
		return fmt.Errorf("admission-owned active placement is missing or was replaced")
	}
	m.activePlacements[reservation.workloadID] = updatedPlacement
	m.placementMu.Unlock()

	// Close the only external-currentness gap after staging the placement map
	// update. This read stays outside locks; if the durable lease was replaced
	// or expired, roll back only the exact staged placement before reservation
	// generation changes. A store cannot atomically join this in-memory commit,
	// so the exact tuple is checked as near as possible to that commit boundary.
	currentLease, leaseErr = m.store.GetAcceleratorLease(context.Background(), lease.AcceleratorID)
	if leaseErr != nil || currentLease == nil || currentLease.AcceleratorID != lease.AcceleratorID || currentLease.WorkloadID != lease.WorkloadID ||
		currentLease.FencingToken != lease.FencingToken || !currentLease.ExpiresAt.After(time.Now()) {
		m.placementMu.Lock()
		if staged, stagedOwned := m.activePlacements[reservation.workloadID]; stagedOwned && staged == updatedPlacement {
			m.activePlacements[reservation.workloadID] = beforePlacement
		}
		m.placementMu.Unlock()
		return fmt.Errorf("admission accelerator lease changed while staging placement handoff")
	}

	liveReservation = !m.admissionReservationReleasing(reservation)
	m.mu.Lock()
	current, targetFound = m.targets[after.ID]
	currentGeneration = m.targetGenerations[after.ID]
	liveReservation = liveReservation && m.reservations[reservation.workloadID] == reservation &&
		reservation.targetID == before.ID && reservation.workloadID == beforePlacement.workloadID &&
		reservation.targetGeneration == beforeGeneration
	if liveReservation && targetFound && currentGeneration == afterGeneration && targetExecutionFactsEqual(current, after) && sameStringSet(current.ResidentModels, after.ResidentModels) {
		reservation.targetGeneration = afterGeneration
		m.mu.Unlock()
		m.placementMu.Lock()
		stillLive := !reservation.released && !reservation.releaseRequested && !reservation.releaseInFlight && m.activePlacements[reservation.workloadID] == updatedPlacement
		if stillLive {
			m.placementMu.Unlock()
			return nil
		}
		if currentPlacement, stillOwned := m.activePlacements[reservation.workloadID]; stillOwned && currentPlacement == updatedPlacement {
			m.activePlacements[reservation.workloadID] = beforePlacement
		}
		m.placementMu.Unlock()
		m.mu.Lock()
		if m.reservations[reservation.workloadID] == reservation && reservation.targetGeneration == afterGeneration {
			reservation.targetGeneration = beforeGeneration
		}
		m.mu.Unlock()
		return fmt.Errorf("admission-owned placement handoff reservation began release after rebinding")
	}
	m.mu.Unlock()

	m.placementMu.Lock()
	if currentPlacement, stillOwned := m.activePlacements[reservation.workloadID]; stillOwned && currentPlacement == updatedPlacement {
		m.activePlacements[reservation.workloadID] = beforePlacement
	}
	m.placementMu.Unlock()
	return fmt.Errorf("admission-owned placement handoff lost its reservation or target fence")
}

// Release-state fields share placementMu with active-placement updates. Sample
// them separately from the reservation map; these locks must never be nested.
func (m *Manager) admissionReservationReleasing(reservation *targetReservation) bool {
	if reservation == nil {
		return true
	}
	m.placementMu.Lock()
	releasing := reservation.released || reservation.releaseRequested || reservation.releaseInFlight
	m.placementMu.Unlock()
	return releasing
}

func withoutExact(models []string, removed string) []string {
	result := make([]string, 0, len(models))
	for _, model := range models {
		if model != removed {
			result = append(result, model)
		}
	}
	return result
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, item := range left {
		counts[item]++
	}
	for _, item := range right {
		counts[item]--
		if counts[item] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

// replaceTargetLocked is called only while the caller owns the manager-wide
// admission fence, the target fence, and m.mu. Every execution-sensitive
// mutation therefore advances one shared generation boundary.
func (m *Manager) replaceTargetLocked(target Target) error {
	previous, found := m.targets[target.ID]
	if !found || targetExecutionFingerprint(previous) != targetExecutionFingerprint(target) {
		if m.targetGenerations[target.ID] == ^uint64(0) {
			return fmt.Errorf("target %s execution generation is exhausted", target.ID)
		}
		m.targetGenerations[target.ID]++
	}
	m.targets[target.ID] = target
	return nil
}

// invalidateTargetAtExhaustedGenerationLocked retires a route when an
// authoritative fact changed but its monotonic generation cannot advance.
// Callers hold the manager admission fence, target fence, and m.mu. The
// exhausted high-water mark remains as a tombstone, so the stale route cannot
// be selected or re-registered under an unfenced generation.
func (m *Manager) invalidateTargetAtExhaustedGenerationLocked(targetID string, target Target) {
	if targetID == "" || m.targetGenerations[targetID] != ^uint64(0) {
		return
	}
	target.Enabled = false
	m.retiredTargets[targetID] = target
	delete(m.targets, targetID)
	m.runtimeProfileBlockedTargets[targetID] = "authoritative target facts changed but execution generation is exhausted"
	if target.NodeID != "" {
		m.runtimeProfileBlockedNodes[target.NodeID] = "authoritative target facts changed but execution generation is exhausted"
	}
	if target.AcceleratorID != "" {
		m.runtimeProfileBlockedCards[target.AcceleratorID] = "authoritative target facts changed but execution generation is exhausted"
	}
	delete(m.pendingResidencyObservations, targetID)
	m.pendingObservationGeneration++
}

// UpdateAcceleratorCapacity binds live physical inventory to every runtime
// route exposing that accelerator. Runtime discovery and telemetry are
// asynchronous, so this operation is safe to repeat on every telemetry tick.
func (m *Manager) UpdateAcceleratorCapacity(acceleratorID string, vramTotalMB int64) {
	if acceleratorID == "" || vramTotalMB <= 0 {
		return
	}
	if _, err := checkedMiBToBytes(vramTotalMB, "accelerator_vram_mb"); err != nil {
		return
	}
	m.mu.RLock()
	targetIDs := make([]string, 0)
	for id, target := range m.targets {
		if target.AcceleratorID != acceleratorID || target.AcceleratorVRAMMB == vramTotalMB {
			continue
		}
		targetIDs = append(targetIDs, id)
	}
	m.mu.RUnlock()
	sort.Strings(targetIDs)
	releases := make([]func(), 0, len(targetIDs))
	for _, id := range targetIDs {
		releases = append(releases, m.lockRuntimeProfileTransitionForTarget(id))
	}
	m.residencyAdmissionMu.Lock()
	changed := false
	generationFailures := make([]string, 0)
	for _, id := range targetIDs {
		fence := m.residencyAdmissionLock(id)
		fence.Lock()
		m.mu.Lock()
		var generationErr error
		target, found := m.targets[id]
		pendingKey := m.runtimeProfileTransitionTarget[id]
		pending := pendingKey != "" && m.runtimeProfileTransitions[pendingKey] != nil && !m.runtimeProfileTransitions[pendingKey].projected
		if found && !pending && target.AcceleratorID == acceleratorID && target.AcceleratorVRAMMB != vramTotalMB {
			previous := target
			target.AcceleratorVRAMMB = vramTotalMB
			generationErr = m.replaceTargetLocked(target)
			if generationErr == nil {
				changed = true
			} else if m.targetGenerations[id] == ^uint64(0) {
				m.invalidateTargetAtExhaustedGenerationLocked(id, previous)
				changed = true
			}
		}
		m.mu.Unlock()
		fence.Unlock()
		if generationErr != nil {
			generationFailures = append(generationFailures, id+": "+generationErr.Error())
		}
	}
	m.residencyAdmissionMu.Unlock()
	for index := len(releases) - 1; index >= 0; index-- {
		releases[index]()
	}
	for _, failure := range generationFailures {
		m.log.Error("skipping accelerator capacity update because target generation is exhausted", "target", failure)
	}
	if changed {
		// Node registration normally precedes the first telemetry frame. A
		// persisted sharing policy may therefore fail its physical-capacity
		// validation during registration; apply it again as soon as the live
		// accelerator envelope arrives.
		if err := m.ApplyStoredTargetPolicies(context.Background()); err != nil {
			m.log.Warn("target policy reapply after capacity update failed", "accelerator", acceleratorID, "error", err)
		}
		m.signal()
	}
}

// ReconcileNodeTargets removes runtime routes that an authoritative node no
// longer advertises. Target IDs from the node protocol are controller-
// namespaced, so this cannot remove static or another node's targets. Active
// reservations retain only their immutable retired cleanup metadata; selection
// and execution must never continue using an omitted route.
func normalizeRuntimeProfileTargetID(nodeID, targetID string) string {
	if targetID != "" && nodeID != "" && !strings.HasPrefix(targetID, nodeID+"-") {
		return nodeID + "-" + targetID
	}
	return targetID
}

func runtimeProfileCommandObservedCard(row *domain.NodeCommand) (routeID, acceleratorID, adapterID, endpoint string, known bool) {
	if row == nil || row.NodeID == "" {
		return "", "", "", "", false
	}
	routeID, _ = row.Args["target_id"].(string)
	routeID = normalizeRuntimeProfileTargetID(row.NodeID, routeID)
	if routeID == "" || len(row.Result) == 0 {
		return routeID, "", "", "", false
	}
	var result runtimeProfileResult
	if err := json.Unmarshal(row.Result, &result); err != nil {
		return routeID, "", "", "", false
	}
	var matched *runtimeProfileResultAdapter
	matches := 0
	for index := range result.Adapters {
		adapter := &result.Adapters[index]
		if normalizeRuntimeProfileTargetID(row.NodeID, adapter.ID) != routeID {
			continue
		}
		matches++
		matched = adapter
	}
	if matches != 1 || matched.Adapter == "" || matched.Endpoint == "" || matched.AcceleratorIndex == nil || *matched.AcceleratorIndex < 0 {
		return routeID, "", "", "", false
	}
	return routeID, fmt.Sprintf("%s-gpu%d", row.NodeID, *matched.AcceleratorIndex), matched.Adapter, matched.Endpoint, true
}

func runtimeProfileHistoryTargetSnapshot(m *Manager, candidate *Target) map[string]Target {
	m.mu.RLock()
	targets := make(map[string]Target, len(m.targets)+len(m.retiredTargets)+1)
	for id, target := range m.targets {
		targets[id] = target
	}
	for id, target := range m.retiredTargets {
		targets[id] = target
	}
	m.mu.RUnlock()
	if candidate != nil && candidate.ID != "" {
		targets[candidate.ID] = *candidate
	}
	return targets
}

// reduceRuntimeProfileHistory applies durable effects only to their canonical
// physical card. Pending effects remain blockers; an unknown route identity
// conservatively blocks the node. Accepted rows are reduced in deterministic
// timestamp order, and equal-time evidence for one card is ambiguous rather
// than selected by an arbitrary row ID.
func reduceRuntimeProfileHistory(nodeID string, target Target, rows []*domain.NodeCommand, knownTargets map[string]Target) string {
	targetID := normalizeRuntimeProfileTargetID(nodeID, target.ID)
	ordered := make([]*domain.NodeCommand, 0, len(rows))
	for _, row := range rows {
		if row != nil && row.NodeID == nodeID && row.Command == "switch_runtime_profile" {
			ordered = append(ordered, row)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
		}
		return ordered[i].ID < ordered[j].ID
	})
	var latest *domain.NodeCommand
	for _, row := range ordered {
		routeID, observedCard, observedAdapter, observedEndpoint, cardKnown := runtimeProfileCommandObservedCard(row)
		accepted := runtimeProfileCommandHasAcceptedResult(row)
		if known, found := knownTargets[routeID]; found && cardKnown {
			if (known.AcceleratorID != "" && known.AcceleratorID != observedCard) || (known.Adapter != "" && known.Adapter != observedAdapter) || (known.Endpoint != "" && known.Endpoint != observedEndpoint) {
				return fmt.Sprintf("profile command %s has conflicting physical route identity; node %s requires reconciliation", row.ID, nodeID)
			}
		}
		if accepted {
			if !cardKnown {
				return fmt.Sprintf("accepted profile command %s has unknown physical-card identity; node %s requires reconciliation", row.ID, nodeID)
			}
			if target.AcceleratorID != "" && observedCard != target.AcceleratorID {
				continue
			}
			if latest != nil && row.CreatedAt.Equal(latest.CreatedAt) && row.ID != latest.ID {
				return fmt.Sprintf("accepted profile switches %s and %s have ambiguous durable ordering for card %s", latest.ID, row.ID, observedCard)
			}
			if latest == nil || row.CreatedAt.After(latest.CreatedAt) {
				latest = row
			}
			continue
		}
		if row.Status == domain.NodeCommandSucceeded {
			// A switch that finished long ago is settled history: the node's
			// current /slots advertisement is authoritative for its profile.
			// Only a recent unproven success can still disagree with it (e.g.
			// rows written by older controllers without route/card proof).
			if settled := runtimeProfileCommandSettledAt(row); !settled.IsZero() && time.Since(settled) > runtimeProfileSettledHistoryAge {
				continue
			}
			return fmt.Sprintf("succeeded profile command %s lacks accepted route/card proof; node %s requires reconciliation", row.ID, nodeID)
		}
		if row.Attempts == 0 && (row.Status == domain.NodeCommandFailed || row.Status == domain.NodeCommandExpired) {
			continue
		}
		if routeID == "" {
			return fmt.Sprintf("profile command %s has unknown target identity; node %s requires reconciliation", row.ID, nodeID)
		}
		if routeID == targetID {
			if cardKnown {
				return fmt.Sprintf("profile command %s is %s with %d delivery attempts on card %s", row.ID, row.Status, row.Attempts, observedCard)
			}
			return fmt.Sprintf("profile command %s is %s with %d delivery attempts", row.ID, row.Status, row.Attempts)
		}
		if cardKnown {
			if target.AcceleratorID != "" && observedCard == target.AcceleratorID {
				return fmt.Sprintf("profile command %s is %s with %d delivery attempts on card %s", row.ID, row.Status, row.Attempts, observedCard)
			}
			continue
		}
		known, found := knownTargets[routeID]
		if !found {
			return fmt.Sprintf("profile command %s has unknown physical-card identity; node %s requires reconciliation", row.ID, nodeID)
		}
		if target.AcceleratorID != "" && known.AcceleratorID == target.AcceleratorID {
			return fmt.Sprintf("profile command %s is %s with %d delivery attempts on card %s", row.ID, row.Status, row.Attempts, target.AcceleratorID)
		}
	}
	if latest == nil {
		return ""
	}
	routeID, _, _, _, _ := runtimeProfileCommandObservedCard(latest)
	if routeID != targetID {
		return fmt.Sprintf("latest accepted profile switch %s on card %s is correlated only to route %s", latest.ID, target.AcceleratorID, routeID)
	}
	if !runtimeProfileAcceptedResultMatchesTarget(latest, target) {
		return fmt.Sprintf("latest accepted profile switch %s conflicts with the current route observation %s on card %s", latest.ID, target.ID, target.AcceleratorID)
	}
	return ""
}

// RuntimeProfileHistoryBlocker shares the deterministic, card-scoped durable
// effect reducer with registration. It is used only while the caller holds an
// exact dispatch claim, never while the manager state lock spans a store call.
func (m *Manager) RuntimeProfileHistoryBlocker(nodeID, targetID string, rows []*domain.NodeCommand) string {
	targetID = normalizeRuntimeProfileTargetID(nodeID, targetID)
	targets := runtimeProfileHistoryTargetSnapshot(m, nil)
	target, found := targets[targetID]
	if !found {
		return fmt.Sprintf("target %s is no longer live", targetID)
	}
	// A new ticket intentionally zeroes the live capacity fields. That pending
	// view must never validate a historical result as current capacity, but it
	// also must not make the immediately preceding accepted proof unusable for
	// the ticket's one authorized dispatch. Use only the exact verified basis
	// captured at ticket creation and only while the pending generation is
	// still current; aliases and unrelated tickets continue through the normal
	// exact-route reducer.
	m.mu.RLock()
	key := m.runtimeProfileTransitionTarget[targetID]
	transition := m.runtimeProfileTransitions[key]
	if transition != nil && !transition.projected && transition.nodeID == nodeID && transition.targetID == targetID &&
		m.targetGenerations[targetID] == transition.expectedGeneration && transition.historyBasisGeneration+1 == transition.expectedGeneration &&
		transition.historyBasis.ID == targetID && transition.historyBasis.NodeID == nodeID && transition.historyBasis.AcceleratorID == transition.acceleratorID &&
		transition.historyBasis.Adapter == transition.adapter && transition.historyBasis.Endpoint == transition.endpoint &&
		transition.historyBasis.CapacityVerified && transition.historyBasis.CapacitySource == "runtime:/slots" && transition.historyBasis.Slots > 0 && transition.historyBasis.ContextLimit > 0 {
		target = transition.historyBasis
		targets[targetID] = target
	}
	m.mu.RUnlock()
	return reduceRuntimeProfileHistory(nodeID, target, rows, targets)
}

func (m *Manager) runtimeProfileQuarantineReason(ctx context.Context, nodeID string, target Target) string {
	if nodeID == "" {
		return ""
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := m.store.ListNodeCommandRecovery(queryCtx, nodeID, "")
	if err != nil {
		return "durable node command history is unavailable"
	}
	knownTargets := runtimeProfileHistoryTargetSnapshot(m, &target)
	return reduceRuntimeProfileHistory(nodeID, target, rows, knownTargets)
}

func runtimeProfileAcceptedResultMatchesTarget(row *domain.NodeCommand, target Target) bool {
	if !runtimeProfileCommandHasAcceptedResult(row) || row == nil {
		return false
	}
	commandTargetID, _ := row.Args["target_id"].(string)
	if commandTargetID != "" && !strings.HasPrefix(commandTargetID, row.NodeID+"-") {
		commandTargetID = row.NodeID + "-" + commandTargetID
	}
	if commandTargetID != target.ID {
		return false
	}
	var result runtimeProfileResult
	if err := json.Unmarshal(row.Result, &result); err != nil {
		return false
	}
	for _, observed := range result.Adapters {
		observedID := observed.ID
		if observedID != "" && !strings.HasPrefix(observedID, row.NodeID+"-") {
			observedID = row.NodeID + "-" + observedID
		}
		if observedID != target.ID {
			continue
		}
		if observed.Adapter == "" || observed.Endpoint == "" || observed.AcceleratorIndex == nil || *observed.AcceleratorIndex < 0 || observed.Adapter != target.Adapter || observed.Endpoint != target.Endpoint || fmt.Sprintf("%s-gpu%d", row.NodeID, *observed.AcceleratorIndex) != target.AcceleratorID || observed.Version != target.RuntimeIdentity || observed.ModelFingerprint != target.ModelFingerprint || observed.CapabilityVersion != target.CapabilityVersion || observed.CapabilityRevision != target.CapabilityRevision || observed.ContextLimit != target.ContextLimit || observed.Slots != target.Slots || observed.CapacitySource != target.CapacitySource || !observed.CapabilitiesVerified || !target.CapacityVerified || observed.ActiveRuntimeProfile != target.ActiveRuntimeProfile {
			return false
		}
		profileMatches := 0
		for _, profile := range target.RuntimeProfiles {
			if profile.ID == observed.ActiveRuntimeProfile && profile.ContextLimit == observed.ContextLimit && profile.Slots == observed.Slots {
				profileMatches++
			}
		}
		return profileMatches == 1
	}
	return false
}

const runtimeProfileSettledHistoryAge = time.Hour

func runtimeProfileCommandSettledAt(row *domain.NodeCommand) time.Time {
	if row.CompletedAt != nil && !row.CompletedAt.IsZero() {
		return *row.CompletedAt
	}
	return row.UpdatedAt
}

func runtimeProfileCommandHasAcceptedResult(row *domain.NodeCommand) bool {
	if row == nil || row.Status != domain.NodeCommandSucceeded || len(row.Result) == 0 {
		return false
	}
	targetID, _ := row.Args["target_id"].(string)
	profileID, _ := row.Args["profile_id"].(string)
	if targetID == "" || profileID == "" || row.NodeID == "" {
		return false
	}
	var result runtimeProfileResult
	if err := json.Unmarshal(row.Result, &result); err != nil {
		return false
	}
	if !strings.HasPrefix(targetID, row.NodeID+"-") {
		targetID = row.NodeID + "-" + targetID
	}
	var matched *runtimeProfileResultAdapter
	matches := 0
	for i := range result.Adapters {
		advertised := &result.Adapters[i]
		advertisedID := advertised.ID
		if advertisedID != "" && !strings.HasPrefix(advertisedID, row.NodeID+"-") {
			advertisedID = row.NodeID + "-" + advertisedID
		}
		if advertisedID == targetID {
			matches++
			matched = advertised
		}
	}
	if matches != 1 || matched.Adapter == "" || matched.Endpoint == "" || matched.AcceleratorIndex == nil || *matched.AcceleratorIndex < 0 || matched.ActiveRuntimeProfile != profileID || matched.ContextLimit <= 0 || matched.Slots <= 0 || matched.CapacitySource != "runtime:/slots" || !matched.CapabilitiesVerified || matched.Version == "" || matched.ModelFingerprint == "" || matched.CapabilityVersion == "" || matched.CapabilityRevision == "" {
		return false
	}
	profileMatches := 0
	for _, profile := range matched.RuntimeProfiles {
		if profile.ID == profileID {
			profileMatches++
			if profile.ContextLimit != matched.ContextLimit || profile.Slots != matched.Slots {
				return false
			}
		}
	}
	return profileMatches == 1
}

// RuntimeProfileCommandHasAcceptedResult is shared with the API durable
// admission guard so a malformed legacy SUCCEEDED row cannot be treated as
// proof by one path and uncertainty by another.
func RuntimeProfileCommandHasAcceptedResult(row *domain.NodeCommand) bool {
	return runtimeProfileCommandHasAcceptedResult(row)
}

func (m *Manager) runtimeProfileTargetBlockerLocked(target Target) string {
	if reason := m.runtimeProfileBlockedTargets[target.ID]; reason != "" {
		return reason
	}
	if target.NodeID != "" {
		if reason := m.runtimeProfileBlockedNodes[target.NodeID]; reason != "" {
			return reason
		}
	}
	if target.AcceleratorID != "" {
		if reason := m.runtimeProfileBlockedCards[target.AcceleratorID]; reason != "" {
			return reason
		}
	}
	return ""
}

// refreshRuntimeProfileProjectedGenerationLocked keeps a correlated profile
// result idempotent across metadata-only target generation changes. Callers
// must already hold m.mu and may use it only after confirming the route's
// profile-bearing identity and observed runtime capacity are unchanged.
func (m *Manager) refreshRuntimeProfileProjectedGenerationLocked(target Target) {
	key := m.runtimeProfileTransitionTarget[target.ID]
	transition := m.runtimeProfileTransitions[key]
	if transition == nil || !transition.projected || target.NodeID != transition.nodeID || target.AcceleratorID != transition.acceleratorID ||
		target.Adapter != transition.adapter || target.Endpoint != transition.endpoint || target.CapabilityVersion != transition.capabilityVersion ||
		target.CapabilityRevision != transition.capabilityRevision || target.RuntimeIdentity != transition.runtimeIdentity ||
		target.ModelFingerprint != transition.modelFingerprint || target.ActiveRuntimeProfile != transition.profile.ID ||
		target.ContextLimit != transition.profile.ContextLimit || target.Slots != transition.profile.Slots || !target.CapacityVerified ||
		target.CapacitySource != "runtime:/slots" {
		return
	}
	transition.projectedGeneration = m.targetGenerations[target.ID]
}

func (m *Manager) runtimeProfileCapacityViewLocked(target Target) Target {
	pendingKey := m.runtimeProfileTransitionTarget[target.ID]
	if pendingKey != "" {
		if transition := m.runtimeProfileTransitions[pendingKey]; transition != nil && !transition.projected {
			target.ContextLimit = 0
			target.Slots = 0
			target.ActiveRuntimeProfile = ""
			target.CapacityVerified = false
			target.CapacitySource = "runtime-profile:pending"
			return target
		}
	}
	if m.runtimeProfileTargetBlockerLocked(target) != "" {
		target.ContextLimit = 0
		target.Slots = 0
		target.ActiveRuntimeProfile = ""
		target.CapacityVerified = false
		target.CapacitySource = "runtime-profile:observation_unavailable"
	}
	return target
}

// ClaimRuntimeProfileDispatch validates and claims one exact live transition
// ticket. The returned release function remains held across the caller's
// durable CAS and websocket write; lifecycle mutations use the same ticket
// mutex without holding manager state locks across those external operations.
func (m *Manager) ClaimRuntimeProfileDispatch(nodeID, targetID string, args map[string]any, idempotencyKey string) (func(), error) {
	profileID, _ := args["profile_id"].(string)
	if nodeID == "" || targetID == "" || profileID == "" || idempotencyKey == "" {
		return nil, fmt.Errorf("runtime profile dispatch ticket is incomplete")
	}
	if !strings.HasPrefix(targetID, nodeID+"-") {
		targetID = nodeID + "-" + targetID
	}
	m.mu.RLock()
	transition := m.runtimeProfileTransitions[idempotencyKey]
	m.mu.RUnlock()
	if transition == nil {
		return nil, fmt.Errorf("runtime profile dispatch ticket is not current")
	}
	transition.dispatchMu.Lock()
	m.mu.RLock()
	current, found := m.targets[targetID]
	valid := found && m.runtimeProfileTransitions[idempotencyKey] == transition && !transition.projected &&
		m.runtimeProfileTransitionTarget[targetID] == idempotencyKey && transition.commandKey == idempotencyKey &&
		transition.nodeID == nodeID && transition.targetID == targetID && transition.profile.ID == profileID &&
		m.targetGenerations[targetID] == transition.expectedGeneration && m.retiredTargets[targetID].ID == "" &&
		current.NodeID == nodeID && current.AcceleratorID == transition.acceleratorID && current.Adapter == transition.adapter &&
		current.Endpoint == transition.endpoint && current.CapabilityVersion == transition.capabilityVersion &&
		current.CapabilityRevision == transition.capabilityRevision && current.RuntimeIdentity == transition.runtimeIdentity &&
		current.ModelFingerprint == transition.modelFingerprint && !current.CapacityVerified && current.Slots == 0 &&
		current.ContextLimit == 0 && current.CapacitySource == "runtime-profile:pending"
	m.mu.RUnlock()
	if !valid {
		transition.dispatchMu.Unlock()
		return nil, fmt.Errorf("runtime profile dispatch ticket is stale, retired, or route-mismatched")
	}
	var once sync.Once
	return func() { once.Do(transition.dispatchMu.Unlock) }, nil
}

// RuntimeProfileDispatchAllowed is a non-claiming snapshot for tests and
// diagnostics. Side-effect gateways must use ClaimRuntimeProfileDispatch.
func (m *Manager) RuntimeProfileDispatchAllowed(nodeID, targetID string, args map[string]any, idempotencyKey string) bool {
	release, err := m.ClaimRuntimeProfileDispatch(nodeID, targetID, args, idempotencyKey)
	if err != nil {
		return false
	}
	release()
	return true
}

// ClaimRuntimeProfileResult holds a short lifecycle fence across the API's
// durable success CAS and projection. It is distinct from dispatchMu because
// a node can synchronously return a result while the sender still owns that
// dispatch claim.
func (m *Manager) ClaimRuntimeProfileResult(commandKey, nodeID string, result map[string]any) (*RuntimeProfileResultClaim, error) {
	m.mu.RLock()
	transition := m.runtimeProfileTransitions[commandKey]
	m.mu.RUnlock()
	if transition == nil || transition.nodeID != nodeID {
		return nil, fmt.Errorf("runtime profile result has no matching transition ticket")
	}
	transition.resultMu.Lock()
	if err := m.ValidateRuntimeProfileCommandResult(commandKey, nodeID, result); err != nil {
		transition.resultMu.Unlock()
		return nil, err
	}
	return &RuntimeProfileResultClaim{manager: m, transition: transition}, nil
}

func (m *Manager) lockRuntimeProfileTransitionForTarget(targetID string) func() {
	for {
		m.mu.RLock()
		key := m.runtimeProfileTransitionTarget[targetID]
		transition := m.runtimeProfileTransitions[key]
		m.mu.RUnlock()
		if key == "" || transition == nil {
			return func() {}
		}
		transition.dispatchMu.Lock()
		transition.resultMu.Lock()
		m.mu.RLock()
		current := m.runtimeProfileTransitions[m.runtimeProfileTransitionTarget[targetID]]
		m.mu.RUnlock()
		if current == transition {
			var once sync.Once
			return func() {
				once.Do(func() {
					transition.resultMu.Unlock()
					transition.dispatchMu.Unlock()
				})
			}
		}
		transition.resultMu.Unlock()
		transition.dispatchMu.Unlock()
	}
}

// reconcileResidencyGeneration fences durable residency high-water recovery
// with the current runtime-profile ticket. The store read has already
// completed before this method is entered; only the short in-memory commit is
// protected by the ticket, admission, target, and manager locks.
func (m *Manager) reconcileResidencyGeneration(target Target, projection *domain.ModelResidency, expectedGeneration uint64) (Target, uint64, error) {
	return m.reconcileResidencyGenerationContext(context.Background(), target, projection, expectedGeneration)
}

// reconcileResidencyGenerationContext applies a durable high-water snapshot
// only while the caller remains live at the in-memory commit point. The
// legacy wrapper above preserves existing callers that do not own a context.
func (m *Manager) reconcileResidencyGenerationContext(ctx context.Context, target Target, projection *domain.ModelResidency, expectedGeneration uint64) (Target, uint64, error) {
	if ctx == nil {
		return target, expectedGeneration, fmt.Errorf("residency high-water recovery context is unavailable")
	}
	if projection == nil {
		return target, expectedGeneration, nil
	}
	for {
		m.mu.RLock()
		priorKey := m.runtimeProfileTransitionTarget[target.ID]
		prior := m.runtimeProfileTransitions[priorKey]
		m.mu.RUnlock()
		if prior != nil {
			prior.dispatchMu.Lock()
			prior.resultMu.Lock()
		}
		m.residencyAdmissionMu.Lock()
		fence := m.residencyAdmissionLock(target.ID)
		fence.Lock()
		m.mu.Lock()
		currentKey := m.runtimeProfileTransitionTarget[target.ID]
		currentTicket := m.runtimeProfileTransitions[currentKey]
		if currentKey != priorKey || currentTicket != prior {
			m.mu.Unlock()
			fence.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			continue
		}
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			fence.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			return target, expectedGeneration, err
		}
		current, found := m.targets[target.ID]
		if !found || m.targetGenerations[target.ID] != expectedGeneration || !targetIdentityMatches(target, current) {
			m.mu.Unlock()
			fence.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			return target, expectedGeneration, fmt.Errorf("residency target changed during durable high-water recovery")
		}
		if prior != nil && !prior.projected {
			m.mu.Unlock()
			fence.Unlock()
			m.residencyAdmissionMu.Unlock()
			prior.resultMu.Unlock()
			prior.dispatchMu.Unlock()
			return target, expectedGeneration, fmt.Errorf("runtime profile observation_unavailable; residency mutation cannot change a pending profile generation")
		}
		generation := m.targetGenerations[target.ID]
		if projection.TargetGeneration > generation || (projection.TargetGeneration == generation && projection.ExecutionFingerprint != "" && projection.ExecutionFingerprint != targetExecutionFingerprint(current)) {
			if projection.TargetGeneration == ^uint64(0) {
				m.mu.Unlock()
				fence.Unlock()
				m.residencyAdmissionMu.Unlock()
				if prior != nil {
					prior.resultMu.Unlock()
					prior.dispatchMu.Unlock()
				}
				return target, expectedGeneration, fmt.Errorf("durable residency target generation is exhausted")
			}
			generation = projection.TargetGeneration + 1
			m.targetGenerations[target.ID] = generation
			// A recovered durable fence may represent metadata that does not
			// change the accepted runtime profile. Preserve result idempotence
			// only when the existing helper confirms the exact route/profile
			// facts; otherwise its projected generation remains stale.
			m.refreshRuntimeProfileProjectedGenerationLocked(current)
		}
		m.mu.Unlock()
		fence.Unlock()
		m.residencyAdmissionMu.Unlock()
		if prior != nil {
			prior.resultMu.Unlock()
			prior.dispatchMu.Unlock()
		}
		return current, generation, nil
	}
}

func (m *Manager) runtimeProfileHasPendingLocked(nodeID, acceleratorID string) bool {
	for _, transition := range m.runtimeProfileTransitions {
		if transition == nil || transition.projected {
			continue
		}
		if nodeID != "" && transition.nodeID == nodeID {
			return true
		}
		if acceleratorID != "" && transition.acceleratorID == acceleratorID {
			return true
		}
	}
	return false
}

func (m *Manager) ReconcileNodeTargets(nodeID string, advertised map[string]struct{}) {
	prefix := nodeID + "-"
	// Snapshot candidate advertisements without nesting the manager and
	// placement locks. Cleanup of active lease metadata is a separate short
	// placement phase after the target-map tombstone is committed.
	type targetSnapshot struct {
		id         string
		transition *runtimeProfileTransition
	}
	for {
		m.mu.RLock()
		candidates := make([]targetSnapshot, 0)
		for id := range m.targets {
			if !strings.HasPrefix(id, prefix) {
				continue
			}
			if _, present := advertised[id]; present {
				continue
			}
			transition := m.runtimeProfileTransitions[m.runtimeProfileTransitionTarget[id]]
			candidates = append(candidates, targetSnapshot{id: id, transition: transition})
		}
		m.mu.RUnlock()
		if len(candidates) == 0 {
			return
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })
		lockedTransitions := make([]*runtimeProfileTransition, 0, len(candidates))
		seenTransitions := make(map[*runtimeProfileTransition]struct{}, len(candidates))
		for _, snapshot := range candidates {
			if snapshot.transition == nil {
				continue
			}
			if _, seen := seenTransitions[snapshot.transition]; seen {
				continue
			}
			snapshot.transition.dispatchMu.Lock()
			snapshot.transition.resultMu.Lock()
			seenTransitions[snapshot.transition] = struct{}{}
			lockedTransitions = append(lockedTransitions, snapshot.transition)
		}
		m.residencyAdmissionMu.Lock()
		targetFences := make([]*sync.RWMutex, 0, len(candidates))
		for _, snapshot := range candidates {
			fence := m.residencyAdmissionLock(snapshot.id)
			fence.Lock()
			targetFences = append(targetFences, fence)
		}
		m.mu.Lock()
		retry := false
		for _, snapshot := range candidates {
			currentTransition := m.runtimeProfileTransitions[m.runtimeProfileTransitionTarget[snapshot.id]]
			if currentTransition != snapshot.transition {
				retry = true
				break
			}
		}
		removed := make([]string, 0, len(candidates))
		exhaustedRetirements := make([]string, 0)
		if !retry {
			for _, snapshot := range candidates {
				retired, exists := m.targets[snapshot.id]
				if !exists {
					continue
				}
				retired.Enabled = false
				m.retiredTargets[snapshot.id] = retired
				delete(m.targets, snapshot.id)
				if m.targetGenerations[snapshot.id] == ^uint64(0) {
					exhaustedRetirements = append(exhaustedRetirements, snapshot.id)
				} else {
					m.targetGenerations[snapshot.id]++
				}
				removed = append(removed, snapshot.id)
			}
		}
		m.mu.Unlock()
		for index := len(targetFences) - 1; index >= 0; index-- {
			targetFences[index].Unlock()
		}
		m.residencyAdmissionMu.Unlock()
		for index := len(lockedTransitions) - 1; index >= 0; index-- {
			lockedTransitions[index].resultMu.Unlock()
			lockedTransitions[index].dispatchMu.Unlock()
		}
		for _, id := range exhaustedRetirements {
			m.log.Error("retired target at exhausted generation without wrapping its fence; re-registration is disabled until restart", "target", id)
		}
		if retry {
			continue
		}
		if len(removed) > 0 {
			m.placementMu.Lock()
			for _, id := range removed {
				if m.targetActive[id] <= 0 {
					delete(m.targetLeases, id)
					delete(m.targetActive, id)
				}
			}
			m.placementMu.Unlock()
			m.signal()
		}
		return
	}
}

func (m *Manager) Targets() []Target {
	// Copy route facts before reading placement state; never hold m.mu while
	// taking placementMu so readers and node refreshes have one lock order.
	m.mu.RLock()
	targets := make([]Target, 0, len(m.targets))
	for _, target := range m.targets {
		targets = append(targets, m.runtimeProfileCapacityViewLocked(target))
	}
	m.mu.RUnlock()
	out := make([]Target, 0, len(targets))
	for _, target := range targets {
		m.placementMu.Lock()
		target.Active = m.targetActive[target.ID]
		m.placementMu.Unlock()
		m.providerMu.Lock()
		if circuit, found := m.providerCircuits[target.ID]; found {
			target.CircuitFailures = circuit.Failures
			if circuit.OpenUntil.After(time.Now()) {
				target.CircuitState = "open"
				until := circuit.OpenUntil
				target.CircuitOpenUntil = &until
			} else {
				target.CircuitState = "closed"
			}
		}
		m.providerMu.Unlock()
		out = append(out, target)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// UpdateTargetPolicy changes only the scheduler safety controls that operators
// are allowed to tune at runtime. The caller persists the returned policy
// before considering the mutation successful.
func (m *Manager) UpdateTargetPolicy(policy domain.TargetPolicyOverride) (Target, error) {
	if policy.VRAMReserveMB < 0 {
		return Target{}, fmt.Errorf("vram_reserve_mb may not be negative")
	}
	if _, err := checkedMiBToBytes(policy.VRAMReserveMB, "vram_reserve_mb"); err != nil {
		return Target{}, err
	}
	if policy.MaxSlowdown < 0 || policy.MaxSlowdown > 10 || (policy.SharingEnabled && policy.MaxSlowdown < 1) {
		return Target{}, fmt.Errorf("max_slowdown must be between 1 and 10 when sharing is enabled")
	}
	releaseProfileTicket := m.lockRuntimeProfileTransitionForTarget(policy.TargetID)
	defer releaseProfileTicket()
	m.residencyAdmissionMu.Lock()
	defer m.residencyAdmissionMu.Unlock()
	fence := m.residencyAdmissionLock(policy.TargetID)
	fence.Lock()
	defer fence.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	target, found := m.targets[policy.TargetID]
	if !found {
		return Target{}, fmt.Errorf("unknown target %q", policy.TargetID)
	}
	if key := m.runtimeProfileTransitionTarget[policy.TargetID]; key != "" {
		if transition := m.runtimeProfileTransitions[key]; transition != nil && !transition.projected {
			return Target{}, fmt.Errorf("runtime profile observation_unavailable; target policy cannot change during unresolved switch %s", key)
		}
	}
	if policy.SharingEnabled && target.AcceleratorVRAMMB == 0 {
		return Target{}, fmt.Errorf("sharing requires a configured accelerator_vram_mb envelope")
	}
	if policy.GuardedExploration && !policy.SharingEnabled {
		return Target{}, fmt.Errorf("guarded exploration requires sharing_enabled")
	}
	target.Enabled = policy.Enabled
	target.Quarantined = policy.Quarantined
	target.SharingEnabled = policy.SharingEnabled
	target.GuardedExploration = policy.GuardedExploration
	target.VRAMReserveMB = policy.VRAMReserveMB
	target.MaxSlowdown = policy.MaxSlowdown
	if err := m.replaceTargetLocked(target); err != nil {
		return Target{}, err
	}
	m.signal()
	return target, nil
}

func (m *Manager) ApplyStoredTargetPolicies(ctx context.Context) error {
	policies, err := m.store.ListTargetPolicyOverrides(ctx)
	if err != nil {
		return err
	}
	for _, policy := range policies {
		m.mu.RLock()
		_, registered := m.targets[policy.TargetID]
		m.mu.RUnlock()
		if !registered {
			continue
		}
		if _, err := m.UpdateTargetPolicy(*policy); err != nil {
			m.log.Warn("ignoring invalid stored target policy", "target", policy.TargetID, "error", err)
		}
	}
	return nil
}

func (m *Manager) Start(ctx context.Context) {
	m.lifecycleMu.Lock()
	if m.lifecycleClosed {
		m.lifecycleMu.Unlock()
		return
	}
	if m.recoveryStarted {
		if m.lifecycleStarting {
			m.lifecycleMu.Unlock()
			return
		}
		recoveryCtx := m.recoveryCtx
		m.lifecycleMu.Unlock()
		if recoveryCtx != nil {
			select {
			case m.recoveryWake <- struct{}{}:
			default:
			}
			releaseOperation, operationErr := m.beginResidencyOperation(recoveryCtx)
			if operationErr == nil {
				m.initializeResidencyRecovery(recoveryCtx)
				m.recoverRegisteredResidencyTransitions(recoveryCtx)
				releaseOperation()
			}
		}
		return
	}
	recoveryCtx, recoveryCancel := context.WithCancel(ctx)
	m.recoveryCtx, m.recoveryCancel, m.recoveryStarted = recoveryCtx, recoveryCancel, true
	m.managerCtx, m.managerCancel = recoveryCtx, recoveryCancel
	m.lifecycleStarting = true
	m.recoveryWG.Add(1)
	m.lifecycleMu.Unlock()
	if err := m.ApplyStoredTargetPolicies(recoveryCtx); err != nil {
		m.log.Warn("target policy override recovery unavailable", "error", err)
	}
	if profiles, err := m.store.ListInterferenceProfiles(recoveryCtx); err == nil {
		loadedProfiles := make(map[string]*domain.InterferenceProfile, len(profiles))
		m.learningMu.Lock()
		for _, profile := range profiles {
			m.interferenceProfiles[profile.Key] = profile
			loadedProfiles[profile.Key] = profile
		}
		m.learningMu.Unlock()
		m.mu.RLock()
		targetSnapshots := make([]struct {
			id     string
			target Target
		}, 0, len(m.targets))
		for id, target := range m.targets {
			targetSnapshots = append(targetSnapshots, struct {
				id     string
				target Target
			}{id, target})
		}
		m.mu.RUnlock()
		for _, snapshot := range targetSnapshots {
			profile := loadedProfiles[standaloneProfileKey(snapshot.target)]
			if snapshot.target.StandaloneVRAMVerified || profile == nil || profile.Confidence < .5 || profile.P95VRAMMB <= snapshot.target.StandaloneVRAMMB {
				continue
			}
			releaseProfileTicket := m.lockRuntimeProfileTransitionForTarget(snapshot.id)
			m.residencyAdmissionMu.Lock()
			fence := m.residencyAdmissionLock(snapshot.id)
			fence.Lock()
			m.mu.Lock()
			var generationErr error
			current, found := m.targets[snapshot.id]
			pendingKey := m.runtimeProfileTransitionTarget[snapshot.id]
			pending := pendingKey != "" && m.runtimeProfileTransitions[pendingKey] != nil && !m.runtimeProfileTransitions[pendingKey].projected
			if found && !pending && targetExecutionGenerationEqual(snapshot.target, current) && !current.StandaloneVRAMVerified && profile.P95VRAMMB > current.StandaloneVRAMMB {
				current.StandaloneVRAMMB = profile.P95VRAMMB
				generationErr = m.replaceTargetLocked(current)
			}
			m.mu.Unlock()
			fence.Unlock()
			m.residencyAdmissionMu.Unlock()
			releaseProfileTicket()
			if generationErr != nil {
				m.log.Error("skipping learned registration capacity update because target generation is exhausted", "target", snapshot.id, "error", generationErr)
			}
		}
	}
	if plans, err := m.store.ListTransitionPlans(recoveryCtx, "", 1000); err == nil {
		for _, plan := range plans {
			if plan.Status != domain.TransitionPlanPlanned && plan.Status != domain.TransitionPlanExecuting {
				continue
			}
			now := time.Now().UTC()
			plan.Status = domain.TransitionPlanFailed
			plan.Error = "controller restarted during transition; action was not replayed"
			plan.UpdatedAt = now
			plan.FinishedAt = &now
			if _, updateErr := m.store.UpdateTransitionPlan(recoveryCtx, plan); updateErr != nil {
				m.log.Warn("transition plan startup recovery unavailable", "plan_id", plan.ID, "error", updateErr)
			}
		}
	}
	m.initializeResidencyRecovery(recoveryCtx)
	m.retryAcceleratorLeaseCleanupIntents(recoveryCtx)
	m.recoverCheckpointRecoveryIntents(recoveryCtx)
	m.recoverCheckpointCleanupIntents(recoveryCtx)
	// Preserve synchronous startup reconciliation for local adapters and
	// existing callers; the lifecycle-owned worker below retries any
	// controller/node failure without losing the durable transition.
	m.recoverRegisteredResidencyTransitions(recoveryCtx)
	// Recovered running work is never blindly duplicated. Work that had not
	// reached a backend can be re-admitted immediately. A persisted external
	// execution is reconciled against its original backend after that target is
	// registered; only a confirmed completion or stop can leave this state.
	if rows, err := m.store.ListWorkloads(recoveryCtx); err == nil {
		cleanupFenced := make(map[string]struct{})
		if operations, operationsOK := m.store.(store.LLMCheckpointOperationStore); operationsOK {
			if cleanupRows, listErr := operations.ListLLMCheckpointOperations(recoveryCtx, ""); listErr == nil {
				for _, cleanupOp := range cleanupRows {
					if cleanupOp != nil && cleanupOp.WorkloadID != "" && cleanupOp.CleanupState != "" && cleanupOp.CleanupState != "confirmed" {
						cleanupFenced[cleanupOp.WorkloadID] = struct{}{}
					}
				}
			}
		}
		for _, w := range rows {
			if w.BudgetCleanupToken != "" {
				if err := m.retryBudgetCleanupIntent(recoveryCtx, w); err != nil {
					m.log.Warn("budget cleanup intent startup retry failed", "workload_id", w.Request.ID, "error", err)
				}
				if refreshed, refreshErr := m.store.GetWorkload(recoveryCtx, w.Request.ID); refreshErr == nil {
					w = refreshed
				}
			}
			if w.CancellationOwner != "" {
				continue
			}
			if w.Status != domain.WorkloadRunning {
				continue
			}
			if _, fenced := cleanupFenced[w.Request.ID]; fenced {
				// Durable cleanup custody owns the projection until the physical
				// stop/release retry confirms absence. Do not terminalize or clear
				// its external handle during generic startup reconciliation.
				continue
			}
			releaseBudget := false
			if w.Request.Recoverable && w.Execution == nil {
				releaseBudget = true
				w.Status = domain.WorkloadQueued
				w.StartedAt = nil
				w.Error = "controller restarted; re-admitting recoverable workload"
			} else if w.Request.Recoverable {
				w.Status = domain.WorkloadWaiting
				w.Decision = domain.AdmissionDecision{Admitted: false, Blocker: restartReconciliationBlocker, Confidence: .95}
				w.Error = restartReconciliationBlocker
			} else {
				w.Status = domain.WorkloadFailed
				w.Error = "controller restarted during non-recoverable execution"
				now := time.Now().UTC()
				w.FinishedAt = &now
			}
			w.UpdatedAt = time.Now().UTC()
			if updated, mutateErr := m.replaceWorkloadCAS(recoveryCtx, w, workloadStatuses(domain.WorkloadRunning), ""); mutateErr == nil {
				w = updated
			} else {
				continue
			}
			if releaseBudget {
				if releaseErr := m.releaseBudgetClaimAfterWorkloadCAS(recoveryCtx, w.Request.ID, w.BudgetReservationToken, w.BudgetReservationAttempt); releaseErr != nil {
					m.log.Warn("startup budget cleanup remains pending", "workload_id", w.Request.ID, "error", releaseErr)
				}
			}
			if w.Status == domain.WorkloadFailed {
				m.settleWorkloadBudget(recoveryCtx, w)
			}
			if w.Status == domain.WorkloadFailed && w.Request.Notifications.OnFinish {
				m.enqueueNotification(recoveryCtx, w, "workload.failed")
			}
		}
	}
	for _, target := range m.Targets() {
		m.reconcileRecoveredExecutionsForTarget(recoveryCtx, target.ID)
	}
	m.lifecycleMu.Lock()
	if m.lifecycleClosed {
		m.lifecycleStarting = false
		m.lifecycleMu.Unlock()
		m.recoveryWG.Done()
		return
	}
	// Reserve the loop wait-group slots before publishing that startup is
	// complete. Close may race this boundary, but it will either wait for the
	// reserved goroutines or observe the closed state and skip their launch.
	m.loopWG.Add(2)
	m.lifecycleStarting = false
	m.lifecycleMu.Unlock()
	go func() { defer m.loopWG.Done(); m.loop(recoveryCtx) }()
	go func() { defer m.loopWG.Done(); m.notificationLoop(recoveryCtx) }()
	go m.residencyRecoveryLoop(recoveryCtx)
}

// recoverCheckpointRecoveryIntents resolves an outer-CAS compensation that
// may have been interrupted by controller shutdown. A pending intent is
// converted into either an adopted running projection or a clean queued
// projection that retains the durable snapshot for the normal resume path.
func (m *Manager) recoverCheckpointRecoveryIntents(ctx context.Context) {
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return
	}
	rows, err := operations.ListLLMCheckpointOperations(ctx, "")
	if err != nil {
		m.log.Warn("checkpoint recovery intent listing unavailable", "error", err)
		return
	}
	for _, op := range rows {
		// Ordinary node compensation rows also carry CompensationOf and the
		// original workload revision.  Only the explicitly marked outer-CAS
		// intent is allowed to mutate the workload projection during startup.
		if op == nil || (op.RecoveryState != "pending" && op.RecoveryState != "restored" && op.RecoveryState != "failed") || op.CompensationOf == "" || op.WorkloadRevision == 0 || op.CleanupOperationID == op.ID {
			continue
		}
		w, getErr := m.store.GetWorkload(ctx, op.WorkloadID)
		if getErr != nil {
			continue
		}
		// Never infer adoption from a newer row alone: its execution may still be
		// the stale pre-checkpoint handle. Only a handle/fence that was durably
		// recorded after physical restore can authorize this branch.
		if op.RecoveryState == "restored" || op.RecoveryState == "failed" {
			if op.RecoveryHandle == nil || strings.TrimSpace(op.RecoveryHandle.ExternalID) == "" || op.RecoveryFence <= op.Fence || op.RecoveryAcceleratorID == "" {
				m.log.Warn("checkpoint recovery intent has incomplete fresh restore identity", "operation_id", op.ID)
				continue
			}
			if op.RecoveryState == "restored" && w.Status == domain.WorkloadRunning && w.Revision > op.WorkloadRevision && checkpointRecoveryHandleMatches(w.Execution, op.RecoveryHandle) && w.CheckpointRef == "" {
				if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), op.ID, "adopted", w.Revision); markErr != nil {
					m.log.Warn("checkpoint recovery adoption marker failed", "operation_id", op.ID, "error", markErr)
				}
				continue
			}
			if op.CleanupState == "stopped" {
				// A stopped cleanup marker is stronger than the projection.  The
				// backend was already physically cancelled, so a running projection
				// that still contains the old fresh handle must be requeued/finalized;
				// it must never be adopted or marked owned again on restart.
				if cleanupErr := m.cleanupCheckpointOperation(context.WithoutCancel(ctx), op); cleanupErr != nil {
					m.log.Warn("checkpoint recovery stopped cleanup release remains pending", "operation_id", op.ID, "error", cleanupErr)
					continue
				}
				if refreshed, refreshErr := operations.GetLLMCheckpointOperation(context.WithoutCancel(ctx), op.ID); refreshErr == nil {
					op = refreshed
				}
				if op.CleanupState != "confirmed" {
					continue
				}
				if w.Status == domain.WorkloadRunning {
					if requeueErr := m.requeueCheckpointVictimAfterCleanup(context.WithoutCancel(ctx), w.Request.ID, op.TargetID, op.SnapshotName); requeueErr != nil {
						m.log.Warn("checkpoint recovery stopped cleanup requeue failed", "operation_id", op.ID, "error", requeueErr)
						continue
					}
				}
				recoveryState := "requeued"
				if isTerminalWorkloadStatus(w.Status) {
					recoveryState = "terminalized"
				}
				if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), op.ID, recoveryState, 0); markErr != nil {
					m.log.Warn("checkpoint recovery stopped cleanup marker failed", "operation_id", op.ID, "error", markErr)
				}
				continue
			}
			if op.RecoveryState == "restored" && w.Status == domain.WorkloadRunning && w.Revision == op.WorkloadRevision {
				updated, adoptErr := m.mutateWorkloadCAS(context.WithoutCancel(ctx), w.Request.ID, workloadStatuses(domain.WorkloadRunning), "", func(current *domain.Workload) error {
					current.Status = domain.WorkloadRunning
					current.Execution = op.RecoveryHandle
					current.CheckpointRef = ""
					current.Error = ""
					current.Decision = domain.AdmissionDecision{Admitted: true, TargetID: op.TargetID, Confidence: .9}
					current.FinishedAt = nil
					current.UpdatedAt = time.Now().UTC()
					return nil
				})
				if adoptErr == nil {
					if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), op.ID, "adopted", updated.Revision); markErr != nil {
						m.log.Warn("checkpoint recovery adoption marker failed", "operation_id", op.ID, "error", markErr)
					}
					continue
				}
				m.log.Warn("checkpoint recovery fresh handle adoption failed", "operation_id", op.ID, "error", adoptErr)
			}
			// A different/newer projection, a queued projection, or a terminal
			// projection cannot safely inherit a live restored handle. Cancel the
			// exact durable handle and release its fresh fence before requeueing.
			if cleanupErr := m.cancelCheckpointRecoveryHandle(context.WithoutCancel(ctx), op); cleanupErr != nil {
				m.log.Warn("checkpoint recovery fresh handle cleanup pending", "operation_id", op.ID, "error", cleanupErr)
				continue
			}
			if w.Status == domain.WorkloadRunning {
				if requeueErr := m.requeueCheckpointVictimAfterCleanup(context.WithoutCancel(ctx), w.Request.ID, op.TargetID, op.SnapshotName); requeueErr != nil {
					m.log.Warn("checkpoint recovery fresh handle requeue failed", "operation_id", op.ID, "error", requeueErr)
					continue
				}
			}
			recoveryState := "requeued"
			if isTerminalWorkloadStatus(w.Status) {
				// The physical restore crossed the fresh-fence boundary, but the
				// projection is already terminal.  Cleanup is complete; do not
				// describe that outcome as a future resume queue.
				recoveryState = "terminalized"
			}
			if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), op.ID, recoveryState, 0); markErr != nil {
				m.log.Warn("checkpoint recovery requeue marker failed", "operation_id", op.ID, "error", markErr)
			}
			continue
		}
		if w.Status != domain.WorkloadRunning {
			// A terminal projection does not erase physical custody.  A crash can
			// leave a pending/owned cleanup row alongside a terminal workload; stop
			// and release that exact generation first, and only then terminalize the
			// outer recovery intent.  If the node is offline or the lease cannot be
			// verified, retain the row/fence for the periodic retry worker.
			if op.CleanupState != "" && op.CleanupState != "confirmed" {
				if cleanupErr := m.cleanupCheckpointOperation(context.WithoutCancel(ctx), op); cleanupErr != nil {
					m.log.Warn("terminal workload still owns checkpoint cleanup custody", "operation_id", op.ID, "error", cleanupErr)
					continue
				}
				if refreshed, refreshErr := operations.GetLLMCheckpointOperation(context.WithoutCancel(ctx), op.ID); refreshErr == nil {
					op = refreshed
				}
				if op.CleanupState != "confirmed" {
					continue
				}
			}
			if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), op.ID, "terminalized", w.Revision); markErr != nil {
				m.log.Warn("checkpoint recovery terminal marker failed", "operation_id", op.ID, "error", markErr)
			}
			continue
		}
		if op.CleanupState != "" {
			// Join the outer recovery row to the physical compensation operation
			// before deciding that no fresh handle exists. A pending outer row with
			// slot -1 is not evidence that the node never accepted :compensate.
			if enriched, enrichErr := m.resolveCheckpointCleanupIdentity(context.WithoutCancel(ctx), op); enrichErr == nil && enriched != nil {
				op = enriched
			} else if enrichErr != nil {
				m.log.Warn("checkpoint recovery physical cleanup identity remains pending", "operation_id", op.ID, "error", enrichErr)
				continue
			}
			// A pending outer intent may have crossed the physical restore seam
			// without a recorded handle. If a fresh lease is live, reconcile it
			// before requeueing; if no lease ever crossed the arm boundary, the
			// pending root is safe to requeue without inventing a backend stop.
			if currentLease, leaseErr := m.store.GetAcceleratorLease(context.WithoutCancel(ctx), firstNonEmpty(op.CleanupAcceleratorID, op.AcceleratorID)); leaseErr == nil && currentLease != nil {
				if cleanupErr := m.cleanupCheckpointOperation(context.WithoutCancel(ctx), op); cleanupErr != nil {
					m.log.Warn("pending checkpoint recovery cleanup remains fenced", "operation_id", op.ID, "error", cleanupErr)
					continue
				}
				if refreshed, refreshErr := operations.GetLLMCheckpointOperation(context.WithoutCancel(ctx), op.ID); refreshErr == nil {
					op = refreshed
				}
			} else if op.CleanupSlotID < 0 {
				// If no physical operation ever acquired a slot, the arm/pending
				// row is only controller custody.  The fresh unused lease may be
				// absent after a crash or a journal-write rollback; finalize the
				// cleanup row without inventing a node cancel.  A linked row with
				// an assigned slot is deliberately left fenced for retry instead.
				lease := &domain.AcceleratorLease{AcceleratorID: firstNonEmpty(op.CleanupAcceleratorID, op.AcceleratorID), WorkloadID: op.WorkloadID, FencingToken: int64(op.CleanupFence)}
				if _, markErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), op.ID, "confirmed", cleanupJournalHandle(op), m.targetByID(firstNonEmpty(op.CleanupTargetID, op.TargetID)), lease, op.CleanupTerminalDisposition, op.CleanupMessage); markErr != nil {
					m.log.Warn("pending checkpoint recovery custody finalization failed", "operation_id", op.ID, "error", markErr)
					continue
				}
				if refreshed, refreshErr := operations.GetLLMCheckpointOperation(context.WithoutCancel(ctx), op.ID); refreshErr == nil {
					op = refreshed
				}
			} else {
				// A physical compensation row exists but its lease is absent. Do not
				// confirm the outer intent or requeue the victim: the exact node
				// operation still requires authoritative stop/release reconciliation.
				m.log.Warn("pending checkpoint recovery has physical cleanup identity but no verifiable lease", "operation_id", op.ID, "error", leaseErr)
				continue
			}
		}
		// A pending intent has no durable fresh handle. It is therefore not
		// allowed to adopt the stale execution; requeue it for a clean restore.
		updated, mutateErr := m.mutateWorkloadCAS(context.WithoutCancel(ctx), w.Request.ID, workloadStatuses(domain.WorkloadRunning), "", func(current *domain.Workload) error {
			current.Status = domain.WorkloadQueued
			current.Execution = nil
			current.CheckpointRef = op.SnapshotName
			current.StartedAt = nil
			current.FinishedAt = nil
			current.Error = "controller restarted during checkpoint compensation; requeued for durable restore"
			current.Decision = domain.AdmissionDecision{Admitted: false, TargetID: op.TargetID, Blocker: "checkpoint compensation recovered after controller restart", Confidence: .8}
			current.UpdatedAt = time.Now().UTC()
			return nil
		})
		if mutateErr != nil {
			m.log.Warn("checkpoint recovery intent could not requeue workload", "operation_id", op.ID, "workload_id", op.WorkloadID, "error", mutateErr)
			continue
		}
		if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), op.ID, "requeued", updated.Revision); markErr != nil {
			m.log.Warn("checkpoint recovery requeue marker failed", "operation_id", op.ID, "error", markErr)
		}
	}
}

func (m *Manager) recoverCheckpointCleanupIntents(ctx context.Context) {
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return
	}
	rows, err := operations.ListLLMCheckpointOperations(ctx, "")
	if err != nil {
		m.log.Warn("checkpoint cleanup intent listing unavailable", "error", err)
		return
	}
	for _, op := range rows {
		if op == nil || (op.CleanupState != "armed" && op.CleanupState != "pending" && op.CleanupState != "failed" && op.CleanupState != "stopped" && op.CleanupState != "owned") {
			continue
		}
		// Outer-CAS recovery rows are reconciled by
		// recoverCheckpointRecoveryIntents. Their cleanup operation points at a
		// distinct physical :compensate row; letting this generic pass process
		// the outer row again after release can observe an absent lease and turn
		// an already-confirmed cleanup back into failed.
		if op.RecoveryState == "pending" && op.CompensationOf != "" && op.CleanupOperationID != "" && op.CleanupOperationID != op.ID && op.CleanupSlotID < 0 {
			continue
		}
		if enriched, enrichErr := m.resolveCheckpointCleanupIdentity(context.WithoutCancel(ctx), op); enrichErr == nil && enriched != nil {
			op = enriched
		} else if enrichErr != nil {
			m.log.Warn("checkpoint cleanup identity reconciliation remains pending", "operation_id", op.ID, "error", enrichErr)
		}
		workload, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), op.WorkloadID)
		if getErr == nil && workload != nil && workload.Status == domain.WorkloadRunning && op.CleanupHandle != nil && op.CleanupState != "stopped" && checkpointRecoveryHandleMatches(workload.Execution, op.CleanupHandle) {
			lease := &domain.AcceleratorLease{AcceleratorID: firstNonEmpty(op.CleanupAcceleratorID, op.AcceleratorID), WorkloadID: op.WorkloadID, FencingToken: int64(op.CleanupFence)}
			if renewErr := m.store.RenewAcceleratorLease(context.WithoutCancel(ctx), lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); renewErr != nil {
				m.log.Warn("owned checkpoint cleanup fence renewal remains pending", "operation_id", op.ID, "error", renewErr)
			}
			if op.CleanupState != "owned" {
				if _, markErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), op.ID, "owned", op.CleanupHandle, m.targetByID(firstNonEmpty(op.CleanupTargetID, op.TargetID)), &domain.AcceleratorLease{AcceleratorID: firstNonEmpty(op.CleanupAcceleratorID, op.AcceleratorID), WorkloadID: op.WorkloadID, FencingToken: int64(op.CleanupFence)}, op.CleanupTerminalDisposition, op.CleanupMessage); markErr != nil {
					m.log.Warn("checkpoint cleanup ownership marker failed", "operation_id", op.ID, "error", markErr)
				}
			}
			continue
		}
		if cleanupErr := m.cleanupCheckpointOperation(context.WithoutCancel(ctx), op); cleanupErr != nil {
			m.log.Warn("checkpoint cleanup remains fenced after restart", "operation_id", op.ID, "error", cleanupErr)
		}
	}
}

func (m *Manager) cleanupCheckpointOperation(ctx context.Context, op *store.LLMCheckpointOperation) error {
	if op == nil || op.CleanupState == "" || op.CleanupState == "confirmed" {
		return nil
	}
	if enriched, enrichErr := m.resolveCheckpointCleanupIdentity(context.WithoutCancel(ctx), op); enrichErr != nil {
		return m.markCheckpointCleanupFailed(ctx, op, enrichErr)
	} else if enriched != nil {
		op = enriched
	}
	lease := &domain.AcceleratorLease{AcceleratorID: firstNonEmpty(op.CleanupAcceleratorID, op.AcceleratorID), WorkloadID: op.WorkloadID, FencingToken: int64(op.CleanupFence)}
	if lease.AcceleratorID == "" || lease.FencingToken <= 0 {
		return m.markCheckpointCleanupFailed(ctx, op, fmt.Errorf("checkpoint cleanup lease identity is incomplete"))
	}
	target := m.targetByID(firstNonEmpty(op.CleanupTargetID, op.TargetID))
	targetRegistered := target.ID != ""
	if !targetRegistered {
		target = Target{ID: firstNonEmpty(op.CleanupTargetID, op.TargetID), NodeID: firstNonEmpty(op.CleanupNodeID, op.NodeID), Adapter: ""}
	}
	if current, getErr := m.store.GetAcceleratorLease(ctx, lease.AcceleratorID); getErr != nil || current == nil || current.WorkloadID != lease.WorkloadID || current.FencingToken != lease.FencingToken {
		if errors.Is(getErr, store.ErrNotFound) && op.CleanupState == "stopped" {
			// The manager durably recorded stop confirmation before its release
			// request. An absent exact lease now proves that release completed;
			// do not turn this safe terminal seam into a permanent fence.
			confirmed, markErr := m.recordCheckpointCleanupState(ctx, op.ID, "confirmed", cleanupJournalHandle(op), target, lease, op.CleanupTerminalDisposition, op.CleanupMessage)
			if markErr != nil {
				return markErr
			}
			if confirmed != nil {
				op = confirmed
			}
			// A generic lease-cleanup retry may win the release race before this
			// checkpoint pass runs. Finish the same terminal disposition here so
			// an absent lease cannot leave the workload queued forever.
			if workload, workloadErr := m.store.GetWorkload(context.WithoutCancel(ctx), op.WorkloadID); workloadErr == nil && workload != nil && !isTerminalWorkloadStatus(workload.Status) {
				if op.CleanupTerminalDisposition == "failure" {
					m.fail(context.WithoutCancel(ctx), workload, op.CleanupMessage)
				} else if op.CleanupTerminalDisposition == "cancel" {
					m.markStreamCancelled(op.WorkloadID, op.CleanupMessage)
				}
			}
			return nil
		}
		if getErr == nil {
			getErr = fmt.Errorf("live lease belongs to another owner or fence")
		}
		if errors.Is(getErr, store.ErrNotFound) {
			getErr = fmt.Errorf("cleanup lease is absent; stop cannot be proven")
		}
		return m.markCheckpointCleanupFailed(ctx, op, getErr)
	}
	// Keep the exact fence alive while an offline node or a controller restart
	// is being reconciled. Admission must see this same tuple until release is
	// confirmed below.
	if renewErr := m.store.RenewAcceleratorLease(ctx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); renewErr != nil {
		return m.markCheckpointCleanupFailed(ctx, op, fmt.Errorf("renew checkpoint cleanup fence: %w", renewErr))
	}
	if !targetRegistered && op.CleanupState != "stopped" {
		return m.markCheckpointCleanupFailed(ctx, op, fmt.Errorf("checkpoint cleanup target is unavailable"))
	}
	var adapter Adapter
	if op.CleanupState != "stopped" {
		m.mu.RLock()
		adapter = m.adapters[target.Adapter]
		m.mu.RUnlock()
		if adapter == nil {
			return m.markCheckpointCleanupFailed(ctx, op, fmt.Errorf("checkpoint cleanup adapter %s is unavailable", target.Adapter))
		}
		// The outer recovery row is not a physical node operation. Never
		// synthesize a cancel for slot -1; wait for the exact :compensate row.
		if op.CleanupOperationID == "" || op.CleanupGeneration == 0 || op.CleanupFence == 0 || op.CleanupConversationID == "" || (op.CleanupSlotID < 0 && op.CleanupHandle == nil && op.RecoveryHandle == nil) {
			return m.markCheckpointCleanupFailed(ctx, op, fmt.Errorf("physical checkpoint compensation cleanup identity is not yet durable"))
		}
	}
	handle := cleanupJournalHandle(op)
	if op.CleanupState != "stopped" {
		if handle == nil {
			return m.markCheckpointCleanupFailed(ctx, op, fmt.Errorf("checkpoint cleanup handle is unavailable"))
		}
		cleanupCtx, cancel := leaseCleanupContext(ctx)
		cancelErr := adapter.Cancel(cleanupCtx, handle, target)
		cancel()
		if cancelErr != nil {
			return m.markCheckpointCleanupFailed(ctx, op, fmt.Errorf("checkpoint cleanup cancel (stop unconfirmed): %w", cancelErr))
		}
		// Stop confirmation is its own durable boundary.  A release outcome can
		// be ambiguous across a controller crash; recording stopped first lets a
		// restart finish only the idempotent lease release without ever guessing
		// that a live backend disappeared.
		stopped, stoppedErr := m.recordCheckpointCleanupState(ctx, op.ID, "stopped", handle, target, lease, op.CleanupTerminalDisposition, op.CleanupMessage)
		if stoppedErr != nil {
			return stoppedErr
		}
		op = stopped
	}
	if releaseErr := m.rollbackAcceleratorLease(ctx, lease, lease.WorkloadID); releaseErr != nil {
		// The physical backend stop was already durably recorded above.  A
		// transient lease-store failure cannot roll that boundary back to
		// failed: doing so would make a restart issue a second backend cancel
		// or lose the fact that admission may safely wait only on the lease
		// release.  Keep the stopped row authoritative and let the generic
		// exact-fence cleanup intent/periodic pass retry the idempotent release.
		pendingMessage := fmt.Sprintf("lease release pending after confirmed stop: %v", releaseErr)
		if len(pendingMessage) > 2048 {
			pendingMessage = pendingMessage[:2048]
		}
		if stopped, markErr := m.recordCheckpointCleanupState(ctx, op.ID, "stopped", handle, target, lease, op.CleanupTerminalDisposition, pendingMessage); markErr == nil && stopped != nil {
			op = stopped
		} else if markErr != nil {
			m.log.Warn("checkpoint cleanup stopped marker could not retain release diagnostic", "operation_id", op.ID, "error", markErr)
		}
		return fmt.Errorf("checkpoint cleanup lease release remains pending after confirmed stop: %w", releaseErr)
	}
	if _, markErr := m.recordCheckpointCleanupState(ctx, op.ID, "confirmed", handle, target, lease, op.CleanupTerminalDisposition, op.CleanupMessage); markErr != nil {
		return markErr
	}
	if workload, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), op.WorkloadID); getErr == nil && workload != nil && !isTerminalWorkloadStatus(workload.Status) {
		if op.CleanupTerminalDisposition == "failure" {
			m.fail(context.WithoutCancel(ctx), workload, op.CleanupMessage)
		} else if op.CleanupTerminalDisposition == "cancel" {
			m.markStreamCancelled(op.WorkloadID, op.CleanupMessage)
		}
	}
	return nil
}

// resolveCheckpointCleanupIdentity joins the controller custody row to the
// physical node operation created by RestoreWithRuntimeProof.  The outer
// recovery row is intentionally not sufficient: native cancel authorization
// requires the compensation operation id, assigned slot, conversation, exact
// generation, and fresh fence.  This lookup is idempotent and is retried by
// the periodic cleanup worker while an offline node or a controller crash
// delays creation/observation of the linked physical row.
func (m *Manager) resolveCheckpointCleanupIdentity(ctx context.Context, op *store.LLMCheckpointOperation) (*store.LLMCheckpointOperation, error) {
	if op == nil || op.CleanupState == "confirmed" {
		return op, nil
	}
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return op, nil
	}
	if op.CleanupOperationID != "" && op.CleanupSlotID >= 0 && op.CleanupFence > 0 && op.CleanupGeneration > 0 && op.CleanupConversationID != "" {
		return op, nil
	}
	var candidate *store.LLMCheckpointOperation
	if op.CleanupOperationID != "" && op.CleanupOperationID != op.ID {
		if exact, getErr := operations.GetLLMCheckpointOperation(ctx, op.CleanupOperationID); getErr == nil {
			if exact.WorkloadID == op.WorkloadID && exact.TargetID == op.TargetID && exact.SlotID >= 0 && (op.CleanupFence == 0 || exact.Fence == op.CleanupFence) && (op.CleanupGeneration == 0 || exact.Generation == op.CleanupGeneration) {
				candidate = exact
			}
		} else if !errors.Is(getErr, store.ErrNotFound) {
			return op, getErr
		}
	}
	if candidate == nil {
		rows, listErr := operations.ListLLMCheckpointOperations(ctx, "")
		if listErr != nil {
			return op, listErr
		}
		for _, row := range rows {
			if row == nil || row.ID == op.ID || row.WorkloadID != op.WorkloadID || row.TargetID != op.TargetID || row.SlotID < 0 {
				continue
			}
			if op.CleanupOperationID != "" && row.ID != op.CleanupOperationID {
				continue
			}
			if op.CompensationOf != "" && row.CompensationOf != op.CompensationOf {
				continue
			}
			if op.CleanupFence > 0 && row.Fence != op.CleanupFence {
				continue
			}
			if op.CleanupGeneration > 0 && row.Generation != op.CleanupGeneration {
				continue
			}
			if candidate == nil || row.UpdatedAt.After(candidate.UpdatedAt) {
				candidate = row
			}
		}
	}
	if candidate == nil || candidate.SlotID < 0 {
		return op, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		current, getErr := operations.GetLLMCheckpointOperation(ctx, op.ID)
		if getErr != nil {
			return op, getErr
		}
		current.CleanupOperationID = candidate.ID
		current.CleanupSlotID = candidate.SlotID
		current.CleanupGeneration = candidate.Generation
		current.CleanupFence = candidate.Fence
		current.CleanupAcceleratorID = candidate.AcceleratorID
		current.CleanupTargetID = candidate.TargetID
		current.CleanupNodeID = candidate.NodeID
		current.CleanupConversationID = candidate.ConversationID
		current.CleanupContinuationConversationID = candidate.ContinuationConversationID
		if candidate.CleanupHandle != nil {
			current.CleanupHandle = cloneCheckpointHandle(candidate.CleanupHandle)
		}
		updated, updateErr := operations.UpdateLLMCheckpointOperation(ctx, current, current.Revision)
		if updateErr == nil {
			return updated, nil
		}
		if !errors.Is(updateErr, store.ErrLLMCheckpointConflict) && !errors.Is(updateErr, store.ErrWorkloadConflict) {
			return op, updateErr
		}
	}
	return op, fmt.Errorf("checkpoint cleanup identity update conflicted")
}

func (m *Manager) markCheckpointCleanupFailed(ctx context.Context, op *store.LLMCheckpointOperation, cause error) error {
	if op == nil {
		return cause
	}
	target := m.targetByID(firstNonEmpty(op.CleanupTargetID, op.TargetID))
	lease := &domain.AcceleratorLease{AcceleratorID: firstNonEmpty(op.CleanupAcceleratorID, op.AcceleratorID), WorkloadID: op.WorkloadID, FencingToken: int64(op.CleanupFence)}
	message := "checkpoint cleanup failed"
	if cause != nil {
		message = cause.Error()
	}
	if _, markErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), op.ID, "failed", cleanupJournalHandle(op), target, lease, op.CleanupTerminalDisposition, message); markErr != nil {
		return errors.Join(cause, markErr)
	}
	return cause
}

func checkpointRecoveryHandleMatches(actual, expected *domain.ExecutionHandle) bool {
	return actual != nil && expected != nil && actual.ExternalID != "" && actual.ExternalID == expected.ExternalID && bytes.Equal(actual.Opaque, expected.Opaque)
}

func cloneCheckpointHandle(handle *domain.ExecutionHandle) *domain.ExecutionHandle {
	if handle == nil {
		return nil
	}
	copy := *handle
	copy.Opaque = append([]byte(nil), handle.Opaque...)
	if handle.Performance != nil {
		performance := *handle.Performance
		copy.Performance = &performance
	}
	return &copy
}

func checkpointOperationIDFromHandle(handle *domain.ExecutionHandle) string {
	binding, ok := checkpointHandleBinding(handle)
	if !ok {
		return ""
	}
	return strings.TrimSpace(binding.OperationID)
}

type checkpointBindingFields struct {
	SlotID                     int    `json:"slot_id"`
	Generation                 uint64 `json:"generation"`
	Fence                      uint64 `json:"fence"`
	AcceleratorID              string `json:"accelerator_id"`
	ConversationID             string `json:"conversation_id"`
	ContinuationConversationID string `json:"continuation_conversation_id"`
	OperationID                string `json:"operation_id"`
	NodeID                     string `json:"node_id"`
	OwnerID                    string `json:"owner_id"`
	WorkloadID                 string `json:"workload_id"`
	SnapshotName               string `json:"snapshot_name"`
	Resumed                    bool   `json:"resumed"`
}

func checkpointHandleBinding(handle *domain.ExecutionHandle) (checkpointBindingFields, bool) {
	if handle == nil || len(handle.Opaque) == 0 {
		return checkpointBindingFields{}, false
	}
	var binding checkpointBindingFields
	if err := json.Unmarshal(handle.Opaque, &binding); err != nil || strings.TrimSpace(binding.OperationID) == "" {
		return checkpointBindingFields{}, false
	}
	return binding, true
}

func cleanupJournalHandle(op *store.LLMCheckpointOperation) *domain.ExecutionHandle {
	if op == nil {
		return nil
	}
	if op.CleanupHandle != nil {
		return cloneCheckpointHandle(op.CleanupHandle)
	}
	if op.RecoveryHandle != nil {
		return cloneCheckpointHandle(op.RecoveryHandle)
	}
	// A crash can occur after the durable restore phase but before the HTTP
	// response publishes a handle. Reconstruct a signed binding from the
	// durable operation so recovery can still issue one exact cancel. Native
	// HTTP adapters intentionally accept the http-run prefix as their restart
	// fallback and use the opaque binding for node authorization.
	if op.CleanupState == "armed" || op.CleanupState == "owned" || op.CleanupState == "pending" || op.CleanupState == "failed" || op.CleanupState == "stopped" {
		slotID := op.CleanupSlotID
		if slotID < 0 {
			slotID = op.SlotID
		}
		generation := op.CleanupGeneration
		if generation == 0 {
			generation = op.Generation
		}
		fence := op.CleanupFence
		if fence == 0 {
			fence = op.Fence
		}
		operationID := firstNonEmpty(op.CleanupOperationID, op.ID)
		conversation := firstNonEmpty(op.CleanupContinuationConversationID, op.ContinuationConversationID)
		if conversation == "" {
			conversation = firstNonEmpty(op.CleanupConversationID, op.ConversationID)
		}
		opaque, _ := json.Marshal(map[string]any{
			"slot_id": slotID, "accelerator_id": firstNonEmpty(op.CleanupAcceleratorID, op.AcceleratorID),
			"generation": generation, "fence": fence, "conversation_id": conversation,
			"continuation_conversation_id": firstNonEmpty(op.CleanupContinuationConversationID, op.ContinuationConversationID),
			"operation_id":                 operationID, "node_id": firstNonEmpty(op.CleanupNodeID, op.NodeID),
			"owner_id": op.OwnerID, "workload_id": op.WorkloadID, "snapshot_name": op.SnapshotName,
			"resumed": true,
		})
		return &domain.ExecutionHandle{ExternalID: "http-run-recovery-" + operationID, Opaque: opaque, StartedAt: op.UpdatedAt}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// prepareResumeCleanupJournal establishes durable cleanup custody before a
// resumed adapter is allowed to send its first restore command. It is also
// idempotent with the operation row created by HTTPAdapter's coordinator.
func (m *Manager) prepareResumeCleanupJournal(ctx context.Context, w *domain.Workload, target Target, reservation *targetReservation, checkpoint string) (*store.LLMCheckpointOperation, error) {
	if w == nil || w.Plan == nil || reservation == nil || reservation.lease == nil || strings.TrimSpace(checkpoint) == "" {
		return nil, fmt.Errorf("checkpoint cleanup journal identity is incomplete")
	}
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return nil, fmt.Errorf("checkpoint cleanup journal store is unavailable")
	}
	lease := reservation.lease
	generation := reservation.targetGeneration
	if generation == 0 {
		generation = uint64(lease.FencingToken)
	}
	if generation == 0 {
		generation = 1
	}
	nodeID := firstNonEmpty(target.NodeID, target.ID)
	runtimeIdentity := firstNonEmpty(target.RuntimeIdentity, target.ID, "runtime")
	model := firstNonEmpty(w.Plan.ModelFingerprint, target.ModelFingerprint, "unknown-model")
	profile := firstNonEmpty(w.Plan.ProfileDigest, target.ActiveRuntimeProfile, "unknown-profile")
	contextLimit := w.Plan.TargetContextLimit
	if contextLimit <= 0 {
		contextLimit = target.ContextLimit
	}
	if contextLimit <= 0 {
		contextLimit = 1
	}
	operationID := "restore:" + w.Request.ID + ":" + checkpoint
	command := withCheckpointConversation(CheckpointCommand{ID: operationID, IdempotencyKey: operationID, OwnerID: w.Request.OwnerID, WorkloadID: w.Request.ID, WorkloadRevision: w.Revision, Generation: generation, RuntimeIdentity: runtimeIdentity, ModelFingerprint: model, ProfileFingerprint: profile, ContextLimit: contextLimit, Fence: uint64(lease.FencingToken), SnapshotName: checkpoint})
	var op *store.LLMCheckpointOperation
	if existing, getErr := operations.GetLLMCheckpointOperation(ctx, operationID); getErr == nil {
		op = existing
	} else if !errors.Is(getErr, store.ErrNotFound) {
		return nil, getErr
	}
	if op == nil {
		created, _, createErr := operations.CreateLLMCheckpointOperation(ctx, &store.LLMCheckpointOperation{
			ID: command.ID, IdempotencyKey: command.IdempotencyKey, OwnerID: command.OwnerID, WorkloadID: command.WorkloadID,
			NodeID: nodeID, AcceleratorID: lease.AcceleratorID, TargetID: target.ID, SlotID: -1, Generation: command.Generation,
			Fence: command.Fence, RuntimeIdentity: command.RuntimeIdentity, Model: model, ModelFingerprint: model,
			ProfileFingerprint: profile, ContextFingerprint: fmt.Sprintf("ctx:%d", contextLimit), ConversationID: command.ConversationID,
			ContinuationConversationID: command.ContinuationConversationID, WorkloadRevision: command.WorkloadRevision,
			SnapshotName: checkpoint, Phase: "restore_planned", PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), RecoveryState: "pending",
			CleanupOperationID: command.ID, CleanupSlotID: -1, CleanupConversationID: command.ConversationID, CleanupContinuationConversationID: command.ContinuationConversationID,
			CleanupState: "armed", CleanupTargetID: target.ID, CleanupNodeID: nodeID, CleanupAcceleratorID: lease.AcceleratorID,
			CleanupGeneration: generation, CleanupFence: command.Fence,
		})
		if createErr != nil {
			if existing, getErr := operations.GetLLMCheckpointOperation(ctx, operationID); getErr == nil {
				op = existing
			} else {
				return nil, createErr
			}
		} else {
			op = created
		}
	}
	if op == nil || op.ID == "" {
		return nil, fmt.Errorf("checkpoint cleanup journal returned no durable identity")
	}
	if reservation != nil {
		reservation.checkpointOperationID = op.ID
	}
	// An already terminalized operation is not a live cleanup custody. A
	// restart may safely observe it without reopening its lifecycle.
	if op.CleanupState == "confirmed" {
		return op, nil
	}
	updated, err := m.recordCheckpointCleanupState(ctx, op.ID, "armed", nil, target, lease, "", "")
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (m *Manager) recordCheckpointCleanupState(ctx context.Context, operationID, state string, handle *domain.ExecutionHandle, target Target, lease *domain.AcceleratorLease, disposition, message string) (*store.LLMCheckpointOperation, error) {
	if operationID == "" || lease == nil {
		return nil, fmt.Errorf("checkpoint cleanup state identity is incomplete")
	}
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return nil, fmt.Errorf("checkpoint cleanup journal store is unavailable")
	}
	cleanupCtx, cancel := leaseCleanupContext(ctx)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		op, err := operations.GetLLMCheckpointOperation(cleanupCtx, operationID)
		if err != nil {
			return nil, err
		}
		if op.CleanupState == state && (handle == nil || checkpointRecoveryHandleMatches(op.CleanupHandle, handle)) && (message == "" || op.CleanupMessage == message) {
			return op, nil
		}
		generation := op.CleanupGeneration
		if generation == 0 {
			generation = op.Generation
		}
		if generation == 0 {
			generation = uint64(lease.FencingToken)
		}
		if generation == 0 {
			generation = 1
		}
		priorHandle := cloneCheckpointHandle(op.CleanupHandle)
		op.CleanupState = state
		if handle != nil {
			op.CleanupHandle = cloneCheckpointHandle(handle)
		} else if state == "confirmed" {
			op.CleanupHandle = priorHandle
		} else {
			op.CleanupHandle = priorHandle
		}
		op.CleanupTargetID = firstNonEmpty(target.ID, op.TargetID)
		op.CleanupNodeID = firstNonEmpty(target.NodeID, op.NodeID, op.CleanupNodeID)
		op.CleanupAcceleratorID = firstNonEmpty(lease.AcceleratorID, op.CleanupAcceleratorID, op.AcceleratorID)
		op.CleanupGeneration = generation
		op.CleanupFence = uint64(lease.FencingToken)
		if op.CleanupFence == 0 {
			op.CleanupFence = op.RecoveryFence
		}
		if binding, bindingOK := checkpointHandleBinding(handle); bindingOK {
			if binding.OperationID != "" {
				op.CleanupOperationID = binding.OperationID
			}
			if binding.SlotID >= 0 {
				op.CleanupSlotID = binding.SlotID
			}
			if binding.Generation > 0 {
				op.CleanupGeneration = binding.Generation
			}
			if binding.Fence > 0 {
				op.CleanupFence = binding.Fence
			}
			if binding.ConversationID != "" {
				op.CleanupConversationID = binding.ConversationID
			}
			if binding.ContinuationConversationID != "" {
				op.CleanupContinuationConversationID = binding.ContinuationConversationID
			}
		}
		if op.CleanupOperationID == "" {
			op.CleanupOperationID = op.ID
		}
		// An ownership/stop transition often carries no new terminal
		// disposition. Preserve the durable intent in that case: clearing a
		// previously recorded failure/cancel here would make a later retry lose
		// the requested projection finalization after a restart.
		if disposition != "" {
			op.CleanupTerminalDisposition = disposition
		}
		if message != "" {
			op.CleanupMessage = message
		}
		updated, updateErr := operations.UpdateLLMCheckpointOperation(cleanupCtx, op, op.Revision)
		if updateErr == nil {
			return updated, nil
		}
		if !errors.Is(updateErr, store.ErrLLMCheckpointConflict) && !errors.Is(updateErr, store.ErrWorkloadConflict) {
			return nil, updateErr
		}
	}
	return nil, fmt.Errorf("checkpoint cleanup journal update conflicted")
}

// cancelCheckpointRecoveryHandle is the restart-safe terminal path for a
// restored handle that cannot be adopted. It requires the exact fresh fence
// recorded in the intent and leaves the intent pending if either physical
// cancellation or lease release cannot be confirmed.
func (m *Manager) cancelCheckpointRecoveryHandle(ctx context.Context, op *store.LLMCheckpointOperation) error {
	if op == nil || (op.RecoveryHandle == nil && op.CleanupHandle == nil) || (op.RecoveryFence == 0 && op.CleanupFence == 0) || (op.RecoveryAcceleratorID == "" && op.CleanupAcceleratorID == "") {
		return fmt.Errorf("checkpoint recovery fresh cleanup identity is incomplete")
	}
	target := m.targetByID(op.TargetID)
	if target.ID == "" {
		return fmt.Errorf("checkpoint recovery target %s is unavailable", op.TargetID)
	}
	handle := op.RecoveryHandle
	if handle == nil {
		handle = cleanupJournalHandle(op)
	}
	acceleratorID := firstNonEmpty(op.RecoveryAcceleratorID, op.CleanupAcceleratorID)
	fence := op.RecoveryFence
	if fence == 0 {
		fence = op.CleanupFence
	}
	lease := &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: op.WorkloadID, FencingToken: int64(fence)}
	cleanupCtx, cancel := leaseCleanupContext(ctx)
	defer cancel()
	if current, getErr := m.store.GetAcceleratorLease(cleanupCtx, acceleratorID); getErr != nil || current == nil || current.WorkloadID != lease.WorkloadID || current.FencingToken != lease.FencingToken {
		if getErr == nil {
			getErr = fmt.Errorf("live lease belongs to another owner or fence")
		}
		return m.markCheckpointRecoveryIntentFailed(cleanupCtx, op.ID, fmt.Errorf("checkpoint recovery cleanup fence is not verifiable: %w", getErr))
	}
	if renewErr := m.store.RenewAcceleratorLease(cleanupCtx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); renewErr != nil {
		return m.markCheckpointRecoveryIntentFailed(cleanupCtx, op.ID, fmt.Errorf("renew restored checkpoint fence: %w", renewErr))
	}
	// CleanupState=stopped is a durable physical boundary.  Restart recovery
	// must never issue a second node cancel, even when the workload projection
	// still looks like the restored handle is running; only exact-fence lease
	// release/finalization remains.
	if op.CleanupState != "stopped" {
		m.mu.RLock()
		adapter := m.adapters[target.Adapter]
		m.mu.RUnlock()
		if adapter == nil {
			return fmt.Errorf("checkpoint recovery adapter %s is unavailable", target.Adapter)
		}
		if err := adapter.Cancel(cleanupCtx, handle, target); err != nil {
			cleanupErr := fmt.Errorf("cancel restored handle (stop unconfirmed): %w", err)
			if markErr := m.markCheckpointRecoveryIntentFailed(cleanupCtx, op.ID, cleanupErr); markErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record failed checkpoint cleanup: %w", markErr))
			}
			return cleanupErr
		}
		if stopped, stopErr := m.recordCheckpointCleanupState(cleanupCtx, op.ID, "stopped", handle, target, lease, op.CleanupTerminalDisposition, op.CleanupMessage); stopErr != nil {
			return stopErr
		} else if stopped != nil {
			op = stopped
		}
	}
	if err := m.rollbackAcceleratorLease(cleanupCtx, lease, lease.WorkloadID); err != nil {
		cleanupErr := fmt.Errorf("release restored fence after confirmed stop: %w", err)
		// The stopped marker is authoritative.  Keep RecoveryState retryable as
		// well: changing it to failed here sends restart recovery back through
		// the physical-cancel branch and can duplicate the node operation.
		if operations, ok := m.store.(store.LLMCheckpointOperationStore); ok {
			if current, getErr := operations.GetLLMCheckpointOperation(cleanupCtx, op.ID); getErr == nil && current.CleanupState == "stopped" {
				if _, markErr := m.recordCheckpointCleanupState(cleanupCtx, op.ID, "stopped", handle, target, lease, current.CleanupTerminalDisposition, "lease release pending after confirmed stop: "+err.Error()); markErr != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record stopped checkpoint cleanup: %w", markErr))
				}
			} else if markErr := m.markCheckpointRecoveryIntentFailed(cleanupCtx, op.ID, cleanupErr); markErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record failed checkpoint lease cleanup: %w", markErr))
			}
		} else if markErr := m.markCheckpointRecoveryIntentFailed(cleanupCtx, op.ID, cleanupErr); markErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record failed checkpoint lease cleanup: %w", markErr))
		}
		return cleanupErr
	}
	if _, markErr := m.recordCheckpointCleanupState(cleanupCtx, op.ID, "confirmed", handle, target, lease, op.CleanupTerminalDisposition, op.CleanupMessage); markErr != nil {
		return markErr
	}
	m.clearCheckpointCompensationLease(lease, lease.WorkloadID, target.ID)
	return nil
}

// Close stops manager-owned recovery work. The controller calls this during
// shutdown after cancelling its signal context, making registration and
// recovery lifetimes explicit and preventing post-close store writes.
func (m *Manager) Close() {
	m.lifecycleMu.Lock()
	if m.lifecycleClosed {
		m.lifecycleMu.Unlock()
		return
	}
	m.lifecycleClosed = true
	if m.managerCancel != nil {
		m.managerCancel()
	}
	m.lifecycleMu.Unlock()
	m.mu.Lock()
	for id, cancel := range m.cancels {
		if cancel != nil {
			cancel()
		}
		delete(m.cancels, id)
	}
	for id, pending := range m.pendingStreams {
		if pending != nil && pending.timer != nil {
			m.stopPendingStreamTimer(pending)
		}
		if pending != nil && pending.cancel != nil {
			pending.cancel()
		}
		delete(m.pendingStreams, id)
	}
	m.mu.Unlock()
	m.recoveryWG.Wait()
	m.loopWG.Wait()
	m.asyncWG.Wait()
}

// trackAsync reserves a manager-owned goroutine/timer slot before Close can
// begin waiting. Once lifecycleClosed is set no new asynchronous callback may
// be installed, eliminating Add-after-Wait races.
func (m *Manager) trackAsync() bool {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.lifecycleClosed {
		return false
	}
	m.asyncWG.Add(1)
	return true
}

func (m *Manager) untrackAsync() { m.asyncWG.Done() }

func (m *Manager) residencyRecoveryLoop(ctx context.Context) {
	defer m.recoveryWG.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	recover := func() {
		m.retryBudgetIntents(ctx)
		releaseOperation, operationErr := m.beginResidencyOperation(ctx)
		if operationErr != nil {
			return
		}
		defer releaseOperation()
		m.initializeResidencyRecovery(ctx)
		m.recoverRegisteredResidencyTransitions(ctx)
	}
	// Run once immediately without making Manager.Start block on an external
	// node; subsequent attempts remain durable and cancellable.
	recover()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recover()
		case <-m.recoveryWake:
			recover()
		}
	}
}

func (m *Manager) loop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.retryBudgetIntents(ctx)
			m.retryAcceleratorLeaseCleanupIntents(ctx)
			m.retryInMemoryLeaseReleases(ctx)
			m.recoverCheckpointRecoveryIntents(ctx)
			m.recoverCheckpointCleanupIntents(ctx)
			m.reconcile(ctx)
			m.reconcileResidency(ctx)
		case <-m.kick:
			m.reconcile(ctx)
		}
	}
}

func (m *Manager) retryInMemoryLeaseReleases(ctx context.Context) {
	m.mu.RLock()
	reservations := make([]*targetReservation, 0)
	for _, reservation := range m.reservations {
		if reservation == nil {
			continue
		}
		m.placementMu.Lock()
		releasePending := reservation.releaseRequested && !reservation.released
		m.placementMu.Unlock()
		if releasePending {
			reservations = append(reservations, reservation)
		}
	}
	m.mu.RUnlock()
	for _, reservation := range reservations {
		m.placementMu.Lock()
		stopPending := reservation.backendStopPending && !reservation.released
		adapter := reservation.backendAdapter
		target := reservation.backendTarget
		handle := reservation.backendHandle
		m.placementMu.Unlock()
		if stopPending {
			if handle == nil && adapter != nil {
				// The backend returned no cancellable handle. Keep the fresh
				// capacity fence indefinitely rather than guessing that stop
				// succeeded and allowing lease reuse.
				m.log.Warn("backend stop cleanup has no handle; accelerator remains fenced", "workload_id", reservation.workloadID)
				continue
			}
			if stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target); stopErr != nil {
				m.log.Warn("backend stop cleanup retry failed; accelerator remains fenced", "workload_id", reservation.workloadID, "error", stopErr)
				continue
			}
			m.confirmReservationBackendStopped(reservation)
		}
		m.placementMu.Lock()
		releasePending := reservation.releaseRequested && !reservation.released
		terminalDisposition := reservation.backendCleanupTerminal
		cleanupMessage := reservation.backendCleanupMessage
		m.placementMu.Unlock()
		if !releasePending {
			continue
		}
		m.placementMu.Lock()
		checkpointOperationID := reservation.checkpointOperationID
		cleanupTarget := reservation.backendTarget
		cleanupHandle := reservation.backendHandle
		stopConfirmed := reservation.backendStopConfirmed
		m.placementMu.Unlock()
		if checkpointOperationID != "" && stopConfirmed {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), checkpointOperationID, "stopped", cleanupHandle, cleanupTarget, reservation.lease, terminalDisposition, cleanupMessage); journalErr != nil {
				m.log.Warn("checkpoint cleanup stop marker failed; lease remains fenced", "workload_id", reservation.workloadID, "error", journalErr)
				continue
			}
		}
		if err := m.releaseTarget(ctx, reservation); err != nil {
			m.log.Warn("in-memory accelerator lease cleanup retry failed", "workload_id", reservation.workloadID, "error", err)
			continue
		}
		if checkpointOperationID != "" {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), checkpointOperationID, "confirmed", cleanupHandle, cleanupTarget, reservation.lease, terminalDisposition, cleanupMessage); journalErr != nil {
				m.log.Warn("checkpoint cleanup release marker deferred after exact lease release", "workload_id", reservation.workloadID, "error", journalErr)
			}
		}
		if terminalDisposition == "failure" {
			if current, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), reservation.workloadID); getErr == nil && !isTerminalWorkloadStatus(current.Status) {
				m.fail(context.WithoutCancel(ctx), current, cleanupMessage)
			}
		} else if terminalDisposition == "cancel" {
			m.markStreamCancelled(reservation.workloadID, cleanupMessage)
		}
		m.mu.Lock()
		pending, ok := m.pendingLeaseFinalizations[reservation.workloadID]
		if ok {
			delete(m.pendingLeaseFinalizations, reservation.workloadID)
		}
		m.mu.Unlock()
		if ok && pending.workload != nil {
			if err := m.finalizeTerminalLeaseIntent(ctx, &domain.AcceleratorLeaseCleanupIntent{WorkloadID: pending.workload.Request.ID, ExpectedWorkloadRevision: pending.workload.Revision, Owner: reservation.lease.WorkloadID, TerminalDisposition: pending.disposition, TerminalErrorCode: "terminal_" + pending.disposition, ReleaseConfirmed: true}); err != nil {
				m.mu.Lock()
				m.pendingLeaseFinalizations[reservation.workloadID] = pending
				m.mu.Unlock()
			}
		}
	}
}

func (m *Manager) retryBudgetIntents(ctx context.Context) {
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		m.log.Warn("budget intent scan failed; durable intents remain for next retry", "error", err)
		return
	}
	for _, workload := range rows {
		if workload == nil {
			continue
		}
		if workload.BudgetCleanupToken != "" {
			if err := m.retryBudgetCleanupIntent(ctx, workload); err != nil {
				m.log.Warn("budget cleanup intent retry failed", "workload_id", workload.Request.ID, "error", err)
			}
		}
		if workload.BudgetSettlementPending {
			if err := m.retryBudgetSettlementIntent(ctx, workload); err != nil {
				m.log.Warn("budget settlement intent retry failed", "workload_id", workload.Request.ID, "error", err)
			}
		}
	}
}

func (m *Manager) signal() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// NotifyResidencyRecovery wakes the durable residency worker after an
// externally observed node reconnect/readiness event.
func (m *Manager) NotifyResidencyRecovery() {
	m.lifecycleMu.Lock()
	started := m.recoveryStarted
	m.lifecycleMu.Unlock()
	if !started {
		return
	}
	select {
	case m.recoveryWake <- struct{}{}:
	default:
	}
}

func newID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func (m *Manager) Submit(ctx context.Context, req domain.WorkloadRequest) (*domain.Workload, bool, error) {
	if req.ID == "" {
		req.ID = newID("wl")
	}
	if req.OwnerID == "" {
		return nil, false, fmt.Errorf("owner_id is required")
	}
	if req.ItemID == "" {
		req.ItemID = req.ID
	}
	if req.OperationVersion == "" {
		req.OperationVersion = "v1"
	}
	if req.QoS == "" {
		req.QoS = domain.QoSNormal
	}
	if req.QueuePolicy == "" {
		req.QueuePolicy = domain.QueueWait
	}
	if req.Disruption == "" {
		req.Disruption = domain.DisruptionLocked
	}
	if req.Egress == "" {
		req.Egress = domain.EgressLocalOnly
	}
	if req.PlacementPolicy == "" {
		req.PlacementPolicy = domain.PlacementBestFit
	}
	if req.TransformationPolicy == "" {
		req.TransformationPolicy = domain.TransformAsk
	}
	if req.Plane == domain.PlaneCreatorStudio {
		if req.Operation == "" {
			return nil, false, fmt.Errorf("operation is required for Creator Studio workloads")
		}
		if req.QualityClass != "preview" && req.QualityClass != "final" {
			return nil, false, fmt.Errorf("quality_class must be preview or final")
		}
		if req.LatencyClass != "interactive" && req.LatencyClass != "batch" && req.LatencyClass != "background" {
			return nil, false, fmt.Errorf("latency_class must be interactive, batch, or background")
		}
	}
	if req.PlacementPolicy != domain.PlacementBestFit && req.PlacementPolicy != domain.PlacementSticky {
		return nil, false, fmt.Errorf("unsupported placement_policy %q", req.PlacementPolicy)
	}
	if req.PlacementPolicy == domain.PlacementSticky && req.PlacementKey == "" {
		return nil, false, fmt.Errorf("placement_key is required for sticky placement")
	}
	if req.TransformationPolicy != domain.TransformAsk && req.TransformationPolicy != domain.TransformNever && req.TransformationPolicy != domain.TransformDelegateSafeReview {
		return nil, false, fmt.Errorf("unsupported transformation_policy %q", req.TransformationPolicy)
	}
	if len(req.Transformations) > 0 && req.TransformationPolicy == domain.TransformNever {
		return nil, false, fmt.Errorf("transformations are forbidden by transformation_policy=never")
	}
	if req.Bounds.ContextTokens < 0 || req.Bounds.MaxOutput < 0 {
		return nil, false, fmt.Errorf("context_tokens and max_output must be non-negative")
	}
	if err := m.validateNotificationPreferences(req.Notifications); err != nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	req.CreatedAt = now

	m.mu.RLock()
	adapter := m.adapters[req.Adapter]
	m.mu.RUnlock()
	if adapter == nil {
		return nil, false, fmt.Errorf("unknown adapter %q", req.Adapter)
	}
	if capabilities, ok := adapter.(DisruptionCapabilityAdapter); ok {
		supported := capabilities.DisruptionCapabilities()
		if _, targetSpecific := adapter.(TargetDisruptionCapabilityAdapter); targetSpecific {
			m.mu.RLock()
			for _, target := range m.targets {
				if target.Adapter != req.Adapter || !target.Enabled {
					continue
				}
				candidate := disruptionCapabilitiesForTarget(adapter, target)
				supported.Yield = supported.Yield || candidate.Yield
				supported.Checkpoint = supported.Checkpoint || candidate.Checkpoint
				supported.Cancel = supported.Cancel || candidate.Cancel
			}
			m.mu.RUnlock()
		}
		switch req.Disruption {
		case domain.DisruptionYieldable:
			if !supported.Yield {
				return nil, false, fmt.Errorf("adapter %s does not support yieldable execution", req.Adapter)
			}
		case domain.DisruptionCheckpointable:
			if !supported.Checkpoint {
				return nil, false, fmt.Errorf("adapter %s does not support checkpoint/resume execution", req.Adapter)
			}
		case domain.DisruptionCancelable:
			if !supported.Cancel {
				return nil, false, fmt.Errorf("adapter %s cannot guarantee in-flight cancellation", req.Adapter)
			}
		}
	}
	if err := adapter.Validate(ctx, req); err != nil {
		return nil, false, err
	}
	w := &domain.Workload{Request: req, Revision: 1, Status: domain.WorkloadQueued, CreatedAt: now, UpdatedAt: now}
	stored, created, err := m.store.CreateWorkload(ctx, w)
	if err != nil {
		return nil, false, err
	}
	if created {
		m.audit(ctx, req.OwnerID, req.ID, "workload.submitted", "info", nil)
		// Creator Studio uses the asynchronous workload contract. Never let its
		// submission request acquire the reconciler lock: model loading, eviction,
		// or another residency transition may take minutes once reconciliation
		// begins. Persist first, wake the event loop, and return the durable ID.
		if req.Plane == domain.PlaneCreatorStudio {
			m.mu.RLock()
			operational := false
			for _, target := range m.targets {
				if target.Enabled {
					if _, _, matches := creatorProfileForTarget(target, req); matches {
						operational = true
						break
					}
				}
			}
			m.mu.RUnlock()
			if !operational {
				stored.Status = domain.WorkloadWaiting
				stored.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "CAPABILITY_UNAVAILABLE", Confidence: 1}
				stored.UpdatedAt = time.Now().UTC()
				stored, err = m.replaceWorkloadCAS(ctx, stored, workloadStatuses(domain.WorkloadQueued), "")
				if err != nil {
					return nil, false, err
				}
			}
			m.signal()
			refreshed, getErr := m.store.GetWorkload(ctx, req.ID)
			if getErr != nil {
				return nil, false, getErr
			}
			return refreshed, true, nil
		}
		// A short reconciliation pass should preserve the synchronous admission
		// behavior callers rely on. A model/runtime transition can take minutes,
		// though, so never wait behind it indefinitely: fail-fast callers receive
		// an immediate decision and durable asynchronous callers remain queued.
		if !m.tryReconcileWithin(ctx, 250*time.Millisecond) {
			if req.QueuePolicy == domain.QueueFailFast {
				now := time.Now().UTC()
				start := now.Add(m.leaseTTL)
				end := start.Add(m.leaseTTL)
				stored.Status = domain.WorkloadRejected
				stored.Decision = domain.AdmissionDecision{
					Admitted: false, Blocker: "no eligible capacity (fail_fast)",
					EstimatedStart: &start, EstimatedEnd: &end, Confidence: .3,
					Alternatives: []string{"scheduler busy with a model or residency transition"},
				}
				stored.UpdatedAt, stored.FinishedAt = now, &now
				stored, err = m.replaceWorkloadCAS(ctx, stored, workloadStatuses(domain.WorkloadQueued), "")
				if err != nil {
					return nil, false, err
				}
				m.audit(ctx, req.OwnerID, req.ID, "workload.rejected", "info", stored.Decision)
			} else {
				// A running reconcile will not necessarily have listed this newly
				// created row. Wake the event loop so it is considered immediately
				// after the current model transition finishes.
				m.signal()
			}
		}
		refreshed, getErr := m.store.GetWorkload(ctx, req.ID)
		if getErr != nil {
			return nil, false, getErr
		}
		stored = refreshed
	}
	return stored, created, nil
}

func (m *Manager) Get(ctx context.Context, id string) (*domain.Workload, error) {
	return m.store.GetWorkload(ctx, id)
}
func (m *Manager) List(ctx context.Context) ([]*domain.Workload, error) {
	return m.store.ListWorkloads(ctx)
}

// mutateWorkloadCAS is the single controller-side workload mutation boundary.
// Callers describe the statuses they are allowed to mutate and the durable
// cancellation owner they expect. Every retry reloads the row, so a terminal
// result or a cancellation claim cannot be overwritten by a stale projection.
func (m *Manager) mutateWorkloadCAS(ctx context.Context, id string, allowed map[domain.WorkloadStatus]bool, expectedCancellationOwner string, mutate func(*domain.Workload) error) (*domain.Workload, error) {
	if id == "" || mutate == nil {
		return nil, fmt.Errorf("workload mutation requires id and callback")
	}
	for attempt := 0; attempt < 8; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current, err := m.store.GetWorkload(ctx, id)
		if err != nil {
			return nil, err
		}
		if !allowed[current.Status] || current.CancellationOwner != expectedCancellationOwner {
			return nil, store.ErrWorkloadConflict
		}
		expectedRevision, expectedStatus := current.Revision, current.Status
		settlementWasPending := current.BudgetSettlementPending
		if err := mutate(current); err != nil {
			return nil, err
		}
		if !(settlementWasPending && !current.BudgetSettlementPending) {
			if err := ensureBudgetSettlementIntent(current); err != nil {
				return nil, err
			}
		}
		if isTerminalWorkloadStatus(expectedStatus) && current.Status != expectedStatus {
			return nil, store.ErrWorkloadConflict
		}
		updated, err := m.store.CompareAndSwapWorkload(ctx, current, expectedRevision, expectedStatus, expectedCancellationOwner)
		if err == nil {
			return updated, nil
		}
		if !errors.Is(err, store.ErrWorkloadConflict) {
			return nil, err
		}
	}
	return nil, store.ErrWorkloadConflict
}

func workloadStatuses(statuses ...domain.WorkloadStatus) map[domain.WorkloadStatus]bool {
	allowed := make(map[domain.WorkloadStatus]bool, len(statuses))
	for _, status := range statuses {
		allowed[status] = true
	}
	return allowed
}

// replaceWorkloadCAS is retained only for call sites that already have a
// complete projection (restart/admission compatibility). Unlike the delta
// mutation helper it is deliberately one-shot: the projection must carry the
// exact revision that was read by the caller, so a conflict can never cause a
// stale full snapshot to be retried over newer same-status fields.
func (m *Manager) replaceWorkloadCAS(ctx context.Context, desired *domain.Workload, allowed map[domain.WorkloadStatus]bool, expectedCancellationOwner string) (*domain.Workload, error) {
	if desired == nil {
		return nil, fmt.Errorf("nil workload projection")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, err := m.store.GetWorkload(ctx, desired.Request.ID)
	if err != nil {
		return nil, err
	}
	if desired.Revision != current.Revision || !allowed[current.Status] || current.CancellationOwner != expectedCancellationOwner {
		return nil, store.ErrWorkloadConflict
	}
	snapshot := *desired
	if isTerminalWorkloadStatus(current.Status) && snapshot.Status != current.Status {
		return nil, store.ErrWorkloadConflict
	}
	// Preserve the exact ownership token checked above. Full projections must
	// never smuggle a cancellation owner into an observer mutation.
	snapshot.CancellationOwner = expectedCancellationOwner
	if !(current.BudgetSettlementPending && !snapshot.BudgetSettlementPending) {
		if err := ensureBudgetSettlementIntent(&snapshot); err != nil {
			return nil, err
		}
	}
	return m.store.CompareAndSwapWorkload(ctx, &snapshot, current.Revision, current.Status, expectedCancellationOwner)
}

func isTerminalWorkloadStatus(status domain.WorkloadStatus) bool {
	switch status {
	case domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadRejected, domain.WorkloadCancelled:
		return true
	default:
		return false
	}
}

func IsDelegatedTransformationSafe(transformations []string) bool {
	allowed := map[string]struct{}{
		"checkpoint_chunks":     {},
		"reduce_resolution":     {},
		"reduce_steps":          {},
		"quantization_fallback": {},
	}
	if len(transformations) == 0 {
		return false
	}
	for _, transformation := range transformations {
		if _, ok := allowed[transformation]; !ok {
			return false
		}
	}
	return true
}

func (m *Manager) ApproveTransformation(ctx context.Context, workloadID, planHash, approverID, mode string) (*domain.Workload, error) {
	workload, err := m.store.GetWorkload(ctx, workloadID)
	if err != nil {
		return nil, err
	}
	if workload.Status != domain.WorkloadPendingApproval || workload.Plan == nil {
		return nil, fmt.Errorf("workload is not awaiting transformation approval")
	}
	if planHash == "" || planHash != workload.Plan.PlanHash {
		return nil, fmt.Errorf("approval plan hash does not match the current preview")
	}
	if mode == string(domain.TransformDelegateSafeReview) && !IsDelegatedTransformationSafe(workload.Plan.Transformations) {
		return nil, fmt.Errorf("plan contains a transformation outside the delegated safe allowlist")
	}
	approval := &domain.TransformationApproval{WorkloadID: workloadID, PlanHash: planHash, ApproverID: approverID, ApprovalMode: mode, CreatedAt: time.Now().UTC()}
	if _, _, err := m.store.CreateTransformationApproval(ctx, approval); err != nil {
		return nil, err
	}
	workload.Status = domain.WorkloadQueued
	workload.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "approved plan awaiting capacity", Confidence: .9}
	workload.UpdatedAt = time.Now().UTC()
	updated, err := m.replaceWorkloadCAS(ctx, workload, workloadStatuses(domain.WorkloadPendingApproval), "")
	if err != nil {
		return nil, err
	}
	workload = updated
	m.audit(ctx, workload.Request.OwnerID, workloadID, "workload.transformation_approved", "info", map[string]string{"plan_hash": planHash, "approver_id": approverID, "mode": mode})
	m.signal()
	return workload, nil
}

func (m *Manager) Reprioritize(ctx context.Context, workloadID string, priority int, actorID string) (*domain.Workload, error) {
	workload, err := m.store.GetWorkload(ctx, workloadID)
	if err != nil {
		return nil, err
	}
	switch workload.Status {
	case domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadRejected, domain.WorkloadCancelled:
		return nil, fmt.Errorf("terminal workload cannot be reprioritized")
	}
	workload.RuntimePriority = &priority
	workload.UpdatedAt = time.Now().UTC()
	updated, err := m.replaceWorkloadCAS(ctx, workload, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadRunning, domain.WorkloadPendingApproval), "")
	if err != nil {
		return nil, err
	}
	m.auditActor(ctx, actorID, workload.Request.OwnerID, workloadID, "workload.reprioritized", "info", map[string]int{"priority": priority})
	m.signal()
	return updated, nil
}

func (m *Manager) reconcile(ctx context.Context) {
	releaseOperation, operationErr := m.beginResidencyOperation(ctx)
	if operationErr != nil {
		return
	}
	defer releaseOperation()
	m.reconcileLocked(ctx)
}

func (m *Manager) tryReconcileWithin(ctx context.Context, wait time.Duration) bool {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.reconcileMu.TryLock() {
			m.reconcileMu.Unlock()
			releaseOperation, operationErr := m.beginResidencyOperation(ctx)
			if operationErr != nil {
				return false
			}
			defer releaseOperation()
			m.reconcileLocked(ctx)
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-ticker.C:
		}
	}
}

func (m *Manager) reconcileLocked(ctx context.Context) {
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		m.log.Error("list workloads", "err", err)
		return
	}
	m.reconcileRunningNodeLoss(ctx, rows)
	sort.SliceStable(rows, func(i, j int) bool {
		iPriority, jPriority := effectiveWorkloadPriority(rows[i]), effectiveWorkloadPriority(rows[j])
		if iPriority != jPriority {
			return iPriority > jPriority
		}
		if rows[i].Request.Deadline != nil && rows[j].Request.Deadline != nil && !rows[i].Request.Deadline.Equal(*rows[j].Request.Deadline) {
			return rows[i].Request.Deadline.Before(*rows[j].Request.Deadline)
		}
		if (rows[i].Request.Deadline != nil) != (rows[j].Request.Deadline != nil) {
			return rows[i].Request.Deadline != nil
		}
		return rows[i].CreatedAt.Before(rows[j].CreatedAt)
	})
	for _, w := range rows {
		if w.CancellationOwner != "" {
			continue
		}
		if w.Status != domain.WorkloadQueued && w.Status != domain.WorkloadWaiting {
			continue
		}
		if w.Status == domain.WorkloadWaiting && w.Decision.Blocker == restartReconciliationBlocker {
			continue
		}
		m.tryAdmit(ctx, w)
	}
}

func (m *Manager) reconcileRecoveredExecutionsForTarget(ctx context.Context, targetID string) {
	if targetID == "" {
		return
	}
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		return
	}
	target := m.targetByID(targetID)
	if target.ID == "" {
		return
	}
	m.mu.RLock()
	adapter := m.adapters[target.Adapter]
	m.mu.RUnlock()
	if adapter == nil {
		return
	}
	for _, workload := range rows {
		if workload.CancellationOwner != "" {
			continue
		}
		if workload.Status != domain.WorkloadWaiting || workload.Decision.Blocker != restartReconciliationBlocker || workload.Plan == nil || workload.Plan.TargetID != targetID || workload.Execution == nil {
			continue
		}
		reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		observation, observeErr := adapter.Observe(reconcileCtx, workload.Request, workload.Plan, workload.Execution, target)
		if observeErr == nil && observation.Status == domain.WorkloadSucceeded {
			output, refs, collectErr := adapter.CollectOutputs(reconcileCtx, workload.Request, workload.Plan, workload.Execution, target)
			if collectErr == nil {
				output, refs, collectErr = m.materializeCreatorOutputs(reconcileCtx, workload, target, output, refs)
			}
			cancel()
			if collectErr != nil {
				m.failRecoveredExecution(workload, "recovered backend completed but output collection failed: "+collectErr.Error())
				continue
			}
			now := time.Now().UTC()
			workload.Status = domain.WorkloadSucceeded
			workload.Progress = 1
			workload.InlineOutput = output
			workload.OutputRefs = refs
			workload.Error = ""
			workload.UpdatedAt = now
			workload.FinishedAt = &now
			persisted, persistErr := m.replaceWorkloadCAS(context.Background(), workload, workloadStatuses(domain.WorkloadWaiting), "")
			if persistErr != nil {
				continue
			}
			workload = persisted
			m.syncPromptMapping(context.Background(), workload)
			m.settleWorkloadBudget(context.Background(), workload)
			m.audit(context.Background(), workload.Request.OwnerID, workload.Request.ID, "workload.restart_recovered_completed", "info", map[string]string{"target_id": targetID})
			continue
		}
		if observeErr == nil && observation.Status == domain.WorkloadFailed {
			cancel()
			m.failRecoveredExecution(workload, "recovered backend reported failure: "+observation.Error)
			continue
		}
		stopErr := adapter.Cancel(reconcileCtx, workload.Execution, target)
		cancel()
		if stopErr != nil {
			reason := "prior backend execution could not be reconciled or stopped; execution was not duplicated"
			if observeErr != nil {
				reason += ": observe: " + observeErr.Error()
			}
			reason += "; cancel: " + stopErr.Error()
			m.failRecoveredExecution(workload, reason)
			continue
		}
		workload.Status = domain.WorkloadQueued
		workload.Plan = nil
		workload.Execution = nil
		workload.StartedAt = nil
		workload.FinishedAt = nil
		workload.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "prior backend execution stopped after controller restart; safely re-admitting", Confidence: .95}
		workload.Error = "controller restart recovery stopped the prior backend attempt"
		workload.UpdatedAt = time.Now().UTC()
		if persisted, persistErr := m.replaceWorkloadCAS(context.Background(), workload, workloadStatuses(domain.WorkloadWaiting), ""); persistErr == nil {
			workload = persisted
			if releaseErr := m.releaseBudgetClaimAfterWorkloadCAS(context.Background(), workload.Request.ID, workload.BudgetReservationToken, workload.BudgetReservationAttempt); releaseErr != nil {
				m.log.Warn("recovered workload budget cleanup remains pending", "workload_id", workload.Request.ID, "error", releaseErr)
			}
		} else {
			continue
		}
		m.audit(context.Background(), workload.Request.OwnerID, workload.Request.ID, "workload.restart_recovered_requeued", "warn", map[string]string{"target_id": targetID})
		m.signal()
	}
}

func (m *Manager) failRecoveredExecution(workload *domain.Workload, reason string) {
	if workload == nil {
		return
	}
	latest, err := m.store.GetWorkload(context.Background(), workload.Request.ID)
	if err != nil || latest.Status == domain.WorkloadCancelled || latest.Status == domain.WorkloadSucceeded {
		return
	}
	if latest.CancellationOwner != "" {
		return
	}
	expectedStatus := latest.Status
	now := time.Now().UTC()
	latest.Status = domain.WorkloadFailed
	latest.Error = reason
	latest.UpdatedAt = now
	latest.FinishedAt = &now
	persisted, err := m.replaceWorkloadCAS(context.Background(), latest, workloadStatuses(expectedStatus), "")
	if err != nil {
		return
	}
	workload = persisted
	m.settleWorkloadBudget(context.Background(), workload)
	m.audit(context.Background(), workload.Request.OwnerID, workload.Request.ID, "workload.restart_recovery_failed", "error", map[string]string{"error": reason})
}

func (m *Manager) reconcileRunningNodeLoss(ctx context.Context, rows []*domain.Workload) {
	if m.nodes == nil {
		return
	}
	for _, workload := range rows {
		if workload.CancellationOwner != "" {
			continue
		}
		if workload.Status != domain.WorkloadRunning || workload.Plan == nil || workload.Plan.AcceleratorID == "" {
			continue
		}
		target := m.targetByID(workload.Plan.TargetID)
		if target.ID == "" || target.Cloud || m.targetNodeConnected(ctx, target) {
			continue
		}
		m.mu.RLock()
		cancel := m.cancels[workload.Request.ID]
		adapter := m.adapters[workload.Request.Adapter]
		m.mu.RUnlock()
		backendStopped := workload.Execution == nil
		var stopErr error
		if workload.Execution != nil {
			m.mu.Lock()
			m.cancelling[workload.Request.ID] = struct{}{}
			m.mu.Unlock()
			stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if adapter == nil {
				stopErr = fmt.Errorf("adapter is unavailable")
			} else {
				stopErr = adapter.Cancel(stopCtx, workload.Execution, target)
			}
			stopCancel()
			backendStopped = stopErr == nil
		}
		now := time.Now().UTC()
		expectedStatus := workload.Status
		expectedCancellationOwner := workload.CancellationOwner
		releaseBudget := false
		if workload.Request.Recoverable && backendStopped {
			releaseBudget = true
			workload.Status = domain.WorkloadQueued
			workload.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "assigned node was lost; re-admitting recoverable workload", Confidence: .95}
			workload.Plan = nil
			workload.Execution = nil
			workload.Error = "assigned node lost"
			workload.FinishedAt = nil
			if workload.TargetRetryAfter == nil {
				workload.TargetRetryAfter = make(map[string]time.Time)
			}
			workload.TargetRetryAfter[target.ID] = now.Add(5 * time.Second)
			m.audit(ctx, workload.Request.OwnerID, workload.Request.ID, "workload.node_lost_requeued", "warn", map[string]string{"target_id": target.ID})
		} else {
			workload.Status = domain.WorkloadFailed
			if workload.Request.Recoverable && !backendStopped {
				workload.Error = "assigned node lost; backend cancellation unconfirmed, so execution was not duplicated"
				if stopErr != nil {
					workload.Error += ": " + stopErr.Error()
				}
			} else {
				workload.Error = "assigned node lost during non-recoverable execution"
			}
			workload.FinishedAt = &now
			m.audit(ctx, workload.Request.OwnerID, workload.Request.ID, "workload.node_lost_failed", "error", map[string]string{"target_id": target.ID, "backend_stop_confirmed": fmt.Sprintf("%t", backendStopped)})
		}
		workload.UpdatedAt = now
		persisted, casErr := m.replaceWorkloadCAS(ctx, workload, workloadStatuses(expectedStatus), expectedCancellationOwner)
		if casErr != nil {
			continue
		}
		workload = persisted
		if releaseBudget {
			if releaseErr := m.releaseBudgetClaimAfterWorkloadCAS(ctx, workload.Request.ID, workload.BudgetReservationToken, workload.BudgetReservationAttempt); releaseErr != nil {
				m.log.Warn("node-loss budget cleanup remains pending", "workload_id", workload.Request.ID, "error", releaseErr)
			}
		} else {
			m.settleWorkloadBudget(ctx, workload)
		}
		if cancel != nil {
			cancel()
		}
		m.mu.Lock()
		delete(m.cancelling, workload.Request.ID)
		m.mu.Unlock()
	}
}

// targetNodeConnected reports whether the node owning target's accelerator is
// still connected. Unlike targetNodeAvailable it ignores the agent's Ready
// flag, which only means "idle for new commands" and is false while the
// agent executes one (for example the load that preceded this execution).
func (m *Manager) targetNodeConnected(ctx context.Context, target Target) bool {
	nodes, err := m.nodes.ListNodes(ctx)
	if err != nil {
		return true // a store read failure is not evidence of node loss
	}
	for _, node := range nodes {
		for _, accelerator := range node.Accelerators {
			if accelerator.ID == target.AcceleratorID {
				return node.Observed.Connectivity != domain.ConnectivityLost
			}
		}
	}
	return false
}

func (m *Manager) targetNodeAvailable(ctx context.Context, target Target) bool {
	nodes, err := m.nodes.ListNodes(ctx)
	if err != nil {
		return false
	}
	for _, node := range nodes {
		for _, accelerator := range node.Accelerators {
			if accelerator.ID == target.AcceleratorID {
				return node.Observed.Connectivity == domain.ConnectivityConnected && node.Observed.Ready && node.SchedulingState == domain.SchedulingEnabled && node.Desired.SchedulingEnabled
			}
		}
	}
	return false
}

func (m *Manager) tryAdmit(ctx context.Context, w *domain.Workload) {
	// Reconcile token-bound budget sagas before dependency, deadline, or
	// terminal admission decisions. A pending side effect owns the workload;
	// no new reservation or terminal rejection may race it.
	if w != nil && w.BudgetCleanupToken != "" {
		if err := m.retryBudgetCleanupIntent(ctx, w); err != nil {
			m.log.Warn("admission blocked by budget cleanup intent", "workload_id", w.Request.ID, "error", err)
			return
		}
		latest, err := m.store.GetWorkload(ctx, w.Request.ID)
		if err != nil || latest.BudgetCleanupToken != "" {
			return
		}
		w = latest
	}
	if w != nil && w.BudgetSettlementPending {
		if err := m.retryBudgetSettlementIntent(ctx, w); err != nil {
			m.log.Warn("admission blocked by budget settlement intent", "workload_id", w.Request.ID, "error", err)
			return
		}
		latest, err := m.store.GetWorkload(ctx, w.Request.ID)
		if err != nil || latest.BudgetSettlementPending {
			return
		}
		w = latest
	}
	if blocker, terminal := m.dependencyBlocker(ctx, w); blocker != "" {
		wasWaiting := w.Status == domain.WorkloadWaiting
		w.Status = domain.WorkloadWaiting
		w.Decision = domain.AdmissionDecision{Admitted: false, Blocker: blocker, Confidence: 1}
		w.UpdatedAt = time.Now().UTC()
		if updated, mutateErr := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting), ""); mutateErr == nil {
			w = updated
		} else {
			return
		}
		if !wasWaiting {
			severity := "info"
			if terminal {
				severity = "warn"
			}
			m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.dependency_blocked", severity, map[string]any{"reason": blocker, "dependencies": w.Request.Dependencies})
		}
		return
	}
	if w.Request.Deadline != nil && !w.Request.Deadline.After(time.Now()) {
		w.Status = domain.WorkloadRejected
		w.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "deadline has expired", Confidence: 1}
		now := time.Now().UTC()
		w.UpdatedAt, w.FinishedAt = now, &now
		if updated, mutateErr := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting), ""); mutateErr == nil {
			w = updated
		} else {
			return
		}
		m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.deadline_missed", "warn", w.Decision)
		return
	}
	// A budget side-effect intent owns this workload until it is reconciled.
	// Never issue a new reservation while an earlier release/settlement may
	// still be in flight after a crash.
	if w.BudgetCleanupToken != "" {
		if err := m.retryBudgetCleanupIntent(ctx, w); err != nil {
			m.log.Warn("admission blocked by budget cleanup intent", "workload_id", w.Request.ID, "error", err)
			return
		}
		if latest, err := m.store.GetWorkload(ctx, w.Request.ID); err != nil || latest.BudgetCleanupToken != "" {
			return
		} else {
			w = latest
		}
	}
	if w.BudgetSettlementPending {
		if err := m.retryBudgetSettlementIntent(ctx, w); err != nil {
			m.log.Warn("admission blocked by budget settlement intent", "workload_id", w.Request.ID, "error", err)
			return
		}
		if latest, err := m.store.GetWorkload(ctx, w.Request.ID); err != nil || latest.BudgetSettlementPending {
			return
		} else {
			w = latest
		}
	}
	m.mu.RLock()
	adapter := m.adapters[w.Request.Adapter]
	targets := make([]Target, 0, len(m.targets))
	for _, t := range m.targets {
		targets = append(targets, m.runtimeProfileCapacityViewLocked(t))
	}
	m.mu.RUnlock()
	if adapter == nil {
		m.fail(ctx, w, "adapter removed")
		return
	}
	if w.Request.InteractiveStream {
		if _, ok := adapter.(StreamingAdapter); !ok {
			m.fail(ctx, w, "adapter does not support interactive streaming")
			return
		}
	}
	req, err := adapter.Requirements(ctx, w.Request)
	if err != nil {
		m.fail(ctx, w, err.Error())
		return
	}
	concurrencyBlocked := w.Request.ConcurrencyLimit > 0 && m.principalActiveCount(ctx, w.Request.PrincipalID, w.Request.ID) >= w.Request.ConcurrencyLimit
	boundTarget := ""
	if w.Request.PlacementPolicy == domain.PlacementSticky {
		boundTarget = m.boundTarget(ctx, w.Request)
	}
	targetEstimates := m.estimateTargets(ctx, targets, w, req)
	sort.SliceStable(targets, func(i, j int) bool {
		if boundTarget != "" && (targets[i].ID == boundTarget) != (targets[j].ID == boundTarget) {
			return targets[i].ID == boundTarget
		}
		if w.Request.Plane == domain.PlaneCreatorStudio {
			_, leftRank, leftOK := creatorProfileForTarget(targets[i], w.Request)
			_, rightRank, rightOK := creatorProfileForTarget(targets[j], w.Request)
			if leftOK != rightOK {
				return leftOK
			}
			if leftOK && leftRank != rightRank {
				return leftRank < rightRank
			}
		}
		// Multiple routes for the same model commonly exist specifically to
		// reserve a scarce long-context profile while a narrower profile serves
		// ordinary traffic with more slots. Treat the smallest sufficient
		// context as the primary best-fit dimension; residency and transition
		// cost remain tie-breakers. If that route is busy or otherwise
		// incompatible, admission naturally spills to the next candidate.
		if preference := contextProfilePreference(targets[i], targets[j], w.Request.Adapter, req); preference != 0 {
			return preference < 0
		}
		if targetEstimates[targets[i].ID].score != targetEstimates[targets[j].ID].score {
			return targetEstimates[targets[i].ID].score < targetEstimates[targets[j].ID].score
		}
		return targets[i].ID < targets[j].ID
	})

	var blockers []string
	var waitingEstimate *targetEstimate
	stickyTargetRegistered := boundTarget == ""
	creatorProfileMatched := false
	for _, target := range targets {
		comfyProof := comfySchemaProof{}
		if target.ID == boundTarget {
			stickyTargetRegistered = true
		}
		if target.Adapter != w.Request.Adapter {
			continue
		}
		if !targetSupportsDisruption(adapter, target, w.Request.Disruption) {
			blockers = append(blockers, target.ID+": disruption policy unsupported by runtime protocol")
			continue
		}
		selectedProfile := domain.RuntimeProfile{}
		if w.Request.Plane == domain.PlaneCreatorStudio {
			var matches bool
			selectedProfile, _, matches = creatorProfileForTarget(target, w.Request)
			if !matches {
				continue
			}
			creatorProfileMatched = true
		}
		if target.Quarantined {
			blockers = append(blockers, target.ID+": provider/model route is quarantined")
			continue
		}
		if retryAt := w.TargetRetryAfter[target.ID]; retryAt.After(time.Now()) {
			blockers = append(blockers, target.ID+": provider retry cooldown until "+retryAt.UTC().Format(time.RFC3339))
			continue
		}
		if retryAt, open := m.providerCircuitOpen(target.ID); open {
			blockers = append(blockers, target.ID+": provider circuit open until "+retryAt.UTC().Format(time.RFC3339))
			continue
		}
		if concurrencyBlocked {
			blockers = append(blockers, fmt.Sprintf("principal concurrency limit %d reached", w.Request.ConcurrencyLimit))
			break
		}
		if !target.Enabled {
			if target.ID == boundTarget {
				blockers = append(blockers, target.ID+": sticky target is disabled")
			}
			continue
		}
		if req.RuntimeProtocol != "" && target.RuntimeProtocol != req.RuntimeProtocol {
			blockers = append(blockers, target.ID+": required runtime protocol unavailable")
			continue
		}
		if target.Cloud && w.Request.Egress == domain.EgressLocalOnly {
			blockers = append(blockers, target.ID+": egress denied")
			continue
		}
		if w.Request.PlacementPolicy == domain.PlacementSticky && boundTarget != "" && target.ID != boundTarget {
			continue
		}
		if blocker := m.inventoryBlocker(ctx, target, req); blocker != "" {
			waitingEstimate = preferEstimate(waitingEstimate, targetEstimates[target.ID])
			blockers = append(blockers, target.ID+": "+blocker)
			continue
		}
		if req.Model != "" && !containsString(target.Models, req.Model) {
			blockers = append(blockers, target.ID+": model unavailable")
			continue
		}
		missingRequiredModel := ""
		for _, model := range req.RequiredModels {
			if !containsString(target.Models, model) {
				missingRequiredModel = model
				break
			}
		}
		if missingRequiredModel != "" {
			blockers = append(blockers, target.ID+": workflow model unavailable: "+missingRequiredModel)
			continue
		}
		if allowed, limit := m.modelAcceleratorAllowed(target, req.Model); !allowed {
			blockers = append(blockers, fmt.Sprintf("%s: model accelerator limit %d reached", target.ID, limit))
			continue
		}
		if target.Adapter == "comfy" && builtInComfyHTTPAdapter(adapter) {
			comfySchemaGeneration := m.targetGeneration(target.ID)
			var schemaErr error
			comfyProof, schemaErr = m.ComfySchema(ctx, target, comfySchemaGeneration, w.Request)
			if schemaErr != nil {
				blockers = append(blockers, target.ID+": workflow schema unavailable or incompatible")
				continue
			}
		}
		if desired, shouldSwitch := desiredRuntimeProfile(target, req.ContextTokens); shouldSwitch {
			updated, switchReason, switchErr := m.ensureRuntimeProfile(ctx, target, desired, w)
			if switchErr != nil {
				blockers = append(blockers, target.ID+": runtime profile transition failed: "+switchErr.Error())
				continue
			}
			if switchReason != "" {
				waitingEstimate = preferEstimate(waitingEstimate, targetEstimates[target.ID])
				blockers = append(blockers, target.ID+": "+switchReason)
				continue
			}
			target = updated
		}
		if target.Adapter == "comfy" && builtInComfyHTTPAdapter(adapter) {
			comfySchemaGeneration := m.targetGeneration(target.ID)
			latestDigest, schemaErr := m.ComfySchema(ctx, target, comfySchemaGeneration, w.Request)
			if schemaErr != nil || !comfySchemaProofMatches(comfyProof, latestDigest) {
				blockers = append(blockers, target.ID+": workflow schema changed during admission")
				continue
			}
		}
		// Read the durable projection before entering the refresh fence. The
		// admission fence serializes placement decisions, but it must never be
		// held across a potentially slow store call. The target is re-read below
		// and the projection is checked again by the final execution fence.
		var observedResidency *domain.ModelResidency
		var observedResidencyErr error
		if req.Model != "" {
			observedResidency, observedResidencyErr = m.store.GetModelResidency(ctx, target.ID, req.Model)
		}
		// The target snapshot used for scoring is not an admission fact. Take
		// the shared refresh fence only after any profile switch, re-read the
		// current target, and keep it through reserve, residency enforcement,
		// final validation, and the runnable CAS. RegisterTarget takes the same
		// manager-wide-then-target lock order, so a node refresh cannot invalidate
		// this decision between the check and the lifecycle operation.
		m.residencyAdmissionMu.Lock()
		targetLock := m.residencyAdmissionLock(target.ID)
		targetLock.RLock()
		unlockAdmission := func() {
			targetLock.RUnlock()
			m.residencyAdmissionMu.Unlock()
		}
		target = m.targetByID(target.ID)
		if target.ID == "" {
			unlockAdmission()
			blockers = append(blockers, "target disappeared during admission refresh")
			continue
		}
		m.mu.RLock()
		profileKey := m.runtimeProfileTransitionTarget[target.ID]
		profileTransition := m.runtimeProfileTransitions[profileKey]
		profilePending := profileTransition != nil && !profileTransition.projected
		profileBlocker := m.runtimeProfileTargetBlockerLocked(target)
		m.mu.RUnlock()
		if profilePending || profileBlocker != "" || target.CapacitySource == "runtime-profile:pending" || target.CapacitySource == "runtime-profile:observation_unavailable" {
			unlockAdmission()
			reason := profileBlocker
			if reason == "" {
				reason = "runtime profile observation_unavailable; pending transition has no verified admission capacity"
			}
			blockers = append(blockers, target.ID+": "+reason)
			continue
		}
		if m.residencyTransitionInFlight(target.AcceleratorID) {
			unlockAdmission()
			waitingEstimate = preferEstimate(waitingEstimate, targetEstimates[target.ID])
			blockers = append(blockers, target.ID+": accelerator residency transition in progress")
			continue
		}
		needsModelLoad := req.Model != "" && !containsString(target.ResidentModels, req.Model)
		if req.Model != "" {
			// A durable hot projection is authoritative across a node refresh that
			// temporarily omits the model. Reconcile it into the live target before
			// deciding whether a load is required, preventing duplicate loads.
			residency, residencyErr := observedResidency, observedResidencyErr
			if residencyErr == nil && residency.ObservedTier == domain.ResidencyHotVRAM {
				if !containsString(target.ResidentModels, req.Model) {
					generationErr := error(nil)
					invalidated := false
					m.mu.Lock()
					if current, ok := m.targets[target.ID]; ok {
						previous := current
						current.ResidentModels = append(append([]string(nil), current.ResidentModels...), req.Model)
						generationErr = m.replaceTargetLocked(current)
						if generationErr == nil {
							m.refreshRuntimeProfileProjectedGenerationLocked(current)
						} else if m.targetGenerations[target.ID] == ^uint64(0) {
							m.invalidateTargetAtExhaustedGenerationLocked(target.ID, previous)
							invalidated = true
						}
					} else {
						generationErr = fmt.Errorf("target %s disappeared during residency reconciliation", target.ID)
					}
					m.mu.Unlock()
					if generationErr != nil {
						unlockAdmission()
						if invalidated {
							m.signal()
						}
						blockers = append(blockers, target.ID+": "+generationErr.Error())
						continue
					}
					target.ResidentModels = append(target.ResidentModels, req.Model)
				}
				needsModelLoad = false
			} else if residencyErr != nil && !errors.Is(residencyErr, store.ErrNotFound) {
				unlockAdmission()
				blockers = append(blockers, target.ID+": residency reconciliation failed")
				continue
			}
		}
		if needsModelLoad && !target.SupportsModelLifecycle {
			unlockAdmission()
			blockers = append(blockers, target.ID+": model is not resident and target cannot load it")
			continue
		}
		if needsModelLoad {
			residency, residencyErr := observedResidency, observedResidencyErr
			if residencyErr == nil && (residency.Policy == domain.ResidencyManual || residency.Policy == domain.ResidencyOff) {
				unlockAdmission()
				blockers = append(blockers, target.ID+": model loading requires an operator transition")
				continue
			}
		}
		if req.ContextTokens > 0 && target.ContextLimit > 0 && req.ContextTokens > target.ContextLimit {
			unlockAdmission()
			blockers = append(blockers, fmt.Sprintf("%s: context limit %d is below required %d", target.ID, target.ContextLimit, req.ContextTokens))
			continue
		}
		missingNode := false
		for _, node := range req.CustomNodes {
			// An empty list means a statically configured backend with unknown
			// inventory. Discovered Comfy backends advertise the complete class
			// set, so absence there is authoritative.
			if len(target.CustomNodes) > 0 && !containsString(target.CustomNodes, node) {
				missingNode = true
				break
			}
		}
		if missingNode {
			unlockAdmission()
			blockers = append(blockers, target.ID+": custom node unavailable")
			continue
		}
		if len(w.Request.Transformations) > 0 {
			// The preview invokes adapter.Plan and therefore cannot run under the
			// refresh fence. Reacquire and fence its target facts before using it.
			targetLock.RUnlock()
			m.residencyAdmissionMu.Unlock()
			preview, previewErr := m.prepareExecutionPlan(adapter, w, target)
			if previewErr != nil {
				blockers = append(blockers, target.ID+": transformation preview rejected")
				continue
			}
			_, approvalErr := m.store.GetTransformationApproval(ctx, w.Request.ID, preview.PlanHash)
			m.residencyAdmissionMu.Lock()
			targetLock.RLock()
			currentTarget := m.targetByID(target.ID)
			if !targetIdentityMatches(target, currentTarget) {
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				blockers = append(blockers, target.ID+": target facts changed during transformation preview")
				continue
			}
			target = currentTarget
			if approvalErr != nil {
				w.Status = domain.WorkloadPendingApproval
				w.Plan = preview
				w.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "transformation approval required for exact plan hash", Confidence: .9, TargetID: target.ID, AcceleratorID: target.AcceleratorID, ContextLimit: target.ContextLimit, TargetSlots: target.Slots, CapacitySource: target.CapacitySource, CapacityVerified: target.CapacityVerified}
				w.UpdatedAt = time.Now().UTC()
				unlockAdmission()
				if updated, mutateErr := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting), ""); mutateErr == nil {
					w = updated
				} else {
					return
				}
				m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.transformation_pending", "info", map[string]any{"plan_hash": preview.PlanHash, "transformations": preview.Transformations})
				return
			}
		}
		estimatedCost := estimateTargetCost(target, req)
		candidateResult := func() admitCandidateResult {
			budgetCleanupDone := false
			budgetToken := w.BudgetReservationToken
			budgetAttempt := w.BudgetReservationAttempt
			budgetReserved := budgetToken != ""
			budgetTransferred := false
			// This defer is installed before any candidate-side budget work. It is
			// deliberately one-shot: every return from this inner admission scope
			// reaches it, including target-refresh, lease, reclaim, validation, and
			// runnable-CAS failures. Cleanup uses a fresh bounded context so a
			// cancelled admission cannot abandon a linked claim. The defer is
			// disarmed only after the runnable workload CAS has won.
			defer func() {
				if budgetCleanupDone || budgetTransferred || !budgetReserved || budgetToken == "" {
					return
				}
				budgetCleanupDone = true
				cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancelCleanup()
				if releaseErr := m.releaseBudgetClaimAfterWorkloadCAS(cleanupCtx, w.Request.ID, budgetToken, budgetAttempt); releaseErr != nil {
					m.log.Warn("budget cleanup remains pending", "workload_id", w.Request.ID, "error", releaseErr)
				}
			}()
			if target.Cloud && w.Request.BudgetLimitCents > 0 {
				if estimatedCost <= 0 {
					unlockAdmission()
					blockers = append(blockers, target.ID+": cloud price is not configured")
					return admitCandidateNext
				}
				if budgetToken == "" {
					budgetToken = newID("budget-attempt")
				}
				// Budget claims are durable CAS operations. Release the refresh fence
				// around the store call, then verify the target before retaining the
				// claim for this admission attempt.
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				var reservationClaim *domain.BudgetReservation
				var allowed bool
				var reserveErr error
				if linker, ok := m.store.(store.BudgetClaimLinker); ok {
					var linked *domain.Workload
					reservationClaim, linked, allowed, _, reserveErr = linker.ReserveAndLinkBudgetClaim(ctx, w.Request.PrincipalID, w.Request.ID, estimatedCost, w.Request.BudgetLimitCents, budgetToken, w.Revision, w.Status, w.CancellationOwner)
					if reserveErr == nil && linked != nil {
						w = linked
						if w.BudgetReservationToken != "" {
							budgetToken = w.BudgetReservationToken
							budgetAttempt = w.BudgetReservationAttempt
							budgetReserved = true
						}
					}
				} else {
					reserveErr = fmt.Errorf("budget claim linker is unavailable")
				}
				if reservationClaim != nil {
					budgetToken = reservationClaim.OwnershipToken
					budgetAttempt = reservationClaim.Attempt
					budgetReserved = budgetToken != ""
				}
				m.residencyAdmissionMu.Lock()
				targetLock.RLock()
				budgetTarget := m.targetByID(target.ID)
				if !targetIdentityMatches(target, budgetTarget) {
					targetLock.RUnlock()
					m.residencyAdmissionMu.Unlock()
					blockers = append(blockers, target.ID+": target facts changed during budget reservation")
					return admitCandidateNext
				}
				target = budgetTarget
				if reserveErr != nil {
					unlockAdmission()
					blockers = append(blockers, target.ID+": budget reservation failed")
					return admitCandidateNext
				}
				if !allowed {
					unlockAdmission()
					blockers = append(blockers, target.ID+": principal cloud budget exhausted")
					return admitCandidateNext
				}
				budgetReserved = budgetReserved || budgetToken != ""
			}
			// Fence this physical accelerator before releasing the refresh lock for
			// durable lease acquisition. Other admissions observe the short marker
			// and cannot reserve the same envelope while this optimistic phase waits.
			if !m.beginResidencyTransition(target.AcceleratorID) {
				unlockAdmission()
				blockers = append(blockers, target.ID+": accelerator residency transition in progress")
				return admitCandidateNext
			}
			unlockAdmission()
			reservation, acquired, reason, err := m.reserveTarget(ctx, target, w, req)
			if err != nil {
				m.endResidencyTransition(target.AcceleratorID)
				blockers = append(blockers, target.ID+": lease error")
				return admitCandidateNext
			}
			if !acquired {
				m.endResidencyTransition(target.AcceleratorID)
				waitingEstimate = preferEstimate(waitingEstimate, targetEstimates[target.ID])
				if m.tryPreempt(ctx, w, target) {
					blockers = append(blockers, target.ID+": victim transition in progress")
					return admitCandidateNext
				}
				blockers = append(blockers, target.ID+": "+reason)
				return admitCandidateNext
			}
			m.mu.Lock()
			m.reservations[w.Request.ID] = reservation
			m.mu.Unlock()
			// Reacquire only for a short identity check after the lease store round
			// trip. A refresh may replace the route while reserveTarget was waiting.
			m.residencyAdmissionMu.Lock()
			targetLock.RLock()
			currentTarget := m.targetByID(target.ID)
			if !targetExecutionFactsEqual(target, currentTarget) {
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				m.endResidencyTransition(target.AcceleratorID)
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": target facts changed during lease acquisition")
				return admitCandidateNext
			}
			target = currentTarget
			reservation.targetGeneration = m.targetGeneration(target.ID)
			if comfyProof.targetID != "" {
				if reservation.targetGeneration != comfyProof.targetGeneration {
					targetLock.RUnlock()
					m.residencyAdmissionMu.Unlock()
					m.endResidencyTransition(target.AcceleratorID)
					if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext { return cleanupResult }
					blockers = append(blockers, target.ID+": workflow schema generation changed during admission")
					return admitCandidateNext
				}
				reservation.comfySchemaProof = comfyProof
			}
			// Lifecycle/reclaim commands are external waits. Release both admission
			// locks; the physical transition marker remains until all rechecks finish.
			unlockAdmission()
			residencyTransitionIDs, reclaimErr := m.reclaimForeignTargets(ctx, target, w, reservation.lease)
			if reclaimErr != nil {
				m.endResidencyTransition(target.AcceleratorID)
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": accelerator reclaim failed: "+reclaimErr.Error())
				return admitCandidateNext
			}
			// Reacquire only for the short fact check. A refresh can legitimately
			// replace the target while reclaim was in flight; never continue with a
			// stale identity or stale accelerator envelope.
			m.residencyAdmissionMu.Lock()
			targetLock.RLock()
			currentTarget = m.targetByID(target.ID)
			if !targetExecutionFactsEqual(target, currentTarget) {
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				m.endResidencyTransition(target.AcceleratorID)
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": target facts changed during accelerator reclaim")
				return admitCandidateNext
			}
			target = currentTarget
			// Reclaim operates on foreign routes sharing this physical accelerator,
			// not this reservation's target. A generation change here is therefore
			// not admission-owned and must not be silently rebound.
			if m.targetGeneration(target.ID) != reservation.targetGeneration {
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				m.endResidencyTransition(target.AcceleratorID)
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": target generation changed during foreign accelerator reclaim")
				return admitCandidateNext
			}
			if needsModelLoad {
				beforeLoadTarget := target
				beforeLoadGeneration := reservation.targetGeneration
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				beforeLoadPlacement, placementFound := m.snapshotAdmissionPlacement(reservation.workloadID)
				if !placementFound {
					m.endResidencyTransition(target.AcceleratorID)
					if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
						return cleanupResult
					}
					blockers = append(blockers, target.ID+": active placement disappeared before owned model load")
					return admitCandidateNext
				}
				transitionIDs, loadErr := m.ensureModelResidentLocked(ctx, target, req.Model, w, reservation.lease)
				if loadErr != nil {
					m.endResidencyTransition(target.AcceleratorID)
					if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
						return cleanupResult
					}
					blockers = append(blockers, target.ID+": model load failed: "+loadErr.Error())
					return admitCandidateNext
				}
				residencyTransitionIDs = append(residencyTransitionIDs, transitionIDs...)
				m.residencyAdmissionMu.Lock()
				targetLock.RLock()
				currentTarget = m.targetByID(target.ID)
				if !targetExecutionFactsEqual(beforeLoadTarget, currentTarget) {
					targetLock.RUnlock()
					m.residencyAdmissionMu.Unlock()
					m.endResidencyTransition(target.AcceleratorID)
					if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
						return cleanupResult
					}
					blockers = append(blockers, target.ID+": target facts changed during model transition")
					return admitCandidateNext
				}
				target = currentTarget
				afterLoadGeneration := m.targetGeneration(target.ID)
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				handoffErr := m.handoffAdmissionOwnedPlacementGeneration(reservation, beforeLoadTarget, target, beforeLoadGeneration, afterLoadGeneration, req.Model, w.Request.OwnerID, w.Request.IdempotencyKey, transitionIDs, beforeLoadPlacement)
				if handoffErr != nil {
					m.endResidencyTransition(target.AcceleratorID)
					if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
						return cleanupResult
					}
					blockers = append(blockers, target.ID+": admission-owned placement generation handoff failed: "+handoffErr.Error())
					return admitCandidateNext
				}
				m.residencyAdmissionMu.Lock()
				targetLock.RLock()
				currentTarget = m.targetByID(target.ID)
				m.mu.RLock()
				reservationFenceMatches := m.reservations[reservation.workloadID] == reservation && reservation.targetGeneration == afterLoadGeneration
				m.mu.RUnlock()
				reservationFenceMatches = reservationFenceMatches && !m.admissionReservationReleasing(reservation)
				if !targetIdentityMatches(target, currentTarget) || m.targetGeneration(target.ID) != afterLoadGeneration || !reservationFenceMatches {
					targetLock.RUnlock()
					m.residencyAdmissionMu.Unlock()
					m.endResidencyTransition(target.AcceleratorID)
					if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
						return cleanupResult
					}
					blockers = append(blockers, target.ID+": target facts changed after owned placement handoff")
					return admitCandidateNext
				}
				target = currentTarget
			}
			m.endResidencyTransition(target.AcceleratorID)
			// Final live validation is deliberately after all transitions and before
			// the workload becomes runnable. This catches a missing/failed projection
			// and rechecks the measured aggregate using the exact in-flight workload
			// exclusion; a stale target snapshot can never start a cold model. The
			// validator performs store reads with the refresh fence released.
			unlockAdmission()
			validatedTarget, validationErr := m.validateExecutionFacts(ctx, target, reservation.targetGeneration, req, w.Request.ID)
			if validationErr != nil {
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": final model validation failed: "+validationErr.Error())
				return admitCandidateNext
			}
			target = validatedTarget
			m.residencyAdmissionMu.Lock()
			targetLock.RLock()
			currentTarget = m.targetByID(target.ID)
			if !targetIdentityMatches(target, currentTarget) || (reservation.targetGeneration > 0 && m.targetGeneration(target.ID) != reservation.targetGeneration) {
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": target facts changed during final model validation")
				return admitCandidateNext
			}
			target = currentTarget
			// Plan generation is an adapter call and may block on a provider. The
			// admission fence must not be held across it; re-read the target and
			// capacity before the runnable CAS below.
			targetLock.RUnlock()
			m.residencyAdmissionMu.Unlock()
			plan, err := m.prepareExecutionPlan(adapter, w, target)
			if err != nil {
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": plan rejected")
				return admitCandidateNext
			}
			validatedTarget, validationErr = m.validateExecutionFacts(ctx, target, reservation.targetGeneration, req, w.Request.ID)
			if validationErr != nil {
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": final model validation failed after plan: "+validationErr.Error())
				return admitCandidateNext
			}
			target = validatedTarget
			m.residencyAdmissionMu.Lock()
			targetLock.RLock()
			currentTarget = m.targetByID(target.ID)
			if !targetIdentityMatches(target, currentTarget) {
				targetLock.RUnlock()
				m.residencyAdmissionMu.Unlock()
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				blockers = append(blockers, target.ID+": target facts changed during execution plan")
				return admitCandidateNext
			}
			target = currentTarget
			plan.EstimatedCostCents = estimatedCost
			plan.InputCentsPerMTok = target.InputCentsPerMTok
			plan.OutputCentsPerMTok = target.OutputCentsPerMTok
			plan.Provider = target.Provider
			plan.Model = req.Model
			if w.Request.Plane == domain.PlaneCreatorStudio {
				plan.ProfileID = selectedProfile.ProfileID
				plan.ProfileVersion = selectedProfile.Version
				plan.ProfileDigest = selectedProfile.Digest
				plan.CapabilityRevision = selectedProfile.CapabilityRevision
				plan.CapabilityDefinitionHash = selectedProfile.CapabilityDefinitionHash
				plan.ExecutionLocality = selectedProfile.ExecutionLocality
			}
			plan.ResidencyTransitionIDs = residencyTransitionIDs
			now := time.Now().UTC()
			w.Status = domain.WorkloadRunning
			w.StartedAt = &now
			w.ExecutionAttempts++
			w.Plan = plan
			confidence := .7
			if target.CapacityVerified {
				confidence = .9
			}
			w.Decision = domain.AdmissionDecision{Admitted: true, Confidence: confidence, TargetID: target.ID, AcceleratorID: target.AcceleratorID, ContextLimit: target.ContextLimit, TargetSlots: target.Slots, CapacitySource: target.CapacitySource, CapacityVerified: target.CapacityVerified}
			if w.Request.Plane == domain.PlaneCreatorStudio {
				w.Decision.ProfileID = selectedProfile.ProfileID
				w.Decision.ProfileVersion = selectedProfile.Version
				w.Decision.ProfileDigest = selectedProfile.Digest
			}
			if estimate := targetEstimates[target.ID]; estimate != nil {
				start := now
				end := now.Add(estimate.duration)
				w.Decision.EstimatedStart = &start
				w.Decision.EstimatedEnd = &end
				if estimate.confidence > w.Decision.Confidence {
					w.Decision.Confidence = estimate.confidence
				}
			}
			w.UpdatedAt = now
			w.Error = ""
			if budgetReserved {
				w.BudgetReservationToken = budgetToken
				w.BudgetReservationAttempt = budgetAttempt
			}
			// The durable workload CAS and all cleanup paths below may block on the
			// store or GPU idle command. Reservation state is already authoritative;
			// release the refresh fence before crossing either boundary.
			targetLock.RUnlock()
			m.residencyAdmissionMu.Unlock()
			updatedWorkload, err := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting), "")
			if err != nil {
				if cleanupResult := m.releaseAdmissionReservation(context.Background(), reservation, target.ID, &blockers); cleanupResult != admitCandidateNext {
					return cleanupResult
				}
				return admitCandidateNext
			}
			w = updatedWorkload
			// The linked claim is now owned by the durable running workload. Mark
			// the transfer before any subsequent audit/stream/lifecycle branch so
			// those branches cannot release it a second time or leak it on close.
			budgetTransferred = true
			budgetCleanupDone = true
			m.syncPromptMapping(ctx, w)
			m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.admitted", "info", w.Decision)
			if w.Request.Notifications.OnStart {
				m.enqueueNotification(ctx, w, "workload.started")
			}
			m.lifecycleMu.Lock()
			execParent := m.managerCtx
			m.lifecycleMu.Unlock()
			if execParent == nil {
				execParent = ctx
			}
			execCtx, cancel := context.WithCancel(execParent)
			m.lifecycleMu.Lock()
			if m.lifecycleClosed {
				m.lifecycleMu.Unlock()
				cancel()
				m.releaseTarget(execCtx, reservation)
				return admitCandidateAdmitted
			}
			m.mu.Lock()
			m.cancels[w.Request.ID] = cancel
			if w.Request.InteractiveStream {
				// A preempted interactive workload retains its client-owned
				// session. Re-admission delivers the next backend segment to
				// that session; only the initial attach uses pendingStreams.
				if session := m.streamSessions[w.Request.ID]; session != nil {
					if session.isDisconnected() {
						delete(m.cancels, w.Request.ID)
						m.mu.Unlock()
						m.lifecycleMu.Unlock()
						m.releaseTarget(execCtx, reservation)
						return admitCandidateAdmitted
					}
					segment := streamSegment{ctx: execCtx, target: target, reservation: reservation}
					select {
					case session.segments <- segment:
					default:
						delete(m.cancels, w.Request.ID)
						m.mu.Unlock()
						m.lifecycleMu.Unlock()
						m.releaseTarget(execCtx, reservation)
						return admitCandidateAdmitted
					}
					m.mu.Unlock()
					m.lifecycleMu.Unlock()
					return admitCandidateAdmitted
				}
				pending := &pendingStream{ctx: execCtx, cancel: cancel, target: target, reservation: reservation}
				m.pendingStreams[w.Request.ID] = pending
				m.asyncWG.Add(1)
				pending.timer = time.AfterFunc(5*time.Second, func() {
					defer pending.timerDone.Do(m.untrackAsync)
					m.expirePendingStream(w.Request.ID, pending)
				})
				m.mu.Unlock()
				m.lifecycleMu.Unlock()
				return admitCandidateAdmitted
			}
			m.mu.Unlock()
			m.lifecycleMu.Unlock()
			if m.trackAsync() {
				go func() {
					defer m.untrackAsync()
					m.execute(execCtx, w.Request.ID, target, reservation)
				}()
			} else {
				// Close won the lifecycle race after the durable admission CAS. The
				// claim is still safe to release through the manager context; no
				// backend execution is launched after shutdown begins.
				m.releaseTarget(execCtx, reservation)
			}
			return admitCandidateAdmitted
		}()
		if candidateResult == admitCandidateNext {
			continue
		}
		return
	}
	if !stickyTargetRegistered {
		blockers = append(blockers, boundTarget+": sticky target is no longer registered")
	}
	if w.Request.Plane == domain.PlaneCreatorStudio && !creatorProfileMatched {
		blockers = append([]string{"CAPABILITY_UNAVAILABLE"}, blockers...)
	}

	wasWaiting := w.Status == domain.WorkloadWaiting
	estimatedStart := time.Now().UTC().Add(m.leaseTTL)
	estimatedEnd := estimatedStart.Add(m.leaseTTL)
	estimateConfidence := .2
	if waitingEstimate != nil {
		estimatedStart = waitingEstimate.start
		estimatedEnd = waitingEstimate.end
		estimateConfidence = waitingEstimate.confidence
	}
	w.Status = domain.WorkloadWaiting
	primaryBlocker := "no eligible capacity"
	if len(blockers) > 0 {
		primaryBlocker = blockers[0]
	}
	w.Decision = domain.AdmissionDecision{Admitted: false, Blocker: primaryBlocker, EstimatedStart: &estimatedStart, EstimatedEnd: &estimatedEnd, Confidence: estimateConfidence, Alternatives: blockers}
	w.UpdatedAt = time.Now().UTC()
	if w.Request.QueuePolicy == domain.QueueFailFast {
		w.Decision.Blocker = "no eligible capacity (fail_fast)"
		w.Status = domain.WorkloadRejected
		now := time.Now().UTC()
		w.FinishedAt = &now
	}
	if updated, mutateErr := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting), ""); mutateErr == nil {
		w = updated
	} else {
		return
	}
	if !wasWaiting {
		eventType := "workload.waiting"
		if w.Status == domain.WorkloadRejected {
			eventType = "workload.rejected"
		}
		m.audit(ctx, w.Request.OwnerID, w.Request.ID, eventType, "info", w.Decision)
		if w.Status == domain.WorkloadRejected && w.Request.Notifications.OnFinish {
			m.enqueueNotification(ctx, w, "workload.rejected")
		}
	}
}

func contextProfilePreference(left, right Target, adapter string, requirements Requirements) int {
	if requirements.ContextTokens <= 0 || left.Adapter != adapter || right.Adapter != adapter || left.Cloud != right.Cloud {
		return 0
	}
	if requirements.Model != "" && (!containsString(left.Models, requirements.Model) || !containsString(right.Models, requirements.Model)) {
		return 0
	}
	leftContext, leftFits := effectiveContextCapacity(left, requirements.ContextTokens)
	rightContext, rightFits := effectiveContextCapacity(right, requirements.ContextTokens)
	if !leftFits || !rightFits || leftContext == rightContext {
		return 0
	}
	if leftContext < rightContext {
		return -1
	}
	return 1
}

func effectiveContextCapacity(target Target, required int) (int, bool) {
	profile, found := smallestRuntimeProfile(target.RuntimeProfiles, required)
	if found && target.SupportsRuntimeProfileSwitch {
		return profile.ContextLimit, true
	}
	if target.ContextLimit > 0 && target.ContextLimit >= required {
		return target.ContextLimit, true
	}
	return target.ContextLimit, false
}

func smallestRuntimeProfile(profiles []RuntimeCapacityProfile, required int) (RuntimeCapacityProfile, bool) {
	var selected RuntimeCapacityProfile
	for _, profile := range profiles {
		if profile.ID == "" || profile.ContextLimit <= 0 || profile.Slots <= 0 || profile.ContextLimit < required {
			continue
		}
		if selected.ID == "" || profile.ContextLimit < selected.ContextLimit || (profile.ContextLimit == selected.ContextLimit && profile.Slots > selected.Slots) {
			selected = profile
		}
	}
	return selected, selected.ID != ""
}

func desiredRuntimeProfile(target Target, required int) (RuntimeCapacityProfile, bool) {
	if required <= 0 || !target.SupportsRuntimeProfileSwitch {
		return RuntimeCapacityProfile{}, false
	}
	profile, found := smallestRuntimeProfile(target.RuntimeProfiles, required)
	if !found {
		return RuntimeCapacityProfile{}, false
	}
	if target.ActiveRuntimeProfile == profile.ID && target.ContextLimit == profile.ContextLimit && target.Slots == profile.Slots {
		return RuntimeCapacityProfile{}, false
	}
	return profile, true
}

func (m *Manager) runtimeSwitchLock(target Target) *sync.Mutex {
	key := target.AcceleratorID
	if key == "" {
		key = "target/" + target.ID
	}
	m.runtimeSwitchLocksMu.Lock()
	defer m.runtimeSwitchLocksMu.Unlock()
	lock := m.runtimeSwitchLocks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		m.runtimeSwitchLocks[key] = lock
	}
	return lock
}

func (m *Manager) beginRuntimeProfileTransition(target Target, desired RuntimeCapacityProfile, nodeID string, generation uint64) (*runtimeProfileTransition, Target, error) {
	key := newID("runtime-profile")
	for {
		m.mu.RLock()
		priorKey := m.runtimeProfileTransitionTarget[target.ID]
		prior := m.runtimeProfileTransitions[priorKey]
		m.mu.RUnlock()
		if prior != nil {
			// A new physical effect must not replace a ticket while an API
			// gateway is still carrying that ticket through durable CAS/write.
			// Wait before admission/state locks, then revalidate below.
			prior.dispatchMu.Lock()
			prior.resultMu.Lock()
		}
		m.residencyAdmissionMu.Lock()
		m.mu.Lock()
		currentPriorKey := m.runtimeProfileTransitionTarget[target.ID]
		currentPrior := m.runtimeProfileTransitions[currentPriorKey]
		if currentPriorKey != priorKey || currentPrior != prior {
			m.mu.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			continue
		}
		current, found := m.targets[target.ID]
		if !found || m.targetGenerations[target.ID] != generation || !targetIdentityMatches(target, current) {
			m.mu.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			return nil, target, fmt.Errorf("runtime profile transition target changed before command")
		}
		// Starting a physical switch consumes one generation when capacity is
		// withheld and one more when its result is projected. Do not dispatch an
		// effect that can no longer complete under a monotonic uint64 fence.
		if generation >= ^uint64(0)-1 {
			m.mu.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			return nil, target, fmt.Errorf("runtime profile target generation is exhausted for a complete switch")
		}
		if priorKey != "" {
			if prior != nil && !prior.projected {
				m.mu.Unlock()
				m.residencyAdmissionMu.Unlock()
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
				return nil, target, fmt.Errorf("runtime profile observation_unavailable; prior physical switch %s requires operator reconciliation", priorKey)
			}
		}
		if reason := m.runtimeProfileTargetBlockerLocked(current); reason != "" {
			m.mu.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			return nil, target, fmt.Errorf("runtime profile observation_unavailable; %s", reason)
		}
		if nodeID == "" {
			nodeID = current.NodeID
		}
		historyBasis := current
		historyBasis.RuntimeProfiles = append([]RuntimeCapacityProfile(nil), current.RuntimeProfiles...)
		blockReason := "runtime profile observation_unavailable; physical switch outcome is unresolved"
		transition := &runtimeProfileTransition{
			commandKey: key, nodeID: nodeID, targetID: target.ID, acceleratorID: target.AcceleratorID,
			adapter: target.Adapter, endpoint: target.Endpoint, capabilityVersion: target.CapabilityVersion,
			capabilityRevision: target.CapabilityRevision, runtimeIdentity: target.RuntimeIdentity,
			modelFingerprint: target.ModelFingerprint, profile: desired,
			historyBasis: historyBasis, historyBasisGeneration: m.targetGenerations[target.ID],
		}
		current.CapacityVerified = false
		current.CapacitySource = "runtime-profile:pending"
		current.ContextLimit = 0
		current.Slots = 0
		current.ActiveRuntimeProfile = ""
		if err := m.replaceTargetLocked(current); err != nil {
			m.mu.Unlock()
			m.residencyAdmissionMu.Unlock()
			if prior != nil {
				prior.resultMu.Unlock()
				prior.dispatchMu.Unlock()
			}
			return nil, target, err
		}
		if priorKey != "" {
			delete(m.runtimeProfileTransitions, priorKey)
			delete(m.runtimeProfileTransitionTarget, target.ID)
		}
		if nodeID != "" {
			m.runtimeProfileNodeEpochs[nodeID]++
			m.runtimeProfileBlockedNodes[nodeID] = blockReason
		}
		if current.AcceleratorID != "" {
			m.runtimeProfileCardEpochs[current.AcceleratorID]++
			m.runtimeProfileBlockedCards[current.AcceleratorID] = blockReason
		}
		for aliasID, alias := range m.targets {
			sameCard := current.AcceleratorID != "" && alias.AcceleratorID == current.AcceleratorID
			if aliasID == target.ID || !sameCard {
				continue
			}
			m.runtimeProfileBlockedTargets[aliasID] = blockReason
		}
		transition.expectedGeneration = m.targetGenerations[target.ID]
		m.runtimeProfileTransitions[key] = transition
		m.runtimeProfileTransitionTarget[target.ID] = key
		m.mu.Unlock()
		m.residencyAdmissionMu.Unlock()
		if prior != nil {
			prior.resultMu.Unlock()
			prior.dispatchMu.Unlock()
		}
		return transition, current, nil
	}
}

// ValidateRuntimeProfileCommandResult validates a profile observation without
// publishing it. The API uses this before the durable command-result CAS.
func (m *Manager) ValidateRuntimeProfileCommandResult(commandKey, nodeID string, result map[string]any) error {
	return m.applyRuntimeProfileCommandResult(commandKey, nodeID, result, false)
}

// ProjectRuntimeProfileCommandResult accepts only a verified runtime slot
// observation returned by the exact pending profile-switch command. It is
// safe to call from both the websocket result handler and the command waiter.
func (m *Manager) ProjectRuntimeProfileCommandResult(commandKey, nodeID string, result map[string]any) error {
	claim, err := m.ClaimRuntimeProfileResult(commandKey, nodeID, result)
	if err != nil {
		return err
	}
	defer claim.Release()
	return claim.Project(result)
}

func (m *Manager) applyRuntimeProfileCommandResult(commandKey, nodeID string, result map[string]any, project bool) error {
	if commandKey == "" || nodeID == "" {
		return fmt.Errorf("runtime profile projection is missing command or node identity")
	}
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("runtime profile result cannot be encoded: %w", err)
	}
	var decoded runtimeProfileResult
	if err := json.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("runtime profile result is malformed: %w", err)
	}
	fingerprint := sha256.Sum256(body)
	resultFingerprint := hex.EncodeToString(fingerprint[:])
	if project {
		// Publication participates in the admission/target fence but never
		// waits for dispatchMu; a result may reenter while the sender is in its
		// websocket write callback.
		m.residencyAdmissionMu.Lock()
		m.mu.RLock()
		transition := m.runtimeProfileTransitions[commandKey]
		targetID := ""
		if transition != nil {
			targetID = transition.targetID
		}
		m.mu.RUnlock()
		var targetFence *sync.RWMutex
		if targetID != "" {
			targetFence = m.residencyAdmissionLock(targetID)
			targetFence.Lock()
		}
		defer func() {
			if targetFence != nil {
				targetFence.Unlock()
			}
			m.residencyAdmissionMu.Unlock()
		}()
	}

	m.mu.Lock()
	transition := m.runtimeProfileTransitions[commandKey]
	if transition == nil || transition.nodeID != nodeID || m.runtimeProfileTransitionTarget[transition.targetID] != commandKey {
		m.mu.Unlock()
		return fmt.Errorf("runtime profile result has no matching transition ticket")
	}
	if transition.projected {
		current, found := m.targets[transition.targetID]
		valid := found && m.targetGenerations[transition.targetID] == transition.projectedGeneration && transition.resultFingerprint == resultFingerprint && current.ActiveRuntimeProfile == transition.profile.ID && current.ContextLimit == transition.profile.ContextLimit && current.Slots == transition.profile.Slots && current.CapacityVerified && current.CapacitySource == "runtime:/slots"
		m.mu.Unlock()
		if !valid {
			return fmt.Errorf("runtime profile projection was superseded or target retired")
		}
		return nil
	}
	current, found := m.targets[transition.targetID]
	if !found || m.targetGenerations[transition.targetID] != transition.expectedGeneration || m.retiredTargets[transition.targetID].ID != "" {
		m.mu.Unlock()
		return fmt.Errorf("runtime profile transition target is stale or retired")
	}
	if current.NodeID != transition.nodeID || current.AcceleratorID != transition.acceleratorID || current.Adapter != transition.adapter || current.Endpoint != transition.endpoint || current.CapabilityVersion != transition.capabilityVersion || current.CapabilityRevision != transition.capabilityRevision || current.RuntimeIdentity != transition.runtimeIdentity || current.ModelFingerprint != transition.modelFingerprint || current.CapacityVerified || current.Slots != 0 || current.ContextLimit != 0 || current.CapacitySource != "runtime-profile:pending" {
		m.mu.Unlock()
		return fmt.Errorf("runtime profile transition route or pending generation changed")
	}
	var matched *runtimeProfileResultAdapter
	matches := 0
	for i := range decoded.Adapters {
		advertised := &decoded.Adapters[i]
		if advertised.ID == "" {
			continue
		}
		advertisedTargetID := advertised.ID
		if !strings.HasPrefix(advertisedTargetID, nodeID+"-") {
			advertisedTargetID = nodeID + "-" + advertisedTargetID
		}
		if advertisedTargetID != transition.targetID {
			continue
		}
		matches++
		matched = advertised
	}
	if matches != 1 {
		m.mu.Unlock()
		return fmt.Errorf("runtime profile result must contain exactly one matching target observation")
	}
	if matched.Adapter == "" || matched.Endpoint == "" || matched.AcceleratorIndex == nil || *matched.AcceleratorIndex < 0 || matched.Adapter != transition.adapter || matched.Endpoint != transition.endpoint || matched.Version != transition.runtimeIdentity || matched.ModelFingerprint != transition.modelFingerprint || matched.CapabilityVersion != transition.capabilityVersion || matched.CapabilityRevision != transition.capabilityRevision || fmt.Sprintf("%s-gpu%d", nodeID, *matched.AcceleratorIndex) != transition.acceleratorID {
		m.mu.Unlock()
		return fmt.Errorf("runtime profile observation is bound to a different route")
	}
	if !matched.CapabilitiesVerified || matched.CapacitySource != "runtime:/slots" || matched.ActiveRuntimeProfile != transition.profile.ID || matched.ContextLimit != transition.profile.ContextLimit || matched.Slots != transition.profile.Slots {
		m.mu.Unlock()
		return fmt.Errorf("runtime profile observation does not verify the requested profile, context, and slots")
	}
	profileMatches := 0
	for _, profile := range matched.RuntimeProfiles {
		if profile.ID != transition.profile.ID {
			continue
		}
		profileMatches++
		if profile.ContextLimit != transition.profile.ContextLimit || profile.Slots != transition.profile.Slots {
			m.mu.Unlock()
			return fmt.Errorf("runtime profile observation advertises conflicting profile dimensions")
		}
	}
	if profileMatches != 1 {
		m.mu.Unlock()
		return fmt.Errorf("runtime profile observation must advertise the requested profile exactly once")
	}
	if !project {
		m.mu.Unlock()
		return nil
	}
	current = projectedRuntimeProfileTarget(current, transition.profile)
	if err := m.replaceTargetLocked(current); err != nil {
		m.mu.Unlock()
		return err
	}
	aliasReason := "runtime profile observation is correlated only for another route; operator reconciliation is required"
	for targetID, alias := range m.targets {
		sameCard := transition.acceleratorID != "" && alias.AcceleratorID == transition.acceleratorID
		if targetID == transition.targetID || !sameCard {
			continue
		}
		m.runtimeProfileBlockedTargets[targetID] = aliasReason
	}
	transition.projected = true
	transition.projectedGeneration = m.targetGenerations[transition.targetID]
	transition.resultFingerprint = resultFingerprint
	if transition.nodeID != "" && !m.runtimeProfileHasPendingLocked(transition.nodeID, "") {
		delete(m.runtimeProfileBlockedNodes, transition.nodeID)
	}
	if transition.acceleratorID != "" && !m.runtimeProfileHasPendingLocked("", transition.acceleratorID) {
		delete(m.runtimeProfileBlockedCards, transition.acceleratorID)
	}
	m.mu.Unlock()
	return nil
}

func projectedRuntimeProfileTarget(target Target, profile RuntimeCapacityProfile) Target {
	target.ActiveRuntimeProfile = profile.ID
	target.ContextLimit = profile.ContextLimit
	target.Slots = profile.Slots
	target.CapacitySource = "runtime:/slots"
	target.CapacityVerified = true
	return target
}

func (m *Manager) ensureRuntimeProfile(ctx context.Context, target Target, desired RuntimeCapacityProfile, workload *domain.Workload) (Target, string, error) {
	key := target.AcceleratorID
	if key == "" {
		key = "target/" + target.ID
	}
	for {
		m.runtimeSwitchLocksMu.Lock()
		inFlight := m.runtimeSwitchInFlight[key]
		if inFlight == nil {
			inFlight = make(chan struct{})
			m.runtimeSwitchInFlight[key] = inFlight
			m.runtimeSwitchLocksMu.Unlock()
			defer func() {
				m.runtimeSwitchLocksMu.Lock()
				if current := m.runtimeSwitchInFlight[key]; current == inFlight {
					delete(m.runtimeSwitchInFlight, key)
					close(inFlight)
				}
				m.runtimeSwitchLocksMu.Unlock()
			}()
			break
		}
		m.runtimeSwitchLocksMu.Unlock()
		select {
		case <-inFlight:
			continue
		case <-ctx.Done():
			return target, "", ctx.Err()
		}
	}

	m.mu.RLock()
	current, found := m.targets[target.ID]
	generation := m.targetGenerations[target.ID]
	m.mu.RUnlock()
	if !found {
		return target, "runtime profile transition target is no longer advertised", nil
	}
	target = current
	if target.CapacitySource == "runtime-profile:observation_unavailable" {
		return target, "runtime profile observation is unavailable; operator reconciliation is required", nil
	}
	m.mu.RLock()
	if pendingKey := m.runtimeProfileTransitionTarget[target.ID]; pendingKey != "" {
		if pending := m.runtimeProfileTransitions[pendingKey]; pending != nil && !pending.projected {
			m.mu.RUnlock()
			return target, "runtime profile observation_unavailable; operator reconciliation required", nil
		}
	}
	m.mu.RUnlock()
	if target.ActiveRuntimeProfile == desired.ID && target.ContextLimit == desired.ContextLimit && target.Slots == desired.Slots && target.CapacityVerified && target.CapacitySource == "runtime:/slots" {
		return target, "", nil
	}
	m.placementMu.Lock()
	for _, active := range m.activePlacements {
		if active.acceleratorID == target.AcceleratorID {
			m.placementMu.Unlock()
			return target, "runtime profile transition is waiting for the accelerator to become idle", nil
		}
	}
	m.placementMu.Unlock()
	control, nodeID, ok := m.nodeControlForTarget(ctx, target)
	if !ok {
		return target, "runtime profile switch control is unavailable", nil
	}
	owner := "profile-switch/" + workload.Request.ID
	lease, acquired, err := m.store.AcquireAcceleratorLease(ctx, target.AcceleratorID, owner, 2*time.Minute)
	if err != nil {
		return target, "", err
	}
	if !acquired {
		return target, "runtime profile transition is waiting for accelerator lease", nil
	}
	defer func() {
		if releaseErr := m.rollbackAcceleratorLease(ctx, lease, owner); releaseErr != nil && !errors.Is(releaseErr, errLeaseCleanupRecorded) {
			m.log.Error("runtime profile lease cleanup requires durable retry", "accelerator_id", lease.AcceleratorID, "owner", owner, "error", releaseErr)
		}
	}()
	transition, pendingTarget, err := m.beginRuntimeProfileTransition(target, desired, nodeID, generation)
	if err != nil {
		return target, "", err
	}
	target = pendingTarget
	result, err := control(ctx, nodeID, "switch_runtime_profile", map[string]any{"target_id": target.ID, "profile_id": desired.ID}, transition.commandKey)
	if err != nil {
		return target, "", err
	}
	if err = m.ProjectRuntimeProfileCommandResult(transition.commandKey, nodeID, result); err != nil {
		return target, "", fmt.Errorf("runtime profile observation rejected: %w", err)
	}
	target = m.targetByID(target.ID)
	m.audit(ctx, workload.Request.OwnerID, workload.Request.ID, "runtime.profile_switched", "info", map[string]any{"target_id": target.ID, "profile_id": desired.ID, "context_limit": desired.ContextLimit, "slots": desired.Slots})
	return target, "", nil
}

type targetEstimate struct {
	start      time.Time
	end        time.Time
	duration   time.Duration
	confidence float64
	score      float64
}

func preferEstimate(current, candidate *targetEstimate) *targetEstimate {
	if candidate == nil {
		return current
	}
	if current == nil || candidate.start.Before(current.start) || (candidate.start.Equal(current.start) && candidate.end.Before(current.end)) {
		copy := *candidate
		return &copy
	}
	return current
}

// estimateTargets derives execution p95s and queue delay from durable real
// workload history. Sparse targets remain deliberately low-confidence and use
// the lease TTL as a conservative fallback instead of manufacturing precision.
func (m *Manager) estimateTargets(ctx context.Context, targets []Target, workload *domain.Workload, requirements Requirements) map[string]*targetEstimate {
	now := time.Now().UTC()
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		rows = nil
	}
	targetByID := make(map[string]Target, len(targets))
	durations := make(map[string][]time.Duration, len(targets))
	for _, target := range targets {
		targetByID[target.ID] = target
	}
	for _, row := range rows {
		if row.Plan == nil || row.FinishedAt == nil || (row.StartedAt == nil && row.Execution == nil) || row.Status != domain.WorkloadSucceeded || row.Request.WorkloadType != workload.Request.WorkloadType {
			continue
		}
		var startedAt time.Time
		if row.Execution != nil {
			startedAt = row.Execution.StartedAt
		}
		if row.StartedAt != nil {
			startedAt = *row.StartedAt
		}
		duration := row.FinishedAt.Sub(startedAt)
		if duration > 0 {
			durations[row.Plan.TargetID] = append(durations[row.Plan.TargetID], duration)
		}
	}
	p95 := make(map[string]time.Duration, len(targets))
	for _, target := range targets {
		values := durations[target.ID]
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		if len(values) == 0 {
			m.learningMu.RLock()
			profile := m.interferenceProfiles[standaloneProfileKey(target)]
			if profile != nil && profile.Confidence >= .5 && profile.P95DurationMS > 0 {
				p95[target.ID] = time.Duration(profile.P95DurationMS) * time.Millisecond
			} else {
				p95[target.ID] = m.leaseTTL
			}
			m.learningMu.RUnlock()
		} else {
			index := (95*len(values)+99)/100 - 1
			p95[target.ID] = values[index]
		}
	}

	result := make(map[string]*targetEstimate, len(targets))
	for _, target := range targets {
		duration := p95[target.ID]
		queueDelay := time.Duration(0)
		for _, row := range rows {
			if row.Status != domain.WorkloadRunning || row.Plan == nil || (row.StartedAt == nil && row.Execution == nil) || row.Request.ID == workload.Request.ID {
				continue
			}
			otherTarget := targetByID[row.Plan.TargetID]
			sameTarget := row.Plan.TargetID == target.ID
			sameAccelerator := target.AcceleratorID != "" && otherTarget.AcceleratorID == target.AcceleratorID
			if !sameTarget && !sameAccelerator {
				continue
			}
			if sameTarget && m.availableSlots(target) > 0 {
				continue
			}
			remaining := p95[row.Plan.TargetID]
			if remaining <= 0 {
				remaining = m.leaseTTL
			}
			if row.Progress > 0 && row.Progress < 1 {
				remaining = time.Duration(float64(remaining) * (1 - row.Progress))
			} else {
				var startedAt time.Time
				if row.Execution != nil {
					startedAt = row.Execution.StartedAt
				}
				if row.StartedAt != nil {
					startedAt = *row.StartedAt
				}
				if elapsed := now.Sub(startedAt); elapsed > 0 && elapsed < remaining {
					remaining -= elapsed
				}
			}
			if queueDelay == 0 || remaining < queueDelay {
				queueDelay = remaining
			}
		}
		transitionCost := time.Duration(0)
		if requirements.Model != "" && !containsString(target.ResidentModels, requirements.Model) && target.SupportsModelLifecycle {
			transitionCost = minDuration(30*time.Second, m.leaseTTL)
		}
		start := now.Add(queueDelay + transitionCost)
		confidence := .25
		if samples := len(durations[target.ID]); samples > 0 {
			confidence = math.Min(.9, .35+.55*float64(samples)/float64(samples+4))
		}
		score := (queueDelay + transitionCost).Seconds() + duration.Seconds()*.05
		if slack, known := contextSlack(target, requirements.ContextTokens); known && target.ContextLimit > 0 {
			score += 10 * float64(slack) / float64(target.ContextLimit)
		} else if requirements.ContextTokens > 0 {
			score += 15
		}
		if target.Cloud {
			score += 20
		}
		if !target.CapacityVerified {
			score += 2
		}
		if target.PredictedSlowdown > 1 {
			score += (target.PredictedSlowdown - 1) * duration.Seconds()
		}
		score += m.creatorHintAdjustment(ctx, workload, target)
		end := start.Add(duration)
		if workload.Request.Deadline != nil && end.After(*workload.Request.Deadline) {
			score += 10_000 + end.Sub(*workload.Request.Deadline).Seconds()
		}
		result[target.ID] = &targetEstimate{start: start, end: end, duration: duration, confidence: confidence, score: score}
	}
	return result
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func effectivePriority(request domain.WorkloadRequest) int {
	priority := request.Priority
	switch request.QoS {
	case domain.QoSInteractive:
		priority += 20
	case domain.QoSBackground:
		priority -= 20
	}
	return priority
}

func effectiveWorkloadPriority(workload *domain.Workload) int {
	request := workload.Request
	if workload.RuntimePriority != nil {
		request.Priority = *workload.RuntimePriority
	}
	return effectivePriority(request)
}

func (m *Manager) inventoryBlocker(ctx context.Context, target Target, requirements Requirements) string {
	if m.nodes == nil || target.Cloud || target.AcceleratorID == "" {
		return ""
	}
	nodes, err := m.nodes.ListNodes(ctx)
	if err != nil {
		return "inventory unavailable"
	}
	for _, node := range nodes {
		for _, accelerator := range node.Accelerators {
			if accelerator.ID != target.AcceleratorID {
				continue
			}
			if node.Observed.Connectivity != domain.ConnectivityConnected || !node.Observed.Ready {
				return "node disconnected or not ready"
			}
			if node.SchedulingState != domain.SchedulingEnabled || !node.Desired.SchedulingEnabled {
				return "node scheduling disabled"
			}
			if requirements.EstimatedVRAMMB > 0 && accelerator.VRAMFreeMB < requirements.EstimatedVRAMMB {
				return "insufficient measured VRAM"
			}
			return ""
		}
	}
	return "accelerator not present in live inventory"
}

func contextSlack(target Target, required int) (int, bool) {
	if target.ContextLimit <= 0 {
		return int(^uint(0) >> 1), false
	}
	if required > target.ContextLimit {
		return int(^uint(0) >> 1), true
	}
	return target.ContextLimit - required, true
}

func estimateTargetCost(target Target, requirements Requirements) int64 {
	if !target.Cloud || requirements.ContextTokens <= 0 {
		return 0
	}
	rate := target.InputCentsPerMTok
	if target.OutputCentsPerMTok > rate {
		rate = target.OutputCentsPerMTok
	}
	if rate <= 0 {
		return 0
	}
	numerator := int64(requirements.ContextTokens) * rate
	return (numerator + 999_999) / 1_000_000
}

func (m *Manager) principalActiveCount(ctx context.Context, principalID, excludeWorkloadID string) int {
	if principalID == "" {
		return 0
	}
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		return 0
	}
	active := 0
	for _, row := range rows {
		if row.Request.ID != excludeWorkloadID && row.Request.PrincipalID == principalID && row.Status == domain.WorkloadRunning {
			active++
		}
	}
	return active
}

func budgetActualCents(workload *domain.Workload) int64 {
	if workload == nil {
		return 0
	}
	if workload.Plan == nil || workload.Plan.EstimatedCostCents <= 0 {
		if workload.BudgetReservationCents > 0 {
			return workload.BudgetReservationCents
		}
		return 0
	}
	actual := workload.Plan.EstimatedCostCents
	var response struct {
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(workload.InlineOutput, &response) == nil && (response.Usage.PromptTokens > 0 || response.Usage.CompletionTokens > 0) {
		numerator := response.Usage.PromptTokens*workload.Plan.InputCentsPerMTok + response.Usage.CompletionTokens*workload.Plan.OutputCentsPerMTok
		if numerator > 0 {
			actual = (numerator + 999_999) / 1_000_000
		}
	}
	return actual
}

// ensureBudgetSettlementIntent is called inside every workload CAS boundary.
// Terminal state cannot become durable while a token-bound settlement intent
// is absent, closing the crash window between terminalization and settlement.
func ensureBudgetSettlementIntent(workload *domain.Workload) error {
	if workload == nil || !isTerminalWorkloadStatus(workload.Status) || workload.BudgetReservationToken == "" || workload.BudgetReservationAttempt == 0 {
		return nil
	}
	actual := budgetActualCents(workload)
	if actual <= 0 {
		return fmt.Errorf("budget reservation has no priced settlement amount")
	}
	if workload.BudgetSettlementPending {
		if workload.BudgetSettlementAttempt != workload.BudgetReservationAttempt || workload.BudgetSettlementActualCents != actual {
			return fmt.Errorf("budget settlement intent belongs to another attempt")
		}
		return nil
	}
	workload.ActualCostCents = actual
	workload.BudgetSettlementPending = true
	workload.BudgetSettlementAttempt = workload.BudgetReservationAttempt
	workload.BudgetSettlementActualCents = actual
	return nil
}

func (m *Manager) settleWorkloadBudget(ctx context.Context, workload *domain.Workload) {
	actual := budgetActualCents(workload)
	if actual <= 0 {
		return
	}
	latest, err := m.store.GetWorkload(ctx, workload.Request.ID)
	if err != nil || latest.CancellationOwner != "" {
		// A cancellation owner still holds the row, or the durable row could
		// not be read. Do not settle budget against an observation that has not
		// crossed the durable CAS.
		return
	}
	status := latest.Status
	if latest.BudgetReservationToken == "" || latest.BudgetReservationAttempt == 0 {
		return
	}
	// Publish the settlement intent before touching the budget store. A crash
	// after this CAS is recoverable: the worker repeats the exact token-bound
	// idempotent settle and clears the marker only after it observes success.
	persisted, casErr := m.mutateWorkloadCAS(ctx, workload.Request.ID, workloadStatuses(status), "", func(current *domain.Workload) error {
		current.ActualCostCents = actual
		if !current.BudgetSettlementPending {
			current.BudgetSettlementPending = true
			current.BudgetSettlementAttempt = current.BudgetReservationAttempt
			current.BudgetSettlementActualCents = actual
		} else if current.BudgetSettlementAttempt != current.BudgetReservationAttempt || current.BudgetSettlementActualCents != actual {
			return fmt.Errorf("budget settlement intent belongs to another attempt")
		}
		current.UpdatedAt = time.Now().UTC()
		return nil
	})
	if casErr != nil {
		return
	}
	*workload = *persisted
	if err := m.retryBudgetSettlementIntent(ctx, workload); err != nil {
		m.log.Warn("budget settlement intent remains pending", "workload_id", workload.Request.ID, "error", err)
	}
}

// releaseBudgetClaimAfterWorkloadCAS records a durable cleanup intent while
// retaining the published claim, releases the exact reservation, and clears
// the linkage only after the side effect succeeds. If release fails, the
// intent remains durable for startup retry.
func (m *Manager) releaseBudgetClaimAfterWorkloadCAS(ctx context.Context, workloadID, token string, attempt uint64) error {
	if token == "" {
		return nil
	}
	latest, err := m.store.GetWorkload(ctx, workloadID)
	if err != nil {
		return err
	}
	if latest.BudgetCleanupToken != "" {
		if latest.BudgetCleanupToken != token || latest.BudgetCleanupAttempt != attempt {
			return fmt.Errorf("budget cleanup intent belongs to another attempt")
		}
		return m.retryBudgetCleanupIntent(ctx, latest)
	}
	// Cleanup is only safe when the durable workload already owns the exact
	// token/attempt. Never retrofit linkage from a caller-supplied token: that
	// would let a stale admission attempt release another attempt's claim.
	if latest.BudgetReservationToken == "" {
		return fmt.Errorf("budget claim has no safe durable workload linkage")
	}
	if latest.BudgetReservationToken != token || latest.BudgetReservationAttempt != attempt {
		return fmt.Errorf("budget claim token is owned by another admission attempt")
	}
	if latest.CancellationOwner != "" {
		return fmt.Errorf("budget claim is owned by cancellation flow")
	}
	if latest.Status != domain.WorkloadQueued && latest.Status != domain.WorkloadWaiting && latest.Status != domain.WorkloadPendingApproval {
		return fmt.Errorf("budget claim cannot be released from workload status %s", latest.Status)
	}
	latest.BudgetCleanupToken = token
	latest.BudgetCleanupAttempt = attempt
	latest.UpdatedAt = time.Now().UTC()
	// Keep the reservation linkage published while the cleanup intent is
	// durable. This closes the crash window between unlinking the workload and
	// releasing the claim, and prevents a new admission from racing the old
	// side effect.
	if _, err := m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadPendingApproval), latest.CancellationOwner); err != nil {
		return err
	}
	return m.retryBudgetCleanupIntent(ctx, latest)
}

func (m *Manager) retryBudgetCleanupIntent(ctx context.Context, workload *domain.Workload) error {
	if workload == nil || workload.BudgetCleanupToken == "" || workload.BudgetCleanupAttempt == 0 {
		return nil
	}
	if workload.BudgetReservationToken != "" && (workload.BudgetReservationToken != workload.BudgetCleanupToken || workload.BudgetReservationAttempt != workload.BudgetCleanupAttempt) {
		return fmt.Errorf("budget cleanup intent does not match published reservation")
	}
	if err := m.store.ReleaseBudgetClaim(ctx, workload.Request.ID, workload.BudgetCleanupToken, workload.BudgetCleanupAttempt); err != nil {
		return err
	}
	latest, err := m.store.GetWorkload(ctx, workload.Request.ID)
	if err != nil {
		return err
	}
	if latest.BudgetCleanupToken != workload.BudgetCleanupToken || latest.BudgetCleanupAttempt != workload.BudgetCleanupAttempt {
		return fmt.Errorf("budget cleanup intent changed during release")
	}
	latest.BudgetReservationToken = ""
	latest.BudgetReservationAttempt = 0
	latest.BudgetCleanupToken = ""
	latest.BudgetCleanupAttempt = 0
	latest.UpdatedAt = time.Now().UTC()
	_, err = m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadPendingApproval), latest.CancellationOwner)
	return err
}

func (m *Manager) retryBudgetSettlementIntent(ctx context.Context, workload *domain.Workload) error {
	if workload == nil || !workload.BudgetSettlementPending || workload.BudgetReservationToken == "" || workload.BudgetSettlementAttempt == 0 {
		return nil
	}
	if _, err := m.store.SettleBudgetClaim(ctx, workload.Request.ID, workload.BudgetReservationToken, workload.BudgetSettlementAttempt, workload.BudgetSettlementActualCents); err != nil {
		return err
	}
	latest, err := m.store.GetWorkload(ctx, workload.Request.ID)
	if err != nil {
		return err
	}
	if latest.BudgetReservationToken != workload.BudgetReservationToken || latest.BudgetReservationAttempt != workload.BudgetSettlementAttempt {
		return fmt.Errorf("budget settlement intent changed during settlement")
	}
	latest.BudgetSettlementPending = false
	latest.BudgetSettlementAttempt = 0
	latest.BudgetSettlementActualCents = 0
	latest.UpdatedAt = time.Now().UTC()
	_, err = m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadCancelled), latest.CancellationOwner)
	return err
}

func (m *Manager) providerCircuitOpen(targetID string) (time.Time, bool) {
	m.providerMu.Lock()
	defer m.providerMu.Unlock()
	circuit, found := m.providerCircuits[targetID]
	if !found || !circuit.OpenUntil.After(time.Now()) {
		return time.Time{}, false
	}
	return circuit.OpenUntil, true
}

func (m *Manager) recordProviderFailure(target Target, failure error) (time.Time, bool) {
	var backend *BackendError
	if !errors.As(failure, &backend) || !backend.Retryable {
		return time.Time{}, false
	}
	delay := backend.RetryAfter
	if delay < time.Second {
		delay = time.Second
	}
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}
	if !target.Cloud {
		return time.Now().UTC().Add(delay), true
	}
	m.providerMu.Lock()
	circuit := m.providerCircuits[target.ID]
	circuit.Failures++
	circuit.OpenUntil = time.Now().UTC().Add(delay)
	m.providerCircuits[target.ID] = circuit
	m.providerMu.Unlock()
	return circuit.OpenUntil, true
}

func (m *Manager) recordProviderSuccess(target Target) {
	if !target.Cloud {
		return
	}
	m.providerMu.Lock()
	delete(m.providerCircuits, target.ID)
	m.providerMu.Unlock()
}

// retryProviderFailure performs scheduler-level failover only for explicitly
// recoverable work and structured transient failures. It never loops inside
// an adapter, persists the failed-target cooldown, and caps total attempts.
func (m *Manager) retryProviderFailure(ctx context.Context, workload *domain.Workload, target Target, failure error) bool {
	retryAt, retryable := m.recordProviderFailure(target, failure)
	if !retryable || !workload.Request.Recoverable || workload.ExecutionAttempts >= 4 {
		return false
	}
	latest, err := m.store.GetWorkload(ctx, workload.Request.ID)
	if err != nil || latest.Status == domain.WorkloadCancelled {
		return false
	}
	if latest.TargetRetryAfter == nil {
		latest.TargetRetryAfter = make(map[string]time.Time)
	}
	latest.TargetRetryAfter[target.ID] = retryAt
	latest.Status = domain.WorkloadQueued
	latest.Decision = domain.AdmissionDecision{Admitted: false, Blocker: target.ID + ": transient provider failure; selecting fallback", Confidence: .8, Alternatives: []string{failure.Error()}}
	latest.Plan = nil
	latest.Execution = nil
	latest.Error = failure.Error()
	latest.UpdatedAt = time.Now().UTC()
	latest.FinishedAt = nil
	if _, err := m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadRunning, domain.WorkloadWaiting, domain.WorkloadQueued), ""); err != nil {
		return false
	}
	// Release only after the durable fallback transition wins. A failed CAS
	// must leave the original reservation untouched for its current owner.
	if releaseErr := m.releaseBudgetClaimAfterWorkloadCAS(ctx, latest.Request.ID, latest.BudgetReservationToken, latest.BudgetReservationAttempt); releaseErr != nil {
		// The workload is durably queued, but fallback must stop here: trying a
		// second provider while the old budget claim is unresolved would create
		// two admission attempts against one unsettled reservation. Reconciliation
		// will retry the exact token-bound cleanup and wake admission afterward.
		m.log.Warn("provider fallback paused until budget cleanup succeeds", "workload_id", latest.Request.ID, "error", releaseErr)
		latest.Decision.Blocker = "budget cleanup pending; provider fallback paused"
		latest.Error = "budget cleanup pending: " + releaseErr.Error()
		latest.UpdatedAt = time.Now().UTC()
		_, _ = m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadQueued), "")
		return true
	}
	m.audit(ctx, latest.Request.OwnerID, latest.Request.ID, "workload.provider_fallback", "warn", map[string]any{"failed_target": target.ID, "retry_after": retryAt, "attempt": latest.ExecutionAttempts, "error": failure.Error()})
	m.signal()
	return true
}

func (m *Manager) availableSlots(target Target) int {
	if target.CapacitySource == "runtime-profile:observation_unavailable" {
		return 0
	}
	m.residencyAdmissionMu.Lock()
	defer m.residencyAdmissionMu.Unlock()
	m.mu.RLock()
	current, found := m.targets[target.ID]
	if !found || !targetIdentityMatches(target, current) {
		m.mu.RUnlock()
		return 0
	}
	target = current
	if m.runtimeProfileTargetBlockerLocked(target) != "" {
		m.mu.RUnlock()
		return 0
	}
	pendingKey := m.runtimeProfileTransitionTarget[target.ID]
	pending := pendingKey != "" && m.runtimeProfileTransitions[pendingKey] != nil && !m.runtimeProfileTransitions[pendingKey].projected
	m.mu.RUnlock()
	if pending {
		return 0
	}
	slots := target.Slots
	if slots <= 0 {
		slots = 1
	}
	m.placementMu.Lock()
	active := m.targetActive[target.ID]
	m.placementMu.Unlock()
	return slots - active
}

func (m *Manager) boundTarget(ctx context.Context, req domain.WorkloadRequest) string {
	if req.PlacementKey == "" {
		return ""
	}
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		return ""
	}
	var target string
	var newest time.Time
	for _, row := range rows {
		if row.Request.ID == req.ID || row.Request.OwnerID != req.OwnerID || row.Request.Adapter != req.Adapter || row.Request.PlacementKey != req.PlacementKey || row.Plan == nil {
			continue
		}
		if row.CreatedAt.After(newest) {
			target = row.Plan.TargetID
			newest = row.CreatedAt
		}
	}
	return target
}

type targetReservation struct {
	targetID         string
	workloadID       string
	targetGeneration uint64
	comfySchemaProof  comfySchemaProof
	lease            *domain.AcceleratorLease
	shared           bool
	predictedVRAMMB  int64
	reserveVRAMMB    int64
	capacityVRAMMB   int64
	maxSlowdown      float64
	exploration      bool
	profileKey       string
	workloadClasses  []string
	runtimeVersion   string
	exactProfileKey  string
	releaseRequested bool
	releaseInFlight  bool
	released         bool
	cleanupIntent    *domain.AcceleratorLeaseCleanupIntent
	// backendCleanup retains the exact handle/adapter/target while a physical
	// stop is still unconfirmed. Capacity remains fenced until the retry worker
	// confirms cancellation and release; a lease cleanup intent alone is not
	// sufficient because it carries no backend handle.
	backendHandle          *domain.ExecutionHandle
	backendAdapter         Adapter
	backendTarget          Target
	backendStopPending     bool
	backendStopConfirmed   bool
	backendStopInFlight    bool
	backendCleanupMessage  string
	backendCleanupTerminal string
	// checkpointOperationID links a resumed generation to its durable
	// restore/cleanup journal. It is populated before ResumeWithLease crosses
	// the physical boundary so a later cleanup failure is restart-safe.
	checkpointOperationID string
}

// admitCandidateResult is returned by the per-target admission scope. Keeping
// the candidate in a function (rather than using continue from the outer
// loop) gives its budget-attempt defer one structural exit for every failure
// path. A linked claim is therefore either transferred by the runnable CAS or
// released by the bounded cleanup path before the next candidate is tried.
type admitCandidateResult uint8

const (
	admitCandidateNext admitCandidateResult = iota
	admitCandidateStopped
	admitCandidateAdmitted
)

type activePlacement struct {
	workloadID         string
	targetID           string
	acceleratorID      string
	workloadClass      string
	runtimeVersion     string
	fingerprint        string
	disruption         domain.DisruptionPolicy
	vramMB             int64
	capacityVRAMMB     int64
	reserveVRAMMB      int64
	sharingEnabled     bool
	guardedExploration bool
	predictedSlowdown  float64
	maxSlowdown        float64
	safetyCritical     bool
	sharedObserved     bool
	model              string
	contextTokens      int
	targetGeneration   uint64
	profileID          string
	runtimeIdentity    string
	// requestIncrementBytes is populated only from an identity-bound runtime
	// observation. EstimatedVRAMMB and standalone envelopes never populate it.
	requestIncrementBytes int64
	requestIncrementVerified bool
}

type pendingStream struct {
	ctx         context.Context
	cancel      context.CancelFunc
	target      Target
	reservation *targetReservation
	timer       *time.Timer
	timerDone   sync.Once
}

// errStreamPreempted is an internal segment result.  It is deliberately not
// exposed as a workload failure: the durable workload is requeued and the
// attached interactive session waits for the next admission segment.
var errStreamPreempted = errors.New("interactive stream backend segment preempted")

type streamSegment struct {
	ctx         context.Context
	target      Target
	reservation *targetReservation
}

type streamSession struct {
	emit       func([]byte) error
	segments   chan streamSegment
	clientDone chan struct{}

	mu                 sync.Mutex
	preemptRequested   bool
	clientDisconnected bool
}

func newStreamSession(emit func([]byte) error) *streamSession {
	return &streamSession{emit: emit, segments: make(chan streamSegment, 1), clientDone: make(chan struct{})}
}

func (s *streamSession) markPreempting() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.preemptRequested = true
	s.mu.Unlock()
}

func (s *streamSession) clearPreempting() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.preemptRequested = false
	s.mu.Unlock()
}

func (s *streamSession) isPreempting() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preemptRequested
}

func (s *streamSession) disconnect() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.clientDisconnected {
		s.clientDisconnected = true
		close(s.clientDone)
	}
	s.mu.Unlock()
}

func (s *streamSession) isDisconnected() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientDisconnected
}

// stopPendingStreamTimer releases the timer's async slot only when Stop
// proves that the callback will not run. If Stop returns false, the callback
// owns the slot and releases it in its defer after all expiration work ends.
func (m *Manager) stopPendingStreamTimer(pending *pendingStream) {
	if pending == nil || pending.timer == nil {
		return
	}
	if pending.timer.Stop() {
		pending.timerDone.Do(m.untrackAsync)
	}
}

func (m *Manager) expirePendingStream(id string, pending *pendingStream) {
	m.mu.Lock()
	if m.pendingStreams[id] != pending {
		m.mu.Unlock()
		return
	}
	delete(m.pendingStreams, id)
	delete(m.cancels, id)
	m.mu.Unlock()
	pending.cancel()
	ctx := m.lifecycleContext()
	w, getErr := m.store.GetWorkload(ctx, id)
	if getErr != nil {
		m.log.Error("expired stream workload lookup failed", "workload_id", id, "error", getErr)
		m.signal()
		return
	}
	if releaseErr := m.releaseBeforeTerminal(ctx, w, pending.reservation, "failure", "stream client did not attach within 5 seconds"); releaseErr != nil {
		m.log.Error("expired stream remains non-terminal until accelerator cleanup is durable", "workload_id", id, "error", releaseErr)
		m.signal()
		return
	}
	m.fail(ctx, w, "stream client did not attach within 5 seconds")
	m.signal()
}

func (m *Manager) reserveTarget(ctx context.Context, target Target, workload *domain.Workload, requirements Requirements) (*targetReservation, bool, string, error) {
	// Bind direct callers to the normalized live advertisement before taking a
	// generation snapshot. The final fenced phase below repeats this check so
	// a refresh that wins immediately before publication cannot leave stale
	// placement facts behind.
	if current := m.targetByID(target.ID); current.ID != "" {
		target = current
	}
	m.mu.RLock()
	blockedReason := m.runtimeProfileTargetBlockerLocked(target)
	pendingKey := m.runtimeProfileTransitionTarget[target.ID]
	runtimeProfilePending := pendingKey != "" && m.runtimeProfileTransitions[pendingKey] != nil && !m.runtimeProfileTransitions[pendingKey].projected
	m.mu.RUnlock()
	if runtimeProfilePending {
		return nil, false, "runtime profile transition is awaiting observed capacity", nil
	}
	if blockedReason != "" {
		return nil, false, "runtime profile observation is unavailable; operator reconciliation is required", nil
	}
	if target.CapacitySource == "runtime-profile:observation_unavailable" {
		return nil, false, "runtime profile observation is unavailable; operator reconciliation is required", nil
	}
	if err := validateCapacityByteFields(target); err != nil {
		return nil, false, "", err
	}
	if err := validateTargetMiBFields(target); err != nil {
		return nil, false, "", err
	}
	if requirements.EstimatedVRAMMB < 0 {
		return nil, false, "", fmt.Errorf("estimated_vram_mb must be non-negative")
	}
	if requirements.ContextTokens < 0 {
		return nil, false, "", fmt.Errorf("context_tokens must be non-negative")
	}
	if _, err := checkedMiBToBytes(requirements.EstimatedVRAMMB, "estimated_vram_mb"); err != nil {
		return nil, false, "", err
	}
	if err := m.validateActivePlacementBytes(target.AcceleratorID); err != nil {
		return nil, false, "", err
	}
	// Snapshot manager-only facts before taking placementMu. The placement
	// fence is deliberately never nested inside m.mu and is never held across
	// the durable accelerator-lease call below.
	m.mu.RLock()
	targetGeneration := m.targetGenerations[target.ID]
	modelLimit := m.modelLimitLocked(requirements.Model)
	requestObserver, _ := m.adapters[target.Adapter].(RequestVRAMIncrementObserver)
	m.mu.RUnlock()
	var increment RequestVRAMIncrementObservation
	if requestObserver != nil && requirements.Model != "" {
		observed, observeErr := requestObserver.ObserveRequestVRAMIncrement(ctx, target, workload.Request, requirements)
		if observeErr != nil {
			if !errors.Is(observeErr, ErrUnsupported) {
				return nil, false, "authoritative request VRAM increment observation unavailable", nil
			}
		} else {
			if err := validateRequestVRAMIncrementObservation(observed, target, workload.Request.ID, requirements, targetGeneration, time.Now().UTC()); err != nil {
				return nil, false, "authoritative request VRAM increment observation is invalid", nil
			}
			observed.TargetGeneration = targetGeneration
			increment = observed
			if !m.targetFenceMatches(target, targetGeneration) {
				return nil, false, "target facts changed during request capacity observation", nil
			}
		}
	}
	slots := target.Slots
	if slots <= 0 {
		slots = 1
	}
	workloadID := workload.Request.ID
	leaseID := target.AcceleratorID
	if leaseID == "" {
		leaseID = "virtual/" + target.ID
	}
	placement := activePlacement{
		workloadID: workloadID, targetID: target.ID, acceleratorID: leaseID,
		workloadClass: targetWorkloadClass(target), runtimeVersion: target.CapabilityVersion, fingerprint: workloadProfileFingerprint(target, workload.Request), disruption: workload.Request.Disruption,
		vramMB: target.StandaloneVRAMMB, capacityVRAMMB: target.AcceleratorVRAMMB,
		reserveVRAMMB: target.VRAMReserveMB, sharingEnabled: target.SharingEnabled,
		guardedExploration: target.GuardedExploration, predictedSlowdown: target.PredictedSlowdown,
		maxSlowdown: target.MaxSlowdown, safetyCritical: target.SafetyCritical,
		model: requirements.Model, contextTokens: requirements.ContextTokens,
		targetGeneration: targetGeneration, profileID: target.ActiveRuntimeProfile,
		runtimeIdentity: residencyCapacityIdentity(target),
	}
	if increment.Verified {
		placement.requestIncrementBytes = increment.Bytes
		placement.requestIncrementVerified = true
	}
	if placement.vramMB <= 0 {
		m.learningMu.RLock()
		profile := m.interferenceProfiles[standaloneRequestProfileKey(target, workload.Request)]
		if profile == nil || profile.Confidence < .5 {
			profile = m.interferenceProfiles[standaloneProfileKey(target)]
		}
		if profile != nil && profile.Confidence >= .5 {
			placement.vramMB = profile.P95VRAMMB
		}
		m.learningMu.RUnlock()
	}
	if placement.maxSlowdown <= 0 {
		placement.maxSlowdown = 1.25
	}
	if _, err := checkedMiBToBytes(placement.vramMB, "active placement vram_mb"); err != nil {
		return nil, false, "", err
	}
	targetFence := m.residencyAdmissionLock(target.ID)
	for {
		// Fast path and co-scheduling decisions are fully in-memory and brief.
		// The manager-wide admission fence is acquired before the per-target
		// fence (the same order used by RegisterTarget/reconcile/policy). This
		// makes the placement publication atomic with the target snapshot while
		// keeping all durable calls outside both locks.
		m.residencyAdmissionMu.Lock()
		targetFence.RLock()
		m.mu.RLock()
		currentTarget, currentFound := m.targets[target.ID]
		currentGeneration := m.targetGenerations[target.ID]
		factsOK := currentFound && currentGeneration == targetGeneration && targetIdentityMatches(target, currentTarget)
		blockedReason = m.runtimeProfileTargetBlockerLocked(currentTarget)
		m.mu.RUnlock()
		if blockedReason != "" {
			targetFence.RUnlock()
			m.residencyAdmissionMu.Unlock()
			return nil, false, "runtime profile observation is unavailable; operator reconciliation is required", nil
		}
		if !factsOK {
			targetFence.RUnlock()
			m.residencyAdmissionMu.Unlock()
			return nil, false, "target facts changed before placement", nil
		}
		m.placementMu.Lock()
		if m.targetActive[target.ID] >= slots {
			m.placementMu.Unlock()
			targetFence.RUnlock()
			m.residencyAdmissionMu.Unlock()
			return nil, false, "all execution slots are busy", nil
		}
		if requirements.Model != "" && target.AcceleratorID != "" && !target.Cloud {
			activeAccelerators := make(map[string]struct{})
			for _, active := range m.activePlacements {
				if active.model == requirements.Model && active.acceleratorID != "" {
					activeAccelerators[active.acceleratorID] = struct{}{}
				}
			}
			if _, alreadyUsed := activeAccelerators[target.AcceleratorID]; !alreadyUsed && len(activeAccelerators) >= modelLimit {
				m.placementMu.Unlock()
				targetFence.RUnlock()
				m.residencyAdmissionMu.Unlock()
				return nil, false, fmt.Sprintf("model accelerator limit %d reached", modelLimit), nil
			}
		}
		if lease := m.targetLeases[target.ID]; lease != nil {
			m.targetActive[target.ID]++
			m.activePlacements[workloadID] = placement
			m.placementMu.Unlock()
			targetFence.RUnlock()
			m.residencyAdmissionMu.Unlock()
			return &targetReservation{targetID: target.ID, workloadID: workloadID, targetGeneration: targetGeneration, lease: lease}, true, "", nil
		}
		var sharedLease *domain.AcceleratorLease
		for _, lease := range m.targetLeases {
			if lease.AcceleratorID == leaseID {
				sharedLease = lease
				break
			}
		}
		if sharedLease != nil {
			predictedVRAM, reserve, capacity, slowdown, exploration, allowed, reason := m.canCoScheduleLocked(placement)
			if !allowed {
				m.placementMu.Unlock()
				targetFence.RUnlock()
				m.residencyAdmissionMu.Unlock()
				return nil, false, reason, nil
			}
			m.targetActive[target.ID]++
			m.targetLeases[target.ID] = sharedLease
			for id, active := range m.activePlacements {
				if active.acceleratorID == placement.acceleratorID {
					active.sharedObserved = true
					m.activePlacements[id] = active
				}
			}
			placement.sharedObserved = true
			m.activePlacements[workloadID] = placement
			profileKey, classes, runtimeVersions := m.sharingProfileKeyLocked(placement)
			exactProfileKey := m.sharingExactProfileKeyLocked(placement, profileKey)
			m.placementMu.Unlock()
			targetFence.RUnlock()
			m.residencyAdmissionMu.Unlock()
			return &targetReservation{targetID: target.ID, workloadID: workloadID, targetGeneration: targetGeneration, lease: sharedLease, shared: true, predictedVRAMMB: predictedVRAM, reserveVRAMMB: reserve, capacityVRAMMB: capacity, maxSlowdown: slowdown, exploration: exploration, profileKey: profileKey, exactProfileKey: exactProfileKey, workloadClasses: classes, runtimeVersion: runtimeVersions}, true, "", nil
		}
		m.placementMu.Unlock()
		targetFence.RUnlock()
		m.residencyAdmissionMu.Unlock()

		// Durable lease acquisition is the only slow part of this phase and runs
		// with every manager/placement lock released.
		lease, acquired, err := m.store.AcquireAcceleratorLease(ctx, leaseID, workloadID, m.leaseTTL)
		if err != nil {
			return nil, false, "", err
		}
		if !acquired {
			return nil, false, "accelerator is reserved by " + lease.WorkloadID, nil
		}

		// Recheck after the store round trip. A concurrent admission may have
		// filled the slot or installed a shared lease while this call waited;
		// independently, a target refresh may have changed the route facts. Do
		// not publish any in-memory reservation until both fences agree.
		// Final target-fact validation and placement publication are one short
		// fenced phase. Refresh/policy/capacity mutations use the same order,
		// so no target can change between this snapshot and the commit.
		m.residencyAdmissionMu.Lock()
		targetFence.Lock()
		m.mu.RLock()
		currentTarget, currentFound = m.targets[target.ID]
		currentGeneration = m.targetGenerations[target.ID]
		identityOK := currentFound && currentGeneration == targetGeneration && targetIdentityMatches(target, currentTarget)
		blockedReason = m.runtimeProfileTargetBlockerLocked(currentTarget)
		m.mu.RUnlock()
		if blockedReason != "" {
			targetFence.Unlock()
			m.residencyAdmissionMu.Unlock()
			if rollbackErr := m.rollbackAcceleratorLease(context.Background(), lease, workloadID); rollbackErr != nil {
				return nil, false, "runtime profile observation became unavailable during accelerator lease acquisition", rollbackErr
			}
			return nil, false, "runtime profile observation is unavailable; operator reconciliation is required", nil
		}
		if !identityOK {
			targetFence.Unlock()
			m.residencyAdmissionMu.Unlock()
			if rollbackErr := m.rollbackAcceleratorLease(context.Background(), lease, workloadID); rollbackErr != nil {
				return nil, false, "target facts changed during accelerator lease acquisition", rollbackErr
			}
			return nil, false, "target facts changed during accelerator lease acquisition", nil
		}
		m.placementMu.Lock()
		if m.targetActive[target.ID] >= slots || m.targetLeases[target.ID] != nil {
			m.placementMu.Unlock()
			targetFence.Unlock()
			m.residencyAdmissionMu.Unlock()
			if rollbackErr := m.rollbackAcceleratorLease(context.Background(), lease, workloadID); rollbackErr != nil {
				return nil, false, "accelerator lease publication requires reconciliation", rollbackErr
			}
			continue
		}
		m.targetActive[target.ID] = 1
		m.targetLeases[target.ID] = lease
		m.activePlacements[workloadID] = placement
		m.placementMu.Unlock()
		targetFence.Unlock()
		m.residencyAdmissionMu.Unlock()
		return &targetReservation{targetID: target.ID, workloadID: workloadID, targetGeneration: targetGeneration, lease: lease}, true, "", nil
	}
}

func (m *Manager) canCoScheduleLocked(newcomer activePlacement) (predictedVRAMMB, reserveVRAMMB, capacityVRAMMB int64, maxSlowdown float64, exploration, allowed bool, reason string) {
	if !newcomer.sharingEnabled || newcomer.safetyCritical || newcomer.disruption != domain.DisruptionSlowdown {
		return 0, 0, 0, 0, false, false, "accelerator is busy and newcomer policy does not allow sharing"
	}
	capacityVRAMMB = newcomer.capacityVRAMMB
	reserveVRAMMB = newcomer.reserveVRAMMB
	predictedVRAMMB = newcomer.vramMB
	maxSlowdown = newcomer.maxSlowdown
	profileKnown := newcomer.predictedSlowdown > 0
	if newcomer.vramMB <= 0 || capacityVRAMMB <= 0 {
		return 0, 0, 0, 0, false, false, "sharing requires measured standalone VRAM envelopes"
	}
	if newcomer.predictedSlowdown > maxSlowdown {
		return predictedVRAMMB, reserveVRAMMB, capacityVRAMMB, maxSlowdown, false, false, "predicted newcomer slowdown exceeds policy"
	}
	for _, victim := range m.activePlacements {
		if victim.acceleratorID != newcomer.acceleratorID {
			continue
		}
		if !victim.sharingEnabled || victim.safetyCritical || victim.disruption != domain.DisruptionSlowdown || victim.vramMB <= 0 {
			return 0, 0, 0, 0, false, false, "active victim disruption policy forbids sharing"
		}
		predictedVRAMMB += victim.vramMB
		if victim.capacityVRAMMB > 0 && (capacityVRAMMB == 0 || victim.capacityVRAMMB < capacityVRAMMB) {
			capacityVRAMMB = victim.capacityVRAMMB
		}
		if victim.reserveVRAMMB > reserveVRAMMB {
			reserveVRAMMB = victim.reserveVRAMMB
		}
		if victim.maxSlowdown > 0 && victim.maxSlowdown < maxSlowdown {
			maxSlowdown = victim.maxSlowdown
		}
		profileKnown = profileKnown && victim.predictedSlowdown > 0
		if victim.predictedSlowdown > maxSlowdown {
			return predictedVRAMMB, reserveVRAMMB, capacityVRAMMB, maxSlowdown, false, false, "predicted victim slowdown exceeds policy"
		}
	}
	if reserveVRAMMB <= 0 {
		reserveVRAMMB = 512
	}
	if predictedVRAMMB+reserveVRAMMB > capacityVRAMMB {
		return predictedVRAMMB, reserveVRAMMB, capacityVRAMMB, maxSlowdown, false, false, "conservative p95 VRAM composition exceeds reserve"
	}
	profileKey, _, _ := m.sharingProfileKeyLocked(newcomer)
	exactProfileKey := m.sharingExactProfileKeyLocked(newcomer, profileKey)
	m.learningMu.RLock()
	learned := m.interferenceProfiles[exactProfileKey]
	if learned == nil || learned.Confidence < .5 {
		learned = m.interferenceProfiles[profileKey]
	}
	m.learningMu.RUnlock()
	if learned != nil && learned.Confidence >= .5 {
		profileKnown = true
		if learned.P95VRAMMB+reserveVRAMMB > capacityVRAMMB {
			return learned.P95VRAMMB, reserveVRAMMB, capacityVRAMMB, maxSlowdown, false, false, "learned p95 VRAM profile exceeds reserve"
		}
		if learned.PredictedSlowdown > maxSlowdown {
			return predictedVRAMMB, reserveVRAMMB, capacityVRAMMB, maxSlowdown, false, false, "learned slowdown profile exceeds policy"
		}
	}
	if !profileKnown {
		exploration = newcomer.guardedExploration && predictedVRAMMB+2*reserveVRAMMB <= capacityVRAMMB
		if !exploration {
			return predictedVRAMMB, reserveVRAMMB, capacityVRAMMB, maxSlowdown, false, false, "sharing combination lacks a measured interference profile"
		}
	}
	return predictedVRAMMB, reserveVRAMMB, capacityVRAMMB, maxSlowdown, exploration, true, ""
}

func (m *Manager) sharingProfileKeyLocked(newcomer activePlacement) (string, []string, string) {
	classes := []string{newcomer.workloadClass}
	versions := []string{newcomer.runtimeVersion}
	for _, victim := range m.activePlacements {
		if victim.acceleratorID == newcomer.acceleratorID {
			classes = append(classes, victim.workloadClass)
			versions = append(versions, victim.runtimeVersion)
		}
	}
	sort.Strings(classes)
	sort.Strings(versions)
	versions = compactStrings(versions)
	runtimeVersions := strings.Join(versions, "+")
	return newcomer.acceleratorID + "|" + runtimeVersions + "|" + strings.Join(classes, "+"), classes, runtimeVersions
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func targetWorkloadClass(target Target) string {
	if target.WorkloadClass != "" {
		return target.WorkloadClass
	}
	return target.Adapter
}

func standaloneProfileKey(target Target) string {
	acceleratorID := target.AcceleratorID
	if acceleratorID == "" {
		acceleratorID = "virtual/" + target.ID
	}
	return acceleratorID + "|" + target.CapabilityVersion + "|" + targetWorkloadClass(target)
}

func standaloneRequestProfileKey(target Target, request domain.WorkloadRequest) string {
	return standaloneProfileKey(target) + "|fp:" + workloadProfileFingerprint(target, request)
}

func workloadProfileFingerprint(target Target, request domain.WorkloadRequest) string {
	var envelope struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(request.Payload, &envelope)
	material, _ := json.Marshal(struct {
		RuntimeVersion   string
		ModelFingerprint string
		WorkloadType     string
		Model            string
		Bounds           domain.WorkloadBounds
	}{target.CapabilityVersion, target.ModelFingerprint, request.WorkloadType, envelope.Model, request.Bounds})
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:12])
}

func (m *Manager) sharingExactProfileKeyLocked(newcomer activePlacement, classKey string) string {
	fingerprints := []string{newcomer.fingerprint}
	for _, victim := range m.activePlacements {
		if victim.acceleratorID == newcomer.acceleratorID {
			fingerprints = append(fingerprints, victim.fingerprint)
		}
	}
	sort.Strings(fingerprints)
	return classKey + "|fp:" + strings.Join(fingerprints, "+")
}

// restoreCheckpointVictim is the compensation boundary for a durable CAS
// race after physical checkpointing. The node released the old fencing token;
// compensation therefore obtains a fresh manager lease before invoking the
// signed restore/reload/resume path. A failure is returned to the transition
// caller so the urgent request remains fenced instead of claiming capacity
// that may still contain an unresolved victim.
func (m *Manager) restoreCheckpointVictim(ctx context.Context, victim *domain.Workload, target Target, adapter Adapter, checkpoint string, oldLease *domain.AcceleratorLease, transitionID string) (*domain.ExecutionHandle, *domain.AcceleratorLease, error) {
	if victim == nil || victim.Plan == nil || checkpoint == "" || oldLease == nil {
		return nil, nil, fmt.Errorf("checkpoint compensation identity is incomplete")
	}
	aware, ok := adapter.(LeaseAwareCheckpointAdapter)
	if !ok {
		return nil, nil, fmt.Errorf("checkpoint adapter cannot restore a leased victim")
	}
	compCtx := context.WithoutCancel(ctx)
	// Establish the durable custody row before releasing the old fence or
	// sending a physical restore. This closes the crash seam in which a node
	// accepts a fresh generation before the controller has any restart-visible
	// identity for it. Existing callers that already persisted the intent are
	// idempotent here; direct compensation callers now get the same protection.
	intent, intentErr := m.persistCheckpointRecoveryIntent(compCtx, victim, target, checkpoint, transitionID, oldLease)
	if intentErr != nil {
		return nil, nil, fmt.Errorf("checkpoint compensation could not establish cleanup custody: %w", intentErr)
	}
	// CheckpointWithLease normally releases the original manager lease after
	// the physical snapshot is committed.  Compensation must therefore accept
	// an already-absent exact lease, while still fencing any live owner that
	// appeared under the same accelerator before reacquisition.
	if err := m.store.ReleaseAcceleratorLease(compCtx, oldLease.AcceleratorID, oldLease.WorkloadID, oldLease.FencingToken); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, fmt.Errorf("checkpoint compensation could not release stale lease: %w", err)
	}
	if current, getErr := m.store.GetAcceleratorLease(compCtx, oldLease.AcceleratorID); getErr == nil && current != nil {
		if current.WorkloadID != oldLease.WorkloadID || current.FencingToken != oldLease.FencingToken {
			return nil, nil, fmt.Errorf("checkpoint compensation found a different live accelerator owner")
		}
	} else if getErr != nil && !errors.Is(getErr, store.ErrNotFound) {
		return nil, nil, fmt.Errorf("checkpoint compensation could not verify stale lease: %w", getErr)
	}
	recoveryLeaser, recoveryLeaseOK := m.store.(store.CheckpointRecoveryLeaseStore)
	if !recoveryLeaseOK {
		return nil, nil, fmt.Errorf("checkpoint compensation recovery lease store is unavailable")
	}
	cleanupOperationID := firstNonEmpty(intent.CleanupOperationID, transitionID+":compensate")
	lease, acquired, err := recoveryLeaser.AcquireAcceleratorLeaseForCheckpointRecovery(compCtx, oldLease.AcceleratorID, oldLease.WorkloadID, cleanupOperationID, m.leaseTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("checkpoint compensation reacquire failed: %w", err)
	}
	if !acquired || lease == nil || lease.FencingToken <= oldLease.FencingToken {
		return nil, nil, fmt.Errorf("checkpoint compensation did not obtain a fresh fencing token")
	}
	if _, armErr := m.recordCheckpointCleanupState(compCtx, intent.ID, "pending", nil, target, lease, "", "checkpoint compensation restore cleanup pending"); armErr != nil {
		// No physical restore has started yet.  Release this unused fresh lease
		// immediately; if the release itself is ambiguous, persist the generic
		// durable lease-cleanup intent so admission remains fenced for retry.
		if releaseErr := m.store.ReleaseAcceleratorLease(compCtx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken); releaseErr != nil && !errors.Is(releaseErr, store.ErrNotFound) {
			_ = m.recordLeaseCleanupIntent(context.WithoutCancel(compCtx), lease, lease.WorkloadID, releaseErr, 1)
			return nil, lease, fmt.Errorf("checkpoint compensation could not arm fresh cleanup custody: %w; unused lease release remains pending: %v", armErr, releaseErr)
		}
		if _, stopErr := m.recordCheckpointCleanupState(compCtx, intent.ID, "stopped", nil, target, lease, "", "checkpoint compensation cleanup journal failed before physical restore"); stopErr == nil {
			_, _ = m.recordCheckpointCleanupState(compCtx, intent.ID, "confirmed", nil, target, lease, "", "checkpoint compensation cleanup journal failed before physical restore")
		} else {
			m.log.Warn("checkpoint compensation unused-lease cleanup marker remains pending", "operation_id", intent.ID, "error", stopErr)
		}
		return nil, nil, fmt.Errorf("checkpoint compensation could not arm fresh cleanup custody: %w", armErr)
	}
	command := CheckpointCommand{ID: transitionID + ":compensate", IdempotencyKey: transitionID + ":compensate", OwnerID: victim.Request.OwnerID, WorkloadID: victim.Request.ID, WorkloadRevision: victim.Revision, Generation: m.targetGeneration(target.ID), RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: victim.Plan.ModelFingerprint, ProfileFingerprint: victim.Plan.ProfileDigest, ContextLimit: victim.Plan.TargetContextLimit, Fence: uint64(lease.FencingToken), SnapshotName: checkpoint, CompensationOf: transitionID + ":checkpoint"}
	if command.ContextLimit <= 0 {
		command.ContextLimit = target.ContextLimit
	}
	resumeLease := SlotLease{TargetID: target.ID, NodeID: target.NodeID, AcceleratorID: oldLease.AcceleratorID, SlotID: -1, OwnerID: victim.Request.OwnerID, WorkloadID: victim.Request.ID, Generation: command.Generation, Fence: command.Fence, RuntimeIdentity: command.RuntimeIdentity, ModelFingerprint: command.ModelFingerprint, ProfileFingerprint: command.ProfileFingerprint, ContextLimit: command.ContextLimit}
	handle, err := aware.ResumeWithLease(compCtx, victim.Request, victim.Plan, checkpoint, target, resumeLease, command)
	if err != nil || handle == nil {
		if err == nil {
			err = fmt.Errorf("checkpoint compensation returned no resumed handle")
		}
		// ResumeWithLease owns the freshly acquired fence once it has crossed
		// into the node. Never release that fence until a bounded cancel has
		// confirmed that the fresh backend generation stopped.
		// If the physical compensation crossed its node boundary but the
		// response was lost, cleanup must address the node's :compensate row.
		// The outer-CAS intent intentionally has slot -1 and is never a cancel
		// target.
		cleanupErr := m.cleanupFreshCheckpointRestore(ctx, adapter, target, handle, lease, cleanupOperationID)
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
		return nil, nil, fmt.Errorf("checkpoint compensation restore/resume failed: %w", err)
	}
	// The physical restore has crossed the fresh-fence boundary. Persist the
	// exact handle and fence before the caller attempts the outer workload CAS;
	// a controller crash in that seam must never leave recovery guessing from
	// the stale pre-checkpoint execution embedded in the workload row.
	if recordErr := m.recordCheckpointRecoveryRestored(compCtx, transitionID, handle, lease); recordErr != nil {
		// The pending custody row and exact fresh lease remain authoritative. Do
		// not cancel/release here merely because the handle journal update lost a
		// race: restart recovery can synthesize the signed binding and retry the
		// stop without launching a duplicate restore.
		return handle, lease, fmt.Errorf("checkpoint compensation fresh handle intent could not be persisted: %w", recordErr)
	}
	m.placementMu.Lock()
	for targetID, existing := range m.targetLeases {
		if existing != nil && existing.AcceleratorID == lease.AcceleratorID && existing.WorkloadID == oldLease.WorkloadID {
			m.targetLeases[targetID] = lease
		}
	}
	m.placementMu.Unlock()
	return handle, lease, nil
}

// recordCheckpointRecoveryRestored durably records the post-restore handle
// before any projection CAS.  It is intentionally idempotent and only updates
// mutable recovery fields; the original operation fence/revision remain the
// immutable identity of the outer-CAS intent.
func (m *Manager) recordCheckpointRecoveryRestored(ctx context.Context, transitionID string, handle *domain.ExecutionHandle, lease *domain.AcceleratorLease) error {
	if transitionID == "" || handle == nil || strings.TrimSpace(handle.ExternalID) == "" || lease == nil || lease.FencingToken <= 0 {
		return fmt.Errorf("checkpoint restored intent identity is incomplete")
	}
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return fmt.Errorf("checkpoint recovery intent store is unavailable")
	}
	intentID := transitionID + ":outer-recovery"
	op, err := operations.GetLLMCheckpointOperation(ctx, intentID)
	if errors.Is(err, store.ErrNotFound) {
		// A physical restore without its outer-CAS intent is not recoverable
		// after a controller crash.  Fail closed while the fresh handle is
		// still in the caller's custody so restoreCheckpointVictim cancels it
		// and releases the exact fresh fence before returning.
		return fmt.Errorf("checkpoint recovery intent is missing")
	}
	if err != nil {
		return err
	}
	if op.RecoveryState == "adopted" || op.RecoveryState == "requeued" || op.RecoveryState == "terminalized" {
		return nil
	}
	if op.RecoveryState == "restored" {
		if op.RecoveryFence == uint64(lease.FencingToken) && op.RecoveryAcceleratorID == lease.AcceleratorID && checkpointRecoveryHandleMatches(op.RecoveryHandle, handle) && op.RecoveryWorkloadRevision == op.WorkloadRevision {
			// A retry after a controller crash must not replace an already
			// identified fresh handle with a second physical restore.  The
			// durable row is already sufficient for startup adoption/cancel.
			return nil
		}
		return fmt.Errorf("checkpoint recovery intent is already restored with a different identity")
	}
	if op.RecoveryState != "pending" {
		return fmt.Errorf("checkpoint recovery intent is not pending: %s", op.RecoveryState)
	}
	copyHandle := *handle
	copyHandle.Opaque = append([]byte(nil), handle.Opaque...)
	if handle.Performance != nil {
		performance := *handle.Performance
		copyHandle.Performance = &performance
	}
	op.RecoveryState = "restored"
	op.RecoveryHandle = &copyHandle
	op.RecoveryFence = uint64(lease.FencingToken)
	op.RecoveryAcceleratorID = lease.AcceleratorID
	op.CleanupState = "owned"
	op.CleanupHandle = cloneCheckpointHandle(handle)
	op.CleanupTargetID = op.TargetID
	op.CleanupNodeID = op.NodeID
	op.CleanupAcceleratorID = lease.AcceleratorID
	op.CleanupGeneration = op.Generation
	op.CleanupFence = uint64(lease.FencingToken)
	// The outer row is not the physical node operation.  Keep the durable
	// compensation identity established before restore; a returned handle may
	// legitimately omit opaque metadata (for example while the controller is
	// crossing the pre-handle crash seam).  Replacing it with the outer row id
	// would make a later native cancel fail operation authorization.
	op.CleanupOperationID = firstNonEmpty(op.CleanupOperationID, transitionID+":compensate", op.ID)
	if op.CleanupSlotID < 0 && op.SlotID >= 0 {
		op.CleanupSlotID = op.SlotID
	}
	if binding, bindingOK := checkpointHandleBinding(handle); bindingOK {
		if binding.OperationID != "" {
			op.CleanupOperationID = binding.OperationID
		}
		if binding.SlotID >= 0 {
			op.CleanupSlotID = binding.SlotID
		}
		if binding.Generation > 0 {
			op.CleanupGeneration = binding.Generation
		}
		if binding.Fence > 0 {
			op.CleanupFence = binding.Fence
		}
		op.CleanupConversationID = binding.ConversationID
		op.CleanupContinuationConversationID = binding.ContinuationConversationID
	}
	// The outer workload CAS has not happened yet, so the fresh handle is
	// still authorized against the original projection revision.  Persist that
	// association explicitly; adoption later advances RecoveryWorkloadRevision
	// to the CAS result, while restart cleanup can prove which revision the
	// restored generation was intended to replace.
	op.RecoveryWorkloadRevision = op.WorkloadRevision
	updated, err := operations.UpdateLLMCheckpointOperation(ctx, op, op.Revision)
	if err != nil {
		return err
	}
	if updated == nil || updated.RecoveryState != "restored" || updated.RecoveryFence != uint64(lease.FencingToken) || updated.RecoveryAcceleratorID != lease.AcceleratorID || updated.RecoveryWorkloadRevision != op.WorkloadRevision || !checkpointRecoveryHandleMatches(updated.RecoveryHandle, handle) {
		return fmt.Errorf("checkpoint restored intent was not durably identified")
	}
	return nil
}

// clearCheckpointCompensationLease removes only the exact fenced lease that a
// failed compensation attempt acquired. It deliberately leaves a newer lease
// or an unrelated workload untouched.
func (m *Manager) clearCheckpointCompensationLease(lease *domain.AcceleratorLease, workloadID, targetID string) {
	if lease == nil {
		return
	}
	m.placementMu.Lock()
	for id, existing := range m.targetLeases {
		if existing != nil && existing.AcceleratorID == lease.AcceleratorID && existing.WorkloadID == workloadID && existing.FencingToken == lease.FencingToken {
			delete(m.targetLeases, id)
		}
	}
	if targetID != "" {
		if active := m.targetActive[targetID]; active <= 1 {
			delete(m.targetActive, targetID)
		} else {
			m.targetActive[targetID] = active - 1
		}
	}
	m.placementMu.Unlock()
}

// cleanupFreshCheckpointRestore is the only compensation path allowed to
// discard a fresh restore fence.  A non-nil adapter error (including
// ErrUnsupported) means the backend stop is unconfirmed, so the exact lease
// and in-memory placement remain authoritative for a retry.  Once stop is
// confirmed, releaseAcceleratorLease may still fail; rollbackAcceleratorLease
// records the exact fenced release for durable retry and leaves placement
// fenced until that retry confirms absence.
func (m *Manager) cleanupFreshCheckpointRestore(ctx context.Context, adapter Adapter, target Target, handle *domain.ExecutionHandle, lease *domain.AcceleratorLease, operationID string) error {
	cleanupCtx, cancel := leaseCleanupContext(ctx)
	defer cancel()
	if operationID == "" {
		operationID = checkpointOperationIDFromHandle(handle)
	}
	var cleanupOp *store.LLMCheckpointOperation
	if operationID != "" {
		if operations, ok := m.store.(store.LLMCheckpointOperationStore); ok {
			if op, getErr := operations.GetLLMCheckpointOperation(cleanupCtx, operationID); getErr == nil {
				cleanupOp = op
			} else if !errors.Is(getErr, store.ErrNotFound) {
				return getErr
			}
		}
	}
	if handle == nil && cleanupOp != nil && cleanupOp.CleanupOperationID == operationID && cleanupOp.CleanupSlotID >= 0 && cleanupOp.CleanupGeneration > 0 && cleanupOp.CleanupFence > 0 && cleanupOp.CleanupConversationID != "" {
		// A response can be lost after the node created the physical
		// compensation operation. Reconstruct only from that exact row; the
		// outer recovery row has slot -1 and cannot authorize cancellation.
		handle = cleanupJournalHandle(cleanupOp)
	}
	if handle == nil {
		cleanupErr := fmt.Errorf("fresh checkpoint restore returned no physical compensation handle; backend stop is unconfirmed")
		if markErr := m.markCheckpointRecoveryIntentFailed(cleanupCtx, operationID, cleanupErr); markErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record failed checkpoint cleanup: %w", markErr))
		}
		return cleanupErr
	}
	if cleanupOp == nil || cleanupOp.CleanupState != "stopped" {
		if adapter == nil {
			cleanupErr := fmt.Errorf("fresh checkpoint restore cleanup adapter is unavailable")
			if markErr := m.markCheckpointRecoveryIntentFailed(cleanupCtx, operationID, cleanupErr); markErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record failed checkpoint cleanup: %w", markErr))
			}
			return cleanupErr
		}
		if err := adapter.Cancel(cleanupCtx, handle, target); err != nil {
			cleanupErr := fmt.Errorf("cancel fresh checkpoint restore (stop unconfirmed): %w", err)
			if markErr := m.markCheckpointRecoveryIntentFailed(cleanupCtx, operationID, cleanupErr); markErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record failed checkpoint cleanup: %w", markErr))
			}
			return cleanupErr
		}
	}
	if lease == nil {
		return nil
	}
	if cleanupOp != nil && cleanupOp.CleanupState != "confirmed" {
		// Confirmed physical cancellation is a durable stop boundary.  Persist it
		// before attempting the lease release so a crash/retry cannot confuse an
		// ambiguous release with an unconfirmed backend.
		if _, markErr := m.recordCheckpointCleanupState(cleanupCtx, operationID, "stopped", handle, target, lease, cleanupOp.CleanupTerminalDisposition, cleanupOp.CleanupMessage); markErr != nil {
			return markErr
		}
	}
	if err := m.rollbackAcceleratorLease(cleanupCtx, lease, lease.WorkloadID); err != nil {
		cleanupErr := fmt.Errorf("release fresh checkpoint restore fence after confirmed stop: %w", err)
		if cleanupOp != nil && cleanupOp.CleanupState == "stopped" {
			// Stop is already durable; retain that state and retry only the
			// exact-fence release.  Marking the outer recovery failed here would
			// cause a restart to issue a duplicate physical cancel.
			if _, markErr := m.recordCheckpointCleanupState(cleanupCtx, operationID, "stopped", handle, target, lease, cleanupOp.CleanupTerminalDisposition, "lease release pending after confirmed stop: "+err.Error()); markErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record stopped checkpoint cleanup: %w", markErr))
			}
		} else if markErr := m.markCheckpointRecoveryIntentFailed(cleanupCtx, operationID, cleanupErr); markErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record failed checkpoint lease cleanup: %w", markErr))
		}
		return cleanupErr
	}
	if cleanupOp != nil {
		if _, markErr := m.recordCheckpointCleanupState(cleanupCtx, operationID, "confirmed", handle, target, lease, cleanupOp.CleanupTerminalDisposition, cleanupOp.CleanupMessage); markErr != nil {
			return markErr
		}
	}
	// The exact store lease is now absent. Only at this point is it safe to
	// clear the corresponding in-memory fence/placement.
	m.clearCheckpointCompensationLease(lease, lease.WorkloadID, target.ID)
	return nil
}

func (m *Manager) checkpointCleanupOperationForHandle(ctx context.Context, workloadID, targetID string, handle *domain.ExecutionHandle, lease *domain.AcceleratorLease) string {
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok || handle == nil {
		return ""
	}
	rows, err := operations.ListLLMCheckpointOperations(ctx, "")
	if err != nil {
		return ""
	}
	for _, row := range rows {
		if row == nil || row.ID == "" || row.WorkloadID != workloadID || row.TargetID != targetID {
			continue
		}
		if lease != nil && (firstNonEmpty(row.CleanupAcceleratorID, row.AcceleratorID) != lease.AcceleratorID || (row.CleanupFence != 0 && row.CleanupFence != uint64(lease.FencingToken))) {
			continue
		}
		if checkpointRecoveryHandleMatches(row.RecoveryHandle, handle) || checkpointRecoveryHandleMatches(row.CleanupHandle, handle) {
			return row.ID
		}
	}
	return ""
}

// abandonRestoredCheckpointVictim is used after a physical restore succeeded
// but the durable CAS that should adopt it failed. The restored backend must
// be fenced by a signed cancel and its exact fresh lease must be released; a
// caller must never simply drop either handle or lease. A victim CAS conflict
// keeps the in-memory placement fence until recovery can reconcile the still
// running durable workload; a newcomer CAS conflict can remove that placement
// after the victim row has already been durably queued.
func (m *Manager) abandonRestoredCheckpointVictim(ctx context.Context, victim *domain.Workload, target Target, adapter Adapter, handle *domain.ExecutionHandle, lease *domain.AcceleratorLease, keepFence bool) error {
	operationID := checkpointOperationIDFromHandle(handle)
	if victim != nil {
		if durableID := m.checkpointCleanupOperationForHandle(context.WithoutCancel(ctx), victim.Request.ID, target.ID, handle, lease); durableID != "" {
			operationID = durableID
		}
	}
	cleanupErr := m.cleanupFreshCheckpointRestore(ctx, adapter, target, handle, lease, operationID)
	if cleanupErr != nil {
		// Keep the fresh fence and placement authoritative. Callers that own a
		// durable recovery operation mark it failed for restart retry.
		return cleanupErr
	}
	if victim != nil && !keepFence {
		m.placementMu.Lock()
		if active, ok := m.activePlacements[victim.Request.ID]; ok && active.targetID == target.ID {
			delete(m.activePlacements, victim.Request.ID)
			if count := m.targetActive[target.ID]; count <= 1 {
				delete(m.targetActive, target.ID)
			} else {
				m.targetActive[target.ID] = count - 1
			}
		}
		m.placementMu.Unlock()
	}
	return cleanupErr
}

// persistCheckpointRecoveryIntent records the outer workload CAS boundary in
// the same durable operation journal as the physical restore. The intent is
// separate from the node compensation row so its original workload revision
// and stale-fence identity cannot be rewritten by a later restore lease.
func (m *Manager) persistCheckpointRecoveryIntent(ctx context.Context, victim *domain.Workload, target Target, checkpoint, transitionID string, oldLease *domain.AcceleratorLease) (*store.LLMCheckpointOperation, error) {
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return nil, fmt.Errorf("checkpoint recovery intent store is unavailable")
	}
	if victim == nil || victim.Plan == nil || target.NodeID == "" || oldLease == nil || oldLease.FencingToken <= 0 || victim.Revision == 0 {
		return nil, fmt.Errorf("checkpoint recovery intent identity is incomplete")
	}
	model := victim.Plan.ModelFingerprint
	profile := victim.Plan.ProfileDigest
	contextLimit := victim.Plan.TargetContextLimit
	if contextLimit <= 0 {
		contextLimit = target.ContextLimit
	}
	command := withCheckpointConversation(CheckpointCommand{ID: transitionID + ":outer-recovery", IdempotencyKey: transitionID + ":outer-recovery", OwnerID: victim.Request.OwnerID, WorkloadID: victim.Request.ID, WorkloadRevision: victim.Revision, Generation: m.targetGeneration(target.ID), RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: model, ProfileFingerprint: profile, ContextLimit: contextLimit, Fence: uint64(oldLease.FencingToken), SnapshotName: checkpoint, CompensationOf: transitionID + ":checkpoint"})
	if err := command.valid(); err != nil {
		return nil, err
	}
	nodeID := firstNonEmpty(target.NodeID, target.ID)
	op := &store.LLMCheckpointOperation{ID: command.ID, IdempotencyKey: command.IdempotencyKey, OwnerID: command.OwnerID, WorkloadID: command.WorkloadID, NodeID: nodeID, AcceleratorID: oldLease.AcceleratorID, TargetID: target.ID, SlotID: -1, Generation: command.Generation, Fence: command.Fence, RuntimeIdentity: command.RuntimeIdentity, Model: model, ModelFingerprint: model, ProfileFingerprint: profile, ContextFingerprint: fmt.Sprintf("ctx:%d", contextLimit), ConversationID: command.ConversationID, ContinuationConversationID: command.ContinuationConversationID, CompensationOf: command.CompensationOf, WorkloadRevision: victim.Revision, SnapshotName: checkpoint, Phase: "restore_planned", PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), RecoveryState: "pending", CleanupOperationID: transitionID + ":compensate", CleanupSlotID: -1, CleanupConversationID: command.ConversationID, CleanupContinuationConversationID: "continuation-" + transitionID + ":compensate", CleanupState: "armed", CleanupTargetID: target.ID, CleanupNodeID: nodeID, CleanupAcceleratorID: oldLease.AcceleratorID, CleanupGeneration: command.Generation, CleanupFence: command.Fence}
	created, _, err := operations.CreateLLMCheckpointOperation(ctx, op)
	if err != nil {
		if existing, getErr := operations.GetLLMCheckpointOperation(ctx, op.ID); getErr == nil {
			if existing.WorkloadID != op.WorkloadID || existing.WorkloadRevision != op.WorkloadRevision || existing.NodeID != op.NodeID || existing.AcceleratorID != op.AcceleratorID || existing.TargetID != op.TargetID || existing.Fence != op.Fence || existing.SnapshotName != op.SnapshotName || existing.CompensationOf != op.CompensationOf {
				return nil, fmt.Errorf("checkpoint recovery intent identity conflicts with existing operation")
			}
			return existing, nil
		}
		return nil, err
	}
	if created == nil || created.ID == "" {
		return nil, fmt.Errorf("checkpoint recovery intent store returned no durable operation")
	}
	return created, nil
}

func (m *Manager) markCheckpointRecoveryIntent(ctx context.Context, operationID, state string, adoptedRevision uint64) error {
	if operationID == "" {
		return nil
	}
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return fmt.Errorf("checkpoint recovery intent store is unavailable")
	}
	op, err := operations.GetLLMCheckpointOperation(ctx, operationID)
	if err != nil {
		return err
	}
	if state == "adopted" && adoptedRevision == 0 {
		return fmt.Errorf("adopted checkpoint recovery intent requires workload revision")
	}
	if state != "pending" && state != "restored" && state != "failed" && state != "adopted" && state != "requeued" && state != "terminalized" {
		return fmt.Errorf("invalid checkpoint recovery state %q", state)
	}
	op.RecoveryState = state
	op.RecoveryWorkloadRevision = adoptedRevision
	_, err = operations.UpdateLLMCheckpointOperation(ctx, op, op.Revision)
	return err
}

// markCheckpointRecoveryIntentFailed preserves the exact fresh restore
// identity when physical cleanup cannot yet be confirmed.  A failed intent is
// deliberately retryable by startup recovery; it must never be rewritten to
// requeued while the fresh backend generation or fence may still be live.
func (m *Manager) markCheckpointRecoveryIntentFailed(ctx context.Context, operationID string, cause error) error {
	if operationID == "" {
		return nil
	}
	operations, ok := m.store.(store.LLMCheckpointOperationStore)
	if !ok {
		return fmt.Errorf("checkpoint recovery intent store is unavailable")
	}
	cleanupCtx, cancel := leaseCleanupContext(ctx)
	defer cancel()
	op, err := operations.GetLLMCheckpointOperation(cleanupCtx, operationID)
	if err != nil {
		return err
	}
	if op.RecoveryState == "adopted" || op.RecoveryState == "requeued" || op.RecoveryState == "terminalized" {
		return nil
	}
	op.RecoveryState = "failed"
	if cause != nil {
		op.Error = cause.Error()
		if len(op.Error) > 512 {
			op.Error = op.Error[:512]
		}
	}
	_, err = operations.UpdateLLMCheckpointOperation(cleanupCtx, op, op.Revision)
	return err
}

// adoptRestoredCheckpointVictim closes an outer-CAS race by publishing the
// freshly resumed handle against the latest workload revision. It is the
// only successful path after a victim CAS conflict; callers must cancel the
// restored generation if this atomic adoption fails.
func (m *Manager) adoptRestoredCheckpointVictim(ctx context.Context, victim *domain.Workload, target Target, handle *domain.ExecutionHandle, intentID string) (*domain.Workload, error) {
	if victim == nil || handle == nil {
		return nil, fmt.Errorf("restored victim adoption identity is incomplete")
	}
	updated, err := m.mutateWorkloadCAS(ctx, victim.Request.ID, workloadStatuses(domain.WorkloadRunning), "", func(current *domain.Workload) error {
		if current.Plan == nil || current.Plan.TargetID != target.ID {
			return fmt.Errorf("restored victim target changed")
		}
		current.Status = domain.WorkloadRunning
		current.Execution = handle
		current.CheckpointRef = ""
		current.Error = ""
		current.Decision = domain.AdmissionDecision{Admitted: true, TargetID: target.ID, Confidence: .9}
		current.FinishedAt = nil
		current.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), intentID, "adopted", updated.Revision); err != nil {
		return nil, err
	}
	return updated, nil
}

func (m *Manager) requeueCheckpointVictimAfterCleanup(ctx context.Context, victimID, targetID, checkpoint string) error {
	if victimID == "" {
		return nil
	}
	_, err := m.mutateWorkloadCAS(ctx, victimID, workloadStatuses(domain.WorkloadRunning), "", func(current *domain.Workload) error {
		current.Status = domain.WorkloadQueued
		current.Execution = nil
		// Keep the durable snapshot reference available for the next clean
		// admission. A restored handle that cannot be adopted has been cancelled,
		// but discarding the only checkpoint would turn a safe recovery into data
		// loss and force the workload to replay from the stale pre-checkpoint
		// execution.
		current.CheckpointRef = checkpoint
		current.StartedAt = nil
		current.FinishedAt = nil
		current.Error = "checkpoint compensation requeued after workload CAS conflict"
		current.Decision = domain.AdmissionDecision{Admitted: false, TargetID: targetID, Blocker: "checkpoint compensation requeued after workload CAS conflict", Confidence: .8}
		current.UpdatedAt = time.Now().UTC()
		return nil
	})
	if errors.Is(err, store.ErrWorkloadConflict) || errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

func (m *Manager) tryPreempt(ctx context.Context, newcomer *domain.Workload, target Target) bool {
	if newcomer == nil || effectiveWorkloadPriority(newcomer) <= 0 || newcomer.Request.PreemptionBudget <= 0 || newcomer.PreemptionsInitiated >= newcomer.Request.PreemptionBudget {
		return false
	}
	acceleratorID := target.AcceleratorID
	if acceleratorID == "" {
		acceleratorID = "virtual/" + target.ID
	}
	m.placementMu.Lock()
	var victimIDs []string
	for _, placement := range m.activePlacements {
		if placement.acceleratorID == acceleratorID {
			victimIDs = append(victimIDs, placement.workloadID)
		}
	}
	m.placementMu.Unlock()
	var victim *domain.Workload
	for _, id := range victimIDs {
		candidate, err := m.store.GetWorkload(ctx, id)
		if err != nil || candidate.Status != domain.WorkloadRunning || candidate.Execution == nil || candidate.Plan == nil {
			continue
		}
		if candidate.Request.Disruption == domain.DisruptionLocked || candidate.Request.Disruption == domain.DisruptionSlowdown {
			continue
		}
		if candidate.Request.Disruption == domain.DisruptionCheckpointable && !candidate.Request.InterruptionConsent {
			continue
		}
		if candidate.Request.Disruption == domain.DisruptionCheckpointable && !candidate.Request.Recoverable {
			continue
		}
		if effectiveWorkloadPriority(candidate) >= effectiveWorkloadPriority(newcomer) {
			continue
		}
		if victim == nil || effectiveWorkloadPriority(candidate) < effectiveWorkloadPriority(victim) {
			victim = candidate
		}
	}
	if victim == nil {
		return false
	}
	m.mu.RLock()
	adapter := m.adapters[victim.Request.Adapter]
	victimTarget := m.targets[victim.Plan.TargetID]
	cancel := m.cancels[victim.Request.ID]
	m.mu.RUnlock()
	if adapter == nil {
		return false
	}
	// Priority never overrides operator protection or a revoked production
	// checkpoint proof. Keep the victim running and leave the urgent request
	// queued when the target is pinned/manual/off or the adapter cannot prove
	// this exact disruption path.
	if victimTarget.ResidencyPolicy == domain.ResidencyPinned || victimTarget.ResidencyPolicy == domain.ResidencyManual || victimTarget.ResidencyPolicy == domain.ResidencyOff {
		return false
	}
	if !targetSupportsDisruption(adapter, victimTarget, victim.Request.Disruption) {
		return false
	}
	action := ""
	toState := string(domain.WorkloadQueued)
	rollback := []domain.TransitionStep{{Action: "requeue", WorkloadID: victim.Request.ID, FromState: string(domain.WorkloadRunning), ToState: string(domain.WorkloadQueued)}}
	switch victim.Request.Disruption {
	case domain.DisruptionYieldable:
		action = "yield"
	case domain.DisruptionCheckpointable:
		action = "checkpoint"
		rollback = []domain.TransitionStep{{Action: "resume_checkpoint", WorkloadID: victim.Request.ID, FromState: string(domain.WorkloadQueued), ToState: string(domain.WorkloadRunning)}}
	case domain.DisruptionCancelable:
		action = "cancel"
		toState = string(domain.WorkloadCancelled)
		rollback = nil
	default:
		return false
	}
	now := time.Now().UTC()
	transition := &domain.TransitionPlan{
		ID: newID("transition-plan"), WorkloadID: newcomer.Request.ID, VictimWorkloadID: victim.Request.ID,
		TargetID: target.ID, AcceleratorID: acceleratorID, Reason: "higher-priority workload requires exclusive capacity",
		Steps:    []domain.TransitionStep{{Action: action, WorkloadID: victim.Request.ID, FromState: string(domain.WorkloadRunning), ToState: toState, Policy: string(victim.Request.Disruption)}},
		Rollback: rollback, Status: domain.TransitionPlanPlanned, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := m.store.CreateTransitionPlan(ctx, transition); err != nil {
		return false
	}
	transition.Status = domain.TransitionPlanExecuting
	transition.UpdatedAt = time.Now().UTC()
	if _, err := m.store.UpdateTransitionPlan(ctx, transition); err != nil {
		return false
	}
	failTransition := func(err error) bool {
		finished := time.Now().UTC()
		transition.Status = domain.TransitionPlanFailed
		transition.Error = err.Error()
		transition.UpdatedAt = finished
		transition.FinishedAt = &finished
		_, _ = m.store.UpdateTransitionPlan(context.Background(), transition)
		return false
	}
	resultAction := ""
	var checkpointLease *domain.AcceleratorLease
	switch victim.Request.Disruption {
	case domain.DisruptionYieldable:
		if !victim.Request.Recoverable {
			return failTransition(fmt.Errorf("yieldable victim is not recoverable"))
		}
		if err := adapter.Yield(ctx, victim.Execution, victimTarget); err != nil {
			return failTransition(err)
		}
		resultAction = "yielded"
	case domain.DisruptionCheckpointable:
		lease, leaseErr := m.store.GetAcceleratorLease(ctx, acceleratorID)
		if leaseErr != nil || lease == nil || lease.WorkloadID != victim.Request.ID || lease.FencingToken <= 0 {
			if leaseErr == nil {
				leaseErr = fmt.Errorf("authoritative accelerator lease is unavailable")
			}
			return failTransition(leaseErr)
		}
		checkpointLease = lease
		aware, supported := adapter.(LeaseAwareCheckpointAdapter)
		if !supported || victim.Plan == nil {
			// Compatibility adapters used by non-LLM runtimes retain their
			// legacy checkpoint contract; native HTTPAdapter never enters this
			// branch and is always lease-aware.
			checkpoint, legacyErr := adapter.Checkpoint(ctx, victim.Execution, victimTarget)
			if legacyErr != nil || checkpoint == "" {
				if legacyErr == nil {
					legacyErr = fmt.Errorf("adapter returned an empty checkpoint reference")
				}
				return failTransition(legacyErr)
			}
			victim.CheckpointRef = checkpoint
			resultAction = "checkpointed"
			break
		}
		generation := m.targetGeneration(victimTarget.ID)
		profile := victim.Plan.ProfileDigest
		contextLimit := victim.Plan.TargetContextLimit
		if contextLimit <= 0 {
			contextLimit = victimTarget.ContextLimit
		}
		command := CheckpointCommand{ID: transition.ID + ":checkpoint", IdempotencyKey: transition.ID + ":checkpoint", OwnerID: victim.Request.OwnerID, WorkloadID: victim.Request.ID, WorkloadRevision: victim.Revision, Generation: generation, RuntimeIdentity: victimTarget.RuntimeIdentity, ModelFingerprint: victim.Plan.ModelFingerprint, ProfileFingerprint: profile, ContextLimit: contextLimit, Fence: uint64(lease.FencingToken)}
		checkpoint, err := aware.CheckpointWithLease(ctx, victim.Execution, victimTarget, SlotLease{TargetID: victimTarget.ID, AcceleratorID: acceleratorID, SlotID: -1, OwnerID: victim.Request.OwnerID, WorkloadID: victim.Request.ID, Generation: generation, Fence: uint64(lease.FencingToken), RuntimeIdentity: command.RuntimeIdentity, ModelFingerprint: command.ModelFingerprint, ProfileFingerprint: command.ProfileFingerprint, ContextLimit: command.ContextLimit}, command)
		if err != nil || checkpoint == "" {
			if err == nil {
				err = fmt.Errorf("adapter returned an empty checkpoint reference")
			}
			return failTransition(err)
		}
		victim.CheckpointRef = checkpoint
		resultAction = "checkpointed"
	case domain.DisruptionCancelable:
		if err := cancelAdapterStopConfirmed(ctx, adapter, victim.Execution, victimTarget); err != nil {
			return failTransition(err)
		}
		resultAction = "cancelled"
	}
	now = time.Now().UTC()
	victim.PreemptionCount++
	victim.Execution = nil
	victim.TransitionPlanIDs = append(victim.TransitionPlanIDs, transition.ID)
	if resultAction == "cancelled" {
		victim.Status = domain.WorkloadCancelled
		victim.FinishedAt = &now
	} else {
		victim.Status = domain.WorkloadQueued
		victim.StartedAt = nil
		victim.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "preempted by higher-priority workload; awaiting resume", Confidence: .8}
		victim.FinishedAt = nil
	}
	victim.Error = "preempted: " + resultAction
	victim.UpdatedAt = now
	updatedVictim, err := m.replaceWorkloadCAS(ctx, victim, workloadStatuses(domain.WorkloadRunning), "")
	if err != nil {
		if resultAction == "checkpointed" && victim.CheckpointRef != "" {
			checkpoint := victim.CheckpointRef
			intent, intentErr := m.persistCheckpointRecoveryIntent(context.WithoutCancel(ctx), victim, victimTarget, checkpoint, transition.ID, checkpointLease)
			if intentErr != nil {
				err = fmt.Errorf("victim CAS failed after physical checkpoint %q; durable compensation intent failed: %v: %w", checkpoint, intentErr, err)
			} else if handle, restoredLease, restoreErr := m.restoreCheckpointVictim(ctx, victim, victimTarget, adapter, checkpoint, checkpointLease, transition.ID); restoreErr != nil {
				err = fmt.Errorf("victim CAS failed after physical checkpoint %q; compensation unresolved and urgent capacity remains fenced: %v: %w", checkpoint, restoreErr, err)
				if operations, ok := m.store.(store.LLMCheckpointOperationStore); ok {
					if currentIntent, getErr := operations.GetLLMCheckpointOperation(context.WithoutCancel(ctx), intent.ID); getErr == nil && currentIntent.RecoveryState == "pending" {
						// No fresh lease/handle crossed the restore boundary. Keep the
						// pending intent retryable; cleanupFreshCheckpointRestore marks
						// it failed when a fresh stop is unconfirmed.
						if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), intent.ID, "pending", 0); markErr != nil {
							m.log.Warn("checkpoint recovery pending marker failed after restore error", "operation_id", intent.ID, "error", markErr)
						}
					}
				}
			} else if _, adoptErr := m.adoptRestoredCheckpointVictim(context.WithoutCancel(ctx), victim, victimTarget, handle, intent.ID); adoptErr != nil {
				cleanupErr := m.abandonRestoredCheckpointVictim(ctx, victim, victimTarget, adapter, handle, restoredLease, false)
				if cleanupErr != nil {
					markErr := m.markCheckpointRecoveryIntentFailed(context.WithoutCancel(ctx), intent.ID, cleanupErr)
					err = fmt.Errorf("victim CAS failed after physical checkpoint %q; restored backend cleanup remains fenced: %v; adoption: %v: %w", checkpoint, errors.Join(cleanupErr, markErr), adoptErr, err)
				} else if requeueErr := m.requeueCheckpointVictimAfterCleanup(context.WithoutCancel(ctx), victim.Request.ID, victimTarget.ID, checkpoint); requeueErr != nil {
					markErr := m.markCheckpointRecoveryIntentFailed(context.WithoutCancel(ctx), intent.ID, requeueErr)
					err = fmt.Errorf("victim CAS failed after physical checkpoint %q; restored backend stopped but requeue failed: %v; adoption: %v: %w", checkpoint, errors.Join(requeueErr, markErr), adoptErr, err)
				} else if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), intent.ID, "requeued", 0); markErr != nil {
					err = fmt.Errorf("victim CAS failed after physical checkpoint %q; restored backend was cancelled and requeued but recovery marker failed: %v; adoption: %v: %w", checkpoint, markErr, adoptErr, err)
				} else {
					err = fmt.Errorf("victim CAS failed after physical checkpoint %q; restored handle could not be adopted and victim was requeued: %v: %w", checkpoint, adoptErr, err)
				}
			} else {
				// The latest durable workload row now owns the fresh handle and
				// fence. Keep that generation live; never cancel it merely because
				// the stale projection lost its CAS race.
				err = fmt.Errorf("victim CAS conflicted after physical checkpoint %q; restored handle adopted durably: %w", checkpoint, err)
			}
		}
		return failTransition(err)
	}
	victim = updatedVictim
	if resultAction == "cancelled" {
		m.settleWorkloadBudget(ctx, victim)
	}
	newcomer.PreemptionsInitiated++
	newcomer.TransitionPlanIDs = append(newcomer.TransitionPlanIDs, transition.ID)
	newcomer.UpdatedAt = now
	if updatedNewcomer, err := m.replaceWorkloadCAS(ctx, newcomer, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadRunning), ""); err != nil {
		if resultAction == "checkpointed" && victim.CheckpointRef != "" {
			checkpoint := victim.CheckpointRef
			// The victim projection has already crossed its durable CAS.  Before
			// touching the backend again, journal the exact queued projection that
			// the fresh restore must replace.  This is the newcomer-CAS branch's
			// recovery root; a crash after physical restore can otherwise leave a
			// live handle with no authoritative owner.
			intent, intentErr := m.persistCheckpointRecoveryIntent(context.WithoutCancel(ctx), victim, victimTarget, checkpoint, transition.ID, checkpointLease)
			if intentErr != nil {
				return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; durable compensation intent failed before restore: %v: %w", checkpoint, intentErr, err))
			}
			if intent == nil || intent.ID == "" {
				return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; durable compensation intent returned no identity: %w", checkpoint, err))
			}
			handle, restoredLease, restoreErr := m.restoreCheckpointVictim(ctx, victim, victimTarget, adapter, checkpoint, checkpointLease, transition.ID)
			if restoreErr != nil {
				return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; urgent admission blocked and restore is unresolved: %v: %w", checkpoint, restoreErr, err))
			}
			restored := *victim
			restored.Status = domain.WorkloadRunning
			restored.Execution = handle
			restored.CheckpointRef = ""
			restored.Error = ""
			restored.UpdatedAt = time.Now().UTC()
			adoptedVictim, restoreCASErr := m.replaceWorkloadCAS(context.WithoutCancel(ctx), &restored, workloadStatuses(domain.WorkloadQueued), "")
			if restoreCASErr != nil {
				cleanupErr := m.abandonRestoredCheckpointVictim(ctx, victim, victimTarget, adapter, handle, restoredLease, false)
				if cleanupErr != nil {
					markErr := m.markCheckpointRecoveryIntentFailed(context.WithoutCancel(ctx), intent.ID, cleanupErr)
					return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; restored backend durable CAS failed and cleanup remains fenced: %v; durable restore: %v: %w", checkpoint, errors.Join(cleanupErr, markErr), restoreCASErr, err))
				}
				if requeueErr := m.requeueCheckpointVictimAfterCleanup(context.WithoutCancel(ctx), victim.Request.ID, victimTarget.ID, checkpoint); requeueErr != nil {
					markErr := m.markCheckpointRecoveryIntentFailed(context.WithoutCancel(ctx), intent.ID, requeueErr)
					return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; restored backend stopped but requeue failed: %v; durable restore: %v: %w", checkpoint, errors.Join(requeueErr, markErr), restoreCASErr, err))
				}
				if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), intent.ID, "requeued", 0); markErr != nil {
					return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; restored backend was cancelled and requeued but recovery marker failed: %v; durable restore: %v: %w", checkpoint, markErr, restoreCASErr, err))
				}
				return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; restored backend was cancelled and released after durable CAS failure: %v: %w", checkpoint, restoreCASErr, err))
			}
			if adoptedVictim == nil || adoptedVictim.Revision == 0 {
				return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; restored victim adoption returned no durable projection: %w", checkpoint, err))
			}
			if markErr := m.markCheckpointRecoveryIntent(context.WithoutCancel(ctx), intent.ID, "adopted", adoptedVictim.Revision); markErr != nil {
				// The workload CAS has already published the exact fresh handle. Keep
				// the handle live and let startup recovery observe the adopted
				// projection; cancelling here would create a duplicate-free but
				// unavailable workload.
				return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; restored victim adopted but recovery marker failed: %v: %w", checkpoint, markErr, err))
			}
			return failTransition(fmt.Errorf("newcomer CAS failed after victim checkpoint %q; original victim restored: %w", checkpoint, err))
		}
		return failTransition(err)
	} else {
		newcomer = updatedNewcomer
	}
	// Stop only the current backend segment after both durable workload CAS
	// transitions have succeeded. The interactive client session remains
	// attached and receives the next admitted segment automatically.
	m.mu.Lock()
	if session := m.streamSessions[victim.Request.ID]; session != nil {
		session.markPreempting()
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	finished := time.Now().UTC()
	transition.Status = domain.TransitionPlanCompleted
	transition.UpdatedAt = finished
	transition.FinishedAt = &finished
	if _, err := m.store.UpdateTransitionPlan(ctx, transition); err != nil {
		return false
	}
	m.audit(ctx, victim.Request.OwnerID, victim.Request.ID, "workload.preempted", "warn", map[string]any{"action": resultAction, "by_workload": newcomer.Request.ID, "transition_plan_id": transition.ID})
	m.signal()
	return true
}

func (m *Manager) releaseTarget(ctx context.Context, reservation *targetReservation) error {
	var intent *domain.AcceleratorLeaseCleanupIntent
	if reservation != nil {
		m.placementMu.Lock()
		intent = reservation.cleanupIntent
		m.placementMu.Unlock()
	}
	return m.releaseTargetWithIntent(ctx, reservation, intent)
}

func (m *Manager) releaseTargetWithIntent(ctx context.Context, reservation *targetReservation, terminal *domain.AcceleratorLeaseCleanupIntent) error {
	if reservation == nil || reservation.lease == nil {
		return nil
	}
	m.placementMu.Lock()
	if reservation.backendStopPending && !reservation.backendStopConfirmed {
		reservation.releaseRequested = true
		m.placementMu.Unlock()
		return fmt.Errorf("backend stop is unconfirmed; accelerator release remains fenced")
	}
	if reservation.released || reservation.releaseInFlight {
		m.placementMu.Unlock()
		return nil
	}
	stillActive := false
	for _, placement := range m.activePlacements {
		if placement.workloadID == reservation.workloadID {
			continue
		}
		if placement.acceleratorID == reservation.lease.AcceleratorID {
			stillActive = true
			break
		}
	}
	if !stillActive {
		reservation.releaseRequested = true
		reservation.releaseInFlight = true
	} else {
		// Remove a non-last co-scheduled workload while holding the same fence
		// used for election. This makes the last-releaser decision atomic and
		// prevents two concurrent finalizers from both issuing Release.
		reservation.released = true
		delete(m.activePlacements, reservation.workloadID)
		active := m.targetActive[reservation.targetID]
		if active > 1 {
			m.targetActive[reservation.targetID] = active - 1
		} else {
			delete(m.targetActive, reservation.targetID)
			delete(m.targetLeases, reservation.targetID)
		}
	}
	m.placementMu.Unlock()
	if stillActive {
		m.mu.Lock()
		if current := m.reservations[reservation.workloadID]; current == reservation {
			delete(m.reservations, reservation.workloadID)
		}
		m.mu.Unlock()
		return nil
	}
	cleanupErr := m.rollbackAcceleratorLeaseWithIntent(ctx, reservation.lease, reservation.lease.WorkloadID, false, terminal)
	if cleanupErr != nil && !errors.Is(cleanupErr, errLeaseCleanupRecorded) {
		m.placementMu.Lock()
		reservation.releaseInFlight = false
		m.placementMu.Unlock()
		// Keep placement ownership until either the exact release succeeds or
		// durable cleanup intent is recorded. The retry loop can safely call this
		// method again while the workload remains non-terminal.
		m.log.Error("accelerator lease cleanup requires durable retry", "accelerator_id", reservation.lease.AcceleratorID, "workload_id", reservation.lease.WorkloadID, "error", cleanupErr)
		return cleanupErr
	}
	if cleanupErr != nil {
		// A durable intent is not physical release confirmation. Keep the
		// reservation pending so terminal phases cannot publish until retry has
		// released or confirmed absence of this exact fenced lease.
		m.placementMu.Lock()
		reservation.releaseInFlight = false
		m.placementMu.Unlock()
		return cleanupErr
	}
	m.finishReleasedReservation(reservation)
	if ctx == nil {
		ctx = m.lifecycleContext()
	}
	idleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	idleKey := fmt.Sprintf("gpu-power:idle:%s:%s:%d", reservation.workloadID, reservation.lease.AcceleratorID, reservation.lease.FencingToken)
	if err := m.setGPUPerformanceProfile(idleCtx, reservation.lease.AcceleratorID, "idle", idleKey); err != nil {
		m.log.Warn("GPU idle performance transition failed", "accelerator_id", reservation.lease.AcceleratorID, "error", err)
	}
	return cleanupErr
}

func (m *Manager) releaseAdmissionReservation(ctx context.Context, reservation *targetReservation, targetID string, blockers *[]string) admitCandidateResult {
	if err := m.releaseTarget(ctx, reservation); err != nil {
		if blockers != nil {
			*blockers = append(*blockers, targetID+": cleanup_pending: "+err.Error())
		}
		return admitCandidateStopped
	}
	return admitCandidateNext
}

func (m *Manager) finishReleasedReservation(reservation *targetReservation) {
	m.placementMu.Lock()
	if reservation.released {
		m.placementMu.Unlock()
		return
	}
	m.finishReleasedReservationLocked(reservation)
	m.placementMu.Unlock()
	m.mu.Lock()
	if current := m.reservations[reservation.workloadID]; current == reservation {
		delete(m.reservations, reservation.workloadID)
	}
	m.mu.Unlock()
}

func (m *Manager) finishReleasedReservationLocked(reservation *targetReservation) {
	reservation.released = true
	reservation.releaseInFlight = false
	reservation.cleanupIntent = nil
	reservation.backendHandle = nil
	reservation.backendAdapter = nil
	reservation.backendTarget = Target{}
	reservation.backendStopPending = false
	reservation.backendStopConfirmed = true
	reservation.backendCleanupMessage = ""
	reservation.backendCleanupTerminal = ""
	delete(m.activePlacements, reservation.workloadID)
	active := m.targetActive[reservation.targetID]
	if active > 1 {
		m.targetActive[reservation.targetID] = active - 1
	} else {
		delete(m.targetActive, reservation.targetID)
		delete(m.targetLeases, reservation.targetID)
	}
}

// lifecycleContext returns the manager-owned cancellation context without
// holding lifecycleMu during any store or backend operation. It is used by
// compatibility paths that predate the explicit execution context.
func (m *Manager) lifecycleContext() context.Context {
	m.lifecycleMu.Lock()
	ctx := m.managerCtx
	m.lifecycleMu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func hashPlan(req domain.WorkloadRequest, plan *domain.ExecutionPlan) string {
	b, _ := json.Marshal(struct {
		Payload                            json.RawMessage       `json:"payload"`
		Bounds                             domain.WorkloadBounds `json:"bounds"`
		AdapterVersion, Target, Capability string
		RuntimeProtocol                    string
		ModelFingerprint, CapacitySource   string
		TargetContextLimit, TargetSlots    int
		CapacityVerified                   bool
		Transformations                    []string
		Material                           json.RawMessage
		Provider, Model                    string
	}{req.Payload, req.Bounds, plan.AdapterVersion, plan.TargetID, plan.CapabilityVersion, plan.RuntimeProtocol, plan.ModelFingerprint, plan.CapacitySource, plan.TargetContextLimit, plan.TargetSlots, plan.CapacityVerified, plan.Transformations, plan.Material, plan.Provider, plan.Model})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (m *Manager) prepareExecutionPlan(adapter Adapter, workload *domain.Workload, target Target) (*domain.ExecutionPlan, error) {
	plan, err := adapter.Plan(m.lifecycleContext(), workload.Request, target)
	if err != nil {
		return nil, err
	}
	plan.ID = newID("plan")
	plan.WorkloadID = workload.Request.ID
	plan.Adapter = adapter.Name()
	plan.AdapterVersion = adapter.Version()
	plan.TargetID = target.ID
	plan.RuntimeProtocol = target.RuntimeProtocol
	plan.AcceleratorID = target.AcceleratorID
	plan.CapabilityVersion = target.CapabilityVersion
	plan.TargetContextLimit = target.ContextLimit
	plan.TargetSlots = target.Slots
	plan.ModelFingerprint = target.ModelFingerprint
	plan.CapacitySource = target.CapacitySource
	plan.CapacityVerified = target.CapacityVerified
	// Native checkpoint commands require one immutable profile fingerprint even
	// for the public OpenAI/API planes, which do not carry creator-studio
	// profile metadata.  A runtime advertisement's active profile is the
	// authoritative target-scoped identity in that case; without this fallback
	// the signed stream/checkpoint envelope would be rejected as incomplete.
	if plan.ProfileDigest == "" && target.ActiveRuntimeProfile != "" {
		plan.ProfileDigest = target.ActiveRuntimeProfile
	}
	plan.Provider = target.Provider
	plan.InputCentsPerMTok = target.InputCentsPerMTok
	plan.OutputCentsPerMTok = target.OutputCentsPerMTok
	var modelEnvelope struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(workload.Request.Payload, &modelEnvelope)
	plan.Model = modelEnvelope.Model
	plan.Transformations = append([]string(nil), workload.Request.Transformations...)
	plan.CreatedAt = time.Now().UTC()
	plan.PlanHash = hashPlan(workload.Request, plan)
	return plan, nil
}

// targetIdentityMatches is the canonical execution-fence comparison for an
// advertisement. It includes resident-model eligibility and every dispatch,
// policy, capacity, endpoint, provider, pricing, authorization, profile, and
// custom-node fact; only ephemeral controller Active/circuit telemetry is
// excluded by the fingerprint helper.
func targetIdentityMatches(expected, current Target) bool {
	return expected.ID != "" && current.ID == expected.ID && targetExecutionFingerprint(expected) == targetExecutionFingerprint(current)
}

// targetFenceMatches is a short, lock-free-to-call snapshot check used before
// and after external runtime transitions. It intentionally performs no store
// or adapter work; callers can use it at the boundary of an external wait.
func (m *Manager) targetFenceMatches(expected Target, generation uint64) bool {
	// Compatibility/unit callers may invoke lifecycle helpers with a detached
	// target that was never registered. There is no mutable controller fact to
	// fence in that mode; registered production targets always start at a
	// non-zero generation and take the strict path below.
	if generation == 0 {
		return true
	}
	current := m.targetByID(expected.ID)
	return targetIdentityMatches(expected, current) && m.targetGeneration(expected.ID) == generation
}

// validateExecutionFacts takes only short manager snapshots and performs its
// store reads without a state lock.  It never performs an adapter/node
// command.  Keeping this helper free of long-held manager locks is what lets
// RegisterTarget make progress while Start/StartStream is waiting on a signed
// node command; the generation checks fence the snapshot after those reads.
func (m *Manager) validateExecutionFacts(ctx context.Context, expected Target, expectedGeneration uint64, req Requirements, workloadID string) (Target, error) {
	current := m.targetByID(expected.ID)
	if !targetIdentityMatches(expected, current) {
		return Target{}, fmt.Errorf("target facts changed before execution")
	}
	if expectedGeneration > 0 {
		m.mu.RLock()
		generation := m.targetGenerations[expected.ID]
		m.mu.RUnlock()
		if generation != expectedGeneration {
			return Target{}, fmt.Errorf("target generation changed before execution")
		}
	}
	if req.Model == "" {
		latest := m.targetByID(expected.ID)
		if !targetIdentityMatches(current, latest) || (expectedGeneration > 0 && m.targetGeneration(expected.ID) != expectedGeneration) {
			return Target{}, fmt.Errorf("target facts changed during execution validation")
		}
		return latest, nil
	}
	residency, residencyErr := m.store.GetModelResidency(ctx, current.ID, req.Model)
	legacyResident := containsString(current.ResidentModels, req.Model)
	if residencyErr == nil && residency.ObservedTier != domain.ResidencyHotVRAM {
		return Target{}, fmt.Errorf("model residency changed before execution")
	}
	if residencyErr != nil && (!errors.Is(residencyErr, store.ErrNotFound) || !legacyResident) {
		return Target{}, fmt.Errorf("model residency changed before execution")
	}
	if capacityErr := m.checkResidentCapacityForWorkload(ctx, current, req.Model, workloadID); capacityErr != nil {
		return Target{}, fmt.Errorf("model capacity changed before execution: %w", capacityErr)
	}
	latest := m.targetByID(expected.ID)
	if !targetIdentityMatches(current, latest) || (expectedGeneration > 0 && m.targetGeneration(expected.ID) != expectedGeneration) {
		return Target{}, fmt.Errorf("target facts changed during execution validation")
	}
	return latest, nil
}

// RunStream claims an admitted interactive stream and synchronously proxies
// it through emit. The caller's context owns cancellation, while the manager
// continues to own the accelerator reservation and fencing lease.
func (m *Manager) RunStream(ctx context.Context, id string, emit func([]byte) error) (*domain.Workload, error) {
	if emit == nil {
		return nil, fmt.Errorf("stream emitter is required")
	}
	if !m.trackAsync() {
		return nil, fmt.Errorf("manager is closed")
	}
	defer m.untrackAsync()
	m.mu.Lock()
	pending := m.pendingStreams[id]
	if pending != nil {
		delete(m.pendingStreams, id)
		m.stopPendingStreamTimer(pending)
	}
	m.mu.Unlock()
	if pending == nil {
		return nil, fmt.Errorf("workload %s has no attachable stream", id)
	}
	session := newStreamSession(emit)
	m.mu.Lock()
	// The pending entry is consumed exactly once. A second HTTP attachment is
	// never accepted while the first response still owns the session.
	if prior := m.streamSessions[id]; prior != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("workload %s already has an attached stream", id)
	}
	m.streamSessions[id] = session
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if m.streamSessions[id] == session {
			delete(m.streamSessions, id)
		}
		m.mu.Unlock()
	}()

	// Client disconnect is a session event, not a backend-segment event. The
	// callback cancels only the currently running segment; if the victim is
	// waiting for re-admission the cancellation path below settles it durably.
	stopClientCancellation := context.AfterFunc(ctx, func() {
		session.disconnect()
		m.mu.RLock()
		cancel := m.cancels[id]
		m.mu.RUnlock()
		if cancel != nil {
			cancel()
		}
	})
	defer stopClientCancellation()

	segment := streamSegment{ctx: pending.ctx, target: pending.target, reservation: pending.reservation}
	for {
		row, streamErr := m.executeStreamSegment(segment.ctx, id, segment.target, segment.reservation, session)
		if !errors.Is(streamErr, errStreamPreempted) {
			return row, streamErr
		}
		// The backend segment was checkpointed and its physical reservation was
		// released. Wait for the normal admission loop to deliver a new segment
		// while keeping this HTTP response/emitter alive.
		select {
		case <-ctx.Done():
			// A queued checkpoint victim has no active segment for the callback to
			// cancel. Use the manager's durable cancellation path to settle it.
			cancelCtx := context.WithoutCancel(ctx)
			if current, getErr := m.store.GetWorkload(cancelCtx, id); getErr == nil {
				if cancelErr := m.Cancel(cancelCtx, id, current.Request.OwnerID, false); cancelErr != nil {
					m.log.Error("interactive stream cancellation cleanup remains fenced", "workload_id", id, "error", cancelErr)
				}
			}
			return row, ctx.Err()
		case segment = <-session.segments:
			if session.isDisconnected() {
				cancelCtx := context.WithoutCancel(ctx)
				if current, getErr := m.store.GetWorkload(cancelCtx, id); getErr == nil {
					if cancelErr := m.Cancel(cancelCtx, id, current.Request.OwnerID, false); cancelErr != nil {
						m.log.Error("interactive stream disconnect cleanup remains fenced", "workload_id", id, "error", cancelErr)
					}
				}
				return row, context.Canceled
			}
			session.clearPreempting()
		}
	}
}

func (m *Manager) executeStream(ctx context.Context, id string, target Target, reservation *targetReservation, emit func([]byte) error) (*domain.Workload, error) {
	return m.executeStreamSegment(ctx, id, target, reservation, newStreamSession(emit))
}

func (m *Manager) executeStreamSegment(ctx context.Context, id string, target Target, reservation *targetReservation, session *streamSession) (*domain.Workload, error) {
	if session == nil {
		session = newStreamSession(nil)
	}
	emit := session.emit
	var adapter Adapter
	var handle *domain.ExecutionHandle
	backendStopConfirmed := false
	backendStopUnconfirmed := false
	cleanupDisposition := ""
	cleanupMessage := ""
	defer func() {
		// Segment cancellation is expected during checkpoint preemption and
		// client disconnect. Cleanup must still use the manager-owned authority;
		// otherwise a cancelled segment context can strand the accelerator lease.
		m.placementMu.Lock()
		reservationReleased := reservation == nil || reservation.released
		checkpointOperationID := ""
		if reservation != nil {
			checkpointOperationID = reservation.checkpointOperationID
		}
		m.placementMu.Unlock()
		cancellationOwnedExternally := m.isCancelling(id)
		var cleanupErr error
		if !reservationReleased && !cancellationOwnedExternally && backendStopUnconfirmed {
			cleanupErr = fmt.Errorf("backend stop unconfirmed: no cancellable execution handle")
		} else if !reservationReleased && !cancellationOwnedExternally && handle != nil && !backendStopConfirmed {
			cleanupErr = m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
			if cleanupErr == nil {
				backendStopConfirmed = true
				m.confirmReservationBackendStopped(reservation)
			}
		}
		if cleanupErr == nil && !reservationReleased && !cancellationOwnedExternally && checkpointOperationID != "" && backendStopConfirmed {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), checkpointOperationID, "stopped", handle, target, reservation.lease, cleanupDisposition, cleanupMessage); journalErr != nil {
				cleanupErr = fmt.Errorf("checkpoint cleanup stop boundary could not be durably recorded: %w", journalErr)
			}
		}
		if cleanupErr == nil && !reservationReleased && !cancellationOwnedExternally {
			cleanupErr = m.releaseTarget(context.WithoutCancel(ctx), reservation)
		}
		if cleanupErr == nil && checkpointOperationID != "" {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), checkpointOperationID, "confirmed", handle, target, reservation.lease, cleanupDisposition, cleanupMessage); journalErr != nil {
				m.log.Warn("checkpoint cleanup confirmation marker deferred after exact release", "workload_id", id, "error", journalErr)
			}
		}
		if cleanupErr == nil && cleanupDisposition == "failure" && !m.isCancelling(id) {
			if current, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), id); getErr == nil && !isTerminalWorkloadStatus(current.Status) {
				m.fail(context.WithoutCancel(ctx), current, cleanupMessage)
			}
		}
		if cleanupErr != nil {
			if cleanupDisposition == "" && !m.isCancelling(id) {
				cleanupDisposition = "failure"
			}
			if cleanupMessage == "" {
				cleanupMessage = "stream backend cleanup failed; accelerator remains fenced: " + cleanupErr.Error()
			}
			cleanupAdapter := adapter
			cleanupHandle := handle
			if backendStopConfirmed {
				cleanupAdapter = nil
				cleanupHandle = nil
			}
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, cleanupAdapter, target, cleanupHandle, cleanupDisposition, cleanupMessage)
			m.log.Error("stream execution cleanup failed", "workload_id", id, "error", cleanupErr)
		}
		m.mu.Lock()
		delete(m.cancels, id)
		m.mu.Unlock()
		m.signal()
	}()
	w, err := m.store.GetWorkload(ctx, id)
	if err != nil {
		return nil, err
	}
	planID := ""
	if w.Plan != nil {
		planID = w.Plan.ID
	}
	m.mu.RLock()
	adapter = m.adapters[w.Request.Adapter]
	m.mu.RUnlock()
	streaming, ok := adapter.(StreamingAdapter)
	if !ok {
		m.fail(ctx, w, "adapter does not support interactive streaming")
		return m.store.GetWorkload(ctx, id)
	}
	liveStreaming, hasLiveStreaming := adapter.(LiveStreamingAdapter)
	leaseStreaming, hasLeaseStreaming := adapter.(LeaseAwareStreamingAdapter)
	if capability, ok := adapter.(LeaseAwareStreamingCapability); ok && !capability.LeaseStreamingEnabled() {
		hasLeaseStreaming = false
	}
	// Requirements may query a remote/runtime adapter.  Do this before taking
	// the refresh fence so a blocked attach cannot starve RegisterTarget.
	requirements, requirementsErr := adapter.Requirements(ctx, w.Request)
	if requirementsErr != nil {
		m.failAfterReservation(ctx, w, reservation, "runtime requirements changed before stream attach: "+requirementsErr.Error())
		return m.store.GetWorkload(ctx, id)
	}
	currentTarget, validationErr := m.validateExecutionFacts(ctx, target, reservation.targetGeneration, requirements, id)
	if validationErr != nil {
		m.failAfterReservation(ctx, w, reservation, validationErr.Error())
		return m.store.GetWorkload(ctx, id)
	}
	target = currentTarget
	if capability, ok := adapter.(TargetLeaseAwareStreamingCapability); ok && !capability.LeaseStreamingEnabledForTarget(target) {
		hasLeaseStreaming = false
	}
	runCtx, stopRun, leaseErrors := m.startLeaseKeeper(ctx, reservation.lease)
	defer stopRun()
	activeKey := fmt.Sprintf("gpu-power:active:%s:%s:%d", id, reservation.lease.AcceleratorID, reservation.lease.FencingToken)
	if err := m.setGPUPerformanceProfile(runCtx, reservation.lease.AcceleratorID, "active", activeKey); err != nil {
		m.failAfterReservation(ctx, w, reservation, "GPU active performance transition failed: "+err.Error())
		return m.store.GetWorkload(ctx, id)
	}
	// The profile command is also an external wait. Revalidate immediately
	// after it returns, closing the attach-delay interleaving before StartStream.
	currentTarget, validationErr = m.validateExecutionFacts(ctx, target, reservation.targetGeneration, requirements, id)
	if validationErr != nil {
		m.failAfterReservation(ctx, w, reservation, validationErr.Error())
		return m.store.GetWorkload(ctx, id)
	}
	target = currentTarget
	var clientWriteErr error
	streamCommand := CheckpointCommand{ID: "stream:" + id + ":" + fmt.Sprint(reservation.lease.FencingToken), IdempotencyKey: "stream:" + id + ":" + fmt.Sprint(reservation.lease.FencingToken), OwnerID: w.Request.OwnerID, WorkloadID: id, WorkloadRevision: w.Revision, Generation: reservation.targetGeneration, RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: w.Plan.ModelFingerprint, ProfileFingerprint: w.Plan.ProfileDigest, ContextLimit: w.Plan.TargetContextLimit, Fence: uint64(reservation.lease.FencingToken)}
	if streamCommand.ContextLimit <= 0 {
		streamCommand.ContextLimit = target.ContextLimit
	}
	checkpointRef := w.CheckpointRef
	resumingCheckpoint := strings.TrimSpace(checkpointRef) != ""
	var resumeCleanup resumeProtocolCleanupResult
	if resumingCheckpoint {
		if _, journalErr := m.prepareResumeCleanupJournal(context.WithoutCancel(ctx), w, target, reservation, checkpointRef); journalErr != nil {
			m.failAfterReservation(ctx, w, reservation, "checkpoint cleanup journal unavailable before resume: "+journalErr.Error())
			return m.store.GetWorkload(ctx, id)
		}
		if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), reservation.checkpointOperationID, "pending", nil, target, reservation.lease, "failure", "resumed backend cleanup pending"); journalErr != nil {
			m.failAfterReservation(ctx, w, reservation, "checkpoint cleanup custody could not be armed before resume: "+journalErr.Error())
			return m.store.GetWorkload(ctx, id)
		}
	}
	startStream := func() (*domain.ExecutionHandle, error) {
		if resumingCheckpoint {
			aware, supported := adapter.(LeaseAwareCheckpointAdapter)
			if !supported || w.Plan == nil {
				return nil, ErrUnsupported
			}
			resumeCommand := CheckpointCommand{ID: "restore:" + id + ":" + checkpointRef, IdempotencyKey: "restore:" + id + ":" + checkpointRef, OwnerID: w.Request.OwnerID, WorkloadID: id, WorkloadRevision: w.Revision, Generation: reservation.targetGeneration, RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: streamCommand.ModelFingerprint, ProfileFingerprint: streamCommand.ProfileFingerprint, ContextLimit: streamCommand.ContextLimit, Fence: uint64(reservation.lease.FencingToken)}
			var handle *domain.ExecutionHandle
			handle, err, resumeCleanup = resumeWithLeaseWatchingProtocol(runCtx, aware, w.Request, w.Plan, checkpointRef, target, SlotLease{TargetID: target.ID, NodeID: target.NodeID, AcceleratorID: reservation.lease.AcceleratorID, SlotID: -1, OwnerID: w.Request.OwnerID, WorkloadID: id, Generation: reservation.targetGeneration, Fence: uint64(reservation.lease.FencingToken), RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: streamCommand.ModelFingerprint, ProfileFingerprint: streamCommand.ProfileFingerprint, ContextLimit: streamCommand.ContextLimit}, resumeCommand)
			if resumeCleanup.confirmed {
				backendStopConfirmed = true
				m.confirmReservationBackendStopped(reservation)
				cleanupDisposition = "failure"
				cleanupMessage = "resumed stream backend protocol failed after signed cancellation"
				if resumeCleanup.err != nil {
					cleanupMessage += ": " + resumeCleanup.err.Error()
				}
			}
			return handle, err
		}
		if hasLeaseStreaming {
			return leaseStreaming.StartStreamWithLease(runCtx, w.Request, w.Plan, target, SlotLease{TargetID: target.ID, AcceleratorID: reservation.lease.AcceleratorID, SlotID: -1, OwnerID: w.Request.OwnerID, WorkloadID: id, Generation: reservation.targetGeneration, Fence: uint64(reservation.lease.FencingToken), RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: streamCommand.ModelFingerprint, ProfileFingerprint: streamCommand.ProfileFingerprint, ContextLimit: streamCommand.ContextLimit}, streamCommand, func(chunk []byte) error { clientWriteErr = emit(chunk); return clientWriteErr })
		}
		if hasLiveStreaming {
			return liveStreaming.StartStreamLive(runCtx, w.Request, w.Plan, target, func(chunk []byte) error {
				clientWriteErr = emit(chunk)
				return clientWriteErr
			})
		}
		return streaming.StartStream(runCtx, w.Request, w.Plan, target, func(chunk []byte) error {
			clientWriteErr = emit(chunk)
			return clientWriteErr
		})
	}
	handle, err = startStream()
	if handle != nil {
		m.rememberReservationBackend(reservation, adapter, target, handle)
		if resumingCheckpoint {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), reservation.checkpointOperationID, "owned", handle, target, reservation.lease, "", ""); journalErr != nil {
				backendStopUnconfirmed = true
				cleanupDisposition = "failure"
				cleanupMessage = "resumed backend handle could not be durably recorded: " + journalErr.Error()
				m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
				return nil, journalErr
			}
		}
	}
	if err == nil && resumingCheckpoint && handle == nil {
		err = fmt.Errorf("checkpoint ResumeWithLease returned no handle; backend stop is unconfirmed")
		backendStopUnconfirmed = true
		cleanupDisposition = "failure"
		cleanupMessage = err.Error()
		m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, nil, cleanupDisposition, cleanupMessage)
		return nil, err
	}
	if err != nil {
		if resumeCleanup.confirmed {
			// The bounded watcher cancelled the malformed resumed generation
			// before ResumeWithLease returned. Its cleanup owns the signed stop;
			// let the outer defer release the controller fence and publish the
			// visible protocol failure without issuing a second Cancel.
			return nil, err
		}
		if m.isCancelling(id) {
			latest, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), id)
			if getErr != nil {
				return nil, getErr
			}
			return latest, err
		}
		if resumingCheckpoint && handle == nil {
			backendStopUnconfirmed = true
			cleanupDisposition = "failure"
			cleanupMessage = "checkpoint ResumeWithLease failed without a handle; backend stop is unconfirmed: " + err.Error()
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, nil, cleanupDisposition, cleanupMessage)
			return nil, err
		}
		if handle != nil && !session.isPreempting() {
			if stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target); stopErr != nil {
				cleanupDisposition = "failure"
				cleanupMessage = "stream start/resume failed and backend stop is unconfirmed: " + stopErr.Error()
				m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
				return nil, errors.Join(err, stopErr)
			}
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
		}
		if session.isPreempting() {
			// CheckpointWithLease has already performed the signed pause/stop
			// transition for this segment. Treat that operation as the physical
			// stop confirmation so the defer does not issue a second Cancel with
			// a different checkpoint idempotency key.
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
			latest, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), id)
			if getErr != nil {
				return nil, getErr
			}
			return latest, errStreamPreempted
		}
		m.recordProviderFailure(target, err)
		if leaseErr := takeLeaseError(leaseErrors); leaseErr != nil {
			m.failAfterReservation(ctx, w, reservation, "accelerator lease lost: "+leaseErr.Error())
		} else if runCtx.Err() != nil || clientWriteErr != nil {
			if m.isCancelling(id) {
				latest, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), id)
				if getErr != nil {
					return nil, getErr
				}
				return latest, err
			}
			stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
			if stopErr != nil {
				cleanupDisposition = "cancel"
				cleanupMessage = "stream client disconnected; backend stop is unconfirmed: " + stopErr.Error()
				m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
				m.log.Error("stream cancellation backend cleanup failed; accelerator remains fenced", "workload_id", id, "error", stopErr)
			} else {
				backendStopConfirmed = true
				m.confirmReservationBackendStopped(reservation)
				if releaseErr := m.releaseBeforeTerminal(context.WithoutCancel(ctx), w, reservation, "cancel", "stream client disconnected"); releaseErr == nil {
					m.markStreamCancelled(id, "stream client disconnected")
				} else {
					m.log.Error("stream cancellation deferred until accelerator cleanup is durable", "workload_id", id, "error", releaseErr)
				}
			}
		} else {
			m.failAfterReservation(ctx, w, reservation, err.Error())
		}
		latest, getErr := m.store.GetWorkload(ctx, id)
		if getErr != nil {
			return nil, getErr
		}
		return latest, err
	}
	// Publish the live handle before observation. A failed durable CAS cancels
	// the real backend generation so no unowned slot continues after return.
	if hasLeaseStreaming || hasLiveStreaming {
		published := *w
		published.Execution = handle
		if resumingCheckpoint {
			// The signed restore operation has adopted the live response. Clear
			// the queued snapshot reference before publishing the new segment so
			// a later observer cannot launch the same continuation twice.
			published.CheckpointRef = ""
		}
		published.UpdatedAt = time.Now().UTC()
		if _, publishErr := m.replaceWorkloadCAS(ctx, &published, workloadStatuses(domain.WorkloadRunning), ""); publishErr != nil {
			if m.isCancelling(id) {
				return m.store.GetWorkload(context.WithoutCancel(ctx), id)
			}
			cancelErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
			message := "live stream handle publication failed: " + publishErr.Error()
			if cancelErr != nil {
				message += "; signed backend cancellation failed: " + cancelErr.Error()
				cleanupDisposition = "failure"
				cleanupMessage = message
				m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
				return m.store.GetWorkload(ctx, id)
			}
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
			cleanupDisposition = "failure"
			cleanupMessage = message
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, nil, target, nil, cleanupDisposition, cleanupMessage)
			return m.store.GetWorkload(ctx, id)
		}
	}
	if hasLiveStreaming {
		// A live handle is deliberately published before the first token. Keep
		// the reservation and checkpoint ownership until the real backend
		// goroutine reaches a terminal observation.
		for {
			observation, observeErr := adapter.Observe(runCtx, w.Request, w.Plan, handle, target)
			if observeErr != nil {
				err = observeErr
				break
			}
			if observation.Status == domain.WorkloadSucceeded || observation.Status == domain.WorkloadFailed || observation.Status == domain.WorkloadCancelled {
				// Observe has authoritatively reported that this stream generation
				// reached a terminal backend state. Mark the physical stop before
				// any workload refresh/terminal CAS can return through the defer;
				// otherwise the defer may issue a second Cancel after the adapter has
				// already released its checkpoint binding.
				backendStopConfirmed = true
				m.confirmReservationBackendStopped(reservation)
				break
			}
			select {
			case <-runCtx.Done():
				err = runCtx.Err()
			default:
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				break
			}
		}
		if err != nil {
			if session.isPreempting() {
				// The checkpoint transition owns stop confirmation for a preempted
				// segment; avoid a deferred adapter Cancel racing its signed pause.
				backendStopConfirmed = true
				m.confirmReservationBackendStopped(reservation)
				latest, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), id)
				if getErr != nil {
					return nil, getErr
				}
				return latest, errStreamPreempted
			}
			m.recordProviderFailure(target, err)
			if leaseErr := takeLeaseError(leaseErrors); leaseErr != nil {
				m.failAfterReservation(ctx, w, reservation, "accelerator lease lost: "+leaseErr.Error())
			} else if runCtx.Err() != nil || clientWriteErr != nil {
				if m.isCancelling(id) {
					latest, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), id)
					if getErr != nil {
						return nil, getErr
					}
					return latest, err
				}
				stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
				if stopErr != nil {
					cleanupDisposition = "cancel"
					cleanupMessage = "stream client disconnected; backend stop is unconfirmed: " + stopErr.Error()
					m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
					m.log.Error("stream cancellation backend cleanup failed; accelerator remains fenced", "workload_id", id, "error", stopErr)
				} else {
					backendStopConfirmed = true
					m.confirmReservationBackendStopped(reservation)
					if releaseErr := m.releaseBeforeTerminal(context.WithoutCancel(ctx), w, reservation, "cancel", "stream client disconnected"); releaseErr == nil {
						m.markStreamCancelled(id, "stream client disconnected")
					}
				}
			} else {
				// An observe/stream protocol error does not prove that a
				// lease-aware or restored backend stopped. Cancel it before the
				// terminal release path; otherwise failAfterReservation can leave
				// the workload non-terminal while its fresh fence is still live.
				stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
				if stopErr != nil {
					cleanupDisposition = "failure"
					cleanupMessage = "stream observation failed and backend stop is unconfirmed: " + stopErr.Error()
					m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
					// Surface the failure immediately while retainReservation keeps
					// the exact accelerator fence for bounded cleanup retry.
					m.fail(context.WithoutCancel(ctx), w, cleanupMessage)
				} else {
					backendStopConfirmed = true
					m.confirmReservationBackendStopped(reservation)
					m.failAfterReservation(ctx, w, reservation, err.Error())
				}
			}
			latest, getErr := m.store.GetWorkload(ctx, id)
			if getErr != nil {
				return nil, getErr
			}
			return latest, err
		}
	}
	// A refresh can complete while the runtime is attaching. Do not let a
	// successful handle turn a cold/stale target into a runnable stream.
	currentTarget, validationErr = m.validateExecutionFacts(ctx, target, reservation.targetGeneration, requirements, id)
	if validationErr != nil {
		if m.isCancelling(id) {
			return m.store.GetWorkload(context.WithoutCancel(ctx), id)
		}
		cancelErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
		message := validationErr.Error()
		if cancelErr != nil {
			message += "; signed backend cancellation failed: " + cancelErr.Error()
			cleanupDisposition = "failure"
			cleanupMessage = message
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
			return m.store.GetWorkload(ctx, id)
		}
		backendStopConfirmed = true
		m.confirmReservationBackendStopped(reservation)
		m.failAfterReservation(ctx, w, reservation, message)
		return m.store.GetWorkload(ctx, id)
	}
	target = currentTarget
	if err := m.store.RenewAcceleratorLease(ctx, reservation.lease.AcceleratorID, reservation.lease.WorkloadID, reservation.lease.FencingToken, m.leaseTTL); err != nil {
		if m.isCancelling(id) {
			return m.store.GetWorkload(context.WithoutCancel(ctx), id)
		}
		if stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target); stopErr != nil {
			cleanupDisposition = "failure"
			cleanupMessage = "accelerator lease renewal failed before stream completion; backend stop is unconfirmed: " + stopErr.Error()
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
			latest, _ := m.store.GetWorkload(context.WithoutCancel(ctx), id)
			return latest, err
		}
		backendStopConfirmed = true
		m.confirmReservationBackendStopped(reservation)
		m.failAfterReservation(ctx, w, reservation, "accelerator lease lost before stream completion")
		latest, _ := m.store.GetWorkload(ctx, id)
		return latest, err
	}
	latest, err := m.store.GetWorkload(ctx, id)
	if err != nil {
		return nil, err
	}
	if latest.Status != domain.WorkloadRunning || latest.Plan == nil || latest.Plan.ID != planID {
		return latest, context.Canceled
	}
	// The synchronous stream call has completed the backend generation. Mark
	// that physical stop before the terminal release/CAS sequence.
	backendStopConfirmed = true
	m.confirmReservationBackendStopped(reservation)
	now := time.Now().UTC()
	latest.Status = domain.WorkloadSucceeded
	latest.Progress = 1
	latest.Execution = handle
	if resumingCheckpoint {
		latest.CheckpointRef = ""
	}
	latest.InlineOutput = json.RawMessage(`{"streamed":true}`)
	latest.UpdatedAt = now
	latest.FinishedAt = &now
	if releaseErr := m.releaseBeforeTerminal(ctx, latest, reservation, "success", ""); releaseErr != nil {
		return latest, releaseErr
	}
	persisted, err := m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadRunning), "")
	if err != nil {
		if current, getErr := m.store.GetWorkload(ctx, id); getErr == nil && current.Status == domain.WorkloadSucceeded {
			return current, nil
		}
		return latest, err
	}
	latest = persisted
	m.syncPromptMapping(ctx, latest)
	m.settleWorkloadBudget(ctx, latest)
	m.recordProviderSuccess(target)
	m.recordSchedulingSample(ctx, latest, target, reservation, Observation{Status: domain.WorkloadSucceeded}, "succeeded")
	m.markModelUsed(ctx, latest, target)
	m.audit(ctx, latest.Request.OwnerID, id, "workload.succeeded", "info", map[string]bool{"streamed": true})
	if latest.Request.Notifications.OnFinish {
		m.enqueueNotification(ctx, latest, "workload.succeeded")
	}
	return latest, nil
}

func (m *Manager) markStreamCancelled(id, reason string) {
	ctx := m.lifecycleContext()
	w, err := m.store.GetWorkload(ctx, id)
	if err != nil || w.Status != domain.WorkloadRunning {
		return
	}
	now := time.Now().UTC()
	w.Status = domain.WorkloadCancelled
	w.Error = reason
	w.UpdatedAt = now
	w.FinishedAt = &now
	persisted, casErr := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadRunning), "")
	if casErr != nil {
		return
	}
	w = persisted
	m.settleWorkloadBudget(ctx, w)
	m.audit(ctx, w.Request.OwnerID, id, "workload.cancelled", "warn", map[string]string{"reason": reason})
	if w.Request.Notifications.OnFinish {
		m.enqueueNotification(ctx, w, "workload.cancelled")
	}
}

func (m *Manager) startLeaseKeeper(ctx context.Context, lease *domain.AcceleratorLease) (context.Context, context.CancelFunc, <-chan error) {
	runCtx, cancel := context.WithCancel(ctx)
	errors := make(chan error, 1)
	interval := m.leaseTTL / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	go func() {
		if !m.trackAsync() {
			cancel()
			return
		}
		defer m.untrackAsync()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := m.store.RenewAcceleratorLease(runCtx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); err != nil {
					errors <- err
					cancel()
					return
				}
			}
		}
	}()
	return runCtx, cancel, errors
}

func takeLeaseError(errors <-chan error) error {
	select {
	case err := <-errors:
		return err
	default:
		return nil
	}
}

func (m *Manager) execute(ctx context.Context, id string, target Target, reservation *targetReservation) {
	lease := reservation.lease
	leaseID := lease.AcceleratorID
	var adapter Adapter
	var handle *domain.ExecutionHandle
	backendStopConfirmed := false
	backendStopUnconfirmed := false
	cleanupDisposition := ""
	cleanupMessage := ""
	defer func() {
		m.placementMu.Lock()
		reservationReleased := reservation == nil || reservation.released
		checkpointOperationID := ""
		if reservation != nil {
			checkpointOperationID = reservation.checkpointOperationID
		}
		m.placementMu.Unlock()
		cancellationOwnedExternally := m.isCancelling(id)
		var cleanupErr error
		if !reservationReleased && !cancellationOwnedExternally && backendStopUnconfirmed {
			cleanupErr = fmt.Errorf("backend stop unconfirmed: no cancellable execution handle")
		} else if !reservationReleased && !cancellationOwnedExternally && handle != nil && !backendStopConfirmed {
			cleanupErr = m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
			if cleanupErr == nil {
				backendStopConfirmed = true
				m.confirmReservationBackendStopped(reservation)
			}
		}
		if cleanupErr == nil && !reservationReleased && !cancellationOwnedExternally && checkpointOperationID != "" && backendStopConfirmed {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), checkpointOperationID, "stopped", handle, target, reservation.lease, cleanupDisposition, cleanupMessage); journalErr != nil {
				cleanupErr = fmt.Errorf("checkpoint cleanup stop boundary could not be durably recorded: %w", journalErr)
			}
		}
		if cleanupErr == nil && !reservationReleased && !cancellationOwnedExternally {
			cleanupErr = m.releaseTarget(context.WithoutCancel(ctx), reservation)
		}
		if cleanupErr == nil && checkpointOperationID != "" {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), checkpointOperationID, "confirmed", handle, target, reservation.lease, cleanupDisposition, cleanupMessage); journalErr != nil {
				m.log.Warn("checkpoint cleanup confirmation marker deferred after exact release", "workload_id", id, "error", journalErr)
			}
		}
		if cleanupErr == nil && cleanupDisposition == "failure" && !m.isCancelling(id) {
			if current, getErr := m.store.GetWorkload(context.WithoutCancel(ctx), id); getErr == nil && !isTerminalWorkloadStatus(current.Status) {
				m.fail(context.WithoutCancel(ctx), current, cleanupMessage)
			}
		}
		if cleanupErr != nil {
			if cleanupDisposition == "" && !m.isCancelling(id) {
				cleanupDisposition = "failure"
			}
			if cleanupMessage == "" {
				cleanupMessage = "backend cleanup failed; accelerator remains fenced: " + cleanupErr.Error()
			}
			cleanupAdapter := adapter
			cleanupHandle := handle
			if backendStopConfirmed {
				cleanupAdapter = nil
				cleanupHandle = nil
			}
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, cleanupAdapter, target, cleanupHandle, cleanupDisposition, cleanupMessage)
			m.log.Error("workload execution cleanup failed", "workload_id", id, "error", cleanupErr)
		}
		m.mu.Lock()
		delete(m.cancels, id)
		m.mu.Unlock()
		m.signal()
	}()
	w, err := m.store.GetWorkload(ctx, id)
	if err != nil {
		return
	}
	m.mu.RLock()
	adapter = m.adapters[w.Request.Adapter]
	m.mu.RUnlock()
	if adapter == nil {
		return
	}
	planID := ""
	if w.Plan != nil {
		planID = w.Plan.ID
	}
	// Requirements may perform a runtime/API read. Keep all refresh locks out of
	// that call so a signed node refresh can complete while admission is waiting.
	requirements, requirementsErr := adapter.Requirements(ctx, w.Request)
	if requirementsErr != nil {
		m.failAfterReservation(ctx, w, reservation, "runtime requirements changed before execution: "+requirementsErr.Error())
		return
	}
	// Validate against the latest generation, then release the fence before any
	// GPU profile or backend command. The post-command validation below is the
	// transition fence for a refresh that arrives during Start/Resume.
	currentTarget, validationErr := m.validateExecutionFacts(ctx, target, reservation.targetGeneration, requirements, id)
	if validationErr != nil {
		m.requeueAfterPreDispatchDrift(ctx, w, reservation, validationErr.Error())
		return
	}
	target = currentTarget
	runCtx, stopRun, leaseErrors := m.startLeaseKeeper(ctx, lease)
	defer stopRun()
	activeKey := fmt.Sprintf("gpu-power:active:%s:%s:%d", id, lease.AcceleratorID, lease.FencingToken)
	if err := m.setGPUPerformanceProfile(runCtx, lease.AcceleratorID, "active", activeKey); err != nil {
		m.failAfterReservation(ctx, w, reservation, "GPU active performance transition failed: "+err.Error())
		return
	}
	// The GPU profile command is an external wait. Revalidate immediately
	// before Resume/Start so a target removed or refreshed during that command
	// cannot cold-start through a stale admission snapshot.
	currentTarget, validationErr = m.validateExecutionFacts(ctx, target, reservation.targetGeneration, requirements, id)
	if validationErr != nil {
		m.requeueAfterPreDispatchDrift(ctx, w, reservation, validationErr.Error())
		return
	}
	target = currentTarget
	if target.Adapter == "comfy" && builtInComfyHTTPAdapter(adapter) {
		latestProof, schemaErr := m.ComfySchema(runCtx, target, reservation.targetGeneration, w.Request)
		if schemaErr != nil || !comfySchemaProofMatches(reservation.comfySchemaProof, latestProof) {
			m.failAfterReservation(ctx, w, reservation, "Comfy workflow schema changed before backend start")
			return
		}
	}
	resumingCheckpoint := strings.TrimSpace(w.CheckpointRef) != ""
	var resumeCleanup resumeProtocolCleanupResult
	if resumingCheckpoint {
		if _, journalErr := m.prepareResumeCleanupJournal(context.WithoutCancel(ctx), w, target, reservation, w.CheckpointRef); journalErr != nil {
			m.failAfterReservation(ctx, w, reservation, "checkpoint cleanup journal unavailable before resume: "+journalErr.Error())
			return
		}
		if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), reservation.checkpointOperationID, "pending", nil, target, reservation.lease, "failure", "resumed backend cleanup pending"); journalErr != nil {
			m.failAfterReservation(ctx, w, reservation, "checkpoint cleanup custody could not be armed before resume: "+journalErr.Error())
			return
		}
	}
	if w.CheckpointRef != "" {
		if aware, ok := adapter.(LeaseAwareCheckpointAdapter); ok && w.Plan != nil {
			contextLimit := w.Plan.TargetContextLimit
			if contextLimit <= 0 {
				contextLimit = target.ContextLimit
			}
			command := CheckpointCommand{ID: "restore:" + w.Request.ID + ":" + w.CheckpointRef, IdempotencyKey: "restore:" + w.Request.ID + ":" + w.CheckpointRef, OwnerID: w.Request.OwnerID, WorkloadID: w.Request.ID, WorkloadRevision: w.Revision, Generation: reservation.targetGeneration, RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: w.Plan.ModelFingerprint, ProfileFingerprint: w.Plan.ProfileDigest, ContextLimit: contextLimit, Fence: uint64(lease.FencingToken)}
			resumeLease := SlotLease{TargetID: target.ID, AcceleratorID: lease.AcceleratorID, SlotID: -1, OwnerID: w.Request.OwnerID, WorkloadID: w.Request.ID, Generation: reservation.targetGeneration, Fence: uint64(lease.FencingToken), RuntimeIdentity: command.RuntimeIdentity, ModelFingerprint: command.ModelFingerprint, ProfileFingerprint: command.ProfileFingerprint, ContextLimit: contextLimit}
			handle, err, resumeCleanup = resumeWithLeaseWatchingProtocol(runCtx, aware, w.Request, w.Plan, w.CheckpointRef, target, resumeLease, command)
			if resumeCleanup.confirmed {
				backendStopConfirmed = true
				m.confirmReservationBackendStopped(reservation)
				cleanupDisposition = "failure"
				cleanupMessage = "resumed backend protocol failed after signed cancellation"
				if resumeCleanup.err != nil {
					cleanupMessage += ": " + resumeCleanup.err.Error()
				}
			}
		} else {
			// Non-LLM compatibility adapters retain their established restore
			// contract. HTTPAdapter implements the branch above.
			handle, err = adapter.Resume(runCtx, w.Request, w.Plan, w.CheckpointRef, target)
		}
	} else {
		if async, ok := adapter.(AsyncStartAdapter); ok {
			handle, err = async.StartAsync(runCtx, w.Request, w.Plan, target)
			if errors.Is(err, ErrUnsupported) {
				handle, err = adapter.Start(runCtx, w.Request, w.Plan, target)
			}
		} else {
			handle, err = adapter.Start(runCtx, w.Request, w.Plan, target)
		}
	}
	if handle != nil {
		m.rememberReservationBackend(reservation, adapter, target, handle)
		if resumingCheckpoint {
			if _, journalErr := m.recordCheckpointCleanupState(context.WithoutCancel(ctx), reservation.checkpointOperationID, "owned", handle, target, reservation.lease, "", ""); journalErr != nil {
				backendStopUnconfirmed = true
				cleanupDisposition = "failure"
				cleanupMessage = "resumed backend handle could not be durably recorded: " + journalErr.Error()
				m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
				return
			}
		}
	}
	if err == nil && resumingCheckpoint && handle == nil {
		err = fmt.Errorf("checkpoint ResumeWithLease returned no handle; backend stop is unconfirmed")
		backendStopUnconfirmed = true
		cleanupDisposition = "failure"
		cleanupMessage = err.Error()
		m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, nil, cleanupDisposition, cleanupMessage)
		return
	}
	if err != nil {
		if resumeCleanup.confirmed {
			// ResumeWithLease was interrupted after its live stream reported a
			// protocol failure. The watcher completed the signed cancel, so the
			// defer may release the controller fence without a second adapter call.
			return
		}
		if m.isCancelling(id) {
			return
		}
		if handle == nil && resumingCheckpoint {
			backendStopUnconfirmed = true
			cleanupDisposition = "failure"
			cleanupMessage = "checkpoint ResumeWithLease failed without a handle; backend stop is unconfirmed: " + err.Error()
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, nil, cleanupDisposition, cleanupMessage)
			return
		}
		if handle != nil {
			if stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target); stopErr != nil {
				cleanupDisposition = "failure"
				cleanupMessage = "backend start/resume failed and stop is unconfirmed: " + stopErr.Error()
				m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
				return
			}
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
		}
		if runCtx.Err() != nil {
			return
		} else if leaseErr := takeLeaseError(leaseErrors); leaseErr != nil {
			m.failAfterReservation(ctx, w, reservation, "accelerator lease lost: "+leaseErr.Error())
		} else if m.retryProviderFailureAfterReservation(ctx, w, target, reservation, err) {
			return
		} else {
			m.failAfterReservation(ctx, w, reservation, err.Error())
		}
		return
	}
	// Never publish a runnable execution after a refresh invalidated the target
	// or removed its model while the backend command was in flight.
	currentTarget, validationErr = m.validateExecutionFacts(ctx, target, reservation.targetGeneration, requirements, id)
	if validationErr != nil {
		if m.isCancelling(id) {
			return
		}
		cancelErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
		message := validationErr.Error()
		if cancelErr != nil {
			message = "refreshed target projection invalidated execution; " + message + "; signed backend cancellation failed: " + cancelErr.Error()
			cleanupDisposition = "failure"
			cleanupMessage = message
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
			return
		}
		backendStopConfirmed = true
		m.confirmReservationBackendStopped(reservation)
		m.failAfterReservation(ctx, w, reservation, message)
		return
	}
	target = currentTarget
	current, currentErr := m.store.GetWorkload(ctx, id)
	if currentErr != nil || current.Status != domain.WorkloadRunning || current.Plan == nil || current.Plan.ID != planID {
		if m.isCancelling(id) {
			return
		}
		if stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target); stopErr != nil {
			cleanupDisposition = "failure"
			cleanupMessage = "execution projection was refreshed before publication; backend stop is unconfirmed: " + stopErr.Error()
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
			return
		}
		backendStopConfirmed = true
		m.confirmReservationBackendStopped(reservation)
		cleanupDisposition = "failure"
		cleanupMessage = "execution projection was refreshed before publication"
		return
	}
	w = current
	w.Execution = handle
	w.CheckpointRef = ""
	w.UpdatedAt = time.Now().UTC()
	if persisted, persistErr := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadRunning), ""); persistErr != nil {
		if m.isCancelling(id) {
			return
		}
		if stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target); stopErr != nil {
			cleanupDisposition = "failure"
			cleanupMessage = "backend execution handle publication failed; backend stop is unconfirmed: " + stopErr.Error()
			m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
			return
		}
		backendStopConfirmed = true
		m.confirmReservationBackendStopped(reservation)
		cleanupDisposition = "failure"
		cleanupMessage = "backend execution handle publication failed: " + persistErr.Error()
		m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, nil, target, nil, cleanupDisposition, cleanupMessage)
		return
	} else {
		w = persisted
	}
	m.syncPromptMapping(ctx, w)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		obs, err := adapter.Observe(runCtx, w.Request, w.Plan, handle, target)
		if err != nil {
			if m.isCancelling(id) {
				// Cancellation owns the physical lease until Adapter.Cancel has
				// confirmed the backend stopped. Transient observe failures during
				// an interrupt must not let this goroutine release it early.
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					continue
				}
			}
			if runCtx.Err() != nil {
				return
			}
			if m.isCancelling(id) {
				return
			}
			if stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target); stopErr != nil {
				cleanupDisposition = "failure"
				cleanupMessage = "backend observation failed and stop is unconfirmed: " + stopErr.Error()
				m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
				return
			}
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
			if !m.retryProviderFailureAfterReservation(ctx, w, target, reservation, err) {
				m.failAfterReservation(ctx, w, reservation, err.Error())
			}
			return
		}
		if obs.Status == domain.WorkloadSucceeded || obs.Status == domain.WorkloadFailed || obs.Status == domain.WorkloadCancelled {
			// A terminal observation is already a bounded backend-stop
			// confirmation. Record it before reading the durable projection so a
			// concurrent projection change cannot send an already-complete
			// ordinary backend through deferred cancellation.
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
		}
		current, currentErr := m.store.GetWorkload(ctx, id)
		if currentErr != nil || current.Status != domain.WorkloadRunning || current.Plan == nil || current.Plan.ID != planID {
			return
		}
		w = current
		if m.isCancelling(id) {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				continue
			}
		}
		if reservation.shared {
			obs = m.withAcceleratorTelemetry(ctx, target.AcceleratorID, obs)
		}
		if reason := sharingViolation(reservation, obs); reason != "" {
			if m.isCancelling(id) {
				return
			}
			if yieldErr := adapter.Yield(ctx, handle, target); yieldErr != nil {
				if m.isCancelling(id) {
					return
				}
				stopErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, adapter, handle, target)
				if stopErr != nil {
					cleanupDisposition = "failure"
					cleanupMessage = fmt.Sprintf("adaptive sharing rollback: %s; yield failed: %v; backend stop is unconfirmed: %v", reason, yieldErr, stopErr)
					m.retainReservationForBackendCleanup(context.WithoutCancel(ctx), id, reservation, adapter, target, handle, cleanupDisposition, cleanupMessage)
					return
				}
			}
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
			m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.sharing_rollback", "error", map[string]any{"reason": reason, "observed_vram_mb": obs.VRAMUsedMB, "observed_slowdown": obs.Slowdown, "temperature_c": obs.TemperatureC})
			m.recordSharingSample(ctx, w, target, reservation, obs, "rolled_back")
			m.failAfterReservation(ctx, w, reservation, "adaptive sharing rollback: "+reason)
			return
		}
		terminalObservation := obs.Status == domain.WorkloadSucceeded || obs.Status == domain.WorkloadFailed || obs.Status == domain.WorkloadCancelled
		if !terminalObservation {
			previousProgress := w.Progress
			w.Progress = obs.Progress
			if obs.ProgressStage != "" {
				w.ProgressStage = obs.ProgressStage
			}
			if obs.ProgressNode != "" {
				w.ProgressNode = obs.ProgressNode
			}
			if obs.ProgressCurrent != 0 {
				w.ProgressCurrent = obs.ProgressCurrent
			}
			if obs.ProgressTotal != 0 {
				w.ProgressTotal = obs.ProgressTotal
			}
			w.UpdatedAt = time.Now().UTC()
			if persisted, persistErr := m.replaceWorkloadCAS(ctx, w, workloadStatuses(domain.WorkloadRunning), ""); persistErr != nil {
				if errors.Is(persistErr, store.ErrWorkloadConflict) {
					if refreshed, refreshErr := m.store.GetWorkload(ctx, id); refreshErr == nil {
						w = refreshed
						continue
					}
				}
				return
			} else {
				w = persisted
			}
			if obs.Progress != previousProgress {
				m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.progress", "info", map[string]any{"progress": obs.Progress, "stage": obs.ProgressStage, "node": obs.ProgressNode, "current": obs.ProgressCurrent, "total": obs.ProgressTotal, "backend_prompt_id": handle.ExternalID})
			}
		}
		if obs.Status == domain.WorkloadSucceeded {
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
			output, refs, err := adapter.CollectOutputs(runCtx, w.Request, w.Plan, handle, target)
			if err != nil {
				if !m.retryProviderFailureAfterReservation(ctx, w, target, reservation, err) {
					m.failAfterReservation(ctx, w, reservation, err.Error())
				}
				return
			}
			output, refs, err = m.materializeCreatorOutputs(runCtx, w, target, output, refs)
			if err != nil {
				m.failAfterReservation(ctx, w, reservation, "persist output artifact: "+err.Error())
				return
			}
			if err := m.store.RenewAcceleratorLease(runCtx, leaseID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); err != nil {
				return
			}
			latest, err := m.store.GetWorkload(ctx, id)
			if err != nil || latest.Status != domain.WorkloadRunning || latest.Plan == nil || latest.Plan.ID != planID {
				return
			}
			now := time.Now().UTC()
			if reservation.shared && obs.Slowdown <= 0 {
				obs.Slowdown = m.completedSlowdown(latest, target, handle, now)
			}
			latest.Status = domain.WorkloadSucceeded
			latest.Progress = 1
			// Observe may enrich the in-memory handle with backend timing and
			// token counters. Persist that final handle so TPS/TTFT remain
			// available to the dashboard after polling or a controller restart.
			latest.Execution = handle
			latest.InlineOutput = output
			latest.OutputRefs = refs
			latest.UpdatedAt = now
			latest.FinishedAt = &now
			m.recordProviderSuccess(target)
			m.recordSchedulingSample(ctx, latest, target, reservation, obs, "succeeded")
			m.markModelUsed(ctx, latest, target)
			if releaseErr := m.releaseBeforeTerminal(ctx, latest, reservation, "success", ""); releaseErr != nil {
				return
			}
			persisted, persistErr := m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadRunning), "")
			if persistErr != nil {
				return
			}
			latest = persisted
			m.syncPromptMapping(ctx, latest)
			m.settleWorkloadBudget(ctx, latest)
			m.audit(ctx, latest.Request.OwnerID, id, "workload.succeeded", "info", nil)
			if latest.Request.Notifications.OnFinish {
				m.enqueueNotification(ctx, latest, "workload.succeeded")
			}
			return
		}
		if obs.Status == domain.WorkloadFailed {
			backendStopConfirmed = true
			m.confirmReservationBackendStopped(reservation)
			m.failAfterReservation(ctx, w, reservation, obs.Error)
			return
		}
		select {
		case <-runCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

// completedSlowdown derives a real-run slowdown ratio when a backend cannot
// expose live throughput while it is executing. It intentionally only uses a
// previously measured standalone duration for the exact bounded request (or,
// conservatively, the runtime class) and never invents a live measurement.
func (m *Manager) completedSlowdown(workload *domain.Workload, target Target, handle *domain.ExecutionHandle, finishedAt time.Time) float64 {
	if workload == nil {
		return 0
	}
	m.learningMu.RLock()
	profile := m.interferenceProfiles[standaloneRequestProfileKey(target, workload.Request)]
	if profile == nil || profile.P95DurationMS <= 0 {
		profile = m.interferenceProfiles[standaloneProfileKey(target)]
	}
	var baselineMS int64
	if profile != nil && profile.Samples > 0 {
		baselineMS = profile.P95DurationMS
	}
	m.learningMu.RUnlock()
	if baselineMS <= 0 {
		return 0
	}

	measuredMS := float64(0)
	if handle != nil && handle.Performance != nil {
		measuredMS = handle.Performance.DurationMS
	}
	if measuredMS <= 0 {
		startedAt := time.Time{}
		if handle != nil {
			startedAt = handle.StartedAt
		}
		if startedAt.IsZero() && workload.StartedAt != nil {
			startedAt = *workload.StartedAt
		}
		if !startedAt.IsZero() {
			measuredMS = float64(finishedAt.Sub(startedAt).Milliseconds())
		}
	}
	if measuredMS <= 0 {
		return 0
	}
	ratio := measuredMS / float64(baselineMS)
	if ratio < 1 {
		return 1
	}
	return ratio
}

func (m *Manager) withAcceleratorTelemetry(ctx context.Context, acceleratorID string, observation Observation) Observation {
	if m.nodes == nil || acceleratorID == "" {
		return observation
	}
	nodes, err := m.nodes.ListNodes(ctx)
	if err != nil {
		return observation
	}
	for _, node := range nodes {
		for _, accelerator := range node.Accelerators {
			if accelerator.ID != acceleratorID {
				continue
			}
			observation.VRAMUsedMB = accelerator.VRAMUsedMB
			observation.TemperatureC = accelerator.TemperatureC
			return observation
		}
	}
	return observation
}

func (m *Manager) syncPromptMapping(ctx context.Context, workload *domain.Workload) {
	if workload == nil || workload.Request.Plane != domain.PlaneComfy || workload.Request.ItemID == "" {
		return
	}
	mapping := &domain.PromptMapping{PublicPromptID: workload.Request.ItemID, WorkloadID: workload.Request.ID}
	if workload.Plan != nil {
		mapping.TargetID = workload.Plan.TargetID
	}
	if workload.Execution != nil {
		mapping.BackendPromptID = workload.Execution.ExternalID
	}
	_ = m.store.SavePromptMapping(ctx, mapping)
}

func sharingViolation(reservation *targetReservation, observation Observation) string {
	if reservation == nil || !reservation.shared {
		return ""
	}
	if observation.VRAMUsedMB > 0 && reservation.capacityVRAMMB > 0 && observation.VRAMUsedMB+reservation.reserveVRAMMB > reservation.capacityVRAMMB {
		return "VRAM reserve threshold violated"
	}
	if observation.Slowdown > 0 && reservation.maxSlowdown > 0 && observation.Slowdown > reservation.maxSlowdown {
		return "slowdown threshold violated"
	}
	if observation.TemperatureC >= 90 {
		return "thermal threshold violated"
	}
	return ""
}

func (m *Manager) recordSchedulingSample(ctx context.Context, workload *domain.Workload, target Target, reservation *targetReservation, observation Observation, outcome string) {
	if reservation == nil {
		return
	}
	if reservation.shared {
		m.recordSharingSample(ctx, workload, target, reservation, observation, outcome)
		return
	}
	m.placementMu.Lock()
	placement, found := m.activePlacements[reservation.workloadID]
	m.placementMu.Unlock()
	if !found || placement.sharedObserved {
		return
	}
	m.recordStandaloneSample(ctx, workload, target, observation, outcome)
}

func (m *Manager) recordStandaloneSample(ctx context.Context, workload *domain.Workload, target Target, observation Observation, outcome string) {
	if workload == nil || workload.Plan == nil || target.AcceleratorID == "" || target.Cloud {
		return
	}
	observedVRAM := int64(0)
	if target.StandaloneVRAMVerified && target.StandaloneVRAMMB > 0 {
		observedVRAM = target.StandaloneVRAMMB
	} else {
		observedVRAM = observation.VRAMUsedMB
	}
	if observedVRAM <= 0 && m.nodes != nil {
		if nodes, err := m.nodes.ListNodes(ctx); err == nil {
			for _, node := range nodes {
				for _, accelerator := range node.Accelerators {
					if accelerator.ID == target.AcceleratorID && accelerator.VRAMUsedMB > observedVRAM {
						observedVRAM = accelerator.VRAMUsedMB
					}
				}
			}
		}
	}
	if observedVRAM <= 0 {
		observedVRAM = target.StandaloneVRAMMB
	}
	duration := workloadDuration(workload)
	predicted, _ := json.Marshal(map[string]any{"configured_vram_mb": target.StandaloneVRAMMB, "context_tokens": workload.Request.Bounds.ContextTokens, "max_output": workload.Request.Bounds.MaxOutput, "frames": workload.Request.Bounds.Frames, "width": workload.Request.Bounds.Width, "height": workload.Request.Bounds.Height, "steps": workload.Request.Bounds.Steps})
	observed, _ := json.Marshal(map[string]any{"vram_mb": observedVRAM, "duration_ms": duration.Milliseconds(), "temperature_c": observation.TemperatureC})
	fingerprintInput := "standalone|" + target.CapabilityVersion + "|" + target.ModelFingerprint + "|" + workload.Plan.PlanHash
	fingerprintHash := sha256.Sum256([]byte(fingerprintInput))
	_, _ = m.store.SaveSchedulerLearningSample(ctx, &domain.SchedulerLearningSample{AcceleratorID: target.AcceleratorID, RuntimeVersion: target.CapabilityVersion, WorkloadClass: targetWorkloadClass(target), Fingerprint: hex.EncodeToString(fingerprintHash[:]), Predicted: predicted, Observed: observed, Outcome: "standalone_" + outcome, CreatedAt: time.Now().UTC()})
	classes := []string{targetWorkloadClass(target)}
	profile := m.updateInterferenceProfile(ctx, standaloneProfileKey(target), target.AcceleratorID, target.CapabilityVersion, classes, observedVRAM, 1, duration, outcome)
	m.updateInterferenceProfile(ctx, standaloneRequestProfileKey(target, workload.Request), target.AcceleratorID, target.CapabilityVersion, classes, observedVRAM, 1, duration, outcome)
	if !target.StandaloneVRAMVerified && profile != nil && profile.Confidence >= .5 && profile.P95VRAMMB > 0 {
		releaseProfileTicket := m.lockRuntimeProfileTransitionForTarget(target.ID)
		m.residencyAdmissionMu.Lock()
		fence := m.residencyAdmissionLock(target.ID)
		fence.Lock()
		m.mu.Lock()
		current := m.targets[target.ID]
		pendingKey := m.runtimeProfileTransitionTarget[target.ID]
		pending := pendingKey != "" && m.runtimeProfileTransitions[pendingKey] != nil && !m.runtimeProfileTransitions[pendingKey].projected
		var generationErr error
		if !pending && targetExecutionGenerationEqual(target, current) && current.StandaloneVRAMMB < profile.P95VRAMMB {
			current.StandaloneVRAMMB = profile.P95VRAMMB
			generationErr = m.replaceTargetLocked(current)
		}
		m.mu.Unlock()
		fence.Unlock()
		m.residencyAdmissionMu.Unlock()
		releaseProfileTicket()
		if generationErr != nil {
			m.log.Error("skipping learned capacity update because target generation is exhausted", "target", target.ID, "error", generationErr)
		}
	}
}

func workloadDuration(workload *domain.Workload) time.Duration {
	if workload == nil || (workload.StartedAt == nil && (workload.Execution == nil || workload.Execution.StartedAt.IsZero())) {
		return 0
	}
	var startedAt time.Time
	if workload.Execution != nil {
		startedAt = workload.Execution.StartedAt
	}
	if workload.StartedAt != nil {
		startedAt = *workload.StartedAt
	}
	end := time.Now().UTC()
	if workload.FinishedAt != nil {
		end = *workload.FinishedAt
	}
	if duration := end.Sub(startedAt); duration > 0 {
		return duration
	}
	return 0
}

func (m *Manager) recordSharingSample(ctx context.Context, workload *domain.Workload, target Target, reservation *targetReservation, observation Observation, outcome string) {
	if reservation == nil || !reservation.shared || workload == nil || workload.Plan == nil {
		return
	}
	predicted, _ := json.Marshal(map[string]any{"vram_mb": reservation.predictedVRAMMB, "reserve_mb": reservation.reserveVRAMMB, "max_slowdown": reservation.maxSlowdown, "guarded_exploration": reservation.exploration})
	observed, _ := json.Marshal(map[string]any{"vram_mb": observation.VRAMUsedMB, "slowdown": observation.Slowdown, "temperature_c": observation.TemperatureC})
	fingerprintInput := target.CapabilityVersion + "|" + target.ModelFingerprint + "|" + workload.Plan.PlanHash
	fingerprintHash := sha256.Sum256([]byte(fingerprintInput))
	_, _ = m.store.SaveSchedulerLearningSample(ctx, &domain.SchedulerLearningSample{AcceleratorID: reservation.lease.AcceleratorID, RuntimeVersion: target.CapabilityVersion, WorkloadClass: targetWorkloadClass(target), Fingerprint: hex.EncodeToString(fingerprintHash[:]), Predicted: predicted, Observed: observed, Outcome: outcome, CreatedAt: time.Now().UTC()})

	observedVRAM := observation.VRAMUsedMB
	if observedVRAM <= 0 {
		observedVRAM = reservation.predictedVRAMMB
	}
	m.updateInterferenceProfile(ctx, reservation.profileKey, reservation.lease.AcceleratorID, reservation.runtimeVersion, reservation.workloadClasses, observedVRAM, observation.Slowdown, workloadDuration(workload), outcome)
	m.updateInterferenceProfile(ctx, reservation.exactProfileKey, reservation.lease.AcceleratorID, reservation.runtimeVersion, reservation.workloadClasses, observedVRAM, observation.Slowdown, workloadDuration(workload), outcome)
}

// updateInterferenceProfile maintains a conservative online envelope while
// preserving every raw sample for later calibrated/offline p95 estimation.
func (m *Manager) updateInterferenceProfile(ctx context.Context, profileKey, acceleratorID, runtimeVersion string, classes []string, observedVRAM int64, observedSlowdown float64, duration time.Duration, outcome string) *domain.InterferenceProfile {
	if profileKey == "" {
		return nil
	}
	for attempt := 0; attempt < 4; attempt++ {
		m.learningMu.RLock()
		profile := cloneInterferenceProfile(m.interferenceProfiles[profileKey])
		m.learningMu.RUnlock()
		if profile == nil {
			profile = &domain.InterferenceProfile{Key: profileKey, AcceleratorID: acceleratorID, RuntimeVersion: runtimeVersion, WorkloadClasses: append([]string(nil), classes...)}
		}
		profile.Samples++
		profile.Version++
		if outcome == "succeeded" {
			profile.Successes++
		} else {
			profile.Rollbacks++
		}
		if observedVRAM > profile.P95VRAMMB {
			profile.P95VRAMMB = observedVRAM
		}
		if observedSlowdown <= 0 {
			observedSlowdown = 1
		}
		if observedSlowdown > profile.PredictedSlowdown {
			profile.PredictedSlowdown = observedSlowdown
		}
		if duration.Milliseconds() > profile.P95DurationMS {
			profile.P95DurationMS = duration.Milliseconds()
		}
		profile.Confidence = math.Min(.95, float64(profile.Samples)/float64(profile.Samples+3))
		profile.UpdatedAt = time.Now().UTC()
		stored, err := m.store.UpsertInterferenceProfile(ctx, profile)
		if err != nil {
			if errors.Is(err, store.ErrInterferenceProfileConflict) {
				continue
			}
			m.log.Warn("persist scheduler interference profile", "profile", profileKey, "error", err)
			return nil
		}
		m.learningMu.Lock()
		current := m.interferenceProfiles[profileKey]
		if current == nil || current.Version <= stored.Version {
			m.interferenceProfiles[profileKey] = cloneInterferenceProfile(stored)
			m.learningMu.Unlock()
			return cloneInterferenceProfile(stored)
		}
		m.learningMu.Unlock()
	}
	m.log.Warn("scheduler interference profile update lost concurrent version race", "profile", profileKey)
	return nil
}

func cloneInterferenceProfile(profile *domain.InterferenceProfile) *domain.InterferenceProfile {
	if profile == nil {
		return nil
	}
	cloned := *profile
	cloned.WorkloadClasses = append([]string(nil), profile.WorkloadClasses...)
	return &cloned
}

func (m *Manager) fail(ctx context.Context, w *domain.Workload, message string) {
	if m.isCancelling(w.Request.ID) {
		return
	}
	latest, err := m.mutateWorkloadCAS(ctx, w.Request.ID, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadRunning, domain.WorkloadPendingApproval), "", func(candidate *domain.Workload) error {
		if candidate.CancellationOwner != "" || m.isCancelling(w.Request.ID) {
			return store.ErrWorkloadConflict
		}
		now := time.Now().UTC()
		candidate.Status = domain.WorkloadFailed
		candidate.Error = message
		candidate.UpdatedAt = now
		candidate.FinishedAt = &now
		return nil
	})
	if err != nil {
		return
	}
	m.settleWorkloadBudget(ctx, latest)
	m.audit(ctx, latest.Request.OwnerID, latest.Request.ID, "workload.failed", "error", map[string]string{"error": message})
	if latest.Request.Notifications.OnFinish {
		m.enqueueNotification(ctx, latest, "workload.failed")
	}
}

// failAfterReservation enforces the terminal visibility ordering: physical
// placement/lease cleanup completes (or records its durable cleanup residue)
// before the workload CAS can publish a terminal status.
func (m *Manager) failAfterReservation(ctx context.Context, w *domain.Workload, reservation *targetReservation, message string) {
	if releaseErr := m.releaseBeforeTerminal(ctx, w, reservation, "failure", message); releaseErr != nil {
		return
	}
	m.fail(ctx, w, message)
}

// requeueAfterPreDispatchDrift handles a target refresh that lands between
// admission and the first backend command. Nothing was dispatched, so the
// workload returns to the queue for fresh placement instead of failing; the
// reservation is released through the same confirmed-intent path as provider
// fallback, and repeated drift is bounded by the execution attempt cap.
func (m *Manager) requeueAfterPreDispatchDrift(ctx context.Context, w *domain.Workload, reservation *targetReservation, message string) {
	if strings.TrimSpace(w.CheckpointRef) != "" || reservation.checkpointOperationID != "" {
		// Checkpoint resumes own a durable restore protocol with its own
		// recovery; keep their established fail-and-reconcile semantics.
		m.failAfterReservation(ctx, w, reservation, message)
		return
	}
	intent, prepareErr := m.prepareTerminalLeaseIntent(ctx, w, reservation, "failure", message)
	if prepareErr != nil {
		return
	}
	if releaseErr := m.releaseTargetWithIntent(ctx, reservation, intent); releaseErr != nil {
		return
	}
	intent.ReleaseConfirmed = true
	if _, phaseErr := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, intent); phaseErr != nil {
		scheduleLeaseCleanupRetry(intent, phaseErr)
		recordCtx, recordCancel := leaseCleanupContext(ctx)
		_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, intent)
		recordCancel()
		return
	}
	deleteCtx, deleteCancel := leaseCleanupContext(ctx)
	_ = m.deleteLeaseCleanupIntent(deleteCtx, intent)
	deleteCancel()
	latest, err := m.store.GetWorkload(ctx, w.Request.ID)
	if err == nil && latest.Status != domain.WorkloadCancelled && latest.ExecutionAttempts < 4 {
		latest.Status = domain.WorkloadQueued
		latest.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "target changed before dispatch; re-placing", Confidence: .8, Alternatives: []string{message}}
		latest.Plan = nil
		latest.Execution = nil
		latest.Error = message
		latest.UpdatedAt = time.Now().UTC()
		latest.FinishedAt = nil
		if _, casErr := m.replaceWorkloadCAS(ctx, latest, workloadStatuses(domain.WorkloadRunning, domain.WorkloadWaiting, domain.WorkloadQueued), ""); casErr == nil {
			if releaseErr := m.releaseBudgetClaimAfterWorkloadCAS(ctx, latest.Request.ID, latest.BudgetReservationToken, latest.BudgetReservationAttempt); releaseErr != nil {
				m.log.Warn("pre-dispatch requeue paused until budget cleanup succeeds", "workload_id", latest.Request.ID, "error", releaseErr)
			}
			m.audit(ctx, latest.Request.OwnerID, latest.Request.ID, "workload.requeued_before_dispatch", "info", map[string]any{"attempt": latest.ExecutionAttempts, "reason": message})
			m.signal()
			return
		}
	}
	m.fail(ctx, w, message)
}

func (m *Manager) retryProviderFailureAfterReservation(ctx context.Context, w *domain.Workload, target Target, reservation *targetReservation, failure error) bool {
	// A provider failure owns a typed failure continuation before its first
	// release attempt. If release cannot be confirmed, leave that exact intent
	// pending; retry/recovery will publish failure only after the fenced lease is
	// actually gone. This path must never create an ordinary second row.
	intent, prepareErr := m.prepareTerminalLeaseIntent(ctx, w, reservation, "failure", failure.Error())
	if prepareErr != nil {
		return true
	}
	releaseErr := m.releaseTargetWithIntent(ctx, reservation, intent)
	if releaseErr != nil {
		return true
	}
	intent.ReleaseConfirmed = true
	if _, phaseErr := m.store.RecordAcceleratorLeaseCleanupIntent(ctx, intent); phaseErr != nil {
		scheduleLeaseCleanupRetry(intent, phaseErr)
		recordCtx, recordCancel := leaseCleanupContext(ctx)
		_, _ = m.store.RecordAcceleratorLeaseCleanupIntent(recordCtx, intent)
		recordCancel()
		return true
	}
	// Physical release is complete. Remove the continuation before requeueing;
	// fallback is now safe and cannot be mistaken for an unconfirmed failure.
	deleteCtx, deleteCancel := leaseCleanupContext(ctx)
	_ = m.deleteLeaseCleanupIntent(deleteCtx, intent)
	deleteCancel()
	if m.retryProviderFailure(ctx, w, target, failure) {
		return true
	}
	// No eligible fallback remained; the already-confirmed release permits a
	// direct terminal failure without another release attempt.
	m.fail(ctx, w, failure.Error())
	return true
}

func (m *Manager) Cancel(ctx context.Context, id, ownerID string, admin bool) error {
	w, err := m.store.GetWorkload(ctx, id)
	if err != nil {
		return err
	}
	if !admin && w.Request.OwnerID != ownerID {
		return store.ErrNotFound
	}
	cancellationOwner := ownerID
	if cancellationOwner == "" {
		cancellationOwner = "admin"
	}
	// Cancellation is idempotent and must never rewrite an immutable terminal
	// result. This also prevents duplicate terminal notifications and budget
	// settlement when clients retry a cancellation request.
	switch w.Status {
	case domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadRejected, domain.WorkloadCancelled:
		if w.CancellationOwner != "" && w.CancellationOwner != cancellationOwner {
			return store.ErrWorkloadConflict
		}
		return nil
	}
	if w.CancellationOwner == cancellationOwner {
		m.mu.RLock()
		_, reservationExists := m.reservations[id]
		m.mu.RUnlock()
		if !reservationExists {
			// A prior caller already owns cancellation and there is no physical
			// reservation left for this retry to finish.
			return nil
		}
	}
	// Claim cancellation durably before calling the backend. This is the
	// ownership boundary that prevents an observer from publishing progress or
	// failure while the stop operation is in flight.
	claimedRow, err := m.mutateWorkloadCAS(ctx, id, workloadStatuses(domain.WorkloadQueued, domain.WorkloadWaiting, domain.WorkloadRunning, domain.WorkloadPendingApproval), "", func(current *domain.Workload) error {
		current.CancellationOwner = cancellationOwner
		current.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrWorkloadConflict) {
			latest, getErr := m.store.GetWorkload(ctx, id)
			if getErr == nil && (latest.Status == domain.WorkloadCancelled || latest.Status == domain.WorkloadSucceeded || latest.Status == domain.WorkloadFailed) {
				return nil
			}
			if getErr == nil && latest.CancellationOwner == cancellationOwner &&
				(latest.Status == domain.WorkloadQueued || latest.Status == domain.WorkloadWaiting || latest.Status == domain.WorkloadRunning || latest.Status == domain.WorkloadPendingApproval) {
				// The same caller retried while its durable stop claim is still
				// in flight. Continue the physical stop/release path so a prior
				// cleanup-intent persistence failure can make progress.
				claimedRow = latest
			} else {
				return err
			}
		} else {
			return err
		}
	}
	w = claimedRow
	m.mu.Lock()
	cancel := m.cancels[id]
	adapter := m.adapters[w.Request.Adapter]
	target := m.targets[w.Decision.TargetID]
	reservation := m.reservations[id]
	m.cancelling[id] = struct{}{}
	pending := m.pendingStreams[id]
	if pending != nil {
		delete(m.pendingStreams, id)
		delete(m.cancels, id)
		m.stopPendingStreamTimer(pending)
	}
	m.mu.Unlock()
	physicalHandle := w.Execution
	physicalAdapter := adapter
	physicalTarget := target
	if reservation != nil {
		m.placementMu.Lock()
		if physicalHandle == nil {
			physicalHandle = reservation.backendHandle
		}
		if physicalAdapter == nil {
			physicalAdapter = reservation.backendAdapter
		}
		if physicalTarget.ID == "" {
			physicalTarget = reservation.backendTarget
		}
		m.placementMu.Unlock()
	}
	if physicalHandle == nil && reservation != nil {
		// A cancellation request may race the short interval between backend
		// return and handle publication. Wait only on the manager-owned bounded
		// cleanup context; releasing a still-pending reservation would violate
		// the physical stop fence.
		waitCtx, waitCancel := leaseCleanupContext(ctx)
		for {
			m.placementMu.Lock()
			physicalHandle = reservation.backendHandle
			if physicalAdapter == nil {
				physicalAdapter = reservation.backendAdapter
			}
			if physicalTarget.ID == "" {
				physicalTarget = reservation.backendTarget
			}
			pendingStop := reservation.backendStopPending && !reservation.backendStopConfirmed && !reservation.released
			m.placementMu.Unlock()
			if physicalHandle != nil || !pendingStop {
				break
			}
			select {
			case <-waitCtx.Done():
				waitCancel()
				return fmt.Errorf("cancel backend execution: handle publication did not complete; accelerator release remains fenced")
			case <-time.After(10 * time.Millisecond):
			}
		}
		waitCancel()
	}
	if physicalHandle != nil {
		if cancelErr := m.cancelReservationBackend(context.WithoutCancel(ctx), reservation, physicalAdapter, physicalHandle, physicalTarget); cancelErr != nil {
			// Release ownership only if the same durable revision is still ours;
			// a concurrent terminal result remains authoritative.
			_, releaseOwnerErr := m.mutateWorkloadCAS(ctx, id, workloadStatuses(w.Status), cancellationOwner, func(released *domain.Workload) error {
				released.CancellationOwner = ""
				released.UpdatedAt = time.Now().UTC()
				return nil
			})
			m.mu.Lock()
			delete(m.cancelling, id)
			m.mu.Unlock()
			if releaseOwnerErr != nil {
				return fmt.Errorf("cancel backend execution: %w; cancellation claim cleanup failed: %v", cancelErr, releaseOwnerErr)
			}
			return fmt.Errorf("cancel backend execution: %w", cancelErr)
		}
		if reservation != nil {
			// The durable cancellation call is the physical-stop confirmation
			// for the in-memory reservation as well. Release cannot cross the
			// reservation guard until this mark is visible.
			m.confirmReservationBackendStopped(reservation)
		}
	}
	// Do not publish cancellation until the physical reservation/lease has
	// been released or a durable terminal continuation has been recorded.
	if reservation != nil {
		if releaseErr := m.releaseBeforeTerminal(context.WithoutCancel(ctx), w, reservation, "cancel", "workload cancellation"); releaseErr != nil {
			return releaseErr
		}
	}
	if pending != nil && (reservation == nil || pending.reservation != reservation) {
		if releaseErr := m.releaseBeforeTerminal(context.WithoutCancel(ctx), w, pending.reservation, "cancel", "workload cancellation"); releaseErr != nil {
			return releaseErr
		}
	}
	if current, getErr := m.store.GetWorkload(ctx, id); getErr == nil && isTerminalWorkloadStatus(current.Status) {
		if cancel != nil {
			cancel()
		}
		m.mu.Lock()
		delete(m.cancelling, id)
		m.mu.Unlock()
		return nil
	}
	now := time.Now().UTC()
	cancelled, err := m.mutateWorkloadCAS(ctx, id, workloadStatuses(w.Status), cancellationOwner, func(current *domain.Workload) error {
		current.Status = domain.WorkloadCancelled
		current.CancellationOwner = ""
		current.UpdatedAt = now
		current.FinishedAt = &now
		return nil
	})
	if err == nil {
		w = cancelled
		m.settleWorkloadBudget(ctx, w)
		m.audit(ctx, w.Request.OwnerID, id, "workload.cancelled", "warn", nil)
		if w.Request.Notifications.OnFinish {
			m.enqueueNotification(ctx, w, "workload.cancelled")
		}
	}
	// Persist the terminal state before cancelling the execution context so a
	// racing observer cannot rewrite the workload as failed. For Comfy, the
	// adapter has also confirmed the backend prompt stopped before this releases
	// the physical accelerator reservation.
	if cancel != nil {
		cancel()
	}
	m.mu.Lock()
	delete(m.cancelling, id)
	m.mu.Unlock()
	if pending != nil {
		m.signal()
	}
	return err
}

func (m *Manager) isCancelling(id string) bool {
	m.mu.RLock()
	_, found := m.cancelling[id]
	m.mu.RUnlock()
	return found
}

func (m *Manager) Wait(ctx context.Context, id string) (*domain.Workload, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		w, err := m.store.GetWorkload(ctx, id)
		if err != nil {
			return nil, err
		}
		switch w.Status {
		case domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadCancelled, domain.WorkloadRejected:
			return w, nil
		}
		select {
		case <-ctx.Done():
			return w, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *Manager) Subscribe() (<-chan domain.AuditEvent, func()) {
	ch := make(chan domain.AuditEvent, 32)
	m.mu.Lock()
	m.subscribers[ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		if _, ok := m.subscribers[ch]; ok {
			delete(m.subscribers, ch)
			close(ch)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) audit(ctx context.Context, ownerID, workloadID, eventType, severity string, payload any) {
	m.auditActor(ctx, "", ownerID, workloadID, eventType, severity, payload)
}

func (m *Manager) auditActor(ctx context.Context, actorID, ownerID, workloadID, eventType, severity string, payload any) {
	b, _ := json.Marshal(payload)
	event := domain.AuditEvent{ID: newID("evt"), Timestamp: time.Now().UTC(), ActorID: actorID, OwnerID: ownerID, WorkloadID: workloadID, Type: eventType, Severity: severity, Payload: b}
	_ = m.store.AppendAuditEvent(ctx, &event)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for ch := range m.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}
