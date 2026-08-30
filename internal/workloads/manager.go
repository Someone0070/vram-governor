package workloads

import (
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

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

type Manager struct {
	log      *slog.Logger
	store    store.WorkloadStore
	nodes    store.NodeStore
	leaseTTL time.Duration

	mu             sync.RWMutex
	adapters       map[string]Adapter
	targets        map[string]Target
	cancels        map[string]context.CancelFunc
	cancelling     map[string]struct{}
	pendingStreams map[string]*pendingStream
	subscribers    map[chan domain.AuditEvent]struct{}
	kick           chan struct{}

	placementMu          sync.Mutex
	targetActive         map[string]int
	targetLeases         map[string]*domain.AcceleratorLease
	activePlacements     map[string]activePlacement
	reconcileMu          sync.Mutex
	residency            ResidencyOptions
	lastResidencySweep   time.Time
	recoveryTransitions  map[string]struct{}
	notificationMu       sync.Mutex
	notifications        NotificationOptions
	notificationNets     []*net.IPNet
	providerMu           sync.Mutex
	providerCircuits     map[string]providerCircuit
	learningMu           sync.RWMutex
	interferenceProfiles map[string]*domain.InterferenceProfile
	nodeControl          NodeControl
}

// NodeControl executes a fixed, signed operation on the node that owns a
// target. It is injected by the controller API so the scheduler never needs
// network access to a node-local runtime endpoint.
type NodeControl func(context.Context, string, string, map[string]any, string) (map[string]any, error)

type providerCircuit struct {
	Failures  int
	OpenUntil time.Time
}

func NewManager(log *slog.Logger, backing store.WorkloadStore, leaseTTL time.Duration) *Manager {
	if leaseTTL <= 0 {
		leaseTTL = 30 * time.Second
	}
	return &Manager{
		log: log, store: backing, leaseTTL: leaseTTL,
		adapters: make(map[string]Adapter), targets: make(map[string]Target),
		cancels: make(map[string]context.CancelFunc), cancelling: make(map[string]struct{}), pendingStreams: make(map[string]*pendingStream), subscribers: make(map[chan domain.AuditEvent]struct{}),
		kick: make(chan struct{}, 1), targetActive: make(map[string]int), targetLeases: make(map[string]*domain.AcceleratorLease), activePlacements: make(map[string]activePlacement),
		residency: DefaultResidencyOptions(), recoveryTransitions: make(map[string]struct{}),
		notifications:        DefaultNotificationOptions(),
		providerCircuits:     make(map[string]providerCircuit),
		interferenceProfiles: make(map[string]*domain.InterferenceProfile),
	}
}

func (m *Manager) RegisterAdapter(adapter Adapter) {
	m.mu.Lock()
	m.adapters[adapter.Name()] = adapter
	m.mu.Unlock()
}

func (m *Manager) SetNodeStore(nodes store.NodeStore) { m.nodes = nodes }

func (m *Manager) SetNodeControl(control NodeControl) {
	m.mu.Lock()
	m.nodeControl = control
	m.mu.Unlock()
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
	if target.Slots <= 0 {
		target.Slots = 1
	}
	if target.ResidencyPolicy == "" {
		target.ResidencyPolicy = domain.ResidencyAuto
	} else if target.ResidencyPolicy != domain.ResidencyAuto && target.ResidencyPolicy != domain.ResidencyPinned && target.ResidencyPolicy != domain.ResidencyManual && target.ResidencyPolicy != domain.ResidencyOff {
		m.log.Warn("invalid target residency policy; protecting target as manual", "target", target.ID, "policy", target.ResidencyPolicy)
		target.ResidencyPolicy = domain.ResidencyManual
	}
	if len(target.ResidentModels) == 0 && !target.SupportsModelLifecycle {
		target.ResidentModels = append([]string(nil), target.Models...)
	}
	m.mu.Lock()
	m.targets[target.ID] = target
	m.mu.Unlock()
	// Node-discovered targets arrive after Manager.Start, so apply their
	// durable override at registration time as well as during startup recovery.
	if policies, err := m.store.ListTargetPolicyOverrides(context.Background()); err == nil {
		for _, policy := range policies {
			if policy.TargetID == target.ID {
				if _, applyErr := m.UpdateTargetPolicy(*policy); applyErr != nil {
					m.log.Warn("ignoring invalid stored target policy", "target", policy.TargetID, "error", applyErr)
				}
				break
			}
		}
	}
	m.observeTargetResidency(context.Background(), target)
	m.recoverResidencyTransitionsForTarget(context.Background(), target.ID)
	m.signal()
}

func (m *Manager) Targets() []Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Target, 0, len(m.targets))
	for _, target := range m.targets {
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
	if policy.MaxSlowdown < 0 || policy.MaxSlowdown > 10 || (policy.SharingEnabled && policy.MaxSlowdown < 1) {
		return Target{}, fmt.Errorf("max_slowdown must be between 1 and 10 when sharing is enabled")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	target, found := m.targets[policy.TargetID]
	if !found {
		return Target{}, fmt.Errorf("unknown target %q", policy.TargetID)
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
	m.targets[target.ID] = target
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
	if err := m.ApplyStoredTargetPolicies(ctx); err != nil {
		m.log.Warn("target policy override recovery unavailable", "error", err)
	}
	if profiles, err := m.store.ListInterferenceProfiles(ctx); err == nil {
		loadedProfiles := make(map[string]*domain.InterferenceProfile, len(profiles))
		m.learningMu.Lock()
		for _, profile := range profiles {
			m.interferenceProfiles[profile.Key] = profile
			loadedProfiles[profile.Key] = profile
		}
		m.learningMu.Unlock()
		m.mu.Lock()
		for id, target := range m.targets {
			profile := loadedProfiles[standaloneProfileKey(target)]
			if profile != nil && profile.Confidence >= .5 && profile.P95VRAMMB > target.StandaloneVRAMMB {
				target.StandaloneVRAMMB = profile.P95VRAMMB
				m.targets[id] = target
			}
		}
		m.mu.Unlock()
	}
	if plans, err := m.store.ListTransitionPlans(ctx, "", 1000); err == nil {
		for _, plan := range plans {
			if plan.Status != domain.TransitionPlanPlanned && plan.Status != domain.TransitionPlanExecuting {
				continue
			}
			now := time.Now().UTC()
			plan.Status = domain.TransitionPlanFailed
			plan.Error = "controller restarted during transition; action was not replayed"
			plan.UpdatedAt = now
			plan.FinishedAt = &now
			_, _ = m.store.UpdateTransitionPlan(ctx, plan)
		}
	}
	m.initializeResidencyRecovery(ctx)
	// Recovered running work is never blindly duplicated. Recoverable work is
	// re-admitted; non-recoverable work is failed for operator inspection.
	if rows, err := m.store.ListWorkloads(ctx); err == nil {
		for _, w := range rows {
			if w.Status != domain.WorkloadRunning {
				continue
			}
			if w.Request.Recoverable {
				_ = m.store.ReleaseBudget(ctx, w.Request.ID)
				w.Status = domain.WorkloadQueued
				w.Execution = nil
				w.StartedAt = nil
				w.Error = "controller restarted; re-admitting recoverable workload"
			} else {
				w.Status = domain.WorkloadFailed
				w.Error = "controller restarted during non-recoverable execution"
				now := time.Now().UTC()
				w.FinishedAt = &now
			}
			w.UpdatedAt = time.Now().UTC()
			_, _ = m.store.UpdateWorkload(ctx, w)
			if w.Status == domain.WorkloadFailed {
				m.settleWorkloadBudget(ctx, w)
			}
			if w.Status == domain.WorkloadFailed && w.Request.Notifications.OnFinish {
				m.enqueueNotification(ctx, w, "workload.failed")
			}
		}
	}
	m.recoverRegisteredResidencyTransitions(ctx)
	go m.loop(ctx)
	go m.notificationLoop(ctx)
}

func (m *Manager) loop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.reconcile(ctx)
			m.reconcileResidency(ctx)
		case <-m.kick:
			m.reconcile(ctx)
		}
	}
}

func (m *Manager) signal() {
	select {
	case m.kick <- struct{}{}:
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
	if err := adapter.Validate(ctx, req); err != nil {
		return nil, false, err
	}
	w := &domain.Workload{Request: req, Status: domain.WorkloadQueued, CreatedAt: now, UpdatedAt: now}
	stored, created, err := m.store.CreateWorkload(ctx, w)
	if err != nil {
		return nil, false, err
	}
	if created {
		m.audit(ctx, req.OwnerID, req.ID, "workload.submitted", "info", nil)
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
				stored, err = m.store.UpdateWorkload(ctx, stored)
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
	if _, err := m.store.UpdateWorkload(ctx, workload); err != nil {
		return nil, err
	}
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
	updated, err := m.store.UpdateWorkload(ctx, workload)
	if err != nil {
		return nil, err
	}
	m.auditActor(ctx, actorID, workload.Request.OwnerID, workloadID, "workload.reprioritized", "info", map[string]int{"priority": priority})
	m.signal()
	return updated, nil
}

func (m *Manager) reconcile(ctx context.Context) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	m.reconcileLocked(ctx)
}

func (m *Manager) tryReconcileWithin(ctx context.Context, wait time.Duration) bool {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.reconcileMu.TryLock() {
			defer m.reconcileMu.Unlock()
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
		if w.Status != domain.WorkloadQueued && w.Status != domain.WorkloadWaiting {
			continue
		}
		m.tryAdmit(ctx, w)
	}
}

func (m *Manager) reconcileRunningNodeLoss(ctx context.Context, rows []*domain.Workload) {
	if m.nodes == nil {
		return
	}
	for _, workload := range rows {
		if workload.Status != domain.WorkloadRunning || workload.Plan == nil || workload.Plan.AcceleratorID == "" {
			continue
		}
		target := m.targetByID(workload.Plan.TargetID)
		if target.ID == "" || target.Cloud || m.targetNodeAvailable(ctx, target) {
			continue
		}
		m.mu.RLock()
		cancel := m.cancels[workload.Request.ID]
		m.mu.RUnlock()
		now := time.Now().UTC()
		if workload.Request.Recoverable {
			_ = m.store.ReleaseBudget(ctx, workload.Request.ID)
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
			workload.Error = "assigned node lost during non-recoverable execution"
			workload.FinishedAt = &now
			m.settleWorkloadBudget(ctx, workload)
			m.audit(ctx, workload.Request.OwnerID, workload.Request.ID, "workload.node_lost_failed", "error", map[string]string{"target_id": target.ID})
		}
		workload.UpdatedAt = now
		_, _ = m.store.UpdateWorkload(ctx, workload)
		if cancel != nil {
			cancel()
		}
	}
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
	if w.Request.Deadline != nil && !w.Request.Deadline.After(time.Now()) {
		w.Status = domain.WorkloadRejected
		w.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "deadline has expired", Confidence: 1}
		now := time.Now().UTC()
		w.UpdatedAt, w.FinishedAt = now, &now
		_, _ = m.store.UpdateWorkload(ctx, w)
		m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.deadline_missed", "warn", w.Decision)
		return
	}
	m.mu.RLock()
	adapter := m.adapters[w.Request.Adapter]
	targets := make([]Target, 0, len(m.targets))
	for _, t := range m.targets {
		targets = append(targets, t)
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
		if targetEstimates[targets[i].ID].score != targetEstimates[targets[j].ID].score {
			return targetEstimates[targets[i].ID].score < targetEstimates[targets[j].ID].score
		}
		return targets[i].ID < targets[j].ID
	})

	var blockers []string
	var waitingEstimate *targetEstimate
	stickyTargetRegistered := boundTarget == ""
	for _, target := range targets {
		if target.ID == boundTarget {
			stickyTargetRegistered = true
		}
		if target.Adapter != w.Request.Adapter {
			continue
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
		needsModelLoad := req.Model != "" && !containsString(target.ResidentModels, req.Model)
		if needsModelLoad && !target.SupportsModelLifecycle {
			blockers = append(blockers, target.ID+": model is not resident and target cannot load it")
			continue
		}
		if needsModelLoad {
			residency, residencyErr := m.store.GetModelResidency(ctx, target.ID, req.Model)
			if residencyErr == nil && (residency.Policy == domain.ResidencyManual || residency.Policy == domain.ResidencyOff) {
				blockers = append(blockers, target.ID+": model loading requires an operator transition")
				continue
			}
		}
		if req.ContextTokens > 0 && target.ContextLimit > 0 && req.ContextTokens > target.ContextLimit {
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
			blockers = append(blockers, target.ID+": custom node unavailable")
			continue
		}
		if len(w.Request.Transformations) > 0 {
			preview, previewErr := m.prepareExecutionPlan(adapter, w, target)
			if previewErr != nil {
				blockers = append(blockers, target.ID+": transformation preview rejected")
				continue
			}
			if _, approvalErr := m.store.GetTransformationApproval(ctx, w.Request.ID, preview.PlanHash); approvalErr != nil {
				w.Status = domain.WorkloadPendingApproval
				w.Plan = preview
				w.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "transformation approval required for exact plan hash", Confidence: .9, TargetID: target.ID, AcceleratorID: target.AcceleratorID, ContextLimit: target.ContextLimit, TargetSlots: target.Slots, CapacitySource: target.CapacitySource, CapacityVerified: target.CapacityVerified}
				w.UpdatedAt = time.Now().UTC()
				_, _ = m.store.UpdateWorkload(ctx, w)
				m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.transformation_pending", "info", map[string]any{"plan_hash": preview.PlanHash, "transformations": preview.Transformations})
				return
			}
		}
		estimatedCost := estimateTargetCost(target, req)
		budgetReserved := false
		if target.Cloud && w.Request.BudgetLimitCents > 0 {
			if estimatedCost <= 0 {
				blockers = append(blockers, target.ID+": cloud price is not configured")
				continue
			}
			_, allowed, reserveErr := m.store.ReserveBudget(ctx, w.Request.PrincipalID, w.Request.ID, estimatedCost, w.Request.BudgetLimitCents)
			if reserveErr != nil {
				blockers = append(blockers, target.ID+": budget reservation failed")
				continue
			}
			if !allowed {
				blockers = append(blockers, target.ID+": principal cloud budget exhausted")
				continue
			}
			budgetReserved = true
		}
		reservation, acquired, reason, err := m.reserveTarget(ctx, target, w, req)
		if err != nil {
			if budgetReserved {
				_ = m.store.ReleaseBudget(ctx, w.Request.ID)
			}
			blockers = append(blockers, target.ID+": lease error")
			continue
		}
		if !acquired {
			if budgetReserved {
				_ = m.store.ReleaseBudget(ctx, w.Request.ID)
			}
			waitingEstimate = preferEstimate(waitingEstimate, targetEstimates[target.ID])
			if m.tryPreempt(ctx, w, target) {
				blockers = append(blockers, target.ID+": victim transition in progress")
				continue
			}
			blockers = append(blockers, target.ID+": "+reason)
			continue
		}
		residencyTransitionIDs, reclaimErr := m.reclaimForeignTargets(ctx, target, w, reservation.lease)
		if reclaimErr != nil {
			m.releaseTarget(context.Background(), reservation)
			if budgetReserved {
				_ = m.store.ReleaseBudget(ctx, w.Request.ID)
			}
			blockers = append(blockers, target.ID+": accelerator reclaim failed: "+reclaimErr.Error())
			continue
		}
		if needsModelLoad {
			if m.targetActiveCount(target.ID) > 1 {
				m.releaseTarget(context.Background(), reservation)
				if budgetReserved {
					_ = m.store.ReleaseBudget(ctx, w.Request.ID)
				}
				blockers = append(blockers, target.ID+": runtime must drain before changing resident model")
				continue
			}
			transitionIDs, loadErr := m.ensureModelResident(ctx, target, req.Model, w, reservation.lease)
			if loadErr != nil {
				m.releaseTarget(context.Background(), reservation)
				if budgetReserved {
					_ = m.store.ReleaseBudget(ctx, w.Request.ID)
				}
				blockers = append(blockers, target.ID+": model load failed: "+loadErr.Error())
				continue
			}
			residencyTransitionIDs = append(residencyTransitionIDs, transitionIDs...)
			target = m.targetByID(target.ID)
		}
		plan, err := m.prepareExecutionPlan(adapter, w, target)
		if err != nil {
			m.releaseTarget(context.Background(), reservation)
			if budgetReserved {
				_ = m.store.ReleaseBudget(ctx, w.Request.ID)
			}
			blockers = append(blockers, target.ID+": plan rejected")
			continue
		}
		plan.EstimatedCostCents = estimatedCost
		plan.InputCentsPerMTok = target.InputCentsPerMTok
		plan.OutputCentsPerMTok = target.OutputCentsPerMTok
		plan.Provider = target.Provider
		plan.Model = req.Model
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
		if _, err := m.store.UpdateWorkload(ctx, w); err != nil {
			m.releaseTarget(context.Background(), reservation)
			if budgetReserved {
				_ = m.store.ReleaseBudget(ctx, w.Request.ID)
			}
			return
		}
		m.syncPromptMapping(ctx, w)
		m.audit(ctx, w.Request.OwnerID, w.Request.ID, "workload.admitted", "info", w.Decision)
		if w.Request.Notifications.OnStart {
			m.enqueueNotification(ctx, w, "workload.started")
		}
		execCtx, cancel := context.WithCancel(context.Background())
		m.mu.Lock()
		m.cancels[w.Request.ID] = cancel
		if w.Request.InteractiveStream {
			pending := &pendingStream{ctx: execCtx, cancel: cancel, target: target, reservation: reservation}
			m.pendingStreams[w.Request.ID] = pending
			pending.timer = time.AfterFunc(5*time.Second, func() { m.expirePendingStream(w.Request.ID, pending) })
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		go m.execute(execCtx, w.Request.ID, target, reservation)
		return
	}
	if !stickyTargetRegistered {
		blockers = append(blockers, boundTarget+": sticky target is no longer registered")
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
	_, _ = m.store.UpdateWorkload(ctx, w)
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

func (m *Manager) settleWorkloadBudget(ctx context.Context, workload *domain.Workload) {
	if workload == nil || workload.Plan == nil || workload.Plan.EstimatedCostCents <= 0 {
		return
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
	workload.ActualCostCents = actual
	_, _ = m.store.UpdateWorkload(ctx, workload)
	_, _ = m.store.SettleBudget(ctx, workload.Request.ID, actual)
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
	if !target.Cloud {
		return time.Time{}, false
	}
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
	_ = m.store.ReleaseBudget(ctx, latest.Request.ID)
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
	if _, err := m.store.UpdateWorkload(ctx, latest); err != nil {
		return false
	}
	m.audit(ctx, latest.Request.OwnerID, latest.Request.ID, "workload.provider_fallback", "warn", map[string]any{"failed_target": target.ID, "retry_after": retryAt, "attempt": latest.ExecutionAttempts, "error": failure.Error()})
	m.signal()
	return true
}

func (m *Manager) availableSlots(target Target) int {
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
	targetID        string
	workloadID      string
	lease           *domain.AcceleratorLease
	shared          bool
	predictedVRAMMB int64
	reserveVRAMMB   int64
	capacityVRAMMB  int64
	maxSlowdown     float64
	exploration     bool
	profileKey      string
	workloadClasses []string
	runtimeVersion  string
	exactProfileKey string
}

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
}

type pendingStream struct {
	ctx         context.Context
	cancel      context.CancelFunc
	target      Target
	reservation *targetReservation
	timer       *time.Timer
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
	m.releaseTarget(context.Background(), pending.reservation)
	if w, err := m.store.GetWorkload(context.Background(), id); err == nil {
		m.fail(context.Background(), w, "stream client did not attach within 5 seconds")
	}
	m.signal()
}

func (m *Manager) reserveTarget(ctx context.Context, target Target, workload *domain.Workload, requirements Requirements) (*targetReservation, bool, string, error) {
	m.placementMu.Lock()
	defer m.placementMu.Unlock()
	slots := target.Slots
	if slots <= 0 {
		slots = 1
	}
	if m.targetActive[target.ID] >= slots {
		return nil, false, "all execution slots are busy", nil
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
	}
	if requirements.EstimatedVRAMMB > 0 {
		placement.vramMB = requirements.EstimatedVRAMMB
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
	if lease := m.targetLeases[target.ID]; lease != nil {
		m.targetActive[target.ID]++
		m.activePlacements[workloadID] = placement
		return &targetReservation{targetID: target.ID, workloadID: workloadID, lease: lease}, true, "", nil
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
		return &targetReservation{targetID: target.ID, workloadID: workloadID, lease: sharedLease, shared: true, predictedVRAMMB: predictedVRAM, reserveVRAMMB: reserve, capacityVRAMMB: capacity, maxSlowdown: slowdown, exploration: exploration, profileKey: profileKey, exactProfileKey: exactProfileKey, workloadClasses: classes, runtimeVersion: runtimeVersions}, true, "", nil
	}
	lease, acquired, err := m.store.AcquireAcceleratorLease(ctx, leaseID, workloadID, m.leaseTTL)
	if err != nil {
		return nil, false, "", err
	}
	if !acquired {
		return nil, false, "accelerator is reserved by " + lease.WorkloadID, nil
	}
	m.targetActive[target.ID] = 1
	m.targetLeases[target.ID] = lease
	m.activePlacements[workloadID] = placement
	return &targetReservation{targetID: target.ID, workloadID: workloadID, lease: lease}, true, "", nil
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
		if err != nil || candidate.Status != domain.WorkloadRunning || candidate.Execution == nil {
			continue
		}
		if candidate.Request.Disruption == domain.DisruptionLocked || candidate.Request.Disruption == domain.DisruptionSlowdown {
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
		checkpoint, err := adapter.Checkpoint(ctx, victim.Execution, victimTarget)
		if err != nil || checkpoint == "" {
			if err == nil {
				err = fmt.Errorf("adapter returned an empty checkpoint reference")
			}
			return failTransition(err)
		}
		victim.CheckpointRef = checkpoint
		resultAction = "checkpointed"
	case domain.DisruptionCancelable:
		if err := adapter.Cancel(ctx, victim.Execution, victimTarget); err != nil && !errors.Is(err, ErrUnsupported) {
			return failTransition(err)
		}
		resultAction = "cancelled"
	}
	if cancel != nil {
		cancel()
	}
	now = time.Now().UTC()
	victim.PreemptionCount++
	victim.Execution = nil
	victim.TransitionPlanIDs = append(victim.TransitionPlanIDs, transition.ID)
	if resultAction == "cancelled" {
		victim.Status = domain.WorkloadCancelled
		victim.FinishedAt = &now
		m.settleWorkloadBudget(ctx, victim)
	} else {
		victim.Status = domain.WorkloadQueued
		victim.StartedAt = nil
		victim.Plan = nil
		victim.Decision = domain.AdmissionDecision{Admitted: false, Blocker: "preempted by higher-priority workload; awaiting resume", Confidence: .8}
		victim.FinishedAt = nil
	}
	victim.Error = "preempted: " + resultAction
	victim.UpdatedAt = now
	if _, err := m.store.UpdateWorkload(ctx, victim); err != nil {
		return failTransition(err)
	}
	newcomer.PreemptionsInitiated++
	newcomer.TransitionPlanIDs = append(newcomer.TransitionPlanIDs, transition.ID)
	newcomer.UpdatedAt = now
	if _, err := m.store.UpdateWorkload(ctx, newcomer); err != nil {
		return failTransition(err)
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

func (m *Manager) releaseTarget(ctx context.Context, reservation *targetReservation) {
	if reservation == nil || reservation.lease == nil {
		return
	}
	m.placementMu.Lock()
	delete(m.activePlacements, reservation.workloadID)
	active := m.targetActive[reservation.targetID]
	if active > 1 {
		m.targetActive[reservation.targetID] = active - 1
	} else {
		delete(m.targetActive, reservation.targetID)
		delete(m.targetLeases, reservation.targetID)
	}
	stillActive := false
	for _, placement := range m.activePlacements {
		if placement.acceleratorID == reservation.lease.AcceleratorID {
			stillActive = true
			break
		}
	}
	m.placementMu.Unlock()
	if stillActive {
		return
	}
	_ = m.store.ReleaseAcceleratorLease(ctx, reservation.lease.AcceleratorID, reservation.lease.WorkloadID, reservation.lease.FencingToken)
}

func hashPlan(req domain.WorkloadRequest, plan *domain.ExecutionPlan) string {
	b, _ := json.Marshal(struct {
		Payload                            json.RawMessage       `json:"payload"`
		Bounds                             domain.WorkloadBounds `json:"bounds"`
		AdapterVersion, Target, Capability string
		ModelFingerprint, CapacitySource   string
		TargetContextLimit, TargetSlots    int
		CapacityVerified                   bool
		Transformations                    []string
		Material                           json.RawMessage
		Provider, Model                    string
	}{req.Payload, req.Bounds, plan.AdapterVersion, plan.TargetID, plan.CapabilityVersion, plan.ModelFingerprint, plan.CapacitySource, plan.TargetContextLimit, plan.TargetSlots, plan.CapacityVerified, plan.Transformations, plan.Material, plan.Provider, plan.Model})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (m *Manager) prepareExecutionPlan(adapter Adapter, workload *domain.Workload, target Target) (*domain.ExecutionPlan, error) {
	plan, err := adapter.Plan(context.Background(), workload.Request, target)
	if err != nil {
		return nil, err
	}
	plan.ID = newID("plan")
	plan.WorkloadID = workload.Request.ID
	plan.Adapter = adapter.Name()
	plan.AdapterVersion = adapter.Version()
	plan.TargetID = target.ID
	plan.AcceleratorID = target.AcceleratorID
	plan.CapabilityVersion = target.CapabilityVersion
	plan.TargetContextLimit = target.ContextLimit
	plan.TargetSlots = target.Slots
	plan.ModelFingerprint = target.ModelFingerprint
	plan.CapacitySource = target.CapacitySource
	plan.CapacityVerified = target.CapacityVerified
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

// RunStream claims an admitted interactive stream and synchronously proxies
// it through emit. The caller's context owns cancellation, while the manager
// continues to own the accelerator reservation and fencing lease.
func (m *Manager) RunStream(ctx context.Context, id string, emit func([]byte) error) (*domain.Workload, error) {
	if emit == nil {
		return nil, fmt.Errorf("stream emitter is required")
	}
	m.mu.Lock()
	pending := m.pendingStreams[id]
	if pending != nil {
		delete(m.pendingStreams, id)
		pending.timer.Stop()
	}
	m.mu.Unlock()
	if pending == nil {
		return nil, fmt.Errorf("workload %s has no attachable stream", id)
	}
	stopClientCancellation := context.AfterFunc(ctx, pending.cancel)
	defer stopClientCancellation()
	defer pending.cancel()
	return m.executeStream(pending.ctx, id, pending.target, pending.reservation, emit)
}

func (m *Manager) executeStream(ctx context.Context, id string, target Target, reservation *targetReservation, emit func([]byte) error) (*domain.Workload, error) {
	defer func() {
		m.releaseTarget(context.Background(), reservation)
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
	adapter := m.adapters[w.Request.Adapter]
	m.mu.RUnlock()
	streaming, ok := adapter.(StreamingAdapter)
	if !ok {
		m.fail(context.Background(), w, "adapter does not support interactive streaming")
		return m.store.GetWorkload(context.Background(), id)
	}
	runCtx, stopRun, leaseErrors := m.startLeaseKeeper(ctx, reservation.lease)
	defer stopRun()
	var clientWriteErr error
	handle, err := streaming.StartStream(runCtx, w.Request, w.Plan, target, func(chunk []byte) error {
		clientWriteErr = emit(chunk)
		return clientWriteErr
	})
	if err != nil {
		m.recordProviderFailure(target, err)
		if leaseErr := takeLeaseError(leaseErrors); leaseErr != nil {
			m.fail(context.Background(), w, "accelerator lease lost: "+leaseErr.Error())
		} else if runCtx.Err() != nil || clientWriteErr != nil {
			m.markStreamCancelled(id, "stream client disconnected")
		} else {
			m.fail(context.Background(), w, err.Error())
		}
		latest, getErr := m.store.GetWorkload(context.Background(), id)
		if getErr != nil {
			return nil, getErr
		}
		return latest, err
	}
	if err := m.store.RenewAcceleratorLease(context.Background(), reservation.lease.AcceleratorID, reservation.lease.WorkloadID, reservation.lease.FencingToken, m.leaseTTL); err != nil {
		m.fail(context.Background(), w, "accelerator lease lost before stream completion")
		latest, _ := m.store.GetWorkload(context.Background(), id)
		return latest, err
	}
	latest, err := m.store.GetWorkload(context.Background(), id)
	if err != nil {
		return nil, err
	}
	if latest.Status != domain.WorkloadRunning || latest.Plan == nil || latest.Plan.ID != planID {
		return latest, context.Canceled
	}
	now := time.Now().UTC()
	latest.Status = domain.WorkloadSucceeded
	latest.Progress = 1
	latest.Execution = handle
	latest.InlineOutput = json.RawMessage(`{"streamed":true}`)
	latest.UpdatedAt = now
	latest.FinishedAt = &now
	if _, err := m.store.UpdateWorkload(context.Background(), latest); err != nil {
		return latest, err
	}
	m.syncPromptMapping(context.Background(), latest)
	m.settleWorkloadBudget(context.Background(), latest)
	m.recordProviderSuccess(target)
	m.recordSchedulingSample(context.Background(), latest, target, reservation, Observation{Status: domain.WorkloadSucceeded}, "succeeded")
	m.markModelUsed(context.Background(), latest, target)
	m.audit(context.Background(), latest.Request.OwnerID, id, "workload.succeeded", "info", map[string]bool{"streamed": true})
	if latest.Request.Notifications.OnFinish {
		m.enqueueNotification(context.Background(), latest, "workload.succeeded")
	}
	return latest, nil
}

func (m *Manager) markStreamCancelled(id, reason string) {
	w, err := m.store.GetWorkload(context.Background(), id)
	if err != nil || w.Status != domain.WorkloadRunning {
		return
	}
	now := time.Now().UTC()
	w.Status = domain.WorkloadCancelled
	w.Error = reason
	w.UpdatedAt = now
	w.FinishedAt = &now
	_, _ = m.store.UpdateWorkload(context.Background(), w)
	m.settleWorkloadBudget(context.Background(), w)
	m.audit(context.Background(), w.Request.OwnerID, id, "workload.cancelled", "warn", map[string]string{"reason": reason})
	if w.Request.Notifications.OnFinish {
		m.enqueueNotification(context.Background(), w, "workload.cancelled")
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
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := m.store.RenewAcceleratorLease(context.Background(), lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); err != nil {
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
	defer func() {
		m.releaseTarget(context.Background(), reservation)
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
	adapter := m.adapters[w.Request.Adapter]
	m.mu.RUnlock()
	if adapter == nil {
		return
	}
	planID := ""
	if w.Plan != nil {
		planID = w.Plan.ID
	}
	runCtx, stopRun, leaseErrors := m.startLeaseKeeper(ctx, lease)
	defer stopRun()
	var handle *domain.ExecutionHandle
	if w.CheckpointRef != "" {
		handle, err = adapter.Resume(runCtx, w.Request, w.Plan, w.CheckpointRef, target)
	} else {
		handle, err = adapter.Start(runCtx, w.Request, w.Plan, target)
	}
	if err != nil {
		if runCtx.Err() != nil {
			return
		} else if leaseErr := takeLeaseError(leaseErrors); leaseErr != nil {
			m.fail(context.Background(), w, "accelerator lease lost: "+leaseErr.Error())
		} else if m.retryProviderFailure(context.Background(), w, target, err) {
			return
		} else {
			m.fail(context.Background(), w, err.Error())
		}
		return
	}
	current, currentErr := m.store.GetWorkload(context.Background(), id)
	if currentErr != nil || current.Status != domain.WorkloadRunning || current.Plan == nil || current.Plan.ID != planID {
		_ = adapter.Cancel(context.Background(), handle, target)
		return
	}
	w = current
	w.Execution = handle
	w.CheckpointRef = ""
	w.UpdatedAt = time.Now().UTC()
	_, _ = m.store.UpdateWorkload(context.Background(), w)
	m.syncPromptMapping(context.Background(), w)

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
			if !m.retryProviderFailure(context.Background(), w, target, err) {
				m.fail(context.Background(), w, err.Error())
			}
			return
		}
		current, currentErr := m.store.GetWorkload(context.Background(), id)
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
		if reason := sharingViolation(reservation, obs); reason != "" {
			if yieldErr := adapter.Yield(context.Background(), handle, target); yieldErr != nil {
				_ = adapter.Cancel(context.Background(), handle, target)
			}
			m.audit(context.Background(), w.Request.OwnerID, w.Request.ID, "workload.sharing_rollback", "error", map[string]any{"reason": reason, "observed_vram_mb": obs.VRAMUsedMB, "observed_slowdown": obs.Slowdown, "temperature_c": obs.TemperatureC})
			m.recordSharingSample(context.Background(), w, target, reservation, obs, "rolled_back")
			m.fail(context.Background(), w, "adaptive sharing rollback: "+reason)
			return
		}
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
		_, _ = m.store.UpdateWorkload(context.Background(), w)
		if obs.Progress != previousProgress {
			m.audit(context.Background(), w.Request.OwnerID, w.Request.ID, "workload.progress", "info", map[string]any{"progress": obs.Progress, "stage": obs.ProgressStage, "node": obs.ProgressNode, "current": obs.ProgressCurrent, "total": obs.ProgressTotal, "backend_prompt_id": handle.ExternalID})
		}
		if obs.Status == domain.WorkloadSucceeded {
			output, refs, err := adapter.CollectOutputs(runCtx, w.Request, w.Plan, handle, target)
			if err != nil {
				if !m.retryProviderFailure(context.Background(), w, target, err) {
					m.fail(context.Background(), w, err.Error())
				}
				return
			}
			if err := m.store.RenewAcceleratorLease(context.Background(), leaseID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); err != nil {
				return
			}
			latest, err := m.store.GetWorkload(context.Background(), id)
			if err != nil || latest.Status != domain.WorkloadRunning || latest.Plan == nil || latest.Plan.ID != planID {
				return
			}
			now := time.Now().UTC()
			latest.Status = domain.WorkloadSucceeded
			latest.Progress = 1
			latest.InlineOutput = output
			latest.OutputRefs = refs
			latest.UpdatedAt = now
			latest.FinishedAt = &now
			_, _ = m.store.UpdateWorkload(context.Background(), latest)
			m.syncPromptMapping(context.Background(), latest)
			m.settleWorkloadBudget(context.Background(), latest)
			m.recordProviderSuccess(target)
			m.recordSchedulingSample(context.Background(), latest, target, reservation, obs, "succeeded")
			m.markModelUsed(context.Background(), latest, target)
			m.audit(context.Background(), latest.Request.OwnerID, id, "workload.succeeded", "info", nil)
			if latest.Request.Notifications.OnFinish {
				m.enqueueNotification(context.Background(), latest, "workload.succeeded")
			}
			return
		}
		if obs.Status == domain.WorkloadFailed {
			m.fail(context.Background(), w, obs.Error)
			return
		}
		select {
		case <-runCtx.Done():
			return
		case <-ticker.C:
		}
	}
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
	observedVRAM := observation.VRAMUsedMB
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
	if profile != nil && profile.Confidence >= .5 && profile.P95VRAMMB > 0 {
		m.mu.Lock()
		current := m.targets[target.ID]
		if current.CapabilityVersion == target.CapabilityVersion && current.StandaloneVRAMMB < profile.P95VRAMMB {
			current.StandaloneVRAMMB = profile.P95VRAMMB
			m.targets[target.ID] = current
		}
		m.mu.Unlock()
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
	m.learningMu.Lock()
	defer m.learningMu.Unlock()
	profile := cloneInterferenceProfile(m.interferenceProfiles[profileKey])
	if profile == nil {
		profile = &domain.InterferenceProfile{
			Key:             profileKey,
			AcceleratorID:   acceleratorID,
			RuntimeVersion:  runtimeVersion,
			WorkloadClasses: append([]string(nil), classes...),
		}
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
		m.log.Warn("persist scheduler interference profile", "profile", profileKey, "error", err)
		return nil
	}
	m.interferenceProfiles[profileKey] = stored
	return cloneInterferenceProfile(stored)
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
	latest, err := m.store.GetWorkload(ctx, w.Request.ID)
	if err != nil || latest.Status == domain.WorkloadCancelled {
		return
	}
	now := time.Now().UTC()
	latest.Status = domain.WorkloadFailed
	latest.Error = message
	latest.UpdatedAt = now
	latest.FinishedAt = &now
	_, _ = m.store.UpdateWorkload(ctx, latest)
	m.settleWorkloadBudget(ctx, latest)
	m.audit(ctx, latest.Request.OwnerID, latest.Request.ID, "workload.failed", "error", map[string]string{"error": message})
	if latest.Request.Notifications.OnFinish {
		m.enqueueNotification(ctx, latest, "workload.failed")
	}
}

func (m *Manager) Cancel(ctx context.Context, id, ownerID string, admin bool) error {
	w, err := m.store.GetWorkload(ctx, id)
	if err != nil {
		return err
	}
	if !admin && w.Request.OwnerID != ownerID {
		return store.ErrNotFound
	}
	// Cancellation is idempotent and must never rewrite an immutable terminal
	// result. This also prevents duplicate terminal notifications and budget
	// settlement when clients retry a cancellation request.
	switch w.Status {
	case domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadRejected, domain.WorkloadCancelled:
		return nil
	}
	m.mu.Lock()
	cancel := m.cancels[id]
	adapter := m.adapters[w.Request.Adapter]
	target := m.targets[w.Decision.TargetID]
	m.cancelling[id] = struct{}{}
	pending := m.pendingStreams[id]
	if pending != nil {
		delete(m.pendingStreams, id)
		delete(m.cancels, id)
		pending.timer.Stop()
	}
	m.mu.Unlock()
	if adapter != nil && w.Execution != nil {
		if cancelErr := adapter.Cancel(ctx, w.Execution, target); cancelErr != nil && !errors.Is(cancelErr, ErrUnsupported) {
			m.mu.Lock()
			delete(m.cancelling, id)
			m.mu.Unlock()
			return fmt.Errorf("cancel backend execution: %w", cancelErr)
		}
	}
	now := time.Now().UTC()
	w.Status = domain.WorkloadCancelled
	w.UpdatedAt = now
	w.FinishedAt = &now
	_, err = m.store.UpdateWorkload(ctx, w)
	if err == nil {
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
		m.releaseTarget(context.Background(), pending.reservation)
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
