package workloads

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

// ResidencyOptions controls conservative automatic unloading. Loading is
// always demand- or operator-triggered; ReuseScore only ranks what to retain.
type ResidencyOptions struct {
	Enabled                bool
	ReconcileInterval      time.Duration
	DefaultIdleUnloadAfter time.Duration
	DefaultMinResidency    time.Duration
	TransitionTimeout      time.Duration
	QuietHoursStart        string
	QuietHoursEnd          string
}

func DefaultResidencyOptions() ResidencyOptions {
	return ResidencyOptions{
		Enabled:                true,
		ReconcileInterval:      10 * time.Second,
		DefaultIdleUnloadAfter: 15 * time.Minute,
		DefaultMinResidency:    5 * time.Minute,
		TransitionTimeout:      2 * time.Minute,
	}
}

func (m *Manager) SetResidencyOptions(options ResidencyOptions) {
	defaults := DefaultResidencyOptions()
	if options.ReconcileInterval <= 0 {
		options.ReconcileInterval = defaults.ReconcileInterval
	}
	if options.DefaultIdleUnloadAfter <= 0 {
		options.DefaultIdleUnloadAfter = defaults.DefaultIdleUnloadAfter
	}
	if options.DefaultMinResidency < 0 {
		options.DefaultMinResidency = 0
	}
	if options.TransitionTimeout <= 0 {
		options.TransitionTimeout = defaults.TransitionTimeout
	}
	m.reconcileMu.Lock()
	m.residency = options
	m.lastResidencySweep = time.Time{}
	m.reconcileMu.Unlock()
}

func (m *Manager) targetActiveCount(targetID string) int {
	m.placementMu.Lock()
	defer m.placementMu.Unlock()
	return m.targetActive[targetID]
}

func (m *Manager) targetByID(targetID string) Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.targets[targetID]
}

func hasExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (m *Manager) observeTargetResidency(ctx context.Context, target Target) {
	if !target.SupportsModelLifecycle {
		return
	}
	now := time.Now().UTC()
	for _, model := range target.Models {
		if model == "" || model == "*" {
			continue
		}
		residency, err := m.store.GetModelResidency(ctx, target.ID, model)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			m.log.Warn("read model residency", "target", target.ID, "model", model, "err", err)
			continue
		}
		resident := hasExact(target.ResidentModels, model)
		if residency == nil {
			tier := domain.ResidencyColdDisk
			if resident {
				tier = domain.ResidencyHotVRAM
			}
			idle := target.IdleUnloadAfter
			if idle <= 0 {
				idle = m.residency.DefaultIdleUnloadAfter
			}
			residency = &domain.ModelResidency{
				ID: target.ID + "::" + model, TargetID: target.ID,
				AcceleratorID: target.AcceleratorID, Adapter: target.Adapter, Model: model,
				DesiredTier: tier, ObservedTier: tier, Policy: target.ResidencyPolicy,
				CapacityVerified: target.CapacityVerified, WarmRAMSupported: target.WarmRAMSupported,
				IdleUnloadAfterSec: int(idle / time.Second), UpdatedAt: now,
			}
			if resident {
				loaded := now
				residency.LastLoadedAt = &loaded
				minimum := target.MinResidency
				if minimum <= 0 {
					minimum = m.residency.DefaultMinResidency
				}
				until := now.Add(minimum)
				residency.MinResidentUntil = &until
			}
		} else {
			wasResident := residency.ObservedTier == domain.ResidencyHotVRAM
			residency.AcceleratorID = target.AcceleratorID
			residency.Adapter = target.Adapter
			residency.CapacityVerified = target.CapacityVerified
			residency.WarmRAMSupported = target.WarmRAMSupported
			residency.ObservedTier = domain.ResidencyColdDisk
			if resident {
				residency.ObservedTier = domain.ResidencyHotVRAM
				if !wasResident {
					loaded := now
					residency.LastLoadedAt = &loaded
				}
			}
			residency.UpdatedAt = now
		}
		if _, err := m.store.UpsertModelResidency(ctx, residency); err != nil {
			m.log.Warn("persist observed model residency", "target", target.ID, "model", model, "err", err)
		}
	}
}

func (m *Manager) ensureModelResident(ctx context.Context, target Target, model string, workload *domain.Workload, lease *domain.AcceleratorLease) ([]string, error) {
	if hasExact(target.ResidentModels, model) {
		return nil, nil
	}
	if !target.SupportsModelLifecycle {
		return nil, fmt.Errorf("runtime does not support model lifecycle")
	}
	lifecycle, ok := m.adapterLifecycle(target.Adapter)
	if !ok {
		return nil, fmt.Errorf("adapter %s does not implement model lifecycle", target.Adapter)
	}

	var transitionIDs []string
	var evicted []string
	maxResident := target.MaxResidentModels
	if maxResident > 0 {
		needed := len(target.ResidentModels) - maxResident + 1
		if needed > 0 {
			candidates, err := m.evictionCandidates(ctx, target, model)
			if err != nil {
				return nil, err
			}
			if len(candidates) < needed {
				return nil, fmt.Errorf("resident capacity is protected by policy or queued demand")
			}
			for i := 0; i < needed; i++ {
				victim := candidates[i]
				transition, err := m.transitionModel(ctx, lifecycle, target, victim.Model, domain.ResidencyColdDisk, "capacity_for_demand", workload.Request.OwnerID, workload.Request.ID, "demand-evict:"+workload.Request.ID+":"+target.ID+":"+victim.Model, lease)
				if err != nil {
					return transitionIDs, err
				}
				transitionIDs = append(transitionIDs, transition.ID)
				evicted = append(evicted, victim.Model)
				target = m.targetByID(target.ID)
			}
		}
	}
	transition, err := m.transitionModel(ctx, lifecycle, target, model, domain.ResidencyHotVRAM, "workload_demand", workload.Request.OwnerID, workload.Request.ID, "demand-load:"+workload.Request.ID+":"+target.ID+":"+model, lease)
	if err != nil {
		for i := len(evicted) - 1; i >= 0; i-- {
			current := m.targetByID(target.ID)
			rollback, rollbackErr := m.transitionModel(ctx, lifecycle, current, evicted[i], domain.ResidencyHotVRAM, "demand_load_rollback", workload.Request.OwnerID, workload.Request.ID, "demand-rollback:"+workload.Request.ID+":"+target.ID+":"+evicted[i], lease)
			if rollback != nil {
				transitionIDs = append(transitionIDs, rollback.ID)
			}
			if rollbackErr != nil {
				err = fmt.Errorf("%w; rollback of %s failed: %v", err, evicted[i], rollbackErr)
			}
		}
		return transitionIDs, err
	}
	transitionIDs = append(transitionIDs, transition.ID)
	return transitionIDs, nil
}

func (m *Manager) adapterLifecycle(adapterName string) (ModelLifecycleAdapter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	adapter, ok := m.adapters[adapterName]
	if !ok {
		return nil, false
	}
	lifecycle, ok := adapter.(ModelLifecycleAdapter)
	return lifecycle, ok
}

func (m *Manager) evictionCandidates(ctx context.Context, target Target, requested string) ([]*domain.ModelResidency, error) {
	rows, err := m.store.ListModelResidencies(ctx)
	if err != nil {
		return nil, err
	}
	var candidates []*domain.ModelResidency
	for _, row := range rows {
		if row.TargetID != target.ID || row.Model == requested || row.ObservedTier != domain.ResidencyHotVRAM {
			continue
		}
		if row.Policy == domain.ResidencyPinned || row.Policy == domain.ResidencyManual || row.Policy == domain.ResidencyOff {
			continue
		}
		if m.modelHasQueuedDemand(ctx, row.Model) {
			continue
		}
		candidates = append(candidates, row)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].ReuseScore != candidates[j].ReuseScore {
			return candidates[i].ReuseScore < candidates[j].ReuseScore
		}
		return residencyTime(candidates[i]).Before(residencyTime(candidates[j]))
	})
	return candidates, nil
}

func residencyTime(row *domain.ModelResidency) time.Time {
	var latest time.Time
	if row.LastUsedAt != nil && row.LastUsedAt.After(latest) {
		latest = *row.LastUsedAt
	}
	if row.LastLoadedAt != nil && row.LastLoadedAt.After(latest) {
		latest = *row.LastLoadedAt
	}
	return latest
}

func (m *Manager) modelHasQueuedDemand(ctx context.Context, model string) bool {
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		return true
	}
	for _, workload := range rows {
		if workload.Status != domain.WorkloadQueued && workload.Status != domain.WorkloadWaiting {
			continue
		}
		m.mu.RLock()
		adapter := m.adapters[workload.Request.Adapter]
		m.mu.RUnlock()
		if adapter == nil {
			continue
		}
		requirements, err := adapter.Requirements(ctx, workload.Request)
		if err == nil && requirements.Model == model {
			return true
		}
	}
	return false
}

func (m *Manager) transitionModel(ctx context.Context, lifecycle ModelLifecycleAdapter, target Target, model string, to domain.ResidencyTier, reason, actor, workloadID, idempotencyKey string, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, error) {
	if to != domain.ResidencyHotVRAM && to != domain.ResidencyColdDisk && to != domain.ResidencyWarmRAM {
		return nil, fmt.Errorf("unsupported residency tier %q", to)
	}
	if to == domain.ResidencyWarmRAM && !target.WarmRAMSupported {
		return nil, fmt.Errorf("target %s does not support warm RAM offload", target.ID)
	}
	residency, err := m.store.GetModelResidency(ctx, target.ID, model)
	if err != nil {
		return nil, err
	}
	transition := &domain.ResidencyTransition{
		ID: newID("rtr"), IdempotencyKey: idempotencyKey, TargetID: target.ID,
		AcceleratorID: target.AcceleratorID, Model: model, FromTier: residency.ObservedTier,
		ToTier: to, Reason: reason, RequestedBy: actor, WorkloadID: workloadID,
		Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC(),
	}
	transition, created, err := m.store.CreateResidencyTransition(ctx, transition)
	if err != nil {
		return nil, err
	}
	if !created {
		if transition.Status == domain.ResidencyTransitionSucceeded {
			return transition, nil
		}
		return transition, fmt.Errorf("residency transition %s is %s", transition.ID, transition.Status)
	}
	started := time.Now().UTC()
	transition.StartedAt = &started
	transition.Status = domain.ResidencyTransitionRunning
	if lease != nil {
		transition.FencingToken = lease.FencingToken
	}
	_, _ = m.store.UpdateResidencyTransition(ctx, transition)
	m.auditActor(ctx, actor, "", workloadID, "residency.transition.started", "info", transition)

	options := m.residency
	transitionCtx, cancel := context.WithTimeout(ctx, options.TransitionTimeout)
	defer cancel()
	runCtx := transitionCtx
	stopRun := func() {}
	var leaseErrors <-chan error
	if lease != nil {
		runCtx, stopRun, leaseErrors = m.startLeaseKeeper(transitionCtx, lease)
	}
	defer stopRun()
	if control, nodeID, ok := m.nodeControlForTarget(runCtx, target); ok && (to == domain.ResidencyHotVRAM || to == domain.ResidencyColdDisk) {
		command := "load_model"
		if to == domain.ResidencyColdDisk {
			command = "unload_model"
		}
		_, err = control(runCtx, nodeID, command, map[string]any{"target_id": target.ID, "model": model}, idempotencyKey)
	} else if to == domain.ResidencyHotVRAM {
		err = lifecycle.LoadModel(runCtx, target, model)
	} else if to == domain.ResidencyColdDisk {
		err = lifecycle.UnloadModel(runCtx, target, model)
	} else if warm, ok := lifecycle.(WarmRAMLifecycleAdapter); ok {
		err = warm.OffloadModelToRAM(runCtx, target, model)
	} else {
		err = fmt.Errorf("adapter does not implement warm RAM offload")
	}
	if err == nil && lease != nil {
		if leaseErr := takeLeaseError(leaseErrors); leaseErr != nil {
			err = fmt.Errorf("accelerator lease lost: %w", leaseErr)
		} else if renewErr := m.store.RenewAcceleratorLease(context.Background(), lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); renewErr != nil {
			err = fmt.Errorf("accelerator lease lost before transition completion: %w", renewErr)
		}
	}
	finished := time.Now().UTC()
	transition.FinishedAt = &finished
	if err != nil {
		transition.Status = domain.ResidencyTransitionFailed
		transition.Error = err.Error()
		residency.LastError = err.Error()
		residency.UpdatedAt = finished
		_, _ = m.store.UpsertModelResidency(context.Background(), residency)
		_, _ = m.store.UpdateResidencyTransition(context.Background(), transition)
		m.auditActor(context.Background(), actor, "", workloadID, "residency.transition.failed", "error", transition)
		return transition, err
	}

	transition.Status = domain.ResidencyTransitionSucceeded
	residency.ObservedTier = to
	residency.DesiredTier = to
	residency.LastError = ""
	residency.UpdatedAt = finished
	if to == domain.ResidencyHotVRAM {
		loaded := finished
		residency.LastLoadedAt = &loaded
		minimum := target.MinResidency
		if minimum <= 0 {
			minimum = options.DefaultMinResidency
		}
		until := finished.Add(minimum)
		residency.MinResidentUntil = &until
	} else {
		residency.MinResidentUntil = nil
	}
	if _, err := m.store.UpsertModelResidency(context.Background(), residency); err != nil {
		transition.Status = domain.ResidencyTransitionFailed
		transition.Error = "runtime changed state but residency persistence failed: " + err.Error()
		_, _ = m.store.UpdateResidencyTransition(context.Background(), transition)
		m.setTargetResident(target.ID, model, to == domain.ResidencyHotVRAM)
		m.auditActor(context.Background(), actor, "", workloadID, "residency.transition.persistence_failed", "error", transition)
		return transition, err
	}
	_, _ = m.store.UpdateResidencyTransition(context.Background(), transition)
	m.setTargetResident(target.ID, model, to == domain.ResidencyHotVRAM)
	m.auditActor(context.Background(), actor, "", workloadID, "residency.transition.succeeded", "info", transition)
	return transition, nil
}

func (m *Manager) reclaimForeignTargets(ctx context.Context, selected Target, workload *domain.Workload, lease *domain.AcceleratorLease) ([]string, error) {
	if selected.AcceleratorID == "" {
		return nil, nil
	}
	m.mu.RLock()
	targets := make([]Target, 0, len(m.targets))
	adapters := make(map[string]Adapter, len(m.adapters))
	for _, target := range m.targets {
		targets = append(targets, target)
	}
	for name, adapter := range m.adapters {
		adapters[name] = adapter
	}
	m.mu.RUnlock()

	var transitionIDs []string
	for _, foreign := range targets {
		if foreign.ID == selected.ID || foreign.AcceleratorID != selected.AcceleratorID || m.targetActiveCount(foreign.ID) > 0 {
			continue
		}
		adapter := adapters[foreign.Adapter]
		if foreign.SupportsModelLifecycle {
			lifecycle, ok := adapter.(ModelLifecycleAdapter)
			if !ok {
				return transitionIDs, fmt.Errorf("target %s advertises model lifecycle without an implementation", foreign.ID)
			}
			for _, model := range append([]string(nil), foreign.ResidentModels...) {
				residency, err := m.store.GetModelResidency(ctx, foreign.ID, model)
				if err != nil || residency.ObservedTier != domain.ResidencyHotVRAM {
					continue
				}
				if residency.Policy == domain.ResidencyPinned || residency.Policy == domain.ResidencyManual {
					return transitionIDs, fmt.Errorf("foreign resident %s on %s is protected by %s policy", model, foreign.ID, residency.Policy)
				}
				transition, err := m.transitionModel(ctx, lifecycle, foreign, model, domain.ResidencyColdDisk, "cross_adapter_reclaim", workload.Request.OwnerID, workload.Request.ID, "cross-adapter:"+workload.Request.ID+":"+foreign.ID+":"+model, lease)
				if transition != nil {
					transitionIDs = append(transitionIDs, transition.ID)
				}
				if err != nil {
					return transitionIDs, err
				}
			}
			continue
		}
		if !strings.EqualFold(foreign.Adapter, "comfy") || !foreign.SupportsAcceleratorReclaim {
			continue
		}
		reclaimer, ok := adapter.(AcceleratorReclaimer)
		if !ok {
			continue
		}
		transition, err := m.transitionRuntimeCache(ctx, reclaimer, foreign, workload, lease, "cross_adapter_reclaim")
		if transition != nil {
			transitionIDs = append(transitionIDs, transition.ID)
		}
		if err != nil {
			return transitionIDs, err
		}
	}
	return transitionIDs, nil
}

func (m *Manager) transitionRuntimeCache(ctx context.Context, reclaimer AcceleratorReclaimer, target Target, workload *domain.Workload, lease *domain.AcceleratorLease, reason string) (*domain.ResidencyTransition, error) {
	transition := &domain.ResidencyTransition{
		ID: newID("rtr"), IdempotencyKey: reason + ":" + workload.Request.ID + ":" + target.ID + ":runtime-cache",
		TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: "runtime-cache",
		FromTier: domain.ResidencyHotVRAM, ToTier: domain.ResidencyColdDisk,
		Reason: reason, RequestedBy: workload.Request.OwnerID, WorkloadID: workload.Request.ID,
		Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC(),
	}
	transition, created, err := m.store.CreateResidencyTransition(ctx, transition)
	if err != nil || !created {
		if err == nil && transition.Status != domain.ResidencyTransitionSucceeded {
			err = fmt.Errorf("runtime-cache transition %s is %s", transition.ID, transition.Status)
		}
		return transition, err
	}
	started := time.Now().UTC()
	transition.StartedAt, transition.Status = &started, domain.ResidencyTransitionRunning
	if lease != nil {
		transition.FencingToken = lease.FencingToken
	}
	_, _ = m.store.UpdateResidencyTransition(ctx, transition)
	m.auditActor(ctx, workload.Request.OwnerID, "", workload.Request.ID, "residency.transition.started", "info", transition)

	transitionCtx, cancel := context.WithTimeout(ctx, m.residency.TransitionTimeout)
	defer cancel()
	if control, nodeID, ok := m.nodeControlForTarget(transitionCtx, target); ok {
		_, err = control(transitionCtx, nodeID, "reclaim_accelerator", map[string]any{"target_id": target.ID}, transition.IdempotencyKey)
	} else {
		err = reclaimer.ReclaimAccelerator(transitionCtx, target)
	}
	finished := time.Now().UTC()
	transition.FinishedAt = &finished
	if err != nil {
		transition.Status, transition.Error = domain.ResidencyTransitionFailed, err.Error()
		_, _ = m.store.UpdateResidencyTransition(context.Background(), transition)
		m.auditActor(context.Background(), workload.Request.OwnerID, "", workload.Request.ID, "residency.transition.failed", "error", transition)
		return transition, err
	}
	transition.Status = domain.ResidencyTransitionSucceeded
	_, _ = m.store.UpdateResidencyTransition(context.Background(), transition)
	m.auditActor(context.Background(), workload.Request.OwnerID, "", workload.Request.ID, "residency.transition.succeeded", "info", transition)
	return transition, nil
}

func (m *Manager) setTargetResident(targetID, model string, resident bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	target, ok := m.targets[targetID]
	if !ok {
		return
	}
	if resident && !hasExact(target.ResidentModels, model) {
		target.ResidentModels = append(target.ResidentModels, model)
	}
	if !resident {
		filtered := target.ResidentModels[:0]
		for _, current := range target.ResidentModels {
			if current != model {
				filtered = append(filtered, current)
			}
		}
		target.ResidentModels = filtered
	}
	m.targets[targetID] = target
}

func (m *Manager) markModelUsed(ctx context.Context, workload *domain.Workload, target Target) {
	m.mu.RLock()
	adapter := m.adapters[workload.Request.Adapter]
	m.mu.RUnlock()
	if adapter == nil {
		return
	}
	requirements, err := adapter.Requirements(ctx, workload.Request)
	if err != nil || requirements.Model == "" {
		return
	}
	residency, err := m.store.GetModelResidency(ctx, target.ID, requirements.Model)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	residency.UseCount++
	residency.ReuseScore = residency.ReuseScore*.8 + .2
	residency.LastUsedAt = &now
	residency.ObservedTier = domain.ResidencyHotVRAM
	if residency.Policy == domain.ResidencyAuto {
		residency.DesiredTier = domain.ResidencyHotVRAM
	}
	minimum := target.MinResidency
	if minimum <= 0 {
		minimum = m.residency.DefaultMinResidency
	}
	until := now.Add(minimum)
	residency.MinResidentUntil = &until
	residency.UpdatedAt = now
	_, _ = m.store.UpsertModelResidency(ctx, residency)
}

func (m *Manager) reconcileResidency(ctx context.Context) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	options := m.residency
	now := time.Now().UTC()
	m.expireUnresolvedResidencyTransitions(ctx, now)
	if !options.Enabled {
		return
	}
	if !m.lastResidencySweep.IsZero() && now.Sub(m.lastResidencySweep) < options.ReconcileInterval {
		return
	}
	m.lastResidencySweep = now
	rows, err := m.store.ListModelResidencies(ctx)
	if err != nil {
		m.log.Warn("list model residencies", "err", err)
		return
	}
	quiet := withinQuietHours(time.Now(), options.QuietHoursStart, options.QuietHoursEnd)
	for _, residency := range rows {
		if residency.ObservedTier != domain.ResidencyHotVRAM || residency.Policy != domain.ResidencyAuto {
			continue
		}
		target := m.targetByID(residency.TargetID)
		if target.ID == "" || !target.Enabled || !target.SupportsModelLifecycle || m.targetActiveCount(target.ID) != 0 {
			continue
		}
		if residency.MinResidentUntil != nil && now.Before(*residency.MinResidentUntil) {
			continue
		}
		idle := target.IdleUnloadAfter
		if idle <= 0 && residency.IdleUnloadAfterSec > 0 {
			idle = time.Duration(residency.IdleUnloadAfterSec) * time.Second
		}
		if idle <= 0 {
			idle = options.DefaultIdleUnloadAfter
		}
		last := residencyTime(residency)
		if !quiet && (last.IsZero() || now.Sub(last) < idle) {
			continue
		}
		if m.modelHasQueuedDemand(ctx, residency.Model) {
			continue
		}
		lifecycle, ok := m.adapterLifecycle(target.Adapter)
		if !ok {
			continue
		}
		holderID := newID("rtr-holder")
		holder := &domain.Workload{Request: domain.WorkloadRequest{ID: holderID, Disruption: domain.DisruptionLocked}}
		reservation, acquired, _, err := m.reserveTarget(ctx, target, holder, Requirements{})
		if err != nil || !acquired {
			continue
		}
		reason := "idle_timeout"
		if quiet {
			reason = "quiet_hours"
		}
		_, err = m.transitionModel(ctx, lifecycle, target, residency.Model, domain.ResidencyColdDisk, reason, "residency-controller", "", "auto-unload:"+target.ID+":"+residency.Model+":"+now.Format("200601021504"), reservation.lease)
		m.releaseTarget(context.Background(), reservation)
		if err != nil {
			m.log.Warn("automatic model unload", "target", target.ID, "model", residency.Model, "err", err)
		}
	}
}

func (m *Manager) initializeResidencyRecovery(ctx context.Context) {
	rows, err := m.store.ListResidencyTransitions(ctx, 1000)
	if err != nil {
		m.log.Warn("list residency transitions for recovery", "err", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, transition := range rows {
		if transition.Status == domain.ResidencyTransitionPlanned || transition.Status == domain.ResidencyTransitionRunning {
			m.recoveryTransitions[transition.ID] = struct{}{}
		}
	}
}

func (m *Manager) recoverRegisteredResidencyTransitions(ctx context.Context) {
	m.mu.RLock()
	targetIDs := make([]string, 0, len(m.targets))
	for targetID := range m.targets {
		targetIDs = append(targetIDs, targetID)
	}
	m.mu.RUnlock()
	for _, targetID := range targetIDs {
		m.recoverResidencyTransitionsForTarget(ctx, targetID)
	}
}

func (m *Manager) recoverResidencyTransitionsForTarget(ctx context.Context, targetID string) {
	m.mu.RLock()
	hasRecovery := len(m.recoveryTransitions) > 0
	m.mu.RUnlock()
	if !hasRecovery {
		return
	}
	rows, err := m.store.ListResidencyTransitions(ctx, 1000)
	if err != nil {
		return
	}
	for _, transition := range rows {
		m.mu.RLock()
		_, recovering := m.recoveryTransitions[transition.ID]
		m.mu.RUnlock()
		if !recovering || transition.TargetID != targetID {
			continue
		}
		residency, err := m.store.GetModelResidency(ctx, transition.TargetID, transition.Model)
		if err != nil {
			continue
		}
		finished := time.Now().UTC()
		transition.FinishedAt = &finished
		if residency.ObservedTier == transition.ToTier {
			transition.Status = domain.ResidencyTransitionSucceeded
			transition.Error = ""
			m.auditActor(ctx, "residency-recovery", "", transition.WorkloadID, "residency.transition.recovered", "info", transition)
		} else {
			transition.Status = domain.ResidencyTransitionFailed
			transition.Error = fmt.Sprintf("controller restarted during transition; authoritative observation is %s", residency.ObservedTier)
			m.auditActor(ctx, "residency-recovery", "", transition.WorkloadID, "residency.transition.recovery_failed", "warn", transition)
		}
		_, _ = m.store.UpdateResidencyTransition(ctx, transition)
		m.mu.Lock()
		delete(m.recoveryTransitions, transition.ID)
		m.mu.Unlock()
	}
}

func (m *Manager) expireUnresolvedResidencyTransitions(ctx context.Context, now time.Time) {
	m.mu.RLock()
	ids := make(map[string]struct{}, len(m.recoveryTransitions))
	for id := range m.recoveryTransitions {
		ids[id] = struct{}{}
	}
	m.mu.RUnlock()
	if len(ids) == 0 {
		return
	}
	rows, err := m.store.ListResidencyTransitions(ctx, 1000)
	if err != nil {
		return
	}
	for _, transition := range rows {
		if _, ok := ids[transition.ID]; !ok || now.Sub(transition.CreatedAt) < m.residency.TransitionTimeout {
			continue
		}
		finished := now
		transition.FinishedAt = &finished
		transition.Status = domain.ResidencyTransitionFailed
		transition.Error = "controller restarted during transition and target did not return before recovery timeout"
		_, _ = m.store.UpdateResidencyTransition(ctx, transition)
		m.auditActor(ctx, "residency-recovery", "", transition.WorkloadID, "residency.transition.recovery_timeout", "error", transition)
		m.mu.Lock()
		delete(m.recoveryTransitions, transition.ID)
		m.mu.Unlock()
	}
}

func withinQuietHours(now time.Time, start, end string) bool {
	if strings.TrimSpace(start) == "" || strings.TrimSpace(end) == "" {
		return false
	}
	startClock, errStart := time.Parse("15:04", start)
	endClock, errEnd := time.Parse("15:04", end)
	if errStart != nil || errEnd != nil {
		return false
	}
	minute := now.Hour()*60 + now.Minute()
	startMinute := startClock.Hour()*60 + startClock.Minute()
	endMinute := endClock.Hour()*60 + endClock.Minute()
	if startMinute == endMinute {
		return true
	}
	if startMinute < endMinute {
		return minute >= startMinute && minute < endMinute
	}
	return minute >= startMinute || minute < endMinute
}

func (m *Manager) ListResidencies(ctx context.Context) ([]*domain.ModelResidency, error) {
	return m.store.ListModelResidencies(ctx)
}

func (m *Manager) ListResidencyTransitions(ctx context.Context, limit int) ([]*domain.ResidencyTransition, error) {
	return m.store.ListResidencyTransitions(ctx, limit)
}

// ConfigureResidency applies an explicit operator policy and, when necessary,
// executes the requested transition under the accelerator's fenced lease.
func (m *Manager) ConfigureResidency(ctx context.Context, targetID, model string, desired domain.ResidencyTier, policy domain.ResidencyPolicyMode, actor, idempotencyKey string) (*domain.ModelResidency, []*domain.ResidencyTransition, error) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	if idempotencyKey == "" {
		return nil, nil, fmt.Errorf("idempotency key is required")
	}
	target := m.targetByID(targetID)
	if target.ID == "" {
		return nil, nil, fmt.Errorf("unknown target %q", targetID)
	}
	if !hasExact(target.Models, model) {
		return nil, nil, fmt.Errorf("model %q is not allowlisted on target %s", model, targetID)
	}
	residency, err := m.store.GetModelResidency(ctx, targetID, model)
	if err != nil {
		return nil, nil, err
	}
	previousPolicy := residency.Policy
	if policy != "" {
		switch policy {
		case domain.ResidencyAuto, domain.ResidencyPinned, domain.ResidencyManual, domain.ResidencyOff:
			residency.Policy = policy
		default:
			return nil, nil, fmt.Errorf("unsupported residency policy %q", policy)
		}
	}
	if desired == "" {
		desired = residency.DesiredTier
	}
	switch desired {
	case domain.ResidencyHotVRAM, domain.ResidencyColdDisk, domain.ResidencyWarmRAM:
	default:
		return nil, nil, fmt.Errorf("unsupported residency tier %q", desired)
	}
	if desired == domain.ResidencyWarmRAM && !target.WarmRAMSupported {
		return nil, nil, fmt.Errorf("target %s does not support warm RAM offload", target.ID)
	}
	if desired == domain.ResidencyWarmRAM {
		lifecycle, ok := m.adapterLifecycle(target.Adapter)
		if !ok {
			return nil, nil, fmt.Errorf("adapter %s does not implement model lifecycle", target.Adapter)
		}
		if _, ok := lifecycle.(WarmRAMLifecycleAdapter); !ok {
			return nil, nil, fmt.Errorf("adapter %s does not implement warm RAM offload", target.Adapter)
		}
	}
	residency.DesiredTier = desired
	residency.UpdatedAt = time.Now().UTC()
	if _, err := m.store.UpsertModelResidency(ctx, residency); err != nil {
		return nil, nil, err
	}
	if residency.Policy != previousPolicy {
		m.auditActor(ctx, actor, "", "", "residency.policy.updated", "info", map[string]any{"target_id": targetID, "model": model, "from": previousPolicy, "to": residency.Policy})
	}
	if desired == residency.ObservedTier {
		return residency, nil, nil
	}
	if !target.SupportsModelLifecycle {
		return residency, nil, fmt.Errorf("target %s does not support model lifecycle", target.ID)
	}
	if m.targetActiveCount(target.ID) != 0 {
		return residency, nil, fmt.Errorf("target %s must drain before changing residency", target.ID)
	}
	lifecycle, ok := m.adapterLifecycle(target.Adapter)
	if !ok {
		return residency, nil, fmt.Errorf("adapter %s does not implement model lifecycle", target.Adapter)
	}
	holder := &domain.Workload{Request: domain.WorkloadRequest{ID: "residency-command:" + idempotencyKey, Disruption: domain.DisruptionLocked}}
	reservation, acquired, reason, err := m.reserveTarget(ctx, target, holder, Requirements{})
	if err != nil {
		return residency, nil, err
	}
	if !acquired {
		return residency, nil, fmt.Errorf("target %s unavailable: %s", target.ID, reason)
	}
	defer m.releaseTarget(context.Background(), reservation)

	var transitions []*domain.ResidencyTransition
	if desired == domain.ResidencyHotVRAM {
		fake := &domain.Workload{Request: domain.WorkloadRequest{ID: "operator:" + idempotencyKey, OwnerID: actor}}
		ids, err := m.reclaimForeignTargets(ctx, target, fake, reservation.lease)
		if err != nil {
			return residency, transitionsForIDs(ctx, m.store, ids), err
		}
		loadIDs, err := m.ensureModelResident(ctx, target, model, fake, reservation.lease)
		ids = append(ids, loadIDs...)
		if err != nil {
			return residency, transitionsForIDs(ctx, m.store, ids), err
		}
		transitions = append(transitions, transitionsForIDs(ctx, m.store, ids)...)
	} else {
		transition, err := m.transitionModel(ctx, lifecycle, target, model, desired, "operator_request", actor, "", "operator:"+idempotencyKey+":"+targetID+":"+model+":"+string(desired), reservation.lease)
		if err != nil {
			return residency, []*domain.ResidencyTransition{transition}, err
		}
		transitions = append(transitions, transition)
	}
	updated, err := m.store.GetModelResidency(ctx, targetID, model)
	return updated, transitions, err
}

func transitionsForIDs(ctx context.Context, backing store.WorkloadStore, ids []string) []*domain.ResidencyTransition {
	rows, _ := backing.ListResidencyTransitions(ctx, 1000)
	byID := make(map[string]*domain.ResidencyTransition, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	result := make([]*domain.ResidencyTransition, 0, len(ids))
	for _, id := range ids {
		if row := byID[id]; row != nil {
			result = append(result, row)
		}
	}
	return result
}

type NodeDrainResult struct {
	NodeID        string   `json:"node_id"`
	Accelerators  []string `json:"accelerators"`
	TransitionIDs []string `json:"transition_ids"`
	Scheduling    string   `json:"scheduling_state"`
}

// DrainNode releases idle runtime/model allocations without changing whether
// the scheduler may use the node. Active workloads are never interrupted.
func (m *Manager) DrainNode(ctx context.Context, nodeID, actor, idempotencyKey string) (*NodeDrainResult, error) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	if idempotencyKey == "" {
		return nil, fmt.Errorf("idempotency key is required")
	}
	if m.nodes == nil {
		return nil, fmt.Errorf("node inventory is unavailable")
	}
	node, err := m.nodes.GetNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	accelerators := make(map[string]struct{}, len(node.Accelerators))
	result := &NodeDrainResult{NodeID: nodeID, Scheduling: string(node.SchedulingState)}
	for _, accelerator := range node.Accelerators {
		accelerators[accelerator.ID] = struct{}{}
		result.Accelerators = append(result.Accelerators, accelerator.ID)
	}
	targets := m.Targets()
	for _, target := range targets {
		if _, attached := accelerators[target.AcceleratorID]; attached && m.targetActiveCount(target.ID) > 0 {
			return result, fmt.Errorf("target %s has active workloads; drain will not interrupt them", target.ID)
		}
	}
	for acceleratorID := range accelerators {
		var attached []Target
		for _, target := range targets {
			if target.AcceleratorID == acceleratorID {
				attached = append(attached, target)
			}
		}
		if len(attached) == 0 {
			continue
		}
		holder := &domain.Workload{Request: domain.WorkloadRequest{ID: "node-drain:" + idempotencyKey + ":" + acceleratorID, OwnerID: actor, Disruption: domain.DisruptionLocked}}
		reservation, acquired, reason, reserveErr := m.reserveTarget(ctx, attached[0], holder, Requirements{})
		if reserveErr != nil {
			return result, reserveErr
		}
		if !acquired {
			return result, fmt.Errorf("accelerator %s unavailable: %s", acceleratorID, reason)
		}
		for _, target := range attached {
			m.mu.RLock()
			adapter := m.adapters[target.Adapter]
			m.mu.RUnlock()
			if target.SupportsModelLifecycle {
				lifecycle, ok := adapter.(ModelLifecycleAdapter)
				if !ok {
					m.releaseTarget(context.Background(), reservation)
					return result, fmt.Errorf("target %s has no lifecycle implementation", target.ID)
				}
				for _, model := range append([]string(nil), target.ResidentModels...) {
					transition, transitionErr := m.transitionModel(ctx, lifecycle, target, model, domain.ResidencyColdDisk, "operator_node_drain", actor, "", "node-drain:"+idempotencyKey+":"+target.ID+":"+model, reservation.lease)
					if transition != nil {
						result.TransitionIDs = append(result.TransitionIDs, transition.ID)
					}
					if transitionErr != nil {
						m.releaseTarget(context.Background(), reservation)
						return result, transitionErr
					}
					target = m.targetByID(target.ID)
				}
			}
			if target.SupportsAcceleratorReclaim {
				if reclaimer, ok := adapter.(AcceleratorReclaimer); ok {
					transition, transitionErr := m.transitionRuntimeCache(ctx, reclaimer, target, holder, reservation.lease, "operator_node_drain")
					if transition != nil {
						result.TransitionIDs = append(result.TransitionIDs, transition.ID)
					}
					if transitionErr != nil {
						m.releaseTarget(context.Background(), reservation)
						return result, transitionErr
					}
				}
			}
		}
		m.releaseTarget(context.Background(), reservation)
	}
	m.auditActor(ctx, actor, "", "", "node.runtime.drained", "info", result)
	return result, nil
}
