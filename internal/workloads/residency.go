package workloads

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
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

func (m *Manager) targetGeneration(targetID string) uint64 {
	m.mu.RLock()
	generation := m.targetGenerations[targetID]
	m.mu.RUnlock()
	return generation
}

// casResidencyTransition is the only manager-side finalization path for a
// durable transition.  Recovery runs concurrently with command completion
// (and may be running in another manager instance), so an unconditional
// update could erase a newer node observation.  Reload, compare all durable
// guards, and retry only against the row we just observed.
func (m *Manager) casResidencyTransition(ctx context.Context, desired *domain.ResidencyTransition) error {
	if desired == nil {
		return nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		current, err := m.store.GetResidencyTransition(ctx, desired.ID)
		if err != nil {
			return err
		}
		// A terminal observed result always wins over a stale recovery/failure
		// snapshot.  Copy it back so callers cannot subsequently overwrite it.
		if current.Status == domain.ResidencyTransitionSucceeded && !(current.ProjectionRepairPending && !desired.ProjectionRepairPending) {
			*desired = *current
			return nil
		}
		merged := *current
		merged.Status = desired.Status
		if desired.Reason != "" {
			merged.Reason = desired.Reason
		}
		merged.StartedAt = desired.StartedAt
		merged.FinishedAt = desired.FinishedAt
		if desired.Error != "" || current.Error == "" {
			merged.Error = desired.Error
		}
		// Preserve the authoritative observation produced by the node.  The
		// CAS merge starts from the freshly reloaded row so a concurrent
		// recovery cannot be clobbered, but it must still carry the structured
		// result fields from this completion into that row for exact replay.
		if desired.ObservedTier != "" {
			merged.ObservedTier = desired.ObservedTier
		}
		if desired.WarmModelBytes != 0 || desired.WarmModelBytesVerified {
			merged.WarmModelBytes = desired.WarmModelBytes
			merged.WarmModelBytesVerified = desired.WarmModelBytesVerified
		}
		if desired.RuntimeIdentity != "" {
			merged.RuntimeIdentity = desired.RuntimeIdentity
		}
		if desired.CapabilityVersion != "" {
			merged.CapabilityVersion = desired.CapabilityVersion
		}
		if desired.CapabilityRevision != "" {
			merged.CapabilityRevision = desired.CapabilityRevision
		}
		if desired.ObservedFence != 0 {
			merged.ObservedFence = desired.ObservedFence
		}
		if desired.Status == domain.ResidencyTransitionSucceeded {
			merged.ProjectionRepairPending = desired.ProjectionRepairPending
		}
		updated, casErr := m.store.CompareAndSwapResidencyTransition(ctx, &merged, current.Revision, current.Status, current.FencingToken)
		if casErr == nil {
			*desired = *updated
			return nil
		}
		if !errors.Is(casErr, store.ErrResidencyTransitionConflict) {
			return casErr
		}
	}
	return store.ErrResidencyTransitionConflict
}

func (m *Manager) persistResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) bool {
	if err := m.casResidencyTransition(ctx, transition); err != nil {
		m.log.Warn("residency transition CAS update lost or failed", "transition_id", transition.ID, "err", err)
		return false
	}
	return true
}

// persistResidencyProjection is the observer-side projection boundary. A
// cancelled transition must not write a stale residency snapshot over a newer
// authoritative observation or cancellation-owned terminal state.
func (m *Manager) persistResidencyProjection(ctx context.Context, residency *domain.ModelResidency, expectedRevision uint64) error {
	if residency == nil {
		return nil
	}
	if residency.TargetGeneration == 0 {
		if target := m.targetByID(residency.TargetID); target.ID != "" {
			bindResidencyTargetFacts(residency, target, m.targetGeneration(target.ID))
		}
	}
	if err := normalizeResidencyTier(residency, residency.ObservedTier, residency.WarmModelBytes, residency.WarmModelBytesVerified); err != nil {
		return err
	}
	persistCtx := context.WithoutCancel(ctx)
	updated, err := m.store.CompareAndSwapModelResidency(persistCtx, residency, expectedRevision)
	if err != nil {
		return err
	}
	*residency = *updated
	return nil
}

func bindResidencyTargetFacts(residency *domain.ModelResidency, target Target, generation uint64) {
	if residency == nil {
		return
	}
	residency.TargetGeneration = generation
	residency.ExecutionFingerprint = targetExecutionFingerprint(target)
}

// normalizeResidencyTier is the single projection invariant for observations,
// transitions, and rollback recovery. Warm RAM is a verified physical claim;
// hot/cold observations must not retain stale warm accounting or VRAM pin
// deadlines from an earlier tier.
func normalizeResidencyTier(residency *domain.ModelResidency, tier domain.ResidencyTier, warmBytes int64, warmVerified bool) error {
	if residency == nil {
		return nil
	}
	switch tier {
	case domain.ResidencyWarmRAM:
		if warmBytes <= 0 || !warmVerified {
			return fmt.Errorf("warm_ram observation requires verified warm_model_bytes > 0")
		}
		residency.WarmModelBytes = warmBytes
		residency.WarmModelBytesVerified = true
		residency.MinResidentUntil = nil
	case domain.ResidencyColdDisk:
		residency.WarmModelBytes = 0
		residency.WarmModelBytesVerified = false
		residency.SessionCheckpointable = false
		residency.MinResidentUntil = nil
	case domain.ResidencyHotVRAM:
		residency.WarmModelBytes = 0
		residency.WarmModelBytesVerified = false
	default:
		return fmt.Errorf("unknown residency tier %q", tier)
	}
	return nil
}

// validateAuthoritativeTransitionEvidence is shared by manager replay and
// controller-adapter completion. A terminal row is reusable only when the
// complete node observation is durable and still matches the current target
// capability identity and exact resource fence.
func validateAuthoritativeTransitionEvidence(transition *domain.ResidencyTransition, target Target, model string, desired domain.ResidencyTier) error {
	if transition == nil || transition.Status != domain.ResidencyTransitionSucceeded || transition.TargetID != target.ID || transition.Model != model || transition.ObservedTier != desired {
		return fmt.Errorf("durable residency replay lacks authoritative observation")
	}
	if model == "runtime-cache" {
		if transition.RuntimeIdentity == "" || transition.ObservedFence <= 0 {
			return fmt.Errorf("runtime-cache transition lacks authoritative fence")
		}
		return nil
	}
	// Legacy HTTP lifecycle has an explicit read-after-write model listing but
	// no signed capability envelope. It may prove hot/cold state only; warm
	// remains unavailable without the versioned node contract.
	legacyHTTP := target.CapabilityVersion == "" && target.CapabilityRevision == "" && target.Capabilities.Version == ""
	if legacyHTTP {
		if desired == domain.ResidencyWarmRAM || transition.RuntimeIdentity != strings.Join([]string{target.ID, target.Adapter, target.RuntimeProtocol, target.CapabilityVersion, target.ModelFingerprint}, "|") || transition.ObservedFence <= 0 {
			return fmt.Errorf("legacy HTTP lifecycle cannot prove warm-RAM or canonical node evidence")
		}
		return nil
	}
	identity, _, identityErr := canonicalResidencyIdentity(target, model, desired == domain.ResidencyWarmRAM)
	if identityErr != nil {
		return fmt.Errorf("durable residency replay capability identity invalid: %w", identityErr)
	}
	if transition.RuntimeIdentity == "" || transition.RuntimeIdentity != identity || transition.CapabilityVersion != target.CapabilityVersion || transition.CapabilityRevision != target.CapabilityRevision || transition.ObservedFence <= 0 {
		return fmt.Errorf("durable residency replay observation identity or fence mismatch")
	}
	if desired == domain.ResidencyWarmRAM && (transition.WarmModelBytes <= 0 || !transition.WarmModelBytesVerified) {
		return fmt.Errorf("durable warm residency replay lacks verified bytes")
	}
	return nil
}

// acceptSucceededResidencyTransition is the single manager-side success
// boundary. Callers must already have captured the node observation on the
// transition; this function validates it, normalizes and persists the model
// projection, then durably CASes the terminal transition.
func (m *Manager) acceptSucceededResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition, target Target, residency *domain.ModelResidency, expectedRevision, expectedGeneration uint64) error {
	if transition == nil {
		return fmt.Errorf("nil residency transition")
	}
	generation := expectedGeneration
	if !m.refreshStableLifecycleTarget(&target, &generation) {
		return fmt.Errorf("transition target changed before acceptance")
	}
	fingerprint := targetExecutionFingerprint(target)
	if transition.TargetGeneration > generation {
		return fmt.Errorf("transition target generation changed before acceptance")
	}
	if transition.TargetGeneration > 0 && transition.TargetGeneration < generation {
		// The command was started under an older controller fence but its
		// authoritative post-command observation arrived after a newer target
		// advertisement. Rebind the accepted result to the newer fence; an older
		// result can thereby repair current state, but can never overwrite it at
		// its obsolete generation.
		transition.TargetGeneration = generation
		transition.ExecutionFingerprint = fingerprint
	} else if transition.ExecutionFingerprint != "" && transition.ExecutionFingerprint != fingerprint {
		return fmt.Errorf("transition execution fingerprint changed before acceptance")
	}
	if transition.TargetGeneration == 0 {
		transition.TargetGeneration = generation
	}
	if transition.ExecutionFingerprint == "" {
		transition.ExecutionFingerprint = fingerprint
	}
	// Validate the complete authoritative evidence before changing the durable
	// status. Callers may pass a running row after node observation; the
	// acceptance boundary is the only place allowed to mint Succeeded.
	evidence := *transition
	evidence.Status = domain.ResidencyTransitionSucceeded
	if err := validateAuthoritativeTransitionEvidence(&evidence, target, transition.Model, transition.ToTier); err != nil {
		return err
	}
	// A durable observation may outlive newer generations (for example, a
	// historical succeeded row retained for projection repair). Never project
	// that stale evidence over a newer resource fence. The transition itself
	// remains terminal and replayable; only the current generation may update
	// the mutable residency projection.
	projectCurrent := residency != nil
	if projectCurrent && transition.ProjectionRepairPending && transition.FencingToken > 0 {
		if highwater, err := m.store.MaxResidencyFencingToken(ctx, transition.TargetID, transition.Model); err != nil {
			return err
		} else if highwater > transition.FencingToken {
			projectCurrent = false
		}
	}
	if projectCurrent {
		bindResidencyTargetFacts(residency, target, generation)
		residency.ObservedTier = transition.ObservedTier
		residency.DesiredTier = transition.ToTier
		residency.WarmModelBytes = transition.WarmModelBytes
		residency.WarmModelBytesVerified = transition.WarmModelBytesVerified
		residency.LastError = ""
		residency.UpdatedAt = time.Now().UTC()
		if err := normalizeResidencyTier(residency, transition.ObservedTier, transition.WarmModelBytes, transition.WarmModelBytesVerified); err != nil {
			return err
		}
		if !m.refreshStableLifecycleTarget(&target, &generation) {
			return fmt.Errorf("transition target changed before projection persistence")
		}
		if err := m.persistResidencyProjection(ctx, residency, expectedRevision); err != nil {
			// The node's post-operation advertisement may project the same
			// residency first. Re-read once: an identical observed tier is
			// already the accepted truth; otherwise apply this result to the
			// fresh revision.
			if !errors.Is(err, store.ErrModelResidencyConflict) {
				return err
			}
			current, getErr := m.store.GetModelResidency(ctx, residency.TargetID, residency.Model)
			if getErr != nil {
				return err
			}
			if current.ObservedTier != transition.ObservedTier {
				fresh := *current
				bindResidencyTargetFacts(&fresh, target, generation)
				fresh.ObservedTier, fresh.DesiredTier = transition.ObservedTier, transition.ToTier
				fresh.WarmModelBytes, fresh.WarmModelBytesVerified = transition.WarmModelBytes, transition.WarmModelBytesVerified
				fresh.LastError, fresh.UpdatedAt = "", time.Now().UTC()
				if normErr := normalizeResidencyTier(&fresh, transition.ObservedTier, transition.WarmModelBytes, transition.WarmModelBytesVerified); normErr != nil {
					return normErr
				}
				if retryErr := m.persistResidencyProjection(ctx, &fresh, current.Revision); retryErr != nil {
					return retryErr
				}
				*residency = fresh
			} else {
				*residency = *current
			}
		}
		if !m.refreshStableLifecycleTarget(&target, &generation) {
			return fmt.Errorf("transition target changed during acceptance")
		}
	}
	transition.ProjectionRepairPending = false
	transition.Status = domain.ResidencyTransitionSucceeded
	if transition.FinishedAt == nil {
		finished := time.Now().UTC()
		transition.FinishedAt = &finished
	}
	if !m.persistResidencyTransition(ctx, transition) {
		return fmt.Errorf("persist succeeded residency transition")
	}
	if !m.refreshStableLifecycleTarget(&target, &generation) {
		return fmt.Errorf("transition target changed after acceptance")
	}
	return nil
}

func hasExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (m *Manager) residencyObservationLock(targetID string) *sync.Mutex {
	m.residencyObservationLocksMu.Lock()
	defer m.residencyObservationLocksMu.Unlock()
	if lock := m.residencyObservationLocks[targetID]; lock != nil {
		return lock
	}
	lock := &sync.Mutex{}
	m.residencyObservationLocks[targetID] = lock
	return lock
}

// residencyAdmissionLock is a per-target refresh fence. Admissions and
// execution starts take its read side so independent slots may proceed
// concurrently; RegisterTarget takes the write side before replacing runtime
// facts. The manager-wide residencyAdmissionMu is always acquired first.
func (m *Manager) residencyAdmissionLock(targetID string) *sync.RWMutex {
	m.residencyAdmissionLocksMu.Lock()
	defer m.residencyAdmissionLocksMu.Unlock()
	if lock := m.residencyAdmissionLocks[targetID]; lock != nil {
		return lock
	}
	lock := &sync.RWMutex{}
	m.residencyAdmissionLocks[targetID] = lock
	return lock
}

// beginResidencyTransition reserves the physical accelerator while a
// lifecycle/profile command is in flight. It is a short bookkeeping fence,
// not a mutex held across the command: refreshes and unrelated targets can
// continue to acquire their own locks, while another admission on this
// accelerator fails/retries instead of racing aggregate capacity accounting.
func (m *Manager) beginResidencyTransition(acceleratorID string) bool {
	if acceleratorID == "" {
		return true
	}
	m.residencyTransitionsMu.Lock()
	defer m.residencyTransitionsMu.Unlock()
	if _, busy := m.residencyTransitions[acceleratorID]; busy {
		return false
	}
	m.residencyTransitions[acceleratorID] = struct{}{}
	return true
}

func (m *Manager) endResidencyTransition(acceleratorID string) {
	if acceleratorID == "" {
		return
	}
	m.residencyTransitionsMu.Lock()
	delete(m.residencyTransitions, acceleratorID)
	m.residencyTransitionsMu.Unlock()
}

func (m *Manager) residencyTransitionInFlight(acceleratorID string) bool {
	if acceleratorID == "" {
		return false
	}
	m.residencyTransitionsMu.Lock()
	_, busy := m.residencyTransitions[acceleratorID]
	m.residencyTransitionsMu.Unlock()
	return busy
}

// beginResidencyOperation serializes operator residency/drain workflows with
// a channel fence rather than holding reconcileMu over store or runtime I/O.
// The marker is acquired/released under a short critical section; callers
// must re-read target identity before committing any post-command projection.
func (m *Manager) beginResidencyOperation(ctx context.Context) (func(), error) {
	for {
		m.residencyOperationInFlightMu.Lock()
		inFlight := m.residencyOperationInFlight
		if inFlight == nil {
			inFlight = make(chan struct{})
			m.residencyOperationInFlight = inFlight
			m.residencyOperationInFlightMu.Unlock()
			return func() {
				m.residencyOperationInFlightMu.Lock()
				if m.residencyOperationInFlight == inFlight {
					m.residencyOperationInFlight = nil
					close(inFlight)
				}
				m.residencyOperationInFlightMu.Unlock()
			}, nil
		}
		m.residencyOperationInFlightMu.Unlock()
		select {
		case <-inFlight:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (m *Manager) observeTargetResidency(ctx context.Context, target Target) bool {
	return m.observeTargetResidencyLocked(ctx, target)
}

// hasFencedHotTransition proves that a complete refresh which omits a model
// is merely lagging an exact, signed lifecycle result. A durable hot row by
// itself is not proof: after a restart or physical removal, reusing it would
// permit a cold start and skip the required load/recheck.
// fencedHotGrace is how long a completed load outranks an advertisement that
// omits the model: an advertisement collected just before the load finished
// must not undo it. Nodes re-advertise every 30 s, so after a few cycles the
// omission is authoritative (the model was unloaded or its process died).
var fencedHotGrace = 90 * time.Second

func (m *Manager) hasFencedHotTransition(ctx context.Context, target Target, model string) bool {
	transitions, err := m.store.ListResidencyTransitions(ctx, -1)
	if err != nil {
		return false
	}
	// Only the latest finished transition counts. Any hot load in the past
	// used to count forever, so a model unloaded or crashed outside the LB
	// stayed "hot" and every request for it failed with "model is not loaded".
	var latest *domain.ResidencyTransition
	for _, transition := range transitions {
		if transition == nil || transition.TargetID != target.ID || transition.Model != model || transition.FinishedAt == nil {
			continue
		}
		if latest == nil || transition.FinishedAt.After(*latest.FinishedAt) {
			latest = transition
		}
	}
	if latest == nil || latest.ToTier != domain.ResidencyHotVRAM || time.Since(*latest.FinishedAt) > fencedHotGrace {
		return false
	}
	return validateAuthoritativeTransitionEvidence(latest, target, model, domain.ResidencyHotVRAM) == nil
}

func (m *Manager) observeTargetResidencyLocked(ctx context.Context, target Target) bool {
	if !target.SupportsModelLifecycle {
		return true
	}
	now := time.Now().UTC()
	targetGeneration := m.targetGeneration(target.ID)
	targetFingerprint := targetExecutionFingerprint(target)
	ok := true
	for _, model := range target.Models {
		if model == "" || model == "*" {
			continue
		}
		residency, err := m.store.GetModelResidency(ctx, target.ID, model)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			m.log.Warn("read model residency", "target", target.ID, "model", model, "err", err)
			ok = false
			continue
		}
		resident := hasExact(target.ResidentModels, model)
		createdNew := false
		adoptedExisting := false
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
			residency.TargetGeneration = targetGeneration
			residency.ExecutionFingerprint = targetFingerprint
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
			if normalizeErr := normalizeResidencyTier(residency, residency.ObservedTier, residency.WarmModelBytes, residency.WarmModelBytesVerified); normalizeErr != nil {
				m.log.Warn("normalize observed model residency", "target", target.ID, "model", model, "err", normalizeErr)
				ok = false
				continue
			}
			// Create-if-absent closes the race between an older observation's
			// missing-row read and a newer registration creating authoritative
			// material facts. Never use Upsert for that boundary.
			observationLock := m.residencyObservationLock(target.ID)
			observationLock.Lock()
			current := m.targetObservationFactsCurrent(target)
			observationLock.Unlock()
			var createErr error
			if current {
				// Store I/O is deliberately outside observationLock. The second
				// short check prevents an obsolete registration from being treated
				// as the committed observation after a refresh wins the race.
				residency, createdNew, createErr = m.store.CreateModelResidency(ctx, residency)
				observationLock.Lock()
				stillCurrent := m.targetObservationFactsCurrent(target)
				observationLock.Unlock()
				if !stillCurrent {
					createErr = fmt.Errorf("target observation facts changed during persistence")
				}
			}
			if createErr != nil && errors.Is(createErr, store.ErrModelResidencyGenerationConflict) {
				if latest, readErr := m.store.GetModelResidency(ctx, target.ID, model); readErr == nil {
					if latest.TargetGeneration > targetGeneration || (latest.TargetGeneration == targetGeneration && latest.ExecutionFingerprint != "" && latest.ExecutionFingerprint != targetFingerprint) {
						residency = latest
						createdNew = false
						adoptedExisting = true
						createErr = nil
					}
				}
			}
			if !current || createErr != nil {
				if createErr != nil {
					m.log.Warn("create observed model residency", "target", target.ID, "model", model, "err", createErr)
				}
				ok = false
				continue
			}
			adoptedExisting = !createdNew
		}
		// Only an exact fenced lifecycle result may override an authoritative
		// complete omission. Durable hot rows without that evidence are stale
		// across restart/physical removal and are reconciled cold immediately.
		if !resident && residency.ObservedTier == domain.ResidencyHotVRAM && m.hasFencedHotTransition(ctx, target, model) {
			adoptedExisting = true
		}
		if !createdNew && !adoptedExisting {
			// Refresh facts from the latest row and commit them through the
			// revision CAS. A delayed registration/retry must not overwrite a
			// newer tier, byte, fence, or runtime observation.
			for attempt := 0; attempt < 4; attempt++ {
				expectedRevision := residency.Revision
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
				if normalizeErr := normalizeResidencyTier(residency, residency.ObservedTier, residency.WarmModelBytes, residency.WarmModelBytesVerified); normalizeErr != nil {
					m.log.Warn("normalize observed model residency", "target", target.ID, "model", model, "err", normalizeErr)
					ok = false
					break
				}
				residency.UpdatedAt = now
				residency.TargetGeneration = targetGeneration
				residency.ExecutionFingerprint = targetFingerprint
				observationLock := m.residencyObservationLock(target.ID)
				observationLock.Lock()
				currentBeforeStore := m.targetObservationFactsCurrent(target)
				observationLock.Unlock()
				if !currentBeforeStore {
					ok = false
					break
				}
				// The durable CAS is outside observationLock. Recheck the target
				// facts immediately after the write before accepting the result.
				updated, casErr := m.store.CompareAndSwapModelResidency(ctx, residency, expectedRevision)
				observationLock.Lock()
				currentAfterStore := m.targetObservationFactsCurrent(target)
				observationLock.Unlock()
				if !currentAfterStore && casErr == nil {
					casErr = fmt.Errorf("target observation facts changed during persistence")
				}
				if casErr == nil {
					residency = updated
					break
				}
				if !errors.Is(casErr, store.ErrModelResidencyConflict) && !errors.Is(casErr, store.ErrModelResidencyGenerationConflict) {
					m.log.Warn("persist observed model residency", "target", target.ID, "model", model, "err", casErr)
					ok = false
					break
				}
				latest, getErr := m.store.GetModelResidency(ctx, target.ID, model)
				if getErr != nil {
					m.log.Warn("reload observed model residency", "target", target.ID, "model", model, "err", getErr)
					ok = false
					break
				}
				if errors.Is(casErr, store.ErrModelResidencyGenerationConflict) &&
					(latest.TargetGeneration > targetGeneration || (latest.TargetGeneration == targetGeneration && latest.ExecutionFingerprint != "" && latest.ExecutionFingerprint != targetFingerprint)) {
					// A durable row from a newer target fence is authoritative. Adopt
					// it rather than replaying this older observation over the newer
					// generation; a subsequent target refresh will rebind if facts
					// genuinely changed.
					residency = latest
					adoptedExisting = true
					break
				}
				// A concurrent controller transition may have advanced the row to
				// a different authoritative tier. Hardware facts from this
				// observation may be merged only when they describe that same tier;
				// never reapply the older target snapshot over a newer warm/hot
				// transition.
				expectedTier := domain.ResidencyColdDisk
				if resident {
					expectedTier = domain.ResidencyHotVRAM
				}
				if latest.ObservedTier != expectedTier || latest.DesiredTier != expectedTier || latest.UpdatedAt.After(now) {
					residency = latest
					adoptedExisting = true
					break
				}
				residency = latest
				if attempt == 3 {
					ok = false
				}
			}
		}
	}
	return ok
}

func equalObservationModels(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]struct{}, len(left))
	for _, model := range left {
		seen[model] = struct{}{}
	}
	for _, model := range right {
		if _, ok := seen[model]; !ok {
			return false
		}
	}
	return true
}

func (m *Manager) targetObservationFactsCurrent(target Target) bool {
	m.mu.RLock()
	current, ok := m.targets[target.ID]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	// Observations are durable projections of the complete execution target.
	// Use the same canonical fence as admission/transition commits so a change
	// to endpoint, profile, policy, pricing, custom nodes, or learned capacity
	// cannot be mistaken for the facts that were read before the store round
	// trip.
	return current.ID == target.ID && targetExecutionFingerprint(current) == targetExecutionFingerprint(target)
}

func (m *Manager) ensureModelResident(ctx context.Context, target Target, model string, workload *domain.Workload, lease *domain.AcceleratorLease) ([]string, error) {
	// Network-backed observation and lifecycle commands must never run while a
	// manager or refresh lock is held. The durable transition/idempotency fence
	// below serializes the state changes; callers re-read target facts after the
	// command returns.
	if !m.beginResidencyTransition(target.AcceleratorID) {
		return nil, fmt.Errorf("accelerator residency transition in progress")
	}
	defer m.endResidencyTransition(target.AcceleratorID)
	return m.ensureModelResidentLocked(ctx, target, model, workload, lease)
}

// ensureModelResidentLocked is called with residencyAdmissionMu and the
// target's residency observation lock held. Keeping this separate lets the
// production admission path re-read the target and retain the same fences
// through reserve, model enforcement, final validation, and runnability.
func (m *Manager) ensureModelResidentLocked(ctx context.Context, target Target, model string, workload *domain.Workload, lease *domain.AcceleratorLease) ([]string, error) {
	if err := m.ensureMeasuredCapacity(ctx, target, model); err != nil {
		return nil, err
	}
	if hasExact(target.ResidentModels, model) {
		return nil, nil
	}
	if !target.SupportsModelLifecycle {
		return nil, fmt.Errorf("runtime does not support model lifecycle")
	}
	lifecycle, ok := m.adapterLifecycle(target.Adapter)
	if !ok && target.AcceleratorID != "" && !target.Cloud && m.nodes != nil {
		m.mu.RLock()
		lifecycle = m.controllerResidency
		m.mu.RUnlock()
		ok = lifecycle != nil
	}
	if !ok {
		return nil, fmt.Errorf("adapter %s does not implement model lifecycle", target.Adapter)
	}

	var transitionIDs []string
	var evicted []string
	capacityScheduling := multiResidentAdmissionConfigured(target)
	maxResident := target.MaxResidentModels
	if !capacityScheduling && maxResident <= 0 {
		maxResident = 1
	}
	priority := requestedPriority(workload)
	if maxResident > 0 {
		needed := len(target.ResidentModels) - maxResident + 1
		if needed > 0 {
			candidates, protection, err := m.evictionCandidates(ctx, target, model, priority)
			if err != nil {
				return nil, err
			}
			if len(candidates) < needed {
				return nil, protection.blockError(fmt.Errorf("resident capacity is protected by policy or queued demand"))
			}
			for i := 0; i < needed; i++ {
				victim := candidates[i]
				transition, err := m.transitionModel(ctx, lifecycle, target, victim.Model, domain.ResidencyColdDisk, "capacity_for_demand", workload.Request.OwnerID, workload.Request.ID, demandEvictKey(workload.Request.ID, target.ID, victim.Model, lease), lease)
				if err != nil {
					return transitionIDs, err
				}
				transitionIDs = append(transitionIDs, transition.ID)
				evicted = append(evicted, victim.Model)
				target = m.targetByID(target.ID)
			}
		}
	}
	if capacityScheduling {
		// A measured byte budget can require more victims than the legacy count
		// limit. Evict only eligible automatic rows, rechecking after every durable
		// transition so a failed/uncertain unload never frees phantom capacity.
		for {
			capacityErr := m.checkResidentCapacityForWorkload(ctx, target, model, workload.Request.ID)
			if capacityErr == nil {
				break
			}
			candidates, protection, candidateErr := m.evictionCandidates(ctx, target, model, priority)
			if candidateErr != nil {
				return transitionIDs, candidateErr
			}
			used := make(map[string]struct{}, len(evicted))
			for _, name := range evicted {
				used[name] = struct{}{}
			}
			var victim *domain.ModelResidency
			for _, candidate := range candidates {
				if _, already := used[candidate.Model]; !already {
					victim = candidate
					break
				}
			}
			if victim == nil {
				return transitionIDs, protection.blockError(capacityErr)
			}
			transition, transitionErr := m.transitionModel(ctx, lifecycle, target, victim.Model, domain.ResidencyColdDisk, "capacity_for_demand", workload.Request.OwnerID, workload.Request.ID, demandEvictKey(workload.Request.ID, target.ID, victim.Model, lease), lease)
			if transition != nil {
				transitionIDs = append(transitionIDs, transition.ID)
				evicted = append(evicted, victim.Model)
			}
			if transitionErr != nil {
				return transitionIDs, transitionErr
			}
			target = m.targetByID(target.ID)
		}
		// Recheck after any eviction and immediately before the load transition.
		// A failed/uncertain eviction must never be treated as released capacity.
		if err := m.checkResidentCapacityForWorkload(ctx, target, model, workload.Request.ID); err != nil {
			return transitionIDs, err
		}
	}
	loadKey := demandLoadKey(workload.Request.ID, target.ID, model, workload.Request.IdempotencyKey, lease)
	transition, err := m.transitionModel(ctx, lifecycle, target, model, domain.ResidencyHotVRAM, "workload_demand", workload.Request.OwnerID, workload.Request.ID, loadKey, lease)
	if err != nil {
		for i := len(evicted) - 1; i >= 0; i-- {
			current := m.targetByID(target.ID)
			rollback, rollbackErr := m.transitionModel(ctx, lifecycle, current, evicted[i], domain.ResidencyHotVRAM, "demand_load_rollback", workload.Request.OwnerID, workload.Request.ID, demandTransitionKey("demand-rollback:"+workload.Request.ID+":"+target.ID+":"+evicted[i], workload.Request.ID, lease), lease)
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

// ModelCapacityObserver is an optional runtime/node boundary. Implementations
// must return exact measured bytes for this model and active profile from an
// authoritative observation; target-wide budgets and learned estimates are not
// valid substitutes.
type ModelCapacityObserver interface {
	ObserveModelCapacity(context.Context, Target, string) (store.ModelCapacity, error)
}

// evictionProtection records why residents were withheld from demand
// eviction so the admission decision can report a stable code and, for a
// min_residency window, the instant the resident becomes evictable.
type evictionProtection struct {
	minResidentUntil *time.Time
	pinned           bool
}

func (p evictionProtection) blockError(err error) error {
	switch {
	case p.minResidentUntil != nil:
		return &admissionBlockError{code: domain.BlockerTransitionBusy, until: p.minResidentUntil, msg: err.Error() + "; resident within min_residency until " + p.minResidentUntil.UTC().Format(time.RFC3339)}
	case p.pinned:
		return &admissionBlockError{code: domain.BlockerPinnedResident, msg: err.Error()}
	}
	return err
}

// requestedPriority is the caller-requested priority without QoS boosts, so
// "urgent" means the same thing for every plane.
func requestedPriority(workload *domain.Workload) int {
	if workload == nil {
		return 0
	}
	if workload.RuntimePriority != nil {
		return *workload.RuntimePriority
	}
	return workload.Request.Priority
}

// evictionCandidates lists residents demand may evict. A resident inside its
// min_residency window is protected from ordinary demand (that window exists
// to stop load/unload thrash) and only an urgent request may override it.
func (m *Manager) evictionCandidates(ctx context.Context, target Target, requested string, priority int) ([]*domain.ModelResidency, evictionProtection, error) {
	var protection evictionProtection
	if (target.QueueRunning > 0 || target.QueuePending > 0) && !m.runtimeQueueCountersStale(target) {
		return nil, protection, nil
	}
	rows, err := m.store.ListModelResidencies(ctx)
	if err != nil {
		return nil, protection, err
	}
	now := time.Now()
	var candidates []*domain.ModelResidency
	for _, row := range rows {
		if row.TargetID != target.ID || row.Model == requested || row.ObservedTier != domain.ResidencyHotVRAM {
			continue
		}
		if row.Policy == domain.ResidencyPinned || row.Policy == domain.ResidencyManual || row.Policy == domain.ResidencyOff {
			protection.pinned = true
			continue
		}
		if row.MinResidentUntil != nil && now.Before(*row.MinResidentUntil) && priority < UrgentPriority {
			protection.minResidentUntil = earlierTime(protection.minResidentUntil, row.MinResidentUntil)
			continue
		}
		if m.modelHasActiveDemand(row.Model) {
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
	return candidates, protection, nil
}

// SetModelCapacity records a measured model/profile envelope. It is intended
// for node/runtime measurement callbacks and is safe to replay after restart.
func (m *Manager) SetModelCapacity(ctx context.Context, capacity store.ModelCapacity) (*store.ModelCapacity, error) {
	if capacity.TargetID == "" || capacity.Model == "" {
		return nil, fmt.Errorf("model capacity requires target and model")
	}
	if !capacity.Verified || capacity.FootprintBytes() <= 0 || capacity.CapacitySource == "" || !strings.HasPrefix(capacity.CapacitySource, "runtime:") || capacity.ModelFingerprint == "" || capacity.RuntimeIdentity == "" || capacity.CapabilityVersion == "" || capacity.CapabilityRevision == "" || capacity.ObservedAt.IsZero() {
		return nil, fmt.Errorf("model capacity requires a verified positive authoritative observation with identity and observed_at")
	}
	if target, ok := func() (Target, bool) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		target, found := m.targets[capacity.TargetID]
		return target, found
	}(); ok {
		if err := validateCapacityBinding(&capacity, target, time.Now().UTC()); err != nil {
			return nil, err
		}
	}
	return m.store.UpsertModelCapacity(ctx, &capacity)
}

// RecordModelCapacity is a named compatibility alias for measurement code.
func (m *Manager) RecordModelCapacity(ctx context.Context, capacity store.ModelCapacity) (*store.ModelCapacity, error) {
	return m.SetModelCapacity(ctx, capacity)
}

func (m *Manager) ModelCapacity(ctx context.Context, targetID, model, profileID string) (*store.ModelCapacity, error) {
	return m.store.GetModelCapacity(ctx, targetID, model, profileID)
}

const modelCapacityMaxAge = 24 * time.Hour

func residencyCapacityIdentity(target Target) string {
	return strings.Join([]string{target.ID, target.Adapter, target.RuntimeProtocol, target.CapabilityVersion, target.ModelFingerprint}, "|")
}

func validateCapacityBinding(capacity *store.ModelCapacity, target Target, now time.Time) error {
	if capacity == nil {
		return store.ErrNotFound
	}
	if !capacity.Verified || capacity.FootprintBytes() <= 0 || capacity.CapacitySource == "" || !strings.HasPrefix(capacity.CapacitySource, "runtime:") || capacity.AcceleratorID == "" || capacity.ModelFingerprint == "" || capacity.RuntimeIdentity == "" || capacity.CapabilityVersion == "" || capacity.CapabilityRevision == "" {
		return fmt.Errorf("capacity measurement is not an authoritative positive observation for target %s", target.ID)
	}
	if capacity.ProfileID != target.ActiveRuntimeProfile || capacity.AcceleratorID != target.AcceleratorID || capacity.ModelFingerprint != target.ModelFingerprint || capacity.RuntimeIdentity != residencyCapacityIdentity(target) || capacity.CapabilityVersion != target.CapabilityVersion || capacity.CapabilityRevision != target.CapabilityRevision {
		return fmt.Errorf("capacity measurement identity drifted for target %s", target.ID)
	}
	expectedUnified := target.Capacity.VRAMTotalBytes <= 0 && target.Capacity.VRAMHardCapBytes <= 0 && target.Capacity.RAMTotalBytes > 0
	expectedHardCap := target.Capacity.VRAMHardCapBytes
	if expectedHardCap <= 0 && expectedUnified {
		expectedHardCap = target.Capacity.RAMHardCapBytes
	}
	if capacity.VRAMTotalBytes != target.Capacity.VRAMTotalBytes || capacity.RAMTotalBytes != target.Capacity.RAMTotalBytes || capacity.VRAMReserveBytes != target.Capacity.VRAMReserveBytes || capacity.RAMReserveBytes != target.Capacity.RAMReserveBytes || capacity.RuntimeHardCapBytes != expectedHardCap || capacity.UnifiedMemory != expectedUnified {
		return fmt.Errorf("capacity measurement envelope drifted for target %s", target.ID)
	}
	if capacity.ObservedAt.IsZero() || now.Sub(capacity.ObservedAt) > modelCapacityMaxAge || capacity.ObservedAt.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("capacity measurement is stale for target %s", target.ID)
	}
	return nil
}

func validateRequestVRAMIncrementObservation(observation RequestVRAMIncrementObservation, target Target, requestID string, requirements Requirements, generation uint64, now time.Time) error {
	if !observation.Verified || observation.Bytes < 0 || observation.Source == "" || !strings.HasPrefix(observation.Source, "runtime:") {
		return fmt.Errorf("request increment is not a verified runtime observation")
	}
	if generation == 0 || (observation.TargetGeneration != 0 && observation.TargetGeneration != generation) || observation.TargetID != target.ID || observation.AcceleratorID != target.AcceleratorID || observation.RequestID != requestID || observation.Model != requirements.Model || observation.ProfileID != target.ActiveRuntimeProfile || observation.RuntimeIdentity != residencyCapacityIdentity(target) || observation.CapabilityVersion != target.CapabilityVersion || observation.CapabilityRevision != target.CapabilityRevision || observation.ModelFingerprint != target.ModelFingerprint || observation.ContextTokens != requirements.ContextTokens {
		return fmt.Errorf("request increment identity drifted for target %s", target.ID)
	}
	if observation.ContextTokens < 0 || observation.ObservedAt.IsZero() || now.Sub(observation.ObservedAt) > modelCapacityMaxAge || observation.ObservedAt.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("request increment observation is stale or malformed")
	}
	return nil
}

func multiResidentAdmissionConfigured(target Target) bool {
	// A zero/one resident target is the legacy lifecycle contract. Byte-wise
	// multi-resident admission is opt-in so old signed node observations do not
	// get a fabricated per-model footprint from a target-wide budget.
	return target.SharingEnabled || target.MaxResidentModels > 1 || target.Capabilities.MaxResidentModels > 1
}

// ensureMeasuredCapacity accepts only an existing durable observation or an
// optional authoritative runtime/node measurement callback. It deliberately
// never derives a per-model footprint from total VRAM/RAM, hard caps, learned
// estimates, or freshness timestamps minted by the controller.
func (m *Manager) ensureMeasuredCapacity(ctx context.Context, target Target, model string) error {
	profileID := target.ActiveRuntimeProfile
	existing, err := m.store.GetModelCapacity(ctx, target.ID, model, profileID)
	if err == nil {
		return validateCapacityBinding(existing, target, time.Now().UTC())
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if !multiResidentAdmissionConfigured(target) {
		return nil
	}
	lifecycle, ok := m.adapterLifecycle(target.Adapter)
	if !ok && target.AcceleratorID != "" && !target.Cloud && m.nodes != nil {
		m.mu.RLock()
		lifecycle = m.controllerResidency
		m.mu.RUnlock()
		ok = lifecycle != nil
	}
	if !ok {
		return fmt.Errorf("capacity measurement missing for target %s model %s", target.ID, model)
	}
	observer, ok := lifecycle.(ModelCapacityObserver)
	if !ok {
		// The runtime cannot report per-model bytes (e.g. a llama.cpp router).
		// Leave the model unmeasured: checkResidentCapacity then admits it only
		// with exclusive use of the accelerator, never via byte accounting.
		return nil
	}
	capacity, err := observer.ObserveModelCapacity(ctx, target, model)
	if err != nil {
		return fmt.Errorf("authoritative capacity observation failed for target %s model %s: %w", target.ID, model, err)
	}
	if capacity.TargetID == "" {
		capacity.TargetID = target.ID
	}
	if capacity.Model == "" {
		capacity.Model = model
	}
	if capacity.ProfileID != profileID || capacity.TargetID != target.ID || capacity.Model != model {
		return fmt.Errorf("authoritative capacity observation identity mismatch for target %s model %s", target.ID, model)
	}
	if err := validateCapacityBinding(&capacity, target, time.Now().UTC()); err != nil {
		return err
	}
	if _, err := m.store.UpsertModelCapacity(ctx, &capacity); err != nil {
		return fmt.Errorf("persist authoritative capacity measurement: %w", err)
	}
	return nil
}

const bytesPerMiB int64 = 1024 * 1024

func checkedMiBToBytes(value int64, field string) (int64, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s must be non-negative", field)
	}
	if value > math.MaxInt64/bytesPerMiB {
		return 0, fmt.Errorf("%s overflows int64 bytes", field)
	}
	return value * bytesPerMiB, nil
}

func validateTargetMiBFields(target Target) error {
	for field, value := range map[string]int64{
		"standalone_vram_mb": target.StandaloneVRAMMB, "accelerator_vram_mb": target.AcceleratorVRAMMB,
		"vram_reserve_mb": target.VRAMReserveMB,
	} {
		if _, err := checkedMiBToBytes(value, field); err != nil {
			return err
		}
	}
	return nil
}

func validateCapacityByteFields(target Target) error {
	for name, value := range map[string]int64{
		"vram_total_bytes": target.Capacity.VRAMTotalBytes, "vram_reserve_bytes": target.Capacity.VRAMReserveBytes,
		"vram_hard_cap_bytes": target.Capacity.VRAMHardCapBytes, "ram_total_bytes": target.Capacity.RAMTotalBytes,
		"ram_reserve_bytes": target.Capacity.RAMReserveBytes, "ram_hard_cap_bytes": target.Capacity.RAMHardCapBytes,
	} {
		if value < 0 {
			return fmt.Errorf("%s must be non-negative", name)
		}
	}
	return nil
}

func targetCapacityBytes(target Target) (total, reserve, hardCap int64, err error) {
	if err = validateCapacityByteFields(target); err != nil {
		return 0, 0, 0, err
	}
	if err = validateTargetMiBFields(target); err != nil {
		return 0, 0, 0, err
	}
	total = target.Capacity.VRAMTotalBytes
	reserve = target.Capacity.VRAMReserveBytes
	hardCap = target.Capacity.VRAMHardCapBytes
	if total <= 0 && target.AcceleratorVRAMMB > 0 {
		if total, err = checkedMiBToBytes(target.AcceleratorVRAMMB, "accelerator_vram_mb"); err != nil {
			return 0, 0, 0, err
		}
	}
	if reserve <= 0 && target.VRAMReserveMB > 0 {
		if reserve, err = checkedMiBToBytes(target.VRAMReserveMB, "vram_reserve_mb"); err != nil {
			return 0, 0, 0, err
		}
	}
	if hardCap <= 0 {
		hardCap = total
	}
	if total > 0 && hardCap > total {
		hardCap = total
	}
	return total, reserve, hardCap, nil
}

func (m *Manager) capacityForModel(ctx context.Context, target Target, model string) (*store.ModelCapacity, error) {
	profileID := target.ActiveRuntimeProfile
	capacity, err := m.store.GetModelCapacity(ctx, target.ID, model, profileID)
	if err == nil {
		if bindingErr := validateCapacityBinding(capacity, target, time.Now().UTC()); bindingErr != nil {
			return nil, bindingErr
		}
		return capacity, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	// Older targets only had a measured standalone VRAM envelope. Preserve
	// that API while making it explicit that profile bytes are unknown.
	return nil, store.ErrNotFound
}

func (m *Manager) checkResidentCapacity(ctx context.Context, target Target, requested string) error {
	return m.checkResidentCapacityExcluding(ctx, target, requested, "")
}

func (m *Manager) checkResidentCapacityForWorkload(ctx context.Context, target Target, requested, workloadID string) error {
	return m.checkResidentCapacityExcluding(ctx, target, requested, workloadID)
}

func (m *Manager) checkExclusiveUnmeasuredPlacement(target Target, excludeWorkloadID string) error {
	m.placementMu.Lock()
	defer m.placementMu.Unlock()
	for _, placement := range m.activePlacements {
		if placement.workloadID == excludeWorkloadID || placement.targetID == target.ID {
			continue
		}
		if placement.acceleratorID == target.AcceleratorID {
			return fmt.Errorf("unmeasured model cannot share accelerator %s with active target %s", target.AcceleratorID, placement.targetID)
		}
	}
	return nil
}

func (m *Manager) checkResidentCapacityExcluding(ctx context.Context, target Target, requested, excludeWorkloadID string) error {
	total, reserve, hardCap, capacityErr := targetCapacityBytes(target)
	if capacityErr != nil {
		return capacityErr
	}
	if err := m.validateActivePlacementBytes(target.AcceleratorID); err != nil {
		return err
	}
	// An active placement without a separately measured incremental/KV byte
	// value is not treated as zero: the runtime's advertised slot/profile hard
	// cap is the only honest bound. This protects the N+1 request while letting
	// all N slots share one physical resident footprint below.
	m.placementMu.Lock()
	activeSlots := m.targetActive[target.ID]
	for _, placement := range m.activePlacements {
		if placement.targetID == target.ID && placement.workloadID == excludeWorkloadID {
			activeSlots--
			break
		}
	}
	slots := target.Slots
	if pool, pooled := modelPool(target, requested); pooled {
		slots = pool.Slots
	}
	if slots <= 0 {
		slots = 1
	}
	if activeSlots >= slots {
		m.placementMu.Unlock()
		return fmt.Errorf("runtime slot/profile cap %d reached", slots)
	}
	m.placementMu.Unlock()
	hasVRAMBudget := total > 0 || hardCap > 0
	hasRAMBudget := target.Capacity.RAMTotalBytes > 0 || target.Capacity.RAMHardCapBytes > 0
	requestedCapacity, requestedErr := m.capacityForModel(ctx, target, requested)
	if errors.Is(requestedErr, store.ErrNotFound) && !target.Cloud && target.AcceleratorID != "" && requested != "" {
		// Runtimes such as plain llama.cpp do not report per-model bytes. A
		// never-measured model may still run, bounded by the slot cap above,
		// but only while no other target holds work on the same accelerator:
		// it can never be co-placed through byte accounting it cannot satisfy.
		// A model measured under another profile is drift, not "unmeasured".
		prior, err := m.store.ListModelCapacities(ctx, target.ID, requested)
		if err != nil {
			return fmt.Errorf("read model capacity history: %w", err)
		}
		if len(prior) == 0 {
			return m.checkExclusiveUnmeasuredPlacement(target, excludeWorkloadID)
		}
	}
	enforceVRAM := hasVRAMBudget
	if !hasVRAMBudget && !hasRAMBudget {
		// Preserve the legacy no-budget path for cloud/nonphysical and
		// non-model work, but never certify a local physical model placement
		// without a measured model capacity and an enforceable runtime cap.
		if requestedErr != nil || requestedCapacity.RuntimeHardCapBytes <= 0 {
			if !target.Cloud && target.AcceleratorID != "" && requested != "" {
				return fmt.Errorf("physical model request has no enforceable measured capacity budget")
			}
			return nil
		}
	}
	limit := hardCap
	if limit <= 0 {
		limit = total
	}
	if limit <= 0 {
		limit = math.MaxInt64
	}
	rows, err := m.store.ListModelResidencies(ctx)
	if err != nil {
		return fmt.Errorf("read resident capacity: %w", err)
	}
	if err := m.validatePhysicalAcceleratorEnvelope(ctx, target); err != nil {
		return err
	}
	usedVRAM, usedRAM := int64(0), int64(0)
	reserveVRAM := reserve
	reserveRAM := target.Capacity.RAMReserveBytes
	effectiveHardCap := limit
	unifiedMemory := !hasVRAMBudget && hasRAMBudget
	type modelContribution struct{ vram, ram int64 }
	countedAllocations := make(map[string]modelContribution)
	for _, row := range rows {
		if row.ObservedTier != domain.ResidencyHotVRAM {
			continue
		}
		if row.AcceleratorID != "" && row.AcceleratorID != target.AcceleratorID {
			continue
		}
		rowTarget := target
		if row.TargetID != target.ID {
			rowTarget = m.targetByID(row.TargetID)
			if rowTarget.ID == "" || rowTarget.AcceleratorID != target.AcceleratorID {
				continue
			}
		}
		capacity, lookupErr := m.capacityForModel(ctx, rowTarget, row.Model)
		if lookupErr != nil {
			return fmt.Errorf("capacity measurement missing for resident model %s", row.Model)
		}
		footprint := capacity.FootprintBytes()
		if footprint <= 0 {
			return fmt.Errorf("capacity measurement invalid for resident model %s", row.Model)
		}
		ramFootprint := capacity.RAMBytes
		rowUnified := rowTarget.Capacity.VRAMTotalBytes <= 0 && rowTarget.Capacity.VRAMHardCapBytes <= 0 && rowTarget.Capacity.RAMTotalBytes > 0
		if ramFootprint == 0 && rowUnified {
			ramFootprint = footprint
		}
		vramFootprint := int64(0)
		if !unifiedMemory || !rowUnified {
			vramFootprint = footprint
		}
		allocationKey := modelCapacityAllocationKey(capacity)
		prior := countedAllocations[allocationKey]
		if vramFootprint > prior.vram {
			usedVRAM, err = addCapacityBytes(usedVRAM, vramFootprint-prior.vram)
			if err != nil {
				return err
			}
			prior.vram = vramFootprint
		}
		if ramFootprint > prior.ram {
			usedRAM, err = addCapacityBytes(usedRAM, ramFootprint-prior.ram)
			if err != nil {
				return err
			}
			prior.ram = ramFootprint
		}
		countedAllocations[allocationKey] = prior
		if capacity.RuntimeHardCapBytes > 0 && capacity.RuntimeHardCapBytes < effectiveHardCap {
			effectiveHardCap = capacity.RuntimeHardCapBytes
		}
		if capacity.RuntimeHardCapBytes > 0 {
			enforceVRAM = true
		}
	}
	if requestedErr != nil {
		return fmt.Errorf("capacity measurement missing for requested model %s", requested)
	}
	requestedBytes := requestedCapacity.FootprintBytes()
	if requestedBytes <= 0 {
		return fmt.Errorf("capacity measurement invalid for requested model %s", requested)
	}
	requestedRAMBytes := requestedCapacity.RAMBytes
	if requestedRAMBytes == 0 && unifiedMemory {
		requestedRAMBytes = requestedBytes
	}
	requestedVRAMBytes := int64(0)
	if !unifiedMemory {
		requestedVRAMBytes = requestedBytes
	}
	requestedAllocationKey := modelCapacityAllocationKey(requestedCapacity)
	prior := countedAllocations[requestedAllocationKey]
	if requestedVRAMBytes > prior.vram {
		usedVRAM, err = addCapacityBytes(usedVRAM, requestedVRAMBytes-prior.vram)
		if err != nil {
			return err
		}
		prior.vram = requestedVRAMBytes
	}
	if requestedRAMBytes > prior.ram {
		usedRAM, err = addCapacityBytes(usedRAM, requestedRAMBytes-prior.ram)
		if err != nil {
			return err
		}
		prior.ram = requestedRAMBytes
	}
	countedAllocations[requestedAllocationKey] = prior
	if requestedCapacity.RuntimeHardCapBytes > 0 && requestedCapacity.RuntimeHardCapBytes < effectiveHardCap {
		effectiveHardCap = requestedCapacity.RuntimeHardCapBytes
	}
	if requestedCapacity.RuntimeHardCapBytes > 0 {
		enforceVRAM = true
	}
	// Snapshot active requests under the placement fence, then do store reads
	// without holding it. Unknown increments are accepted only when the
	// identity-bound initialized profile pool already includes them and its
	// verified slot/context bounds cover the active request.
	m.placementMu.Lock()
	placements := make([]activePlacement, 0, len(m.activePlacements))
	for _, placement := range m.activePlacements {
		if placement.acceleratorID == target.AcceleratorID {
			placements = append(placements, placement)
		}
	}
	m.placementMu.Unlock()
	poolUsers, poolSlots := 0, 0
	poolIdentity := ""
	for _, placement := range placements {
		if placement.model == "" {
			continue
		}
		activeTarget := m.targetByID(placement.targetID)
		if activeTarget.ID == "" || activeTarget.Cloud || activeTarget.AcceleratorID != target.AcceleratorID ||
			placement.acceleratorID != target.AcceleratorID || placement.targetGeneration == 0 ||
			m.targetGeneration(activeTarget.ID) != placement.targetGeneration ||
			activeTarget.ActiveRuntimeProfile != placement.profileID ||
			residencyCapacityIdentity(activeTarget) != placement.runtimeIdentity {
			return fmt.Errorf("active physical allocation binding is stale for workload %s", placement.workloadID)
		}
		activeCapacity, capacityErr := m.capacityForModel(ctx, activeTarget, placement.model)
		if capacityErr != nil {
			return fmt.Errorf("capacity measurement missing for active allocation %s/%s: %w", activeTarget.ID, placement.model, capacityErr)
		}
		activeFootprint := activeCapacity.FootprintBytes()
		if activeFootprint <= 0 {
			return fmt.Errorf("capacity measurement invalid for active allocation %s/%s", activeTarget.ID, placement.model)
		}
		activeRAMFootprint := activeCapacity.RAMBytes
		activeUnified := activeTarget.Capacity.VRAMTotalBytes <= 0 && activeTarget.Capacity.VRAMHardCapBytes <= 0 && activeTarget.Capacity.RAMTotalBytes > 0
		if activeRAMFootprint == 0 && activeUnified {
			activeRAMFootprint = activeFootprint
		}
		activeVRAMFootprint := int64(0)
		if !unifiedMemory || !activeUnified {
			activeVRAMFootprint = activeFootprint
		}
		activeAllocationKey := modelCapacityAllocationKey(activeCapacity)
		priorFootprint := countedAllocations[activeAllocationKey]
		if activeVRAMFootprint > priorFootprint.vram {
			usedVRAM, err = addCapacityBytes(usedVRAM, activeVRAMFootprint-priorFootprint.vram)
			if err != nil {
				return err
			}
			priorFootprint.vram = activeVRAMFootprint
		}
		if activeRAMFootprint > priorFootprint.ram {
			usedRAM, err = addCapacityBytes(usedRAM, activeRAMFootprint-priorFootprint.ram)
			if err != nil {
				return err
			}
			priorFootprint.ram = activeRAMFootprint
		}
		countedAllocations[activeAllocationKey] = priorFootprint
		footprintCharged := priorFootprint.vram > 0 || priorFootprint.ram > 0
		if activeCapacity.RuntimeHardCapBytes > 0 && activeCapacity.RuntimeHardCapBytes < effectiveHardCap {
			effectiveHardCap = activeCapacity.RuntimeHardCapBytes
		}
		if activeCapacity.RuntimeHardCapBytes > 0 {
			enforceVRAM = true
		}
		profileSlots, profileIdentity := m.verifiedProfileSlotBound(placement)
		if profileSlots > 0 {
			if poolIdentity != "" && poolIdentity != profileIdentity {
				return fmt.Errorf("active requests disagree on the initialized physical profile pool")
			}
			poolIdentity, poolSlots = profileIdentity, profileSlots
			poolUsers++
		}
		if !placement.requestIncrementVerified {
			if !m.verifiedProfileCoversRequest(placement, activeCapacity, footprintCharged) || profileSlots <= 0 {
				return fmt.Errorf("request increment is unknown and no verified initialized profile/slot/context bound covers workload %s", placement.workloadID)
			}
			// This pool is included once in ModelCapacity.ProfileBytes above.
			continue
		}
		if placement.requestIncrementBytes < 0 {
			return fmt.Errorf("active request increment is negative")
		}
		if unifiedMemory {
			usedRAM, err = addCapacityBytes(usedRAM, placement.requestIncrementBytes)
		} else {
			usedVRAM, err = addCapacityBytes(usedVRAM, placement.requestIncrementBytes)
		}
		if err != nil {
			return err
		}
	}
	if poolUsers > poolSlots {
		return fmt.Errorf("active request count %d exceeds verified physical profile slot cap %d", poolUsers, poolSlots)
	}
	withReserve, err := addCapacityBytes(usedVRAM, reserveVRAM)
	if err != nil {
		return err
	}
	if enforceVRAM && (withReserve > effectiveHardCap || (total > 0 && withReserve > total)) {
		return fmt.Errorf("measured resident capacity %d bytes exceeds target budget %d bytes", withReserve, effectiveHardCap)
	}
	if target.Capacity.RAMTotalBytes > 0 {
		ramLimit := target.Capacity.RAMHardCapBytes
		if ramLimit <= 0 || ramLimit > target.Capacity.RAMTotalBytes {
			ramLimit = target.Capacity.RAMTotalBytes
		}
		withRAMReserve, ramErr := addCapacityBytes(usedRAM, reserveRAM)
		if ramErr != nil {
			return ramErr
		}
		if withRAMReserve > ramLimit {
			return fmt.Errorf("measured unified-memory capacity %d bytes exceeds target budget %d bytes", withRAMReserve, ramLimit)
		}
	}
	return nil
}

func (m *Manager) verifiedProfileCoversRequest(placement activePlacement, capacity *store.ModelCapacity, footprintCharged bool) bool {
	profileSlots, _ := m.verifiedProfileSlotBound(placement)
	return profileSlots > 0 && footprintCharged && capacity != nil && capacity.ProfileID == placement.profileID && capacity.ProfileBytes > 0
}

func modelCapacityAllocationKey(capacity *store.ModelCapacity) string {
	if capacity == nil {
		return ""
	}
	// Target + runtime/profile/model binding identifies the single initialized
	// allocation represented by this durable capacity row. In particular, the
	// model name alone is not an allocation identity: two targets/runtimes on
	// one physical accelerator may each hold a separate copy.
	return strings.Join([]string{capacity.TargetID, capacity.Model, capacity.ProfileID, capacity.RuntimeIdentity, capacity.ModelFingerprint}, "\x00")
}

func (m *Manager) verifiedProfileSlotBound(placement activePlacement) (int, string) {
	if placement.targetID == "" || placement.model == "" || placement.targetGeneration == 0 || placement.profileID == "" || placement.contextTokens <= 0 {
		return 0, ""
	}
	target := m.targetByID(placement.targetID)
	if target.ID == "" || target.AcceleratorID != placement.acceleratorID || target.ActiveRuntimeProfile != placement.profileID || residencyCapacityIdentity(target) != placement.runtimeIdentity || target.ContextLimit <= 0 || placement.contextTokens > target.ContextLimit || target.Slots <= 0 || !target.CapacityVerified || target.CapacitySource != "runtime:/slots" || m.targetGeneration(target.ID) != placement.targetGeneration {
		return 0, ""
	}
	profileMatches := 0
	for _, profile := range target.RuntimeProfiles {
		if profile.ID == placement.profileID && profile.Slots == target.Slots && profile.ContextLimit == target.ContextLimit && profile.Slots > 0 && profile.ContextLimit > 0 {
			profileMatches++
		}
	}
	if profileMatches != 1 {
		return 0, ""
	}
	return target.Slots, fmt.Sprintf("%s|%d|%d", placement.profileID, target.ContextLimit, target.Slots)
}

func (m *Manager) validatePhysicalAcceleratorEnvelope(ctx context.Context, target Target) error {
	if target.AcceleratorID == "" {
		return fmt.Errorf("capacity measurement is missing physical accelerator identity for target %s", target.ID)
	}
	capacities, err := m.store.ListModelCapacities(ctx, "", "")
	if err != nil {
		return fmt.Errorf("read physical accelerator capacity envelopes: %w", err)
	}
	var canonical *store.ModelCapacity
	for _, capacity := range capacities {
		if capacity.AcceleratorID != target.AcceleratorID {
			continue
		}
		rowTarget := m.targetByID(capacity.TargetID)
		if rowTarget.ID == "" || capacity.ProfileID != rowTarget.ActiveRuntimeProfile {
			continue
		}
		if err := validateCapacityBinding(capacity, rowTarget, time.Now().UTC()); err != nil {
			return fmt.Errorf("capacity envelope for %s/%s is invalid: %w", capacity.TargetID, capacity.Model, err)
		}
		if canonical == nil {
			copy := *capacity
			canonical = &copy
			continue
		}
		if capacity.VRAMTotalBytes != canonical.VRAMTotalBytes || capacity.RAMTotalBytes != canonical.RAMTotalBytes || capacity.VRAMReserveBytes != canonical.VRAMReserveBytes || capacity.RAMReserveBytes != canonical.RAMReserveBytes || capacity.RuntimeHardCapBytes != canonical.RuntimeHardCapBytes || capacity.UnifiedMemory != canonical.UnifiedMemory {
			return fmt.Errorf("physical accelerator %s has conflicting measured capacity envelopes", target.AcceleratorID)
		}
	}
	return nil
}

func addCapacityBytes(left, right int64) (int64, error) {
	if left < 0 || right < 0 || right > math.MaxInt64-left {
		return 0, fmt.Errorf("capacity byte total overflows int64")
	}
	return left + right, nil
}

func (m *Manager) validateActivePlacementBytes(acceleratorID string) error {
	if acceleratorID == "" {
		return nil
	}
	m.placementMu.Lock()
	defer m.placementMu.Unlock()
	for _, placement := range m.activePlacements {
		if placement.acceleratorID != acceleratorID {
			continue
		}
		if _, err := checkedMiBToBytes(placement.vramMB, "active placement vram_mb"); err != nil {
			return err
		}
		if placement.requestIncrementBytes < 0 || (!placement.requestIncrementVerified && placement.requestIncrementBytes != 0) {
			return fmt.Errorf("active request increment is invalid")
		}
	}
	return nil
}

func (m *Manager) modelHasActiveDemand(model string) bool {
	m.placementMu.Lock()
	defer m.placementMu.Unlock()
	for _, placement := range m.activePlacements {
		if placement.model == model {
			return true
		}
	}
	return false
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

// operatorWorkloadPrefix marks the synthetic workload ConfigureResidency
// uses to drive an operator's hot_vram request through demand loading.
const operatorWorkloadPrefix = "operator:"

// demandTransitionKey binds a workload's residency transition key to the
// admission lease it runs under. The store only replays a leased key for the
// exact lease that allocated it, so a per-workload key reused by a later
// admission attempt (new lease) was rejected forever: one failed attempt, e.g.
// a load refused while the node briefly reported not-ready right after the
// eviction, made every retry fail until the request's deadline. A replay under
// the same lease (restart recovery) still maps to the same key. Operator
// commands keep their caller key unscoped: it names one requested change and
// must replay across calls.
func demandTransitionKey(key, workloadID string, lease *domain.AcceleratorLease) string {
	if lease == nil || strings.HasPrefix(workloadID, operatorWorkloadPrefix) {
		return key
	}
	return fmt.Sprintf("%s:lease%d", key, lease.FencingToken)
}

func demandEvictKey(workloadID, targetID, model string, lease *domain.AcceleratorLease) string {
	return demandTransitionKey("demand-evict:"+workloadID+":"+targetID+":"+model, workloadID, lease)
}

func demandLoadKey(workloadID, targetID, model, requestKey string, lease *domain.AcceleratorLease) string {
	key := "demand-load:" + workloadID + ":" + targetID + ":" + model
	if requestKey != "" {
		key = requestKey
	}
	return demandTransitionKey(key, workloadID, lease)
}

func (m *Manager) transitionModel(ctx context.Context, lifecycle ModelLifecycleAdapter, target Target, model string, to domain.ResidencyTier, reason, actor, workloadID, idempotencyKey string, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, error) {
	// Callers may hold a pre-registration advertisement (notably admission
	// tests and recovery replay). Bind the transition fence to the current
	// normalized target before capturing its generation; otherwise benign
	// registration defaults would look like a mid-command replacement.
	if current := m.targetByID(target.ID); current.ID != "" {
		target = current
	}
	if to != domain.ResidencyHotVRAM && to != domain.ResidencyColdDisk && to != domain.ResidencyWarmRAM {
		return nil, fmt.Errorf("unsupported residency tier %q", to)
	}
	if to == domain.ResidencyWarmRAM && !targetWarmCapabilityAvailable(target) {
		return nil, fmt.Errorf("target %s does not support warm RAM offload", target.ID)
	}
	runtimeIdentity := strings.Join([]string{target.ID, target.Adapter, target.RuntimeProtocol, target.CapabilityVersion, target.ModelFingerprint}, "|")
	canonicalReason := reason + " runtime=" + runtimeIdentity
	targetGeneration := m.targetGeneration(target.ID)
	if lease != nil {
		if idempotencyKey == "" {
			currentLease, leaseErr := m.store.GetAcceleratorLease(ctx, lease.AcceleratorID)
			if leaseErr != nil {
				return nil, leaseErr
			}
			if currentLease == nil || currentLease.AcceleratorID != lease.AcceleratorID || currentLease.WorkloadID != lease.WorkloadID ||
				currentLease.FencingToken != lease.FencingToken || !currentLease.ExpiresAt.After(time.Now()) {
				return nil, fmt.Errorf("%w: leased residency transition requires the exact current lease", store.ErrResidencyTransitionConflict)
			}
			return nil, fmt.Errorf("%w: leased residency transition requires an idempotency key", store.ErrResidencyTransitionConflict)
		}
		// Fence even the manager-local high-water reconciliation below: a stale
		// or foreign leased replay must fail before it can rebind target facts.
		if _, replayErr := m.store.GetResidencyTransitionByIdempotencyForLease(ctx, idempotencyKey, lease); replayErr != nil && !errors.Is(replayErr, store.ErrNotFound) {
			return nil, replayErr
		}
	}
	// A different manager instance may have already projected a newer target
	// fence into the durable row (for example during restart replay). Advance
	// this instance above that durable high-water mark before starting a new
	// transition; an older local generation must never attempt to overwrite it.
	if projection, projectionErr := m.store.GetModelResidency(ctx, target.ID, model); projectionErr == nil {
		var reconcileErr error
		target, targetGeneration, reconcileErr = m.reconcileResidencyGeneration(target, projection, targetGeneration)
		if reconcileErr != nil {
			return nil, reconcileErr
		}
	}
	// Resolve a caller-key replay before reading the mutable current tier.
	// FromTier is part of the original canonical transition, but a successful
	// replay may occur after the model has moved; comparing it to the new live
	// tier would incorrectly evade idempotency or reject a valid replay.
	if idempotencyKey != "" {
		var existing *domain.ResidencyTransition
		var lookupErr error
		if lease != nil {
			// A leased admission replay may repair projection only after the store
			// proves this exact live lease is the immutable allocation origin.
			existing, lookupErr = m.store.GetResidencyTransitionByIdempotencyForLease(ctx, idempotencyKey, lease)
		} else {
			existing, lookupErr = m.store.GetResidencyTransitionByIdempotency(ctx, idempotencyKey)
		}
		if lookupErr == nil {
			if existing.TargetID != target.ID || existing.AcceleratorID != transitionAccelerator(target, lease) || existing.Model != model || existing.ToTier != to || existing.Reason != canonicalReason || existing.RequestedBy != actor || existing.WorkloadID != workloadID {
				return existing, fmt.Errorf("%w: canonical residency transition arguments differ", store.ErrResidencyTransitionConflict)
			}
			if existing.Status == domain.ResidencyTransitionSucceeded {
				if evidenceErr := validateAuthoritativeTransitionEvidence(existing, target, model, to); evidenceErr != nil {
					return existing, evidenceErr
				}
				// A successful transition is authoritative across controller
				// reconstruction. Repair a stale residency projection before
				// returning the exact durable replay, without dispatching again.
				projection, projectionErr := m.store.GetModelResidency(ctx, target.ID, model)
				if projectionErr != nil {
					return existing, fmt.Errorf("load residency projection for durable replay: %w", projectionErr)
				}
				// A restart may legitimately publish a newer target generation
				// (for example, learned capacity was restored before registration)
				// while the idempotent lifecycle result remains the same. Project the
				// already-authoritative result under the current fence without
				// rewriting the historical transition or letting its older generation
				// win a durable CAS.
				if existing.TargetGeneration != targetGeneration || existing.ExecutionFingerprint != targetExecutionFingerprint(target) {
					projection.ObservedTier = existing.ObservedTier
					projection.DesiredTier = existing.ToTier
					projection.WarmModelBytes = existing.WarmModelBytes
					projection.WarmModelBytesVerified = existing.WarmModelBytesVerified
					projection.LastError = ""
					projection.UpdatedAt = time.Now().UTC()
					bindResidencyTargetFacts(projection, target, targetGeneration)
					if normalizeErr := normalizeResidencyTier(projection, existing.ObservedTier, existing.WarmModelBytes, existing.WarmModelBytesVerified); normalizeErr != nil {
						return existing, normalizeErr
					}
					if persistErr := m.persistResidencyProjection(ctx, projection, projection.Revision); persistErr != nil {
						return existing, fmt.Errorf("repair residency projection from durable transition: %w", persistErr)
					}
					return existing, nil
				}
				if err := m.acceptSucceededResidencyTransition(ctx, existing, target, projection, projection.Revision, targetGeneration); err != nil {
					return existing, fmt.Errorf("repair residency projection from durable transition: %w", err)
				}
				return existing, nil
			}
			return existing, fmt.Errorf("residency transition %s is %s", existing.ID, existing.Status)
		}
		if !errors.Is(lookupErr, store.ErrNotFound) {
			return nil, lookupErr
		}
	}
	willBeResident := to == domain.ResidencyHotVRAM
	if hasExact(target.ResidentModels, model) != willBeResident && targetGeneration == ^uint64(0) {
		return nil, fmt.Errorf("target %s execution generation is exhausted; residency transition cannot publish its resident-model change", target.ID)
	}
	residency, err := m.store.GetModelResidency(ctx, target.ID, model)
	if err != nil {
		return nil, err
	}
	residencyRevision := residency.Revision
	transition := &domain.ResidencyTransition{
		ID: newID("rtr"), IdempotencyKey: idempotencyKey, TargetID: target.ID,
		AcceleratorID: transitionAccelerator(target, lease), Model: model, FromTier: residency.ObservedTier,
		ToTier: to, Reason: canonicalReason, RequestedBy: actor, WorkloadID: workloadID,
		CapabilityVersion: target.CapabilityVersion, CapabilityRevision: target.CapabilityRevision,
		Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC(),
		TargetGeneration: targetGeneration, ExecutionFingerprint: targetExecutionFingerprint(target),
	}
	if lease != nil {
		transition.FencingToken = lease.FencingToken
	}
	var created bool
	if lease != nil {
		transition, created, err = m.store.AllocateResidencyTransitionWithLease(ctx, transition, lease)
	} else {
		transition, created, err = m.store.AllocateResidencyTransition(ctx, transition)
	}
	if err != nil {
		return nil, err
	}
	if lease != nil && (!transition.LeaseOriginAllocated || transition.LeaseOriginAcceleratorID != lease.AcceleratorID ||
		transition.LeaseOriginWorkloadID != lease.WorkloadID || transition.LeaseOriginFencingToken != lease.FencingToken ||
		transition.FencingToken < lease.FencingToken) {
		return transition, fmt.Errorf("%w: leased residency allocation did not return its exact store-issued origin", store.ErrResidencyTransitionConflict)
	}
	if !created {
		if transition.Status == domain.ResidencyTransitionSucceeded {
			projection, projectionErr := m.store.GetModelResidency(ctx, target.ID, model)
			if projectionErr != nil {
				return transition, projectionErr
			}
			if err := m.acceptSucceededResidencyTransition(ctx, transition, target, projection, projection.Revision, targetGeneration); err != nil {
				return transition, err
			}
			return transition, nil
		}
		return transition, fmt.Errorf("residency transition %s is %s", transition.ID, transition.Status)
	}
	started := time.Now().UTC()
	transition.StartedAt = &started
	transition.Status = domain.ResidencyTransitionRunning
	if casErr := m.casResidencyTransition(ctx, transition); casErr != nil {
		return transition, fmt.Errorf("persist residency transition start: %w", casErr)
	}
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
	if target.AcceleratorID != "" {
		err = m.setGPUPerformanceProfile(runCtx, target.AcceleratorID, "active", "gpu-power:active:residency:"+transition.ID)
		if err == nil {
			defer func() {
				idleCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if idleErr := m.setGPUPerformanceProfile(idleCtx, target.AcceleratorID, "idle", "gpu-power:idle:residency:"+transition.ID); idleErr != nil {
					m.log.Warn("GPU idle transition after model residency failed", "accelerator_id", target.AcceleratorID, "error", idleErr)
				}
			}()
		}
	}
	var observation ResidencyObservation
	if err == nil {
		// A refresh can retire or replace the route while the power-profile
		// command is pending. Do not dispatch a lifecycle operation against a
		// stale target snapshot.
		if !m.targetFenceMatches(target, targetGeneration) {
			err = fmt.Errorf("transition target changed before dispatch")
		}
	}
	if err == nil {
		localNode := target.AcceleratorID != "" && !target.Cloud && m.nodes != nil
		if localNode {
			control, nodeID, ok := m.nodeControlForTarget(runCtx, target)
			m.mu.RLock()
			controllerAdapter := m.controllerResidency
			m.mu.RUnlock()
			if !ok || control == nil || controllerAdapter == nil || !m.nodeReady(runCtx, nodeID) {
				err = &ResidencyAdapterError{Code: ResidencyBlockerNodeNotReady, Operation: "transition", TargetID: target.ID, Model: model, Message: "owning node is offline or not ready", Retryable: true}
			} else {
				observation, err = controllerAdapter.TransitionWithNodeIDFromTier(runCtx, target, model, residency.ObservedTier, to, idempotencyKey, nodeID)
			}
		} else if to == domain.ResidencyHotVRAM {
			err = lifecycle.LoadModel(runCtx, target, model)
		} else if to == domain.ResidencyColdDisk {
			err = lifecycle.UnloadModel(runCtx, target, model)
		} else if warm, ok := lifecycle.(WarmRAMLifecycleAdapter); ok {
			err = warm.OffloadModelToRAM(runCtx, target, model)
		} else {
			err = fmt.Errorf("adapter does not implement warm RAM offload")
		}
		if err == nil && !localNode && to != domain.ResidencyWarmRAM {
			if observer, ok := lifecycle.(interface {
				ObserveResidencyExpected(context.Context, Target, string, domain.ResidencyTier) (ResidencyObservation, error)
			}); ok {
				observation, err = observer.ObserveResidencyExpected(runCtx, target, model, to)
			} else if observer, ok := lifecycle.(ResidencyObserver); ok {
				observation, err = observer.ObserveResidency(runCtx, target, model)
			} else {
				err = fmt.Errorf("lifecycle adapter did not provide authoritative residency observation")
			}
		}
	}
	if err == nil && !m.refreshStableLifecycleTarget(&target, &targetGeneration) {
		// The runtime result is now stale. Preserve only a durable reconciling
		// transition; never apply its tier or bytes to a replacement target.
		transition.Status = domain.ResidencyTransitionRunning
		transition.Error = "reconciling: transition target changed during external operation"
		m.persistResidencyTransition(context.Background(), transition)
		m.mu.Lock()
		m.recoveryTransitions[transition.ID] = struct{}{}
		m.mu.Unlock()
		return transition, fmt.Errorf("transition target changed during external operation")
	}
	if err != nil && err.Error() == "transition target changed before dispatch" {
		transition.Status = domain.ResidencyTransitionFailed
		transition.Error = err.Error()
		m.persistResidencyTransition(context.Background(), transition)
		return transition, err
	}
	if err == nil && lease != nil {
		if leaseErr := takeLeaseError(leaseErrors); leaseErr != nil {
			err = fmt.Errorf("accelerator lease lost: %w", leaseErr)
		} else if renewErr := m.store.RenewAcceleratorLease(context.Background(), lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); renewErr != nil {
			err = fmt.Errorf("accelerator lease lost before transition completion: %w", renewErr)
		}
	}
	if !m.refreshStableLifecycleTarget(&target, &targetGeneration) {
		transition.Status = domain.ResidencyTransitionRunning
		transition.Error = "reconciling: transition target changed before persistence"
		m.persistResidencyTransition(context.Background(), transition)
		m.mu.Lock()
		m.recoveryTransitions[transition.ID] = struct{}{}
		m.mu.Unlock()
		return transition, fmt.Errorf("transition target changed before persistence")
	}
	finished := time.Now().UTC()
	if err != nil {
		var adapterErr *ResidencyAdapterError
		if errors.As(err, &adapterErr) && adapterErr.IsIndeterminate() {
			// A timeout, cancellation, stale/late result, or rollback failure
			// means the runtime may still have changed. Keep the transition
			// running and let restart/reconciliation observe before dispatching
			// another fenced command.
			transition.Status = domain.ResidencyTransitionRunning
			transition.Error = "reconciling: " + err.Error()
			residency.LastError = transition.Error
			residency.UpdatedAt = finished
			bindResidencyTargetFacts(residency, target, targetGeneration)
			if projectionErr := m.persistResidencyProjection(ctx, residency, residencyRevision); projectionErr != nil {
				m.log.Warn("preserve newer residency projection after indeterminate transition", "target", target.ID, "model", model, "error", projectionErr)
			}
			m.persistResidencyTransition(context.Background(), transition)
			m.mu.Lock()
			m.recoveryTransitions[transition.ID] = struct{}{}
			m.mu.Unlock()
			m.auditActor(context.Background(), actor, "", workloadID, "residency.transition.reconciling", "warn", transition)
			return transition, err
		}
		transition.FinishedAt = &finished
		transition.Status = domain.ResidencyTransitionFailed
		transition.Error = err.Error()
		residency.LastError = err.Error()
		residency.UpdatedAt = finished
		bindResidencyTargetFacts(residency, target, targetGeneration)
		if projectionErr := m.persistResidencyProjection(ctx, residency, residencyRevision); projectionErr != nil {
			m.log.Warn("preserve newer residency projection after failed transition", "target", target.ID, "model", model, "error", projectionErr)
		}
		m.persistResidencyTransition(context.Background(), transition)
		m.auditActor(context.Background(), actor, "", workloadID, "residency.transition.failed", "error", transition)
		return transition, err
	}

	transition.FinishedAt = &finished
	transition.ObservedTier = observation.Tier
	transition.WarmModelBytes = observation.WarmModelBytes
	transition.WarmModelBytesVerified = observation.WarmModelBytesVerified
	transition.RuntimeIdentity = observation.RuntimeIdentity
	transition.ObservedFence = int64(observation.FencingToken)
	if observation.RuntimeIdentity != "" {
		transition.Error = fmt.Sprintf("observed tier=%s warm_model_bytes=%d locked_bytes=%d released_vram=%t runtime=%s fence=%d", observation.Tier, observation.WarmModelBytes, observation.LockedBytes, observation.VRAMReleased, observation.RuntimeIdentity, observation.FencingToken)
	}
	residency.ObservedTier = to
	residency.DesiredTier = to
	if to == domain.ResidencyWarmRAM {
		residency.WarmModelBytes = observation.WarmModelBytes
		residency.WarmModelBytesVerified = observation.WarmModelBytesVerified
	}
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
	if err := m.acceptSucceededResidencyTransition(ctx, transition, target, residency, residencyRevision, targetGeneration); err != nil {
		transition.Status = domain.ResidencyTransitionFailed
		transition.Error = "runtime changed state but residency acceptance failed: " + err.Error()
		m.persistResidencyTransition(context.Background(), transition)
		_ = m.setTargetResident(target.ID, model, to == domain.ResidencyHotVRAM, targetGeneration)
		m.auditActor(context.Background(), actor, "", workloadID, "residency.transition.persistence_failed", "error", transition)
		return transition, err
	}
	if residentErr := m.setTargetResident(target.ID, model, to == domain.ResidencyHotVRAM, targetGeneration); residentErr != nil {
		return transition, residentErr
	}
	m.auditActor(context.Background(), actor, "", workloadID, "residency.transition.succeeded", "info", transition)
	return transition, nil
}

func (m *Manager) nodeReady(ctx context.Context, nodeID string) bool {
	if m.nodes == nil || nodeID == "" {
		return false
	}
	node, err := m.nodes.GetNode(ctx, nodeID)
	return err == nil && node != nil && node.Observed.Ready && node.Observed.Connectivity == domain.ConnectivityConnected
}

// transitionAccelerator is the GPU a residency transition is recorded and
// fenced on: the target's own, or - for a target spanning several GPUs
// evicted by a neighbour on one of them - the shared GPU whose lease the
// caller holds.
func transitionAccelerator(target Target, lease *domain.AcceleratorLease) string {
	if lease != nil && lease.AcceleratorID != target.AcceleratorID && containsString(targetAccelerators(target), lease.AcceleratorID) {
		return lease.AcceleratorID
	}
	return target.AcceleratorID
}

// reclaimLease picks the lease that fences evicting foreign: selected's own
// when foreign uses that GPU, otherwise selected's companion lease on a GPU
// foreign uses (a split target evicting the per-card router of its second
// GPU).
func (m *Manager) reclaimLease(selected, foreign Target, lease *domain.AcceleratorLease) *domain.AcceleratorLease {
	if lease == nil || containsString(targetAccelerators(foreign), lease.AcceleratorID) {
		return lease
	}
	m.companions.mu.Lock()
	defer m.companions.mu.Unlock()
	if hold := m.companions.holds[selected.ID]; hold != nil {
		for _, companion := range hold.leases {
			if containsString(targetAccelerators(foreign), companion.AcceleratorID) {
				return companion
			}
		}
	}
	return lease
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
		if foreign.ID == selected.ID || !targetsShareAccelerator(foreign, selected) || m.targetActiveCount(foreign.ID) > 0 {
			continue
		}
		if (selected.ComfyUI || foreign.ComfyUI) && strings.EqualFold(selected.Adapter, "comfy") && strings.EqualFold(foreign.Adapter, "comfy") {
			// The web UI target fronts the same ComfyUI process as the managed
			// harness on its accelerator; ComfyUI manages VRAM between its own
			// jobs, and freeing its cache would reload every model each run.
			continue
		}
		if foreign.QueueRunning > 0 || foreign.QueuePending > 0 {
			// Busy counters arrive with periodic node advertisements. Counters
			// published before the LB's last release on that target are stale
			// (the request just finished): reclaim as if idle. Skipping instead
			// started Comfy work beside a still-loaded LLM model and ran the card
			// out of memory. Fresh counters mean work the LB is not tracking.
			if !m.runtimeQueueCountersStale(foreign) {
				if foreign.SupportsModelLifecycle && foreign.Enabled {
					return transitionIDs, fmt.Errorf("foreign target %s on the same accelerator reports running or queued work", foreign.ID)
				}
				continue
			}
		}
		adapter := adapters[foreign.Adapter]
		if foreign.SupportsModelLifecycle {
			lifecycle, ok := adapter.(ModelLifecycleAdapter)
			if !ok {
				return transitionIDs, fmt.Errorf("target %s advertises model lifecycle without an implementation", foreign.ID)
			}
			models := append([]string(nil), foreign.ResidentModels...)
			if rows, listErr := m.store.ListModelResidencies(ctx); listErr == nil {
				seen := make(map[string]struct{}, len(models))
				for _, model := range models {
					seen[model] = struct{}{}
				}
				for _, row := range rows {
					if row.TargetID == foreign.ID && row.ObservedTier == domain.ResidencyHotVRAM {
						if _, exists := seen[row.Model]; !exists {
							models = append(models, row.Model)
							seen[row.Model] = struct{}{}
						}
					}
				}
			} else {
				return transitionIDs, listErr
			}
			sort.Strings(models)
			for _, model := range models {
				residency, err := m.store.GetModelResidency(ctx, foreign.ID, model)
				if err != nil || residency.ObservedTier != domain.ResidencyHotVRAM {
					continue
				}
				if residency.Policy == domain.ResidencyPinned || residency.Policy == domain.ResidencyManual || residency.Policy == domain.ResidencyOff {
					return transitionIDs, fmt.Errorf("foreign resident %s on %s is protected by %s policy", model, foreign.ID, residency.Policy)
				}
				if m.modelHasActiveDemand(model) || m.modelHasQueuedDemand(ctx, model) {
					return transitionIDs, fmt.Errorf("foreign resident %s on %s is protected by active or queued demand", model, foreign.ID)
				}
				fence := m.reclaimLease(selected, foreign, lease)
				transition, err := m.transitionModel(ctx, lifecycle, foreign, model, domain.ResidencyColdDisk, "cross_adapter_reclaim", workload.Request.OwnerID, workload.Request.ID, demandTransitionKey("cross-adapter:"+workload.Request.ID+":"+foreign.ID+":"+model, workload.Request.ID, fence), fence)
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
		if foreign.ResidencyPolicy == domain.ResidencyPinned || foreign.ResidencyPolicy == domain.ResidencyManual || foreign.ResidencyPolicy == domain.ResidencyOff {
			return transitionIDs, fmt.Errorf("foreign managed Comfy target %s is protected by %s policy", foreign.ID, foreign.ResidencyPolicy)
		}
		if m.targetHasQueuedDemand(ctx, foreign.ID) {
			return transitionIDs, fmt.Errorf("foreign managed Comfy target %s is protected by queued demand", foreign.ID)
		}
		reclaimer, ok := adapter.(AcceleratorReclaimer)
		if !ok {
			continue
		}
		transition, err := m.transitionRuntimeCache(ctx, reclaimer, foreign, workload, m.reclaimLease(selected, foreign, lease), "cross_adapter_reclaim")
		if transition != nil {
			transitionIDs = append(transitionIDs, transition.ID)
		}
		if err != nil {
			return transitionIDs, err
		}
	}
	return transitionIDs, nil
}

func (m *Manager) targetHasQueuedDemand(ctx context.Context, targetID string) bool {
	rows, err := m.store.ListWorkloads(ctx)
	if err != nil {
		return true
	}
	for _, workload := range rows {
		if workload.Status != domain.WorkloadQueued && workload.Status != domain.WorkloadWaiting {
			continue
		}
		if workload.Decision.TargetID == targetID || workload.Plan != nil && workload.Plan.TargetID == targetID {
			return true
		}
	}
	return false
}

func (m *Manager) transitionRuntimeCache(ctx context.Context, reclaimer AcceleratorReclaimer, target Target, workload *domain.Workload, lease *domain.AcceleratorLease, reason string) (*domain.ResidencyTransition, error) {
	// Native ComfyUI exposes /free without a correlated post-state. Only the
	// managed harness protocol may be allowed to cross this side-effecting
	// boundary, and only when its advertised capability is explicit.
	if !target.SupportsAcceleratorReclaim || (strings.EqualFold(target.Adapter, "comfy") && (target.RuntimeProtocol != managedComfyProtocol || strings.TrimSpace(target.CapabilityVersion) == "" || target.CapabilityRevision != domain.CapabilityContractVersion)) {
		return nil, fmt.Errorf("runtime cache reclaim unsupported: backend lacks correlated authoritative status")
	}
	targetGeneration := m.targetGeneration(target.ID)
	if !m.targetFenceMatches(target, targetGeneration) {
		return nil, fmt.Errorf("transition target changed before dispatch")
	}
	transition := &domain.ResidencyTransition{
		// Keyed per lease: a retry under a new fence is a new reclaim (the old
		// key with new arguments was refused and blocked the request).
		ID: newID("rtr"), IdempotencyKey: reason + ":" + workload.Request.ID + ":" + target.ID + ":runtime-cache:" + leaseFenceKey(lease),
		TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: "runtime-cache",
		FromTier: domain.ResidencyHotVRAM, ToTier: domain.ResidencyColdDisk,
		Reason: reason, RequestedBy: workload.Request.OwnerID, WorkloadID: workload.Request.ID,
		CapabilityVersion: target.CapabilityVersion, CapabilityRevision: target.CapabilityRevision,
		Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC(),
	}
	if lease != nil {
		transition.FencingToken = lease.FencingToken
	}
	transition, created, err := m.store.AllocateResidencyTransition(ctx, transition)
	if err != nil || !created {
		if err == nil && transition.Status != domain.ResidencyTransitionSucceeded {
			err = fmt.Errorf("runtime-cache transition %s is %s", transition.ID, transition.Status)
		}
		return transition, err
	}
	started := time.Now().UTC()
	transition.StartedAt, transition.Status = &started, domain.ResidencyTransitionRunning
	m.persistResidencyTransition(ctx, transition)
	m.auditActor(ctx, workload.Request.OwnerID, "", workload.Request.ID, "residency.transition.started", "info", transition)

	transitionCtx, cancel := context.WithTimeout(ctx, m.residency.TransitionTimeout)
	defer cancel()
	var observation ResidencyObservation
	if observer, ok := reclaimer.(AcceleratorReclaimObserver); ok && target.RuntimeProtocol == managedComfyProtocol {
		// The managed harness measures the post-state itself; the node agent
		// only knows native ComfyUI, whose /free reports nothing.
		observation, err = observer.ReclaimAcceleratorObserved(transitionCtx, target, transition.FencingToken)
	} else if control, nodeID, ok := m.nodeControlForTarget(transitionCtx, target); ok {
		identity, _, identityErr := canonicalResidencyIdentity(target, "runtime-cache", false)
		if identityErr != nil {
			err = identityErr
		} else {
			result, commandErr := control(transitionCtx, nodeID, "reclaim_accelerator", map[string]any{"target_id": target.ID, "model": "runtime-cache", "runtime_identity": identity, "capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision, "expected_tier": string(domain.ResidencyColdDisk), "fencing_token": transition.FencingToken}, transition.IdempotencyKey)
			err = commandErr
			if err == nil {
				observedFence, fenceOK := exactResultUint(result["fencing_token"])
				observedTier := strings.TrimSpace(fmt.Sprint(result["tier"]))
				observedIdentity := strings.TrimSpace(fmt.Sprint(result["runtime_identity"]))
				observation = ResidencyObservation{TargetID: target.ID, Model: "runtime-cache", RuntimeIdentity: observedIdentity, Tier: domain.ResidencyTier(observedTier), FencingToken: observedFence}
				if observation.RuntimeIdentity == "" || observedIdentity != identity || strings.TrimSpace(fmt.Sprint(result["capability_version"])) != target.CapabilityVersion || strings.TrimSpace(fmt.Sprint(result["capability_revision"])) != target.CapabilityRevision || !fenceOK || observedFence != uint64(transition.FencingToken) || observedTier != string(domain.ResidencyColdDisk) || strings.TrimSpace(fmt.Sprint(result["target_id"])) != target.ID || strings.TrimSpace(fmt.Sprint(result["model"])) != "runtime-cache" {
					err = fmt.Errorf("reclaim result lacks authoritative runtime identity or fence")
				}
			}
		}
	} else {
		observer, ok := reclaimer.(AcceleratorReclaimObserver)
		if !ok {
			err = fmt.Errorf("runtime cache reclaim lacks authoritative post-state observer")
		} else {
			observation, err = observer.ReclaimAcceleratorObserved(transitionCtx, target, transition.FencingToken)
		}
	}
	if err == nil && !m.refreshStableLifecycleTarget(&target, &targetGeneration) {
		transition.Status = domain.ResidencyTransitionRunning
		transition.Error = "reconciling: transition target changed during external operation"
		m.persistResidencyTransition(context.Background(), transition)
		m.mu.Lock()
		m.recoveryTransitions[transition.ID] = struct{}{}
		m.mu.Unlock()
		return transition, fmt.Errorf("transition target changed during external operation")
	}
	finished := time.Now().UTC()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "observation_unavailable") || strings.Contains(strings.ToLower(err.Error()), "unresolved") {
			// A reclaim side effect crossed the node boundary, but no authoritative
			// post-state exists. Keep the transition running/recoverable with its
			// exact fence instead of falsely terminalizing it as failed.
			transition.Status = domain.ResidencyTransitionRunning
			transition.Error = err.Error()
			m.persistResidencyTransition(ctx, transition)
			m.auditActor(ctx, workload.Request.OwnerID, "", workload.Request.ID, "residency.transition.indeterminate", "warn", transition)
			return transition, err
		}
		transition.FinishedAt = &finished
		transition.Status, transition.Error = domain.ResidencyTransitionFailed, err.Error()
		m.persistResidencyTransition(ctx, transition)
		m.auditActor(ctx, workload.Request.OwnerID, "", workload.Request.ID, "residency.transition.failed", "error", transition)
		return transition, err
	}
	transition.ObservedTier = observation.Tier
	transition.RuntimeIdentity = observation.RuntimeIdentity
	transition.CapabilityVersion = target.CapabilityVersion
	transition.CapabilityRevision = target.CapabilityRevision
	transition.ObservedFence = int64(observation.FencingToken)
	if err := m.acceptSucceededResidencyTransition(ctx, transition, target, nil, 0, targetGeneration); err != nil {
		return transition, err
	}
	m.auditActor(ctx, workload.Request.OwnerID, "", workload.Request.ID, "residency.transition.succeeded", "info", transition)
	return transition, nil
}

func (m *Manager) setTargetResident(targetID, model string, resident bool, expectedGeneration ...uint64) error {
	generation := uint64(0)
	if len(expectedGeneration) > 0 {
		generation = expectedGeneration[0]
	}
	// Resident-model publication advances the route generation. Serialize it
	// with profile dispatch/result lifecycle before taking admission or target
	// locks, and never mutate an unresolved profile ticket's generation.
	releaseProfileTicket := m.lockRuntimeProfileTransitionForTarget(targetID)
	defer releaseProfileTicket()
	if !m.targetFenceMatches(m.targetByID(targetID), generation) {
		return fmt.Errorf("transition target changed before resident mutation")
	}
	m.residencyAdmissionMu.Lock()
	defer m.residencyAdmissionMu.Unlock()
	fence := m.residencyAdmissionLock(targetID)
	fence.Lock()
	defer fence.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	target, ok := m.targets[targetID]
	if !ok {
		return fmt.Errorf("target %s is no longer advertised", targetID)
	}
	if generation > 0 && m.targetGenerations[targetID] != generation {
		return fmt.Errorf("transition target changed before resident mutation")
	}
	profileKey := m.runtimeProfileTransitionTarget[targetID]
	profileTransition := m.runtimeProfileTransitions[profileKey]
	if profileTransition != nil && !profileTransition.projected {
		return fmt.Errorf("runtime profile observation_unavailable; resident mutation cannot change an unresolved profile generation")
	}
	residentModels := append([]string(nil), target.ResidentModels...)
	if resident && !hasExact(residentModels, model) {
		residentModels = append(residentModels, model)
	}
	if !resident {
		filtered := make([]string, 0, len(residentModels))
		for _, current := range residentModels {
			if current != model {
				filtered = append(filtered, current)
			}
		}
		residentModels = filtered
	}
	target.ResidentModels = residentModels
	if err := m.replaceTargetLocked(target); err != nil {
		if m.targetGenerations[targetID] == ^uint64(0) {
			// The observed resident set is authoritative, but its generation
			// cannot safely advance. Retire the route instead of continuing to
			// schedule against stale residency metadata.
			m.invalidateTargetAtExhaustedGenerationLocked(targetID, m.targets[targetID])
			m.signal()
		}
		return err
	}
	m.refreshRuntimeProfileProjectedGenerationLocked(target)
	return nil
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
	residencyRevision := residency.Revision
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
	_ = m.persistResidencyProjection(ctx, residency, residencyRevision)
}

func (m *Manager) reconcileResidency(ctx context.Context) {
	releaseOperation, operationErr := m.beginResidencyOperation(ctx)
	if operationErr != nil {
		return
	}
	defer releaseOperation()
	m.reconcileMu.Lock()
	options := m.residency
	now := time.Now().UTC()
	if !options.Enabled {
		m.reconcileMu.Unlock()
		return
	}
	if !m.lastResidencySweep.IsZero() && now.Sub(m.lastResidencySweep) < options.ReconcileInterval {
		m.reconcileMu.Unlock()
		return
	}
	m.lastResidencySweep = now
	m.reconcileMu.Unlock()
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
	// Scan the durable transition inventory directly. Reclaim transitions may
	// legitimately have no ModelResidency projection, so recovery cannot be
	// discovered only by walking projections.
	transitions, transitionErr := m.store.ListResidencyTransitions(ctx, -1)
	if transitionErr != nil {
		m.log.Warn("list residency transitions for recovery", "err", transitionErr)
		return
	}
	recovered := make(map[string]struct{})
	for _, transition := range transitions {
		if transition != nil && recoverableResidencyTransition(transition) {
			recovered[transition.ID] = struct{}{}
		}
	}
	// Keep the projection walk as a compatibility fallback for stores that
	// return transition rows without complete target metadata.
	residencies, err := m.store.ListModelResidencies(ctx)
	if err != nil {
		m.log.Warn("list residency transitions for recovery", "err", err)
		residencies = nil
	}
	for _, residency := range residencies {
		if residency == nil {
			continue
		}
		rows, listErr := m.store.ListActiveResidencyTransitions(ctx, residency.TargetID, residency.Model)
		if listErr != nil {
			m.log.Warn("list resource residency transitions for recovery", "target", residency.TargetID, "model", residency.Model, "err", listErr)
			continue
		}
		for _, transition := range rows {
			if transition != nil {
				recovered[transition.ID] = struct{}{}
			}
		}
	}
	m.mu.Lock()
	for transitionID := range recovered {
		m.recoveryTransitions[transitionID] = struct{}{}
	}
	m.mu.Unlock()
}

func recoverableResidencyTransition(transition *domain.ResidencyTransition) bool {
	if transition == nil {
		return false
	}
	return transition.Status == domain.ResidencyTransitionPlanned || transition.Status == domain.ResidencyTransitionRunning || (transition.Status == domain.ResidencyTransitionSucceeded && transition.ProjectionRepairPending)
}

func (m *Manager) recoverRegisteredResidencyTransitions(ctx context.Context) {
	m.recoverPendingResidencyObservations(ctx)
	m.mu.RLock()
	targetIDs := make([]string, 0, len(m.targets))
	seen := make(map[string]struct{}, len(m.targets))
	for targetID := range m.targets {
		targetIDs = append(targetIDs, targetID)
		seen[targetID] = struct{}{}
	}
	recoveryIDs := make([]string, 0, len(m.recoveryTransitions))
	for transitionID := range m.recoveryTransitions {
		recoveryIDs = append(recoveryIDs, transitionID)
	}
	m.mu.RUnlock()
	for _, transitionID := range recoveryIDs {
		if transition, err := m.store.GetResidencyTransition(ctx, transitionID); err == nil && transition != nil {
			if _, exists := seen[transition.TargetID]; !exists {
				targetIDs = append(targetIDs, transition.TargetID)
				seen[transition.TargetID] = struct{}{}
			}
		}
	}
	for _, targetID := range targetIDs {
		m.recoverResidencyTransitionsForTarget(ctx, targetID)
	}
}

// recoverPendingResidencyObservations retains node-discovered targets whose
// initial durable observation failed. Registration is the durable inventory
// boundary: a later reconnect re-registers the same target, while this map
// keeps retries alive across recovery-worker restarts without doing store I/O
// under m.mu.
func (m *Manager) recoverPendingResidencyObservations(ctx context.Context) {
	m.mu.RLock()
	pending := make([]pendingResidencyObservation, 0, len(m.pendingResidencyObservations))
	for _, observation := range m.pendingResidencyObservations {
		pending = append(pending, observation)
	}
	m.mu.RUnlock()
	for _, observation := range pending {
		if ctx.Err() != nil {
			return
		}
		if !m.observeTargetResidency(ctx, observation.target) {
			continue
		}
		m.mu.Lock()
		if current, exists := m.pendingResidencyObservations[observation.target.ID]; exists && current.generation == observation.generation {
			delete(m.pendingResidencyObservations, observation.target.ID)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) recoverResidencyTransitionsForTarget(ctx context.Context, targetID string) {
	m.mu.RLock()
	hasRecovery := len(m.recoveryTransitions) > 0
	m.mu.RUnlock()
	if !hasRecovery {
		return
	}
	allTransitions, err := m.store.ListResidencyTransitions(ctx, -1)
	if err != nil {
		return
	}
	rows := make([]*domain.ResidencyTransition, 0)
	for _, candidate := range allTransitions {
		if candidate != nil && candidate.TargetID == targetID && recoverableResidencyTransition(candidate) {
			rows = append(rows, candidate)
		}
	}
	for _, transition := range rows {
		m.mu.RLock()
		_, recovering := m.recoveryTransitions[transition.ID]
		m.mu.RUnlock()
		if !recovering || transition.TargetID != targetID {
			continue
		}
		if transition.Status != domain.ResidencyTransitionPlanned && transition.Status != domain.ResidencyTransitionRunning && !(transition.Status == domain.ResidencyTransitionSucceeded && transition.ProjectionRepairPending) {
			m.mu.Lock()
			delete(m.recoveryTransitions, transition.ID)
			m.mu.Unlock()
			continue
		}
		target := m.targetByID(transition.TargetID)
		// Capture the route fence before any projection/node/store wait in this
		// recovery attempt. Acceptance must use this snapshot, never a newly
		// read generation after an external command has returned.
		targetGeneration := m.targetGeneration(transition.TargetID)
		residency, err := m.store.GetModelResidency(ctx, transition.TargetID, transition.Model)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				m.mu.RLock()
				controllerAdapter := m.controllerResidency
				m.mu.RUnlock()
				// A managed harness may provide an exact target/command/fence
				// query even when runtime-cache has no model projection. Use that
				// protocol only when the target advertises the correlated reclaim
				// capability; native ComfyUI never reaches this branch.
				if transition.Model == "runtime-cache" && controllerAdapter != nil && target.ID != "" && target.SupportsAcceleratorReclaim && target.RuntimeProtocol == managedComfyProtocol {
					nodeID := mustNodeID(target)
					if nodeID != "" && m.nodeReady(ctx, nodeID) {
						observation, reconcileErr := controllerAdapter.TransitionWithNodeIDFromTier(ctx, target, transition.Model, transition.FromTier, transition.ToTier, transition.IdempotencyKey, nodeID)
						if reconcileErr == nil {
							transition.ObservedTier = observation.Tier
							transition.RuntimeIdentity = observation.RuntimeIdentity
							transition.CapabilityVersion = target.CapabilityVersion
							transition.CapabilityRevision = target.CapabilityRevision
							transition.ObservedFence = int64(observation.FencingToken)
							if acceptErr := m.acceptSucceededResidencyTransition(ctx, transition, target, nil, 0, targetGeneration); acceptErr == nil {
								m.mu.Lock()
								delete(m.recoveryTransitions, transition.ID)
								m.mu.Unlock()
								continue
							}
						}
						var adapterErr *ResidencyAdapterError
						if errors.As(reconcileErr, &adapterErr) && adapterErr.IsIndeterminate() {
							continue
						}
					}
				}
				// A native Comfy reclaim has no model projection and no
				// correlation-capable query protocol. Surface a durable manual
				// reconciliation marker and stop retrying it as if it were a
				// normal model transition.
				transition.Status = domain.ResidencyTransitionManualReconciliation
				transition.Error = "no authoritative projection or correlated backend query"
				if m.persistResidencyTransition(ctx, transition) {
					m.auditActor(ctx, "residency-recovery", "", transition.WorkloadID, "residency.transition.manual_reconciliation", "warn", transition)
					m.mu.Lock()
					delete(m.recoveryTransitions, transition.ID)
					m.mu.Unlock()
				}
			}
			continue
		}
		residencyRevision := residency.Revision
		if transition.Status == domain.ResidencyTransitionSucceeded {
			// The adapter captured a complete node observation but deliberately
			// left projection repair pending. Validate the durable evidence again
			// and use the same success boundary as normal completion; a recovery
			// scan must never treat a projected tier as proof on its own.
			if target.ID == "" || validateAuthoritativeTransitionEvidence(transition, target, transition.Model, transition.ToTier) != nil {
				continue
			}
			if err := m.acceptSucceededResidencyTransition(ctx, transition, target, residency, residencyRevision, targetGeneration); err != nil {
				continue
			}
			m.mu.Lock()
			delete(m.recoveryTransitions, transition.ID)
			m.mu.Unlock()
			continue
		}
		m.mu.RLock()
		controllerAdapter := m.controllerResidency
		m.mu.RUnlock()
		if controllerAdapter != nil && strings.HasPrefix(transition.Reason, "controller-adapter rollback") && target.ID != "" && target.AcceleratorID != "" && !target.Cloud {
			nodeID := mustNodeID(target)
			if nodeID == "" || !m.nodeReady(ctx, nodeID) {
				continue
			}
			if reconcileErr := controllerAdapter.ReconcileRollbackTransition(ctx, target, transition, nodeID); reconcileErr != nil {
				var adapterErr *ResidencyAdapterError
				if errors.As(reconcileErr, &adapterErr) && adapterErr.IsIndeterminate() {
					continue
				}
				transition.Error = "rollback recovery failed: " + reconcileErr.Error()
				if !m.persistResidencyTransition(ctx, transition) {
					continue
				}
				continue
			}
			// Reconciliation persists the exact inverse observation. Reload the
			// row before completing the manager phase so a stale recovery snapshot
			// cannot erase that evidence (or a newer status/error).
			if latest, reloadErr := m.store.GetResidencyTransition(ctx, transition.ID); reloadErr == nil {
				transition = latest
			}
			if transition.Status == domain.ResidencyTransitionSucceeded {
				if evidenceErr := validateAuthoritativeTransitionEvidence(transition, target, transition.Model, transition.ToTier); evidenceErr != nil {
					continue
				}
				if transition.ProjectionRepairPending {
					projection, projectionErr := m.store.GetModelResidency(ctx, target.ID, transition.Model)
					if projectionErr != nil {
						continue
					}
					if err := m.acceptSucceededResidencyTransition(ctx, transition, target, projection, projection.Revision, targetGeneration); err != nil {
						continue
					}
				}
				m.mu.Lock()
				delete(m.recoveryTransitions, transition.ID)
				m.mu.Unlock()
				continue
			}
			finished := time.Now().UTC()
			transition.FinishedAt = &finished
			// Reconciliation may already have persisted the exact inverse
			// observation. Preserve that evidence and the request linkage instead
			// of erasing it while marking the manager row complete.
			if err := m.acceptSucceededResidencyTransition(ctx, transition, target, nil, 0, targetGeneration); err != nil {
				continue
			}
			m.mu.Lock()
			delete(m.recoveryTransitions, transition.ID)
			m.mu.Unlock()
			continue
		}
		if controllerAdapter != nil && target.ID != "" && target.AcceleratorID != "" && !target.Cloud && !strings.HasPrefix(transition.Reason, "controller-adapter rollback") {
			nodeID := mustNodeID(target)
			if nodeID == "" || !m.nodeReady(ctx, nodeID) {
				continue
			}
			observation, reconcileErr := controllerAdapter.TransitionWithNodeIDFromTier(ctx, target, transition.Model, transition.FromTier, transition.ToTier, transition.IdempotencyKey, nodeID)
			if reconcileErr != nil {
				var adapterErr *ResidencyAdapterError
				if errors.As(reconcileErr, &adapterErr) && adapterErr.IsIndeterminate() {
					continue
				}
				finished := time.Now().UTC()
				transition.FinishedAt = &finished
				transition.Status = domain.ResidencyTransitionFailed
				transition.Error = "controller residency recovery failed: " + reconcileErr.Error()
				if !m.persistResidencyTransition(ctx, transition) {
					continue
				}
				m.mu.Lock()
				delete(m.recoveryTransitions, transition.ID)
				m.mu.Unlock()
				continue
			}
			finished := time.Now().UTC()
			transition.FinishedAt = &finished
			transition.ObservedTier = observation.Tier
			transition.WarmModelBytes = observation.WarmModelBytes
			transition.WarmModelBytesVerified = observation.WarmModelBytesVerified
			transition.RuntimeIdentity = observation.RuntimeIdentity
			transition.ObservedFence = int64(observation.FencingToken)
			// Keep the authoritative node observation on the durable transition;
			// clearing Error here would erase the exact tier/runtime/fence evidence
			// that the adapter persisted while reconciling the uncertain command.
			transition.Error = fmt.Sprintf("observed tier=%s warm_model_bytes=%d locked_bytes=%d released_vram=%t runtime=%s fence=%d", observation.Tier, observation.WarmModelBytes, observation.LockedBytes, observation.VRAMReleased, observation.RuntimeIdentity, observation.FencingToken)
			residency.ObservedTier = observation.Tier
			residency.DesiredTier = observation.Tier
			if observation.Tier == domain.ResidencyWarmRAM {
				residency.WarmModelBytes = observation.WarmModelBytes
				residency.WarmModelBytesVerified = observation.WarmModelBytesVerified
			}
			residency.LastError = ""
			residency.UpdatedAt = finished
			if err := m.acceptSucceededResidencyTransition(ctx, transition, target, residency, residencyRevision, targetGeneration); err != nil {
				continue
			}
			m.mu.Lock()
			delete(m.recoveryTransitions, transition.ID)
			m.mu.Unlock()
			continue
		}
		finished := time.Now().UTC()
		transition.FinishedAt = &finished
		evidenceCandidate := *transition
		evidenceCandidate.Status = domain.ResidencyTransitionSucceeded
		evidenceErr := validateAuthoritativeTransitionEvidence(&evidenceCandidate, target, transition.Model, transition.ToTier)
		if residency.ObservedTier == transition.ToTier && evidenceErr == nil {
			transition.Error = ""
			m.auditActor(ctx, "residency-recovery", "", transition.WorkloadID, "residency.transition.recovered", "info", transition)
		} else {
			transition.Status = domain.ResidencyTransitionRunning
			transition.Error = fmt.Sprintf("reconciliation requires authoritative transition evidence: %v", evidenceErr)
			m.auditActor(ctx, "residency-recovery", "", transition.WorkloadID, "residency.transition.reconciling", "warn", transition)
		}
		if transition.Status == domain.ResidencyTransitionRunning && evidenceErr == nil {
			if err := m.acceptSucceededResidencyTransition(ctx, transition, target, residency, residencyRevision, targetGeneration); err != nil {
				continue
			}
			m.mu.Lock()
			delete(m.recoveryTransitions, transition.ID)
			m.mu.Unlock()
		}
	}
}

func (m *Manager) expireUnresolvedResidencyTransitions(ctx context.Context, now time.Time) {
	// An age threshold cannot prove that a node-side command did not complete.
	// Keep the durable row planned/running until the original command result,
	// an authoritative runtime query, or an inverse rollback settles it.
	_ = ctx
	_ = now
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
	if ctx == nil {
		return nil, nil, fmt.Errorf("residency configuration context is required")
	}
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
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// Capture the target fence before the durable read so the helper can
	// reject a stale writer snapshot if a runtime-profile result projects while
	// that store operation is in flight.
	targetGeneration := m.targetGeneration(targetID)
	residency, err := m.store.GetModelResidency(ctx, targetID, model)
	if err != nil {
		return nil, nil, err
	}
	if residency == nil {
		return nil, nil, fmt.Errorf("model residency snapshot is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	releaseOperation, operationErr := m.beginResidencyOperation(ctx)
	if operationErr != nil {
		return nil, nil, operationErr
	}
	defer releaseOperation()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	target, targetGeneration, err = m.reconcileResidencyGenerationContext(ctx, target, residency, targetGeneration)
	if err != nil {
		return residency, nil, err
	}
	if err := ctx.Err(); err != nil {
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
	if desired == domain.ResidencyWarmRAM && !targetWarmCapabilityAvailable(target) {
		return nil, nil, fmt.Errorf("target %s does not support warm RAM offload", target.ID)
	}
	if desired == domain.ResidencyWarmRAM {
		lifecycle, ok := m.adapterLifecycle(target.Adapter)
		m.mu.RLock()
		controllerAvailable := m.controllerResidency != nil && target.AcceleratorID != "" && !target.Cloud && m.nodes != nil
		m.mu.RUnlock()
		if !ok && !controllerAvailable {
			return nil, nil, fmt.Errorf("adapter %s does not implement model lifecycle", target.Adapter)
		}
		if ok {
			if _, lifecycleWarm := lifecycle.(WarmRAMLifecycleAdapter); !lifecycleWarm && !controllerAvailable {
				return nil, nil, fmt.Errorf("adapter %s does not implement warm RAM offload", target.Adapter)
			}
		}
	}
	residencyRevision := residency.Revision
	if !m.targetFenceMatches(target, targetGeneration) {
		return residency, nil, fmt.Errorf("transition target changed during residency configuration")
	}
	residency.DesiredTier = desired
	residency.UpdatedAt = time.Now().UTC()
	bindResidencyTargetFacts(residency, target, targetGeneration)
	if err := m.persistResidencyProjection(ctx, residency, residencyRevision); err != nil {
		return nil, nil, err
	}
	if residency.Policy != previousPolicy {
		m.auditActor(ctx, actor, "", "", "residency.policy.updated", "info", map[string]any{"target_id": targetID, "model": model, "from": previousPolicy, "to": residency.Policy})
	}
	if desired == residency.ObservedTier {
		if existing, transitionErr := m.store.GetResidencyTransitionByIdempotency(ctx, idempotencyKey); transitionErr == nil && existing != nil {
			if evidenceErr := validateAuthoritativeTransitionEvidence(existing, target, model, desired); evidenceErr != nil {
				return nil, nil, evidenceErr
			}
			residency.ObservedTier = existing.ObservedTier
			residency.DesiredTier = existing.ObservedTier
			residency.WarmModelBytes = existing.WarmModelBytes
			residency.WarmModelBytesVerified = existing.WarmModelBytesVerified
			if err := normalizeResidencyTier(residency, existing.ObservedTier, existing.WarmModelBytes, existing.WarmModelBytesVerified); err != nil {
				return nil, nil, err
			}
			residencyRevision = residency.Revision
			bindResidencyTargetFacts(residency, target, targetGeneration)
			if err := m.persistResidencyProjection(ctx, residency, residencyRevision); err != nil {
				return nil, nil, err
			}
			return residency, []*domain.ResidencyTransition{existing}, nil
		}
		return residency, nil, nil
	}
	if !targetLifecycleCapabilityAvailable(target) {
		return residency, nil, fmt.Errorf("target %s does not support model lifecycle", target.ID)
	}
	if m.targetActiveCount(target.ID) != 0 {
		return residency, nil, fmt.Errorf("target %s must drain before changing residency", target.ID)
	}
	lifecycle, ok := m.adapterLifecycle(target.Adapter)
	if !ok && target.AcceleratorID != "" && !target.Cloud && m.nodes != nil {
		m.mu.RLock()
		lifecycle = m.controllerResidency
		m.mu.RUnlock()
		ok = lifecycle != nil
	}
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
		fake := &domain.Workload{Request: domain.WorkloadRequest{ID: operatorWorkloadPrefix + idempotencyKey, IdempotencyKey: idempotencyKey, OwnerID: actor}}
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
		transition, err := m.transitionModel(ctx, lifecycle, target, model, desired, "operator_request", actor, "", idempotencyKey, reservation.lease)
		if err != nil {
			return residency, []*domain.ResidencyTransition{transition}, err
		}
		transitions = append(transitions, transition)
	}
	updated, err := m.store.GetModelResidency(ctx, targetID, model)
	return updated, transitions, err
}

func transitionsForIDs(ctx context.Context, backing store.WorkloadStore, ids []string) []*domain.ResidencyTransition {
	result := make([]*domain.ResidencyTransition, 0, len(ids))
	for _, id := range ids {
		if row, err := backing.GetResidencyTransition(ctx, id); err == nil && row != nil {
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
	releaseOperation, operationErr := m.beginResidencyOperation(ctx)
	if operationErr != nil {
		return nil, operationErr
	}
	defer releaseOperation()
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

// runtimeQueueCountersStale reports whether the node's busy counters predate
// the controller's last release on this target while nothing of ours still
// runs there. Counters arrive with the periodic advertisement (~30 s), so a
// request that just finished otherwise blocks demand eviction until the next
// refresh; counters for work outside the LB still protect residents.
func (m *Manager) runtimeQueueCountersStale(target Target) bool {
	m.placementMu.Lock()
	active := m.targetActive[target.ID]
	released := m.targetReleasedAt[target.ID]
	m.placementMu.Unlock()
	m.mu.RLock()
	advertised := m.targetAdvertisedAt[target.ID]
	m.mu.RUnlock()
	return active == 0 && !released.IsZero() && !advertised.IsZero() && advertised.Before(released)
}

func leaseFenceKey(lease *domain.AcceleratorLease) string {
	if lease == nil {
		return "no-lease"
	}
	return strconv.FormatInt(lease.FencingToken, 10)
}
