package workloads

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/wsproto"
)

// ResidencyBlockerCode is deliberately stable.  API layers may add human
// detail, but schedulers and clients should branch only on these values.
type ResidencyBlockerCode string

// ResidencyTransitionOutcome separates a definitive rejection from an
// uncertain command whose runtime may still be applying or reconciling. The
// latter must remain durable and fenced before another command is admitted.
type ResidencyTransitionOutcome string

const (
	ResidencyOutcomeTerminalFailed ResidencyTransitionOutcome = "terminal_failed"
	ResidencyOutcomeIndeterminate  ResidencyTransitionOutcome = "indeterminate"
)

const (
	ResidencyBlockerCapabilityUnavailable ResidencyBlockerCode = "capability_unavailable"
	ResidencyBlockerRuntimeUnsupported    ResidencyBlockerCode = "runtime_unsupported"
	ResidencyBlockerIdentityMismatch      ResidencyBlockerCode = "identity_mismatch"
	ResidencyBlockerNodeNotReady          ResidencyBlockerCode = "node_not_ready"
	ResidencyBlockerTransitionBusy        ResidencyBlockerCode = "transition_busy"
	ResidencyBlockerTransitionTimeout     ResidencyBlockerCode = "transition_timeout"
	ResidencyBlockerStaleResult           ResidencyBlockerCode = "stale_result"
	ResidencyBlockerRollbackFailed        ResidencyBlockerCode = "rollback_failed"
	ResidencyBlockerCommandFailed         ResidencyBlockerCode = "command_failed"
)

// ResidencyAdapterError is safe to expose to an admission layer.  Cause is
// retained for errors.Is/errors.As by the caller but never included in the
// stable Error string (node responses may contain backend-specific detail).
type ResidencyAdapterError struct {
	Code              ResidencyBlockerCode       `json:"code"`
	Operation         string                     `json:"operation"`
	TargetID          string                     `json:"target_id"`
	Model             string                     `json:"model"`
	RuntimeIdentity   string                     `json:"runtime_identity"`
	FencingToken      uint64                     `json:"fencing_token"`
	IdempotencyKey    string                     `json:"idempotency_key"`
	Retryable         bool                       `json:"retryable"`
	RollbackAttempted bool                       `json:"rollback_attempted"`
	RollbackSucceeded bool                       `json:"rollback_succeeded"`
	Message           string                     `json:"message"`
	Cause             error                      `json:"-"`
	Outcome           ResidencyTransitionOutcome `json:"outcome"`
}

func (e *ResidencyAdapterError) Error() string {
	if e == nil {
		return "residency adapter error"
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *ResidencyAdapterError) Unwrap() error { return e.Cause }

func (e *ResidencyAdapterError) IsIndeterminate() bool {
	return e != nil && e.Outcome == ResidencyOutcomeIndeterminate
}

// ResidencyObservation is the controller's transactional view of a model.
// Warm RAM is considered observed only when the node reports both an
// authoritative warm proof and released accelerator memory.
type ResidencyObservation struct {
	TargetID               string               `json:"target_id"`
	Model                  string               `json:"model"`
	RuntimeIdentity        string               `json:"runtime_identity"`
	Tier                   domain.ResidencyTier `json:"tier"`
	WarmModelBytes         int64                `json:"warm_model_bytes,omitempty"`
	LockedBytes            int64                `json:"locked_bytes,omitempty"`
	WarmModelBytesVerified bool                 `json:"warm_model_bytes_verified"`
	VRAMReleased           bool                 `json:"vram_released"`
	FencingToken           uint64               `json:"fencing_token"`
	IdempotencyKey         string               `json:"idempotency_key"`
}

type residencyPending struct {
	Operation       string
	TargetID        string
	Model           string
	RuntimeIdentity string
	Tier            domain.ResidencyTier
	FencingToken    uint64
	IdempotencyKey  string
	StartedAt       time.Time
}

// ControllerResidencyAdapter is the controller-side implementation of the
// lifecycle interfaces.  Its command function is the API's signed node
// command boundary; it is intentionally not an HTTP client to a runtime.
type ControllerResidencyAdapter struct {
	name              string
	version           string
	command           NodeControl
	store             store.WorkloadStore
	transitionTimeout time.Duration
	pollInterval      time.Duration

	mu        sync.Mutex
	fences    map[string]uint64
	pending   map[string]residencyPending
	completed map[string]ResidencyObservation
}

type ControllerResidencyAdapterOptions struct {
	Name              string
	Version           string
	Command           NodeControl
	TransitionTimeout time.Duration
	PollInterval      time.Duration
	Store             store.WorkloadStore
}

func NewControllerResidencyAdapter(options ControllerResidencyAdapterOptions) *ControllerResidencyAdapter {
	name := strings.TrimSpace(options.Name)
	if name == "" {
		name = "controller-residency"
	}
	version := strings.TrimSpace(options.Version)
	if version == "" {
		version = domain.CapabilityContractVersion
	}
	timeout := options.TransitionTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	interval := options.PollInterval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	if interval > timeout {
		interval = timeout
	}
	return &ControllerResidencyAdapter{
		name: name, version: version, command: options.Command,
		store:             options.Store,
		transitionTimeout: timeout, pollInterval: interval,
		fences: make(map[string]uint64), pending: make(map[string]residencyPending),
		completed: make(map[string]ResidencyObservation),
	}
}

// NewControllerResidencyAdapterWithCommand is a compact compatibility
// constructor for controller wiring that already has a node command closure.
func NewControllerResidencyAdapterWithCommand(name string, command NodeControl) *ControllerResidencyAdapter {
	return NewControllerResidencyAdapter(ControllerResidencyAdapterOptions{Name: name, Command: command})
}

func (a *ControllerResidencyAdapter) Name() string    { return a.name }
func (a *ControllerResidencyAdapter) Version() string { return a.version }

// PendingTransitions returns a stable snapshot useful to restart/reconcile
// code.  A timed-out command remains pending because its node-side effect is
// unknown; retrying it under a new idempotency key would be unsafe.
func (a *ControllerResidencyAdapter) PendingTransitions() []ResidencyObservation {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]ResidencyObservation, 0, len(a.pending))
	for _, pending := range a.pending {
		result = append(result, ResidencyObservation{TargetID: pending.TargetID, Model: pending.Model, RuntimeIdentity: pending.RuntimeIdentity, Tier: pending.Tier, FencingToken: pending.FencingToken, IdempotencyKey: pending.IdempotencyKey})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IdempotencyKey < result[j].IdempotencyKey })
	return result
}

func (a *ControllerResidencyAdapter) LoadModel(ctx context.Context, target Target, model string) error {
	_, err := a.transition(ctx, target, model, domain.ResidencyHotVRAM, "load_model", false, "", "")
	return err
}

func (a *ControllerResidencyAdapter) UnloadModel(ctx context.Context, target Target, model string) error {
	_, err := a.transition(ctx, target, model, domain.ResidencyColdDisk, "unload_model", false, "", "")
	return err
}

func (a *ControllerResidencyAdapter) OffloadModelToRAM(ctx context.Context, target Target, model string) error {
	_, err := a.transition(ctx, target, model, domain.ResidencyWarmRAM, "offload_model", true, "", "")
	return err
}

// Transition is exported for controller code that needs the resulting
// observation.  The regular lifecycle interfaces intentionally return only an
// error to remain compatible with existing schedulers.
func (a *ControllerResidencyAdapter) Transition(ctx context.Context, target Target, model string, tier domain.ResidencyTier) (ResidencyObservation, error) {
	command := map[domain.ResidencyTier]string{domain.ResidencyHotVRAM: "load_model", domain.ResidencyColdDisk: "unload_model", domain.ResidencyWarmRAM: "offload_model"}[tier]
	if command == "" {
		return ResidencyObservation{}, &ResidencyAdapterError{Code: ResidencyBlockerRuntimeUnsupported, Operation: "transition", TargetID: target.ID, Model: model, Message: "unsupported residency tier"}
	}
	return a.transition(ctx, target, model, tier, command, tier == domain.ResidencyWarmRAM, "", "")
}

// TransitionWithIdempotency is used by the durable manager path when a caller
// supplies an explicit retry identity. Empty keys create a new generation.
func (a *ControllerResidencyAdapter) TransitionWithIdempotency(ctx context.Context, target Target, model string, tier domain.ResidencyTier, idempotency string) (ResidencyObservation, error) {
	return a.transitionWithNode(ctx, target, model, tier, idempotency, "")
}

// TransitionWithNodeID is the production manager path. The node registry is
// authoritative for ownership, so it may provide a node ID even when a legacy
// accelerator identifier predates the node-gpuN spelling.
func (a *ControllerResidencyAdapter) TransitionWithNodeID(ctx context.Context, target Target, model string, tier domain.ResidencyTier, idempotency, nodeID string) (ResidencyObservation, error) {
	return a.transitionWithNode(ctx, target, model, tier, idempotency, nodeID)
}

// TransitionWithNodeIDFromTier is the durable manager path. The caller's
// observed FromTier is authoritative for rollback; inferring it from ToTier
// would restore a hot model to cold when it was actually warm (or vice versa).
func (a *ControllerResidencyAdapter) TransitionWithNodeIDFromTier(ctx context.Context, target Target, model string, fromTier, tier domain.ResidencyTier, idempotency, nodeID string) (ResidencyObservation, error) {
	command := map[domain.ResidencyTier]string{domain.ResidencyHotVRAM: "load_model", domain.ResidencyColdDisk: "unload_model", domain.ResidencyWarmRAM: "offload_model"}[tier]
	if command == "" {
		return ResidencyObservation{}, &ResidencyAdapterError{Code: ResidencyBlockerRuntimeUnsupported, Outcome: ResidencyOutcomeTerminalFailed, Operation: "transition", TargetID: target.ID, Model: model, Message: "unsupported residency tier"}
	}
	return a.transitionWithFrom(ctx, target, model, fromTier, tier, command, tier == domain.ResidencyWarmRAM, idempotency, nodeID)
}

// ReconcileRollbackTransition resumes a durable rollback phase after a
// controller restart. It deliberately reuses the persisted rollback key and
// fence instead of manufacturing a constant retry command.
func (a *ControllerResidencyAdapter) ReconcileRollbackTransition(ctx context.Context, target Target, transition *domain.ResidencyTransition, nodeID string) error {
	if transition == nil {
		return fmt.Errorf("rollback transition is missing")
	}
	identity, _, err := canonicalResidencyIdentity(target, transition.Model, transition.ToTier == domain.ResidencyWarmRAM)
	if err != nil {
		return err
	}
	request := ""
	if marker := strings.LastIndex(transition.Reason, " request="); marker >= 0 {
		request = transition.Reason[marker+len(" request="):]
	}
	return a.rollback(ctx, target, transition.Model, identity, transition.ToTier, transition.FromTier, uint64(maxInt64(transition.FencingToken-1)), nodeID, request)
}

func (a *ControllerResidencyAdapter) transitionWithNode(ctx context.Context, target Target, model string, tier domain.ResidencyTier, idempotency, nodeOverride string) (ResidencyObservation, error) {
	command := map[domain.ResidencyTier]string{domain.ResidencyHotVRAM: "load_model", domain.ResidencyColdDisk: "unload_model", domain.ResidencyWarmRAM: "offload_model"}[tier]
	if command == "" {
		return ResidencyObservation{}, &ResidencyAdapterError{Code: ResidencyBlockerRuntimeUnsupported, Operation: "transition", TargetID: target.ID, Model: model, Message: "unsupported residency tier"}
	}
	return a.transitionWithFrom(ctx, target, model, inferredResidencyFrom(tier), tier, command, tier == domain.ResidencyWarmRAM, idempotency, nodeOverride)
}

func (a *ControllerResidencyAdapter) transition(ctx context.Context, target Target, model string, tier domain.ResidencyTier, command string, warm bool, requestedKey, nodeOverride string) (ResidencyObservation, error) {
	return a.transitionWithFrom(ctx, target, model, inferredResidencyFrom(tier), tier, command, warm, requestedKey, nodeOverride)
}

func (a *ControllerResidencyAdapter) transitionWithFrom(ctx context.Context, target Target, model string, fromTier, tier domain.ResidencyTier, command string, warm bool, requestedKey, nodeOverride string) (ResidencyObservation, error) {
	identity, nodeID, err := canonicalResidencyIdentity(target, model, warm)
	if err != nil {
		return ResidencyObservation{}, err
	}
	if nodeOverride != "" {
		nodeID = nodeOverride
	}
	if nodeID == "" {
		return ResidencyObservation{}, adapterError(ResidencyBlockerNodeNotReady, "validate", target, model, identity, 0, "target has no canonical owning node", true, nil)
	}
	if a.command == nil {
		return ResidencyObservation{}, adapterError(ResidencyBlockerNodeNotReady, command, target, model, identity, 0, "signed node command boundary is unavailable", false, errNil)
	}
	key, generation, durableTransition, durableCreated, durableErr := a.prepareDurableTransition(ctx, target, model, fromTier, tier, identity, requestedKey)
	if durableErr != nil {
		return ResidencyObservation{}, durableErr
	}
	commandKey := requestedKey
	if commandKey == "" {
		commandKey = key
	}
	reconcileDurable := durableTransition != nil && !durableCreated &&
		(durableTransition.Status == domain.ResidencyTransitionPlanned || durableTransition.Status == domain.ResidencyTransitionRunning) &&
		(requestedKey == "" || durableTransition.IdempotencyKey == durableRequestKey(requestedKey))
	if durableTransition != nil && !durableCreated {
		switch durableTransition.Status {
		case domain.ResidencyTransitionSucceeded:
			// Replay only from the exact node observation persisted with the
			// transition. A manager residency row alone is not command truth and
			// must never mint a warm-RAM promise after restart.
			observation, replayErr := replayDurableObservation(durableTransition, target, model, identity, tier)
			if replayErr != nil {
				return ResidencyObservation{}, replayErr
			}
			observation.IdempotencyKey = commandKey
			return observation, nil
		case domain.ResidencyTransitionPlanned, domain.ResidencyTransitionRunning:
			if strings.HasPrefix(durableTransition.Reason, "controller-adapter runtime=") && !reconcileDurable {
				return ResidencyObservation{}, markIndeterminate(adapterError(ResidencyBlockerTransitionBusy, command, target, model, identity, uint64(maxInt64(durableTransition.FencingToken)), "transition is pending reconciliation", true, nil))
			}
		case domain.ResidencyTransitionFailed:
			return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, command, target, model, identity, uint64(maxInt64(durableTransition.FencingToken)), "idempotent transition previously failed", true, nil)
		}
	}
	a.mu.Lock()
	if previous, ok := a.pending[commandKey]; ok && !reconcileDurable {
		a.mu.Unlock()
		return ResidencyObservation{}, markIndeterminate(adapterError(ResidencyBlockerTransitionBusy, command, target, model, identity, previous.FencingToken, "transition is pending reconciliation", true, nil))
	}
	if reconcileDurable {
		delete(a.pending, commandKey)
	}
	fenceKey := identity + "\x00" + model
	if reconcileDurable {
		fence := uint64(maxInt64(durableTransition.FencingToken))
		if fence > a.fences[fenceKey] {
			a.fences[fenceKey] = fence
		}
	} else if generation > a.fences[fenceKey] {
		a.fences[fenceKey] = generation
	} else {
		a.fences[fenceKey]++
	}
	fence := a.fences[fenceKey]
	idempotency := commandKey
	a.pending[commandKey] = residencyPending{Operation: command, TargetID: target.ID, Model: model, RuntimeIdentity: identity, Tier: tier, FencingToken: fence, IdempotencyKey: idempotency, StartedAt: time.Now().UTC()}
	a.mu.Unlock()

	runCtx, cancel := context.WithTimeout(ctx, a.transitionTimeout)
	defer cancel()
	args := wsproto.CanonicalResidencyCommandArgs(target.ID, model, identity, target.CapabilityVersion, target.CapabilityRevision, string(tier), int64(fence))
	result, callErr := a.invokeNodeCommand(runCtx, nodeID, command, args, idempotency)
	if callErr != nil {
		unresolved := strings.Contains(strings.ToLower(callErr.Error()), "unresolved")
		keepPending := unresolved || errors.Is(callErr, context.DeadlineExceeded) || errors.Is(callErr, context.Canceled) || runCtx.Err() != nil
		if keepPending && strings.Contains(strings.ToLower(callErr.Error()), "unresolved") {
			// A signed command may have crossed the controller wait deadline
			// after mutating the node. Reconcile through a fresh, read-only signed
			// query before retaining the transition or issuing any inverse.
			queryTimeout := a.transitionTimeout / 2
			if queryTimeout <= 0 {
				queryTimeout = time.Second
			}
			queryCtx, queryCancel := context.WithTimeout(context.Background(), queryTimeout)
			queryArgs := wsproto.CanonicalResidencyCommandArgs(target.ID, model, identity, target.CapabilityVersion, target.CapabilityRevision, "query", int64(fence))
			queryArgs["expected_fence"] = int64(fence)
			queryArgs["observed_after_fence"] = int64(fence)
			queryArgs["original_idempotency_key"] = idempotency
			queryResult, queryErr := a.invokeNodeCommand(queryCtx, nodeID, "query_model_state", queryArgs, "controller-residency-query:"+idempotency)
			queryCancel()
			if queryErr == nil {
				if observed, queryObserveErr := observeResidencyQueryResult(queryResult, target, model, identity, tier, command, fence, idempotency); queryObserveErr == nil {
					if durableTransition != nil {
						if persistErr := a.persistTransitionObservation(context.Background(), durableTransition, observed); persistErr == nil {
							a.clearPending(commandKey)
							return observed, nil
						}
					} else {
						a.clearPending(commandKey)
						return observed, nil
					}
				}
			}
		}
		if !keepPending {
			a.clearPending(commandKey)
		}
		code := ResidencyBlockerCommandFailed
		if runCtx.Err() != nil {
			code = ResidencyBlockerTransitionTimeout
		}
		message := "node command did not complete"
		if callErr != nil {
			// Keep the node's reason (e.g. the runtime could not load the
			// model) instead of reporting only that the command failed.
			message += ": " + callErr.Error()
		}
		failure := adapterError(code, command, target, model, identity, fence, message, true, callErr)
		if runCtx.Err() != nil || unresolved {
			markIndeterminate(failure)
		}
		failure.IdempotencyKey = idempotency
		if durableTransition != nil {
			a.persistTransitionFailure(context.Background(), durableTransition, failure, keepPending)
		}
		return ResidencyObservation{}, failure
	}
	observation, observeErr := observeResidencyResult(result, target, model, identity, tier, command, fence, idempotency)
	if observeErr == nil {
		if durableTransition != nil {
			if persistErr := a.persistTransitionObservation(context.Background(), durableTransition, observation); persistErr != nil {
				failure := markIndeterminate(adapterError(ResidencyBlockerCommandFailed, command, target, model, identity, fence, "could not persist completed observation", true, persistErr))
				failure.IdempotencyKey = idempotency
				// Keep the in-memory intent until durable completion is visible;
				// the node result is not safe to replay without that record.
				return ResidencyObservation{}, failure
			}
		}
		a.mu.Lock()
		delete(a.pending, commandKey)
		a.mu.Unlock()
		return observation, nil
	}
	observeErr.IdempotencyKey = idempotency
	if observeErr.Code == ResidencyBlockerStaleResult || observeErr.Code == ResidencyBlockerIdentityMismatch {
		markIndeterminate(observeErr)
		if durableTransition != nil {
			a.persistTransitionFailure(context.Background(), durableTransition, observeErr, true)
		}
		// Late/stale results may represent a runtime mutation that completed
		// after the controller deadline. Keep the local fence until reconcile.
		return ResidencyObservation{}, observeErr
	}
	// A nil command error with an invalid tier is an observable side effect;
	// issue the inverse through the same signed boundary before reporting.
	observeErr.RollbackAttempted = true
	rollbackErr := a.rollback(runCtx, target, model, identity, fromTier, tier, fence, nodeID, idempotency)
	a.clearPending(commandKey)
	if rollbackErr != nil {
		observeErr.Code = ResidencyBlockerRollbackFailed
		markIndeterminate(observeErr)
		observeErr.RollbackSucceeded = false
		observeErr.Cause = errors.Join(observeErr.Cause, rollbackErr)
		if durableTransition != nil {
			a.persistTransitionFailure(context.Background(), durableTransition, observeErr, true)
		}
		return ResidencyObservation{}, observeErr
	}
	observeErr.RollbackSucceeded = true
	if durableTransition != nil {
		a.persistTransitionFailure(context.Background(), durableTransition, observeErr, false)
	}
	return ResidencyObservation{}, observeErr
}

func (a *ControllerResidencyAdapter) invokeNodeCommand(ctx context.Context, nodeID, command string, args map[string]any, idempotency string) (map[string]any, error) {
	resultCh := make(chan struct {
		result map[string]any
		err    error
	}, 1)
	go func() {
		result, err := a.command(ctx, nodeID, command, args, idempotency)
		resultCh <- struct {
			result map[string]any
			err    error
		}{result: result, err: err}
	}()
	ticker := time.NewTicker(a.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case completed := <-resultCh:
			return completed.result, completed.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			// The signed API command is itself the durable poll boundary. The
			// tick keeps cancellation observable without unbounded sleeps.
		}
	}
}

func inferredResidencyFrom(to domain.ResidencyTier) domain.ResidencyTier {
	switch to {
	case domain.ResidencyHotVRAM:
		return domain.ResidencyColdDisk
	case domain.ResidencyColdDisk:
		return domain.ResidencyHotVRAM
	case domain.ResidencyWarmRAM:
		return domain.ResidencyHotVRAM
	default:
		return domain.ResidencyColdDisk
	}
}

func (a *ControllerResidencyAdapter) rollback(ctx context.Context, target Target, model, identity string, fromTier, tier domain.ResidencyTier, priorFence uint64, nodeID, originalKey string) error {
	command, expectedTier := rollbackCommand(fromTier, tier)
	if command == "" {
		return fmt.Errorf("unsupported rollback from %s to %s", fromTier, tier)
	}
	rollbackKey, rollbackTransition, rollbackFence, prepareErr := a.prepareRollbackTransition(ctx, target, model, identity, fromTier, tier, priorFence, originalKey)
	if prepareErr != nil {
		return prepareErr
	}
	if rollbackTransition != nil && rollbackTransition.Status == domain.ResidencyTransitionSucceeded {
		_, replayErr := replayDurableObservation(rollbackTransition, target, model, identity, expectedTier)
		return replayErr
	}
	a.mu.Lock()
	fenceKey := identity + "\x00" + model
	if rollbackFence > a.fences[fenceKey] {
		a.fences[fenceKey] = rollbackFence
	} else if a.fences[fenceKey] <= priorFence {
		a.fences[fenceKey] = priorFence + 1
	}
	fence := a.fences[fenceKey]
	a.mu.Unlock()
	rollbackTimeout := a.transitionTimeout / 2
	if rollbackTimeout <= 0 {
		rollbackTimeout = time.Second
	}
	// Rollback is safety work.  It must not inherit a caller deadline that was
	// consumed by the failed command, but it remains independently bounded.
	rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	args := wsproto.CanonicalResidencyCommandArgs(target.ID, model, identity, target.CapabilityVersion, target.CapabilityRevision, string(expectedTier), int64(fence))
	if nodeID == "" {
		nodeID = mustNodeID(target)
	}
	result, err := a.invokeNodeCommand(rollbackCtx, nodeID, command, args, rollbackKey)
	if err != nil {
		if rollbackTransition != nil {
			a.persistTransitionFailure(context.Background(), rollbackTransition, adapterError(ResidencyBlockerRollbackFailed, command, target, model, identity, fence, "rollback command did not complete", true, err), true)
		}
		return err
	}
	if targetID, _ := result["target_id"].(string); targetID != "" && targetID != target.ID {
		err = fmt.Errorf("rollback target identity mismatch")
	}
	if err == nil {
		if resultModel, _ := result["model"].(string); resultModel != "" && resultModel != model {
			err = fmt.Errorf("rollback model identity mismatch")
		}
	}
	if err == nil {
		if _, validationErr := observeResidencyResult(result, target, model, identity, expectedTier, command, fence, rollbackKey); validationErr != nil {
			err = validationErr
		}
	}
	if err != nil {
		if rollbackTransition != nil {
			failure := adapterError(ResidencyBlockerRollbackFailed, command, target, model, identity, fence, "rollback observation did not prove the inverse state", true, err)
			keepPending := true
			var adapterErr *ResidencyAdapterError
			if errors.As(err, &adapterErr) && !adapterErr.IsIndeterminate() {
				keepPending = false
			}
			a.persistTransitionFailure(context.Background(), rollbackTransition, failure, keepPending)
		}
		return err
	}
	if rollbackTransition != nil {
		observation, _ := observeResidencyResult(result, target, model, identity, expectedTier, command, fence, rollbackKey)
		if persistErr := a.persistTransitionObservation(context.Background(), rollbackTransition, observation); persistErr != nil {
			return persistErr
		}
	}
	return nil
}

func (a *ControllerResidencyAdapter) prepareRollbackTransition(ctx context.Context, target Target, model, identity string, fromTier, tier domain.ResidencyTier, priorFence uint64, originalKey string) (string, *domain.ResidencyTransition, uint64, error) {
	prefix := "controller-residency-rollback-" + stableResidencyKey(identity+"\x00"+originalKey, model, fromTier+"->"+tier) + "-g"
	if a.store == nil {
		return prefix + "1", nil, priorFence + 1, nil
	}
	generationValue, err := a.store.MaxResidencyFencingToken(ctx, target.ID, model)
	if err != nil {
		return "", nil, 0, err
	}
	generation := uint64(maxInt64(generationValue))
	active, err := a.store.ListActiveResidencyTransitions(ctx, target.ID, model)
	if err != nil {
		return "", nil, 0, err
	}
	for _, row := range active {
		if row != nil && strings.HasPrefix(row.IdempotencyKey, prefix) {
			return row.IdempotencyKey, row, uint64(maxInt64(row.FencingToken)), nil
		}
	}
	generation++
	key := fmt.Sprintf("%s%d", prefix, generation)
	transition := &domain.ResidencyTransition{ID: "rtr-rollback-" + stableResidencyKey(identity+"\x00"+originalKey, model, fromTier+"->"+tier) + fmt.Sprintf("-g%d", generation), IdempotencyKey: key, TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: model, FromTier: tier, ToTier: fromTier, CapabilityVersion: target.CapabilityVersion, CapabilityRevision: target.CapabilityRevision, Status: domain.ResidencyTransitionPlanned, FencingToken: int64(generation), CreatedAt: time.Now().UTC(), Reason: "controller-adapter rollback runtime=" + identity + " request=" + originalKey}
	created, createdOK, err := a.store.AllocateResidencyTransition(ctx, transition)
	if err != nil {
		return "", nil, 0, err
	}
	transition = created
	generation = uint64(maxInt64(transition.FencingToken))
	if !createdOK {
		return transition.IdempotencyKey, transition, generation, nil
	}
	started := time.Now().UTC()
	transition.StartedAt = &started
	transition.Status = domain.ResidencyTransitionRunning
	err = a.casTransition(ctx, transition, func(current *domain.ResidencyTransition) {
		current.StartedAt = &started
		current.Status = domain.ResidencyTransitionRunning
	})
	if err != nil {
		return "", nil, 0, err
	}
	return key, transition, generation, nil
}

func rollbackCommand(fromTier, toTier domain.ResidencyTier) (string, domain.ResidencyTier) {
	// The inverse command must restore the observed FromTier, not merely undo
	// the requested ToTier. Warm RAM is a real state and therefore uses an
	// offload proof when it is the inverse target, while cleanup is used when
	// the original state was cold and an incomplete warm pin must be removed.
	switch fromTier {
	case domain.ResidencyHotVRAM:
		return "load_model", domain.ResidencyHotVRAM
	case domain.ResidencyColdDisk:
		if toTier == domain.ResidencyWarmRAM {
			return "cleanup_warm_model", domain.ResidencyColdDisk
		}
		return "unload_model", domain.ResidencyColdDisk
	case domain.ResidencyWarmRAM:
		return "offload_model", domain.ResidencyWarmRAM
	default:
		return "", ""
	}
}

func (a *ControllerResidencyAdapter) clearPending(key string) {
	a.mu.Lock()
	delete(a.pending, key)
	a.mu.Unlock()
}

func (a *ControllerResidencyAdapter) prepareDurableTransition(ctx context.Context, target Target, model string, fromTier, tier domain.ResidencyTier, identity, requestedKey string) (string, uint64, *domain.ResidencyTransition, bool, *ResidencyAdapterError) {
	requestedDurableKey := durableRequestKey(requestedKey)
	if a.store == nil {
		if requestedKey != "" {
			return requestedDurableKey, 0, nil, false, nil
		}
		return "residency-" + stableResidencyKey(identity, model, tier), 0, nil, true, nil
	}
	// Generation is per target/model resource, not per desired tier: a
	// load→unload→load sequence must be fenced 1→2→3.
	prefix := "controller-residency-" + stableResidencyKey(identity, model, "") + "-g"
	maxFence, err := a.store.MaxResidencyFencingToken(ctx, target.ID, model)
	if err != nil {
		return "", 0, nil, false, adapterError(ResidencyBlockerCommandFailed, "prepare", target, model, identity, 0, "could not read resource fence", true, err)
	}
	generation := uint64(maxInt64(maxFence))
	if requestedDurableKey != "" {
		row, lookupErr := a.store.GetResidencyTransitionByIdempotency(ctx, requestedDurableKey)
		if lookupErr == nil {
			if row.TargetID != target.ID || row.Model != model || row.AcceleratorID != target.AcceleratorID || row.FromTier != fromTier || row.ToTier != tier || !strings.Contains(row.Reason, "runtime="+identity) {
				return requestedKey, uint64(maxInt64(row.FencingToken)), row, false, adapterError(ResidencyBlockerIdentityMismatch, "prepare", target, model, identity, uint64(maxInt64(row.FencingToken)), "idempotency key was reused for different canonical residency arguments", false, nil)
			}
			switch row.Status {
			case domain.ResidencyTransitionSucceeded, domain.ResidencyTransitionPlanned, domain.ResidencyTransitionRunning:
				return requestedKey, uint64(maxInt64(row.FencingToken)), row, false, nil
			case domain.ResidencyTransitionFailed:
				return requestedKey, uint64(maxInt64(row.FencingToken)), row, false, adapterError(ResidencyBlockerCommandFailed, "prepare", target, model, identity, uint64(maxInt64(row.FencingToken)), "idempotent transition previously failed", true, nil)
			}
		} else if !errors.Is(lookupErr, store.ErrNotFound) {
			return "", 0, nil, false, adapterError(ResidencyBlockerCommandFailed, "prepare", target, model, identity, 0, "could not read idempotent transition", true, lookupErr)
		}
	}
	active, err := a.store.ListActiveResidencyTransitions(ctx, target.ID, model)
	if err != nil {
		return "", 0, nil, false, adapterError(ResidencyBlockerCommandFailed, "prepare", target, model, identity, generation, "could not read active resource transitions", true, err)
	}
	var pending *domain.ResidencyTransition
	for _, row := range active {
		if row == nil {
			continue
		}
		// A succeeded transition with a pending projection repair is returned
		// by the recovery query so the manager can repair its projection, but it
		// is not an in-flight node command and must not fence a new generation.
		if row.Status == domain.ResidencyTransitionSucceeded {
			continue
		}
		// A pending controller transition blocks every other tier for the same
		// target/model.  Allowing load while an unload is pending could issue a
		// late command after restart and violate the generation fence.
		if strings.HasPrefix(row.Reason, "controller-adapter runtime=") {
			copy := *row
			pending = &copy
		}
	}
	if pending != nil {
		if requestedDurableKey == "" || requestedDurableKey == pending.IdempotencyKey {
			return pending.IdempotencyKey, uint64(maxInt64(pending.FencingToken)), pending, false, nil
		}
		return requestedKey, uint64(maxInt64(pending.FencingToken)), pending, false, markIndeterminate(adapterError(ResidencyBlockerTransitionBusy, "prepare", target, model, identity, uint64(maxInt64(pending.FencingToken)), "a prior controller transition is pending reconciliation", true, nil))
	}
	if requestedDurableKey == "" {
		generation++
		requestedDurableKey = fmt.Sprintf("%s%d", prefix, generation)
	} else {
		// Explicit caller keys still receive a fresh durable generation. The
		// key is the replay identity; the generation is the resource fence.
		generation++
	}
	transition := &domain.ResidencyTransition{ID: "rtr-" + stableResidencyKey(identity, model, tier) + fmt.Sprintf("-g%d", generation), IdempotencyKey: requestedDurableKey, TargetID: target.ID, AcceleratorID: target.AcceleratorID, Model: model, FromTier: fromTier, ToTier: tier, CapabilityVersion: target.CapabilityVersion, CapabilityRevision: target.CapabilityRevision, Status: domain.ResidencyTransitionPlanned, FencingToken: int64(generation), CreatedAt: time.Now().UTC(), Reason: "controller-adapter runtime=" + identity + " request=" + requestedKey}
	created, createdOK, createErr := a.store.AllocateResidencyTransition(ctx, transition)
	if createErr != nil {
		return "", generation, nil, false, adapterError(ResidencyBlockerCommandFailed, "prepare", target, model, identity, generation, "could not persist transition intent", true, createErr)
	}
	transition = created
	generation = uint64(maxInt64(transition.FencingToken))
	if !createdOK {
		return transition.IdempotencyKey, generation, transition, false, nil
	}
	started := time.Now().UTC()
	transition.StartedAt = &started
	transition.Status = domain.ResidencyTransitionRunning
	updateErr := a.casTransition(ctx, transition, func(current *domain.ResidencyTransition) {
		current.StartedAt = &started
		current.Status = domain.ResidencyTransitionRunning
	})
	if updateErr != nil {
		return "", generation, nil, false, adapterError(ResidencyBlockerCommandFailed, "prepare", target, model, identity, generation, "could not persist running transition", true, updateErr)
	}
	return requestedDurableKey, generation, transition, true, nil
}

func replayDurableObservation(transition *domain.ResidencyTransition, target Target, model, identity string, tier domain.ResidencyTier) (ResidencyObservation, *ResidencyAdapterError) {
	if transition == nil {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "replay", target, model, identity, 0, "durable transition is missing", true, nil)
	}
	if evidenceErr := validateAuthoritativeTransitionEvidence(transition, target, model, tier); evidenceErr != nil {
		return ResidencyObservation{}, adapterError(ResidencyBlockerStaleResult, "replay", target, model, identity, uint64(maxInt64(transition.ObservedFence)), evidenceErr.Error(), true, evidenceErr)
	}
	fence := uint64(maxInt64(transition.ObservedFence))
	observation := ResidencyObservation{TargetID: target.ID, Model: model, RuntimeIdentity: identity, Tier: tier, FencingToken: fence, IdempotencyKey: transition.IdempotencyKey}
	var persistedTier string
	var warmBytes, lockedBytes int64
	var released bool
	var persistedRuntime string
	var persistedFence uint64
	if !strings.HasPrefix(transition.Error, "observed tier=") {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "replay", target, model, identity, fence, "durable transition has no exact node observation", true, nil)
	}
	if _, err := fmt.Sscanf(transition.Error, "observed tier=%s warm_model_bytes=%d locked_bytes=%d released_vram=%t runtime=%s fence=%d", &persistedTier, &warmBytes, &lockedBytes, &released, &persistedRuntime, &persistedFence); err != nil || persistedTier != string(tier) || persistedRuntime != identity || persistedFence != fence {
		return ResidencyObservation{}, adapterError(ResidencyBlockerStaleResult, "replay", target, model, identity, fence, "durable transition observation does not match the canonical request", true, nil)
	}
	if tier == domain.ResidencyWarmRAM {
		if warmBytes <= 0 || lockedBytes <= 0 || !released {
			return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "replay", target, model, identity, fence, "durable warm-RAM observation lacks verified bytes or released VRAM", true, nil)
		}
		observation.WarmModelBytes = warmBytes
		observation.LockedBytes = lockedBytes
		observation.WarmModelBytesVerified = true
		observation.VRAMReleased = released
	}
	return observation, nil
}

func (a *ControllerResidencyAdapter) persistTransitionObservation(ctx context.Context, transition *domain.ResidencyTransition, observation ResidencyObservation) error {
	if a.store == nil || transition == nil {
		return nil
	}
	finished := time.Now().UTC()
	return a.casTransition(ctx, transition, func(current *domain.ResidencyTransition) {
		if current.Status == domain.ResidencyTransitionSucceeded {
			return
		}
		current.Status = domain.ResidencyTransitionSucceeded
		current.FinishedAt = &finished
		current.ObservedTier = observation.Tier
		current.WarmModelBytes = observation.WarmModelBytes
		current.WarmModelBytesVerified = observation.WarmModelBytesVerified
		current.RuntimeIdentity = observation.RuntimeIdentity
		current.ObservedFence = int64(observation.FencingToken)
		current.ProjectionRepairPending = true
		current.Error = fmt.Sprintf("observed tier=%s warm_model_bytes=%d locked_bytes=%d released_vram=%t runtime=%s fence=%d", observation.Tier, observation.WarmModelBytes, observation.LockedBytes, observation.VRAMReleased, observation.RuntimeIdentity, observation.FencingToken)
	})
}

func (a *ControllerResidencyAdapter) persistTransitionFailure(ctx context.Context, transition *domain.ResidencyTransition, failure *ResidencyAdapterError, keepPending bool) {
	if a.store == nil || transition == nil || failure == nil {
		return
	}
	_ = a.casTransition(ctx, transition, func(current *domain.ResidencyTransition) {
		if current.Status == domain.ResidencyTransitionSucceeded {
			return
		}
		current.Error = failure.Error()
		if !keepPending {
			current.Status = domain.ResidencyTransitionFailed
			finished := time.Now().UTC()
			current.FinishedAt = &finished
		}
	})
}

func (a *ControllerResidencyAdapter) casTransition(ctx context.Context, transition *domain.ResidencyTransition, mutate func(*domain.ResidencyTransition)) error {
	if a.store == nil || transition == nil {
		return nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		current, err := a.store.GetResidencyTransition(ctx, transition.ID)
		if err != nil {
			return err
		}
		// A terminal row is authoritative. Never run a stale mutator over its
		// observed evidence; callers receive the durable terminal copy.
		if current.Status == domain.ResidencyTransitionSucceeded && !(current.ProjectionRepairPending && !transition.ProjectionRepairPending) {
			*transition = *current
			return nil
		}
		expectedRevision, expectedStatus, expectedFence := current.Revision, current.Status, current.FencingToken
		candidate := *current
		mutate(&candidate)
		updated, err := a.store.CompareAndSwapResidencyTransition(ctx, &candidate, expectedRevision, expectedStatus, expectedFence)
		if err == nil {
			*transition = *updated
			return nil
		}
		if !errors.Is(err, store.ErrResidencyTransitionConflict) {
			return err
		}
	}
	return store.ErrResidencyTransitionConflict
}

var errNil = errors.New("controller adapter unavailable")

func maxInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func adapterError(code ResidencyBlockerCode, operation string, target Target, model, identity string, fence uint64, message string, retryable bool, cause error) *ResidencyAdapterError {
	return &ResidencyAdapterError{Code: code, Outcome: ResidencyOutcomeTerminalFailed, Operation: operation, TargetID: target.ID, Model: model, RuntimeIdentity: identity, FencingToken: fence, Retryable: retryable, Message: message, Cause: cause}
}

func markIndeterminate(err *ResidencyAdapterError) *ResidencyAdapterError {
	if err != nil {
		err.Outcome = ResidencyOutcomeIndeterminate
	}
	return err
}

func canonicalResidencyIdentity(target Target, model string, warm bool) (string, string, error) {
	if strings.TrimSpace(target.ID) == "" || strings.TrimSpace(model) == "" || strings.TrimSpace(target.Adapter) == "" {
		return "", "", adapterError(ResidencyBlockerIdentityMismatch, "validate", target, model, "", 0, "target, adapter, and model identities are required", false, nil)
	}
	if strings.TrimSpace(target.CapabilityVersion) == "" {
		return "", "", adapterError(ResidencyBlockerIdentityMismatch, "validate", target, model, "", 0, "runtime capability version is required for canonical identity", false, nil)
	}
	if target.MaxAcceleratorsPerWorkload > 1 || target.Capabilities.MaxAcceleratorsPerWorkload > 1 {
		return "", "", adapterError(ResidencyBlockerRuntimeUnsupported, "validate", target, model, "", 0, "residency is limited to one accelerator per workload", false, nil)
	}
	if target.CapabilityRevision != "" && target.CapabilityRevision != domain.CapabilityContractVersion {
		return "", "", adapterError(ResidencyBlockerCapabilityUnavailable, "validate", target, model, "", 0, "unsupported capability contract version", false, nil)
	}
	if target.CapabilityRevision != "" || target.Capabilities.Version != "" {
		if target.CapabilityRevision != domain.CapabilityContractVersion || target.Capabilities.Version != domain.CapabilityContractVersion {
			return "", "", adapterError(ResidencyBlockerCapabilityUnavailable, "validate", target, model, "", 0, "incomplete capability contract version", false, nil)
		}
	}
	if err := target.Capabilities.Validate(); err != nil {
		return "", "", adapterError(ResidencyBlockerCapabilityUnavailable, "validate", target, model, "", 0, "invalid advertised capability contract", false, err)
	}
	if warm {
		caps := target.Capabilities
		if target.CapabilityRevision != domain.CapabilityContractVersion || caps.Version != domain.CapabilityContractVersion || !caps.SupportsWarmRAM || !caps.WarmRAMVerified || strings.TrimSpace(caps.WarmRAMVerification) == "" {
			return "", "", adapterError(ResidencyBlockerCapabilityUnavailable, "offload_model", target, model, "", 0, "verified warm-RAM runtime capability is unavailable", false, nil)
		}
	}
	if !warm {
		if target.CapabilityRevision != domain.CapabilityContractVersion || target.Capabilities.Version != domain.CapabilityContractVersion || !target.Capabilities.SupportsModelLifecycle {
			return "", "", adapterError(ResidencyBlockerRuntimeUnsupported, "lifecycle", target, model, "", 0, "runtime lifecycle capability is unavailable", false, nil)
		}
	}
	nodeID := mustNodeID(target)
	identity := strings.Join([]string{target.ID, target.Adapter, target.RuntimeProtocol, target.CapabilityVersion, target.ModelFingerprint}, "|")
	return identity, nodeID, nil
}

func targetWarmCapabilityAvailable(target Target) bool {
	caps := target.Capabilities
	return target.CapabilityRevision == domain.CapabilityContractVersion &&
		caps.Version == domain.CapabilityContractVersion && caps.SupportsWarmRAM &&
		caps.WarmRAMVerified && strings.TrimSpace(caps.WarmRAMVerification) != ""
}

func targetLifecycleCapabilityAvailable(target Target) bool {
	if target.CapabilityRevision != "" || target.Capabilities.Version != "" {
		if target.CapabilityRevision != domain.CapabilityContractVersion || target.Capabilities.Version != domain.CapabilityContractVersion {
			return false
		}
		return target.Capabilities.SupportsModelLifecycle
	}
	return target.SupportsModelLifecycle
}

func mustNodeID(target Target) string {
	accelerator := strings.TrimSpace(target.AcceleratorID)
	marker := strings.LastIndex(accelerator, "-gpu")
	if marker <= 0 || marker+4 >= len(accelerator) {
		return ""
	}
	for _, char := range accelerator[marker+4:] {
		if char < '0' || char > '9' {
			return ""
		}
	}
	return accelerator[:marker]
}

func stableResidencyKey(identity, model string, tier domain.ResidencyTier) string {
	sum := sha256.Sum256([]byte(identity + "\x00" + model + "\x00" + string(tier)))
	return hex.EncodeToString(sum[:])
}

func durableRequestKey(requested string) string {
	if requested == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(requested))
	return "controller-residency-request-" + hex.EncodeToString(sum[:])
}

func observeResidencyResult(result map[string]any, target Target, model, identity string, tier domain.ResidencyTier, expectedAction string, fence uint64, idempotency string) (ResidencyObservation, *ResidencyAdapterError) {
	if result == nil {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, "node returned no transition result", true, nil)
	}
	if value, ok := result["target_id"].(string); !ok || value != target.ID {
		return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "node returned a different target identity", false, nil)
	}
	if value, ok := result["model"].(string); !ok || value != model {
		return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "node returned a different model identity", false, nil)
	}
	if raw, present := result["runtime_identity"]; present {
		value, ok := raw.(string)
		if !ok || value != identity {
			return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "node returned a different runtime identity", false, nil)
		}
	} else {
		return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "node omitted runtime identity", false, nil)
	}
	if raw, present := result["fencing_token"]; present {
		value, ok := exactResultUint(raw)
		if !ok || value != fence {
			return ResidencyObservation{}, adapterError(ResidencyBlockerStaleResult, "observe", target, model, identity, fence, "node returned a stale fencing token", true, nil)
		}
	} else {
		return ResidencyObservation{}, adapterError(ResidencyBlockerStaleResult, "observe", target, model, identity, fence, "node omitted fencing token", true, nil)
	}
	observedTier, tierOK := result["tier"].(string)
	if !tierOK || strings.TrimSpace(observedTier) == "" {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, "node returned no canonical residency tier", true, nil)
	}
	actualTier := domain.ResidencyTier(observedTier)
	if schemaErr := validateObservedResidencySchema(result, actualTier); schemaErr != "" {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, schemaErr, true, nil)
	}
	if _, currentEnvelope := result["target_kind"]; currentEnvelope {
		if result["target_kind"] != "llamacpp" || result["target_id"] != target.ID || result["model"] != model || result["runtime_identity"] != identity {
			return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "current residency proof identity does not match the target", false, nil)
		}
		if target.CapabilityVersion != "" && result["capability_version"] != target.CapabilityVersion {
			return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "current residency proof capability version drifted", false, nil)
		}
		if target.CapabilityRevision != "" && result["capability_revision"] != target.CapabilityRevision {
			return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "current residency proof capability revision drifted", false, nil)
		}
	}
	if expectedAction != "" {
		if action, ok := result["action"].(string); ok && action != expectedAction {
			return ResidencyObservation{}, adapterError(ResidencyBlockerIdentityMismatch, "observe", target, model, identity, fence, "node returned a result for a different residency action", false, nil)
		}
	}
	if observedTier != string(tier) {
		observedTier := "<missing>"
		observedTier = strings.TrimSpace(fmt.Sprint(result["tier"]))
		observedIdentity := strings.TrimSpace(fmt.Sprint(result["runtime_identity"]))
		observedFence := strings.TrimSpace(fmt.Sprint(result["fencing_token"]))
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, fmt.Sprintf("node returned an unexpected residency tier observed_tier=%s observed_runtime_identity=%s observed_fence=%s", observedTier, observedIdentity, observedFence), true, nil)
	}
	observation := ResidencyObservation{TargetID: target.ID, Model: model, RuntimeIdentity: identity, Tier: tier, FencingToken: fence, IdempotencyKey: idempotency}
	resident, residentOK := result["resident"].(bool)
	warm, warmOK := result["warm_ram"].(bool)
	verified, verifiedOK := result["warm_model_bytes_verified"].(bool)
	if tier == domain.ResidencyHotVRAM && (!residentOK || !resident || !warmOK || warm) {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, "node did not prove hot-VRAM residency", true, nil)
	}
	if tier == domain.ResidencyColdDisk && (!residentOK || resident || !warmOK || warm) {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, "node did not prove cold-disk residency", true, nil)
	}
	if tier == domain.ResidencyWarmRAM {
		if !residentOK || resident || !warmOK || !warm || !verifiedOK || !verified {
			return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, "node did not prove verified warm-RAM residency", true, nil)
		}
		observation.WarmModelBytes, _ = exactResultInt64(result["warm_model_bytes"])
		observation.LockedBytes, _ = exactResultInt64(result["locked_bytes"])
		observation.VRAMReleased, _ = result["released_vram"].(bool)
		if observation.WarmModelBytes <= 0 || observation.LockedBytes <= 0 || !observation.VRAMReleased {
			return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "observe", target, model, identity, fence, "warm-RAM proof lacks locked bytes or released VRAM", true, nil)
		}
		observation.WarmModelBytesVerified = true
	}
	return observation, nil
}

// validateObservedResidencySchema is intentionally finite and state-specific.
// A tier-only or mixed hot/cold/warm result is not an authoritative proof.
func validateObservedResidencySchema(result map[string]any, tier domain.ResidencyTier) string {
	allowed := map[string]bool{"action": true, "target_kind": true, "target_id": true, "model": true, "node_id": true, "runtime_identity": true, "capability_version": true, "capability_revision": true, "tier": true, "resident": true, "warm_ram": true, "changed": true, "fencing_token": true, "observed_after_fence": true, "command_id": true, "idempotency_key": true, "command_fingerprint": true, "fingerprint": true, "original_command_id": true, "original_idempotency_key": true, "expected_fence": true, "reconciled": true}
	for key := range result {
		if !allowed[key] && key != "cleaned" && key != "warm_entry_absent" && key != "warm_release_verified" && key != "warm_model_bytes" && key != "locked_bytes" && key != "warm_model_bytes_verified" && key != "released_vram" && key != "oracle" && key != "protected" && key != "active_references" {
			return "node returned an unknown residency proof field " + key
		}
	}
	// A current node envelope is finite and self-authenticating.  Once its
	// target kind (or any current command alias) is present, every canonical
	// binding is required and typed; a sparse result must never be upgraded by
	// inference.  Results without these fields remain the deliberately narrow
	// pre-envelope compatibility shape and are validated by the legacy caller.
	currentEnvelope := false
	for _, key := range []string{"target_kind", "node_id", "capability_version", "capability_revision", "command_id", "idempotency_key", "command_fingerprint", "fingerprint", "original_command_id", "original_idempotency_key"} {
		if _, present := result[key]; present {
			currentEnvelope = true
			break
		}
	}
	if currentEnvelope {
		for _, key := range []string{"action", "target_kind", "target_id", "model", "node_id", "runtime_identity", "capability_version", "capability_revision", "tier", "command_id", "idempotency_key", "command_fingerprint", "fingerprint", "original_command_id", "original_idempotency_key"} {
			value, ok := result[key].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return "current residency proof omitted required string " + key
			}
		}
		if result["target_kind"] != "llamacpp" {
			return "current residency proof target_kind is not llamacpp"
		}
		for _, key := range []string{"resident", "warm_ram", "changed"} {
			if _, ok := result[key].(bool); !ok {
				return "current residency proof omitted typed boolean " + key
			}
		}
		for _, key := range []string{"fencing_token", "observed_after_fence"} {
			if _, ok := exactResultUint(result[key]); !ok {
				return "current residency proof omitted integer fence " + key
			}
		}
		if reconciled, present := result["reconciled"]; present {
			if _, ok := reconciled.(bool); !ok {
				return "current residency proof reconciled must be boolean"
			}
		} else {
			return "current residency proof omitted reconciled"
		}
		queryProof := result["original_command_id"] != nil && result["command_id"] != nil && result["original_command_id"] != result["command_id"]
		if queryProof {
			if _, ok := exactResultUint(result["expected_fence"]); !ok {
				return "current query proof omitted expected_fence"
			}
		} else if _, present := result["expected_fence"]; present {
			if _, ok := exactResultUint(result["expected_fence"]); !ok {
				return "current residency proof expected_fence must be an integer"
			}
		}
	}
	changed, changedOK := result["changed"].(bool)
	if _, present := result["changed"]; present && !changedOK {
		return "node returned an untyped changed proof"
	}
	if currentEnvelope && !changedOK {
		return "node returned an untyped changed proof"
	}
	resident, residentOK := result["resident"].(bool)
	warm, warmOK := result["warm_ram"].(bool)
	if currentEnvelope && (!residentOK || !warmOK) {
		return "node omitted typed residency state"
	}
	cleanupKeys := []string{"cleaned", "warm_entry_absent", "warm_release_verified"}
	warmKeys := []string{"warm_model_bytes_verified", "released_vram", "oracle", "protected", "active_references"}
	hasAny := func(keys []string) bool {
		for _, key := range keys {
			if _, present := result[key]; present {
				return true
			}
		}
		return false
	}
	if tier == domain.ResidencyHotVRAM {
		if !residentOK || !warmOK || !resident || warm || hasAny(cleanupKeys) || hasAny(warmKeys) {
			return "hot proof contains non-hot fields"
		}
		return ""
	}
	if tier == domain.ResidencyColdDisk {
		if !residentOK || !warmOK || resident || warm || hasAny(warmKeys) {
			return "cold proof contains warm fields"
		}
		cleaned, cOK := result["cleaned"].(bool)
		absent, aOK := result["warm_entry_absent"].(bool)
		released, rOK := result["warm_release_verified"].(bool)
		bytes, bOK := exactResultInt64(result["warm_model_bytes"])
		locked, lOK := exactResultInt64(result["locked_bytes"])
		if currentEnvelope || result["action"] != nil {
			if !cOK || !cleaned || !aOK || !absent || !rOK || !released || !bOK || !lOK || bytes != 0 || locked != 0 {
				return "cold proof lacks exact cleanup evidence"
			}
		} else if (cOK && (!cleaned || !aOK || !absent || !rOK || !released)) || (bOK && bytes != 0) || (lOK && locked != 0) {
			return "cold proof lacks exact cleanup evidence"
		}
		return ""
	}
	if tier == domain.ResidencyWarmRAM {
		// Mutation observations may legitimately mark changed=true; the
		// correlated query proof (distinct original and query IDs) must be
		// unchanged and cannot claim a second mutation.
		queryProof := result["original_command_id"] != nil && result["command_id"] != nil && result["original_command_id"] != result["command_id"]
		if (queryProof && changedOK && changed) || !residentOK || !warmOK || resident || !warm || hasAny(cleanupKeys) {
			return fmt.Sprintf("warm proof contains non-warm fields result=%v", result)
		}
		verified, vOK := result["warm_model_bytes_verified"].(bool)
		released, rOK := result["released_vram"].(bool)
		oracle, oOK := result["oracle"].(string)
		bytes, bOK := exactResultInt64(result["warm_model_bytes"])
		locked, lOK := exactResultInt64(result["locked_bytes"])
		if currentEnvelope || result["action"] != nil {
			if !vOK || !verified || !rOK || !released || !oOK || oracle != "mincore+mlock" || !bOK || !lOK || bytes <= 0 || locked < bytes {
				return "warm proof lacks exact locked-byte evidence"
			}
		} else if (vOK && !verified) || (rOK && !released) || (oOK && oracle != "mincore+mlock") || (bOK && bytes <= 0) || (lOK && locked <= 0) || (bOK && lOK && locked < bytes) {
			return "warm proof lacks exact locked-byte evidence"
		}
		return ""
	}
	return "node returned a non-canonical residency tier"
}

func observeResidencyQueryResult(result map[string]any, target Target, model, identity string, tier domain.ResidencyTier, expectedAction string, referenceFence uint64, idempotency string) (ResidencyObservation, *ResidencyAdapterError) {
	if result == nil {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "query", target, model, identity, referenceFence, "node returned no authoritative state", true, nil)
	}
	if changed, ok := result["changed"].(bool); !ok || changed {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "query", target, model, identity, referenceFence, "authoritative query must prove changed=false", true, nil)
	}
	observedFence, ok := exactResultUint(result["fencing_token"])
	if !ok || observedFence < referenceFence {
		return ResidencyObservation{}, adapterError(ResidencyBlockerStaleResult, "query", target, model, identity, referenceFence, "authoritative query returned a fence older than the mutation", true, nil)
	}
	afterFence, ok := exactResultUint(result["observed_after_fence"])
	if !ok || afterFence < referenceFence {
		return ResidencyObservation{}, adapterError(ResidencyBlockerStaleResult, "query", target, model, identity, referenceFence, "authoritative query omitted the mutation reference fence", true, nil)
	}
	observedTier, tierOK := result["tier"].(string)
	if !tierOK || strings.TrimSpace(observedTier) == "" {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "query", target, model, identity, referenceFence, "authoritative query omitted canonical residency tier", true, nil)
	}
	observation, validationErr := observeResidencyResult(result, target, model, identity, domain.ResidencyTier(observedTier), expectedAction, observedFence, idempotency)
	if validationErr != nil {
		return ResidencyObservation{}, validationErr
	}
	// A query can authoritatively prove the inverse state (the original
	// mutation then settles as a failed/rolled-back command), but it may never
	// prove the unrelated third canonical tier.  Keep that distinction explicit
	// instead of treating every valid state proof as success for the request.
	if domain.ResidencyTier(observedTier) != tier {
		return ResidencyObservation{}, adapterError(ResidencyBlockerCommandFailed, "query", target, model, identity, referenceFence, fmt.Sprintf("authoritative query observed tier %s for requested %s", observedTier, tier), true, nil)
	}
	// The durable transition remains fenced at the original mutation. Keep
	// that reference in the persisted observation while still accepting a
	// newer authoritative node fence above.
	observation.FencingToken = referenceFence
	return observation, nil
}

func exactResultUint(value any) (uint64, bool) {
	switch typed := value.(type) {
	case int:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	case int64:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	case uint64:
		return typed, true
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, false
		}
		return uint64(typed), true
	default:
		return 0, false
	}
}

func exactResultInt64(value any) (int64, bool) {
	unsigned, ok := exactResultUint(value)
	if !ok || unsigned > uint64(^uint64(0)>>1) {
		return 0, false
	}
	return int64(unsigned), true
}
