package workloads

import (
	"errors"
	"fmt"
	"time"
)

// Backoff for models whose load definitely failed on a target. Doubling from
// modelLoadBackoffBase up to modelLoadBackoffMax lets a transient cause (VRAM
// briefly held by another runtime) clear quickly while a model the runtime
// can never load (live: llama.cpp "unknown model architecture") stops being
// retried on every admission pass; each attempt made the node briefly
// not-ready for all other work.
var (
	modelLoadBackoffBase = 30 * time.Second
	modelLoadBackoffMax  = 30 * time.Minute
)

// modelLoadFailFastAfter consecutive definite failures make a request whose
// every route is unsupported or fenced fail instead of waiting out its deadline.
const modelLoadFailFastAfter = 3

type modelLoadFailure struct {
	count    int
	reason   string
	until    time.Time
	identity string
}

func modelLoadFailureKey(targetID, model string) string { return targetID + "\x00" + model }

func modelLoadIdentity(target Target) string {
	return target.CapabilityVersion + "\x00" + target.ModelFingerprint
}

// isDefiniteLoadFailure reports a load of model that the runtime completed
// without the model becoming resident. Indeterminate outcomes (timeouts,
// unresolved custody) and eviction or capacity errors do not count.
func isDefiniteLoadFailure(err error, model string) bool {
	var adapterErr *ResidencyAdapterError
	return errors.As(err, &adapterErr) && !adapterErr.IsIndeterminate() && adapterErr.Operation == "load_model" && adapterErr.Model == model
}

func (m *Manager) recordModelLoadFailure(target Target, model, reason string) {
	key := modelLoadFailureKey(target.ID, model)
	m.mu.Lock()
	defer m.mu.Unlock()
	failure := m.modelLoadFailures[key]
	if failure.identity != modelLoadIdentity(target) {
		failure = modelLoadFailure{identity: modelLoadIdentity(target)}
	}
	failure.count++
	backoff := modelLoadBackoffBase
	for i := 1; i < failure.count && backoff < modelLoadBackoffMax; i++ {
		backoff *= 2
	}
	if backoff > modelLoadBackoffMax {
		backoff = modelLoadBackoffMax
	}
	failure.reason, failure.until = reason, time.Now().Add(backoff)
	m.modelLoadFailures[key] = failure
}

func (m *Manager) clearModelLoadFailure(targetID, model string) {
	m.mu.Lock()
	delete(m.modelLoadFailures, modelLoadFailureKey(targetID, model))
	m.mu.Unlock()
}

// modelLoadFenced reports whether a load of model on target is backing off,
// with a blocker text and the consecutive failure count. A runtime or model
// fingerprint change forgets the history.
func (m *Manager) modelLoadFenced(target Target, model string) (string, int, bool) {
	key := modelLoadFailureKey(target.ID, model)
	m.mu.Lock()
	defer m.mu.Unlock()
	failure, ok := m.modelLoadFailures[key]
	if !ok {
		return "", 0, false
	}
	if failure.identity != modelLoadIdentity(target) {
		delete(m.modelLoadFailures, key)
		return "", 0, false
	}
	if !time.Now().Before(failure.until) {
		return "", failure.count, false
	}
	return fmt.Sprintf("model %s failed to load %d time(s) in a row; next attempt after %s: %s", model, failure.count, failure.until.UTC().Format(time.RFC3339), failure.reason), failure.count, true
}
