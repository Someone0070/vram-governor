package workloads

import (
	"errors"
	"strings"
	"time"
)

// modelLoadFailureTTL bounds how long a definite load failure fences a model
// on a target. A runtime or model fingerprint change clears it sooner.
const modelLoadFailureTTL = 30 * time.Minute

// modelLoadFailure remembers that a runtime tried to load a model and the
// model crashed out (e.g. llama.cpp "unknown model architecture"). Retrying
// such a load every admission pass only repeats the failure, and each
// attempt briefly makes the node not-ready for everything else.
type modelLoadFailure struct {
	reason   string
	until    time.Time
	identity string
}

func modelLoadFailureKey(targetID, model string) string { return targetID + "\x00" + model }

func modelLoadIdentity(target Target) string {
	return target.CapabilityVersion + "\x00" + target.ModelFingerprint
}

// isRuntimeLoadFailure reports a definite failure reported by the node: the
// runtime attempted the load and the model is confirmed absent. Transport,
// fence and capacity errors are not, and stay retryable.
func isRuntimeLoadFailure(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if strings.Contains(err.Error(), "node command failed: model failed to load in the runtime") {
			return true
		}
	}
	return false
}

func (m *Manager) recordModelLoadFailure(target Target, model, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modelLoadFailures[modelLoadFailureKey(target.ID, model)] = modelLoadFailure{reason: reason, until: time.Now().Add(modelLoadFailureTTL), identity: modelLoadIdentity(target)}
}

func (m *Manager) modelLoadFailed(target Target, model string) (string, bool) {
	key := modelLoadFailureKey(target.ID, model)
	m.mu.Lock()
	defer m.mu.Unlock()
	failure, ok := m.modelLoadFailures[key]
	if !ok {
		return "", false
	}
	if time.Now().After(failure.until) || failure.identity != modelLoadIdentity(target) {
		delete(m.modelLoadFailures, key)
		return "", false
	}
	return "model " + model + " failed to load in the runtime (retry after " + failure.until.UTC().Format(time.RFC3339) + " or after the runtime changes; see the node's runtime log)", true
}
