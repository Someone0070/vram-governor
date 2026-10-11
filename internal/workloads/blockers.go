package workloads

import (
	"errors"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

// realEstimateConfidence separates history-backed start estimates from the
// lease-TTL placeholders (.2 waiting fallback, .25 no-sample target, .3 busy
// fail_fast). Clients act on ETA/RetryAfter, so a placeholder must never be
// published as if it were a prediction.
const realEstimateConfidence = .35

// UrgentPriority is the requested priority at which demand eviction may
// override a resident's min_residency window. Interactive QoS boosts are
// deliberately not counted: every OpenAI request is interactive.
const UrgentPriority = 8

// admissionBlockError carries a stable code (and, when known, the instant the
// cause clears) from the place the cause is decided up to the admission
// decision, so the code never depends on human-readable error text.
type admissionBlockError struct {
	code  domain.AdmissionBlocker
	until *time.Time
	msg   string
}

func (e *admissionBlockError) Error() string { return e.msg }

func blockerFromError(err error) (domain.AdmissionBlocker, *time.Time) {
	var coded *admissionBlockError
	if errors.As(err, &coded) {
		return coded.code, coded.until
	}
	return "", nil
}

// ClassifyBlocker maps free-text blocker strings to a stable code. It is the
// fallback for decisions whose producer did not record a code at the source
// (older rows, rarely-hit paths); the source code always wins.
func ClassifyBlocker(text string) domain.AdmissionBlocker {
	lower := strings.ToLower(text)
	has := func(parts ...string) bool {
		for _, part := range parts {
			if strings.Contains(lower, part) {
				return true
			}
		}
		return false
	}
	switch {
	case has("disconnected", "not ready", "offline", "node was lost", "not present in live inventory", "inventory unavailable", "scheduling disabled", "quarantined", "no longer registered"):
		return domain.BlockerNodeOffline
	case has("pinned", "protected by policy", "operator transition"):
		return domain.BlockerPinnedResident
	case has("locked workload", "non-preemptible", "not preemptible"):
		return domain.BlockerLockedWorkload
	case has("capability_unavailable", "unsupported", "runtime protocol unavailable", "cannot load", "does not support", "does not implement", "model unavailable", "custom node unavailable", "schema unavailable", "egress denied", "price is not configured"):
		return domain.BlockerRuntimeUnsupported
	case has("transition", "min_residency", "reconcil", "re-placing", "re-admitting", "changed during", "changed before", "changed after", "cooldown", "circuit open", "awaiting observed capacity"):
		return domain.BlockerTransitionBusy
	}
	return domain.BlockerCapacity
}

// dominantBlockerCode is the code for a decision with several per-target
// causes: a shared code is reported as-is, a mix is reported as capacity
// because at least one route may clear by waiting.
func dominantBlockerCode(codes []domain.AdmissionBlocker) domain.AdmissionBlocker {
	if len(codes) == 0 {
		return domain.BlockerCapacity
	}
	for _, code := range codes[1:] {
		if code != codes[0] {
			return domain.BlockerCapacity
		}
	}
	return codes[0]
}

func earlierTime(current, candidate *time.Time) *time.Time {
	if candidate == nil {
		return current
	}
	if current == nil || candidate.Before(*current) {
		value := *candidate
		return &value
	}
	return current
}

// completeAdmissionDecision fills the machine-readable fields of a blocked
// decision immediately before it is persisted. Every CAS funnels through it,
// so a decision built by any path carries a code, real-only retry hints, and
// a notification handle for the in-app event stream.
func completeAdmissionDecision(w *domain.Workload) {
	if w == nil || w.Decision.Admitted {
		return
	}
	decision := &w.Decision
	if decision.BlockerCode == "" && decision.Blocker != "" {
		decision.BlockerCode = ClassifyBlocker(decision.Blocker)
	}
	if decision.EstimatedStart != nil && decision.Confidence >= realEstimateConfidence {
		if decision.ETA == nil {
			start := *decision.EstimatedStart
			decision.ETA = &start
		}
		if decision.RetryAfter == nil {
			retry := *decision.EstimatedStart
			decision.RetryAfter = &retry
		}
	}
	if w.Status == domain.WorkloadWaiting || w.Status == domain.WorkloadQueued {
		// The workload ID is the handle: the workload.admitted audit event (and
		// the optional workload.started notification) are keyed by it.
		decision.NotificationID = w.Request.ID
	} else {
		decision.NotificationID = ""
	}
}

func realEstimate(decision domain.AdmissionDecision) *time.Time {
	if decision.EstimatedStart == nil || decision.Confidence < realEstimateConfidence {
		return nil
	}
	start := *decision.EstimatedStart
	return &start
}
