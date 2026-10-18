package workloads

import (
	"sync"
	"time"

	"vram-governor/internal/domain"
)

// Learned speeds keep the scheduler's picture of each target current: every
// finished request reports its prompt and decode speed, and a moving
// average per target and model replaces the one-off calibration once a few
// samples exist. A target running far below its calibration (a placement
// that collapsed, a degraded card) is logged so it can be recalibrated.

const (
	learnedSpeedWeight     = 0.2 // weight of the newest sample in the average
	learnedSpeedMinSamples = 3   // samples before the average replaces calibration
	learnedSpeedAlarmRatio = 0.6 // average below this share of calibration is logged
)

type learnedSpeed struct {
	decode, prompt float64
	samples        int
	alarmedAt      time.Time
}

type learnedSpeeds struct {
	mu    sync.Mutex
	byKey map[string]*learnedSpeed
}

func learnedSpeedKey(targetID, model string) string { return targetID + "\x00" + model }

// observeSpeed folds one finished request's speeds into its target's average.
func (m *Manager) observeSpeed(workload *domain.Workload, target Target) {
	if workload == nil || workload.Plan == nil || workload.Plan.Model == "" || workload.Execution == nil || workload.Execution.Performance == nil {
		return
	}
	performance := workload.Execution.Performance
	if performance.DecodeTPS <= 0 || performance.PromptTPS <= 0 || performance.CompletionTokens < 16 {
		return // too short to say anything about speed
	}
	model := workload.Plan.Model
	m.speeds.mu.Lock()
	defer m.speeds.mu.Unlock()
	if m.speeds.byKey == nil {
		m.speeds.byKey = make(map[string]*learnedSpeed)
	}
	key := learnedSpeedKey(target.ID, model)
	entry := m.speeds.byKey[key]
	if entry == nil {
		entry = &learnedSpeed{decode: performance.DecodeTPS, prompt: performance.PromptTPS}
		m.speeds.byKey[key] = entry
	} else {
		entry.decode += learnedSpeedWeight * (performance.DecodeTPS - entry.decode)
		entry.prompt += learnedSpeedWeight * (performance.PromptTPS - entry.prompt)
	}
	entry.samples++
	if pool, ok := target.ModelPools[model]; ok && pool.DecodeTPS > 0 && entry.samples >= 5 && entry.decode < pool.DecodeTPS*learnedSpeedAlarmRatio && time.Since(entry.alarmedAt) > time.Hour {
		entry.alarmedAt = time.Now()
		m.log.Warn("target runs far below its calibrated speed; recalibrate it",
			"target_id", target.ID, "model", model, "decode_tps", entry.decode, "calibrated_decode_tps", pool.DecodeTPS,
			"prompt_tps", entry.prompt, "calibrated_prompt_tps", pool.PromptTPS, "samples", entry.samples)
	}
}

// withLearnedSpeeds returns target with its pool for model carrying the
// learned speeds, once enough samples exist (the map is copied, never shared).
func (m *Manager) withLearnedSpeeds(target Target, model string) Target {
	if model == "" {
		return target
	}
	pool, ok := target.ModelPools[model]
	if !ok {
		return target
	}
	m.speeds.mu.Lock()
	entry := m.speeds.byKey[learnedSpeedKey(target.ID, model)]
	var decode, prompt float64
	if entry != nil && entry.samples >= learnedSpeedMinSamples {
		decode, prompt = entry.decode, entry.prompt
	}
	m.speeds.mu.Unlock()
	if decode <= 0 {
		return target
	}
	pools := make(map[string]ModelPool, len(target.ModelPools))
	for name, existing := range target.ModelPools {
		pools[name] = existing
	}
	pool.DecodeTPS, pool.PromptTPS = decode, prompt
	pools[model] = pool
	target.ModelPools = pools
	return target
}
