// Package probe implements the Phase 2 measured-footprint/performance
// prober (docs/measurement.md). It drives a runtime over its own API
// (currently: internal/runtime/llamacpp) the same way the Python reference
// spikes did, and produces a domain.PerformanceProfile containing only
// numbers it actually measured on this hardware — never a hand-configured
// or model-name-inferred value (measurement.md, locked principle).
package probe

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/runtime"
	"vram-governor/internal/runtime/llamacpp"
)

// Config tunes how much work the prober does. Defaults are deliberately
// small (measurement.md §4: join-time footprint probe is Phase 2; full
// curves are Phase 8/9) but every number produced is real, not simulated.
type Config struct {
	EvictReloadCycles   int   // default 5
	KVContextSizes      []int // default [1000, 4000]
	PrefillContextSizes []int // default [500, 4000]
	DecodeConcurrencies []int // default [1, 2]
	DecodeNPredict      int   // default 32
	MinFreeVRAMMarginMB int64 // safety margin above ExpectedVRAMMB before attempting a load
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.EvictReloadCycles <= 0 {
		out.EvictReloadCycles = 5
	}
	if len(out.KVContextSizes) == 0 {
		out.KVContextSizes = []int{1000, 4000}
	}
	if len(out.PrefillContextSizes) == 0 {
		out.PrefillContextSizes = []int{500, 4000}
	}
	if len(out.DecodeConcurrencies) == 0 {
		out.DecodeConcurrencies = []int{1, 2}
	}
	if out.DecodeNPredict <= 0 {
		out.DecodeNPredict = 32
	}
	if out.MinFreeVRAMMarginMB <= 0 {
		out.MinFreeVRAMMarginMB = 512
	}
	return out
}

// Prober runs the Phase 2 measurement suite against a llama.cpp driver.
// Phase 2 ties the prober to the concrete llamacpp.Driver because it needs
// completion/KV primitives beyond the generic runtime.Driver surface
// (Complete, CheckpointSession/RestoreSession, per-PID/free-delta VRAM
// reads); a multi-runtime prober is a later-phase concern once a second
// driver exists to design the shared surface against.
type Prober struct {
	Driver   *llamacpp.Driver
	GPUIndex int
}

func New(d *llamacpp.Driver, gpuIndex int) *Prober {
	return &Prober{Driver: d, GPUIndex: gpuIndex}
}

// Run measures the full PerformanceProfile for spec.Profile on this node's
// hardware. modelArtifactID/quantization feed the §1 identity key. It also
// returns the EngineInstance it launched for the run (State="stopped" by
// the time Run returns — the prober always cleans up after itself) so
// callers can report it via the controller API alongside the profile.
func (p *Prober) Run(ctx context.Context, spec runtime.LaunchSpec, modelArtifactID, quantization string, cfg Config) (*domain.PerformanceProfile, *domain.EngineInstance, error) {
	cfg = cfg.withDefaults()
	notes := []string{}

	hw, hwNotes := detectHardware(ctx, p.GPUIndex)
	notes = append(notes, hwNotes...)

	// --- Honesty gate: check free VRAM before attempting anything (spec). ---
	free, err := p.Driver.FreeVRAMMB(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("probe: cannot read free VRAM, refusing to attempt a load: %w", err)
	}
	expected := spec.Profile.ExpectedVRAMMB
	if expected > 0 && free < expected+cfg.MinFreeVRAMMarginMB {
		return nil, nil, fmt.Errorf("probe: insufficient free VRAM: free=%dMiB expected=%dMiB margin=%dMiB — refusing to launch (would OOM); free the GPU or lower ExpectedVRAMMB and retry",
			free, expected, cfg.MinFreeVRAMMarginMB)
	}
	if expected == 0 {
		notes = append(notes, fmt.Sprintf("ServingProfile.ExpectedVRAMMB was 0 (unset) — skipped the pre-flight capacity gate; free VRAM at probe start was %dMiB", free))
	}

	profile := &domain.PerformanceProfile{
		ID:              fmt.Sprintf("perf-%s-%d", spec.Profile.ID, time.Now().UnixNano()),
		Hardware:        hw,
		ModelArtifactID: modelArtifactID,
		Quantization:    quantization,
		ContextProfile:  spec.Profile.ContextLimit,
		ShardCount:      1,
		Concurrency:     1,
		MeasuredAt:      time.Now().UTC(),
	}

	rtID, err := p.Driver.ProbeRuntime(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("probe runtime identity: %w", err)
	}
	profile.RuntimeName = rtID.Name
	profile.RuntimeVersion = rtID.Version

	// --- Capabilities (measurement.md §2) — this launches/stops its own
	// short-lived engine. ---
	caps, err := p.Driver.ProbeCapabilities(ctx, spec)
	if err != nil {
		notes = append(notes, "capability probe error: "+err.Error())
	}
	profile.Capabilities = caps

	// --- Cold load + footprint ---
	t0 := time.Now()
	engine, err := p.Driver.Launch(ctx, spec)
	if err != nil {
		return nil, nil, fmt.Errorf("cold load failed: %w", err)
	}
	coldLoad := time.Since(t0)

	if mb, ok := p.Driver.PerPIDUsedMB(ctx, engine); ok {
		profile.VRAMFootprintMB = mb
		profile.VRAMMeasurementMethod = "per_pid"
	} else {
		profile.VRAMFootprintMB = p.Driver.ResidentMB(engine)
		profile.VRAMMeasurementMethod = "free_delta"
		notes = append(notes, "nvidia-smi --query-compute-apps reported N/A for this PID (observed under WSL) — used free-VRAM-delta (before vs after load) instead")
	}

	// --- Evict/reload cycles ---
	evict, evictNotes := p.measureEvictReload(ctx, engine, coldLoad, cfg.EvictReloadCycles)
	profile.EvictReload = evict
	notes = append(notes, evictNotes...)
	profile.SampleCount = cfg.EvictReloadCycles

	// --- KV snapshot probe ---
	if caps.SupportsKVRestore {
		kv, kvNotes := p.measureKV(ctx, spec, engine, cfg.KVContextSizes)
		profile.KV = kv
		notes = append(notes, kvNotes...)
	} else {
		notes = append(notes, "KV snapshot capability not confirmed by ProbeCapabilities — skipped KV timing probe")
	}

	// --- Prefill / decode micro-measurement ---
	prefill, prefillNotes := p.measurePrefill(ctx, engine, cfg.PrefillContextSizes)
	profile.Prefill = prefill
	notes = append(notes, prefillNotes...)

	decode, decodeNotes := p.measureDecode(ctx, engine, cfg.DecodeConcurrencies, cfg.DecodeNPredict)
	profile.Decode = decode
	notes = append(notes, decodeNotes...)

	// The prober always cleans up its own engine — never leaves it running.
	if err := p.Driver.Stop(context.Background(), engine); err != nil {
		notes = append(notes, "failed to stop probe engine cleanly: "+err.Error())
	} else {
		engine.State = "stopped"
	}

	profile.Notes = notes
	return profile, engine, nil
}

// ---------------------------------------------------------------------
// Hardware identity (best-effort; unmeasured fields are labeled, not guessed)
// ---------------------------------------------------------------------

func detectHardware(ctx context.Context, gpuIndex int) (domain.HardwareIdentity, []string) {
	var notes []string
	hw := domain.HardwareIdentity{PCIeInfo: "unknown (not probed in Phase 2)"}

	out, err := exec.CommandContext(ctx, "nvidia-smi",
		fmt.Sprintf("--id=%d", gpuIndex),
		"--query-gpu=name,memory.total", "--format=csv,noheader,nounits").Output()
	if err == nil {
		line := strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
		parts := strings.Split(line, ",")
		if len(parts) == 2 {
			hw.GPUModel = strings.TrimSpace(parts[0])
			if v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64); err == nil {
				hw.VRAMTotalMB = v
			}
		}
	} else {
		notes = append(notes, "nvidia-smi GPU identity query failed: "+err.Error())
	}

	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "model name") {
				if idx := strings.Index(line, ":"); idx >= 0 {
					hw.HostCPU = strings.TrimSpace(line[idx+1:])
				}
				break
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						hw.HostRAMMB = kb / 1024
					}
				}
				break
			}
		}
	}
	return hw, notes
}

// ---------------------------------------------------------------------
// Evict/reload
// ---------------------------------------------------------------------

func stat(samples []float64) domain.Stat {
	if len(samples) == 0 {
		return domain.Stat{}
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)
	n := len(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	mean := sum / float64(n)
	var sqDiff float64
	for _, v := range sorted {
		d := v - mean
		sqDiff += d * d
	}
	stdev := 0.0
	if n > 1 {
		stdev = math.Sqrt(sqDiff / float64(n))
	}
	p95idx := int(0.95*float64(n)+0.5) - 1
	if p95idx < 0 {
		p95idx = 0
	}
	if p95idx >= n {
		p95idx = n - 1
	}
	return domain.Stat{Mean: mean, Stdev: stdev, P95: sorted[p95idx], Min: sorted[0], Max: sorted[n-1], N: n}
}

func (p *Prober) measureEvictReload(ctx context.Context, engine *domain.EngineInstance, coldLoad time.Duration, cycles int) (domain.EvictReloadStats, []string) {
	var notes []string
	var tSleep, tWake, tFirst, freed []float64
	for i := 0; i < cycles; i++ {
		res, err := p.Driver.MeasureEvictReloadCycle(ctx, engine)
		if err != nil {
			notes = append(notes, fmt.Sprintf("evict/reload cycle %d failed: %v", i+1, err))
			continue
		}
		tSleep = append(tSleep, res.TSleep.Seconds())
		tWake = append(tWake, res.TWakeWeights.Seconds())
		tFirst = append(tFirst, res.TFirstToken.Seconds())
		freed = append(freed, float64(res.FreedMB))
	}
	return domain.EvictReloadStats{
		TSleepSeconds:            stat(tSleep),
		TWakeWeightsSeconds:      stat(tWake),
		TFirstTokenAfterWakeSecs: stat(tFirst),
		VRAMFreedMB:              stat(freed),
		ColdLoadSeconds:          coldLoad.Seconds(),
	}, notes
}

// ---------------------------------------------------------------------
// KV snapshot probe (ports kv_restore_spike.py methodology)
// ---------------------------------------------------------------------

const resumeSuffix = " Given all of the above, produce the final answer now:"

func makePrompt(approxTokens int) string {
	words := strings.Fields("the quick brown fox jumps over the lazy dog while a curious cat " +
		"watches quietly from the wooden fence near the old red barn")
	var b strings.Builder
	for i := 0; i < approxTokens; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(words[i%len(words)])
	}
	return b.String()
}

func (p *Prober) measureKV(ctx context.Context, spec runtime.LaunchSpec, engine *domain.EngineInstance, contextSizes []int) ([]domain.KVProbePoint, []string) {
	var notes []string
	var results []domain.KVProbePoint

	for _, target := range contextSizes {
		context := makePrompt(target)
		resumePrompt := context + resumeSuffix
		fname := fmt.Sprintf("kv-probe-%d.bin", target)

		// Prime slot 0 with the context (KV resident), get real token count.
		primed, err := p.Driver.Complete(ctx, engine, llamacpp.CompletionRequest{Prompt: context, NPredict: 1, CachePrompt: true, SlotID: 0})
		if err != nil {
			notes = append(notes, fmt.Sprintf("kv probe ctx=%d: prime failed: %v", target, err))
			continue
		}
		contextTokens := primed.Timings.PromptN

		// Path A: RECOMPUTE — fresh full prefill of the resume prompt, no cache.
		var reprefillMS []float64
		for i := 0; i < 2; i++ {
			r, err := p.Driver.Complete(ctx, engine, llamacpp.CompletionRequest{Prompt: resumePrompt, NPredict: 1, CachePrompt: false, SlotID: 0})
			if err != nil {
				notes = append(notes, fmt.Sprintf("kv probe ctx=%d: recompute pass %d failed: %v", target, i, err))
				continue
			}
			reprefillMS = append(reprefillMS, r.Timings.PromptMS)
		}
		if len(reprefillMS) == 0 {
			continue
		}
		tReprefill := minFloat(reprefillMS) / 1000.0

		// Re-prime so the saved KV holds exactly `context`.
		if _, err := p.Driver.Complete(ctx, engine, llamacpp.CompletionRequest{Prompt: context, NPredict: 1, CachePrompt: true, SlotID: 0}); err != nil {
			notes = append(notes, fmt.Sprintf("kv probe ctx=%d: re-prime failed: %v", target, err))
			continue
		}

		// Path B: SLOT KV save.
		ck, err := p.Driver.CheckpointSession(ctx, engine, 0, fname)
		if err != nil {
			notes = append(notes, fmt.Sprintf("kv probe ctx=%d: save failed: %v", target, err))
			continue
		}

		// EVICTED: teardown, relaunch, restore, resume with a NEW turn
		// (never re-send the identical prompt — the KV spike's methodology
		// trap: that degenerately re-prefills in full).
		if err := stopAndRelaunch(ctx, p.Driver, engine); err != nil {
			notes = append(notes, fmt.Sprintf("kv probe ctx=%d: evict/relaunch failed: %v", target, err))
			continue
		}

		restore, err := p.Driver.RestoreSession(ctx, engine, 0, fname)
		if err != nil {
			notes = append(notes, fmt.Sprintf("kv probe ctx=%d: restore failed: %v", target, err))
			continue
		}
		resume, err := p.Driver.Complete(ctx, engine, llamacpp.CompletionRequest{Prompt: resumePrompt, NPredict: 1, CachePrompt: true, SlotID: 0})
		if err != nil {
			notes = append(notes, fmt.Sprintf("kv probe ctx=%d: resume-after-restore failed: %v", target, err))
			continue
		}

		reused := resume.Timings.PromptN < contextTokens/2
		if !reused {
			notes = append(notes, fmt.Sprintf("kv probe ctx=%d: KV NOT reused on resume (resume prefilled %d of %d tokens) — restore path may be degenerate on this build", target, resume.Timings.PromptN, contextTokens))
		}

		results = append(results, domain.KVProbePoint{
			ContextTokens:              contextTokens,
			TReprefillRecomputeSeconds: tReprefill,
			TSlotSaveSeconds:           ck.Duration.Seconds(),
			TSlotRestoreSeconds:        restore.Duration.Seconds(),
			TResumePrefillSeconds:      resume.Timings.PromptMS / 1000.0,
			ResumePrefillTokens:        resume.Timings.PromptN,
			KVFileMB:                   float64(ck.SizeBytes) / (1024 * 1024),
			KVReused:                   reused,
		})
	}
	return results, notes
}

func stopAndRelaunch(ctx context.Context, d *llamacpp.Driver, engine *domain.EngineInstance) error {
	if _, err := d.MeasureEvictReloadCycle(ctx, engine); err != nil {
		// MeasureEvictReloadCycle also does a throwaway completion, which is
		// fine — it warms the pipeline before the real restore measurement.
		return err
	}
	return nil
}

func minFloat(vs []float64) float64 {
	m := vs[0]
	for _, v := range vs[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// ---------------------------------------------------------------------
// Prefill / decode micro-measurement
// ---------------------------------------------------------------------

func (p *Prober) measurePrefill(ctx context.Context, engine *domain.EngineInstance, contextSizes []int) ([]domain.ThroughputPoint, []string) {
	var notes []string
	var points []domain.ThroughputPoint
	for _, n := range contextSizes {
		prompt := makePrompt(n)
		r, err := p.Driver.Complete(ctx, engine, llamacpp.CompletionRequest{Prompt: prompt, NPredict: 1, CachePrompt: false, SlotID: 0})
		if err != nil {
			notes = append(notes, fmt.Sprintf("prefill probe ctx=%d failed: %v", n, err))
			continue
		}
		points = append(points, domain.ThroughputPoint{ContextTokens: r.Timings.PromptN, TokPerSec: r.Timings.PromptPerSec})
	}
	return points, notes
}

func (p *Prober) measureDecode(ctx context.Context, engine *domain.EngineInstance, concurrencies []int, nPredict int) ([]domain.ThroughputPoint, []string) {
	var notes []string
	var points []domain.ThroughputPoint
	for _, c := range concurrencies {
		type res struct {
			tokPerSec float64
			err       error
		}
		ch := make(chan res, c)
		for i := 0; i < c; i++ {
			slot := i % 4
			go func(slot int) {
				r, err := p.Driver.Complete(ctx, engine, llamacpp.CompletionRequest{
					Prompt:   "Tell me a short story about a robot exploring an old space station.",
					NPredict: nPredict, CachePrompt: false, SlotID: slot,
				})
				if err != nil {
					ch <- res{err: err}
					return
				}
				ch <- res{tokPerSec: r.Timings.PredictedPerSec}
			}(slot)
		}
		var total float64
		var okCount int
		for i := 0; i < c; i++ {
			r := <-ch
			if r.err != nil {
				notes = append(notes, fmt.Sprintf("decode probe concurrency=%d stream failed: %v", c, r.err))
				continue
			}
			total += r.tokPerSec
			okCount++
		}
		if okCount == 0 {
			continue
		}
		points = append(points, domain.ThroughputPoint{Concurrency: c, TokPerSec: total})
	}
	return points, notes
}
