# Measurement & Performance Profiles — the "prober" subsystem

> **Locked principle (elevates decision #32 and §20 to a hard rule):**
> The scheduler consumes **only measured performance data**. No timing, footprint,
> throughput, or capability is ever hardcoded, configured by hand, or inferred from
> a GPU's model name. Every node **self-measures** the components that matter, on the
> real hardware + real runtime + real model, and the scheduler reads those profiles.
> Where a profile is missing, the scheduler uses conservative feasibility only and
> **flags the gap** — it never guesses a number.
>
> This is what makes VRAM Governor work on heterogeneous, unseen hardware (mining
> cards, APUs, rented GPUs) instead of only where the author tested. It is a
> correctness requirement for an open-source release, not an optimization.

The RTX 3080 / Qwen-9B-Q5 spike numbers in `scripts/spike/SPIKE_RESULTS.md` are a
**validation of method on one card**, and the reference implementation of three of the
probes below — not constants to be reused anywhere.

---

## 1. Performance identity (the profile key)

Every measured profile is keyed by the full identity (§20). Two setups that differ in
any field are different profiles; results are never shared across them:

```
hardware (gpu model + vram + pcie gen/width + host cpu/ram + disk)
+ runtime (+ version)          # llama.cpp, vLLM, ...
+ model artifact (+ revision)
+ quantization
+ context profile              # ctx length band
+ shard_count
+ concurrency
```

## 2. Capabilities are detected, never assumed (§6)

Before timing anything, the prober asks each runtime driver what it can do and
**verifies it by trying it**, then records the result per node+runtime:

```
supports_weight_sleep_to_ram   # vLLM sleep(1); llama.cpp: false
supports_kv_offload_cpu
supports_kv_snapshot_save/restore  # llama.cpp slot save/restore: true (measured)
supports_staged_wake
supports_hot_kv_resize
supports_prefill_decode_split
supports_continuous_batching
```

A capability claimed but failing a probe is recorded as **unsupported** (empirical wins
over documentation — the whole reason the spikes existed).

## 3. What gets measured, by component that matters

| Component | Metrics | Reference impl |
|---|---|---|
| **GPU compute — prefill** | prompt tok/s vs context length; TTFT; concurrency scaling (§15) | TODO probe (next spike) |
| **GPU compute — decode** | per-stream tok/s; aggregate tok/s vs concurrency; inter-token latency | TODO probe |
| **Model residency** | cold load time; **VRAM footprint (measured per-PID, NVML)**; host-RAM footprint | `evict_reload_spike.py` |
| **Weight sleep/wake** | T_sleep, T_wake, VRAM freed, stability — *if* `supports_weight_sleep_to_ram` | `sleep_wake_spike.py` (vLLM) |
| **Evict/reload** | teardown→VRAM-freed time, reload→ready (cache-warm & cold) | `evict_reload_spike.py` |
| **KV cache** | bytes/token; snapshot save/restore time + on-disk size — *if* supported | `kv_restore_spike.py` |
| **Interconnect** | host↔VRAM (PCIe) bandwidth; weight disk-read bandwidth | TODO probe |
| **Network** | RX/TX, controller RTT, packet loss, sustained transfer; per-node-pair transfer/KV-transfer benchmark (§17, §19) | TODO probe |
| **Batch** | items/sec, avg work-item latency, error/retry rate for a representative op (§15) | TODO probe |

**Derived, not measured directly:** burst shard count = `floor(measured_free_after_sleep
/ measured_worker_footprint)` (decision #32); full lead-restore budget = `T_wake_weights
+ min(T_kv_restore + new-turn prefill, T_reprefill(ctx))` (from the KV spike). Both are
computed from the rows above per node, every time.

## 4. Where probing lives

Probing is a **node-agent responsibility**, driven in Go against the runtime's own API
(exactly how the Python spikes drive `llama-server` over HTTP) so **no Python is required
on nodes** — a single portable agent binary must run on any card for the open-source story.
The Python spikes remain as the readable reference + a dev harness.

- **On node join:** fast path — detect hardware, probe capabilities, measure footprint +
  load/sleep/wake for the node's desired profile(s). Enough to schedule feasibly.
- **Background / on-demand:** fuller curves (prefill vs ctx, decode vs concurrency,
  network, per-node-pair). Rich curves are §47 Phase 8/9; the join-time footprint probe
  is Phase 2 and is a **Milestone A prerequisite** (§47 note).
- **Re-probe triggers:** new model/quant/profile, driver/runtime upgrade, or drift beyond
  a tolerance detected from live telemetry.

## 5. Storage

- `PerformanceProfile` rows (Postgres) keyed by §1 identity: the scalar results
  (footprint, load/sleep/wake times, tok/s points, kv bytes/token, capability flags),
  plus `measured_at`, `runtime_version`, sample count / variance.
- Large artifacts (full curves, raw samples) by reference in object store / NAS (§8A.5).
- The scheduler's feasibility filter (§36) and cost function (§37) read these rows and
  **only** these rows.

## 6. Honesty rules (open-source credibility)

- Never extrapolate a profile across hardware, quant, or runtime version.
- Surface staleness and variance in the UI; a high-variance probe is a scheduling risk
  input, not a hidden average.
- A missing profile is a visible "unmeasured — measuring…" state, never a silent default.
- Every scheduler decision that used a profile can name the profile + `measured_at`
  (feeds the §31 explainability requirement).

---

## 7. Immediate next probe (extends the spikes)

`prefill_decode_probe` — measure prompt tok/s vs context length and decode tok/s vs
concurrency on this card, so restore/prefill cost (the open item from the KV spike) and
routing decisions come from data. Same shape as the existing harnesses: drive the runtime
API, sweep the parameter, persist rows keyed by §1 identity.
