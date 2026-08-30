# Prerequisite spike — lead-weight sleep→wake measurement

> Throwaway ~1-day spike, run **before any controller code** (architecture §42, §47).
> It answers one question: **does Milestone A's lead restore ship on SLEEP_RAM
> (predictive overlap) or must it fall back to EVICTED?**

## What it measures

On the **actual target card**, over ~20 sleep/wake cycles, for vLLM sleep
level 1 (SLEEP_RAM) and level 2 (EVICTED):

| Metric | Meaning | Feeds |
|---|---|---|
| `T_sleep` | time to offload/discard lead weights | handoff step 5–7 |
| `T_wake_weights` | time to restore weights | predictive restore (§10) |
| `T_first_token_after_wake` | wall time to 1 token after wake | resume readiness |
| `vram_freed_gb` | free-VRAM delta the sleep actually yields | burst shard count (decision #32) |
| stability across cycles | stdev / p95 | whether predictive timing is trustworthy |

The scheduler **computes** freed VRAM and restore timing from measurements, never
config (decisions #32, §20). This spike is the first hand-run instance of that.

## Level → design mapping

- `level 1` → **SLEEP_RAM**: weights offloaded to host RAM, KV discarded. Fast wake.
- `level 2` → **EVICTED**: weights discarded; wake reloads from disk/page cache. Slower.

## Setup (target card)

vLLM needs Python 3.9+ (3.10/3.11 recommended). The dev box here is Python 3.8,
so use a fresh venv:

```bash
# on the target GPU box
python3.11 -m venv .venv-spike
source .venv-spike/bin/activate      # Windows: .venv-spike\Scripts\activate
pip install --upgrade pip
pip install vllm pynvml
```

> vLLM's sleep/wake API requires the engine be started with
> `enable_sleep_mode=True` — the harness does this.

## Run

```bash
python sleep_wake_spike.py \
    --model Qwen/Qwen2.5-3B-Instruct \
    --levels 1 2 \
    --cycles 20 \
    --gpu-memory-utilization 0.85 \
    --output spike_result.json
```

**Model choice matters.** Pick a model that fits the card *with headroom* so the
freed-VRAM delta is meaningful:
- Validation on the 10 GB RTX 3080 dev box: a 3B model.
- On the real large-VRAM target card: the actual **lead** model you intend to run
  (e.g. Qwen 27B), because sleep/wake time scales with weight size.

## Reading the result

The script prints a `DECISION INPUT` block. Rule of thumb:

- **SLEEP_RAM wins** (build Milestone A on level 1) if `T_wake_weights +
  T_first_token_after_wake` at p95 is small and *stable* enough that the
  predictive-drain window (§10) can hide it behind the batch tail, and
  `vram_freed_gb` is close to the lead's weight size.
- **Fall back to EVICTED** (level 2) if level 1 is unsupported on the card,
  frees little VRAM, or has a wake budget too large/jittery to overlap. Milestone A
  still ships — just with a slower, less predictive restore.

## Caveats / honesty notes

- `vram_freed_gb` uses **global NVML free-memory delta**, not per-PID accounting.
  Fine for an isolated spike (nothing else should touch the card during the run);
  the production node agent does per-PID VRAM (§23). Close other GPU users first.
- `T_first_token_after_wake` includes prefill of a tiny prompt — it's the
  demo-relevant "lead is usable again" number, not pure weight-load time.
- Unusual mining cards (CMP 170HX, BC250) are exactly why this runs on the *real*
  card: vLLM support and sleep behavior there are unverified until measured.

## Next step after the spike

Feed the numbers into the Milestone A restore design, then start Phase 1
(controller skeleton, §47). Delete this spike or fold its harness into
`scripts/benchmarks/` as the seed of the measured-footprint probe (Phase 2).
