# Spike results — lead-weight sleep/reload (llama.cpp EVICTED path)

**Date:** 2026-08-23 · **Card:** RTX 3080 10 GB (dev box, PCIe) · **Runtime:** llama.cpp `llama-server`
**Model:** Qwen 9B Q5_K_M (6.2 GB GGUF), `-ngl 999 -c 2048`, 20 cycles
**Report:** `spike_9b_llamacpp.json`

> Caveat on hardware: this is the dev 3080, **not** a final target card (CMP 170HX / BC250).
> Reload speed is bounded by host-RAM→VRAM transfer, so re-run on the real cards — a
> slow-PCIe mining card could move the wake number materially.

## Numbers (20 cycles, page-cache-warm)

| Metric | mean | stdev | p95 |
|---|---|---|---|
| `T_sleep` (teardown → VRAM released) | 0.241 s | 0.023 | 0.277 |
| `T_wake_weights` (relaunch → READY) | 1.814 s | 0.070 | 1.890 |
| `T_first_token_after_wake` | 0.021 s | 0.004 | 0.027 |
| `vram_freed_gb` | 5.96 GiB | 0.00 | — |
| **Restore budget** (wake + first token, p95) | | | **~1.92 s** |

Cold load (weights read from disk, first ever load): **8.5 s**.
Page-cache-warm reload: **~1.8 s** — a **~4.7× speedup** from mmap keeping the GGUF in host RAM.

## What this decides (architecture §42)

**Milestone A's predictive restore works on llama.cpp with the EVICTED path alone — SLEEP_RAM (vLLM) is not required to make it viable.**

- Restore budget is small (**~1.9 s p95**) and extremely stable (**±70 ms** wake). That is
  trivially hideable behind a batch tail by the predictive-drain scheduler (§10):
  begin reloading the lead ~2 s before the batch queue drains and it is READY on time.
- Teardown fully reclaims the lead's VRAM (**5.96 GiB**, zero variance) — so freed VRAM is
  measurable and reliable, which is what the burst-shard count formula needs (decision #32).
- The mmap page-cache effect gives ~80% of SLEEP_RAM's benefit (weights served from host
  RAM, not disk) with **zero engine support** — good for the "runs on all hardware" goal,
  since llama.cpp is far more portable to oddball cards than vLLM.

## The important gap this spike does NOT measure

`T_first_token_after_wake` here is **0.02 s only because the probe prompt is 1 token.** The
real cost of restoring a *lead with a long session* is **re-prefilling its context** — EVICTED
discards KV, so on restore the runtime must recompute prefill from canonical/tokenized state
(§8A.4 "recompute prefill from token_ids"). For a lead sitting on, say, 40 K tokens of context,
that re-prefill dominates restore and dwarfs the 1.8 s weight reload.

**Implication for Milestone A design:** the restore-time estimate the scheduler uses (§10, §31)
must be `T_wake_weights + T_reprefill(context_len)`, not just weight reload. Two ways to shrink
the re-prefill term, both worth a follow-up spike:
1. **llama.cpp slot save/restore** (`--slot-save-path`, `/slots/{id}?action=save|restore`) — persist
   the lead's KV to disk on sleep, restore it on wake instead of recomputing. This is the
   llama.cpp analogue of the §8A.3 KV snapshot; measure whether restore beats re-prefill.
2. Measure prefill throughput vs context length on the target card (§15) so the scheduler can
   *predict* re-prefill cost and start the reload earlier.

---

# KV snapshot spike — slot save/restore vs recompute (llama.cpp)

**Harness:** `kv_restore_spike.py` · **Report:** `spike_kv_9b.json` · same card/model/build.
Answers the gap flagged above: EVICTED discards KV, so what does restoring a lead's
*context* cost — recompute-prefill vs llama.cpp slot save/restore?

## The methodology trap (worth remembering)

First pass reported a bogus "16–27× win" because it measured a **degenerate resume**:
re-sending the *identical* context after restore. On this build that re-prefills in
full (the prompt-matcher won't reuse a restored slot when the request is not a strict
extension of it). The **real** resume appends a new turn (§8B: the tool result
answering the open `compute_handoff` call), i.e. `context + new_suffix`. With that,
the restored KV covers the `context` prefix and only the new turn prefills. Always
measure the real resume shape.

## Numbers (9B Q5, ctx=8192, KV verified reused = only ~12 new tokens prefilled)

| Context | Recompute (full prefill) | KV path: restore + new-turn prefill | KV file | Speedup |
|--------:|-------------------------:|------------------------------------:|--------:|--------:|
| 1,000 tok | 0.33 s | 0.026 + 0.139 = **0.16 s** | 82 MiB | 2.0× |
| 2,000 tok | 0.64 s | 0.042 + 0.125 = **0.17 s** | 113 MiB | 3.8× |
| 4,000 tok | 1.21 s | 0.039 + 0.131 = **0.17 s** | 175 MiB | 7.1× |
| 7,000 tok | 2.11 s | 0.050 + 0.093 = **0.14 s** | 269 MiB | 14.7× |

Slot save was ~80–130 ms. KV file grows ~**38 MiB per 1,000 tokens** (9B Q5).

## What this decides

**Build llama.cpp slot save/restore into the runtime driver as the §8A.3 KV snapshot.**

- The KV path is **near-constant (~0.15 s)** regardless of context size, while recompute
  grows linearly. The win widens with context — and a lead orchestrator carries large
  contexts, so this matters exactly where it counts. Extrapolating: a 40 K-token lead
  would recompute in ~12 s but restore its KV in ~0.15 s.
- **Full lead restore on llama.cpp** = `T_wake_weights (~1.8 s) + T_slot_restore (~0.05 s)
  + new-turn prefill (~0.13 s)` ≈ **~2.0 s, flat across context size.** That is trivially
  hideable by predictive drain (§10) no matter how big the lead's context is.
- Without the KV snapshot, restore time grows with context and the predictive window must
  widen accordingly — workable for small contexts, poor for large ones.

## Storage cost (feeds §8A.5)

~38 MiB / 1K tokens ⇒ a 40 K-context lead ≈ ~1.5 GiB KV snapshot. This is the
"large by reference" blob that lives in object store / NAS, never in Postgres. The
canonical session row just holds a `kv_snapshot_ref` + the `prompt_fingerprint` that
validates it (§8A.3/§8A.4).

## Caveat carried forward

Restore correctness still rides on the fingerprint chain (§8A.4): a restored KV blob
must be trusted only when `prompt_fingerprint` matches the tokenized layer, which matches
canonical.version. The spike shows the *mechanism* is fast and works across teardown; the
driver must still gate reuse on that fingerprint so stale KV is never silently used.

---

## Runtime/model notes

- The **2B GGUF (`qwen3.5_2b.gguf`) does not load** on the current `llama-server` build:
  `qwen35.rope.dimension_sections has wrong array length; expected 4, got 3` — a llama.cpp
  version skew. The 9B loads fine. (Not blocking; noted for whoever re-runs.)
- Only `llama-server` is built (no `llama-cli`); the harness drives it over HTTP.
