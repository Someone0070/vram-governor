#!/usr/bin/env python3
"""
VRAM Governor — Prerequisite spike: lead-weight sleep -> wake measurement.

Purpose (architecture §42 "Prerequisite spike", decision #7):
    Measure, on the ACTUAL target card, how a resident lead model's weights
    behave when slept to host RAM and woken again. These numbers decide whether
    Milestone A's restore path is built on SLEEP_RAM (level 1, predictive
    overlap) or must fall back to EVICTED (level 2, full unload -> reload).

What it measures, per cycle, per sleep level:
    T_sleep                  wall time of sleep()             (seconds)
    T_wake_weights           wall time of wake_up()           (seconds)
    T_first_token_after_wake wall time to produce 1 token after wake (seconds)
    vram_freed_gb            free-VRAM delta the sleep actually yielded (GiB)
    vram_resident_gb         free VRAM while the lead is resident (context)
    ...repeated ~N cycles so stability / variance is visible.

Mapping to the locked design:
    level 1  ->  SLEEP_RAM  (weights offloaded to host RAM, KV discarded)
    level 2  ->  EVICTED    (weights discarded; wake reloads from disk cache)

The scheduler never *configures* freed VRAM or restore timing — it measures
them (decisions #32, §20). This spike is the first, throwaway instance of that
measurement, run by hand before any controller code exists.

Runtime: vLLM. Requires the engine be started with enable_sleep_mode=True.
Output: a JSON report + a human-readable summary table to stdout.

Usage:
    python sleep_wake_spike.py \
        --model Qwen/Qwen2.5-3B-Instruct \
        --levels 1 2 \
        --cycles 20 \
        --gpu-memory-utilization 0.85 \
        --output spike_result.json

Pick a --model that comfortably fits the target card WITH headroom, so the
freed-VRAM delta is meaningful. On a 10 GB RTX 3080 a 3B model at q-ish/fp16
is a reasonable validation load; on the real large-VRAM target card use the
actual lead model you intend to run (e.g. Qwen 27B).
"""

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone


def _get_nvml_free_bytes(handle):
    """Global free VRAM on the device, in bytes, via NVML."""
    import pynvml
    info = pynvml.nvmlDeviceGetMemoryInfo(handle)
    return int(info.free)


def _fmt_gb(nbytes):
    return nbytes / (1024 ** 3)


def summarize(samples):
    """Return {mean, median, p95, stdev, min, max} for a list of floats."""
    if not samples:
        return {}
    s = sorted(samples)
    n = len(s)
    # nearest-rank p95
    p95_idx = min(n - 1, max(0, int(round(0.95 * n)) - 1))
    return {
        "mean": statistics.fmean(s),
        "median": statistics.median(s),
        "p95": s[p95_idx],
        "stdev": statistics.pstdev(s) if n > 1 else 0.0,
        "min": s[0],
        "max": s[-1],
        "n": n,
    }


def run_level(llm, handle, level, cycles, prompt, warmup=True):
    """
    Run `cycles` sleep/wake cycles at a given vLLM sleep level.
    Returns a dict of raw per-cycle samples + the resident/asleep VRAM context.
    """
    from vllm import SamplingParams

    one_token = SamplingParams(max_tokens=1, temperature=0.0)

    samples = {
        "T_sleep": [],
        "T_wake_weights": [],
        "T_first_token_after_wake": [],
        "vram_freed_gb": [],
        "vram_resident_gb": [],
        "vram_asleep_gb": [],
    }

    # Ensure the model is awake and warm before we start timing.
    # A first generation compiles/allocates lazily; don't let that pollute cycle 1.
    if warmup:
        llm.generate([prompt], one_token, use_tqdm=False)

    label = "SLEEP_RAM (level 1)" if level == 1 else "EVICTED (level 2)"
    print(f"\n=== {label}: {cycles} cycles ===", flush=True)

    for i in range(cycles):
        free_resident = _get_nvml_free_bytes(handle)

        t0 = time.perf_counter()
        llm.sleep(level=level)
        t_sleep = time.perf_counter() - t0

        free_asleep = _get_nvml_free_bytes(handle)
        freed = free_asleep - free_resident  # positive == VRAM handed back

        t0 = time.perf_counter()
        llm.wake_up()
        t_wake = time.perf_counter() - t0

        # First token after wake: a single-token generation exercises the
        # freshly restored weights end-to-end (this is the demo-relevant number).
        t0 = time.perf_counter()
        llm.generate([prompt], one_token, use_tqdm=False)
        t_first_token = time.perf_counter() - t0

        samples["T_sleep"].append(t_sleep)
        samples["T_wake_weights"].append(t_wake)
        samples["T_first_token_after_wake"].append(t_first_token)
        samples["vram_freed_gb"].append(_fmt_gb(freed))
        samples["vram_resident_gb"].append(_fmt_gb(free_resident))
        samples["vram_asleep_gb"].append(_fmt_gb(free_asleep))

        print(
            f"  cycle {i + 1:>2}/{cycles}  "
            f"sleep={t_sleep:6.3f}s  wake={t_wake:6.3f}s  "
            f"first_tok={t_first_token:6.3f}s  freed={_fmt_gb(freed):6.2f} GiB",
            flush=True,
        )

    return samples


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True,
                    help="HF model id or local path for the lead-model stand-in.")
    ap.add_argument("--levels", type=int, nargs="+", default=[1, 2], choices=[1, 2],
                    help="vLLM sleep levels to test. 1=SLEEP_RAM, 2=EVICTED.")
    ap.add_argument("--cycles", type=int, default=20,
                    help="Sleep/wake cycles per level (spike doc asks ~20).")
    ap.add_argument("--gpu-memory-utilization", type=float, default=0.85)
    ap.add_argument("--max-model-len", type=int, default=4096)
    ap.add_argument("--prompt", default="Summarize the theory of relativity in one word:")
    ap.add_argument("--device-index", type=int, default=0,
                    help="NVML device index to read free VRAM from.")
    ap.add_argument("--output", default="spike_result.json")
    args = ap.parse_args()

    # Import heavy deps here so --help works without them installed.
    try:
        import pynvml
        from vllm import LLM
    except ImportError as e:
        print(f"ERROR: missing dependency: {e}\n"
              f"Install into a py3.10+ venv:  pip install vllm pynvml", file=sys.stderr)
        return 2

    pynvml.nvmlInit()
    handle = pynvml.nvmlDeviceGetHandleByIndex(args.device_index)
    gpu_name = pynvml.nvmlDeviceGetName(handle)
    if isinstance(gpu_name, bytes):
        gpu_name = gpu_name.decode()
    total_vram = _fmt_gb(pynvml.nvmlDeviceGetMemoryInfo(handle).total)

    print(f"Target card : {gpu_name}  ({total_vram:.1f} GiB total)")
    print(f"Model       : {args.model}")
    print(f"Levels      : {args.levels}   Cycles/level: {args.cycles}")

    # enable_sleep_mode=True is mandatory for llm.sleep()/wake_up() to exist.
    load_t0 = time.perf_counter()
    llm = LLM(
        model=args.model,
        enable_sleep_mode=True,
        gpu_memory_utilization=args.gpu_memory_utilization,
        max_model_len=args.max_model_len,
    )
    cold_load_seconds = time.perf_counter() - load_t0
    print(f"Cold load   : {cold_load_seconds:.2f}s")

    results = {}
    for level in args.levels:
        raw = run_level(llm, handle, level, args.cycles, args.prompt)
        results[f"level_{level}"] = {
            "mode": "SLEEP_RAM" if level == 1 else "EVICTED",
            "raw": raw,
            "summary": {k: summarize(v) for k, v in raw.items()},
        }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gpu_name": gpu_name,
        "gpu_vram_total_gb": total_vram,
        "model": args.model,
        "gpu_memory_utilization": args.gpu_memory_utilization,
        "max_model_len": args.max_model_len,
        "cycles_per_level": args.cycles,
        "cold_load_seconds": cold_load_seconds,
        "levels": results,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # ---- Human-readable decision summary ----
    print("\n" + "=" * 70)
    print("SUMMARY  (mean +/- stdev, p95)")
    print("=" * 70)
    metrics = ["T_sleep", "T_wake_weights", "T_first_token_after_wake",
               "vram_freed_gb"]
    for level in args.levels:
        block = results[f"level_{level}"]
        print(f"\n{block['mode']} (level {level}):")
        for m in metrics:
            s = block["summary"][m]
            unit = "GiB" if m.startswith("vram") else "s"
            print(f"  {m:<26} {s['mean']:7.3f} +/- {s['stdev']:5.3f} {unit}"
                  f"   (p95 {s['p95']:7.3f}, min {s['min']:7.3f}, max {s['max']:7.3f})")

    # ---- The actual go/no-go the spike exists to answer ----
    print("\n" + "=" * 70)
    print("DECISION INPUT (architecture §42):")
    if 1 in args.levels:
        l1 = results["level_1"]["summary"]
        restore_overlap = l1["T_wake_weights"]["p95"] + l1["T_first_token_after_wake"]["p95"]
        print(f"  SLEEP_RAM restore budget (p95 wake + first-token): {restore_overlap:.2f}s")
        print(f"  SLEEP_RAM VRAM freed (mean):                       "
              f"{l1['vram_freed_gb']['mean']:.2f} GiB")
        print("  -> If this restore budget is small and stable, Milestone A")
        print("     ships on SLEEP_RAM with predictive overlap (§10).")
    if 2 in args.levels:
        l2 = results["level_2"]["summary"]
        print(f"  EVICTED restore budget (p95 wake + first-token):   "
              f"{l2['T_wake_weights']['p95'] + l2['T_first_token_after_wake']['p95']:.2f}s")
        print("  -> Fallback path if SLEEP_RAM is unsupported/too slow on the card.")
    print("=" * 70)
    print(f"\nFull report written to: {args.output}")

    pynvml.nvmlShutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
