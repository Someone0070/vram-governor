#!/usr/bin/env python3
"""
VRAM Governor — Prerequisite spike (llama.cpp / EVICTED path).

Purpose (architecture §42 spike, decision #7):
    The SLEEP_RAM predictive-restore path needs a runtime with weight-sleep-to-
    host-RAM (vLLM sleep level 1). llama.cpp has no such API — its only lever is
    EVICTED: tear the engine down (free VRAM) and reload. This harness measures
    that EVICTED cycle on the ACTUAL card + the ACTUAL GGUF models, because
    llama.cpp is the primary runtime for this deployment ("runs on all hardware").

    The wrinkle that makes EVICTED viable here: llama.cpp mmaps the GGUF, so after
    the first load the file lives in the OS page cache. A reload then reads weights
    from host RAM into VRAM, not from disk — a poor-man's SLEEP_RAM. This spike
    quantifies whether that reload is fast + stable enough to hide behind the batch
    tail (§10), or whether the lead must simply stay resident on llama.cpp cards.

What it measures, per cycle:
    T_sleep                  process teardown -> VRAM actually released   (s)
    T_wake_weights           relaunch -> server READY (weights in VRAM)   (s)
    T_first_token_after_wake READY -> first token returned                (s)
    vram_freed_gb            free-VRAM delta the teardown yields          (GiB)
    vram_resident_gb         VRAM the loaded model occupies               (GiB)

Runtime: llama.cpp `llama-server` (HTTP). Stdlib-only (urllib + subprocess);
VRAM read via `nvidia-smi`, so no pynvml dependency.

Usage (inside WSL Ubuntu):
    python3 evict_reload_spike.py \
        --server ~/llama.cpp/build/bin/llama-server \
        --model  ~/models/qwen3.5_2b.gguf \
        --ngl 999 --cycles 20 \
        --output spike_llamacpp_2b.json
"""

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def nvidia_free_mib(index):
    """Global free VRAM (MiB) on the given GPU index, via nvidia-smi."""
    out = subprocess.check_output(
        ["nvidia-smi", f"--id={index}",
         "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
        text=True,
    )
    return int(out.strip().splitlines()[0])


def mib_to_gib(m):
    return m / 1024.0


def summarize(samples):
    if not samples:
        return {}
    s = sorted(samples)
    n = len(s)
    p95 = s[min(n - 1, max(0, int(round(0.95 * n)) - 1))]
    return {
        "mean": statistics.fmean(s), "median": statistics.median(s),
        "p95": p95, "stdev": statistics.pstdev(s) if n > 1 else 0.0,
        "min": s[0], "max": s[-1], "n": n,
    }


def wait_ready(port, proc, timeout=300):
    """Poll /health until the server reports ok. Returns when READY or raises."""
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"llama-server exited early (code {proc.returncode})")
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200 and b'"ok"' in r.read():
                    return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.05)
    raise TimeoutError("server did not become ready in time")


def one_token(port):
    """POST a 1-token completion; return wall time to response."""
    body = json.dumps({"prompt": "Hello", "n_predict": 1,
                       "temperature": 0.0, "cache_prompt": False}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/completion", data=body,
        headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as r:
        r.read()
    return time.perf_counter() - t0


def launch(server, model, ngl, port, extra):
    env = dict(os.environ)
    # llama-server needs its sibling .so's on the library path.
    libdir = os.path.dirname(os.path.abspath(os.path.expanduser(server)))
    env["LD_LIBRARY_PATH"] = libdir + ":" + env.get("LD_LIBRARY_PATH", "")
    cmd = [os.path.expanduser(server),
           "-m", os.path.expanduser(model),
           "-ngl", str(ngl),
           "--host", "127.0.0.1", "--port", str(port)] + extra
    return subprocess.Popen(cmd, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def teardown(proc):
    """Kill the server and wait until VRAM is actually released."""
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=30)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="~/llama.cpp/build/bin/llama-server")
    ap.add_argument("--model", required=True)
    ap.add_argument("--ngl", type=int, default=999, help="GPU layers to offload.")
    ap.add_argument("--cycles", type=int, default=20)
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--gpu-index", type=int, default=0)
    ap.add_argument("--extra", nargs=argparse.REMAINDER, default=[],
                    help="Extra args passed through to llama-server (after --extra).")
    ap.add_argument("--output", default="spike_llamacpp.json")
    args = ap.parse_args()

    free_empty = nvidia_free_mib(args.gpu_index)
    print(f"Free VRAM before any load : {mib_to_gib(free_empty):.2f} GiB")
    print(f"Model  : {args.model}")
    print(f"Server : {args.server}   (-ngl {args.ngl})")
    print(f"Cycles : {args.cycles}\n")

    samples = {k: [] for k in
               ("T_sleep", "T_wake_weights", "T_first_token_after_wake",
                "vram_freed_gb", "vram_resident_gb")}

    # ---- Cold load (cycle 0): first load pulls weights from disk into page cache
    t0 = time.perf_counter()
    proc = launch(args.server, args.model, args.ngl, args.port, args.extra)
    wait_ready(args.port, proc)
    cold_load = time.perf_counter() - t0
    free_resident = nvidia_free_mib(args.gpu_index)
    resident = free_empty - free_resident
    print(f"Cold load (disk->cache->VRAM): {cold_load:.2f}s   "
          f"resident VRAM {mib_to_gib(resident):.2f} GiB\n")
    _ = one_token(args.port)  # warm the pipeline once, untimed

    print("=== EVICTED reload cycles (weights served from page cache) ===")
    for i in range(args.cycles):
        free_before = nvidia_free_mib(args.gpu_index)

        # SLEEP == EVICTED: tear down the engine, VRAM returns to the driver.
        t0 = time.perf_counter()
        teardown(proc)
        # poll until VRAM actually drops back (release is async on some drivers)
        for _ in range(200):
            free_after_kill = nvidia_free_mib(args.gpu_index)
            if free_after_kill - free_before > (0.3 * resident):
                break
            time.sleep(0.02)
        t_sleep = time.perf_counter() - t0
        freed = free_after_kill - free_before

        # WAKE: relaunch; weights read from page cache (host RAM) into VRAM.
        t0 = time.perf_counter()
        proc = launch(args.server, args.model, args.ngl, args.port, args.extra)
        wait_ready(args.port, proc)
        t_wake = time.perf_counter() - t0

        t_first = one_token(args.port)

        samples["T_sleep"].append(t_sleep)
        samples["T_wake_weights"].append(t_wake)
        samples["T_first_token_after_wake"].append(t_first)
        samples["vram_freed_gb"].append(mib_to_gib(freed))
        samples["vram_resident_gb"].append(mib_to_gib(resident))

        print(f"  cycle {i + 1:>2}/{args.cycles}  "
              f"sleep={t_sleep:6.3f}s  wake={t_wake:6.3f}s  "
              f"first_tok={t_first:6.3f}s  freed={mib_to_gib(freed):6.2f} GiB",
              flush=True)

    teardown(proc)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime": "llama.cpp/llama-server",
        "restore_mode": "EVICTED (mmap page-cache reload)",
        "model": args.model, "ngl": args.ngl,
        "cold_load_seconds": cold_load,
        "cycles": args.cycles,
        "raw": samples,
        "summary": {k: summarize(v) for k, v in samples.items()},
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 70)
    print("SUMMARY  (mean +/- stdev, p95)")
    print("=" * 70)
    for m in ("T_sleep", "T_wake_weights", "T_first_token_after_wake",
              "vram_freed_gb", "vram_resident_gb"):
        s = report["summary"][m]
        unit = "GiB" if m.startswith("vram") else "s"
        print(f"  {m:<26} {s['mean']:7.3f} +/- {s['stdev']:5.3f} {unit}"
              f"   (p95 {s['p95']:7.3f}, min {s['min']:7.3f}, max {s['max']:7.3f})")

    s_wake = report["summary"]["T_wake_weights"]
    s_ft = report["summary"]["T_first_token_after_wake"]
    budget = s_wake["p95"] + s_ft["p95"]
    print("\n" + "=" * 70)
    print("DECISION INPUT (architecture §42, llama.cpp EVICTED path):")
    print(f"  Restore budget p95 (reload + first token): {budget:.2f}s")
    print(f"  VRAM reclaimed per teardown (mean):        "
          f"{report['summary']['vram_freed_gb']['mean']:.2f} GiB")
    print("  -> If this budget is small + stable, predictive drain (§10) can hide")
    print("     the lead reload behind the batch tail even without SLEEP_RAM.")
    print("  -> If it is large/jittery, keep the lead resident on llama.cpp cards")
    print("     and reclaim VRAM only from worker shards.")
    print("=" * 70)
    print(f"\nFull report: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
