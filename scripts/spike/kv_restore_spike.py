#!/usr/bin/env python3
"""
VRAM Governor — Spike: realistic lead-restore cost (llama.cpp KV paths).

Follows up the EVICTED weight-reload spike (evict_reload_spike.py). That one
showed weight reload is ~1.8s. But EVICTED discards KV, so restoring a lead that
holds real context means paying to rebuild that context. This measures the two
ways to do it, at several context lengths:

    A) RECOMPUTE  — reload weights, then re-prefill the whole context from
                    canonical/tokenized state (§8A.4 "recompute prefill").
                    This is the baseline EVICTED restore with no KV snapshot.

    B) SLOT KV    — before sleep, save the slot's KV to disk (llama.cpp
                    /slots/{id}?action=save); after reload, restore it
                    (action=restore), then continue the session. This is the
                    llama.cpp analogue of the §8A.3 KV snapshot.

IMPORTANT — measure the REAL resume, not a degenerate one. On resume the lead
appends a NEW turn (§8B: a tool result answering the open compute_handoff call),
so the resume request is `context + new_suffix`, and the restored KV covers the
`context` prefix. Re-sending the *identical* context is a degenerate case that
this llama.cpp build re-prefills in full — so the harness always appends a suffix,
matching how the scheduler actually resumes a lead.

For each context length it reports:
    T_reprefill        pure prefill time to rebuild context (path A)   (s)
    T_slot_save        time to write KV to disk                        (s)
    T_slot_restore     time to load KV from disk into VRAM             (s)
    kv_file_mb         on-disk KV snapshot size (§8A.5 storage cost)   (MiB)
    prompt_tokens      actual tokens in the context (server-reported)

Decision output: whether path B beats path A on this card, and the storage cost
per lead session. Requires llama-server started with --slot-save-path.

Usage (inside WSL Ubuntu):
    python3 kv_restore_spike.py \
        --server ~/llama.cpp/build/bin/llama-server \
        --model  ~/models/Qwen3.8-9B-Q5_K_M.gguf \
        --ctx 8192 --ngl 999 \
        --context-tokens 1000 3000 6000 \
        --output spike_kv_9b.json
"""

import argparse
import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def post(port, path, payload, timeout=300):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def wait_ready(port, proc, timeout=300):
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"llama-server exited (code {proc.returncode})")
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200 and b'"ok"' in r.read():
                    return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.05)
    raise TimeoutError("server not ready")


def launch(server, model, ngl, port, ctx, slot_path, extra):
    env = dict(os.environ)
    libdir = os.path.dirname(os.path.abspath(os.path.expanduser(server)))
    env["LD_LIBRARY_PATH"] = libdir + ":" + env.get("LD_LIBRARY_PATH", "")
    cmd = [os.path.expanduser(server), "-m", os.path.expanduser(model),
           "-ngl", str(ngl), "-c", str(ctx), "--host", "127.0.0.1",
           "--port", str(port), "--slot-save-path", slot_path] + extra
    return subprocess.Popen(cmd, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def teardown(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait(timeout=30)


def make_prompt(approx_tokens):
    """Build a prompt of roughly approx_tokens tokens (server reports the real count)."""
    # Varied words so it isn't pathologically compressible; ~1 token/word for Qwen.
    words = ("the quick brown fox jumps over the lazy dog while a curious cat "
             "watches quietly from the wooden fence near the old red barn ").split()
    out = []
    i = 0
    while len(out) < approx_tokens:
        out.append(words[i % len(words)])
        i += 1
    return " ".join(out)


def prefill_only(port, prompt, use_cache, slot=0):
    """Send prompt with n_predict=1; return (prompt_n, prompt_ms) from timings."""
    r = post(port, "/completion", {
        "prompt": prompt, "n_predict": 1, "temperature": 0.0,
        "cache_prompt": use_cache, "id_slot": slot,
    })
    t = r.get("timings", {})
    return int(t.get("prompt_n", 0)), float(t.get("prompt_ms", 0.0))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="~/llama.cpp/build/bin/llama-server")
    ap.add_argument("--model", required=True)
    ap.add_argument("--ngl", type=int, default=999)
    ap.add_argument("--ctx", type=int, default=8192)
    ap.add_argument("--port", type=int, default=8082)
    ap.add_argument("--slot-path", default="/tmp/kvslots")
    ap.add_argument("--context-tokens", type=int, nargs="+", default=[1000, 3000, 6000])
    ap.add_argument("--extra", nargs=argparse.REMAINDER, default=[])
    ap.add_argument("--output", default="spike_kv.json")
    args = ap.parse_args()

    os.makedirs(args.slot_path, exist_ok=True)
    print(f"Model: {args.model}   ctx={args.ctx}   context sizes={args.context_tokens}\n")

    # A short new turn appended on resume (what §8B actually does).
    RESUME_SUFFIX = " Given all of the above, produce the final answer now:"

    results = []
    for target in args.context_tokens:
        context = make_prompt(target)
        resume_prompt = context + RESUME_SUFFIX
        fname = f"lead_{target}.bin"
        fpath = os.path.join(args.slot_path, fname)
        if os.path.exists(fpath):
            os.remove(fpath)

        proc = launch(args.server, args.model, args.ngl, args.port,
                      args.ctx, args.slot_path, args.extra)
        try:
            wait_ready(args.port, proc)

            # Prime slot 0 with the context (KV now resident), record real token count.
            context_tokens, _ = prefill_only(args.port, context, use_cache=True)

            # --- Path A: RECOMPUTE. Cost of rebuilding context from scratch on
            #     restore = a fresh full prefill of the resume prompt (no cache). ---
            reprefill_ms = []
            for _ in range(2):
                n_fresh, ms = prefill_only(args.port, resume_prompt, use_cache=False)
                reprefill_ms.append(ms)
            t_reprefill = min(reprefill_ms) / 1000.0

            # Re-prime so the saved KV holds exactly `context`.
            prefill_only(args.port, context, use_cache=True)

            # --- Path B: SLOT KV save ---
            t0 = time.perf_counter()
            save_resp = post(args.port, "/slots/0?action=save", {"filename": fname})
            t_save = time.perf_counter() - t0
            kv_mb = os.path.getsize(fpath) / (1024 * 1024) if os.path.exists(fpath) else 0.0
            n_saved = save_resp.get("n_saved", save_resp.get("n_written"))
        finally:
            teardown(proc)  # EVICTED: weights + KV gone from VRAM

        # Reload fresh (empty KV), restore saved KV, then RESUME with an appended turn.
        proc = launch(args.server, args.model, args.ngl, args.port,
                      args.ctx, args.slot_path, args.extra)
        try:
            wait_ready(args.port, proc)
            t0 = time.perf_counter()
            post(args.port, "/slots/0?action=restore", {"filename": fname})
            t_restore = time.perf_counter() - t0

            # Real resume: context (restored) + new turn. Only the new turn should prefill.
            resume_tokens, resume_ms = prefill_only(args.port, resume_prompt, use_cache=True)
        finally:
            teardown(proc)

        # KV path total = restore from disk + prefill of only the new turn.
        t_kv_path = t_restore + resume_ms / 1000.0
        kv_reused = resume_tokens < context_tokens * 0.5  # sanity: most of context reused
        row = {
            "target_tokens": target,
            "context_tokens": context_tokens,
            "T_reprefill_recompute_s": t_reprefill,
            "T_slot_save_s": t_save,
            "T_slot_restore_s": t_restore,
            "T_resume_prefill_s": resume_ms / 1000.0,
            "resume_prefill_tokens": resume_tokens,   # small => KV reused
            "T_kv_path_total_s": t_kv_path,
            "kv_file_mb": kv_mb,
            "n_saved_tokens": n_saved,
            "kv_reused": kv_reused,
        }
        results.append(row)
        speedup = (t_reprefill / t_kv_path) if t_kv_path > 0 else float("nan")
        flag = "" if kv_reused else "  <-- KV NOT reused!"
        print(f"ctx {context_tokens:>5} tok: "
              f"recompute={t_reprefill:6.3f}s  |  "
              f"KV: restore={t_restore:5.3f}s + new-turn prefill={resume_ms/1000:5.3f}s "
              f"({resume_tokens} tok) = {t_kv_path:5.3f}s  "
              f"kv={kv_mb:6.1f}MiB  {speedup:4.1f}x{flag}",
              flush=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime": "llama.cpp/llama-server",
        "model": args.model, "ctx": args.ctx, "ngl": args.ngl,
        "results": results,
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 70)
    print("DECISION INPUT — llama.cpp lead restore (weight reload ~1.8s is on top):")
    for r in results:
        if not r["kv_reused"]:
            verdict = "KV NOT reused on this build -> recompute is the only path"
        else:
            verdict = ("SLOT KV wins" if r["T_kv_path_total_s"] < r["T_reprefill_recompute_s"]
                       else "recompute is fine")
        print(f"  {r['context_tokens']:>5} tok ctx: recompute {r['T_reprefill_recompute_s']:.2f}s "
              f"vs KV-path {r['T_kv_path_total_s']:.2f}s  "
              f"({r['kv_file_mb']:.0f} MiB) -> {verdict}")
    print("  Real resume = restore KV + prefill only the new turn (§8B), not re-send context.")
    print("  Total lead restore = T_wake_weights (~1.8s) + this KV/recompute term.")
    print("  KV file size sets the §8A.5 'large by reference' storage cost per session.")
    print("=" * 70)
    print(f"\nFull report: {args.output}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
