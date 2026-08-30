# Liveness & failure handling — requirements from real production failures

Source: `pod-monitor/LB_TROUBLESHOOTING.md` — 13 incidents from running the primitive
`lb-proxy.js` over a real multi-GPU pool (local Ti's + 3090/5060Ti/3080 + rentals).
This distills them into hard requirements for VRAM Governor and extends §40 (Failure
Handling). Every requirement below is traceable to an incident that actually happened.

## The one lesson under all of them

> **The LB's `active`/`queued` counts are not ground truth.** They reflect what the LB
> *thinks* it dispatched, never whether the backend is doing real work. Almost every
> incident presented identically — `active` pinned at `maxConcurrent`, `queued` climbing,
> **backend GPU idle, backend log silent** — a stalled in-flight request on a backend the
> LB couldn't see into. Four+ distinct root causes, one symptom.

The fix is not a single timeout. It is **three independent liveness signals**, because the
failure can be at the node, in the in-flight work, or at the client — and they fail
independently.

## Signal 1 — Node liveness (mostly already handled, and partly designed away)

- Heartbeat from the **node agent running on the backend itself** (Phase 1 ✅). Because the
  agent reports from *on* the box, a network path that looks alive but relays nothing can't
  fool it — the controller simply sees the heartbeat stop.
- **§34A outbound-dial design eliminates whole incident classes.** Incidents #1 (zombie SSH
  tunnel still "listening") and #4 (missing Windows→WSL portproxy) both stem from the
  controller reaching *into* a backend over a fragile forwarded port. VRAM Governor nodes
  **dial the controller outbound** and inference is driven by the on-node agent, so there is
  no inbound tunnel/portproxy to go stale. These failures cannot occur by construction.
- **Node self-health** catches #13 (faulty rental / bad RAM): the node agent runs a quick
  self/probe check on join; a node that can't complete its measurement probe is marked
  degraded, not scheduled. Ties to `docs/measurement.md`.
- **Deployment requirement (from #5, #6):** the node agent MUST run as a durable service
  (systemd unit), never backgrounded inside a shell/`nohup`/session. Incidents #5 and #6
  were both "the process didn't actually survive." Ship a proper service unit; do not rely
  on shell backgrounding.

## Signal 2 — Work-item progress deadline (THE missing piece)

This is the highest-value addition and the direct cure for the recurring symptom.

- The worker (node agent driving the runtime) **streams progress** — tokens generated so
  far — for every in-flight work item, not just a final result.
- A lease carries a **no-progress deadline**, NOT a fixed wall-clock timeout. Reset the
  deadline on every token/progress tick. If no progress arrives within the window →
  the item is **stalled**: revoke the lease, requeue on a different worker (add the stalled
  worker to the item's `tried` set), and flag the worker.
- **Why not a fixed timeout:** incidents #3 and #7 were *legitimately slow* generations
  (hidden 300s socket ceiling; uncapped 2340-token output) killed by a wall-clock timeout
  and then misdiagnosed as backend hangs. A progress-based deadline keeps a slow-but-alive
  generation alive while still catching a truly hung one fast.
- **Cross-check with node GPU telemetry (§22/§23, Phase 2).** The controller already receives
  real GPU util/VRAM per node. "This node holds a lease but its GPU has been idle for N s" is
  an independent stall signal — the automated form of the log's standing rule *"always verify
  real GPU activity, never trust the active count."* Combine: no token progress AND idle GPU
  ⇒ high-confidence stall.
- Helps #1, #12, and de-risks #3/#7. Requires streaming passthrough (see
  `docs/gateway-and-queue.md` upgrade #3).

## Signal 3 — Client presence (the original hypothesis, scoped correctly)

- **Connection-close detection (already have, Phase 3 abort-drop).** This is what actually
  fixed incident #2: when the client's socket closes, mark the item aborted, drop it, never
  requeue phantom work. Preserve this exactly.
- **Optional client heartbeat / keepalive** adds value only for the narrow case where the
  client holds the connection open but has logically given up (its own timer fired, it's no
  longer reading). A lightweight client keepalive (or requiring the client to consume the
  stream) lets the LB reclaim that slot. Belt-and-suspenders — lower priority than Signals 1
  and 2, which cover the dominant, backend-side failure mass.

## What VRAM Governor does NOT try to fix

Several incidents were pure client/ops/config bugs the LB can't and shouldn't fix (#5, #7,
#8, #9, #10). The LB's job is to be **robust to them**: progress-based deadlines instead of
fixed timeouts mean a client's uncapped-generation bug degrades gracefully (slow) instead of
masquerading as a dispatch failure. Don't absorb client correctness into the LB; just don't
get fooled by it.

## Routing note (from #12)

The unresolved ~5% (#12) is plausibly weighted-random occasionally routing to a backend
already saturated past its own request-queue depth. VRAM Governor's cost-based routing (§37)
with measured per-backend capacity + live queue depth replaces weighted-random and should cut
this — a backend at its measured concurrency ceiling stops being a candidate (headroom gate,
carried from lb-proxy), and ties get broken by measured throughput, not chance.

## Requirement checklist (for Phases 3–5)

- [x] Client connection-close → abort-drop (Phase 3)
- [x] Cross-worker retry via `tried` set (Phase 3)
- [x] Node heartbeat + SUSPECT/LOST (Phase 1)
- [x] Outbound-dial transport removes tunnel/portproxy failure classes (§34A design)
- [ ] **Work-item no-progress deadline (reset per token) + requeue** — add to jobs manager
- [ ] **Streaming passthrough** so progress is observable (gateway)
- [ ] **Controller stall cross-check: leased work + idle GPU telemetry** — add to scheduler
- [ ] Node self-health gate on join (degraded if probe fails)
- [x] Ship node agent as a systemd service unit (no shell backgrounding)
- [ ] (Optional) client keepalive for held-open-but-abandoned connections
