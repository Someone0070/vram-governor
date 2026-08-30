# Gateway & Work Queue — carried over from the primitive balancer

The predecessor `lb-proxy.js` deployment
is a hand-rolled, battle-tested version of VRAM Governor's **OpenAI-compatible gateway +
whole-request router + at-least-once work queue** (§33 gateway, §12 work items, §37 routing).
It stays running as-is; its proven mechanisms become the design basis for VG Phases 3–5 so
we reuse working logic instead of reinventing it. This doc pins what to **keep verbatim in
spirit** vs what to **upgrade**, mechanism by mechanism.

## Keep — proven mechanisms to port into the Go gateway/queue

| lb-proxy mechanism | VG component (phase) | Note |
|---|---|---|
| **Zero-gap dispatch**: `tryDispatchQueue` runs on slot-free, capacity-add, AND new work | Job/work-item manager (Phase 3) | A freed lease immediately pulls the next item — never wait for the next client request. This is the §13 "keep capacity saturated, spill" behavior. |
| **Headroom-gated pick**: only backends with `active < maxConcurrent` are candidates | Scheduler feasibility filter (§36) | Concurrency ceiling per engine. In VG the ceiling is **measured** (see Upgrade #1), and it's `EngineInstance`/`WorkerPool` slots, not a raw backend. |
| **Capacity-weighted random** among candidates | Scheduler cost fn (§37), baseline | Good default before the full cost function exists. Weight becomes measured throughput, not a typed `maxConcurrent`. |
| **At-least-once + cross-backend retry**: `tried` set, requeue on 5xx/error, 502 when all tried | Work-item leases (§12) | Maps directly to `QUEUED→LEASED→RUNNING→{SUCCESS,FAILED,LEASE_EXPIRED→QUEUED}`. The `tried` set prevents retrying the same dead node; VG adds lease expiry + dedupe by `job_id+item_id+operation_version`. |
| **Client-abort handling**: `res.on('close') → aborted`, don't requeue phantom work | Work-item manager (§12) | Hard-won fix — a wave of client timeouts used to poison a backend with phantom retries. VG must preserve this: an abandoned item is dropped, not re-leased. |
| **Hot registry + persisted state**: `/admin/add|remove`, `state.json` | Node/pool desired-state (Phase 1 ✅) | Already covered better by VG's desired-vs-observed store + reconciler; the lb-proxy JSON is the same idea without liveness. |
| **OpenAI-compatible front door**: `/v1/chat/completions`, `/v1/models` | Gateway (§33) | Keep the contract identical so existing clients (and lb-proxy itself) can point at VG unchanged. |
| **Whole-request routing** (no prefill/decode split) | Default routing (§19) | Correct default, not a shortcut. Keep. |

## Upgrade — where VG must go beyond the primitive

1. **Measured concurrency, not `maxConcurrent`.** lb-proxy's `1/1/2/24/32` are hand-guessed.
   VG derives per-engine slot counts from the measured-footprint + throughput profiles
   (`docs/measurement.md`, decision #32). The guessed numbers are the single biggest thing
   this project replaces.
2. **Liveness before failure.** lb-proxy only learns a backend is dead by failing a request.
   VG has heartbeat + SUSPECT/LOST (Phase 1 ✅) and drains a node out of the candidate set
   *before* routing to it.
3. **Streaming passthrough.** lb-proxy buffers the whole response (`Buffer.concat`) — no SSE,
   full body in RAM. VG gateway must stream tokens through (SSE/chunked) and only buffer when
   a retry requires it.
4. **VRAM/residency awareness.** lb-proxy assumes every backend permanently serves the model.
   VG's differentiator (Milestone A) is that capacity is elastic: lead sleep, burst-shard
   expansion into freed VRAM, predictive restore. The queue/router must accept that a pool's
   slot count changes at runtime as shards spin up/down.
5. **Cost-based routing.** Replace weighted-random with the §37 estimate (queue delay, prompt
   length, prefill/decode split, measured throughput, network) once profiles exist.
6. **Observability.** lb-proxy exposes a single `/admin/status` snapshot. VG adds telemetry
   history, lifecycle events (§28), and per-decision explanations (§31).

## Migration path (no disruption)

VG's gateway will speak the same OpenAI API, so the cutover is: point clients (or lb-proxy's
own backends list) at the VG gateway when Phases 3–5 are ready. Until then lb-proxy keeps
serving; VG can be developed and measured alongside it. Existing accelerator and Ollama
hosts become VG **nodes** (each runs the node agent) rather than static backend URLs.
