# Implementation status

Last audited: 2026-08-26. See `docs/live-verification-2026-08-26.md` for the
live-only evidence and explicit release gaps.

This is the source of truth for roadmap status. The repository is not an A-Z
production release. It contains a substantial control-plane implementation,
but several important boundaries still have only deterministic test coverage.
PostgreSQL and sequential LLM + ComfyUI operation have now been exercised on
the current RTX 3080 deployment; the complete first-release acceptance matrix
has not yet passed.

## Status meanings

- **Live-proven**: exercised end-to-end against the current local hardware or
  an actual external service.
- **Implemented / simulated**: production-shaped code exists and deterministic
  tests pass, but the external integration has not been accepted live.
- **Partial**: an interface or subset exists, but the roadmap behavior is not
  complete.
- **Missing**: the roadmap behavior is not implemented.

Passing unit tests is not treated as proof that PostgreSQL, ComfyUI, S3, a
cloud provider, restart recovery, or hardware co-scheduling works in a real
deployment.

## Current 3080 test deployment

| Boundary | Status | Evidence / limitation |
|---|---|---|
| NVIDIA device telemetry | Live-proven | Node agent reports the 3080 inventory, utilization, temperature, and VRAM. |
| Local LLM inference | Live-proven | Ollama-backed 3B and 14B requests have run through the scheduler. |
| Demand model load/unload | Live-proven | Cold-to-hot transitions and eviction before a larger request were exercised without downloading models. Readiness is verified from Ollama's live process inventory. |
| Signed node control service | Live-proven | The restricted systemd node agent survived restart/reconnect and completed durable HMAC-signed capability refresh, Ollama load/unload, and Comfy reclaim commands. It has no arbitrary shell or installation command. |
| Runtime drain / scheduler enable | Live-proven | Runtime drain unloaded Ollama and reclaimed Comfy on the owning node while scheduler admission remained enabled. Scheduler enable/disable was toggled separately and persisted. |
| Chat model switching | Live-proven at API/build level | The transcript is retained by default and re-prefilled by the new model; cross-model KV cache is not retained. The UI can clear context on switch. |
| Controller persistence | Live-proven for completed/queued state | PostgreSQL 16 is authoritative. Sessions, queued work, exact approval, completed Comfy mapping/history/artifact, incidents, and one-attempt execution records survived controller restarts. PostgreSQL itself was restarted and the controller reconnected. Mid-flight recoverable execution still needs a safe externally fenced soak. |
| ComfyUI | Live-proven (core path) | Official ComfyUI 0.34.0 is connected on the same 3080 inventory. Discovery, compatibility filtering, central submission, native WebSocket node/current/total progress, upload/staging, execution, pending and running cancellation, history, artifact collection/retrieval, and restart pinning passed with existing weights. |
| OpenRouter | **Not live-proven** | No provider call, budget settlement, or rate-limit recovery has been accepted live. |
| S3-compatible storage | **Not live-proven** | The deployment uses filesystem artifacts. |
| Context/slot measurement | Partial | The active Ollama route reports configured/fallback capacity rather than a verified runtime slot envelope. |
| Warm host-RAM tier | Partial contract | It is capability-gated, but the active Ollama target does not advertise guaranteed warm-RAM retention. |
| Cross-adapter VRAM release | Live-proven | Comfy `/free` and Ollama model eviction are now automatic, capability-gated, fenced, durable `cross_adapter_reclaim` transitions. Both Comfy→Ollama and Ollama→Comfy directions passed on the 3080. |
| Adaptive GPU sharing | Not live-proven | Sharing is disabled on the current route and no real interference profile has been calibrated. |

The Operator Console returns and displays these facts under **Release
readiness**. It remains conservative while runtime capacity measurement and
the remaining dual-workload acceptance cases are incomplete.

## Roadmap audit

### Milestone 0 — stabilize the repository

| Item | Status |
|---|---|
| Project-scoped Git baseline | Live-proven as a subtree-scoped baseline in the existing parent repository. Runtime caches, generated binaries, local data, and UI dependencies are ignored. |
| Documentation reflects actual state | In progress. This audit replaces the earlier blanket completion claim. Some design documents still describe intended behavior and must not be read as acceptance evidence. |
| Formatting and work-item operation-version identity | Implemented / tested. |
| API, store, WebSocket, node-agent, runtime tests | Implemented, with meaningful deterministic coverage. Controller startup and real-service integration coverage remain thin. |
| Reconnect, telemetry retention, mutation auth, `n_predict` decoding | Implemented / tested. |
| Compatibility APIs | Implemented. |

### Milestone 1 — durable and secure core

| Item | Status |
|---|---|
| PostgreSQL store and migrations | Live-proven locally. Migrations through `0014_target_policy_overrides.sql` are applied; the controller recovered a target override after restart and applied it when the node-discovered route registered. |
| Restart recovery | Partial / broad live evidence. Sessions, queued work, exact approval, prompt mapping, completed workload, one-attempt count, incident, history, and artifact retrieval survived controller restart. PostgreSQL service interruption recovered. Running external execution and pending webhook recovery still need live fault injection. |
| Idempotency and audit events | Implemented / tested. |
| Filesystem artifacts | Implemented / tested locally. |
| S3-compatible artifacts | Implemented / simulated with an HTTP test server; not accepted against an actual S3-compatible service. |
| Scoped credentials, ownership, node identities, admin CIDRs, CSRF | Implemented / tested. |
| Browser sessions | Live-proven at HTTP/session level. UI and admin cookies are independent across planes and controller/DB restarts; PostgreSQL contains only 64-character session and CSRF hashes. Visual browser acceptance is blocked by the browser-automation kernel. |
| Durable event-driven state machine | Partial. The active deployment is PostgreSQL-backed; not every mid-flight adapter state has live recovery evidence. |
| Signed webhook outbox | Implemented / simulated, including allowlist and SSRF tests; no live receiver acceptance. |

### Milestone 2 — first usable dual-workload release

This milestone is **not complete**. It may only be released when both LLM and
ComfyUI work end-to-end in one deployment.

| Item | Status |
|---|---|
| OpenAI-compatible local inference and streaming | Live-proven. Real 3B/14B inference, SSE completion, lease renewal beyond TTL, disconnect cancellation, model switching, and cold-load fail-fast passed. |
| External Comfy discovery and filtering | Live-proven with official ComfyUI 0.34.0. Model inventory now includes UNET, text encoder, VAE, and LoRA loader fields rather than checkpoints alone. |
| Central Comfy queue, sticky routing, progress, uploads, history, cancel, outputs | Live-proven for the core path. The adapter now consumes native Comfy WebSocket progress and persists stage, node, current, and total values; that added fidelity still needs a new live workflow acceptance run. |
| OpenRouter fallback, allowlists, budget, circuit breaker, egress | Implemented / simulated; not accepted against OpenRouter. |
| Workload Studio and Admin Dashboard | Implemented / needs renewed browser acceptance. Both build and are embedded. Studio now includes real side-effect-free placement previews, durable decision traces, Comfy node progress, exact approval, priority/cancel, and output retrieval. Admin includes telemetry, load/offload status, residency, same-model profile routing, durable sharing policy, integration readiness, and incident create/propose/escalate workflows. |
| Exclusive scheduling, wait decision, model residency, notifications | Implemented. Exclusive 3080 scheduling and residency are live-proven; durable notifications are not live-proven. |

### Milestone 3 — adaptive orchestration

| Item | Status |
|---|---|
| QoS, deadlines, disruption policy, ETA decisions | Implemented / simulated. ETA confidence remains historical and sparse on new routes. |
| Yield/checkpoint/resume transitions | **Partial interface, missing real adapter support.** The real HTTP adapters return `workload operation unsupported`; only cancellation is generally usable. |
| Residency planning and fenced transitions | Implemented; Ollama load/unload is live-proven. Guaranteed warm-RAM offload is not. |
| Envelope composition and interference learning | Implemented / simulated. No real hardware co-scheduling calibration or rollback acceptance. |
| Transformation proposal and exact-plan approval | Live-proven with real Comfy resolution transformation, wrong-hash rejection, changed-workflow invalidation, execution, artifact output, and restart persistence. |
| Safe video checkpoint chunking | **Missing as a real adapter capability.** It cannot be claimed from workflow rewriting alone. |
| Expanded Studio controls and history | Implemented / needs live UI acceptance. Scheduling preview, transform review, decision/audit trace, progress, preemption plan counts, outputs, reprioritization, cancellation, and approval controls are present. |

### Milestone 4 — system-agent plane

| Item | Status |
|---|---|
| Durable incidents, severity/confidence, evidence references | Live-proven in PostgreSQL for monitor-created and automatic node-loss incidents, including clamps and recovery. |
| Local/cloud verifier escalation with independent authority | Local path live-proven with the real 3B route and recorded provider/model. Cloud path is not live-proven. |
| Observe → analyze → verify → propose API boundary | Partial. A built-in observer opens a durable S2 incident when a node becomes lost and marks it recovered after verified reconnection. Create, escalate, status reconciliation, SSE, and proposal endpoints exist; broader telemetry/evidence monitors and autonomous model analysis do not. |
| Automated remediation | Intentionally deferred and not implemented. |

### Milestone 5 — later extensions

Governor-managed runtime installation, remediation playbooks, OIDC/full
tenancy, controller HA, power control, predictive wake, and additional real
adapters are not implemented.

## Original acceptance scenarios

| Scenario | Status |
|---|---|
| Restart restores all state without duplicate execution | Broad partial live evidence. Sessions, queued work, approval, incident, prompt mapping/workload/artifact and one attempt recovered; mid-flight external work and pending outbox remain. |
| Operation versions remain distinct and idempotency deduplicates | Implemented / tested. |
| Locked video blocks incompatible 20B request with durable ETA | Deterministic scheduler test only. |
| Measured background sharing admits bounded interactive work safely | Deterministic scheduler test only. |
| Unknown combination learns and rolls back | Deterministic scheduler test only. |
| Material workflow change invalidates approval | Live-proven against real Comfy; the changed plan hash rejected the old approval. |
| Comfy prompt pin survives progress/history/cancel/restart/output | Live-proven for native node/current/total progress, history, pending/running cancel, restart mapping, and output. |
| Missing Comfy model/custom node excludes backend without installation | Live-proven; the backend was excluded and the custom-node directory remained unchanged. |
| OpenRouter failures fall back without budget escape/retry storm | Simulated provider tests only. |
| Sensitive evidence stays local unless egress requirements pass | Implemented policy tests. |
| Monitoring model can request a verifier without gaining authority | Implemented policy tests. |
| Priority/severity clamps and victim disruption consent | Implemented / tested. |
| Cross-owner/admin isolation | Implemented / tested. |
| Node loss fences late results and safely re-admits work | Queued-work and incident recovery live-proven with the actual node agent. Mid-flight recoverable external execution/late-result fencing remains deterministic only. |
| Webhook SSRF and duplicate delivery protection | Implemented / simulated. |

## Next completion sequence

1. Extend the live PostgreSQL recovery soak to queued/running work,
   transitions, approvals, incidents, and pending notifications.
2. Finish live Comfy WebSocket progress, upload, cancellation, and automatic
   idle/cross-adapter VRAM reclamation acceptance on the 3080.
3. Exercise an allowed OpenRouter account and S3-compatible store, including
   rate limits, budget settlement, redaction/egress, and retry behavior.
4. Add runtime-specific checkpoint/yield support before enabling disruption
   policies that imply resumability.
5. Calibrate exclusive envelopes and then guarded sharing on real hardware
   before marking adaptive co-scheduling ready.
6. Finish the Studio/Admin workflows and build the autonomous, read-only
   monitoring loop for Milestone 4.

Existing local model weights remain the default; adding or downloading models
is an explicit operator action rather than scheduler behavior.
