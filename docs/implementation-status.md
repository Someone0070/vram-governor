# Implementation status

Last audited: 2026-08-30. See `docs/live-verification-2026-08-26.md` and
`docs/live-verification-2026-08-30.md` for live-only evidence and explicit
release gaps.

This is the source of truth for roadmap status. The repository is not an A-Z
production release. It contains a substantial control-plane implementation,
but several important boundaries still have only deterministic test coverage.
PostgreSQL, LLM + ComfyUI arbitration, dual-profile LLM routing, and guarded
same-GPU sharing have now been exercised on the current RTX 3080 deployment;
the complete production release matrix has not yet passed.

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
| Controller persistence | Live-proven, including mid-flight safety | PostgreSQL 16 is authoritative. Sessions, queued work, exact approval, completed Comfy mapping/history/artifact, incidents, and execution records survived controller restarts. A running Comfy execution was reconciled through backend cancellation before a new attempt; no overlapping duplicate was issued. Unknown/unconfirmed backend state fails indeterminate rather than replaying. |
| ComfyUI | Live-proven (core path) | Official ComfyUI 0.34.0 is connected on the same 3080 inventory. Discovery, compatibility filtering, central submission, native WebSocket node/current/total progress, upload/staging, execution, pending and running cancellation, history, artifact collection/retrieval, and restart pinning passed with existing weights. |
| OpenRouter | **Not live-proven** | No provider call, budget settlement, or rate-limit recovery has been accepted live. |
| S3-compatible storage | **Not live-proven** | The deployment uses filesystem artifacts. |
| Context/slot measurement | Partial | The live node advertises separate 2,048-context/two-slot and 8,192-context/one-slot Ollama profiles and routes correctly. These values are operator-configured runtime arguments, so the UI labels them configured rather than benchmark-verified. |
| Warm host-RAM tier | Partial contract | It is capability-gated, but the active Ollama target does not advertise guaranteed warm-RAM retention. |
| Cross-adapter VRAM release | Live-proven | Comfy `/free` and Ollama model eviction are now automatic, capability-gated, fenced, durable `cross_adapter_reclaim` transitions. Both Comfy→Ollama and Ollama→Comfy directions passed on the 3080. |
| Adaptive GPU sharing | Live-proven for dual Ollama profiles | Guarded sharing admitted simultaneous short- and long-context requests for the same model artifact. Live GPU use peaked at 8,412/10,240 MiB under a 1,024 MiB reserve, persisted a successful sample/profile, and restored its policy after controller restart. Cross-adapter sharing and a live rollback threshold violation remain unproven. |

The Operator Console returns and displays these facts under **Release
readiness**. It remains conservative while runtime capacity measurement and
the remaining dual-workload acceptance cases are incomplete.

## Roadmap audit

### Milestone 0 — stabilize the repository

| Item | Status |
|---|---|
| Project-scoped Git baseline | Live-proven as a subtree-scoped baseline in the existing parent repository. Runtime caches, generated binaries, local data, and UI dependencies are ignored. |
| Documentation reflects actual state | Audited for the current deployment. Design documents still describe intended behavior and are not acceptance evidence unless linked from a dated live-verification report. |
| Formatting and work-item operation-version identity | Implemented / tested. |
| API, store, WebSocket, node-agent, runtime tests | Implemented, with meaningful deterministic coverage. Controller startup and real-service integration coverage remain thin. |
| Reconnect, telemetry retention, mutation auth, `n_predict` decoding | Implemented / tested. |
| Compatibility APIs | Implemented. |

### Milestone 1 — durable and secure core

| Item | Status |
|---|---|
| PostgreSQL store and migrations | Live-proven locally. Migrations through `0014_target_policy_overrides.sql` are applied; the controller recovered a target override after restart and applied it when the node-discovered route registered. |
| Restart recovery | Live-proven for state and one running Comfy fault injection. Completed external executions are collected in place; running/unknown executions are requeued only after confirmed backend stop, otherwise failed indeterminate. Pending webhook recovery still needs a live receiver. |
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
| Central Comfy queue, sticky routing, progress, uploads, history, cancel, outputs | Live-proven for the core path, including native Comfy node/current/total progress. A later local Z-Image restart soak reached controller recovery correctly but the current Comfy process exhausted its 15 GiB WSL host-memory allocation while reading model weights; that external runtime failure is not counted as a successful image run. |
| OpenRouter fallback, allowlists, budget, circuit breaker, egress | Implemented / simulated; not accepted against OpenRouter. |
| Workload Studio and Admin Dashboard | Implemented / needs renewed visual browser acceptance. Both build and are embedded. Admin controls are wired to real policy, scheduling, runtime-drain, residency, signed-command, and incident APIs; performance ranges, hover values, percentage axes, raw logs, GPU/host/network telemetry, TPS/TTFT, transition progress, and conservative release readiness are present. Browser automation is currently blocked before launch by its local kernel-assets error. |
| Exclusive scheduling, wait decision, model residency, notifications | Implemented. Exclusive 3080 scheduling and residency are live-proven; durable notifications are not live-proven. |

### Milestone 3 — adaptive orchestration

| Item | Status |
|---|---|
| QoS, deadlines, disruption policy, ETA decisions | Implemented / simulated. ETA confidence remains historical and sparse on new routes. |
| Yield/checkpoint/resume transitions | **Partial interface, missing real adapter support.** The real HTTP adapters return `workload operation unsupported`; only cancellation is generally usable. |
| Residency planning and fenced transitions | Implemented; Ollama load/unload is live-proven. Guaranteed warm-RAM offload is not. |
| Envelope composition and interference learning | Live-proven for one guarded dual-Ollama combination. Real VRAM observations and successful learning persisted; completed shared LLM requests now retain measured timing/TPS and derive slowdown against an earlier standalone profile. A physical rollback-threshold violation remains unproven. |
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
| Restart restores all state without duplicate execution | Live-proven for durable state and a mid-flight Comfy cancellation/requeue. The controller did not overlap backend attempts. Pending live webhook-outbox recovery remains. |
| Operation versions remain distinct and idempotency deduplicates | Implemented / tested. |
| Locked video blocks incompatible 20B request with durable ETA | Deterministic scheduler test only. |
| Measured background sharing admits bounded interactive work safely | Live-proven for two same-model Ollama context profiles on one 3080; heterogeneous LLM/video sharing remains unproven. |
| Unknown combination learns and rolls back | Deterministic scheduler test only. |
| Material workflow change invalidates approval | Live-proven against real Comfy; the changed plan hash rejected the old approval. |
| Comfy prompt pin survives progress/history/cancel/restart/output | Live-proven for native node/current/total progress, history, pending/running cancel, restart mapping, and output. |
| Missing Comfy model/custom node excludes backend without installation | Live-proven; the backend was excluded and the custom-node directory remained unchanged. |
| OpenRouter failures fall back without budget escape/retry storm | Simulated provider tests only. |
| Sensitive evidence stays local unless egress requirements pass | Implemented policy tests. |
| Monitoring model can request a verifier without gaining authority | Implemented policy tests. |
| Priority/severity clamps and victim disruption consent | Implemented / tested. |
| Cross-owner/admin isolation | Implemented / tested. |
| Node loss fences late results and safely re-admits work | Live node transport and mid-flight controller restart paths were fault-injected. Backend work is only re-admitted after confirmed stop; unconfirmed state fails without duplication. Late fenced-result rejection also has deterministic coverage. |
| Webhook SSRF and duplicate delivery protection | Implemented / simulated. |

## Next completion sequence

1. Exercise pending notification/webhook recovery against a real allowlisted
   receiver and validate an actual S3-compatible object store.
2. Re-run the local Z-Image restart soak after giving Comfy sufficient host
   memory, or use the already-connected remote Comfy route with a compatible
   small workflow.
3. Exercise an allowed OpenRouter account, including
   rate limits, budget settlement, redaction/egress, and retry behavior.
4. Add runtime-specific checkpoint/yield support before enabling disruption
   policies that imply resumability.
5. Calibrate additional exclusive envelopes and a real heterogeneous sharing
   rollback on hardware.
6. Complete visual browser acceptance and expand the autonomous, read-only
   monitoring loop for Milestone 4.

Existing local model weights remain the default; adding or downloading models
is an explicit operator action rather than scheduler behavior.
