# VRAM Governor capability report

**Assessment date:** 2026-08-31  
**Topology clarification:** 2026-09-03  
**Repository revision reviewed:** `e834db8` (`feat: harden live orchestration and fleet console`)  
**Assessment basis:** current source, deterministic regression coverage, dated
live-verification records, and a fresh read-only query of the running
controller on 2026-08-31.

> **Historical evidence notice:** The live measurements in this report are a
> snapshot of the 2026-08-31 WSL-based acceptance environment. They do not
> describe the current deployment topology. The current topology places the
> controller/load balancer and PostgreSQL on a dedicated machine, with node
> agents on the RTX 3080, RTX 3090, and CMP170 hosts. WSL is not required by the
> controller architecture.

## Executive summary

VRAM Governor is a substantial, working single-controller GPU control plane,
not an A-Z production release. Its strongest proven path is a PostgreSQL-backed
controller coordinating local LLM and external ComfyUI workloads through
restricted node agents on one shared accelerator inventory. The deployment can
discover devices and runtimes, route by context and slot capacity, demand-load
and unload models, reclaim VRAM between adapters, stream chat, centrally hold
Comfy prompts, persist execution state, and expose an operator console with
real hardware and workload telemetry.

The 2026-08-31 acceptance deployment had two connected nodes and four enabled
runtime targets. One RTX 3080 exposed two profiles for the same LLM artifact: a
2,048-token/two-slot target and an 8,192-token/one-slot target. Best-fit routing
has been exercised live: short requests preserve the scarce long-context slot,
while long requests use the only compatible target. Guarded simultaneous use
of those profiles also passed on the physical GPU.

The remaining release blockers are real external acceptance and adapter depth:
OpenRouter, S3-compatible storage, and signed webhooks are implemented but not
configured or live-proven; production HTTP adapters do not implement genuine
checkpoint/yield/resume; heterogeneous co-scheduling rollback has not been
fault-injected on hardware; and the embedded web interfaces still need a full
visual browser acceptance pass.

**Production release gate: NOT READY.** The system is useful now as a
controlled home-lab/development platform, provided operators understand the
unproven boundaries listed below.

## Status language

- **Live-proven** — exercised end to end against the running controller,
  physical hardware, PostgreSQL, or an actual external runtime.
- **Implemented/tested** — production-shaped code exists and deterministic
  tests pass, but the relevant external boundary was not exercised live.
- **Simulated only** — behavior was verified against an HTTP or runtime test
  double, not the external service.
- **Partial** — the contract or a useful subset exists, but the complete
  promised behavior does not.
- **Unavailable** — not implemented, intentionally deferred, or disabled in
  the 2026-08-31 acceptance deployment.

Passing a unit test is not treated as proof that a cloud provider, object
store, webhook receiver, GPU-sharing failure, or browser workflow works in the
deployed environment.

## Historical live deployment snapshot

The following facts were re-measured from the controller on 2026-08-31. No
credentials or host addresses are included. These facts are retained as
acceptance evidence and must not be used as the inventory or topology of the
current fleet.

| Area | Current observation |
|---|---|
| Controller state | PostgreSQL authority is enabled and ready. |
| Artifact backend | Filesystem backend is enabled and ready. |
| Fleet | Two node agents are connected, ready, scheduling-enabled, and reporting agent version 1.1.0. |
| Accelerators | One RTX 3080 with 10,240 MiB VRAM and one Quadro P4000 with 8,192 MiB VRAM are visible. |
| Runtime targets | Four enabled targets: two ComfyUI targets plus short- and long-context LLM profiles on the RTX 3080. |
| LLM profiles | The same model artifact is exposed at 2,048 context/two slots and 8,192 context/one slot. Capacity is operator-configured, not benchmark-certified. |
| Residency | Automatic residency is enabled; idle unload is 300 seconds, minimum residency is 60 seconds, and quiet hours are not configured. |
| System agent | One local verifier is ready; no cloud verifier models are allowed and paid emergency fallback is disabled. |
| OpenRouter | Disabled and not ready: no configured cloud routes. |
| Webhooks | Disabled and not ready: no allowlisted destinations or signing secret. |
| Storage | The remote Comfy renderer reported about 208 GiB free on its root disk; the local WSL node reported about 732 GiB free. These are point-in-time root-filesystem values, not artifact quotas. |
| Durable history | The queried database contained 53 workloads, 26 incidents, 50 residency transitions, and persisted scheduler-learning data. These are historical row counts, not health targets. |

At the same sample, both GPUs were responsive and had free VRAM. The RTX 3080
reported 6,632 MiB free, 25% utilization, and 62 C; the remote renderer reported
8,031 MiB free, 0% utilization, and 34 C. Telemetry is point-in-time and should
not be used as a capacity guarantee.

## Capability matrix

| Domain | Status | What works now | Important boundary |
|---|---|---|---|
| Unified workload state machine | Live-proven | Durable request, plan, decision, execution, event, lease, artifact, approval, notification, transition, learning, and incident records. | One active controller; not high availability. |
| Physical accelerator ownership | Live-proven | LLM and Comfy targets reference the same physical accelerator record, so unrelated adapters cannot double-book it. | Cross-controller arbitration does not exist. |
| Local LLM inference | Live-proven | OpenAI-style chat, SSE streaming, async execution, cancellation, usage capture, and durable performance metrics through the Ollama-compatible HTTP route. | The adapter is named `llamacpp` internally even when the current endpoint is Ollama-compatible. |
| Same-model context/slot routing | Live-proven | Chooses the smallest compatible context target, preserves the large-context slot, and supports sticky client placement. | Context/slot values are configured runtime facts rather than live benchmark results. |
| External ComfyUI | Live-proven core path | Discovery, compatibility filtering, central queueing, sticky prompt mapping, progress relay, upload/staging, history, cancellation, outputs, and artifact retrieval. | A recent local Z-Image soak exhausted host RAM; that run is not counted as a successful render. |
| OpenRouter | Implemented/tested; simulated only | Provider/model allowlists, egress checks, quarantine, budgets, actual-cost settlement, circuit breaking, and bounded fallback. | Not configured and not live-proven. |
| Mock adapter | Implemented/tested | Deterministic scheduler and recovery testing. | Never presented as production execution evidence. |
| Exclusive scheduling | Live-proven | Fenced leases, target slots, one shared physical inventory, honest waiting decisions, and event-driven reevaluation. | Multi-controller lease ownership is unavailable. |
| Adaptive co-scheduling | Partial; live-proven for one combination | P95 envelope composition, reserve, interference profiles, guarded exploration, runtime VRAM/thermal/slowdown checks, rollback path, and persisted learning. | Only dual-profile same-model Ollama sharing passed live; heterogeneous sharing and a physical rollback violation are not live-proven. |
| Model residency | Live-proven for disk/VRAM transitions | Demand loading, explicit load/unload, idle eviction, minimum residency, pinned protection, rollback after a failed replacement, transition progress, and historical ETA. | Guaranteed warm host-RAM retention is capability-gated and not advertised by the active Ollama target. |
| Cross-adapter VRAM reclaim | Live-proven | Fenced Comfy cache reclaim and Ollama eviction run automatically before incompatible demand loads. Both directions were exercised on the RTX 3080. | Reclaim depends on the owning node agent and runtime endpoint remaining reachable. |
| Drain versus admission | Live-proven | Runtime drain unloads/reclaims runtimes while leaving `Use for work` independently configurable. | Drain is not a power-off command. |
| Checkpoint/yield/resume | Partial | Scheduler interfaces, state transitions, and deterministic checkpoint-preemption tests exist. | Real HTTP adapters return unsupported; the UI must not promise resumability. |
| Workflow transformations | Live-proven for Comfy resolution change | Immutable original request, material plan hash, exact-hash approval, revalidation, delegated safe-review boundary, and invalidation after workflow/capability change. | Safe long-video chunk checkpointing is unavailable without adapter-proven boundaries. |
| Notifications | Implemented/tested | Durable in-app notifications and signed webhook outbox with retry/idempotency controls. | No live webhook destination has been accepted. |
| Incidents/system-agent plane | Partial; local path live-proven | Durable S0-S4 incidents, evidence, severity clamp, SSE events, local verifier escalation, provider/model recording, and non-executing proposals. Node loss/recovery observer is active. | Broader autonomous monitoring is incomplete; automated remediation is intentionally unavailable. |
| Filesystem artifacts | Live-proven | Durable local uploads, outputs, metadata, traversal rejection, and retrieval. | Filesystem backend is development-oriented and local to the controller host. |
| S3-compatible artifacts | Implemented/tested; simulated only | SigV4 upload/download and durable metadata passed against an HTTP simulator. | No real S3-compatible endpoint has been accepted. |
| Node package/control agent | Live-proven | Signed WebSocket registration, heartbeat, capability discovery, telemetry, logs, runtime/model inventory, and allowlisted control commands. | It deliberately cannot execute arbitrary shell commands, install software, or control power. |
| Operator Console | Implemented/tested at build/API level | Fleet overview, machines/jobs/scheduler/models, device/host/network telemetry, time ranges, hover values, axes, TPS/TTFT, raw logs, transitions, policies, load/unload, drain, scheduling, integration readiness, and incidents. | Complete visual browser acceptance is outstanding because the automation environment failed before page launch. |
| Workload Studio | Implemented/tested at build/API level | Async submission, side-effect-free preview, QoS/deadline/context bounds, placement, transformation review, approval, reprioritization, cancellation, events, and artifacts. | Usability still needs a fresh browser acceptance pass. |
| Chat UI | Live-proven at API/build level | Streaming chat, model selection, context/max-output controls, sticky session, and transcript continuity across model switches. | A model switch re-prefills the transcript; it does not retain the old model's KV cache. |
| Creator Studio integration | Implemented/tested | Hardware-neutral immutable profiles, strict requirements and explicit fallback, stable abstract blocking, sanitized state/artifacts, batches and dependencies, affinity, priority/latency classes, opaque continuations, and durable working-set/release hints. | Source migration `0015` and the API require live PostgreSQL/Creator Studio acceptance before this boundary is live-proven. |

## Scheduler behavior

### Admission and placement

The scheduler filters disconnected, disabled, incompatible, unauthorized, or
egress-ineligible targets. It evaluates model/custom-node availability,
context-dependent bounds, runtime slots, physical accelerator leases,
residency state, and victim disruption consent. Decisions include a blocker,
estimated start/end range, confidence, alternatives, target, accelerator,
context limit, slots, and the source of the capacity estimate where known.

Priority and incident severity are clamped to the authenticated principal's
ceiling. A high-priority request cannot displace a locked victim. Deadline,
QoS, queue policy, disruption policy, egress, concurrency, budget, and
preemption budget are part of the request and policy evaluation.

Waiting work is reevaluated on state changes such as lease release, execution
progress, node discovery, residency transitions, and provider recovery. The
preview endpoint is side-effect-free and uses the same placement logic, so
agents can ask where a job would run before submitting it.

### Same model with different context and slots

This case is explicitly supported. A request that fits both profiles is scored
toward the smaller compatible context target; a request that needs the larger
window can use only the long target. This prevents a short request from
occupying the scarce long-context slot and avoids loading or sharing an
oversized context configuration unnecessarily. Sticky placement can pin a
client/session to one compatible target when isolation is preferred.

Live validation used two simultaneous streams on the same model artifact.
Both completed while the physical GPU remained under the configured reserve;
the run peaked at 8,412/10,240 MiB, persisted an 8,324 MiB observation, and
recorded a successful learning sample. This proves that combination only, not
every model/profile pairing.

The current code also supports mutually exclusive profiles on one endpoint:
when the accelerator is idle, the scheduler can ask its restricted node agent
to switch from (for example) 8K/four slots to 32K/one slot and then admits only
after `/slots` confirms the new capacity. Active work on any adapter sharing
that accelerator blocks the restart. This path is deterministically tested but
has not yet passed physical-fleet acceptance. Stock Ollama does not report its
parallel-slot setting, so the fleet examples remain commented out until a
monitoring wrapper or a `/slots`-capable runtime is installed.

Model discovery now reports current/free/maximum slot counts, selectable
context profiles, and a per-model accelerator ceiling. The ceiling defaults to
one physical card (all slots on that card are still usable) and supports
explicit per-model overrides. Availability snapshots account for offline nodes,
foreign-adapter occupancy, and an already-consumed model card ceiling; final
submission can still queue because discovery does not reserve capacity.

### Capacity learning and safeguards

The learning backend stores standalone and shared execution observations. It
uses conservative p95 envelope composition, class-level interference data,
and exact fingerprints when enough evidence exists. Guarded exploration is
allowed only when both policies consent and reserve remains. Active checks can
abort the newcomer for VRAM reserve, temperature, error, or slowdown
violations. Learned parameters change data, not scheduler code.

## Model lifecycle and memory tiers

Known allowlisted models may move from cold disk to hot VRAM on demand. Before
a load, the controller can select an evictable resident model or reclaim a
different runtime's caches under the same accelerator lease. Load and unload
operations are signed, idempotent node commands with fencing tokens and durable
transition records. The UI receives transition status and an ETA based on
completed historical transitions; a first-ever transition is necessarily less
certain.

Idle models can return to disk after the configured timeout. Quiet-hours rules
existed but were not configured in the 2026-08-31 acceptance deployment. Warm host RAM is an
optional capability rather than an assumption: the scheduler will not claim
that a runtime retained a model in RAM unless the runtime advertises and proves
that tier. The controller never downloads a missing model or installs Comfy
custom nodes automatically.

## Protocol and API surface

The controller serves one gateway with security-plane-aware routes:

- OpenAI compatibility: `POST /v1/chat/completions`, `GET /v1/models`.
- Comfy compatibility: `POST /prompt`, `GET /ws`, `GET /history`,
  `GET /history/{id}`, `GET/POST /queue`, `POST /upload/image`,
  `POST /upload/mask`, and `GET /view`.
- Unified workloads: `POST /api/v1/workloads`, preview, list/get, cancellation,
  exact-plan approval, priority change, artifacts, explanation, events, and
  notifications.
- Creator Studio: `GET /api/v1/capabilities`, capability-oriented submission
  through the same workload endpoint, batch submission/status, and durable
  session working-set create/list/release routes. Public responses omit physical
  targets, accelerators, endpoints, memory, residency, and cache location.
- System agents: `/api/agent/v1/incidents`, incident proposal/escalation, and
  the agent event stream.
- Operators: `/admin/api/overview`, node telemetry, residency transitions,
  node commands, scheduling, drain, integrations, target policy, and incidents.
- Nodes: `GET/POST` compatibility inventory routes and the authenticated
  `/ws/node` telemetry/command channel.
- Embedded applications: `/chat/`, `/studio/`, and `/admin/`.

OpenAI fail-fast paths return structured capacity errors with retry guidance;
async workload submission returns a durable workload ID. Comfy submission
returns a public prompt ID immediately and keeps its backend mapping sticky
through progress, history, cancellation, restart recovery, and output lookup.

## Durability and recovery

Twenty ordered PostgreSQL migrations (`0001` through `0020`) define the
current source schema. PostgreSQL stores node/runtime state, workload identity
and operation version, idempotency, plans, approvals, leases and fencing,
Comfy prompt mappings, transitions, profiles, learning samples, notifications,
commands, browser sessions, audit events, artifacts metadata, budgets, and
incidents, immutable logical runtime profiles, Creator Studio working-set
hints, node enrollment, aligned capability-definition columns, workload
revision/budget-claim recovery fields, and durable accelerator lease cleanup
intents. Migration `0015` was applied to the local PostgreSQL 16 deployment
on 2026-08-31. Migrations `0016` through `0020`
are present in the current source tree but are not claimed as applied in that historical live run; no current live-database state is inferred from them.
The restarted controller accepted real profile discovery,
working-set, blocked-workload, idempotent LLM, and ordered-batch requests.

Controller restart recovery has been fault-injected. Completed external work
is collected in place without another start. A running Comfy prompt was stopped
at the backend before a new attempt was issued. When backend stop could not be
confirmed, the workload failed as indeterminate instead of risking duplicate
execution. Late results from an expired fence are rejected. This is meaningful
single-controller recovery evidence, not high availability.

## Security and control boundaries

The code supports hashed scoped credentials and separate browser sessions for
UI users, admins, node agents, workload clients, and monitoring agents.
Principals carry plane, owner, scopes, adapters, node restriction, priority and
severity ceilings, egress policy, concurrency, budget, and preemption limits.
Ownership checks prevent ordinary principals from reading another owner's
jobs or artifacts.

Admin access can be restricted to configured private CIDRs. Browser mutations
require CSRF protection; UI and admin sessions use independent HTTP-only
cookies. Production mode requires TLS and rejects development authentication
bypass. The current trusted development deployment intentionally uses the
password-free bypass, but still creates normal scoped sessions rather than
turning protected APIs public.

Node commands are signed, expiring, idempotent, node-bound, capability-checked,
audited, and allowlisted. The current agent accepts capability refresh, known
model load/unload, Comfy accelerator reclaim, and runtime drain. It is not a
general remote administration agent.

Webhook destinations require an allowlist, signature, durable delivery record,
retry limit, DNS/IP validation, and SSRF protection. These controls have
deterministic coverage but not live receiver acceptance.

## Telemetry and operator experience

The agent reports GPU model, driver, VRAM totals/use/free, utilization,
temperature, power, fan, clocks, PCIe link, and performance state. Host data
includes OS/kernel/architecture, CPU model/load/utilization, RAM/swap, root
disk totals, network throughput, uptime, runtime/model inventory, queue state,
and recent raw agent logs. Heartbeats are independent from expensive telemetry
collection; a timed-out GPU query retains the last good inventory rather than
temporarily erasing the card.

The node agent and workload scheduler now have opt-in, signed per-accelerator
idle/active GPU performance commands that preserve model residency. This is
code-level capability only until operator clock profiles and live GPU
measurements qualify each card; see `docs/gpu-performance-control.md`.

The Admin UI exposes fleet and machine views, time-window controls, hoverable
telemetry charts with percentage axes, TPS/TTFT and queue data, VRAM
composition, model residency, transition progress, raw logs, jobs/events, and
real control buttons. `Drain` and `Use for work` are separate actions. The
backend and built bundles are verified; the final pixel/interaction pass in a
real browser remains outstanding.

## System-agent plane

Monitoring identities can observe, create incidents, request a stronger model
verifier, and submit remediation proposals without acquiring administrator
authority. Severity, model tier, provider, evidence egress, and action authority
are separate decisions. A live local verification recorded the actual local
provider/model and created an `operator_review` proposal with automated
execution disabled.

The built-in observer currently handles node loss and verified recovery. The
full observe/analyze/verify/propose loop is partial, and automated remediation
is not implemented. Cloud escalation remains local-only unless a route,
allowlist, evidence policy, and budget are explicitly configured.

## Verification evidence

- A fresh live controller read on 2026-08-31 established the deployment facts
  and integration readiness above.
- `docs/live-verification-2026-08-30.md` records physical RTX 3080,
  PostgreSQL, dual-profile routing/sharing, runtime drain, residency,
  restart-safety, LLM performance, Comfy, and local incident evidence.
- `docs/acceptance.md` maps deterministic tests to the roadmap scenarios.
- The report gate reruns the complete Go package suite using the cached Go
  1.23.4 toolchain with network access disabled.
- The report verifier cross-checks key public routes, migration count, status
  language, explicit limitations, and absence of private addresses/credential
  material.

## Known gaps and recommended completion order

1. Accept a real S3-compatible artifact store and a real signed webhook
   receiver, including restart recovery and duplicate delivery behavior.
2. Exercise an allowed OpenRouter account end to end: provider/model pinning,
   rate limiting, budget reservation and settlement, redaction/egress, and
   bounded fallback.
3. Add runtime-specific checkpoint/yield/resume before exposing any disruption
   policy that promises resumability; prove safe video chunk boundaries in the
   adapter rather than inferring them from a workflow.
4. Run additional physical capacity trials, including heterogeneous
   LLM/Comfy or LLM/video sharing and an intentional guardrail violation that
   demonstrates rollback.
5. Re-run the memory-heavy Comfy workflow with sufficient host RAM or a smaller
   compatible workflow, then complete restart/output acceptance on that path.
6. Complete visual browser acceptance for Chat, Studio, and Admin, covering all
   buttons, time ranges, hover values, raw logs, load/unload progress, drain,
   scheduling, approvals, and ownership boundaries.
7. Expand the read-only system-agent observer set. Keep automated remediation
   unavailable until reversible allowlisted playbooks and approval/rollback
   semantics are implemented.
8. Treat OIDC, organization tenancy, multi-controller HA, whole-node power management,
   predictive wake, managed runtime installation, and additional adapters as
   later milestones rather than current capability.

## Bottom line

The load balancer works end to end for its currently proven local LLM and core
ComfyUI paths, including real device control, shared physical inventory,
durability, and operator telemetry. It is not complete across every planned
provider, storage transport, disruption operation, browser workflow, or
production topology. The report therefore supports continued controlled use
and targeted acceptance work, not an unconditional production-complete claim.
