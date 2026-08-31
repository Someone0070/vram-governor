# Unified workload architecture

Every protocol gateway creates the same immutable `domain.WorkloadRequest`.
The scheduler filters targets, creates a deterministic execution-plan hash,
and acquires a fenced lease keyed by `accelerator_id` before calling an adapter.
The adapter name is not part of the lease key; this is what prevents a local
llama.cpp server and an external ComfyUI server from double-booking one GPU.

```text
OpenAI / Comfy / async API / agent
                 |
        immutable WorkloadRequest
                 |
      admission + target filtering
                 |
 PostgreSQL accelerator lease + fence
                 |
 llama.cpp | ComfyUI | OpenRouter | mock
```

## Durability and recovery

`PostgresWorkloadStore` implements the aggregate controller store. It persists
node/runtime inventory, compatibility jobs, the complete workload snapshot,
idempotency identity, public Comfy prompt mappings, approvals, notification
outbox rows, incidents, learning profiles, transition plans, and leases. Lease
acquisition runs at serializable isolation and increments a separate fence
counter. A stale execution cannot renew or release a successor's lease.

On restart, recoverable running work enters backend reconciliation instead of
blindly returning to admission. If the original backend reports completion,
the controller collects that execution in place. If it is still running or
unknown, the controller only re-admits it after backend cancellation is
confirmed; otherwise it fails indeterminate so a late result cannot race a
duplicate attempt. Non-recoverable work is failed with an explicit restart
reason. A Comfy prompt mapping is a separate durable row, so public identity
does not depend on a backend prompt ID.

## Security boundary

Credential policy controls an enforced plane, scopes, adapters, node binding,
owner, priority ceiling, incident severity ceiling, egress, concurrency,
preemption count, and cloud budget. Unspecified egress is local-only.
Development config may contain raw tokens; production accepts only validated
SHA-256 digests. Browser sessions are HTTP-only, SameSite=Strict, time-bounded,
and use a separate CSRF secret for mutations. Production serves TLS directly,
rejects public admin CIDRs, and requires environment-backed command signing.

The system-agent plane can observe, create incidents, request an allowlisted
verifier, and attach proposals. Cloud verification requires classified and
sanitized evidence even when a provider advertises ZDR. The reconciler records
the actual selected provider/model and terminal analysis status. No route
executes a remediation proposal, so model escalation and administrative
authority remain independent.

## Conservative scheduling boundary

Targets with missing models or required Comfy node classes are excluded. Cloud
targets are excluded for local-only workloads. When live node inventory is
available, disconnected, unready, disabled, absent, or VRAM-ineligible devices
are excluded. Unknown or busy combinations remain queued with a blocker,
estimated interval, confidence, and alternatives.

### Duplicate-model context profiles

Targets identify runtime instances, not just model names. Two targets may
advertise the same model while declaring different `context_limit` and `slots`
values. Admission computes required context as the bounded input context plus
maximum output, rejects undersized targets, and orders eligible targets by the
least unused context capacity. This keeps a high-context, low-slot instance
available when a lower-context, higher-slot instance can serve the request.

The default `best_fit` policy can spill a short request to another sufficient
instance when the preferred one is full. A request with `placement_policy` set
to `sticky` and a `placement_key` reuses that owner/adapter/key's last target;
it waits rather than spilling. Decisions and plans record the selected context
limit and slot capacity so routing remains explainable.

Slots are explicit concurrency capacity within a single runtime target. Those
slots share one fenced accelerator lease. Separate targets with the same
physical `accelerator_id` remain mutually exclusive, including llama.cpp and
ComfyUI targets.

Node-advertised llama.cpp targets obtain model identity from `/v1/models` and
capacity from `/slots`, with `/props` and configured values recorded as
fallback sources. Periodic capability messages update the same node-namespaced
target after runtime changes. The resulting fingerprint and provenance are
included in the execution plan and plan hash.

OpenAI streaming requests are admitted before response headers are committed.
The scheduler holds the selected runtime slot and renews its physical lease
while backend SSE bytes are copied with client backpressure. A client
disconnect cancels the backend HTTP request, records cancellation, and releases
the slot. A fail-fast capacity refusal is terminal and is never re-admitted as
an orphaned stream.

### Residency transitions

Available models and resident models are separate target capabilities. A cold
but available model can be loaded for real queued demand when the target and
adapter advertise lifecycle support. Target drain, capacity eviction, model
load, and execution use one physical accelerator lease namespace and fencing
tokens. A failed demand load attempts to restore any model evicted for it.

`auto` residents may be unloaded after their idle and minimum-residency
windows, or during configured local quiet hours. `pinned`, `manual`, and `off`
residents are protected from automatic eviction, as are models with queued
demand. Persisted reuse scores only order eviction candidates; the controller
does not pre-load predicted models.

Desired/observed records and planned/running/succeeded/failed transitions are
durable. Commands are idempotent, fenced, and audited with the actor. Warm RAM
is capability-gated separately because llama.cpp unload does not promise that
weights remain in host memory.

### Priority, ETA, and transitions

Admission orders QoS-adjusted priority and deadline, then scores eligible
targets using history-derived p95 duration/queue delay, context waste, model
transition cost, capacity confidence, cloud locality, slowdown, and deadline
risk. Waiting decisions retain a blocker, start/end range, confidence, and all
considered alternatives. A lease release, progress event, node change,
checkpoint, model transition, or provider recovery signals immediate
reconciliation.

Higher priority may preempt only a victim whose disruption policy explicitly
allows yield, checkpoint, or cancellation, and only within the caller's
preemption budget. Locked and slowdown-only victims are never preempted.
Actions and rollback intent are durable transition plans referenced by both
workloads; interrupted plans are failed on restart and never blindly replayed.

### Adaptive sharing and learning

Cross-target sharing is disabled by default. It requires a common physical
accelerator, `slowdown_allowed` on newcomer and victims, measured standalone
VRAM envelopes, explicit target enablement, reserve headroom, and no
safety-critical participant. Known combinations use runtime-scoped persisted
interference profiles. Unknown combinations run only as guarded exploration
with extra rollback headroom.

Exclusive runs first learn class-level and exact-fingerprint VRAM/duration
envelopes, allowing a target without a prefilled standalone estimate to
bootstrap conservatively after sufficient samples. Every real shared execution
then records predicted and observed VRAM, slowdown, and temperature. Successful
and rolled-back samples update both class-level and exact-fingerprint,
versioned conservative p95 profiles and confidence; scheduler code is never
modified.
Reserve, slowdown, thermal, progress, or error violations abort the newcomer
and preserve evidence for later calibration.

### Transformation safety

The original request remains immutable. Each transformed material payload has
an exact plan hash covering workflow, bounds, adapter/runtime versions, target
capabilities, model fingerprint, provider/model, and transformation set.
`ask` and scoped `delegate_safe_review` approval apply only to that hash.
External ComfyUI supports bounded step and resolution reduction; checkpoint
chunking remains rejected until an adapter can prove safe boundaries.

### Artifacts and notifications

Comfy input artifacts are owner-validated and staged only after placement.
Backend outputs are fetched into the central filesystem or S3-compatible
artifact store and history is rewritten to stable governor artifact IDs.
Webhook destinations require an exact host allowlist, DNS/IP validation,
private-range policy, HMAC signatures, no redirects, and durable idempotent
retry delivery.
