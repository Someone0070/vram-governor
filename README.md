# VRAM Governor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

VRAM Governor is a Go control plane that queues LLM, ComfyUI, batch, and
monitoring workloads against one accelerator inventory. Protocol-specific
gateways share fenced leases, so two adapters cannot independently reserve the
same physical GPU.

VRAM Governor is open source under the [MIT License](LICENSE).

The repository is an active prototype, not a complete A-Z production release.
It has a broad production-shaped implementation and deterministic tests. The
current RTX 3080 WSL deployment now runs PostgreSQL, Ollama, and an external
ComfyUI instance against one accelerator inventory. A real Z-Image workflow,
central artifact collection, and PostgreSQL prompt-route recovery have passed
live acceptance. S3, OpenRouter, runtime checkpointing, and real hardware
co-scheduling still require live acceptance, so the full production release
gate remains open.

See [Implementation status](docs/implementation-status.md) for the audited
live-proven, simulated, partial, and missing feature matrix. The Operator
Console also shows the active deployment's release-readiness facts.

## Implemented code paths

The list below describes code that exists. It is not a list of live acceptance
results; external-boundary status is tracked in the audit linked above.

- Node registry, heartbeat/liveness, nvidia-smi telemetry, and reconnecting
  outbound node WebSocket.
- llama.cpp runtime driver, measurements, legacy job/work-item queue, leases,
  cross-worker retry, and operation-version-safe item identity.
- Immutable `WorkloadRequest`, durable execution state, admission decisions,
  plan hashes, audit events, incidents, prompt mappings, and accelerator leases
  with monotonically increasing fencing tokens.
- One scheduler and lease namespace for `llamacpp`, external `comfy`,
  `openrouter`, and deterministic `mock` adapters.
- Context-aware best-fit routing among duplicate model instances. Each target
  declares its context limit and slot count, so short requests prefer the
  smallest sufficient context while long requests cannot land on an
  undersized instance. Optional per-client stickiness prevents spillover.
- Durable per-target model residency with demand-triggered llama.cpp router
  loads, fenced load/unload transitions, pinned/manual/auto/off policy, idle
  and quiet-hours unloading, rollback after failed hot-loads, and a strict
  no-speculative-loading rule. Reuse history ranks retention only.
- PostgreSQL controller store (`migrations/0001_init.sql` through
  `0014_target_policy_overrides.sql`) and an in-memory development store. PostgreSQL
  durably backs nodes, runtime/profile records, compatibility jobs, unified
  workloads, prompt mappings, leases, approvals, notifications, incidents,
  learning profiles, transition plans, and operator target-policy overrides.
- Restart recovery: recoverable running work is re-admitted; non-recoverable
  interrupted work is failed rather than duplicated.
- Filesystem artifact storage for development and AWS-SigV4 S3-compatible
  storage for production, with owner checks, hashes, bounded uploads, and
  traversal-safe IDs.
- Scoped SHA-256 token credentials, enforced security planes, owner
  boundaries, per-node credentials, concurrency/cloud/preemption budgets,
  priority/severity clamps, browser sessions, CSRF checks, production HTTPS,
  and private-CIDR admin admission.
- OpenAI-compatible `POST /v1/chat/completions`, including native SSE proxy
  streaming, client-disconnect cancellation, lease renewal for long streams,
  and structured terminal fail-fast capacity errors.
- Comfy-compatible central submission, queue/history, cancellation, WebSocket
  progress, remote input staging, central output collection, uploads, and
  artifact reads. Public prompt IDs remain pinned to the selected backend
  across controller restarts.
- Node-agent discovery of an existing ComfyUI endpoint, checkpoint names,
  node classes, version, queue state, and accelerator association. There is no
  custom-node installation command.
- Embedded React/TypeScript Workload Studio at `/studio/` and private Operator
  Console at `/admin/`.
- OpenRouter fallback with model/provider allowlists, route quarantine,
  per-principal budgets, actual usage settlement, bounded retries, and
  rate-limit/provider circuit breakers.
- QoS/deadline ordering, checkpoint/yield/cancel preemption under explicit
  victim consent and credential budgets, durable transition plans, exact-hash
  transformation approval, and safe Comfy step/resolution transforms.
- Conservative p95 VRAM composition, exclusive-run envelope bootstrapping,
  class/runtime and exact-fingerprint interference profiles, guarded
  exploration, thermal/VRAM/slowdown rollback, production sample learning,
  and history-derived duration/ETA scoring.
- Signed, allowlisted, SSRF-protected webhook delivery through a durable
  retrying outbox, plus in-app event streams.
- System-agent incident create/read/escalate/propose APIs with S0–S4 ceiling
  clamps, redaction-independent cloud egress checks, and durable recording of
  the actual verifier route. Agents cannot execute remediation.

## Run locally

Requirements: Go 1.23.4+ and, only when rebuilding the browser bundle, Node.js.

```powershell
go run ./cmd/controller -config configs/controller.yaml
go run ./cmd/node-agent -config configs/node-agent.yaml
```

Open `http://127.0.0.1:8080/chat/` for human chat or `/studio/` for workload
activity and use `dev-studio-token`. Open `/admin/` separately and sign in with
`dev-admin-token`; the admin plane deliberately uses an independent browser
session. These plaintext tokens are development examples only.

The sample configuration enables only the in-process mock target. Set an
adapter target's `enabled` flag to `true` after its endpoint and accelerator ID
are correct. Alternatively, configure `node-agent.yaml`'s `llamacpp.servers`
and `comfyui.endpoint` so the node agent discovers and advertises already-
running runtime instances.

Build the self-contained Linux node package with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-node-agent-package.ps1 -Architecture amd64
```

The archive and SHA-256 sidecar are emitted under `.cache/releases`. Its
guided installer creates a hardened systemd service that reports host, disk,
network, GPU, runtime, model, queue, and agent-log telemetry. Controller
actions remain restricted to signed refresh, model lifecycle, Comfy memory
reclaim, and runtime drain operations; the agent exposes no arbitrary shell.
See [Node agent](docs/node-agent.md) for installation and removal.

The installed single-3080 WSL layout, service locations, model-path policy,
database bootstrap, and verification commands are documented in
[WSL local deployment](docs/wsl-local-deployment.md). The deployment does not
install custom nodes or download model weights.

## PostgreSQL

Apply migrations in order with your normal migration runner, then set
`database_url` in `configs/controller.yaml`. The entire controller state uses
PostgreSQL, including node/runtime inventory, compatibility jobs, workloads,
leases, prompt mappings, audit records, approvals, notifications, and
incidents.

Production mode additionally requires:

- `production: true` and a non-empty `database_url`;
- TLS certificate and key files served directly by the controller;
- credentials configured with `token_sha256` (raw `token` and
  `auth.shared_token` are rejected);
- explicit private/loopback `admin_private_cidrs`;
- a 32-byte-or-longer node-command secret named by
  `command_signing_secret_env`;
- an HTTPS S3-compatible artifact endpoint and credentials supplied through
  the configured environment variable names.

Generate a credential digest, for example:

```powershell
[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("replace-me"))).ToLower()
```

## Main APIs

| Plane | Routes |
|---|---|
| Common async | `/api/v1/workloads`, status, approval, reprioritization, cancellation, artifacts, events, notifications |
| OpenAI | `/v1/chat/completions`, `/v1/models`, human chat at `/chat/` |
| ComfyUI | `/prompt`, `/ws`, `/history`, `/history/{id}`, `/queue`, `/upload/image`, `/view` |
| Node | `/ws/node`, node engine/profile reporting |
| System agent | `/api/agent/v1/incidents/*`, escalation/proposals, `/api/agent/v1/events` |
| Operator | `/admin/`, overview, residency controls, durable signed node commands |

All non-health API calls require a bearer token or browser session. Browser
mutations also require the session's `X-CSRF-Token`. Chat and Activity share a
scoped UI session; Fleet at `/admin/` always requests a separate administrator
session and deliberately ignores the UI cookie.

For a trusted development network, `auth.development_bypass: true` removes the
Chat, Activity, and Fleet password prompts. The controller still creates
separate HTTP-only UI and administrator sessions with CSRF protection, and only
admits clients covered by `admin_private_cidrs`. Production mode refuses to
start while this bypass is enabled.

The embedded browser surfaces are:

- `/chat/` for streaming conversations through the same scheduler agents use;
- `/studio/` for workload activity, placement decisions, and optional manual diagnostics;
- `/admin/` for private-network fleet and device telemetry, residency controls, and operations.

### Context-aware LLM placement

Configure each llama.cpp endpoint as a separate target with `context_limit`
and `slots`. Targets may advertise the same model name. The scheduler uses the
requested input-context budget plus `max_completion_tokens` (or `max_tokens`)
as the required context and picks the smallest target that fits. When that
target's slots are busy, normal `best_fit` requests can spill to another
sufficient target.

For node-managed discovery, the agent reads llama.cpp `/v1/models` and
`/slots`; `/props` and configured values provide conservative fallbacks when
slot monitoring is unavailable. It refreshes capabilities without reconnecting
(30 seconds by default), fingerprints the model/capacity profile, and records
whether capacity came from runtime verification or configuration. See the
[official llama-server API](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).

OpenAI-compatible callers supply the input-context budget and optional client
binding in the private `governor` object:

```json
{
  "model": "local-model",
  "messages": [{"role": "user", "content": "..."}],
  "max_completion_tokens": 1024,
  "governor": {
    "context_tokens": 3000,
    "placement_key": "client-a",
    "placement_policy": "sticky"
  }
}
```

`context_tokens` is the bounded input/prompt budget; the scheduler adds the
maximum output budget before testing a target's limit. `sticky` binds the same
owner, adapter, and placement key to its previously selected target, and waits
when that target is full instead of consuming a larger-context instance. The
placement key may instead be sent in `X-VRAM-Placement-Key`, with `sticky` in
`X-VRAM-Placement-Policy`. The `governor` object is removed before forwarding
the request to llama.cpp or OpenRouter.

Slots describe safe concurrency inside one runtime instance and share one
physical accelerator lease. Different targets configured with the same
`accelerator_id` are exclusive by default. They share only when both workloads
and targets explicitly permit slowdown, measured p95 envelopes plus reserve
fit, no safety-critical workload is involved, and a trusted profile or guarded
exploration policy permits it.

### Model loading and unloading

A lifecycle-capable llama.cpp router advertises available and currently
resident models separately. If a request needs an available cold model, the
scheduler drains that target, acquires the accelerator fence, evicts only
eligible `auto` residents when required, calls `/models/load`, and records the
transition IDs in the execution plan. A failed demand load attempts to restore
models evicted for it. Pinned, manual, and off models are never automatically
evicted, and queued demand protects a model from idle eviction.

Ollama endpoints are detected through `/api/ps`: the installed catalog remains
distinct from models actually resident in memory. Demand loads and unloads use
Ollama's local `keep_alive` lifecycle, under the same accelerator lease and
fencing token. Fleet shows active model operations with elapsed time and an
animated first-load bar; after a successful sample, later loads receive an
ETA-based progress estimate from the recorded transition duration.

Automatic unloading is configured under `workloads.residency`. It observes a
minimum-residency window to prevent thrashing, then unloads an unused model
after `idle_unload_seconds` or during configured local quiet hours. Predictions
and reuse scores can decide which loaded model to retain; they never cause a
speculative load. Stock llama.cpp unload is represented as `cold_disk` because
it does not guarantee warm host-RAM retention. `warm_ram` is a separate,
capability-gated contract for runtimes that can prove that behavior.

Manual commands require admin authentication, private-network admission, and
an `Idempotency-Key` header. The Operator Console exposes the same load/unload
and policy controls. For node discovery, set `router_managed: true` only when
the endpoint implements the router lifecycle APIs, and set
`max_resident_models` to its configured capacity.

## Build and verify

```powershell
go test ./...
go vet ./...

cd web/ui
npm.cmd install
npm.cmd run build
npm.cmd audit --audit-level=high
```

The generated `web/ui/dist` bundle is embedded into the Go binary.
The scenario-to-test mapping is documented in
[`docs/acceptance.md`](docs/acceptance.md).

## Deliberately deferred extensions

The roadmap keeps these outside the single-controller release: governor-managed
runtime/ComfyUI installation and upgrades, automatically executing remediation
playbooks, OIDC and full organization tenancy, multi-controller HA, physical
power control/predictive wake, and additional runtime adapters. Their absence
does not weaken the shared accelerator lease, egress, disruption-consent, or
ownership boundaries implemented here.
