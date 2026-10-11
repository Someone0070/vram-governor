# VRAM Governor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

VRAM Governor is a Go control plane that queues LLM, ComfyUI, batch, and
monitoring workloads against one accelerator inventory. Protocol-specific
gateways share fenced leases, so two adapters cannot independently reserve the
same physical GPU.

VRAM Governor is open source under the [MIT License](LICENSE).

The repository is an active prototype, not a complete A-Z production release.
It has a broad production-shaped implementation and deterministic tests. The
deployment topology uses a dedicated controller/load-balancer machine running
the API, UI, scheduler, and PostgreSQL. Restricted node agents on the RTX 3080,
RTX 3090, and CMP170 machines advertise their LLM, ComfyUI, managed-workflow,
and accelerator capabilities back to that controller. Clients use the
controller's single address; they do not connect to GPU backends directly.

Earlier live acceptance used an RTX 3080 development stack in WSL. That
historical environment proved real Comfy workflows, central artifact
collection, PostgreSQL prompt-route recovery, context-aware routing, demand
loading, runtime drain, and guarded two-profile GPU sharing. It is evidence for
those paths, not the current deployment topology. S3, OpenRouter, managed
runtime checkpointing on physical renderers, and several external failure
boundaries still require live acceptance, so the full production release gate
remains open.

See [Implementation status](docs/implementation-status.md) for the audited
live-proven, simulated, partial, and missing feature matrix. The Operator
Console also shows the active deployment's release-readiness facts.

For a new inference node, follow [Connect GPU nodes to the dedicated LB](docs/connect-gpu-nodes-to-lb.md),
then [Add an existing llama.cpp server](docs/llamacpp-node-setup.md). The
node-agent archive includes these setup guides. Enrolling a node and
advertising a fixed runtime do not by themselves enable model loading or
slot switching.

The local [mesh quickstart](docs/mesh-quickstart.md) provides a role selector
for the separate LB, always-on head GPU node, and slave GPU nodes. It still
requires prepared controller infrastructure and a protected join bundle;
do not mistake a Git clone alone for a fully configured mesh.

## Implemented code paths

The list below describes code that exists. It is not a list of live acceptance
results; external-boundary status is tracked in the audit linked above.

- Node registry, heartbeat/liveness, nvidia-smi telemetry, and reconnecting
  outbound node WebSocket.
- Configured per-rig Tasmota smart-plug telemetry in the Operator Console,
  including relay state, wall watts, voltage/current, power factor, and energy
  totals. Admin-only explicit ON/OFF control is opt-in and guards hard OFF with
  scheduler-disabled/idle checks; direct physical relay OFF/ON was verified on
  one unmapped test plug, but controller/LB control is not yet accepted live.
  See [Smart plugs](docs/smart-plugs.md).
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
- Allowlisted in-place runtime profile switching on an idle accelerator, so a
  target can move between configurations such as 8K/four slots and 32K/one
  slot. The node agent accepts only configured profile IDs, runs fixed argv
  without a shell, and requires the runtime to report the selected capacity.
- Per-model physical-accelerator ceilings default to one card while preserving
  every slot on that card. `GET /v1/models` reports the ceiling, current and
  currently free slots, maximum possible slots, context limits, and selectable
  capacity profiles so clients can choose safe concurrency instead of blindly
  requesting a maximum.
- Durable per-target model residency with demand-triggered llama.cpp router
  loads, fenced load/unload transitions, pinned/manual/auto/off policy, idle
  and quiet-hours unloading, rollback after failed hot-loads, and a strict
  no-speculative-loading rule. Reuse history ranks retention only.
- PostgreSQL controller store (`migrations/0001_init.sql` through
  `0020_accelerator_lease_cleanup.sql`) and an in-memory development store. The current
  source tree contains all 20 ordered migrations, including `0017_node_enrollments.sql`,
  `0018_workload_revision.sql`, `0019_model_capacity.sql`, and
  `0020_accelerator_lease_cleanup.sql`; the historical live run recorded only through
  `0015_creator_studio_contract.sql`. PostgreSQL
  durably backs nodes, runtime/profile records, compatibility jobs, unified
  workloads, prompt mappings, leases, approvals, notifications, incidents,
  learning profiles, transition plans, and operator target-policy overrides.
- Restart recovery reconciles a recoverable external execution with its
  original backend. A completed execution is collected in place; a running or
  unknown execution is only re-admitted after backend cancellation is
  confirmed. Otherwise it fails indeterminate rather than risking duplicate
  execution. Non-recoverable interrupted work is never replayed.
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
- QoS/deadline ordering, capability-gated disruption under explicit victim
  consent and credential budgets, durable transition plans, exact-hash
  transformation approval, and bounded Comfy step/resolution transforms.
  Native HTTP runtimes prove cancellation but do not claim checkpoint/resume.
  The restricted `managed_comfy_v1` chunk harness implements persistent safe-
  boundary yield/checkpoint/resume for explicitly chunked workflows; it remains
  disabled by default until accepted against the physical renderer.
- Conservative p95 VRAM composition, exclusive-run envelope bootstrapping,
  class/runtime and exact-fingerprint interference profiles, guarded
  exploration, thermal/VRAM/slowdown rollback, production sample learning,
  and history-derived duration/ETA scoring.
- Signed, allowlisted, SSRF-protected webhook delivery through a durable
  retrying outbox, plus in-app event streams.
- System-agent incident create/read/escalate/propose APIs with S0–S4 ceiling
  clamps, redaction-independent cloud egress checks, and durable recording of
  the actual verifier route. Agents cannot execute remediation.

- Creator Studio integration with immutable hardware-neutral runnable
  implementations, schemas and Artifact contracts, abstract
  `LB_MANAGED`/`HOSTED` locality, Artifact-backed async LLM results, provenance
  and compatibility tokens, generic upload, partial-safe batches, stable
  blockers, and durable working-set release hints. See
  `docs/creator-studio-integration.md`.

- A credential-safe live fleet acceptance runner and conservative 3080/3090/
  CMP170 deployment templates. The runner refuses a passing live report while
  any required physical scenario remains disabled. See
  `docs/fleet-rollout-and-acceptance.md`.

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
reclaim, runtime drain, and configured runtime-profile operations; the agent
exposes no arbitrary shell.
See [Node agent](docs/node-agent.md) for installation and removal.
For a clone-local Controller/Worker role selector and authenticated worker
join flow, see [Clone-to-mesh setup](docs/mesh-quickstart.md).

The separate-controller three-GPU topology and rollout procedure are documented
in [Three-GPU fleet rollout and acceptance](docs/fleet-rollout-and-acceptance.md).
The installable controller package, security boundaries, configuration steps,
and service lifecycle are documented in
[Dedicated controller deployment](docs/dedicated-controller-deployment.md).
The old single-3080 WSL environment is retained only as a historical
development/acceptance reference in
[WSL local deployment](docs/wsl-local-deployment.md). Neither deployment path
installs custom nodes or downloads model weights.

## PostgreSQL

Apply all ordered migrations `0001` through `0020` with your normal migration
runner (including `0017_node_enrollments.sql`, `0018_workload_revision.sql`, and
`0019_model_capacity.sql`, and `0020_accelerator_lease_cleanup.sql`),
then set `database_url` in `configs/controller.yaml`. The entire controller state uses
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

For encrypted private-LAN development, setting both `tls_cert_file` and
`tls_key_file` also enables HTTPS/WSS while `production` is false. This keeps
development storage and session behavior available without sending node
credentials over plaintext WebSockets. Configuring only one TLS file is
rejected.

Generate a credential digest, for example:

```powershell
[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("replace-me"))).ToLower()
```

## Main APIs

| Plane | Routes |
|---|---|
| Common async | `/api/v1/workloads`, status, approval, reprioritization, cancellation, artifacts, events, notifications |
| Creator Studio | `/api/v1/capabilities`, capability-oriented `/api/v1/workloads`, `/api/v1/workloads/batch`, `/api/v1/batches/{id}`, session working-set hints |
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
