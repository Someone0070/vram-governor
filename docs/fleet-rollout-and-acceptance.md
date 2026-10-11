# Three-GPU fleet rollout and acceptance

This runbook deploys a controlled RTX 3080, RTX 3090, and CMP170 fleet behind a
controller/load balancer on a separate machine. The controller host owns the
public API/UI endpoint, scheduler, and PostgreSQL authority; it is not a WSL
service on any GPU worker. Each GPU host runs a restricted node agent and
advertises all of its LLM, native ComfyUI, and managed-workflow targets under
the same physical accelerator identity. Clients and MCP integrations use the
controller's single IP and port.

The rollout deliberately separates code verification from physical
acceptance. Earlier single-3080 WSL results remain useful historical evidence,
but they are not the current topology. Do not enable sharing, cloud fallback,
or automatic client cutover until its corresponding evidence is green.

The example hostnames, model names, and environment-variable names are safe
templates. Copy the files to ignored `*.local.yaml` files and replace those
values with the deployment inventory. Never commit bearer tokens, signing
secrets, private certificates, provider keys, or storage credentials.

## Migration and baseline

1. Preserve the dedicated controller's deployment configuration and database backup using the
   site's normal snapshot procedure. Record the running controller commit.
2. Build and test the exact candidate commit with
   `node scripts/fleet-acceptance.mjs verify-repository`.
3. Stop the candidate controller, apply every ordered migration through
   `migrations/0020_accelerator_lease_cleanup.sql` (after every ordered migration from
   `0001` through `0020`), and record the PostgreSQL
   migration result. Do not edit an already-applied migration.
4. Start the controller with production TLS, PostgreSQL, environment-backed
   node-command signing, hashed credentials, and private admin CIDRs. Confirm
   `/api/v1/health` before changing any node.
5. Keep the previous controller binary and configuration available as the
   rollback artifact. Database rollback is restore-from-snapshot, not reverse
   execution of migrations.

## Three-node enrollment

Use [the fleet templates](../configs/fleet/) as sources for ignored local
configuration files. Each machine receives its own node credential and the
same command-signing secret through a root-readable service environment file.
Install the packaged node agent with the existing installer; do not give it an
arbitrary shell, package manager, model downloader, or custom-node installer.

The expected physical identities are:

| Host | Node ID | Accelerator ID | Discovered targets |
|---|---|---|---|
| RTX 3080 | `rtx3080-node` | `rtx3080-node-gpu0` | `rtx3080-llm`, `rtx3080-node-comfy` |
| RTX 3090 | `rtx3090-node` | `rtx3090-node-gpu0` | `rtx3090-llm`, `rtx3090-node-comfy` |
| CMP170 | `cmp170-node` | `cmp170-node-gpu0` | `cmp170-llm`, `cmp170-node-comfy` |

The acceptance manifest uses friendly expected Comfy target IDs. Update its
local copy to the actual node-advertised IDs reported by `/admin/api/overview`.
The LLM, native Comfy, and managed video targets on one card must use the same
accelerator ID. That identity—not the adapter name—is the lease and fencing
boundary.

Run a non-mutating inventory check before submitting work:

Inject `VRAM_ACCEPTANCE_ADMIN_TOKEN` into the process through the local secret
store, then run:

```powershell
node scripts/fleet-acceptance.mjs preflight --file configs/fleet-acceptance.local.json --output data/fleet-preflight.json
```

Do not put the token on a command line or in PowerShell history.

## Managed Comfy protocol

Raw ComfyUI remains `runtime_protocol: native` and supports confirmed
cancellation, not checkpoint/resume. A video harness uses
`runtime_protocol: managed_comfy_v1` while retaining adapter `comfy`, so the
public `/prompt`, `/ws`, `/queue`, and `/history` gateway remains unchanged.

The harness exposes `managed-comfy/v1` JSON over these private endpoints:

| Method and path | Required behavior |
|---|---|
| `POST /v1/executions` | Idempotently start or resume by workload/idempotency key; return `execution_id` and an active state. |
| `GET /v1/executions/{id}` | Return authoritative state, progress, optional GPU measurements, and checkpoint reference. |
| `POST /v1/executions/{id}/yield` | Stop at a safe chunk boundary, persist progress, and return state `yielded`. |
| `POST /v1/executions/{id}/checkpoint` | Persist an immutable checkpoint, stop GPU use, and return state `checkpointed`. |
| `POST /v1/executions/{id}/cancel` | Confirm the backend is no longer running; terminal races are acceptable. |
| `GET /v1/executions/{id}/outputs` | Return terminal output JSON and stable governor artifact references. |

Every response carries `protocol_version: managed-comfy/v1`. Checkpoint
references are opaque. A successful checkpoint/yield/cancel response is a
promise that GPU work has stopped; the governor will release the physical
lease after that confirmation. The harness must divide video into idempotent
chunks, persist each chunk before advertising a safe boundary, and assemble
only from committed chunks. It must reject checkpoint requests during an
indivisible step instead of pretending that cancellation is resumability.

The harness endpoint is private and allowlisted. Use a reverse proxy with TLS
or an authenticated private overlay between hosts. Its bearer authorization is
loaded into the controller from an environment variable in the local target
configuration.

Build the restricted Linux harness package with
`scripts/build-comfy-harness-package.ps1`, install the binary at
`/usr/local/bin/vram-governor-comfy-harness`, install
`deploy/comfy-harness.service`, and create the root-owned environment file from
`configs/fleet/comfy-harness.env.example`. The service binds to loopback by
default. Expose it to the controller only through the authenticated private
proxy/overlay, then set `VRAM_MANAGED_COMFY_AUTHORIZATION` on the controller to
the complete `Bearer ...` header value.

## Security planes

Create distinct credentials for these authorities:

- `node`: connect/report only, bound to exactly one node ID.
- `ui`: interactive submission/read/cancel with a moderate priority ceiling.
- `workflow`: batch and managed-video submission with explicit disruption and
  notification rights.
- `mcp`: Comfy submission/read/cancel without administrative controls.
- `agent`: incident create/read/escalate/propose with an S0-S4 ceiling chosen
  for that monitor and sanitized-cloud permission only when required.
- `admin`: private-CIDR operator access with a separate browser session.

Production uses 64-character SHA-256 credential digests, TLS, private admin
CIDRs, CSRF-protected browser sessions, a command-signing secret of at least 32
bytes, and an independent webhook-signing secret. Clamp concurrency, priority,
preemption count, egress, provider/model allowlists, and budgets per principal.
The controller may execute signed refresh/load/unload/reclaim/drain operations;
automatic remediation remains disabled.

## Guarded-sharing rollout

Sharing starts disabled in every template. Establish exclusive baselines first:

1. Run each LLM model and representative Comfy/video workflow alone at least
   three times after warmup. Confirm capacity provenance and retain measured
   p95 VRAM and duration evidence.
2. Enable sharing only on the specific targets being tested, with at least 2
   GiB reserve on CMP170/3090 and a larger reserve if the runtime or display
   workload requires it.
3. Start with `guarded_exploration: true`, `slowdown_allowed` participants, no
   safety-critical workload, and a conservative `max_slowdown`.
4. Exercise one combination at a time. Verify live VRAM, temperature, slowdown,
   progress, and rollback events before retaining the policy.
5. Never label a native Comfy video `checkpointable`. Use `locked` until it is
   routed through the managed harness and has passed checkpoint recovery.

Priority preemption remains separate from co-scheduling. A high-priority job
may interrupt only a lower-priority workload that explicitly declares
`yieldable`, `checkpointable`, or `cancelable`, and only within the caller's
preemption budget. `locked` and `slowdown_allowed` workloads are never priority
preemption victims.

## Live acceptance

Copy `configs/fleet-acceptance.example.json` to the ignored
`configs/fleet-acceptance.local.json`. Replace host and model identifiers,
write the exact physical preconditions for the site, and enable a scenario only
when those preconditions have been established. The runner refuses to declare
live acceptance while any required scenario remains disabled.

Set the three acceptance credential environment variables through the local
secret store, then execute:

```powershell
node scripts/fleet-acceptance.mjs preflight --file configs/fleet-acceptance.local.json --output data/fleet-preflight.json
node scripts/fleet-acceptance.mjs run --file configs/fleet-acceptance.local.json --output data/fleet-acceptance.json
```

The matrix covers urgent small-model execution while CMP video is active,
locked-video refusal, CMP-only 20B wait/ETA behavior, sharing rollback, node
reconnect, controller restart fencing, verifier escalation, OpenRouter, and
artifact/webhook recovery. Evidence output removes credential-shaped fields
and is created with exclusive-write semantics so an earlier run is not silently
overwritten.

The operator must additionally verify that a waiting 20B request creates the
requested in-app/webhook notifications, that a sharing rollback stops only the
newcomer, and that no backend continues using a GPU after its lease is released.

## Rollback

If a sharing threshold trips, disable sharing on the affected target through
the Admin policy control and preserve the workload, transition-plan, learning,
and telemetry records. If managed checkpoint confirmation is ambiguous, mark
the target unavailable and do not release/reuse the accelerator until direct
runtime observation confirms it stopped.

For controller rollback, stop admission, drain runtimes through signed
commands, preserve PostgreSQL and artifacts, stop the candidate controller,
and restore the previous binary/configuration. Restore the database snapshot
only when the old binary cannot read the migrated schema. For a node rollback,
stop the agent, restore the previous signed package and config, then reconnect;
never run two agents with the same node ID concurrently.

OpenRouter, S3, or webhook failure disables only that target/integration. Keep
local inference available when its security policy permits it. Do not weaken
TLS, egress, SSRF, budget, or signature checks to make an acceptance probe pass.

## Evidence and release decision

Retain the exact commit, sanitized configuration hashes, migration result,
controller/node versions, inventory snapshot, scenario evidence, telemetry
window, transition plans, incident IDs, output artifact hashes, provider usage,
webhook delivery IDs, and browser review record. Do not retain bearer tokens or
authorization headers.

Release readiness requires every root gate in
`.unlazy/fleet-completion/GATES.md` to have current evidence. Local tests prove
the implementation boundary; only the physical run proves heterogeneous
sharing, checkpoint safety, restart fencing, real provider/storage delivery,
and the operator experience.
