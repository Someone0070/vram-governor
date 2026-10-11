# Creator Studio integration

This is the implemented Creator Studio contract for VRAM Governor. Creator
Studio sends semantic work; the load balancer selects and operates the exact
execution route without exposing physical hardware.

## Responsibility boundary

Creator Studio owns creative plans, intended manifests, Studio Production
Profiles, calibration, prompt/control compilation, creative eligibility, QA,
rerenders, canon, approval, and policy. VRAM Governor owns workers, GPUs,
VRAM/RAM/storage topology, residency, model lifecycle, caching, local or rented
placement, provider routing, infrastructure retries, leases, and physical
attempts. Workers execute their registered runtime or workflow and create
outputs.

Creator Studio has no API for choosing a worker or GPU, reserving VRAM, loading
or unloading a model, draining a node, restarting a runtime, controlling power,
or buying rented capacity. Those controls remain under `/admin` or inside the
scheduler and node agent.

## LB execution implementation versus Studio Production Profile

The names are intentionally distinct:

- An **LB execution implementation** is the exact executable
  `profile_id + version + digest` registered with the load balancer. It binds a
  runnable adapter/model/workflow stack and its mechanical contract.
- A **Studio Production Profile** is Creator Studio's calibrated creative
  strategy. It binds explicitly to the LB implementation identity,
  `capability_revision`, and creative policy stored by Creator Studio.

The load balancer does not determine whether an implementation is artistically
good, calibrated, production-ready, identity-consistent, or creatively better
than another. The legacy configuration field `calibration_status` is accepted
while reading old configuration but is not serialized or used by the Creator
API.

## Authentication

A Creator principal normally needs:

- `workloads:submit`, `workloads:read`, and `workloads:cancel`;
- `artifacts:write` and `artifacts:read`;
- permission for the adapters behind its selected LB implementations.

Ownership, priority ceiling, concurrency, egress, and budget enforcement remain
LB policy. Creator responses are owner-scoped and hardware-neutral.

## Capability and implementation schema

`GET /api/v1/capabilities` returns only explicitly configured, validated,
callable workflow/model implementations. Model inventory entries such as VAEs,
text encoders, checkpoints, and LoRAs are not synthesized into Creator-visible
profiles. In particular, a Comfy implementation requires an explicit workflow
binding, JSON input/output contracts, accepted/produced Artifact types, a
registered Comfy adapter, and supported operation names.

Example:

```json
{
  "profiles": [
    {
      "profile_id": "video_main",
      "version": "17",
      "digest": "immutable-runtime-stack-digest",
      "capability_revision": "4",
      "capability_definition_hash": "content-addressed-definition-hash",
      "modality": "VIDEO",
      "execution_locality": "LB_MANAGED",
      "operations": [
        "video.generate_sequence",
        "video.continue_sequence",
        "video.retake_region"
      ],
      "features": ["camera_control", "multi_reference"],
      "input_schema": {
        "type": "object",
        "required": ["prompt"]
      },
      "output_schema": {
        "type": "object",
        "required": ["outputs"]
      },
      "accepted_artifact_types": ["image/*", "video/mp4"],
      "produced_artifact_types": ["video/mp4", "application/json"],
      "compatibility_operations": [
        "video.continue_sequence",
        "video.retake_region"
      ],
      "status": "available",
      "availability": {
        "status": "available",
        "observed_at": "2026-09-01T12:00:00Z"
      }
    }
  ]
}
```

`modality` is one of `LLM`, `IMAGE`, `VIDEO`, `AUDIO`, `TRAINING`,
`SPATIAL`, or `OTHER`. `execution_locality` is only `LB_MANAGED` or `HOSTED`.
It tells Creator Studio whether Director work competes for LB-managed compute;
it does not identify a provider, host, worker, rental, GPU, or endpoint.

The immutable definition includes the profile identity, digest, revision,
modality, locality, operations, features, schemas, Artifact types, and
compatibility operations. Availability is evaluated at read time and is not
included in the definition hash. Changing `available` to `temporarily_busy`,
`offline`, or `unavailable` therefore does not create a new revision.

Changing a checkpoint, quantization, workflow, sampler stack, control adapter,
material runtime configuration, or mechanical contract requires a new
implementation version/revision. `profile_id@version` selectors are preferred.
The LB rejects an attempt to redefine an existing immutable identity.

Neither capabilities nor workload responses contain target IDs, node names,
GPU IDs/models, VRAM/RAM, worker addresses, provider endpoints, cache paths,
residency state, lease IDs, or fencing tokens.

Mechanical operation names may include `llm.inference`, `image.generate`,
`image.edit`, `video.generate_sequence`, `video.continue_sequence`,
`audio.sfx_generate`, `audio.tts`, `training.lora`,
`spatial.blender_previs`, and `qa.vision`. An operation appears only when its
registered adapter/workflow has a callable validated contract.

## Workload request schema

Creator Studio submits to `POST /api/v1/workloads`. The presence of `operation`
selects the strict Creator schema; unknown fields are rejected. Existing raw
unified workload callers and `/v1/chat/completions` remain compatible.

```json
{
  "workload_id": "studio_123",
  "idempotency_key": "studio_123-v1",
  "operation": "video.generate_sequence",
  "quality_class": "final",
  "requirements": {
    "features": ["multi_reference", "camera_control"]
  },
  "profile_preferences": {
    "preferred": ["video_main@17"],
    "acceptable": ["video_main@19"],
    "fallback_policy": "explicit"
  },
  "payload": {"prompt": "compiled worker input"},
  "artifact_refs": ["artifact://art-input"],
  "session_id": "episode_14",
  "batch_id": "episode_14_video",
  "affinity_key": "episode_14_video_final",
  "priority": "production",
  "latency_class": "batch",
  "parallelism": {"parallelizable": false},
  "ordered": false,
  "dependencies": [],
  "deadline": "2026-09-02T06:00:00Z",
  "bounds": {
    "frames": 121,
    "width": 1280,
    "height": 720,
    "steps": 30
  }
}
```

Either `workload_id` or `idempotency_key` is required; a missing idempotency key
is derived from the workload ID. The `Idempotency-Key` header overrides the
body key. A replay returns the same logical workload and output Artifact refs.

Entries supplied under `requirements` are mandatory constraints; the object may
be omitted when an operation has no additional feature requirement. The LB may
select only the explicit `preferred` set and, unless `preferred_only` is used,
the explicit `acceptable` set.
`equivalent_or_better_only` remains as a deprecated compatibility spelling for
that explicit acceptable-set behavior; it never asks the LB to judge creative
equivalence or quality. Final work requires at least one selected immutable
implementation. The LB never selects an unlisted implementation.

Supported priority names are `interactive_user`, `review_blocking`,
`production`, `autonomous_content`, `background_calibration`, and
`maintenance`. Supported latency classes are `interactive`, `batch`, and
`background`. Principal ceilings and victim disruption policy remain
authoritative.

## Status, result, and reason contract

Creator Studio polls `GET /api/v1/workloads/{id}` and cancels with
`POST /api/v1/workloads/{id}/cancel`. Public states remain:

| Status | Meaning |
|---|---|
| `queued` | Durable and awaiting admission or a dependency. |
| `preparing` | Admitted; model/runtime preparation is occurring. |
| `running` | A backend execution handle exists. |
| `completed` | Technical execution and output persistence succeeded. |
| `failed` | Terminal infrastructure/runtime failure. |
| `cancelled` | Logical cancellation is terminal. |
| `blocked` | A precise reason prevents execution or requires approval. |

The `reason` field classifies waiting/blocking without adding more states:

| Reason | Meaning |
|---|---|
| `CAPABILITY_UNAVAILABLE` | No registered implementation satisfies the requested operation/features/profile set. Submission is HTTP 422 and creates no workload. |
| `CAPACITY_UNAVAILABLE` | A valid implementation exists, but no usable capacity is currently online/enabled. Waiting workloads remain durable. |
| `TEMPORARILY_BUSY` | Compatible usable capacity exists but its slots are occupied. |
| `DEADLINE_EXPIRED` | The deadline was already expired or became terminal before admission. |
| `NO_FEASIBLE_ROUTE` | Implementations exist, but route policy/mechanical constraints exclude every current route. |
| `APPROVAL_REQUIRED` | An exact LB infrastructure transformation plan needs configured approval. |
| `SOURCE_ARTIFACT_INCOMPATIBLE` | Input media/provenance/token is incompatible with the requested implementation/operation. |

Dependency reasons remain `DEPENDENCY_PENDING`, `DEPENDENCY_FAILED`, and
`DEPENDENCY_UNAVAILABLE`. Version/profile request errors remain
`PROFILE_REQUIRED`, `PROFILE_VERSION_REQUIRED`, and
`PROFILE_SET_INCOMPATIBLE`.

A completed workload with creatively bad media is still `completed`. Creator
Studio QA decides whether to submit a new rerender, retake, or repair workload.

## Async LLM result retrieval

Local and hosted Director turns both use `/api/v1/workloads`. Hosted providers
use the same workload ID, idempotency, events, status, cancellation, and output
shape; provider credentials and routing remain operator configuration. The
checked-in OpenRouter target remains disabled/quarantined unless an operator
separately configures it.

Submit:

```http
POST /api/v1/workloads
```

```json
{
  "workload_id": "director_turn_42",
  "operation": "llm.inference",
  "quality_class": "final",
  "profile_preferences": {
    "preferred": ["director_local@3"],
    "fallback_policy": "preferred_only"
  },
  "payload": {
    "model": "director-model",
    "messages": [{"role": "user", "content": "Plan the next shot."}]
  },
  "priority": "interactive_user",
  "latency_class": "interactive"
}
```

Poll:

```json
{
  "workload_id": "director_turn_42",
  "status": "completed",
  "operation": "llm.inference",
  "profile": {
    "profile_id": "director_local",
    "version": "3",
    "digest": "director-runtime-digest",
    "capability_revision": "2",
    "capability_definition_hash": "director-definition-hash"
  },
  "outputs": [
    {
      "artifact_ref": "artifact://art-result",
      "media_type": "application/vnd.creator-studio.agent-result+json",
      "producer": {
        "profile_id": "director_local",
        "profile_version": "3",
        "profile_digest": "director-runtime-digest",
        "capability_revision": "2",
        "capability_definition_hash": "director-definition-hash",
        "operation": "llm.inference"
      }
    }
  ]
}
```

Retrieve sanitized metadata with `GET /api/v1/artifacts/art-result` and the
immutable bytes with `GET /api/v1/artifacts/art-result/content`. Creator Studio
does not need `/v1/chat/completions` to obtain asynchronous text.

## Artifact upload and provenance schema

Upload any image, video, audio, text, JSON, or binary control artifact with an
authenticated multipart request:

```http
POST /api/v1/artifacts
Content-Type: multipart/form-data
```

The file part is named `file`. Optional `media_metadata` is a JSON form field
containing known dimensions, frame rate/timebase, sample rate/channel layout,
or duration. Unknown facts are left absent; nothing is inferred from a
filename. The controller spools large multipart input outside memory and the
ArtifactStore enforces a 2 GiB maximum.

```json
{
  "artifact_id": "art-input",
  "artifact_ref": "artifact://art-input",
  "owner_id": "studio-owner",
  "name": "source.mov",
  "media": {
    "media_type": "video/quicktime",
    "byte_size": 104857600,
    "sha256": "content-sha256",
    "width": 1920,
    "height": 1080,
    "frame_rate": 24,
    "duration_ms": 12000
  },
  "created_at": "2026-09-01T12:00:00Z",
  "content_url": "/api/v1/artifacts/art-input/content"
}
```

Generated outputs add immutable producer provenance:

```json
{
  "artifact_id": "art-output",
  "owner_id": "studio-owner",
  "workload_id": "studio_123",
  "producer": {
    "profile_id": "video_main",
    "profile_version": "17",
    "profile_digest": "immutable-runtime-stack-digest",
    "capability_revision": "4",
    "capability_definition_hash": "content-addressed-definition-hash",
    "operation": "video.generate_sequence"
  },
  "media": {
    "media_type": "video/mp4",
    "byte_size": 31457280,
    "sha256": "content-sha256"
  },
  "compatibility": {
    "producer_implementation": "video_main@17",
    "capability_revision": "4",
    "capability_definition_hash": "content-addressed-definition-hash",
    "source_artifact_id": "art-output",
    "tokens": {
      "video.continue_sequence": "compat-v1-opaque",
      "video.retake_region": "compat-v1-opaque"
    }
  }
}
```

Backing filesystem/NAS/S3 paths are not present in Creator responses.

## Compatibility-token behavior

Compatibility-sensitive operations are explicitly listed in the execution
implementation's `compatibility_operations`. Every output from that
implementation receives random opaque tokens scoped to the owner, source
Artifact, producer implementation, capability revision, and operation.

Compatible continuation:

```json
{
  "workload_id": "continue_1",
  "operation": "video.continue_sequence",
  "profile_preferences": {
    "preferred": ["video_main@17"],
    "fallback_policy": "preferred_only"
  },
  "artifact_refs": ["artifact://art-output"],
  "continuation_ref": "compat-v1-opaque",
  "payload": {"prompt": "continue"}
}
```

For retake/refinement/upscale operations, the same opaque value may be supplied
as `compatibility_token`. `continuation_ref` is a backward-compatible alias for
continuation and must match `compatibility_token` if both are sent.

At submission the LB checks owner, immutable provenance, accepted media type,
producer implementation, capability revision, source Artifact ID, requested
operation, and exact token. Compatible candidates remain eligible; an
incompatible candidate is removed. If none remain, HTTP 422 returns
`SOURCE_ARTIFACT_INCOMPATIBLE` with sanitized operation/Artifact refs. The
source Artifact itself remains valid. A matching filename or model-family name
never establishes compatibility.

Provider KV/session state is not part of this contract. Creator Studio owns the
transcript, context manifest, memory, tools, canon, and durable asset state.

## Batch and dependency semantics

`POST /api/v1/workloads/batch` preserves existing ordered/DAG scheduling. An
ordered batch adds each accepted item as the next item's dependency. Explicit
`dependencies` remain supported.

Batch creation is intentionally partial, not transactional. Every response
contains all accepted logical workloads and every rejected item:

```json
{
  "batch_id": "episode_assets",
  "partial_acceptance": true,
  "items": [{"workload_id": "greep", "status": "queued"}],
  "accepted": [{"workload_id": "greep", "status": "queued"}],
  "rejected": [
    {
      "index": 1,
      "workload_id": "robe",
      "status": "blocked",
      "reason": "CAPABILITY_UNAVAILABLE",
      "missing": ["image.generate"]
    }
  ]
}
```

All accepted returns HTTP 201, mixed acceptance returns HTTP 207, and no
accepted items returns HTTP 422. `items` remains a compatibility alias for the
accepted list. Retrying the same items with the same idempotency identities is
safe. Creator Studio's own durable DAG can retry only rejected items.

`GET /api/v1/batches/{batch_id}` returns owner-scoped items,
`items_total`, `items_complete`, `items_failed`, and aggregate progress.

## Working-set semantics

The only Creator residency hint is the advisory working set:

```text
PUT    /api/v1/sessions/{session_id}/working-set/{phase_id}
GET    /api/v1/sessions/{session_id}/working-set
DELETE /api/v1/sessions/{session_id}/working-set/{phase_id}
```

```json
{
  "phase_type": "image_refinement",
  "affinity_key": "greep_design_session",
  "desired_profiles": ["director_local@3", "show_image@9"],
  "likely_next_profiles": ["show_image@9"],
  "unlikely_profiles": ["final_video@17"]
}
```

Profile refs require `@version`. Desired/likely/unlikely lists and affinity
only adjust scheduler score. They never override capability, ownership,
deadlines, egress, leases, availability, safety, or disruption policy. Release
is durable and means only that Creator Studio no longer forecasts that phase;
it is not an unload, sleep, RAM, VRAM, worker, or GPU command.

An LB-managed Director may be included like any other implementation. A hosted
Director may be omitted from the working set when it does not compete for local
compute; `execution_locality` lets Creator Studio make that batching decision.

## Infrastructure retry versus creative retry

One logical Creator workload and idempotency key may have multiple opaque
physical attempts. Existing leases, fencing tokens, bounded retry count,
provider cooldown/circuit logic, restart reconciliation, confirmed-stop
requeue, and stale-result rejection remain unchanged and internal.

Transport errors, runtime crashes, rate limits, managed OOMs, and confirmed
worker loss are infrastructure failures. If a backend stop cannot be
confirmed, the workload fails safely instead of duplicating a long render.
Valid but creatively poor output is a technical success and is never retried
by the LB as creative QA.

## Intentionally internal APIs and state

Creator Studio must not call or receive:

- `/admin` residency/load/unload/drain/node-command or policy controls;
- `/api/v1/workloads/preview` physical candidate detail;
- legacy `/jobs` worker/pool details;
- accelerator leases, fencing tokens, execution handles, target IDs;
- provider circuit breakers, rental reconciliation, budgets/prices, or power;
- cache paths, NAS paths, model residency, or warm-RAM/VRAM state.

Creator Studio uses capabilities, workload/batch submit and poll, cancellation,
Artifacts, and working-set upsert/release. Polling is authoritative; a
Creator-specific event stream is not required by this contract.

## Health

`GET /api/v1/health` and `/healthz` return controller health without inventory
or placement details.

## Persistence and migration

Migration `0015_creator_studio_contract.sql` introduced immutable runtime
profiles and working sets. Migration `0016_creator_contract_alignment.sql`
adds indexed capability revision/hash, modality, and abstract locality fields.
Full schemas and compatibility metadata remain in the immutable profile JSON
and ArtifactStore metadata. Existing workload JSON remains backward compatible;
no second scheduler or state machine was introduced.

## Acceptance evidence

The contract is covered by executable tests:

- `TestCreatorStudioCapabilities` and
  `TestRuntimeProfileRegistrationRequiresCallableWorkflowContract` cover
  runnable definitions, schemas/types, locality, stable availability identity,
  component suppression, and hardware non-disclosure.
- `TestArtifactProvenanceRoundTrip` and
  `TestCreatorArtifactCompatibilityAndUpload` cover metadata persistence,
  generic multipart ingestion, opaque tokens, compatible continuation,
  incompatible-route rejection, and filename non-compatibility.
- `TestCreatorAsyncLLMOutputs` covers local/hosted-style async result parity,
  Artifact retrieval, and idempotent output replay.
- `TestCreatorBlockingReasons` covers capability, capacity, busy, deadline,
  route, and approval reasons; source incompatibility is covered separately.
- `TestCreatorBatchPartialAcceptance` covers explicit accepted/rejected items
  and safe idempotent retry.
- `TestCreatorStudioWorkingSet`, existing node-loss/fencing tests, and the
  accepted-creative-output test protect advisory hints and retry ownership.

These tests exercise the real in-memory controller/store and filesystem
ArtifactStore. Hosted provider credentials, real media workflows, and physical
workers are intentionally not enabled by this contract patch.
