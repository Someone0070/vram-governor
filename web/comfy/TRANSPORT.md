# Pinned frontend transport inventory (v1.51.9)

This is a source-derived inventory for the leaf-26 facade contract, not proof that any route exists in the facade. The official frontend base helpers resolve `apiURL(route)` to `/comfy/api${route}`, `internalURL(route)` to `/comfy/internal${route}`, and `fileURL(route)` to `/comfy${route}` while mounted at `/comfy/`. The local launcher allows same-origin API and static canvas paths only, adds `X-CSRF-Token` to unsafe `/comfy/api` fetch and XHR requests, blocks cross-origin traffic, and permits a WebSocket only at same-origin `/comfy/ws` with no `token` query parameter. Unknown route responses must remain explicit errors; they must never fall back to SPA HTML.

## Built-in editor API calls

The following route patterns are emitted by `src/scripts/api.ts` and related built-in editor services. `GET`/`HEAD` are read-only; every listed `POST`, `PATCH`, and `DELETE` is unsafe and must carry session CSRF, including multipart uploads.

| Method | Route | Source behavior / leaf-26 treatment |
| --- | --- | --- |
| GET | `/api/system_stats`, `/api/object_info`, `/api/embeddings`, `/api/i18n` | Editor bootstrap, node schemas, embedding catalog, locale data. |
| GET | `/api/prompt` | 1-second status polling fallback; response is expected to match frontend status shape. |
| POST | `/api/prompt` | Submit frontend `graphToPrompt` result; must be transformed/validated by the facade and queued as one candidate. |
| GET | `/api/queue`, `/api/history`, `/api/history/{id}`, `/api/jobs/{id}` | Queue, history, and detail reads; root must preserve owner/public workload IDs, not upstream prompt IDs. |
| POST | `/api/queue`, `/api/history` | `_postItem` delete/clear operations. Do not let request JSON select another owner. |
| POST | `/api/interrupt` | Upstream global interrupt is not owner-scoped; the canvas launcher does not make it safe. Must be denied/visibly unavailable unless leaf 26 maps to a safe own-job operation. |
| POST | `/api/jobs/cancel`, `/api/jobs/{id}/cancel` | Frontend bulk/single cancellation; enforce own job and terminal semantics. |
| POST | `/api/upload/image` | Multipart image/audio/mask/background/widget uploads. Enforce CSRF, bounded bytes/type, owner scope, and opaque public reference. |
| GET | `/api/view`, `/api/viewvideo` | Query carries output file references and preview parameters; resolve owner-bound public workload outputs only. |
| GET | `/api/view_metadata/{folder}?filename=…`, `/api/video_metadata` | Metadata for selected media; no raw worker path. |
| GET | `/api/experiment/models`, `/api/experiment/models/{folder}` | Model-folder/model catalogs; only registered model selections should be surfaced by the facade. |
| POST | `/api/assets/from-workflow`, `/api/assets/import` | Workflow sharing/import. Optional sharing surface; launcher notice says cloud collaboration unavailable. Must not forward externally. |
| GET | `/api/extensions`, `/api/workflow_templates` | Upstream custom-node extension/template catalogs. These must be disabled in the local patch; only the two local built-in core templates are registered from `/comfy/templates/index.json`. |
| GET | `/api/global_subgraphs`, `/api/global_subgraphs/{id}` | Global subgraph catalog/content; unavailable in this scoped canvas. |
| GET | `/api/users`; POST | `/api/users` | Upstream single-user settings bootstrap/create. Root contract must expose only current owner; no enumeration or arbitrary account creation. |
| GET | `/api/settings`, `/api/settings/{id}`; POST | `/api/settings`, `/api/settings/{id}` | Typed/allowlisted user preferences only, owner-scoped. |
| GET/POST/DELETE | `/api/userdata/{file}` | Workflow/config file open, save, delete; CSRF on mutations. |
| GET | `/api/userdata?dir=…&recurse=…&split=…&full_info=…` | User-data list; clamp path/depth/count and omit filesystem paths. |
| POST | `/api/userdata/{source}/move/{destination}?overwrite=…` | Rename/move; atomic owner-scoped operation, path normalized once. |

`_postItem(type)` is dynamic: the known callers use `queue`, `history`, and `interrupt`; leaf 26 must not accept arbitrary `type` values. Queue/history helper modules also construct per-id history/job detail reads. View/query routes use `filename`, `subfolder`, `type`, preview format, and cache-busting parameters; they are data, never caller-selected worker filesystem paths.

## Internal, direct, and optional requests

| Method | Route or destination | Classification |
| --- | --- | --- |
| GET | `/comfy/internal/logs`, `/comfy/internal/logs/raw` | Local internal server diagnostics; not required by the canvas and must be disabled or safely owner-scoped, never raw host logs. |
| PATCH | `/comfy/internal/logs/subscribe` | Internal log subscription control; unavailable. |
| GET | `/comfy/internal/folder_paths` | Exposes server path topology; unavailable. |
| POST | `/comfy/internal/files/input` | Asset service input-file operation; unavailable absent an explicit bounded owner-artifact facade. |
| GET | `/comfy/api/features`, `/comfy/api/node_replacements`, `/comfy/api/providers`, `/comfy/api/workspace/provider-policy`, `/comfy/api/secrets`, `/comfy/api/secrets/providers` | Remote feature flags, node-replacement extensions, partner/workspace policy, and secret-provider surface; unavailable and must not be used as a bypass. |
| GET/POST | `/comfy/api/tasks/{id}`, `/comfy/api/user`, auth redemption/session routes | Workspace/cloud task, onboarding, desktop login, or unified session flows; unavailable. The local launcher alone performs the scoped `POST /auth/session` exchange with `{token, kind:"ui"}`. |
| GET/POST | `/comfy/api/hub/*`, `/comfy/api/assets/*`, cloud analytics and registry/manager/release endpoints | Cloud sharing, asset hub, telemetry, extension manager, release/update metadata; unavailable. Upload URLs or direct signed URLs are not allowed. |
| GET | `/comfy/templates/index.json`, `/comfy/templates/{name}.json`, `/comfy/templates/{name}-1.webp`, `/comfy/templates/index_logo.json` | Same-origin static files. Only two locally registered template graphs/previews are present; no remote template catalog. |
| GET | `/comfy/dist/**`, `/comfy/upstream/**`, `/comfy/notices/**`, `/comfy/launcher.js` | Same-origin static distribution/source/license files. Never return SPA HTML for missing asset paths. |
| WebSocket | `/comfy/ws?clientId=…` | Required live editor channel. Leaf 26 must bind it to authenticated UI session/owner, map public job IDs, publish status/feature flags/terminal events, enforce expiry/revocation, and reject arbitrary `sid`/foreign identifiers. No `token` query. |

Other direct transports found in the pinned source include `fetch`, Axios clients, `XMLHttpRequest` in LiteGraph, media-cache and download helpers, dynamically imported extension URLs, and worker/cloud URL builders. Same-origin local routes go through the launcher's global fetch/XHR boundary; the launcher rejects every other network origin, disables `sendBeacon`, and rejects WebSockets outside the exact path. The source also contains Comfy Cloud OAuth/workspace, Hub/share, telemetry, registry, remote-config, manager, model-download and update clients; those are classified unavailable above. `data:`/`blob:` reads are browser-local workflow/media handling, not network destinations.

The source inventory is intentionally broader than the two selected workflows: the official editor's built-in modules may construct optional routes even when a user never opens those panels. Leaf 26 must freeze an explicit exact route/method allowlist from this inventory and verify the actual UI trace. No route is implicitly authorized by being present in the upstream frontend.
