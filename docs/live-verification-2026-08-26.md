# Live verification — 2026-08-26

This report counts only observations from the deployed WSL stack. Unit tests,
HTTP test servers, mock adapters, and deterministic scheduler tests are useful
regression gates but are **not** counted as live acceptance evidence here.

## Environment

- NVIDIA GeForce RTX 3080, 10,240 MiB VRAM
- PostgreSQL 16 through the local Unix socket
- official ComfyUI 0.34.0 at `127.0.0.1:8188`
- Ollama at `127.0.0.1:11434`
- controller and node agent built from this worktree with Go 1.23.4, offline
- existing local models only; no models or packages were downloaded
- development filesystem artifact store under `.cache/hardware-test/wsl-data`

## Live-passed boundaries

| Boundary | Live result |
|---|---|
| Physical inventory and telemetry | One physical `gpu-node-01-gpu0` is shared by the Comfy and Ollama routes. Live VRAM, utilization, temperature, and connectivity changed with actual GPU work. |
| Local LLM | Real 3B and 14B non-streaming requests succeeded. A real 3B SSE request completed with `[DONE]`; a long stream held and renewed its physical lease beyond the 30-second TTL, and client disconnect cancelled it and released the lease. |
| Chat context across model changes | The full transcript was sent to the newly selected model. The 14B response returned the earlier phrase `ORBITAL-447`. KV cache is not transferable across models; context is reconstructed from the transcript. |
| Cold-load fail-fast | While the 14B model was loading from disk, a competing 3B OpenAI request returned structured HTTP 429 in 0.851 seconds with `Retry-After: 29` and the alternative `scheduler busy with a model or residency transition`. The 14B request subsequently succeeded. |
| Demand residency | Real cold-to-hot Ollama transitions succeeded for 3B and 14B. Real hot-to-cold eviction occurred before loading the incompatible model. Earlier live idle sweeps persisted successful `idle_timeout` transitions. |
| Comfy → Ollama reclaim | With no Ollama model loaded and about 5.5 GiB still held by Comfy, a 3B request first completed a fenced `runtime-cache` `cross_adapter_reclaim` transition through Comfy `/free`, then loaded Ollama and returned `LIVE-3B-OK`. |
| Ollama → Comfy reclaim | With the 3B model resident, a real Z-Image Comfy request first persisted a successful `cross_adapter_reclaim` unload of the 3B model. Ollama `/api/ps` was empty while the real Comfy backend prompt was running. |
| Active Comfy cancellation | Cancelling a running Z-Image prompt invoked backend interrupt, waited for the backend queue to become empty, durably stored `cancelled`, reduced target activity to zero, and left zero live PostgreSQL leases. The first live attempt exposed a `failed`/`cancelled` race; the final retest passed after the cancellation-in-progress guard was added. |
| Comfy discovery and filtering | The node discovered the actual endpoint, version, queue, models, custom nodes, and accelerator association. A workflow requiring a nonexistent model stayed waiting, and the custom-node directory count did not change. |
| Comfy central queue and sticky mapping | Public prompt IDs mapped to backend prompt IDs. Pending cancellation, active execution, history, restart recovery, and output retrieval used the public ID. |
| Comfy upload, WebSocket, history, and output | A real PNG was uploaded and staged, then processed through `LoadImage → ImageInvert → SaveImage`. The authenticated gateway WebSocket relayed submission/start/progress/completion signals. History and the output artifact survived restart; the retrieved 269,693-byte PNG matched filesystem SHA-256 `ed0f0499b344852bac9d9d290528b522f1c4b2538af5b6812c87b0f4517a8d96`. |
| Drain and enable | The live admin drain mutation changed the node to `draining`. A new async 3B request returned in 0.02 seconds as durable `waiting` with `node scheduling disabled`; requested priority 999 was clamped to 50 and cloud egress to `local_only`. Enable released it and it succeeded exactly once. |
| Idempotency | Repeated workload and node-command idempotency keys returned the same durable identity. Distinct operation versions remained distinct. The tested completed Comfy jobs retain one execution attempt after restarts. |
| Node loss | Stopping the actual node agent changed connectivity `connected → suspect → lost`, opened durable S2 incident `inc-97d4a41a59d8c8f03688edf3`, and made new work wait with a disconnected blocker. Reconnection restored the node, marked the incident `recovered`, and the queued request succeeded once. |
| Controller restart | Multiple real controller restarts retained UI/admin sessions, workloads, exact transformation approval, incidents, prompt mappings, history, and artifacts. The approved transform remained succeeded with one attempt. |
| PostgreSQL restart | Restarting the real PostgreSQL service caused expected temporary socket errors. The running controller reconnected without restart; both browser sessions and persisted workload state remained available. |
| Security planes | Unauthenticated admin API returned 401. UI credentials could not create/administer an admin session. UI and admin cookies were mutually rejected across planes before and after restart. Browser mutations without CSRF returned 403. Cross-owner workload/artifact reads returned 404. Node and monitoring credentials could not enter the admin plane. |
| Session secret storage | Live PostgreSQL rows for both session kinds contained 64-character session-ID hashes and 64-character CSRF hashes; raw browser secrets were not persisted. |
| Artifact ownership and traversal | The owner retrieved the real output with HTTP 200; a different owner received 404. A `../../etc/passwd` view request received 404. |
| Exact workflow approval | A real Comfy 128×128 workflow proposed a 64×64 material plan. A wrong hash returned 409; the exact hash executed successfully once and produced an artifact. Changing the source width produced a different hash and the old approval again returned 409. The approval survived controller restart. |
| System-agent boundary | A monitor-created incident had requested S4 clamped to S1 and confidence clamped to 1. Its proposed action remained a proposal. Escalation ran an actual local 3B verifier workload and recorded the actual provider/model without gaining admin authority. |
| Signed node commands | A controller-signed, expiring `refresh_capabilities` command ran on the real node. Its result reported actual Comfy/Ollama inventory, and a repeated idempotency identity did not execute a second command. |
| Embedded UI delivery | TypeScript checking and the production Vite build passed. `/admin/` and `/chat/` served their React roots, and their built JavaScript assets returned HTTP 200 with JavaScript content types. |
| Side-effect-free placement preview | A live authenticated preview for the discovered 3B route returned `gpu-node-01-wsl-ollama` as eligible and left the owner workload count unchanged at 22. The durable decision-trace endpoint returned the selected workload plus its three audit events. |
| Durable target policy | Migration `0014_target_policy_overrides.sql` was applied to PostgreSQL. An admin-set 768 MiB VRAM reserve survived controller restart and was applied when the node-discovered Ollama route registered again. |
| Native Comfy progress | A real governor-submitted Z-Image workflow completed as `wl-0ac21ef59509051df33a6a85`; the durable workload retained native sampler `current=4`, `total=4`, stage `executing`, and final node `10`. Binary preview frames were ignored without terminating the observer. |
| Admin incident workflow | The admin-plane incident route created `inc-8580b98e3917a010feb69781`, attached an evidence reference and JSON proposal, and recovered the proposed state from PostgreSQL after controller restart. |

## Not accepted or not finished

These are not passes:

| Boundary | Honest status |
|---|---|
| Two simultaneously available copies of the same model with different context/slot profiles | Scheduler best-fit and sticky-placement logic exists only under deterministic tests. The live deployment has one Ollama route (`context=4096`, one conservative slot), so simultaneous low/high-context routing was not live-tested. Runtime-measured slot capacity is also unavailable from this Ollama endpoint. |
| Adaptive co-scheduling and guarded rollback | Disabled on the live target. No real interference profile or two-workload sharing rollback was calibrated. Exclusive physical leasing is the accepted mode. |
| Warm host-RAM model tier | The adapter contract exists, but the live Ollama target reports `warm_ram_supported=false`. Disk unload/reload is accepted; guaranteed RAM offload is not. |
| Quiet-hours unload | Implemented and unit-tested, but quiet hours were disabled in the live config. Idle unload is live-proven; quiet-hours behavior is not. |
| Yield/checkpoint/resume and safe video chunking | No real HTTP adapter proves these operations. They remain unsupported and must not be exposed as resumable behavior. |
| OpenRouter | No credential was present, so no paid/provider call, budget settlement, rate-limit circuit breaker, fallback, ZDR, or cloud-egress path was counted. |
| S3-compatible artifact storage | No MinIO/S3 endpoint or credentials were present. Only the development filesystem store was accepted live. |
| Signed webhooks | Notifications were disabled and no real allowlisted receiver was available. The durable outbox/SSRF code has regression coverage only. |
| Browser visual rendering | HTTP/session/assets were tested, but the in-app browser automation kernel failed before it could launch a page (`failed to write kernel assets`). The black-screen fix was therefore not visually re-accepted in an actual browser during this pass. |
| Mid-flight recoverable execution after node loss | Queued work and incident recovery passed. Deliberately dropping the agent during a real backend execution could duplicate an unfenced external execution, so that unsafe scenario was not claimed as complete. |
| High availability, OIDC/full tenancy, power control, predictive wake, managed Comfy/runtime installation, autonomous remediation | Not implemented by the current release. |

## Regression gates (not live evidence)

- `go test ./...` passes offline.
- `npm.cmd run build` passes (`tsc --noEmit` and Vite production build).
- New regression tests cover fail-fast behavior, cancellation/observer terminal-state races, side-effect-free context-profile preview, durable discovered-target policy, and Comfy progress across binary preview frames.

## Defects fixed during this live pass

1. OpenAI fail-fast requests no longer block behind a long residency transition.
2. Cross-adapter placement now performs fenced Ollama eviction or capability-gated Comfy `/free` before handing the shared accelerator to the other runtime.
3. Running Comfy cancellation now interrupts the backend and waits for absence from its queue before releasing the physical lease.
4. Cancellation owns terminal-state publication, preventing the observer from rewriting an intentional interrupt as failure.
5. A shutdown/context-cancellation path no longer dereferences a missing refreshed workload.
6. Comfy binary preview frames no longer terminate native progress observation; terminal workloads retain their last node/current/total counters.
7. Runtime target safety policy is durably recovered for targets discovered after controller startup.

The current deployment is a useful exclusive-scheduling dual-workload system,
not the complete A–Z roadmap. The unavailable rows above remain release gates.
