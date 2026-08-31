# Live verification — 2026-08-30

This report contains only behavior exercised against the current PostgreSQL +
WSL + physical RTX 3080 deployment. Deterministic tests are listed separately
in `docs/acceptance.md` and are not promoted to live evidence here.

## Deployment

- one controller using PostgreSQL as authoritative state;
- one WSL node agent owning physical accelerator `gpu-node-01-gpu0`, an RTX
  3080 with 10,240 MiB VRAM;
- two Ollama endpoints for the same `qwen2.5:3b-instruct` artifact:
  `gpu-node-01-ollama-short` (2,048 context, two slots) and
  `gpu-node-01-ollama-long` (8,192 context, one slot);
- local ComfyUI 0.34.0 on the same physical inventory and an existing remote
  Comfy node on the private LAN;
- filesystem artifacts. No models or dependencies were downloaded.

## Passed live checks

| Boundary | Evidence |
|---|---|
| Same-model best-fit routing | A bounded short request selected the 2,048-context/two-slot profile. A long request, which could not fit there, selected the 8,192-context/one-slot profile. The short request did not consume the scarce long-context slot. |
| Real guarded sharing | Cold-started short and long requests ran concurrently on the one 3080 and both succeeded. Live GPU memory peaked at 8,412/10,240 MiB with a configured 1,024 MiB reserve. |
| Durable learning | The controller persisted the real guarded-sharing success with predicted composition, observed 8,324 MiB, observed temperature 68°C, and a successful outcome. Readiness now reports measured adaptive co-scheduling from persisted evidence. |
| Policy restart restoration | After controller restart, target discovery initially lacked the physical VRAM envelope. When live telemetry supplied 10,240 MiB, the controller re-applied the stored sharing policy: enabled, guarded exploration enabled, 1,024 MiB reserve, 1.5× maximum slowdown. |
| Runtime drain | Draining the node unloaded both Ollama profiles and reclaimed Comfy runtime caches while leaving scheduling enabled. A later short request demand-loaded its profile and completed. |
| Independent scheduling toggle | `Use for work` changes scheduler admission only. It is separate from runtime drain and does not masquerade as model eviction. |
| Demand loading and cross-adapter reclaim | Cold Ollama demand triggered a durable load transition. Comfy-to-Ollama cache reclaim and Ollama-to-Comfy eviction use signed node commands under the same fenced accelerator lease. |
| Heartbeat under slow telemetry | Node heartbeats no longer wait for `nvidia-smi` or runtime discovery. A five-second telemetry deadline preserves the last good inventory. Open WebSocket transport prevents a transient heavy-runtime stall from being treated as immediate node loss. |
| Mid-flight restart duplicate safety | A running Comfy prompt was reconciled after controller restart. The original backend prompt was cancelled before the controller created a second attempt, so no two backend prompts overlapped. When backend cancellation could not be confirmed in an earlier node-loss case, the workload failed indeterminate instead of replaying. |
| Durable LLM performance | Asynchronous local LLM completion timing and token usage are copied into the final execution handle. Admin TPS/TTFT fields therefore survive normal polling and controller restart instead of depending on adapter memory. |
| System-agent escalation and proposal | An S1 incident was created through the admin plane, analyzed by the real local `qwen2.5:3b-instruct` route, reconciled to `verified`, and then given a durable `operator_review` proposal with `automated_execution=false`. Model choice and action authority remained independent. |

## External failures and unproven boundaries

| Boundary | Honest result |
|---|---|
| Local Z-Image completion during the final restart soak | The controller recovery path behaved safely, but Comfy failed with `HostBuffer.read_file_slice failed` / `errno=12` while the 15 GiB WSL environment had roughly 2.1 GiB available. This is an external host-memory failure and is not counted as a successful image run. Earlier core Comfy and remote LTX workflows remain the successful live evidence. |
| Live slowdown rollback | VRAM and thermal guards were observed during execution and the successful combination was learned. No physical run intentionally violated the configured slowdown/VRAM/thermal threshold, so live rollback remains unproven. |
| Checkpoint, yield, resume | Neither the active Ollama HTTP route nor external Comfy proves these operations. The controller rejects those disruption promises and the UI hides them. |
| OpenRouter | No credential was configured. No provider call, paid budget settlement, rate-limit circuit, ZDR, or cloud fallback is counted. |
| S3-compatible artifacts | No endpoint or credential was configured. Filesystem artifacts are the active development backend. |
| Signed webhook receiver | SSRF, signature, durable outbox, and idempotency have deterministic coverage, but no external allowlisted receiver was available for live delivery/restart acceptance. |
| Visual browser acceptance | The embedded bundles build successfully, but the in-app browser automation environment failed before page launch with `failed to write kernel assets ... os error 3`. API and service checks continued; this is not treated as visual acceptance. |

## Regression gates added with this run

- runtime capacity arrival re-applies a persisted guarded-sharing policy;
- context best-fit preserves the only large-context profile;
- node heartbeat is independent of telemetry sampling and retains transiently
  missing inventory;
- connected transport uses a grace window before declaring a stalled node
  lost;
- completed external restart recovery collects in place without another
  `Start`, while unknown local LLM adapter memory is never blindly replayed;
- node loss only requeues recoverable work after backend stop confirmation;
- completed asynchronous LLM performance is durable;
- completed shared execution derives slowdown only from measured standalone
  history.
