# GPU performance control for warm models

The Load Balancer owns GPU clock/performance control. Creator Studio supplies
workload intent only; it never selects a GPU P-state or clock. Model residency
and GPU performance are independent: a model can stay in VRAM while its GPU is
idle at lower clocks. Host-RAM residency has no GPU P-state.

The controller sends a signed, idempotent `set_gpu_performance_profile` node
command for the exact physical accelerator. Before starting a workload it
selects `active`; after the last reservation on that accelerator is released it
selects `idle`. Per-accelerator locks and a placement recheck prevent a late
idle transition from capping a newly admitted workload. The node agent accepts
only `idle` or `active`, maps the accelerator ID to its locally configured GPU
index, and runs only the corresponding fixed operator-configured command. No
model is unloaded as part of a power-profile transition. An active transition
failure blocks execution; an idle failure is audited/logged and does not turn a
completed workload into a failure. An idle failure is retried from later node
telemetry after a 30-second backoff.

The node advertises only GPU indices with both fixed commands configured.
Unadvertised GPUs incur no power-control command or extra workload latency.
After registration and first telemetry, the controller reconciles configured
idle GPUs once, including after a controller restart; it skips initial parking
when a durable workload is still marked running on that accelerator. Model
load/unload transitions also request active before operating and idle afterward.

This is opt-in per accelerator under `gpu_performance.accelerators` in the node
agent YAML. Leave it absent on GPUs that have not been qualified. On NVIDIA
hardware that supports it, a possible policy is a calibrated low graphics
clock range while idle and `--reset-gpu-clocks` before work. NVIDIA documents
`--lock-gpu-clocks` and `--reset-gpu-clocks` as root-requiring operations on
supported devices. The example in `configs/node-agent.yaml` is illustrative,
**not a validated setting for the CMP170, RTX 3080, or RTX 3090**. Do not copy
its MHz values into a live node without measuring supported clocks, idle watts,
warm-model retention, transition latency, and workload throughput on that card.

P8 is an observed NVIDIA performance state, not a portable command target.
The control objective is lower idle power without evicting the model and full
performance before inference. Qualification must measure the actual P-state,
graphics/memory clocks, watts, VRAM residency, and first-token/render latency.
If a card cannot support safe runtime clock changes, the LB should report it
as unmanaged and let the driver scale automatically rather than claim P8.

This feature does not manage whole-node power, rentals, or RAM caching. Existing
`power_control_mode` governs separate node/chassis power policy. The CMP/Comfy
rig is not ready for live validation, so no fleet configuration is enabled yet.
