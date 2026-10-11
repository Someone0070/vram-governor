# WSL local deployment

Last verified: 2026-08-31

> **Historical development environment:** This document records the old
> single-RTX-3080 WSL acceptance setup. It is not the current production/fleet
> topology and WSL is not a controller requirement. The current topology uses a
> dedicated controller/load-balancer machine and separate RTX 3080, RTX 3090,
> and CMP170 node hosts. See
> [Three-GPU fleet rollout and acceptance](fleet-rollout-and-acceptance.md).

This historical development deployment used one RTX 3080 as one physical accelerator,
even though both Ollama and ComfyUI expose it through separate adapters. The
controller's PostgreSQL accelerator lease prevents concurrent exclusive jobs
from double-booking the card.

## Installed services

| Component | Location / endpoint | Notes |
|---|---|---|
| Controller | `127.0.0.1:18082` | Runs in Ubuntu WSL and connects through the local PostgreSQL Unix socket. |
| Node agent | Ubuntu WSL | Discovers Ollama, ComfyUI, and `nvidia-smi` telemetry. |
| PostgreSQL 16 | `/var/run/postgresql` | Database `vram_governor`; the historical live run applied `0001` through `0015` only. Current source requires ordered migrations through `0020_accelerator_lease_cleanup.sql`, including `0016_creator_contract_alignment.sql`, `0017_node_enrollments.sql`, `0018_workload_revision.sql`, and `0019_model_capacity.sql`. |
| ComfyUI 0.34.0 | `/opt/comfyui`, `127.0.0.1:8188` | systemd service `comfyui.service`; official repository with no third-party custom nodes. |
| Ollama | `127.0.0.1:11434` | Uses the existing local model catalog. |

### Applying the current source migrations

The table above describes the historical acceptance snapshot, not a migration
target. For a fresh or upgraded WSL database, apply the complete ordered
source set through `0020_accelerator_lease_cleanup.sql`; the runner skips nothing and
is safe to rerun only when its normal migration bookkeeping permits it:

```bash
sudo -u vram-governor /usr/local/libexec/vram-governor/apply-migrations.sh
```

This applies `0001`–`0020`, including `0016_creator_contract_alignment.sql`,
`0017_node_enrollments.sql`, `0018_workload_revision.sql`, and
`0019_model_capacity.sql`, and `0020_accelerator_lease_cleanup.sql`. Do not infer
that these later migrations were present in the dated live run above.

ComfyUI is deliberately bound to WSL loopback. The node agent advertises it to
the controller; clients use the governor's Comfy-compatible routes rather than
addressing the backend directly.

## Existing model storage

`/opt/comfyui/extra_model_paths.yaml` points to an operator-provided library at
`/srv/vram-governor/comfyui`. The checked-in source template is
`deploy/wsl/comfyui-extra-model-paths.yaml`. No image model weights are cloned
or downloaded by the service.

The service starts with `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, and
`--disable-api-nodes`. This prevents implicit hub/API-node downloads. Arbitrary
custom-node installation is not part of the node-agent contract.

## Service files

- `deploy/wsl/comfyui.service` is the installed systemd unit source.
- `deploy/wsl/comfyui-extra-model-paths.yaml` records the allowed model roots.
- `deploy/wsl/bootstrap-postgres.sql` creates the local peer-authenticated role
  and database used on this machine.

Useful checks from PowerShell:

```powershell
wsl.exe -d Ubuntu -- systemctl status comfyui postgresql
wsl.exe -d Ubuntu -- curl -sS http://127.0.0.1:8188/system_stats
wsl.exe -d Ubuntu -- nvidia-smi
```

ComfyUI's `/free` endpoint was verified to release idle model allocations after
a completed workflow (about 6.4 GiB in the acceptance run). Automatic
cross-adapter reclamation is now represented as a fenced, durable
`cross_adapter_reclaim` residency transition. The same transition machinery
unloads Ollama before Comfy work and reclaims Comfy before an Ollama demand
load; both directions were exercised on the 3080.

## Live acceptance evidence

The acceptance workflow was submitted through the governor's `/prompt` route,
not directly to ComfyUI. It used the existing Z-Image diffusion model, Qwen
text encoder, and VAE to produce a 512x512 PNG. The governor collected the PNG
as an owner-scoped artifact, then the controller was stopped and restarted.

After restart, PostgreSQL restored:

- public prompt ID `1787717276578130491-1787717276578`;
- workload `wl-4c6e8e18b7f2cc3d70887d7a` with status `succeeded`;
- exactly one execution attempt;
- artifact SHA-256
  `442b8ea93b053be175c33aed51e580a3cfccedd1f364413416242840cfa7955d`;
- history and `/view` retrieval for the 270,460-byte PNG.

A subsequent 3B Ollama request also completed through the same accelerator
inventory. Later acceptance added two Ollama profiles for the same artifact:
2,048 context with two slots and 8,192 context with one slot. A bounded short
request selected the narrow profile while a long request selected the only
sufficient profile, and both ran concurrently under the guarded sharing
policy. The physical 10 GiB envelope peaked at 8,412 MiB with a 1,024 MiB
reserve and persisted a successful real-run learning sample.
