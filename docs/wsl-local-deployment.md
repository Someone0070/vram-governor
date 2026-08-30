# WSL local deployment

Last verified: 2026-08-25

This development deployment uses one RTX 3080 as one physical accelerator,
even though both Ollama and ComfyUI expose it through separate adapters. The
controller's PostgreSQL accelerator lease prevents concurrent exclusive jobs
from double-booking the card.

## Installed services

| Component | Location / endpoint | Notes |
|---|---|---|
| Controller | `127.0.0.1:18082` | Runs in Ubuntu WSL and connects through the local PostgreSQL Unix socket. |
| Node agent | Ubuntu WSL | Discovers Ollama, ComfyUI, and `nvidia-smi` telemetry. |
| PostgreSQL 16 | `/var/run/postgresql` | Database `vram_governor`; migrations `0001` through `0014` are applied. |
| ComfyUI 0.34.0 | `/opt/comfyui`, `127.0.0.1:8188` | systemd service `comfyui.service`; official repository with no third-party custom nodes. |
| Ollama | `127.0.0.1:11434` | Uses the existing local model catalog. |

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
cross-adapter idle reclamation is not yet represented as a durable governor
residency transition; it remains a documented gap rather than a claimed
feature.

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
inventory. This proves sequential dual-adapter use and exclusive leasing; it
does not prove safe concurrent co-scheduling.
