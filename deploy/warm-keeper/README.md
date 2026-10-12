# Warm-RAM keeper

`vram-warm-keeper` is the working "offload to RAM" tier for llama.cpp router
nodes. When a model is evicted from VRAM its file stays pinned in host RAM, so
the next load reads from memory instead of disk.

Measured on CT200 (RTX 3080, ZFS NVMe, 2026-10-12), `qwen3.8-27b-q5_k_m`
(19.3 GiB):

| File state | Model load |
|---|---|
| on NVMe only | 40.5 s |
| in RAM (page cache) | 8.3 s |

Without the keeper the file does not stay in RAM: ComfyUI reads hundreds of
GiB of image/video weights and pushes LLM files out of the page cache, and the
ZFS ARC on the Proxmox host is capped at 16 GiB.

## How it works

- Polls the router's `/models` every 2 s. Every model seen `loaded` becomes the
  most recently used; the list is kept in
  `/var/lib/vram-warm-keeper/state.json`, so after a restart the same models
  are pinned again.
- Pins (`mmap` + `mlock`, 256 MiB at a time) the `--always` models first, then
  the most recently used ones, while they fit `-budget`. A model too big for the
  remaining budget is skipped so smaller recent ones still fit. The pinned pages
  are the same page-cache pages llama.cpp maps, so no memory is duplicated.
- Memory always wins over warmth. While `MemAvailable` is below
  `-min-available` it releases the lowest-priority pin each second, then waits
  `-cooldown` (2 min) before pinning again. A pin is aborted mid-way if pressure
  arrives, and a new pin must leave `-min-available` + `-pin-headroom` free.
- A model file replaced on disk (e.g. by `vram-model-cache-sync`) is released
  and pinned again from the new file.
- It never loads or unloads models and has no say in scheduling; the controller
  still records an evicted model as `cold_disk`. The node agent's older
  `warm_ram` mechanism is separate and remains disabled.

`/run/vram-warm-keeper/status.json` shows the budget, pinned bytes,
MemAvailable, each model's state and the last event.

## Install (CT200)

```sh
install -m 0755 vram-warm-keeper /usr/local/bin/vram-warm-keeper
install -m 0644 vram-warm-keeper.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vram-warm-keeper
```

The unit runs as `vram-governor` with only `CAP_IPC_LOCK`, which the
container must allow (privileged LXC does by default). Without it every pin
fails with `cannot allocate memory` once past `RLIMIT_MEMLOCK`.

Override the defaults (44 GiB budget, 16 GiB floor) in
`/etc/vram-governor/warm-keeper.env`:

```sh
WARM_KEEPER_BUDGET=44GiB
WARM_KEEPER_MIN_AVAILABLE=16GiB
WARM_KEEPER_ALWAYS=qwen3.8_4b,qwen3-embedding_0.6b
```

Size the budget so pinned models plus the largest ComfyUI workload fit in the
container's RAM; the floor is the safety margin, not the budget.
