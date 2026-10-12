# Local model cache for NAS-backed nodes

When model files live on a network share, a model load is bounded by the
share: on CT200 (gigabit CIFS) a 3.3 GiB model took ~32 s to load, almost all
of it reading the file (110 MiB/s cold vs 5.6 GiB/s from the page cache).

`vram-model-cache-sync` copies every llama.cpp router preset target from
`/etc/vram-governor/llama-models` to `/var/lib/vram-governor/model-cache` on
local disk and atomically re-points the preset symlinks. After that:

- a model unloaded from VRAM is reloaded from the Linux page cache (host RAM)
  while memory allows, otherwise from local NVMe — this is the practical
  "offload to RAM" tier: VRAM is freed, the bytes stay in RAM (pinned there by
  [`vram-warm-keeper`](../warm-keeper/README.md), otherwise only until other
  reads push them out);
- nothing in the controller or agent changes; model IDs are the preset names.

Install to `/usr/local/sbin/vram-model-cache-sync` and run once (re-run after
adding models). Size the cache disk for the sum of router models.
