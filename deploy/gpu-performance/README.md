# LB-managed GPU power profile (NVIDIA)

The node agent runs unprivileged, so clock changes go through a root
one-shot unit that polkit lets only the agent user start.

| File | Install to |
|---|---|
| `gpu-clock.sh` | `/usr/libexec/vram-governor/gpu-clock.sh` (0755 root) |
| `vram-gpu-clock@.service` | `/etc/systemd/system/` then `systemctl daemon-reload` |
| `91-vram-gpu-clock.rules` | `/etc/polkit-1/rules.d/` |

Node agent YAML:

```yaml
gpu_performance:
  accelerators:
    - index: 0
      idle_command: ["/usr/bin/systemctl", "start", "--wait", "vram-gpu-clock@idle.service"]
      active_command: ["/usr/bin/systemctl", "start", "--wait", "vram-gpu-clock@active.service"]
```

`idle` locks the memory clock to the lowest value the card reports in
`--query-supported-clocks=mem`; `active` resets clocks. Models stay in VRAM.
Set `VRAM_GPU_INDEX` in a unit drop-in for a GPU other than 0.

Measured on the RTX 3080 (CT200, 2026-10-11): idle P8 / 405 MHz memory /
~15 W; active P2 / 9251 MHz / ~222 W under load; a 4B model went from
~4 to ~90 tokens/s once clocks were no longer pinned during inference.
Re-measure after swapping cards (CMP 170HX): confirm `-lmc` is supported
and watch idle watts and first-token latency.

Do not run another idle-parking timer alongside this; two owners of the
clock lock will pin clocks during inference.
