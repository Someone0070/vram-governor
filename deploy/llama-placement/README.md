# Multi-GPU placement for the llama.cpp router

`vram-llama-placement` decides, before every llama-server start, whether each
router model runs on the primary GPU or is split across all GPUs on the node.
It reads the cards from llama.cpp itself (`llama-server --list-devices`), the
context size from the active runtime profile (`LLAMA_CTX_SIZE`), and each
model's size and KV-cache shape from its GGUF metadata:

| Need (weights + KV + margin) | Placement |
|---|---|
| fits the primary GPU | `device = CUDA0` (other cards stay free) |
| fits all GPUs together | `device = CUDA0,Vulkan1`, `tensor-split` by VRAM, `n-gpu-layers = 99`, `fit = off` |
| fits nowhere | `device = CUDA0`, llama.cpp's auto-fit spills the rest to the CPU |

`fit = off` matters for split models: llama.cpp's auto-fit misjudged the
RX 6900 XT on this X99 board (no Resizable BAR, 256 MiB CPU-visible VRAM) and
put its share in system RAM (0.5 tok/s instead of 20).

## Context pools

Each model also gets one shared context pool (llama.cpp's unified KV cache)
instead of fixed slots: `ctx-size` is the pool, `parallel` the number of
concurrent requests, `kv-unified = 1`. Requests draw tokens from the pool, so
many short chats run side by side while one long-context job can use most of
it. The pools are written to `/etc/vram-governor/llama-model-pools.json`; the
node agent advertises them (`model_pools_file`) and the controller admits a
request if its context (`governor.context_tokens`, at least ~4 bytes of
payload per token, plus `max_tokens` or 2048) fits the model's per-request
maximum and the pool's unreserved tokens. A request beyond the per-request
maximum gets HTTP 400 `context_length_exceeded`; a full pool makes it wait.

Single-GPU pools come from `llama-fit-params` (llama.cpp's own projection,
cached in `/var/lib/vram-governor/llama-fit-cache.json`): the largest context
that keeps every layer on the GPU with 1 GiB free. An estimate that missed the
per-slot state (4B, 210k tokens, 8 slots) made llama.cpp move layers to the
CPU: 104 -> 38 tok/s. Split models use the tool's estimate with auto-fit off
(llama.cpp's fit refuses a fixed tensor split), so a wrong pool fails the load
instead of slowing it down. The router command line must not set
`--ctx-size`/`--parallel`: they override every model's preset.

## MTP speculative decoding

Models with multi-token-prediction layers (`nextn_predict_layers` in the
GGUF: the Qwen3.8 4B and 27B here) run with `spec-type = draft-mtp`. Through
the LB, single request (CT200, 2026-10-17):

| Model | Without MTP | With MTP | Pool without / with |
|---|---|---|---|
| qwen3.8_4b (4070 SUPER) | 103 tok/s | 130-138 tok/s | 186k / 87.5k tokens |
| qwen3.8-27b Q5 (split) | 20.0 | 31.0 | 30.2k / 27.1k |
| qwen3.8-27b Q6 (split) | 18.8 | 28-30 | 35.6k / 32k |

Eight concurrent 4B chats finish faster with MTP (8.9 s vs 12.4 s); four
concurrent 27B requests take about the same (52 vs 49 s).

The draft context needs VRAM that neither this tool's estimate nor
llama-fit-params accounts for, and part of it is only allocated on the first
generation. Too little and llama.cpp moves layers to the CPU (4B at a 131k
pool: 38 tok/s) or, with `fit = off`, aborts with CUDA out of memory. So
`--calibrate` starts a real llama-server per MTP model, binary-searches the
largest pool that loads with every layer on the GPUs and completes a short
generation, then keeps 90% of it after two more clean runs (the 27B Q6 at its
full pool passed once and then failed in the router). A model without a
calibrated MTP pool runs without MTP; `mtp = off` in the base file disables
it. Run `--calibrate` with llama-server stopped.

Hand-written settings (embedding mode, KV-cache types, `placement = single`
to keep a model on the primary GPU, ...) go in
`/etc/vram-governor/llama-presets.base.ini` and always win; the router reads
the generated `/etc/vram-governor/llama-presets.ini`. Run with `--dry-run` to
see the decisions and the estimates behind them.

## Quick calibration (minutes, automatic)

`vram-llama-quickcal` measures each model in three placements (each GPU
alone, one split; a 5-point split scan for a model that needs both GPUs):
one ~5-20 s run each (load from RAM, an untimed warm-up, one 768-token job,
four parallel jobs, and the per-device buffer sizes llama.cpp logs). Runs on
different GPUs go in parallel and the next model is locked in RAM while the
current one runs. A per-model fit predicts every ratio:

| Quantity | Model (share s on the primary GPU) |
|---|---|
| time per generated token | s·a + (1−s)·b + c when split |
| time per prompt token | s·a' + (1−s)·b' |
| pool tokens | min over GPUs of free bytes ÷ KV bytes per token |

On InternVL3.5-8B (4070 SUPER + 6900 XT) the fit is within 1.3% for
generation, 6% for prompt and 5% for the pool. Some ratios collapse at layer
boundaries no formula predicts (Gemma 4 26B: prompt 2180 tok/s at 56:44,
134 at 52:48): a split far below the best measured one is excluded from the
fit and its neighbourhood skipped. Every chosen placement is confirmed by a
run and by a load at its pool with an image request.

Results per role go to the calibration cache: `gpu0` and `gpu1` (each GPU
alone) and `split` (models that need both GPUs, or a split with 30% more
context than either GPU). `vram-llama-autocal` (path unit on the models
directory and base presets, a nightly timer, at boot) calibrates whatever
has no result for the current files, GPUs and llama.cpp build, waiting for
the routers to be idle.

## Per-GPU routers

One router per GPU plus one for split models, so the controller can run a
copy of a model on each card and split only when needed:

| Unit | Port (LB tunnel) | GPU(s) | Role |
|---|---|---|---|
| `llama-server` + `zz-placement-gpu0.conf` | 8080 (9445) | 4070 SUPER | `gpu0` |
| `llama-gpu1.service` | 8085 (9447) | 6900 XT | `gpu1` |
| `llama-split.service` | 8086 (9448) | both | `split` |

Each router gets its own models directory of links, presets and pools
(`VG_LLAMA_ROLE`). The node agent advertises the split router with
`companion_accelerator_indexes: [1]`; the controller holds both GPUs' leases
while it runs, evicts the per-card routers' models before it loads, and
prefers whichever copy finishes a request sooner (pools carry measured
decode and prompt speeds). Vision projectors are pinned to the model's GPU
(`mmproj-device`); the 6900 XT router runs without CUDA visible.

## Mixed NVIDIA + AMD build

Splitting across vendors needs llama.cpp built with both backends; the same
commit as the CUDA-only build, plus Vulkan (RADV for the AMD card, the
NVIDIA driver's Vulkan ICD for the other):

```sh
apt-get install mesa-vulkan-drivers vulkan-tools libvulkan-dev glslc spirv-headers
rsync -a --exclude build /root/llama.cpp/ /root/llama.cpp-mixed/
cd /root/llama.cpp-mixed
cmake -B build -DCMAKE_BUILD_TYPE=Release -DGGML_CUDA=ON -DGGML_CUDA_FA=ON -DGGML_VULKAN=ON \
  -DCMAKE_CUDA_ARCHITECTURES="86;89" -DGGML_NATIVE=ON -DLLAMA_CURL=OFF
cmake --build build -j8 --target llama-server llama-bench llama-fit-params
```

The AMD card must be visible in the container (`/dev/dri`, `/dev/kfd`, cgroup
majors 226 and kfd's dynamic one; see `fix-lxc-nvidia-uvm.sh` on the host).

## Install (CT200)

```sh
install -m 0755 vram-llama-placement /usr/local/sbin/
mv /etc/vram-governor/llama-presets.ini /etc/vram-governor/llama-presets.base.ini
install -m 0644 zz-placement.conf /etc/systemd/system/llama-server.service.d/
systemctl daemon-reload && systemctl restart llama-server
```

Without a second card the tool pins every model to the primary GPU, so the
mixed build and the placement step are safe to leave in place after the card
is removed.

## Measured (CT200, 2026-10-17)

qwen3.8-27b at four sizes (dense; Q3/Q4/Q8 re-quantized from Q6_K for the
test), llama-server, ~720-token prompt, 200 generated tokens. RTX 4070 SUPER
12 GB (CUDA) + RX 6900 XT 16 GB (Vulkan/RADV), X99 board, PCIe 3.0.

| Model | 4070 SUPER alone (CPU spill) | 6900 XT alone | Both cards |
|---|---|---|---|
| 13.5 GB (Q3_K_M) | 6.2 tok/s | 27.2 tok/s | 26.3 tok/s (72:28) |
| 16.8 GB (Q4_K_M) | 4.6 tok/s | does not fit | 24.5 tok/s (60:40) |
| 20.8 GB (Q5_K_M) | 3.2 tok/s | does not fit | 20.0 tok/s (50:50) |
| 29.0 GB (Q8_0) | 2.2 tok/s | does not fit | 6.8 tok/s (57/65 layers on GPUs, rest CPU) |

Generation is bound by memory bandwidth: every token reads all weights once,
VRAM at ~500-900 GB/s, the X99's DDR4 at ~40-50 GB/s. A few GB left on the
CPU dominate, which is why the tool fills every GPU before the CPU.

Split ratios matter: some run at half speed or less (13.5 GB at 42:58:
15.7 tok/s; 16.8 GB at 54:46: 12.0; 27B Q6 at 50:50: 10.1 vs 18.7-19.0 at
46:54, 42:58 and 37:63), different per model. `--calibrate` (llama-bench)
picks the ratio; with the pool settings in the presets, llama-server matches
the benchmark (27B Q6 at 46:54: 18.7 tok/s on repeated loads and after
swapping from other models through the LB). An earlier 9.7 tok/s came from
the router's global `--ctx-size`/`--parallel` overriding the presets.

The amdgpu memory counters do not tell a good load from a bad one on this
board: with the 6900 XT's share running at full speed, both
`mem_info_vram_used` and the process's `drm-memory-vram` read 0 and the
share shows up as GTT. Check tokens per second instead.
