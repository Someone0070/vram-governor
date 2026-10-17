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

Hand-written settings (embedding mode, KV-cache types, `placement = single`
to keep a model on the primary GPU, ...) go in
`/etc/vram-governor/llama-presets.base.ini` and always win; the router reads
the generated `/etc/vram-governor/llama-presets.ini`. Run with `--dry-run` to
see the decisions and the estimates behind them.

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
cmake --build build -j8 --target llama-server llama-bench
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

Known problems with the mixed split (why calibration exists, and why
`qwen3.8-27b-uncensored-q6_k` is pinned with `placement = single`):

- Some split ratios run at half speed or less (13.5 GB at 42:58: 15.7 tok/s;
  16.8 GB at 54:46: 12.0), different per model. llama-bench calibration
  catches most, but the Q6 model ran at 9.7 tok/s in llama-server with a
  ratio that benchmarked at 19.0: the server's context settings matter.
- Loaded right after another model, the AMD card's share once landed in
  system RAM (GTT) instead of VRAM: 0.6 tok/s. The Vulkan backend falls back
  silently; llama.cpp's auto-fit causes the same, hence `fit = off`.
