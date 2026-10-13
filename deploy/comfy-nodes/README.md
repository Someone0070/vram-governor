# ComfyUI node packs

## vram_governor_speech

Speech nodes backed by Qwen2.5-Omni-3B, used by the `audio-speak` and
`audio-transcribe` workflows:

- `VGSpeechSpeak`: text to 24 kHz audio with the built-in voices Chelsie and
  Ethan. Text is spoken in sentence chunks (at most ~160 characters), the
  generated text is capped at the chunk's own length so the chat model cannot
  add remarks, and a chunk that runs out of VRAM is retried as two halves.
- `VGSpeechTranscribe`: audio to text in 30-second windows; the transcript is
  capped by the audio's length.
- `VGSaveText`: writes a string to the output folder so the load balancer
  collects it as a `text/plain` artifact.

The full model (~10 GB in bf16) does not fit a 10 GB card, and speech never
needs the vision tower, so each mode moves only the parts it uses to the GPU
(speak: thinker + talker + token2wav, ~8.7 GB; transcribe: thinker + audio
encoder, ~7.6 GB). ComfyUI's own models are unloaded first, and everything
returns to system RAM after each node.

Install on the Comfy node (needs only what ComfyUI already ships: torch,
torchaudio, transformers with Qwen2.5-Omni support):

```sh
install -d /opt/ComfyUI/custom_nodes/vram_governor_speech
install -m 0644 vram_governor_speech/__init__.py /opt/ComfyUI/custom_nodes/vram_governor_speech/
systemctl restart comfyui
```

Weights: the Qwen2.5-Omni-3B files (config, `model-0000x-of-00003`, index,
tokenizer, `spk_dict.pt`, preprocessor) in `VG_OMNI_DIR`, default
`/models/qwen2.5-omni-3b`. Keep that directory free of other checkpoints: a
stray `model.safetensors` is preferred by the loader over the sharded index.

## vram_governor_auk

`VGAuK`, backed by Tencent AuK (MIT; Qwen2.5-Omni-3B text encoder + 1.5B
diffusion transformer), used by `audio-auk-tts`, `audio-auk-clone` and
`audio-auk-edit`. With `instruction` set it edits the input audio as told
(see AuK's cookbook: replace words, pitch, speed, volume, style, denoise,
separate the voice); otherwise it speaks `text`, in the input audio's voice
when one is connected, else as `voice_description` (`style` replaces it).
`seconds` 0 estimates the length; AuK drops words from the start when the
target is too short, so the estimate is generous. One model run is at most
30 s including the input audio; longer text is spoken in sentence chunks.

Upstream keeps the transformer in fp32 and its ComfyUI nodes keep the models
on the GPU until ComfyUI exits. This node casts the transformer to bf16 (it
already computes under bf16 autocast), drops the text encoder's unused
`lm_head`, uses AuK's `cpu_offload`, and parks the VAE in RAM after each run,
including the weight-norm computed weights that `.to()` leaves behind: a run
peaks at ~8 GB and leaves ~8 MB allocated.

Install the AuK package without its dependency pins (they would downgrade
ComfyUI's torch), plus the few modules it needs:

```sh
git clone https://github.com/Tencent-Hunyuan/AuK /opt/auk
git -C /opt/auk checkout 3b733647222c3915e2042722ad26198a504d803c
/opt/ComfyUI/venv/bin/python -m pip install accelerate torchdiffeq "x_transformers>=1.31.14" ema_pytorch "qwen-omni-utils>=0.0.9" audioread
/opt/ComfyUI/venv/bin/python -m pip install --no-deps /opt/auk
install -d /opt/ComfyUI/custom_nodes/vram_governor_auk
install -m 0644 vram_governor_auk/__init__.py /opt/ComfyUI/custom_nodes/vram_governor_auk/
systemctl restart comfyui
```

Weights: `auk_base.safetensors`, `vae.safetensors` and `config.yaml` in
`VG_AUK_DIR` (default `/models/auk/AuK`); the text encoder is the
Qwen2.5-Omni-3B directory in `VG_OMNI_DIR`.

## vram_governor_compat

No nodes; runtime shims loaded at ComfyUI start. It wraps
`comfy_kitchen.flash_attention_decode_is_available()` with a one-time probe
that runs the fused decode kernel. On CT200's NVIDIA 535 driver (CUDA 12.2)
the kernel fails with "CUDA driver version is insufficient for CUDA runtime
version" (YuE2's language model hit it), so the probe disables it and ComfyUI
uses its standard attention path; a newer driver re-enables it automatically.
It also probes GPU FFT in a child process (cuFFT from torch's CUDA 12.6 wheels
segfaulted on driver 535) and, if that crashes, runs `stft`/`istft`/`torch.fft`
for CUDA tensors on the CPU. CT200 runs driver 580 since 2026-10-13, where both
probes pass and the shims do nothing. `VGSanitizeAudio` replaces NaN/Inf audio
samples (LTX-2.5 occasionally decodes them) before every video is encoded.

```sh
install -d /opt/ComfyUI/custom_nodes/vram_governor_compat
install -m 0644 vram_governor_compat/__init__.py /opt/ComfyUI/custom_nodes/vram_governor_compat/
```
