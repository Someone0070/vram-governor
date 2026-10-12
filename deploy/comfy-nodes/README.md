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

## vram_governor_compat

No nodes; runtime shims loaded at ComfyUI start. It wraps
`comfy_kitchen.flash_attention_decode_is_available()` with a one-time probe
that runs the fused decode kernel. On CT200's NVIDIA 535 driver (CUDA 12.2)
the kernel fails with "CUDA driver version is insufficient for CUDA runtime
version" (YuE2's language model hit it), so the probe disables it and ComfyUI
uses its standard attention path; a newer driver re-enables it automatically.

```sh
install -d /opt/ComfyUI/custom_nodes/vram_governor_compat
install -m 0644 vram_governor_compat/__init__.py /opt/ComfyUI/custom_nodes/vram_governor_compat/
```
