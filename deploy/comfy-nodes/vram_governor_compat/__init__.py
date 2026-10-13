"""Runtime compatibility shims for ComfyUI on the load balancer's nodes.

comfy_kitchen.flash_attention_decode_is_available() reports the fused decode
kernel as available whenever its extension imports, but the kernel needs a
newer NVIDIA driver than CT200's 535 (CUDA 12.2): YuE2's language model then
fails with "CUDA driver version is insufficient for CUDA runtime version".
ComfyUI looks the check up on every call, so it is wrapped here with a one-time
probe that actually runs the kernel on the device; if that fails, ComfyUI takes
its standard attention path instead. GPU FFTs get the same treatment (see
below). With a new enough driver the probes pass and nothing changes.
"""

import logging

log = logging.getLogger(__name__)

import torch

try:
    import comfy_kitchen
except Exception:  # pragma: no cover - ComfyUI without comfy_kitchen
    comfy_kitchen = None

_probed = {}


def _probe(device):
    q = torch.zeros((1, 1, 8, 128), device=device, dtype=torch.bfloat16)
    k = torch.zeros((1, 16, 8, 128), device=device, dtype=torch.bfloat16)
    seqlen = torch.full((1,), 4, device=device, dtype=torch.int32)
    comfy_kitchen.flash_attention_decode(q, k, torch.zeros_like(k), seqlen)
    torch.cuda.synchronize(device)


if comfy_kitchen is not None and hasattr(comfy_kitchen, "flash_attention_decode_is_available"):
    _original = comfy_kitchen.flash_attention_decode_is_available

    def flash_attention_decode_is_available(device):
        if not _original(device):
            return False
        key = str(device)
        if key not in _probed:
            try:
                _probe(device)
                _probed[key] = True
            except Exception as error:  # driver too old, unsupported arch, ...
                _probed[key] = False
                log.warning("comfy_kitchen flash decode disabled on %s: %s", key, str(error).splitlines()[0])
        return _probed[key]

    comfy_kitchen.flash_attention_decode_is_available = flash_attention_decode_is_available


# cuFFT from torch's CUDA 12.6 wheels segfaults on driver 535 (CUDA 12.2): the
# first GPU FFT, e.g. torch.stft in YuE2's SheetSage2 audio encoder, kills the
# whole ComfyUI process. A segfault cannot be caught, so the probe runs in a
# child process; if it dies, FFTs on CUDA tensors run on the CPU instead.
_FFT_PROBE = "import torch; torch.fft.rfft(torch.ones(64, device='cuda')); torch.cuda.synchronize()"


def _gpu_fft_works():
    import subprocess
    import sys

    try:
        result = subprocess.run([sys.executable, "-c", _FFT_PROBE], capture_output=True, timeout=120)
    except Exception as error:  # pragma: no cover - probe could not run
        log.warning("GPU FFT probe did not run (%s); keeping GPU FFT", error)
        return True
    return result.returncode == 0


def _on_cpu(fn):
    def call(*args, **kwargs):
        device = next((a.device for a in list(args) + list(kwargs.values()) if isinstance(a, torch.Tensor)), None)
        if device is None or device.type != "cuda":
            return fn(*args, **kwargs)
        move = lambda v: v.cpu() if isinstance(v, torch.Tensor) else v
        out = fn(*[move(a) for a in args], **{k: move(v) for k, v in kwargs.items()})
        if isinstance(out, torch.Tensor):
            return out.to(device)
        if isinstance(out, tuple):
            return tuple(o.to(device) if isinstance(o, torch.Tensor) else o for o in out)
        return out

    call.__wrapped__ = fn
    return call


if torch.cuda.is_available() and not _gpu_fft_works():
    log.warning("GPU FFT crashes with this NVIDIA driver; running stft/istft/torch.fft on the CPU")
    torch.stft = _on_cpu(torch.stft)
    torch.istft = _on_cpu(torch.istft)
    torch.Tensor.stft = _on_cpu(torch.Tensor.stft)
    torch.Tensor.istft = _on_cpu(torch.Tensor.istft)
    for _name in ("fft", "ifft", "rfft", "irfft", "hfft", "ihfft", "fft2", "ifft2", "rfft2", "irfft2", "fftn", "ifftn", "rfftn", "irfftn"):
        setattr(torch.fft, _name, _on_cpu(getattr(torch.fft, _name)))


class VGSanitizeAudio:
    """Replace NaN/Inf samples and clamp to [-1, 1].

    LTX-2.5 occasionally decodes audio containing NaN, and the AAC encoder in
    SaveVideo/CreateVideo then fails the whole render ("Input contains (near)
    NaN/+-Inf"). Silence in place of the bad samples keeps the video.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {"audio": ("AUDIO",)}}

    RETURN_TYPES = ("AUDIO",)
    FUNCTION = "run"
    CATEGORY = "vram-governor/audio"

    def run(self, audio):
        waveform = audio["waveform"]
        bad = int((~torch.isfinite(waveform)).sum())
        if bad:
            log.warning("VGSanitizeAudio replaced %d non-finite samples", bad)
        cleaned = torch.nan_to_num(waveform, nan=0.0, posinf=1.0, neginf=-1.0).clamp(-1.0, 1.0)
        return ({**audio, "waveform": cleaned},)


NODE_CLASS_MAPPINGS = {"VGSanitizeAudio": VGSanitizeAudio}
NODE_DISPLAY_NAME_MAPPINGS = {"VGSanitizeAudio": "Sanitize audio (NaN/Inf)"}
