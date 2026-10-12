"""Runtime compatibility shims for ComfyUI on the load balancer's nodes.

comfy_kitchen.flash_attention_decode_is_available() reports the fused decode
kernel as available whenever its extension imports, but the kernel needs a
newer NVIDIA driver than CT200's 535 (CUDA 12.2): YuE2's language model then
fails with "CUDA driver version is insufficient for CUDA runtime version".
ComfyUI looks the check up on every call, so it is wrapped here with a one-time
probe that actually runs the kernel on the device; if that fails, ComfyUI takes
its standard attention path instead. With a new enough driver the probe passes
and nothing changes.
"""

import logging

log = logging.getLogger(__name__)

try:
    import comfy_kitchen
    import torch
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

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}
