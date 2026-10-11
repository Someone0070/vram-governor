#!/usr/bin/env python3
"""Enable the CMP managed-Comfy target without disturbing other LB config."""

import os
import pathlib
import shutil
import tempfile
import yaml

path = pathlib.Path("/etc/vram-governor/controller.yaml")
document = yaml.safe_load(path.read_text(encoding="utf-8"))
targets = document.setdefault("workloads", {}).setdefault("targets", [])
managed = next((row for row in targets if row.get("id") == "cmp170-video-managed"), None)
if managed is None:
    managed = {"id": "cmp170-video-managed"}
    targets.append(managed)
managed.update({
    "adapter": "comfy",
    "runtime_protocol": "managed_comfy_v1",
    "endpoint": "http://127.0.0.1:9444",
    "authorization_env": "VRAM_MANAGED_COMFY_AUTHORIZATION",
    "accelerator_id": "cmp170-node-gpu0",
    "models": [
        "gemma4-12b-with-proj-ltx-2.5-bf16.safetensors",
        "ltx-2.5-22b-distilled-transformer-bf16.safetensors",
        "ltx-2.5-video-vae-bf16.safetensors",
    ],
    "custom_nodes": [
        "CLIPLoader", "CLIPTextEncode", "CreateVideo", "EmptyImage", "EmptyLTXVLatentVideo",
        "KSampler", "LTXVConditioning", "LTXVLatentUpsampler",
        "LatentUpscaleModelLoader", "SaveImage", "SaveVideo", "UNETLoader", "UnloadModel",
        "VAEDecode", "VAELoader",
    ],
    "slots": 1,
    "workload_class": "video",
    "vram_reserve_mb": 2048,
    "sharing_enabled": True,
    "guarded_exploration": True,
    "max_slowdown": 1.35,
    "safety_critical": False,
    "enabled": True,
})
shutil.copy2(path, path.with_suffix(".yaml.pre-cmp-runtime"))
fd, temporary = tempfile.mkstemp(prefix=".controller.", suffix=".yaml", dir=path.parent)
try:
    os.fchmod(fd, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        yaml.safe_dump(document, handle, sort_keys=False)
    os.chown(temporary, 0, path.stat().st_gid)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print("CMP managed target configured")
