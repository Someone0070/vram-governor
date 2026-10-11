#!/usr/bin/env python3
"""Install the package's pinned Comfy models; --check never writes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import urllib.request


PACKAGE = Path(__file__).resolve().parents[2] / "configs" / "comfy-bootstrap"
MODEL_ROOT = Path("/opt/ComfyUI/models")
ALLOWED = {"checkpoints", "diffusion_models", "text_encoders", "vae"}
CHUNK = 8 * 1024 * 1024
RESERVE_BYTES = 2 * 1024 * 1024 * 1024
PUBLISHERS = {
    "stabilityai/stable-diffusion-xl-base-1.0": {"462165984030d82259a11f4367a4eed129e94a7b"},
    "Comfy-Org/Wan_2.2_ComfyUI_Repackaged": {"ee6f4a40737a995bf5818954cfce6d59443b0f04"},
}
EXPECTED_IDS = {"sdxl-base-1.0", "wan22-ti2v-5b", "wan22-umt5-xxl-fp8", "wan22-vae"}
EXPECTED_ARTIFACTS = {
    "sdxl-base-1.0": ("checkpoints", "sd_xl_base_1.0.safetensors", "sd_xl_base_1.0.safetensors"),
    "wan22-ti2v-5b": ("diffusion_models", "wan2.2_ti2v_5B_fp16.safetensors", "split_files/diffusion_models/wan2.2_ti2v_5B_fp16.safetensors"),
    "wan22-umt5-xxl-fp8": ("text_encoders", "umt5_xxl_fp8_e4m3fn_scaled.safetensors", "split_files/text_encoders/umt5_xxl_fp8_e4m3fn_scaled.safetensors"),
    "wan22-vae": ("vae", "wan2.2_vae.safetensors", "split_files/vae/wan2.2_vae.safetensors"),
}


def fail(message):
    raise RuntimeError(message)


def load_manifest():
    data = json.loads((PACKAGE / "models.json").read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("models"), list):
        fail("invalid model manifest")
    seen = set()
    if len(data["models"]) != 4:
        fail("manifest must contain exactly four approved artifacts")
    for item in data["models"]:
        folder, name = item.get("target_directory"), item.get("filename")
        model_id = item.get("id")
        if folder not in ALLOWED or not name or Path(name).name != name or name in seen or model_id in seen:
            fail("unsafe or duplicate model destination")
        repository = item.get("publisher", "") + "/" + item.get("repository", "")
        if item.get("revision") not in PUBLISHERS.get(repository, set()):
            fail("publisher, repository, or revision is not approved")
        source_path = item.get("source_path", "")
        parts = source_path.split("/")
        if (not source_path or source_path.startswith("/") or "\\" in source_path or
                any(part in ("", ".", "..") for part in parts)):
            fail("unsafe publisher-relative source path")
        if model_id not in EXPECTED_ARTIFACTS or (folder, name, source_path) != EXPECTED_ARTIFACTS[model_id]:
            fail("artifact destination or publisher path is not approved")
        if len(item.get("sha256", "")) != 64 or any(c not in "0123456789abcdef" for c in item["sha256"]):
            fail("invalid model digest")
        if not isinstance(item.get("bytes"), int) or item["bytes"] <= 0:
            fail("invalid model size")
        seen.update((name, model_id))
    if {item.get("id") for item in data["models"]} != EXPECTED_IDS:
        fail("manifest model ids do not match the approved package")
    return data["models"]


def ensure_real_directory(path, create=False):
    """Walk only the fixed model-root descendants; reject symlinks at every level."""
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                return False
            current.mkdir()
            info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail("model directory path contains a link or non-directory")
        if hasattr(os, "geteuid") and (info.st_uid != 0 or info.st_mode & 0o022):
            fail("model directory path is not root-owned and protected from group/world writes")
    return True


def digest_file(path):
    h = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            fail("existing destination is not a regular file")
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            total += len(block)
            h.update(block)
    return total, h.hexdigest()


def inspect_destination(path, item):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("destination exists and is not a regular file")
    if info.st_size != item["bytes"]:
        fail("existing destination fails pinned size verification")
    size, digest = digest_file(path)
    if size != item["bytes"] or digest != item["sha256"]:
        fail("existing destination fails pinned size or hash verification")
    return "verified"


def download(item, destination):
    repository = item["publisher"] + "/" + item["repository"]
    url = "https://huggingface.co/{}/resolve/{}/{}".format(
        repository, item["revision"], item["source_path"]
    )
    temp_path = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".comfy-bootstrap-", suffix=".part", dir=str(destination.parent))
        temp_path = Path(temp_name)
        h = hashlib.sha256()
        total = 0
        next_notice = 256 * 1024 * 1024
        with os.fdopen(fd, "wb") as output, urllib.request.urlopen(url, timeout=60) as response:
            while True:
                block = response.read(CHUNK)
                if not block:
                    break
                total += len(block)
                if total > item["bytes"]:
                    fail("download exceeded pinned byte count")
                h.update(block)
                output.write(block)
                if total >= next_notice:
                    print("download progress: {} MiB".format(total // (1024 * 1024)), file=sys.stderr)
                    next_notice += 256 * 1024 * 1024
            output.flush()
            os.fsync(output.fileno())
        if total != item["bytes"] or h.hexdigest() != item["sha256"]:
            fail("download failed pinned size or hash verification")
        # Hard-link creation is exclusive: it cannot replace a pre-existing file or symlink.
        os.link(str(temp_path), str(destination))
        temp_path.unlink()
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify installed files without writing")
    mode.add_argument("--apply", action="store_true", help="download and install verified files")
    args = parser.parse_args()

    items = load_manifest()
    root_exists = ensure_real_directory(MODEL_ROOT, create=False)
    missing = []
    for item in items:
        folder = MODEL_ROOT / item["target_directory"]
        if not ensure_real_directory(folder, create=False):
            missing.append(item)
            continue
        target = folder / item["filename"]
        status = inspect_destination(target, item)
        if status == "missing":
            missing.append(item)
    if args.check:
        if missing:
            fail("{} pinned model file(s) are missing".format(len(missing)))
        print("COMFY_MODELS_VERIFIED")
        return
    if not root_exists:
        fail("model root is unavailable")
    if missing:
        available = shutil.disk_usage(str(MODEL_ROOT)).free
        required = sum(item["bytes"] for item in missing) + RESERVE_BYTES
        if available < required:
            fail("insufficient free space for missing models and reserved headroom")
    for item in missing:
        folder = MODEL_ROOT / item["target_directory"]
        ensure_real_directory(folder, create=True)
        download(item, folder / item["filename"])
    print("COMFY_MODELS_INSTALLED")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
        # Exception text from URL libraries can contain the request URL. Keep it out of logs.
        print("ERROR: model operation failed ({})".format(type(exc).__name__), file=sys.stderr)
        sys.exit(1)
