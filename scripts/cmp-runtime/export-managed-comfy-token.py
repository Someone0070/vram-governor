#!/usr/bin/env python3
"""Emit the managed-Comfy token for a protected host-to-host pipe."""

import json
import os
import pathlib
import secrets
import tempfile

path = pathlib.Path("/etc/vram-governor/controller.env")
values = dict(
    line.split("=", 1)
    for line in path.read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#") and "=" in line
)
authorization = values.get("VRAM_MANAGED_COMFY_AUTHORIZATION", "")
if not authorization:
    original = path.stat()
    authorization = "Bearer " + secrets.token_urlsafe(48)
    lines = path.read_text(encoding="utf-8").splitlines()
    replacement = "VRAM_MANAGED_COMFY_AUTHORIZATION=" + authorization
    lines = [replacement if line.startswith("VRAM_MANAGED_COMFY_AUTHORIZATION=") else line for line in lines]
    fd, temporary = tempfile.mkstemp(prefix=".controller-env.", dir=path.parent)
    try:
        os.fchmod(fd, original.st_mode & 0o777)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.chown(temporary, original.st_uid, original.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
if not authorization.startswith("Bearer ") or len(authorization) < 40:
    raise SystemExit("managed Comfy authorization is malformed")
print(json.dumps({"token": authorization.removeprefix("Bearer ")}))
