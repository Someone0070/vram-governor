#!/usr/bin/env python3
"""Install a token received on stdin without echoing it."""

import json
import os
import pathlib
import re
import sys
import tempfile

payload = json.load(sys.stdin)
token = payload.get("token", "")
if not re.fullmatch(r"[A-Za-z0-9._~+/-]{32,512}", token):
    raise SystemExit("managed Comfy token is missing or malformed")
destination = pathlib.Path("/etc/vram-governor/comfy-harness.env")
destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=".comfy-harness.", dir=destination.parent)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("VRAM_COMFY_HARNESS_TOKEN=" + token + "\n")
    os.replace(temporary, destination)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print("managed Comfy credential installed")

