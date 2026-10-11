#!/usr/bin/env python3
"""Register the independently measured local Qwen server with the 780m agent."""

import json
import os
import pathlib
import shutil
import tempfile
import urllib.request
from datetime import datetime, timezone


CONFIG = pathlib.Path("/etc/vram-governor/node-agent.yaml")
MODEL = "/root/models/Qwen3.8-9B-Q5_K_M.gguf"
ENDPOINT = "http://127.0.0.1:8095"
EMPTY = "llamacpp:\n  servers: []"
TARGET = """llamacpp:
  servers:
    - id: "qwen-8095"
      endpoint: "http://127.0.0.1:8095"
      public_endpoint: "http://10.0.0.165:8095"
      accelerator_index: 0
      router_managed: false
      max_resident_models: 1"""


def read_json(path):
    with urllib.request.urlopen(ENDPOINT + path, timeout=5) as response:
        return json.load(response)


def main():
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    if read_json("/health").get("status") != "ok":
        raise SystemExit("llama server is not healthy")
    models = read_json("/v1/models").get("data", [])
    if len(models) != 1 or models[0].get("id") != MODEL:
        raise SystemExit("unexpected resident model")
    slots = read_json("/slots")
    if not isinstance(slots, list) or len(slots) != 4 or any(slot.get("n_ctx") != 32768 for slot in slots):
        raise SystemExit("expected four measured 32768-token slots")

    original = CONFIG.read_text()
    if original.count(EMPTY) != 1:
        raise SystemExit("expected exactly one empty llama.cpp server list; config unchanged")
    if 'node_id: "780m-node"' not in original or 'power_control_mode: "dont_touch"' not in original:
        raise SystemExit("unexpected node identity or power mode; config unchanged")
    changed = original.replace(EMPTY, TARGET, 1)
    backup = CONFIG.with_name(CONFIG.name + ".before-qwen-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    shutil.copy2(CONFIG, backup)
    stat = CONFIG.stat()
    fd, temporary = tempfile.mkstemp(prefix=".node-agent-", dir=CONFIG.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(changed)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, stat.st_uid, stat.st_gid)
        os.chmod(temporary, stat.st_mode & 0o777)
        os.replace(temporary, CONFIG)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("configured=qwen-8095")
    print("measured_model=" + MODEL)
    print("measured_slots=4")
    print("measured_context_per_slot=32768")
    print("backup=" + str(backup))


if __name__ == "__main__":
    main()
