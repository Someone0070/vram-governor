#!/usr/bin/env python3
"""Exercise CMP model lifecycle/profile controls through the controller API."""

import json
import pathlib
import ssl
import time
import urllib.request
import uuid

NODE = "cmp170-node"
TARGET = "cmp170-node-cmp170-llm"
MODEL = "nanbeige-fast_latest"
BASE = "https://10.0.0.115:8443"

values = dict(
    line.split("=", 1)
    for line in pathlib.Path("/root/vram-governor-controller-credentials.env").read_text().splitlines()
    if "=" in line
)
headers = {"Authorization": "Bearer " + values["ADMIN_TOKEN"]}
context = ssl.create_default_context(cafile="/etc/vram-governor/tls/controller.crt")


def request(path, method="GET", body=None, extra=None):
    encoded = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=encoded, method=method, headers={**headers, **(extra or {})})
    with urllib.request.urlopen(req, context=context, timeout=15) as response:
        return json.load(response)


def command(name, args):
    accepted = request(
        f"/admin/api/nodes/{NODE}/commands",
        "POST",
        {"command": name, "args": args, "ttl_seconds": 180},
        {"Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4())},
    )
    for _ in range(360):
        rows = request(f"/admin/api/node-commands?node_id={NODE}&limit=50")
        row = next((item for item in rows if item.get("id") == accepted["id"]), None)
        if row and row.get("status") in ("succeeded", "failed", "expired"):
            if row["status"] != "succeeded":
                raise SystemExit(f"{name} failed: {row.get('error')}")
            print(f"{name}=succeeded")
            return row
        time.sleep(0.5)
    raise SystemExit(f"{name} did not settle")


def target():
    overview = request("/admin/api/overview")
    return next(row for row in overview["targets"] if row["id"] == TARGET)


def wait_target(predicate, failure):
    for _ in range(120):
        row = target()
        if predicate(row):
            return row
        time.sleep(0.5)
    raise SystemExit(failure)


command("load_model", {"target_id": TARGET, "model": MODEL})
loaded = wait_target(lambda row: MODEL in (row.get("resident_models") or []), "load was not reflected in controller residency")
command("switch_runtime_profile", {"target_id": TARGET, "profile_id": "ctx-32k-1"})
long_context = wait_target(lambda row: row.get("capacity_verified") and row.get("context_limit") == 32768 and row.get("slots") == 1, "32K/1 profile was not runtime-verified")
command("switch_runtime_profile", {"target_id": TARGET, "profile_id": "ctx-8k-4"})
short_context = wait_target(lambda row: row.get("capacity_verified") and row.get("context_limit") == 8192 and row.get("slots") == 4, "8K/4 profile was not runtime-verified")
command("unload_model", {"target_id": TARGET, "model": MODEL})
unloaded = wait_target(lambda row: MODEL not in (row.get("resident_models") or []), "unload was not reflected in controller residency")
print("cmp_runtime_controls_verified=True")
