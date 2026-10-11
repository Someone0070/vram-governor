#!/usr/bin/env python3
"""Submit a tiny managed workflow through the public Comfy-compatible LB API."""

import json
import pathlib
import ssl
import time
import urllib.error
import urllib.request
import uuid

BASE = "https://10.0.0.115:8443"
values = dict(
    line.split("=", 1)
    for line in pathlib.Path("/root/vram-governor-controller-credentials.env").read_text().splitlines()
    if "=" in line
)
context = ssl.create_default_context(cafile="/etc/vram-governor/tls/controller.crt")
comfy_headers = {"Authorization": "Bearer " + values["COMFY_MCP_TOKEN"]}
admin_headers = {"Authorization": "Bearer " + values["ADMIN_TOKEN"]}
workflow = {
    "client_id": "governor-managed-smoke",
    "managed_chunks": [{
        "id": "cpu-only-image",
        "prompt": {
            "1": {"class_type": "EmptyImage", "inputs": {"width": 64, "height": 64, "batch_size": 1, "color": 0}},
            "2": {"class_type": "SaveImage", "inputs": {"filename_prefix": "governor-managed-smoke", "images": ["1", 0]}},
        },
    }],
}
request = urllib.request.Request(
    BASE + "/prompt",
    data=json.dumps(workflow).encode(),
    method="POST",
    headers={**comfy_headers, "Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4())},
)
with urllib.request.urlopen(request, context=context, timeout=15) as response:
    prompt_id = json.load(response)["prompt_id"]
for _ in range(240):
    request = urllib.request.Request(BASE + "/history/" + prompt_id, headers=comfy_headers)
    try:
        with urllib.request.urlopen(request, context=context, timeout=15) as response:
            history = json.load(response)
        if history:
            break
    except urllib.error.HTTPError as error:
        if error.code not in (404, 409, 425):
            raise
    time.sleep(0.5)
else:
    raise SystemExit("managed Comfy smoke workflow did not complete")

request = urllib.request.Request(BASE + "/admin/api/overview", headers=admin_headers)
with urllib.request.urlopen(request, context=context, timeout=15) as response:
    overview = json.load(response)
workload = next((row for row in overview["workloads"] if row["request"].get("item_id") == prompt_id), None)
if not workload or workload.get("status") not in ("completed", "succeeded"):
    raise SystemExit("managed Comfy workload was not completed")
if workload.get("plan", {}).get("target_id") != "cmp170-video-managed":
    raise SystemExit("managed Comfy workflow was not routed to the managed CMP target")
print("managed_comfy_prompt_id=" + prompt_id)
print("managed_comfy_target=cmp170-video-managed")
print("managed_comfy_live_verified=True")
