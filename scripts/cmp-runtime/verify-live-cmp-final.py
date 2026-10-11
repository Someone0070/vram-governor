#!/usr/bin/env python3
"""Read-only final topology and safety verification on the dedicated LB."""

import json
import pathlib
import socket
import ssl
import urllib.error
import urllib.request
import yaml

BASE = "https://10.0.0.115:8443"
credentials = dict(
    line.split("=", 1)
    for line in pathlib.Path("/root/vram-governor-controller-credentials.env").read_text().splitlines()
    if "=" in line
)
environment = dict(
    line.split("=", 1)
    for line in pathlib.Path("/etc/vram-governor/controller.env").read_text().splitlines()
    if line and not line.startswith("#") and "=" in line
)
context = ssl.create_default_context(cafile="/etc/vram-governor/tls/controller.crt")


def controller(path):
    request = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + credentials["ADMIN_TOKEN"]})
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        return json.load(response)


overview = controller("/admin/api/overview")
node = next(row for row in overview["nodes"] if row["id"] == "cmp170-node")
if node["observed"]["connectivity"] != "connected":
    raise SystemExit("CMP node is not connected")
if node["desired"]["power_control_mode"] != "dont_touch":
    raise SystemExit("CMP power guard changed")
targets = {row["id"]: row for row in overview["targets"]}
llm = targets["cmp170-node-cmp170-llm"]
raw = targets["cmp170-node-comfy"]
managed = targets["cmp170-video-managed"]
if not llm["enabled"] or not managed["enabled"] or raw["enabled"]:
    raise SystemExit("CMP target policy is incorrect")
if not llm.get("sharing_enabled") or not llm.get("guarded_exploration") or not managed.get("sharing_enabled") or not managed.get("guarded_exploration"):
    raise SystemExit("CMP guarded adaptive sharing is not enabled")
if {llm.get("accelerator_id"), raw.get("accelerator_id"), managed.get("accelerator_id")} != {"cmp170-node-gpu0"}:
    raise SystemExit("CMP targets do not share one physical accelerator lease")
if not llm.get("supports_model_lifecycle") or not llm.get("supports_runtime_profile_switch"):
    raise SystemExit("LLM lifecycle/profile capabilities are absent")
profiles = {(row["id"], row["context_limit"], row["slots"]) for row in llm.get("runtime_profiles", [])}
expected = {("ctx-8k-4", 8192, 4), ("ctx-32k-1", 32768, 1), ("ctx-32k-2", 32768, 2)}
if profiles != expected or len(llm.get("models", [])) < 10:
    raise SystemExit("LLM catalog or profiles are incomplete")
if managed.get("endpoint") != "http://127.0.0.1:9444" or llm.get("endpoint") != "http://127.0.0.1:9445":
    raise SystemExit("controller loopback tunnel routes are incorrect")

plug_rows = controller("/admin/api/smart-plugs").get("smart_plugs", [])
plug = next(row for row in plug_rows if row.get("node_id") == "cmp170-node")
configured_plugs = yaml.safe_load(pathlib.Path("/etc/vram-governor/controller.yaml").read_text())["smart_plugs"]
plug_config = next(row for row in configured_plugs if row.get("node_id") == "cmp170-node")
if "10.0.0.222" not in plug_config.get("url", "") or plug.get("control_enabled") or plug_config.get("control_enabled"):
    raise SystemExit("CMP smart-plug read-only guard is incorrect")

try:
    urllib.request.urlopen("http://127.0.0.1:9444/v1/executions/missing", timeout=5)
    raise SystemExit("managed harness accepted an unauthenticated request")
except urllib.error.HTTPError as error:
    if error.code != 401:
        raise
authorization = environment["VRAM_MANAGED_COMFY_AUTHORIZATION"]
request = urllib.request.Request("http://127.0.0.1:9444/v1/executions/missing", headers={"Authorization": authorization})
try:
    urllib.request.urlopen(request, timeout=5)
    raise SystemExit("missing managed execution unexpectedly exists")
except urllib.error.HTTPError as error:
    if error.code != 404 or json.load(error).get("protocol_version") != "managed-comfy/v1":
        raise
with urllib.request.urlopen("http://127.0.0.1:9445/v1/models", timeout=5) as response:
    if len(json.load(response).get("data", [])) < 10:
        raise SystemExit("tunneled model catalog is incomplete")
with socket.socket() as probe:
    probe.settimeout(1)
    if probe.connect_ex(("10.0.0.60", 8188)) == 0:
        raise SystemExit("raw ComfyUI is exposed on the LAN")

print("cmp_connected=True")
print("shared_accelerator=cmp170-node-gpu0")
print("managed_comfy_enabled=True")
print("raw_comfy_enabled=False")
print("llm_model_count=" + str(len(llm["models"])))
print("runtime_profiles=ctx-8k-4,ctx-32k-1,ctx-32k-2")
print("guarded_adaptive_sharing=True")
print("cmp_power_mode=dont_touch")
print("cmp_plug_control_enabled=False")
print("final_cmp_topology_verified=True")
