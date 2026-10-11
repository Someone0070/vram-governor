#!/usr/bin/env python3
"""Verify the dedicated LB serves the direct runtime-control UI bundle."""

import re
import ssl
import urllib.request

context = ssl.create_default_context(cafile="/etc/vram-governor/tls/controller.crt")


def get(path):
    request = urllib.request.Request("https://10.0.0.115:8443" + path)
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        return response.read().decode()


html = get("/admin/")
match = re.search(r'src="([^"]*admin-[^"]+\.js)"', html)
if not match:
    raise SystemExit("admin asset was not linked")
asset = match.group(1)
javascript = get(asset)
for label in (
    "Runtime controls",
    "Load model",
    "Unload model",
    "switch_runtime_profile",
):
    if label not in javascript:
        raise SystemExit("live bundle is missing " + label)
print("live_models_ui_controls=True")
print("asset=" + asset)
