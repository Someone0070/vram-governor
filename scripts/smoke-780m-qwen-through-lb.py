#!/usr/bin/env python3
"""Send a tiny inference request through the LB without printing credentials/content."""

import json
import pathlib
import ssl
import urllib.error
import urllib.request


MODEL = "/root/models/Qwen3.8-9B-Q5_K_M.gguf"
BASE = "https://10.0.0.115:8443"
values = dict(line.split("=", 1) for line in pathlib.Path("/root/vram-governor-controller-credentials.env").read_text().splitlines() if "=" in line)
context = ssl.create_default_context(cafile="/etc/vram-governor/tls/controller.crt")
headers = {"Authorization": "Bearer " + values["INTERACTIVE_UI_TOKEN"]}

request = urllib.request.Request(BASE + "/v1/models", headers=headers)
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    catalogue = json.load(response)
matches = [entry for entry in catalogue.get("data", []) if entry.get("id") == MODEL]
if len(matches) != 1:
    raise SystemExit("Qwen model not in LB catalogue")
print("catalogue_model_present=True")

body = json.dumps({
    "model": MODEL,
    "messages": [{"role": "user", "content": "Reply with OK."}],
    "max_completion_tokens": 4,
    "stream": False,
    "governor": {"context_tokens": 8192},
}).encode()
request = urllib.request.Request(BASE + "/v1/chat/completions", data=body, headers={**headers, "Content-Type": "application/json"}, method="POST")
try:
    with urllib.request.urlopen(request, context=context, timeout=90) as response:
        result = json.load(response)
        status = response.status
except urllib.error.HTTPError as error:
    failure = json.load(error)
    reason = failure.get("error", {})
    if isinstance(reason, dict):
        reason = reason.get("message") or reason.get("type")
    raise SystemExit(f"LB inference HTTP {error.code}: {reason}") from None

if status != 200 or result.get("object") != "chat.completion" or not result.get("choices"):
    raise SystemExit("LB returned an invalid completion envelope")
print("inference_status=200")
print("response_model=" + str(result.get("model")))
print("choices=" + str(len(result["choices"])))
