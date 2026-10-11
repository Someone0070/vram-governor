# Managed Comfy workflows

These are ComfyUI API prompt graphs. A caller that starts from the Creator Studio operation must compile its prompt into the node graph before submitting it; the managed route does not translate semantic prompts. `video-wan22-5b.json` and `image-sdxl-base.json` are ready-to-submit graph payloads. The `*-smoke.json` variants use deliberately small dimensions, frame counts, and step counts.

The profile descriptors in `profiles.json` use the controller's `RuntimeProfile` fields and bind version 1 of `image-sdxl-base` (`image.generate`) and `video-wan22-5b` (`video.generate_sequence`) to `cmp170-video-managed`. Each immutable profile digest binds its production graph to the pinned model revisions and hashes. `workflow-metadata.json` records smoke graph names and transport media types. The service may also return an `application/json` result manifest; the generated media artifact is PNG or MP4 as listed by each profile.

## Submitting a compiled graph

For the Creator Studio workload API, select the immutable profile version through `profile_preferences.preferred` as `profile-id@version`, and put the compiled Comfy prompt graph in `payload.managed_chunks[0].prompt`. The workflow graph is the JSON object keyed by node id, in the native Comfy API format:

```json
{
  "workload_id": "image-smoke-001",
  "operation": "image.generate",
  "quality_class": "final",
  "profile_preferences": {
    "preferred": ["image-sdxl-base@1"],
    "fallback_policy": "explicit"
  },
  "payload": {
    "managed_chunks": [{
      "id": "image-smoke-001",
      "prompt": {
        "1": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": "sd_xl_base_1.0.safetensors"}}
      }
    }]
  }
}
```

The snippet shows the envelope shape only; use the complete graph from the matching JSON file. The LB-compatible `POST /prompt` surface also accepts a `managed_chunks` array whose chunk has an id and a `prompt` containing the graph, for example `{"client_id":"client-name","managed_chunks":[{"id":"image-smoke-001","prompt":<graph>}]}`. The `managed_chunks` wrapper belongs to the LB API. A direct request to a Comfy backend's native `/prompt` endpoint instead uses Comfy's `{"client_id":"...","prompt":<graph>}` format. Neither submission path accepts a natural-language prompt in place of graph nodes.

For video, use `operation: "video.generate_sequence"` and set `profile_preferences.preferred` to `["video-wan22-5b@1"]`; load `video-wan22-5b.json` or its smoke variant into `payload.managed_chunks[0].prompt`.

## Authentication and TLS

Use the public LB endpoint `https://10.0.0.115:8443`, a caller-provided bearer token from the secret store, and the deployment's verified CA certificate. Set the token in an environment variable such as `VRAM_WORKFLOW_TOKEN`; never paste it into source, command history, or logs. Keep certificate verification enabled and configure the client trust store with the CA file. Do not use `verify=False` or disable hostname/certificate checks. The managed Comfy harness has its own service credential and is not a client credential.

Example request setup in Python (the request body should contain the full selected graph):

```python
import json
import os
import ssl
import urllib.request

endpoint = "https://10.0.0.115:8443/api/v1/workloads"
token = os.environ["VRAM_WORKFLOW_TOKEN"]
with open("configs/comfy-bootstrap/image-sdxl-smoke.json", encoding="utf-8") as stream:
    graph = json.load(stream)
body = {
    "workload_id": "image-smoke-001",
    "operation": "image.generate",
    "quality_class": "final",
    "profile_preferences": {
        "preferred": ["image-sdxl-base@1"],
        "fallback_policy": "explicit",
    },
    "payload": {
        "managed_chunks": [{"id": "image-smoke-001", "prompt": graph}],
    },
}
request = urllib.request.Request(
    endpoint,
    data=json.dumps(body).encode("utf-8"),
    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    method="POST",
)
context = ssl.create_default_context(cafile=os.environ["VRAM_CA_FILE"])
with urllib.request.urlopen(request, context=context, timeout=30) as response:
    result = json.load(response)
```

The LB API envelope can evolve independently of Comfy's graph schema. Selectors are explicit so queued work remains associated with the intended immutable profile version.
