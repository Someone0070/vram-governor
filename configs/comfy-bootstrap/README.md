# Managed Comfy workflows

These are ComfyUI API prompt graphs. A caller that starts from the Creator Studio operation must compile its prompt into the node graph before submitting it; the managed route does not translate semantic prompts. `video-wan22-5b.json` and `image-sdxl-base.json` are ready-to-submit graph payloads. The `*-smoke.json` variants use deliberately small dimensions, frame counts, and step counts.

The profile descriptors in `profiles.json` use the controller's `RuntimeProfile` fields and bind version 1 of `image-sdxl-base` (`image.generate`) and `video-wan22-5b` (`video.generate_sequence`) to `cmp170-video-managed`. Each immutable profile digest binds its production graph to the pinned model revisions and hashes. `workflow-metadata.json` records smoke graph names and transport media types. The service may also return an `application/json` result manifest; the generated media artifact is PNG or MP4 as listed by each profile.

## Workflows (recommended)

The easiest way in: pick a workflow and pass a few settings. The LB fills them into a tuned graph, so callers never build node graphs.

```sh
GET  /api/v1/workflows              # every workflow with its params, limits and defaults
GET  /api/v1/workflows/{id}         # one workflow ({id}@{version} pins a version)
POST /api/v1/workloads              # {"workflow": "...", "params": {...}}
```

```text
{
  "workload_id": "fox-001",
  "workflow": "image-qwen21-photoreal",
  "params": {"prompt": "candid iPhone photo of ...", "negative_prompt": "plastic skin", "width": 1024, "height": 1344}
}
```

| Workflow | What it is for | Params (* required) | Typical |
| --- | --- | --- | --- |
| `image-krea2-turbo` | Stylized, 3D, clay, cartoon, painterly; `style` adds a look LoRA (realism, snapshot, lenovo) | prompt*, width, height, seed, steps, style, style_strength | ~20 s |
| `image-qwen21-photoreal` | Candid phone-photo realism | prompt*, negative_prompt, width, height, seed, steps, cfg, realism | ~2.5 min |
| `image-qwen21` | General images, text inside the image | prompt*, negative_prompt, width, height, seed, steps, cfg | ~50 s |
| `image-sdxl` | Classic SDXL 1.0 | prompt*, negative_prompt, width, height, seed, steps, cfg | ~25 s |
| `video-ltx25-t2v-fast` | Cheap text-to-video drafts with audio | prompt*, negative_prompt, seconds, aspect_ratio, megapixels, seed, enhance_prompt | ~25 s |
| `video-ltx25-t2v` | Two-stage text-to-video with audio | same as above | ~2.5 min |
| `video-ltx25-i2v` | Animate a 3D/stylized image (LTX) | image*, prompt*, negative_prompt, seconds, aspect_ratio, megapixels, seed, enhance_prompt | ~2.5 min |
| `video-minimax-h3-i2v` | Animate 2D/cartoon art on-model (H3) | image*, prompt*, seconds, seed, turbo | ~3 min |
| `video-minimax-h3-flf` | Motion between a start and end frame | image*, last_image*, prompt*, seconds, seed, turbo | ~3 min |
| `video-seedvr2-upscale` | Restore and upscale a video | video*, scale, seed | ~8.5 min |
| `audio-speak` | Text to speech (Qwen2.5-Omni voices Chelsie, Ethan), MP3 | text*, voice | ~5 s per s of speech |
| `audio-transcribe` | Speech to text from audio or video | audio*, language, context | ~real time |

- `image`, `last_image` and `video` take an artifact id: upload with `POST /upload/image` (the response `name`), or pass the `artifact_ref` of an earlier job's output to chain jobs (e.g. Krea image → H3 video → SeedVR2 upscale).
- The Qwen-Image, LTX-2.5 and MiniMax-H3 workflows also take `precision` (`int8`, the default, or `bf16`; bf16 is much slower on a 10 GB card).
- OpenAI-compatible routes run on these workflows: `POST /v1/images/generations` (`model` = an image workflow, default `image-krea2-turbo`; `size`, `n`, `seed`, `negative_prompt`, plus `params` for anything else), `POST /v1/audio/speech` (`audio-speak`; OpenAI voice names map to Chelsie/Ethan) and `POST /v1/audio/transcriptions` (`audio-transcribe`, multipart `file`).
- Omitted params use the workflow's defaults; `seed` is random when omitted. The response's `workflow.params` echoes every effective value, including the seed, so a result can be reproduced.
- Invalid or unknown params are all reported in one `400` response.
- `operation` and `profile_preferences` are optional; when given they must match the workflow.
- Templates live in `workflows/` and are installed to the directory named by `workloads.workflow_templates_dir` (`/etc/vram-governor/workflows` on the LB). Each binds every param to exact node inputs; `-check-config` rejects a template whose profile or operation is not configured. To add one, copy a template, keep the `id` equal to the file name, and bump `version` for any change to an existing one.

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

## Image to video (input images)

Two profiles take a start image (and optionally an end image) as input. They declare `image/jpeg`, `image/png` and `image/webp` in `accepted_artifact_types` and list their features in discovery (`GET /api/v1/capabilities`):

| Profile | Operations | Graph | Notes |
| --- | --- | --- | --- |
| `video-ltx25-i2v@1` | `video.image_to_video` | `video-ltx25-i2v.json` | LTX-2.5 two-stage (half-res pass, 2x latent upscale, refine) with generated audio; 16:9 at ~0.9 MP by default. Best for 3D and stylized looks. |
| `video-minimax-h3-i2v@1` | `video.image_to_video`, `video.first_last_frame` | `video-minimax-h3-i2v.json`, `video-minimax-h3-flf2v.json` | MiniMax-H3 with audio, 8-step turbo LoRA, 768x448 so it fits a 10 GB card. Holds 2D/cartoon art on-model far better than LTX. |

Flow:

1. Upload each image: `POST /upload/image` (multipart field `image`). The response's `name` is the artifact id.
2. Load the graph, replace `INPUT_IMAGE` (and `INPUT_LAST_IMAGE` for first/last frame) with the artifact ids, and `REPLACE_POSITIVE_PROMPT` with the prompt (JSON-escaped).
3. Submit to `POST /api/v1/workloads` with the operation, `profile_preferences.preferred` set to the profile, the graph in `payload.managed_chunks[0].prompt`, and the artifact ids in top-level `artifact_refs`. The controller copies each referenced artifact into the backend under its artifact id before the graph runs, and the graph's upload inputs (LoadImage) are validated against those ids.

```json
{
  "workload_id": "i2v-001",
  "operation": "video.image_to_video",
  "quality_class": "final",
  "artifact_refs": ["art-..."],
  "profile_preferences": {"preferred": ["video-ltx25-i2v@1"], "fallback_policy": "explicit"},
  "payload": {"managed_chunks": [{"id": "i2v-001", "prompt": {"...": "video-ltx25-i2v.json with placeholders replaced"}}]}
}
```

Both graphs keep the input image at full guide strength (the upstream templates use 0.7, which lets the model drift from the image). Start the prompt with "Use the provided start image as the first frame" and describe motion, camera and sound; for cartoon art, also say the subject keeps the same size and shape.

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
