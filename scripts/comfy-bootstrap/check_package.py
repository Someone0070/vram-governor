#!/usr/bin/env python3
"""Offline structural assertions for the Comfy bootstrap source package."""

import copy
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "configs" / "comfy-bootstrap"
REQUIRED_NODES = {
    "image-sdxl-base.json": {"CheckpointLoaderSimple", "CLIPTextEncode", "EmptyLatentImage", "KSampler", "VAEDecode", "SaveImage"},
    "image-sdxl-smoke.json": {"CheckpointLoaderSimple", "EmptyLatentImage", "KSampler", "SaveImage"},
    "video-wan22-5b.json": {"UNETLoader", "CLIPLoader", "VAELoader", "ModelSamplingSD3", "Wan22ImageToVideoLatent", "KSampler", "CreateVideo", "SaveVideo"},
    "video-wan22-5b-smoke.json": {"UNETLoader", "CLIPLoader", "VAELoader", "ModelSamplingSD3", "Wan22ImageToVideoLatent", "KSampler", "CreateVideo", "SaveVideo"},
}
PROFILE_EXPECTATIONS = {
    "image-sdxl-base": ("image.generate", "IMAGE", "image-sdxl-base.json", "image-sdxl-smoke.json", "sdxl-base-1.0", ["sdxl-base-1.0"], {"application/json", "image/png"}),
    "video-wan22-5b": ("video.generate_sequence", "VIDEO", "video-wan22-5b.json", "video-wan22-5b-smoke.json", "wan22-ti2v-5b", ["wan22-ti2v-5b", "wan22-umt5-xxl-fp8", "wan22-vae"], {"application/json", "video/mp4"}),
}


def read_json(name):
    return json.loads((PACKAGE / name).read_text(encoding="utf-8"))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def validate_graph(graph, required_nodes):
    require(isinstance(graph, dict) and graph, "graph must be a nonempty object")
    for node_id, node in graph.items():
        require(isinstance(node, dict) and isinstance(node.get("class_type"), str), "invalid node " + str(node_id))
        require(isinstance(node.get("inputs"), dict), "node inputs missing: " + str(node_id))
        for value in node["inputs"].values():
            if isinstance(value, list):
                require(len(value) == 2 and str(value[0]) in graph and isinstance(value[1], int), "dangling graph link at node " + str(node_id))
    classes = {node["class_type"] for node in graph.values()}
    require(required_nodes <= classes, "graph missing required nodes: " + ",".join(sorted(required_nodes - classes)))
    if "KSampler" in classes:
        sampler = next(n["inputs"] for n in graph.values() if n["class_type"] == "KSampler")
        require({"seed", "steps", "cfg", "sampler_name", "scheduler", "denoise", "model", "positive", "negative", "latent_image"} <= sampler.keys(), "sampler settings incomplete")
    if "SaveVideo" in classes:
        save = next(n["inputs"] for n in graph.values() if n["class_type"] == "SaveVideo")
        require(save.get("format") == "mp4" and save.get("codec") == "h264", "video output must select mp4/h264")
    return True


def profile_digest(workflow, manifest, model_ids):
    rows = {row["id"]: row for row in manifest["models"]}
    material = {
        "graph_sha256": hashlib.sha256((PACKAGE / workflow).read_bytes()).hexdigest(),
        "models": [
            {key: rows[model_id][key] for key in ("id", "revision", "bytes", "sha256")}
            for model_id in sorted(model_ids)
        ],
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_profiles(profiles, graphs, manifest, metadata):
    require(profiles.get("target_id") == "cmp170-video-managed" and profiles.get("adapter") == "comfy" and profiles.get("runtime_protocol") == "managed_comfy_v1", "profile target binding drift")
    rows = {row.get("profile_id"): row for row in profiles.get("profiles", [])}
    require(set(rows) == set(PROFILE_EXPECTATIONS), "profile ids differ from the declared contract")
    require(metadata.get("schema_version") == 1 and metadata.get("target_id") == profiles["target_id"], "workflow metadata binding drift")
    manifest_rows = {row["id"]: row for row in manifest["models"]}
    require(set(metadata.get("profiles", {})) == {"image-sdxl-base@1", "video-wan22-5b@1"}, "workflow metadata profile ids drift")
    for profile_id, (operation, modality, workflow, smoke, model_id, pinned_ids, artifacts) in PROFILE_EXPECTATIONS.items():
        row = rows[profile_id]
        require(row.get("version") == "1" and row.get("operations") == [operation], "profile version or operation drift: " + profile_id)
        require(row.get("modality") == modality and row.get("execution_locality") == "LB_MANAGED", "profile modality/locality drift: " + profile_id)
        require(row.get("capability_revision") == "1" and row.get("adapter") == "comfy", "profile revision/adapter drift")
        require(row.get("model") == manifest_rows[model_id]["filename"] and row.get("workflow") == workflow, "profile model or graph binding drift: " + profile_id)
        require(row.get("digest") == profile_digest(workflow, manifest, pinned_ids), "profile digest mismatch: " + profile_id)
        require(row.get("accepted_artifact_types") == ["application/json"], "accepted artifact contract drift")
        require(set(row.get("produced_artifact_types", [])) == artifacts, "produced artifact types drift")
        schema = row.get("input_schema", {})
        require(schema.get("type") == "object" and "managed_chunks" in schema.get("required", []), "profile must require a compiled managed_chunks graph")
        chunk = schema.get("properties", {}).get("managed_chunks", {})
        require(chunk.get("type") == "array" and chunk.get("minItems", 0) >= 1, "profile graph schema must require at least one chunk")
        chunk_item = chunk.get("items", {})
        require({"id", "prompt"} <= set(chunk_item.get("required", [])), "profile chunk schema must require id and prompt")
        require(chunk_item.get("properties", {}).get("prompt", {}).get("type") == "object", "profile prompt schema must accept a compiled graph object")
        require(workflow in graphs and smoke in graphs, "profile references missing graph")
        meta = metadata["profiles"][profile_id + "@1"]
        require(meta.get("production_graph") == workflow and meta.get("smoke_graph") == smoke, "workflow graph metadata drift")
        require(meta.get("accepted_payload_types") == ["application/json"], "accepted transport payload types drift")
        require(meta.get("produced_media_types") == sorted(artifacts - {"application/json"}), "produced media metadata drift")
    return True


def validate_manifest(manifest):
    require(manifest.get("schema_version") == 1, "unsupported manifest schema")
    rows = manifest.get("models", [])
    require(len(rows) == 4, "manifest must pin the four required artifacts")
    by_id = {row.get("id"): row for row in rows}
    expected = {
        "sdxl-base-1.0": ("stabilityai", "stable-diffusion-xl-base-1.0", "checkpoints", "sd_xl_base_1.0.safetensors"),
        "wan22-ti2v-5b": ("Comfy-Org", "Wan_2.2_ComfyUI_Repackaged", "diffusion_models", "wan2.2_ti2v_5B_fp16.safetensors"),
        "wan22-umt5-xxl-fp8": ("Comfy-Org", "Wan_2.2_ComfyUI_Repackaged", "text_encoders", "umt5_xxl_fp8_e4m3fn_scaled.safetensors"),
        "wan22-vae": ("Comfy-Org", "Wan_2.2_ComfyUI_Repackaged", "vae", "wan2.2_vae.safetensors"),
    }
    require(set(by_id) == set(expected), "manifest model ids drift")
    for model_id, (publisher, repo, folder, filename) in expected.items():
        row = by_id[model_id]
        require((row.get("publisher"), row.get("repository"), row.get("target_directory"), row.get("filename")) == (publisher, repo, folder, filename), "model binding drift: " + model_id)
        require(len(row.get("revision", "")) in (40, 64), "model revision is not pinned")
        require(len(row.get("sha256", "")) == 64 and all(c in "0123456789abcdef" for c in row["sha256"]), "invalid model SHA256")
        require(isinstance(row.get("bytes"), int) and row["bytes"] > 0, "model byte size missing")
        require(row.get("source_path", "").startswith("split_files/") or model_id == "sdxl-base-1.0", "unexpected publisher path")
    return True


def main():
    graphs = {name: read_json(name) for name in REQUIRED_NODES}
    for name, required in REQUIRED_NODES.items():
        validate_graph(graphs[name], required)
    manifest = read_json("models.json")
    validate_manifest(manifest)
    profiles = read_json("profiles.json")
    validate_profiles(profiles, graphs, manifest, read_json("workflow-metadata.json"))

    # Negative controls ensure link and profile-claim failures are detected.
    broken_graph = copy.deepcopy(graphs["image-sdxl-smoke.json"])
    broken_graph["7"]["inputs"]["images"] = ["missing-node", 0]
    try:
        validate_graph(broken_graph, REQUIRED_NODES["image-sdxl-smoke.json"])
    except AssertionError:
        pass
    else:
        raise AssertionError("negative control: dangling link was accepted")
    broken_profiles = copy.deepcopy(profiles)
    broken_profiles["profiles"][0]["produced_artifact_types"] = ["image/png"]
    try:
        validate_profiles(broken_profiles, graphs, manifest, read_json("workflow-metadata.json"))
    except AssertionError:
        pass
    else:
        raise AssertionError("negative control: incomplete artifact contract was accepted")

    installer = (ROOT / "scripts" / "comfy-bootstrap" / "install_models.py").read_text(encoding="utf-8")
    require("--check" in installer and "--apply" in installer, "installer modes missing")
    require("/opt/ComfyUI/models" in installer and "ALLOWED = {\"checkpoints\", \"diffusion_models\", \"text_encoders\", \"vae\"}" in installer, "installer target boundary drift")
    require("subprocess" not in installer and "os.system" not in installer, "installer must not execute shell commands")
    docs = (PACKAGE / "README.md").read_text(encoding="utf-8")
    for text in ("profile_preferences", "image-sdxl-base@1", "video-wan22-5b@1", "payload.managed_chunks[0].prompt", "VRAM_WORKFLOW_TOKEN", "10.0.0.115:8443", "verified CA"):
        require(text in docs, "client documentation missing " + text)
    examples = re.findall(r"```json\s*(.*?)```", docs, re.DOTALL)
    require(bool(examples), "client documentation has no parseable JSON request example")
    request_example = json.loads(examples[0])
    require(request_example.get("operation") == "image.generate", "Creator example operation mismatch")
    require(request_example.get("profile_preferences", {}).get("preferred") == ["image-sdxl-base@1"] and request_example["profile_preferences"].get("fallback_policy") == "explicit", "Creator example profile selector mismatch")
    chunks = request_example.get("payload", {}).get("managed_chunks", [])
    require(len(chunks) == 1 and chunks[0].get("id") and isinstance(chunks[0].get("prompt"), dict), "Creator example must wrap one compiled graph in managed_chunks")
    print("COMFY_BOOTSTRAP_PACKAGE_VERIFIED")


if __name__ == "__main__":
    main()
