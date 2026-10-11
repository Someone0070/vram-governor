#!/usr/bin/env python3
"""Write a deterministic, synthetic one-layer F32 LLAMA GGUF fixture."""

import json
import pathlib
import struct
import sys


ALIGNMENT = 32
ARCH = "llama"
N_EMBD = 256
N_FF = 512
CONTEXT = 1024
TOKENS = ["<unk>", "<s>", "</s>", "a", "b", "c", " ", "ab"]


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def string(value):
    encoded = value.encode("utf-8")
    return u64(len(encoded)) + encoded


def metadata(key, kind, payload):
    return string(key) + u32(kind) + payload


def scalar(key, kind, value, fmt):
    return metadata(key, kind, struct.pack("<" + fmt, value))


def array(key, element_kind, values, encode):
    return metadata(key, 9, u32(element_kind) + u64(len(values)) + b"".join(encode(v) for v in values))


def f32(value):
    return struct.pack("<f", value)


def tensor_values(name, count):
    if name.endswith("norm.weight") or name == "output_norm.weight":
        return [1.0] * count
    # A deterministic, small, nonzero pattern exercises real tensor loading.
    return [(((i * 13 + len(name)) % 29) - 14) / 1024.0 for i in range(count)]


def align(buffer):
    buffer.extend(b"\0" * ((-len(buffer)) % ALIGNMENT))


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: make-tiny-llama-gguf.py OUTPUT.gguf METADATA.json")
    output = pathlib.Path(sys.argv[1])
    metadata_output = pathlib.Path(sys.argv[2])
    if output.resolve() == metadata_output.resolve():
        raise SystemExit("output paths must be distinct")

    meta = [
        metadata("general.architecture", 8, string(ARCH)),
        metadata("general.name", 8, string("checkpoint-compat-synthetic-llama")),
        scalar("general.file_type", 4, 0, "I"),
        scalar("llama.context_length", 4, CONTEXT, "I"),
        scalar("llama.embedding_length", 4, N_EMBD, "I"),
        scalar("llama.block_count", 4, 1, "I"),
        scalar("llama.feed_forward_length", 4, N_FF, "I"),
        scalar("llama.attention.head_count", 4, 4, "I"),
        scalar("llama.attention.head_count_kv", 4, 4, "I"),
        scalar("llama.attention.layer_norm_rms_epsilon", 6, 1.0e-5, "f"),
        scalar("llama.rope.freq_base", 6, 10000.0, "f"),
        metadata("tokenizer.ggml.model", 8, string("llama")),
        array("tokenizer.ggml.tokens", 8, TOKENS, string),
        array("tokenizer.ggml.scores", 6, [0.0] * len(TOKENS), f32),
        array("tokenizer.ggml.token_type", 5, [2, 3, 3, 1, 1, 1, 1, 1], lambda n: struct.pack("<i", n)),
        scalar("tokenizer.ggml.bos_token_id", 4, 1, "I"),
        scalar("tokenizer.ggml.eos_token_id", 4, 2, "I"),
        scalar("tokenizer.ggml.unknown_token_id", 4, 0, "I"),
        scalar("tokenizer.ggml.add_bos_token", 7, 1, "B"),
        scalar("tokenizer.ggml.add_eos_token", 7, 0, "B"),
    ]

    tensors = [
        ("token_embd.weight", [N_EMBD, len(TOKENS)]),
        ("output_norm.weight", [N_EMBD]),
        ("blk.0.attn_norm.weight", [N_EMBD]),
        ("blk.0.attn_q.weight", [N_EMBD, N_EMBD]),
        ("blk.0.attn_k.weight", [N_EMBD, N_EMBD]),
        ("blk.0.attn_v.weight", [N_EMBD, N_EMBD]),
        ("blk.0.attn_output.weight", [N_EMBD, N_EMBD]),
        ("blk.0.ffn_norm.weight", [N_EMBD]),
        ("blk.0.ffn_gate.weight", [N_EMBD, N_FF]),
        ("blk.0.ffn_down.weight", [N_FF, N_EMBD]),
        ("blk.0.ffn_up.weight", [N_EMBD, N_FF]),
        ("output.weight", [N_EMBD, len(TOKENS)]),
    ]

    infos = bytearray()
    chunks = []
    offset = 0
    tensor_meta = []
    for name, shape in tensors:
        count = 1
        for dimension in shape:
            count *= dimension
        values = tensor_values(name, count)
        payload = b"".join(f32(value) for value in values)
        offset = (offset + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT
        infos.extend(string(name) + u32(len(shape)))
        infos.extend(b"".join(u64(dimension) for dimension in shape))
        infos.extend(u32(0))  # GGML_TYPE_F32
        infos.extend(u64(offset))
        chunks.append((offset, payload))
        tensor_meta.append({"name": name, "shape": shape, "type": "F32", "offset": offset, "bytes": len(payload)})
        offset += len(payload)

    header = bytearray(b"GGUF" + u32(3) + u64(len(tensors)) + u64(len(meta)))
    header.extend(b"".join(meta))
    header.extend(infos)
    align(header)
    data = bytearray(header)
    data_start = len(data)
    for tensor_offset, payload in chunks:
        target = data_start + tensor_offset
        if len(data) > target:
            raise SystemExit("internal tensor offset overlap")
        data.extend(b"\0" * (target - len(data)))
        data.extend(payload)

    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    expected = {
        "format": "GGUF v3",
        "architecture": ARCH,
        "contextLength": CONTEXT,
        "ropeFrequencyBase": 10000.0,
        "ropeScalingType": "linear",
        "yarnExtFactor": 0.0,
        "yarnAttnFactor": 1.0,
        "yarnBetaFast": 32.0,
        "yarnBetaSlow": 1.0,
        "embeddingLength": N_EMBD,
        "feedForwardLength": N_FF,
        "heads": 4,
        "kvHeads": 4,
        "headDimension": N_EMBD // 4,
        "layers": 1,
        "vTransposed": True,
        "defaultCacheTypeK": "f16",
        "defaultCacheTypeV": "f16",
        "vocabularySize": len(TOKENS),
        "alignment": ALIGNMENT,
        "tensorCount": len(tensors),
        "fileBytes": len(data),
        "tensors": tensor_meta,
    }
    metadata_output.write_text(json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
