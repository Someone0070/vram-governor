"""Speech generation and editing with Tencent AuK (local weights, MIT).

One node, VGAuK, covers the three uses the load balancer exposes:

* text to speech from a voice description ("instruct TTS"),
* speaking new text in the voice of a reference recording (zero-shot clone),
* editing a recording with a natural-language instruction (content, pitch,
  speed, volume, enhancement, separation; see AuK's cookbook).

AuK runs a Qwen2.5-Omni-3B text encoder and a 1.5B diffusion transformer.
Upstream keeps the transformer in fp32 and its ComfyUI nodes leave the models
on the GPU until ComfyUI exits; on the 10 GB card both are changed here:

* the transformer is cast to bf16 (it already computes under bf16 autocast),
  and the text encoder's unused lm_head is dropped (only hidden states are
  read), so a run peaks at ~8 GB;
* ComfyUI's own models are unloaded first, AuK's cpu_offload keeps the text
  encoder and transformer in RAM between their passes, and the VAE is parked
  in RAM after every run, so the GPU is free for the next workflow.

A model run is at most 30 s of audio including any reference/source audio;
longer text is spoken sentence by sentence.
"""

import gc
import math
import os
import re
import threading

import torch

import comfy.model_management as mm

AUK_DIR = os.environ.get("VG_AUK_DIR", "/models/auk/AuK")
OMNI_DIR = os.environ.get("VG_OMNI_DIR", "/models/qwen2.5-omni-3b")
MAX_SEQUENCE_SECONDS = 30.0
QWEN_RATE = 16000
CHUNK_SECONDS = 20.0

_lock = threading.Lock()
_state = {"engine": None}


def _engine():
    if _state["engine"] is None:
        from auk.infer.infer_auk import AukInfer
        engine = AukInfer(config_path=os.path.join(AUK_DIR, "config.yaml"), ckpt_path=os.path.join(AUK_DIR, "auk_base.safetensors"),
                          device=str(mm.get_torch_device()), dtype="bf16", qwen_path=OMNI_DIR, cpu_offload=True)
        engine.model.transformer.to(torch.bfloat16)
        engine.model.text_encoder.lm_head = torch.nn.Identity()
        _to_cpu(engine.vae_model)
        _state["engine"] = engine
    return _state["engine"]


def _to_cpu(module):
    """module.to("cpu"), plus plain tensor attributes .to() does not move.

    The VAE's weight-normed convolutions keep the computed weight as a plain
    attribute; .to() leaves those (~450 MB) on the GPU.
    """
    module.to("cpu")
    for sub in module.modules():
        for name, value in list(vars(sub).items()):
            if torch.is_tensor(value) and value.is_cuda:
                setattr(sub, name, value.cpu())


def _release():
    engine = _state["engine"]
    if engine is not None:
        for hook in getattr(engine, "_offload_hooks", ()):
            hook.offload()
        _to_cpu(engine.vae_model)
    gc.collect()
    mm.soft_empty_cache()


def _estimate_seconds(text):
    """Speaking time for text: ~2.7 words/s, ~4.5 CJK characters/s."""
    cjk = len(re.findall(r"[぀-ヿ㐀-鿿가-힯]", text))
    words = len(re.sub(r"[぀-ヿ㐀-鿿가-힯]", " ", text).split())
    return words / 2.7 + cjk / 4.5 + 0.6


def _chunks(text, limit_seconds):
    """Whole sentences grouped so each chunk's estimate fits limit_seconds."""
    parts = [p for p in re.split(r"(?<=[.!?;。！？；])\s*", text.strip()) if p]
    chunks, current = [], ""
    for part in parts:
        candidate = (current + " " + part).strip()
        if current and _estimate_seconds(candidate) > limit_seconds:
            chunks.append(current)
            current = part
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def _mono(audio):
    waveform = audio["waveform"]
    if waveform.ndim != 3 or waveform.shape[0] != 1 or waveform.shape[-1] == 0:
        raise ValueError("audio must be one non-empty clip")
    waveform = waveform[0].detach().to(device="cpu", dtype=torch.float32)
    if not torch.isfinite(waveform).all():
        raise ValueError("audio contains NaN or Inf")
    return waveform.mean(dim=0, keepdim=True).contiguous(), int(audio["sample_rate"])


def _model_audio(mono, target_rate):
    import torchaudio.functional as AF
    waveform, rate = mono
    if rate != target_rate:
        waveform = AF.resample(waveform, rate, target_rate)
    qwen = AF.resample(waveform, target_rate, QWEN_RATE) if target_rate != QWEN_RATE else waveform
    return (waveform.contiguous(), target_rate), qwen.squeeze(0).contiguous().numpy()


def _generate(engine, instruction, source, seconds, seed, steps, cfg):
    model_audio, qwen_audio = _model_audio(source, engine.target_sample_rate) if source is not None else (None, None)
    source_seconds = model_audio[0].shape[-1] / model_audio[1] if model_audio is not None else 0.0
    target = seconds if seconds and seconds > 0 else None
    if target is None and model_audio is None:
        raise ValueError("seconds must be > 0 without input audio")
    if source_seconds + (target or source_seconds) > MAX_SEQUENCE_SECONDS + 0.05:
        raise ValueError("AuK handles at most %.0f s per run (input %.1f s + output %.1f s)" % (MAX_SEQUENCE_SECONDS, source_seconds, target or source_seconds))
    content = [{"type": "text", "text": instruction}]
    if qwen_audio is not None:
        content.append({"type": "audio", "audio": qwen_audio})
    torch.manual_seed(seed)
    waveform, rate = engine.generate([{"role": "user", "content": content}], audio=model_audio, gen_seconds=target,
                                     nfe=steps, cfg_strength=cfg, sway_sampling_coef=-1.0, seed=seed)
    return waveform.detach().to(device="cpu", dtype=torch.float32).reshape(-1), rate


class VGAuK:
    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {"text": ("STRING", {"multiline": True, "default": ""}),
                             "voice_description": ("STRING", {"multiline": True, "default": "A calm adult narrator with a warm, clear voice, speaking at a relaxed pace."}),
                             "style": ("STRING", {"multiline": True, "default": ""}),
                             "instruction": ("STRING", {"multiline": True, "default": ""}),
                             "seconds": ("FLOAT", {"default": 0.0, "min": 0.0, "max": MAX_SEQUENCE_SECONDS, "step": 0.1}),
                             "seed": ("INT", {"default": 0, "min": 0, "max": 0xffffffffffffffff}),
                             "steps": ("INT", {"default": 32, "min": 4, "max": 64}),
                             "cfg": ("FLOAT", {"default": 2.0, "min": 0.0, "max": 10.0, "step": 0.1})},
                "optional": {"audio": ("AUDIO",)}}

    RETURN_TYPES = ("AUDIO",)
    FUNCTION = "run"
    CATEGORY = "vram-governor/speech"
    DESCRIPTION = ("instruction set: edit the input audio as instructed (seconds 0 keeps its length). "
                   "Otherwise speak text: in the input audio's voice when given, else as voice_description "
                   "(style, when set, replaces it). seconds 0 estimates the length; long text is split by sentence.")

    def run(self, text, voice_description, style, instruction, seconds, seed, steps, cfg, audio=None):
        seed %= 2**32  # AuK also seeds numpy, which takes 32-bit seeds
        source = _mono(audio) if audio is not None else None
        instruction, text = instruction.strip(), text.strip()
        if instruction:
            jobs = [(instruction, seconds)]
        else:
            if not text:
                raise ValueError("text is empty")
            reference = source[0].shape[-1] / source[1] if source is not None else 0.0
            budget = min(CHUNK_SECONDS, MAX_SEQUENCE_SECONDS - reference - 1.0)
            if budget < 2.0:
                raise ValueError("reference audio is too long; keep it under %.0f s" % (MAX_SEQUENCE_SECONDS - 3))
            description = (style.strip() or voice_description.strip()).replace('"', "'")
            jobs = []
            for chunk in _chunks(text, budget):
                said = chunk.replace('"', "'")
                if source is not None:
                    prompt = "Say the following with the same voice: '%s'" % said.replace("'", "’")
                else:
                    prompt = 'Based on the following description: "%s", generate speech content "%s".' % (description, said)
                length = seconds if seconds > 0 and len(text) == len(chunk) else min(budget, _estimate_seconds(chunk))
                jobs.append((prompt, length))

        def work():
            engine = _engine()
            engine.vae_model.to(mm.get_torch_device())
            pieces, rate = [], engine.target_sample_rate
            for prompt, length in jobs:
                waveform, rate = _generate(engine, prompt, source, length, seed, steps, cfg)
                pieces += [waveform, torch.zeros(int(rate * 0.2))]
            return torch.cat(pieces[:-1]), rate

        failure = None
        with _lock:
            mm.unload_all_models()
            mm.soft_empty_cache()
            try:
                waveform, rate = work()
            except Exception as error:  # noqa: BLE001 - re-raised after cleanup
                # Re-raised as a new exception after cleanup: the original
                # traceback would pin the failed run's GPU tensors.
                failure = (type(error) if isinstance(error, (torch.OutOfMemoryError, ValueError)) else RuntimeError, str(error))
            finally:
                _release()
        if failure:
            raise failure[0](failure[1])
        if not math.isfinite(float(waveform.abs().max())):
            raise RuntimeError("AuK returned non-finite audio")
        return ({"waveform": waveform.clamp(-1, 1).reshape(1, 1, -1), "sample_rate": rate},)


NODE_CLASS_MAPPINGS = {"VGAuK": VGAuK}
NODE_DISPLAY_NAME_MAPPINGS = {"VGAuK": "AuK speech (generate / clone / edit)"}
