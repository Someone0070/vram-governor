"""Speech nodes for ComfyUI backed by Qwen2.5-Omni-3B (local weights).

Transcribe: AUDIO -> STRING. Speak: STRING -> AUDIO (24 kHz). SaveText writes a
STRING to the output folder so the load balancer collects it as an artifact.

The whole model (~10 GB bf16) does not fit a 10 GB card, and speech never
needs the vision tower, so each mode puts only the parts it needs on the GPU
(speak: thinker + talker + token2wav; transcribe: thinker + audio encoder).
ComfyUI's own models are unloaded first, and every part goes back to system
RAM after the node, so the GPU is free for the next workflow.
"""

import gc
import os
import re
import threading

import numpy as np
import torch

import comfy.model_management as mm
import folder_paths

MODEL_DIR = os.environ.get("VG_OMNI_DIR", "/models/qwen2.5-omni-3b")
# Qwen2.5-Omni only produces speech with this exact system prompt.
SYSTEM_PROMPT = ("You are Qwen, a virtual human developed by the Qwen Team, Alibaba Group, capable of "
                 "perceiving auditory and visual inputs, as well as generating text and speech.")
VOICES = ["Chelsie", "Ethan"]
OUTPUT_RATE = 24000
INPUT_RATE = 16000
ASR_WINDOW_SECONDS = 30

_lock = threading.Lock()
_state = {"model": None, "processor": None}


def _load():
    if _state["model"] is None:
        from transformers import Qwen2_5OmniForConditionalGeneration, Qwen2_5OmniProcessor
        model = Qwen2_5OmniForConditionalGeneration.from_pretrained(MODEL_DIR, dtype=torch.bfloat16).eval()
        # generate() routes inputs to the thinker's first parameter, which is
        # the CPU-resident audio/vision encoder; pin it to the compute device.
        type(model.thinker).device = property(lambda self: mm.get_torch_device())
        _state["model"], _state["processor"] = model, Qwen2_5OmniProcessor.from_pretrained(MODEL_DIR)
    return _state["model"], _state["processor"]


def _parts(model, mode):
    shared = [model.thinker.model, model.thinker.lm_head]
    if mode == "speak":
        return shared + [model.talker, model.token2wav]
    return shared + [model.thinker.audio_tower]


def _acquire(mode):
    model, processor = _load()
    mm.unload_all_models()
    mm.soft_empty_cache()
    device = mm.get_torch_device()
    wanted = {id(p) for p in _parts(model, mode)}
    for other in ("speak", "transcribe"):
        for part in _parts(model, other):
            if id(part) not in wanted:
                part.to("cpu")
    for part in _parts(model, mode):
        part.to(device)
    return model, processor


def _release():
    model = _state["model"]
    if model is not None:
        for mode in ("speak", "transcribe"):
            for part in _parts(model, mode):
                part.to("cpu")
    gc.collect()
    mm.soft_empty_cache()


def _run_on_gpu(mode, work):
    """Run work(model, processor) with the parts for mode on the GPU.

    A failure is re-raised only after cleanup, as a new exception: the
    original's traceback pins the failed attempt's GPU tensors, and ComfyUI
    keeps the exception, so ~4 GB stayed allocated after an out-of-memory
    error and no later workflow could get it back (not even via /free).
    """
    failure = None
    with _lock:
        try:
            # Inside the try: an out-of-memory error while moving the parts
            # to the GPU must still move the ones already there back.
            model, processor = _acquire(mode)
            return work(model, processor)
        except Exception as error:  # noqa: BLE001 - re-raised below
            failure = (type(error) if isinstance(error, torch.OutOfMemoryError) else RuntimeError, str(error))
        finally:
            _release()
    raise failure[0](failure[1])


def _conversation(content):
    return [{"role": "system", "content": [{"type": "text", "text": SYSTEM_PROMPT}]},
            {"role": "user", "content": content}]


def _to_device(inputs, device):
    moved = {}
    for key, value in inputs.items():
        if torch.is_tensor(value):
            value = value.to(device)
            if value.dtype == torch.float32:
                value = value.to(torch.bfloat16)
        moved[key] = value
    return moved


def _sentences(text, limit=160):
    """Split text into chunks of whole sentences, each at most ~limit chars."""
    parts = re.split(r"(?<=[.!?;:])\s+", text.strip())
    chunks, current = [], ""
    for part in parts:
        while len(part) > limit:
            cut = part.rfind(" ", 0, limit)
            cut = cut if cut > 0 else limit
            if current:
                chunks.append(current)
                current = ""
            chunks.append(part[:cut].strip())
            part = part[cut:].strip()
        if current and len(current) + 1 + len(part) > limit:
            chunks.append(current)
            current = part
        else:
            current = (current + " " + part).strip()
    if current:
        chunks.append(current)
    return [c for c in chunks if c]


class VGSpeechTranscribe:
    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {"audio": ("AUDIO",)},
                "optional": {"language": ("STRING", {"default": ""}),
                             "context": ("STRING", {"default": "", "multiline": True})}}

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    FUNCTION = "run"
    CATEGORY = "vram-governor/speech"

    def run(self, audio, language="", context=""):
        import torchaudio.functional as AF
        waveform = audio["waveform"][0].float().mean(dim=0)
        if audio["sample_rate"] != INPUT_RATE:
            waveform = AF.resample(waveform, audio["sample_rate"], INPUT_RATE)
        samples = waveform.cpu().numpy().astype(np.float32)
        instruction = "Transcribe the speech exactly as spoken. Output only the transcript, without any commentary."
        if language.strip():
            instruction += " The speech is in " + language.strip() + "."
        if context.strip():
            instruction += " Context that may help with names and terms: " + context.strip()
        window = ASR_WINDOW_SECONDS * INPUT_RATE

        def work(model, processor):
            texts = []
            device = mm.get_torch_device()
            for start in range(0, max(len(samples), 1), window):
                chunk = samples[start:start + window]
                if len(chunk) < INPUT_RATE // 4:
                    continue
                prompt = processor.apply_chat_template(_conversation([{"type": "audio", "audio": chunk}, {"type": "text", "text": instruction}]), add_generation_prompt=True, tokenize=False)
                inputs = _to_device(processor(text=prompt, audio=[chunk], return_tensors="pt", padding=True), device)
                # Bound the text by the audio's length (speech is ~3-4
                # tokens/s) so the chat model cannot run on after it.
                budget = int(len(chunk) / INPUT_RATE * 8) + 24
                with torch.inference_mode():
                    ids = model.generate(**inputs, return_audio=False, thinker_max_new_tokens=budget)
                texts.append(processor.batch_decode(ids[:, inputs["input_ids"].shape[1]:], skip_special_tokens=True)[0].strip())
            return texts

        texts = _run_on_gpu("transcribe", work)
        return (" ".join(t for t in texts if t),)


def _speak_chunk(model, processor, device, chunk, voice):
    prompt = processor.apply_chat_template(_conversation([{"type": "text", "text": "Say exactly the following text and nothing else:\n" + chunk}]), add_generation_prompt=True, tokenize=False)
    inputs = _to_device(processor(text=prompt, return_tensors="pt", padding=True), device)
    # Omni is a chat model and likes to add a closing remark ("If you have
    # any other questions..."); cap the text it speaks at exactly the chunk's
    # length. Only the thinker_* argument reaches the text model.
    budget = len(processor.tokenizer(chunk)["input_ids"])
    try:
        with torch.inference_mode():
            _, audio = model.generate(**inputs, speaker=voice, return_audio=True, thinker_max_new_tokens=budget)
        return [audio.reshape(-1).float().cpu()]
    except torch.OutOfMemoryError as error:
        message = str(error)
    # The vocoder's memory grows with the clip; on a 10 GB card a long chunk
    # can just miss. Retry it as two halves, outside the except block: the
    # exception's traceback pins the failed attempt's GPU tensors.
    del inputs
    gc.collect()
    torch.cuda.empty_cache()
    cut = chunk.rfind(" ", 0, len(chunk) // 2 + 1)
    if cut <= 0 or len(chunk) < 40:
        raise torch.OutOfMemoryError(message)
    return (_speak_chunk(model, processor, device, chunk[:cut].strip(), voice)
            + _speak_chunk(model, processor, device, chunk[cut:].strip(), voice))


class VGSpeechSpeak:
    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {"text": ("STRING", {"multiline": True, "default": ""}),
                             "voice": (VOICES, {"default": "Chelsie"})}}

    RETURN_TYPES = ("AUDIO",)
    FUNCTION = "run"
    CATEGORY = "vram-governor/speech"

    def run(self, text, voice):
        chunks = _sentences(text)
        if not chunks:
            raise ValueError("text is empty")

        def work(model, processor):
            pieces = []
            device = mm.get_torch_device()
            for chunk in chunks:
                pieces.extend(_speak_chunk(model, processor, device, chunk, voice))
                pieces.append(torch.zeros(int(OUTPUT_RATE * 0.15)))
            return pieces

        pieces = _run_on_gpu("speak", work)
        waveform = torch.cat(pieces).clamp(-1, 1).reshape(1, 1, -1)
        return ({"waveform": waveform, "sample_rate": OUTPUT_RATE},)


class VGSaveText:
    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {"text": ("STRING", {"forceInput": True}),
                             "filename_prefix": ("STRING", {"default": "text/ComfyUI"})}}

    RETURN_TYPES = ()
    OUTPUT_NODE = True
    FUNCTION = "run"
    CATEGORY = "vram-governor/speech"

    def run(self, text, filename_prefix):
        output_dir = folder_paths.get_output_directory()
        full_folder, filename, counter, subfolder, _ = folder_paths.get_save_image_path(filename_prefix, output_dir)
        name = f"{filename}_{counter:05}_.txt"
        with open(os.path.join(full_folder, name), "w", encoding="utf-8") as handle:
            handle.write(text)
        return {"ui": {"text_files": [{"filename": name, "subfolder": subfolder, "type": "output"}]}}


NODE_CLASS_MAPPINGS = {
    "VGSpeechTranscribe": VGSpeechTranscribe,
    "VGSpeechSpeak": VGSpeechSpeak,
    "VGSaveText": VGSaveText,
}
NODE_DISPLAY_NAME_MAPPINGS = {
    "VGSpeechTranscribe": "Transcribe speech (Qwen2.5-Omni)",
    "VGSpeechSpeak": "Speak text (Qwen2.5-Omni)",
    "VGSaveText": "Save text",
}
