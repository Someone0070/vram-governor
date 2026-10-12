package workflowtpl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `{
  "id": "image-test", "version": 1, "title": "Test image", "operation": "image.generate", "profile": "image-test@1",
  "params": [
    {"name": "prompt", "type": "string", "required": true, "max_length": 50, "bind": [{"node": "4", "input": "prompt", "format": "l3n0v0, {value}"}]},
    {"name": "negative_prompt", "type": "string", "default": "blurry", "bind": [{"node": "4", "input": "negative_prompt"}]},
    {"name": "width", "type": "integer", "default": 1024, "min": 512, "max": 2048, "multiple_of": 16, "bind": [{"node": "7", "input": "width"}]},
    {"name": "cfg", "type": "number", "default": 3, "min": 1, "max": 10, "bind": [{"node": "8", "input": "cfg"}]},
    {"name": "seed", "type": "seed", "bind": [{"node": "8", "input": "seed"}, {"node": "9", "input": "seed"}]},
    {"name": "sampler", "type": "enum", "default": "res_2s", "values": ["res_2s", "euler"], "bind": [{"node": "8", "input": "sampler_name"}]},
    {"name": "image", "type": "image", "required": true, "bind": [{"node": "1", "input": "image"}]}
  ],
  "graph": {
    "1": {"class_type": "LoadImage", "inputs": {"image": "INPUT_IMAGE"}},
    "4": {"class_type": "TextEncodeQwenImage21", "inputs": {"prompt": "", "negative_prompt": "", "clip": ["3", 0]}},
    "7": {"class_type": "EmptyLatentImage", "inputs": {"width": 1024, "height": 1024, "batch_size": 1}},
    "8": {"class_type": "KSampler", "inputs": {"seed": 1, "cfg": 3.0, "sampler_name": "euler", "model": ["2", 0]}},
    "9": {"class_type": "FaceDetailer", "inputs": {"seed": 1}}
  }
}`

func load(t *testing.T, body string) *Template {
	t.Helper()
	tpl := &Template{}
	if err := json.Unmarshal([]byte(body), tpl); err != nil {
		t.Fatal(err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	return tpl
}

func inputs(c *Compiled, node string) map[string]any {
	return c.Graph[node].(map[string]any)["inputs"].(map[string]any)
}

func TestCompileFillsParamsDefaultsAndSeed(t *testing.T) {
	tpl := load(t, sample)
	c, err := tpl.Compile(map[string]any{"prompt": "a cat", "width": float64(1280), "image": "artifact://art-1", "seed": float64(42)})
	if err != nil {
		t.Fatal(err)
	}
	if got := inputs(c, "4")["prompt"]; got != "l3n0v0, a cat" {
		t.Fatalf("prompt = %v", got)
	}
	if got := inputs(c, "4")["negative_prompt"]; got != "blurry" {
		t.Fatalf("default negative = %v", got)
	}
	if inputs(c, "7")["width"] != int64(1280) || inputs(c, "7")["height"] != float64(1024) {
		t.Fatalf("size = %v", inputs(c, "7"))
	}
	if inputs(c, "8")["seed"] != int64(42) || inputs(c, "9")["seed"] != int64(42) {
		t.Fatal("seed not written to every binding")
	}
	if inputs(c, "8")["sampler_name"] != "res_2s" || inputs(c, "8")["cfg"] != float64(3) {
		t.Fatalf("sampler inputs = %v", inputs(c, "8"))
	}
	if len(c.ArtifactRefs) != 1 || c.ArtifactRefs[0] != "art-1" || inputs(c, "1")["image"] != "art-1" {
		t.Fatalf("artifact refs = %v image=%v", c.ArtifactRefs, inputs(c, "1")["image"])
	}
	if _, linked := inputs(c, "8")["model"].([]any); !linked {
		t.Fatal("links must survive compilation")
	}
	// The template's own graph is untouched.
	again, _ := tpl.Compile(map[string]any{"prompt": "b", "image": "art-2"})
	if inputs(again, "7")["width"] != int64(1024) {
		t.Fatal("compilation mutated the template graph")
	}
	if s, ok := again.Params["seed"].(int64); !ok || s < 0 || s > maxSeed {
		t.Fatalf("random seed = %v", again.Params["seed"])
	}
}

func TestCompileReportsEveryProblem(t *testing.T) {
	tpl := load(t, sample)
	_, err := tpl.Compile(map[string]any{
		"width": float64(1000), "cfg": float64(11), "sampler": "dpm", "seed": float64(-1),
		"prompt": strings.Repeat("x", 51), "image": "../etc/passwd", "steps": float64(4),
	})
	var pe *ParamError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	for _, name := range []string{"width", "cfg", "sampler", "seed", "prompt", "image", "steps"} {
		if pe.Problems[name] == "" {
			t.Errorf("no problem reported for %s: %v", name, pe.Problems)
		}
	}
	_, err = tpl.Compile(map[string]any{})
	if !errors.As(err, &pe) || pe.Problems["prompt"] != "is required" || pe.Problems["image"] != "is required" {
		t.Fatalf("missing required: %v", err)
	}
	if _, err := tpl.Compile(map[string]any{"prompt": "  ", "image": "a"}); err == nil {
		t.Fatal("blank required prompt accepted")
	}
	if _, err := tpl.Compile(map[string]any{"prompt": "a", "image": "a", "width": 1024.5}); err == nil {
		t.Fatal("fractional integer accepted")
	}
}

func TestValidateRejectsBrokenTemplates(t *testing.T) {
	cases := map[string]func(string) string{
		"missing node": func(s string) string {
			return strings.Replace(s, `{"node": "7", "input": "width"}`, `{"node": "70", "input": "width"}`, 1)
		},
		"missing input": func(s string) string { return strings.Replace(s, `"input": "sampler_name"`, `"input": "sampler"`, 1) },
		"linked input":  func(s string) string { return strings.Replace(s, `"input": "sampler_name"`, `"input": "model"`, 1) },
		"bad default":   func(s string) string { return strings.Replace(s, `"default": 1024`, `"default": 1000`, 1) },
		"double binding": func(s string) string {
			return strings.Replace(s, `{"node": "9", "input": "seed"}`, `{"node": "8", "input": "cfg"}`, 1)
		},
		"no default": func(s string) string { return strings.Replace(s, `"default": "blurry", `, ``, 1) },
		"format on int": func(s string) string {
			return strings.Replace(s, `"input": "width"}`, `"input": "width", "format": "{value}px"}`, 1)
		},
		"no profile": func(s string) string {
			return strings.Replace(s, `"profile": "image-test@1"`, `"profile": "image-test"`, 1)
		},
	}
	for name, mutate := range cases {
		tpl := &Template{}
		if err := json.Unmarshal([]byte(mutate(sample)), tpl); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := tpl.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRegistryResolvesLatestAndExactVersions(t *testing.T) {
	dir := t.TempDir()
	v2 := strings.Replace(strings.Replace(sample, `"version": 1`, `"version": 2`, 1), `"title": "Test image"`, `"title": "Test image v2"`, 1)
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(sample), 0o644)
	os.WriteFile(filepath.Join(dir, "b.json"), []byte(v2), 0o644)
	r, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tpl, _ := r.Get("image-test"); tpl.Version != 2 {
		t.Fatalf("bare id resolved to v%d", tpl.Version)
	}
	if tpl, _ := r.Get("image-test@1"); tpl == nil || tpl.Version != 1 {
		t.Fatal("exact version not resolved")
	}
	if _, err := r.Get("nope"); !errors.Is(err, ErrUnknownWorkflow) {
		t.Fatalf("err = %v", err)
	}
	if len(r.All()) != 2 {
		t.Fatal("All")
	}
	os.WriteFile(filepath.Join(dir, "c.json"), []byte(sample), 0o644)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("duplicate version accepted")
	}
	os.Remove(filepath.Join(dir, "c.json"))
	os.WriteFile(filepath.Join(dir, "d.json"), []byte(strings.Replace(sample, `"title"`, `"titel"`, 1)), 0o644)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("unknown template field accepted")
	}
}

const styleTemplate = `{
  "id": "image-style", "version": 1, "title": "Style", "operation": "image.generate", "profile": "image-test@1",
  "params": [
    {"name": "prompt", "type": "string", "required": true, "bind": [{"node": "13", "input": "text", "format": "{tokens:style}{value}"}]},
    {"name": "style", "type": "enum", "default": "none", "values": ["none", "realism", "snapshot"],
     "tokens": {"realism": "r3alism, "},
     "bypass": [{"node": "20", "when": ["none"], "outputs": {"0": "model"}}],
     "bind": [{"node": "20", "input": "lora_name", "map": {"realism": "Krea2-realism-V2.safetensors", "snapshot": "RealisticSnapshotKrea2V2.safetensors"}}]},
    {"name": "style_strength", "type": "number", "default": 0.8, "min": 0, "max": 1.5, "bind": [{"node": "20", "input": "strength_model"}]},
    {"name": "precision", "type": "enum", "default": "int8", "values": ["int8", "bf16"], "bind": [{"node": "11", "input": "unet_name", "map": {"int8": "krea2_turbo_int8_convrot.safetensors", "bf16": "krea2_bf16.safetensors"}}]}
  ],
  "graph": {
    "11": {"class_type": "UNETLoader", "inputs": {"unet_name": "krea2_turbo_int8_convrot.safetensors", "weight_dtype": "default"}},
    "20": {"class_type": "LoraLoaderModelOnly", "inputs": {"model": ["11", 0], "lora_name": "Krea2-realism-V2.safetensors", "strength_model": 0.8}},
    "13": {"class_type": "CLIPTextEncode", "inputs": {"text": ""}},
    "17": {"class_type": "KSampler", "inputs": {"model": ["20", 0], "seed": 1}}
  }
}`

func TestEnumMapsBypassAndTokens(t *testing.T) {
	tpl := load(t, styleTemplate)
	plain, err := tpl.Compile(map[string]any{"prompt": "a fox"})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := plain.Graph["20"]; present {
		t.Fatal("style none must remove the LoRA node")
	}
	if link := inputs(plain, "17")["model"].([]any); link[0] != "11" || link[1] != float64(0) {
		t.Fatalf("sampler not rewired to the UNET: %v", link)
	}
	if inputs(plain, "13")["text"] != "a fox" || inputs(plain, "11")["unet_name"] != "krea2_turbo_int8_convrot.safetensors" {
		t.Fatalf("defaults wrote %v / %v", inputs(plain, "13")["text"], inputs(plain, "11")["unet_name"])
	}
	styled, err := tpl.Compile(map[string]any{"prompt": "a fox", "style": "realism", "style_strength": 1.1, "precision": "bf16"})
	if err != nil {
		t.Fatal(err)
	}
	lora := inputs(styled, "20")
	if lora["lora_name"] != "Krea2-realism-V2.safetensors" || lora["strength_model"] != 1.1 {
		t.Fatalf("lora inputs = %v", lora)
	}
	if inputs(styled, "13")["text"] != "r3alism, a fox" || inputs(styled, "11")["unet_name"] != "krea2_bf16.safetensors" {
		t.Fatalf("tokens/map not applied: %v / %v", inputs(styled, "13")["text"], inputs(styled, "11")["unet_name"])
	}
	if link := inputs(styled, "17")["model"].([]any); link[0] != "20" {
		t.Fatalf("styled sampler must use the LoRA: %v", link)
	}
	snapshot, _ := tpl.Compile(map[string]any{"prompt": "a fox", "style": "snapshot"})
	if inputs(snapshot, "13")["text"] != "a fox" || inputs(snapshot, "20")["lora_name"] != "RealisticSnapshotKrea2V2.safetensors" {
		t.Fatal("a style without tokens must leave the prompt unchanged")
	}
	if _, err := tpl.Compile(map[string]any{"prompt": "a fox", "style": "anime"}); err == nil {
		t.Fatal("unknown style accepted")
	}
}

func TestValidateRejectsBrokenMapsBypassAndTokens(t *testing.T) {
	cases := map[string]func(string) string{
		"map misses a value":   func(s string) string { return strings.Replace(s, `"snapshot": "RealisticSnapshotKrea2V2.safetensors"`, `"other": "x"`, 1) },
		"bypass unknown value": func(s string) string { return strings.Replace(s, `"when": ["none"]`, `"when": ["off"]`, 1) },
		"bypass non-link":      func(s string) string { return strings.Replace(s, `"outputs": {"0": "model"}`, `"outputs": {"0": "lora_name"}`, 1) },
		"unknown token param":  func(s string) string { return strings.Replace(s, `{tokens:style}`, `{tokens:mood}`, 1) },
		"map on a number":      func(s string) string { return strings.Replace(s, `"input": "strength_model"}`, `"input": "strength_model", "map": {"a": 1}}`, 1) },
	}
	for name, mutate := range cases {
		tpl := &Template{}
		if err := json.Unmarshal([]byte(mutate(styleTemplate)), tpl); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := tpl.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
