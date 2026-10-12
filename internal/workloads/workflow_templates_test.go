package workloads

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vram-governor/internal/workflowtpl"
)

// TestRepoWorkflowTemplatesMatchComfySchema compiles every shipped template
// and runs the admission validator against a saved ComfyUI /object_info.
// Set VG_COMFY_OBJECT_INFO to the JSON file (it is large and node-specific,
// so it is not checked in).
func TestRepoWorkflowTemplatesMatchComfySchema(t *testing.T) {
	path := os.Getenv("VG_COMFY_OBJECT_INFO")
	if path == "" {
		t.Skip("VG_COMFY_OBJECT_INFO not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schemas map[string]json.RawMessage
	if err := json.Unmarshal(raw, &schemas); err != nil {
		t.Fatal(err)
	}
	registry, err := workflowtpl.LoadDir(filepath.Join("..", "..", "configs", "comfy-bootstrap", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range registry.All() {
		base := map[string]any{}
		for _, p := range tpl.Params {
			if p.Required {
				base[p.Name] = "art-test-" + p.Name
			}
		}
		// Defaults, then every value of every enum (styles, precisions), so
		// each mapped model or LoRA file is checked against the live schema.
		variants := []map[string]any{base}
		for _, p := range tpl.Params {
			for _, value := range p.Values {
				variant := map[string]any{p.Name: value}
				for k, v := range base {
					variant[k] = v
				}
				variants = append(variants, variant)
			}
		}
		for _, params := range variants {
			compiled, err := tpl.Compile(params)
			if err != nil {
				t.Errorf("%s: %v", tpl.Ref(), err)
				continue
			}
			body, _ := json.Marshal(compiled.Graph)
			var graph map[string]json.RawMessage
			_ = json.Unmarshal(body, &graph)
			uploads := map[string]bool{}
			for _, ref := range compiled.ArtifactRefs {
				uploads[ref] = true
			}
			if err := validateComfyGraphWithUploads(graph, schemas, uploads); err != nil {
				t.Errorf("%s %v: %v", tpl.Ref(), params, err)
			}
		}
	}
}
