package workflowtpl

import (
	"path/filepath"
	"testing"
)

// Every shipped template must load, validate and compile with its defaults.
func TestRepoWorkflowTemplatesLoadAndCompile(t *testing.T) {
	registry, err := LoadDir(filepath.Join("..", "..", "configs", "comfy-bootstrap", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	all := registry.All()
	if len(all) < 10 {
		t.Fatalf("loaded %d templates", len(all))
	}
	for _, tpl := range all {
		params := map[string]any{}
		for _, p := range tpl.Params {
			if !p.Required {
				continue
			}
			switch p.Type {
			case TypeImage, TypeVideo:
				params[p.Name] = "art-test-" + p.Name
			default:
				params[p.Name] = "a test prompt"
			}
		}
		if _, err := tpl.Compile(params); err != nil {
			t.Errorf("%s: %v", tpl.Ref(), err)
		}
	}
}
