package workloads

import (
	"encoding/json"
	"testing"

	"vram-governor/internal/domain"
)

// Schemas copied from ComfyUI v0.39 /object_info (trimmed to the inputs used).
var comfyV3Schemas = map[string]json.RawMessage{
	"LoadImage":           json.RawMessage(`{"input":{"required":{"image":[["existing.png"],{"image_upload":true}]}},"output":["IMAGE","MASK"]}`),
	"PrimitiveInt":        json.RawMessage(`{"input":{"required":{"value":["INT",{"min":0,"max":100}]}},"output":["INT"]}`),
	"ComfyMathExpression": json.RawMessage(`{"input":{"required":{"expression":["STRING",{"multiline":true}],"values":["COMFY_AUTOGROW_V3",{"template":{"input":{"required":{"value":["FLOAT,INT,BOOLEAN",{}]}},"names":["a","b","c"],"min":1}}]}},"output":["FLOAT","INT","BOOLEAN"]}`),
	"PrefixGrow":          json.RawMessage(`{"input":{"optional":{"images":["COMFY_AUTOGROW_V3",{"template":{"input":{"optional":{"image":["IMAGE",{}]}},"prefix":"image_","min":0,"max":3}}]}},"output":["IMAGE"]}`),
	"ComfySwitchNode":     json.RawMessage(`{"input":{"required":{"switch":["BOOLEAN",{}]},"optional":{"on_false":["COMFY_MATCHTYPE_V3",{"lazy":true,"template":{"template_id":"switch","allowed_types":"*"}}],"on_true":["COMFY_MATCHTYPE_V3",{"lazy":true,"template":{"template_id":"switch","allowed_types":"*"}}]}},"output":["COMFY_MATCHTYPE_V3"]}`),
	"ResizeImageMaskNode": json.RawMessage(`{"input":{"required":{"input":["COMFY_MATCHTYPE_V3",{"template":{"template_id":"input_type","allowed_types":"IMAGE,MASK"}}],"resize_type":["COMFY_DYNAMICCOMBO_V3",{"options":[{"key":"scale by multiplier","inputs":{"required":{"multiplier":["FLOAT",{"min":0.01,"max":8}]}}},{"key":"scale longer dimension","inputs":{"required":{"longer_size":["INT",{"min":1,"max":16384}]}}}]}],"scale_method":[["lanczos","area"],{}]}},"output":["COMFY_MATCHTYPE_V3"]}`),
	"PreviewImage":        json.RawMessage(`{"input":{"required":{"images":["IMAGE",{}]}},"output":[]}`),
}

func validateV3(t *testing.T, graph string, uploads map[string]bool) error {
	t.Helper()
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(graph), &parsed); err != nil {
		t.Fatal(err)
	}
	return validateComfyGraphWithUploads(parsed, comfyV3Schemas, uploads)
}

func TestComfyAutogrowInputs(t *testing.T) {
	for _, tc := range []struct {
		name, graph string
		ok          bool
	}{
		{"dotted children", `{"1":{"class_type":"PrimitiveInt","inputs":{"value":3}},"2":{"class_type":"ComfyMathExpression","inputs":{"expression":"a*2","values.a":["1",0],"values.b":4}}}`, true},
		{"min child missing", `{"2":{"class_type":"ComfyMathExpression","inputs":{"expression":"b","values.b":4}}}`, false},
		{"unknown child name", `{"2":{"class_type":"ComfyMathExpression","inputs":{"expression":"a","values.a":1,"values.zz":2}}}`, false},
		{"parent key is not an input", `{"2":{"class_type":"ComfyMathExpression","inputs":{"expression":"a","values":1}}}`, false},
		{"child literal type checked", `{"2":{"class_type":"ComfyMathExpression","inputs":{"expression":"a","values.a":"text"}}}`, false},
		{"prefix template optional and empty", `{"1":{"class_type":"PrefixGrow","inputs":{}}}`, true},
		{"prefix template child", `{"0":{"class_type":"LoadImage","inputs":{"image":"existing.png"}},"1":{"class_type":"PrefixGrow","inputs":{"images.image_0":["0",0]}}}`, true},
		{"prefix beyond max", `{"0":{"class_type":"LoadImage","inputs":{"image":"existing.png"}},"1":{"class_type":"PrefixGrow","inputs":{"images.image_3":["0",0]}}}`, false},
	} {
		if err := validateV3(t, tc.graph, nil); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v want ok=%t", tc.name, err, tc.ok)
		}
	}
}

func TestComfyMatchTypeAndDottedDynamicInputs(t *testing.T) {
	for _, tc := range []struct {
		name, graph string
		ok          bool
	}{
		{"switch passes any type through", `{"0":{"class_type":"LoadImage","inputs":{"image":"existing.png"}},"1":{"class_type":"ComfySwitchNode","inputs":{"switch":false,"on_false":["0",0],"on_true":["0",0]}},"2":{"class_type":"PreviewImage","inputs":{"images":["1",0]}}}`, true},
		{"allowed_types enforced", `{"0":{"class_type":"PrimitiveInt","inputs":{"value":1}},"1":{"class_type":"ResizeImageMaskNode","inputs":{"input":["0",0],"resize_type":"scale by multiplier","resize_type.multiplier":2,"scale_method":"lanczos"}}}`, false},
		{"dotted dynamic child", `{"0":{"class_type":"LoadImage","inputs":{"image":"existing.png"}},"1":{"class_type":"ResizeImageMaskNode","inputs":{"input":["0",0],"resize_type":"scale longer dimension","resize_type.longer_size":1536,"scale_method":"lanczos"}}}`, true},
		{"bare dynamic child still accepted", `{"0":{"class_type":"LoadImage","inputs":{"image":"existing.png"}},"1":{"class_type":"ResizeImageMaskNode","inputs":{"input":["0",0],"resize_type":"scale by multiplier","multiplier":2,"scale_method":"lanczos"}}}`, true},
		{"dynamic child of unselected option", `{"0":{"class_type":"LoadImage","inputs":{"image":"existing.png"}},"1":{"class_type":"ResizeImageMaskNode","inputs":{"input":["0",0],"resize_type":"scale by multiplier","resize_type.multiplier":2,"resize_type.longer_size":5,"scale_method":"lanczos"}}}`, false},
		{"selected dynamic child missing", `{"0":{"class_type":"LoadImage","inputs":{"image":"existing.png"}},"1":{"class_type":"ResizeImageMaskNode","inputs":{"input":["0",0],"resize_type":"scale longer dimension","scale_method":"lanczos"}}}`, false},
	} {
		if err := validateV3(t, tc.graph, nil); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v want ok=%t", tc.name, err, tc.ok)
		}
	}
}

func TestComfyUploadInputAcceptsOwnArtifactsOnly(t *testing.T) {
	graph := `{"0":{"class_type":"LoadImage","inputs":{"image":"art-0123"}},"1":{"class_type":"PreviewImage","inputs":{"images":["0",0]}}}`
	if err := validateV3(t, graph, map[string]bool{"art-0123": true}); err != nil {
		t.Fatalf("request's own artifact rejected: %v", err)
	}
	if err := validateV3(t, graph, nil); err == nil {
		t.Fatal("an artifact the request did not reference was accepted")
	}
	if err := validateV3(t, graph, map[string]bool{"art-other": true}); err == nil {
		t.Fatal("a different request's artifact was accepted")
	}
	// Non-upload inputs never take artifact names.
	prim := `{"0":{"class_type":"ResizeImageMaskNode","inputs":{"input":["1",0],"resize_type":"scale by multiplier","resize_type.multiplier":2,"scale_method":"art-0123"}},"1":{"class_type":"LoadImage","inputs":{"image":"existing.png"}}}`
	if err := validateV3(t, prim, map[string]bool{"art-0123": true}); err == nil {
		t.Fatal("artifact name accepted on a non-upload combo")
	}
	req := domain.WorkloadRequest{ArtifactRefs: []string{"art-0123"}, Payload: json.RawMessage(`{"managed_chunks":[{"id":"c","prompt":` + graph + `}]}`)}
	if err := validateComfyRequestSchema(req, comfyV3Schemas); err != nil {
		t.Fatalf("request-level validation ignored artifact_refs: %v", err)
	}
}
