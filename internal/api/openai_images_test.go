package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"vram-governor/internal/workflowtpl"
)

func TestOpenAIImageParamsMapping(t *testing.T) {
	tpl := &workflowtpl.Template{}
	if err := json.Unmarshal([]byte(testWorkflow), tpl); err != nil {
		t.Fatal(err)
	}
	seed, neg := int64(100), "blur"
	params, err := openAIImageParams(tpl, openAIImageRequest{Prompt: "a fox", Size: "1280x768", Seed: &seed, NegativePrompt: &neg, Params: map[string]any{"width": 1024}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if params["prompt"] != "a fox" || params["width"] != 1024 || params["height"] != nil || params["seed"] != int64(102) || params["negative_prompt"] != "blur" {
		t.Fatalf("params = %v", params)
	}
	if _, err := openAIImageParams(tpl, openAIImageRequest{Prompt: "a", Size: "big"}, 0); err == nil {
		t.Fatal("malformed size accepted")
	}
	noSize := &workflowtpl.Template{ID: "fixed", Params: []workflowtpl.Param{{Name: "prompt"}}}
	if _, err := openAIImageParams(noSize, openAIImageRequest{Prompt: "a", Size: "512x512"}, 0); err == nil {
		t.Fatal("size on a fixed-size workflow accepted")
	}
	if p, err := openAIImageParams(noSize, openAIImageRequest{Prompt: "a", Size: "auto", Quality: "hd", Style: "vivid"}, 0); err != nil || len(p) != 1 {
		t.Fatalf("OpenAI defaults must be ignored, got %v %v", p, err)
	}
}

func TestOpenAIImagesRejectsBadRequests(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	withTestWorkflow(t, srv)
	cases := map[string]struct {
		body map[string]any
		code int
	}{
		"no prompt":     {map[string]any{"model": "image-test"}, http.StatusBadRequest},
		"too many":      {map[string]any{"model": "image-test", "prompt": "a", "n": 5}, http.StatusBadRequest},
		"bad format":    {map[string]any{"model": "image-test", "prompt": "a", "response_format": "png"}, http.StatusBadRequest},
		"unknown model": {map[string]any{"model": "midjourney", "prompt": "a"}, http.StatusNotFound},
	}
	for name, c := range cases {
		response := request(t, srv.Handler(), http.MethodPost, "/v1/images/generations", "alice-token", c.body)
		if response.Code != c.code {
			t.Errorf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
}
