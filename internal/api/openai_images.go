package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/workflowtpl"
)

// defaultImageWorkflow serves /v1/images/generations requests that name no
// model (or an OpenAI model name such as "dall-e-3").
const defaultImageWorkflow = "image-krea2-turbo"

const maxImagesPerRequest = 4

type openAIImageRequest struct {
	Model          string         `json:"model"`
	Prompt         string         `json:"prompt"`
	N              int            `json:"n"`
	Size           string         `json:"size"`
	ResponseFormat string         `json:"response_format"`
	NegativePrompt *string        `json:"negative_prompt"`
	Seed           *int64         `json:"seed"`
	User           string         `json:"user"`
	Quality        string         `json:"quality"`
	Style          string         `json:"style"`
	Params         map[string]any `json:"params"`
	Governor       struct {
		Priority string `json:"priority"`
	} `json:"governor"`
}

// openAIImageParams maps the OpenAI fields onto a workflow's parameters.
// Explicit params win; fields the workflow does not have are ignored rather
// than rejected, because OpenAI clients send them by default.
func openAIImageParams(template *workflowtpl.Template, body openAIImageRequest, index int) (map[string]any, error) {
	has := map[string]bool{}
	for _, p := range template.Params {
		has[p.Name] = true
	}
	params := map[string]any{}
	if has["prompt"] {
		params["prompt"] = body.Prompt
	}
	if body.Size != "" && body.Size != "auto" {
		var width, height int
		if _, err := fmt.Sscanf(body.Size, "%dx%d", &width, &height); err != nil || width <= 0 || height <= 0 {
			return nil, fmt.Errorf("size must look like 1024x1024")
		}
		if !has["width"] && !has["height"] {
			return nil, fmt.Errorf("workflow %s has a fixed size", template.ID)
		}
		if has["width"] {
			params["width"] = width
		}
		if has["height"] {
			params["height"] = height
		}
	}
	if body.NegativePrompt != nil && has["negative_prompt"] {
		params["negative_prompt"] = *body.NegativePrompt
	}
	if body.Seed != nil && has["seed"] {
		// Successive images of one request get successive seeds so n > 1
		// yields different images that are still reproducible.
		params["seed"] = *body.Seed + int64(index)
	}
	for name, value := range body.Params {
		params[name] = value
	}
	return params, nil
}

func (s *Server) handleOpenAIImages(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "inference:submit")
	if !ok {
		return
	}
	var body openAIImageRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error")
		return
	}
	if strings.TrimSpace(body.Prompt) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "prompt is required", "invalid_request_error")
		return
	}
	if body.N == 0 {
		body.N = 1
	}
	if body.N < 1 || body.N > maxImagesPerRequest {
		writeOpenAIError(w, http.StatusBadRequest, fmt.Sprintf("n must be between 1 and %d", maxImagesPerRequest), "invalid_request_error")
		return
	}
	if body.ResponseFormat == "" {
		body.ResponseFormat = "b64_json"
	}
	if body.ResponseFormat != "b64_json" && body.ResponseFormat != "url" {
		writeOpenAIError(w, http.StatusBadRequest, "response_format must be b64_json or url", "invalid_request_error")
		return
	}
	model := body.Model
	if model == "" || strings.HasPrefix(model, "dall-e") || strings.HasPrefix(model, "gpt-image") {
		model = defaultImageWorkflow
	}
	template, err := s.workflowRegistry().Get(model)
	if err != nil || !strings.HasPrefix(template.Operation, "image.") {
		writeOpenAIError(w, http.StatusNotFound, fmt.Sprintf("model %q is not an image workflow (see GET /api/v1/workflows)", model), "invalid_request_error")
		return
	}
	// Creator priority class (e.g. "interactive_user", "background_calibration");
	// empty is the standard production class.
	priority := body.Governor.Priority
	ids := make([]string, 0, body.N)
	var echoes []*creatorWorkflowEcho
	for i := 0; i < body.N; i++ {
		params, err := openAIImageParams(template, body, i)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error")
			return
		}
		creator := creatorStudioRequest{WorkloadID: "img-" + randomSecret()[:20], Workflow: template.Ref(), Params: params, Priority: priority, LatencyClass: "interactive"}
		req, blocked, err := s.buildCreatorWorkload(r, p, creator)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error")
			return
		}
		if blocked != nil {
			writeOpenAIError(w, http.StatusServiceUnavailable, blocked.Reason, "server_error")
			return
		}
		if err := s.prepareRequest(r, p, &req); err != nil {
			writeOpenAIError(w, http.StatusForbidden, err.Error(), "permission_error")
			return
		}
		row, _, err := s.workloads.Submit(r.Context(), req)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error")
			return
		}
		ids = append(ids, row.Request.ID)
	}
	type imageData struct {
		B64JSON string               `json:"b64_json,omitempty"`
		URL     string               `json:"url,omitempty"`
		Seed    any                  `json:"seed,omitempty"`
		Echo    *creatorWorkflowEcho `json:"workflow,omitempty"`
	}
	data := make([]imageData, 0, body.N)
	for _, id := range ids {
		row, err := s.workloads.Wait(r.Context(), id)
		if err != nil {
			s.cancelImageWorkloads(ids, p.OwnerID)
			writeOpenAIError(w, http.StatusServiceUnavailable, err.Error(), "server_error")
			return
		}
		if row.Status != domain.WorkloadSucceeded {
			s.cancelImageWorkloads(ids, p.OwnerID)
			reason := row.Error
			if reason == "" {
				reason = row.Decision.Blocker
			}
			writeOpenAIError(w, http.StatusServiceUnavailable, "image generation "+string(row.Status)+": "+reason, "server_error")
			return
		}
		response := s.creatorResponse(r, row)
		echoes = append(echoes, response.Workflow)
		for _, output := range response.Outputs {
			if !strings.HasPrefix(output.MediaType, "image/") {
				continue
			}
			artifactID := strings.TrimPrefix(output.ArtifactRef, "artifact://")
			item := imageData{Echo: response.Workflow}
			if response.Workflow != nil {
				item.Seed = response.Workflow.Params["seed"]
			}
			if body.ResponseFormat == "url" {
				scheme := "https"
				if r.TLS == nil {
					scheme = "http"
				}
				item.URL = scheme + "://" + r.Host + "/api/v1/artifacts/" + artifactID + "/content"
			} else {
				_, reader, err := s.artifacts.Open(r.Context(), artifactID)
				if err != nil {
					writeOpenAIError(w, http.StatusInternalServerError, "read generated image: "+err.Error(), "server_error")
					return
				}
				var buf bytes.Buffer
				_, err = io.Copy(&buf, reader)
				reader.Close()
				if err != nil {
					writeOpenAIError(w, http.StatusInternalServerError, "read generated image: "+err.Error(), "server_error")
					return
				}
				item.B64JSON = base64.StdEncoding.EncodeToString(buf.Bytes())
			}
			data = append(data, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": time.Now().Unix(), "data": data})
}

func (s *Server) cancelImageWorkloads(ids []string, owner string) {
	for _, id := range ids {
		_ = s.workloads.Cancel(context.Background(), id, owner, false)
	}
}

func writeOpenAIError(w http.ResponseWriter, status int, message, kind string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": message, "type": kind}})
}
