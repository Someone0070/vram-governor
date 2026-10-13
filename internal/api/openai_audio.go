package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"vram-governor/internal/domain"
	"vram-governor/internal/workflowtpl"
)

const (
	defaultSpeechWorkflow     = "audio-speak"
	defaultTranscribeWorkflow = "audio-transcribe"
	maxTranscriptionUpload    = 25 << 20
)

// openAIVoices maps OpenAI voice names onto the workflow's voices: the
// feminine-sounding presets to the first voice, the rest to the second.
var openAIVoices = map[string]int{"alloy": 0, "nova": 0, "shimmer": 0, "coral": 0, "sage": 0,
	"echo": 1, "onyx": 1, "fable": 1, "ash": 1, "ballad": 1, "verse": 1}

// runWorkflowAndWait submits one workflow request as the principal and waits
// for it; the caller turns the outputs into its own response format.
func (s *Server) runWorkflowAndWait(r *http.Request, p Principal, template *workflowtpl.Template, params map[string]any, priority string) (*domain.Workload, creatorWorkloadResponse, int, error) {
	creator := creatorStudioRequest{WorkloadID: "oai-" + randomSecret()[:20], Workflow: template.Ref(), Params: params, Priority: priority, LatencyClass: "interactive"}
	req, blocked, err := s.buildCreatorWorkload(r, p, creator)
	if err != nil {
		return nil, creatorWorkloadResponse{}, http.StatusBadRequest, err
	}
	if blocked != nil {
		return nil, creatorWorkloadResponse{}, http.StatusServiceUnavailable, fmt.Errorf("%s", blocked.Reason)
	}
	if err := s.prepareRequest(r, p, &req); err != nil {
		return nil, creatorWorkloadResponse{}, http.StatusForbidden, err
	}
	row, _, err := s.workloads.Submit(r.Context(), req)
	if err != nil {
		return nil, creatorWorkloadResponse{}, http.StatusBadRequest, err
	}
	row, err = s.workloads.Wait(r.Context(), row.Request.ID)
	if err != nil {
		_ = s.workloads.Cancel(context.Background(), req.ID, p.OwnerID, false)
		return nil, creatorWorkloadResponse{}, http.StatusServiceUnavailable, err
	}
	if row.Status != domain.WorkloadSucceeded {
		reason := row.Error
		if reason == "" {
			reason = row.Decision.Blocker
		}
		return row, creatorWorkloadResponse{}, http.StatusServiceUnavailable, fmt.Errorf("%s %s: %s", template.ID, row.Status, reason)
	}
	return row, s.creatorResponse(r, row), http.StatusOK, nil
}

func (s *Server) readOutput(ctx context.Context, response creatorWorkloadResponse, prefix string) ([]byte, string, error) {
	for _, output := range response.Outputs {
		if !strings.HasPrefix(output.MediaType, prefix) {
			continue
		}
		artifact, reader, err := s.artifacts.Open(ctx, strings.TrimPrefix(output.ArtifactRef, "artifact://"))
		if err != nil {
			return nil, "", err
		}
		data, err := io.ReadAll(io.LimitReader(reader, 1<<30))
		reader.Close()
		return data, artifact.MediaType, err
	}
	return nil, "", fmt.Errorf("workflow produced no %s output", strings.TrimSuffix(prefix, "/"))
}

func (s *Server) audioWorkflow(model, fallback, operation string) (*workflowtpl.Template, error) {
	if model == "" || strings.HasPrefix(model, "tts-") || strings.HasPrefix(model, "whisper") || strings.HasPrefix(model, "gpt-") {
		model = fallback
	}
	template, err := s.workflowRegistry().Get(model)
	if err != nil || template.Operation != operation {
		return nil, fmt.Errorf("model %q is not a %s workflow (see GET /api/v1/workflows)", model, operation)
	}
	return template, nil
}

func (s *Server) handleOpenAISpeech(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "inference:submit")
	if !ok {
		return
	}
	var body struct {
		Model          string `json:"model"`
		Input          string `json:"input"`
		Voice          string `json:"voice"`
		ResponseFormat string `json:"response_format"`
		Speed          any    `json:"speed"`
		Instructions   string `json:"instructions"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error")
		return
	}
	if strings.TrimSpace(body.Input) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "input is required", "invalid_request_error")
		return
	}
	if body.ResponseFormat != "" && body.ResponseFormat != "mp3" {
		writeOpenAIError(w, http.StatusBadRequest, "response_format must be mp3", "invalid_request_error")
		return
	}
	template, err := s.audioWorkflow(body.Model, defaultSpeechWorkflow, "audio.speech")
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, err.Error(), "invalid_request_error")
		return
	}
	params := openAISpeechParams(template, body.Input, body.Voice, body.Instructions)
	_, response, status, err := s.runWorkflowAndWait(r, p, template, params, "")
	if err != nil {
		writeOpenAIError(w, status, err.Error(), "server_error")
		return
	}
	audio, mediaType, err := s.readOutput(r.Context(), response, "audio/")
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error")
		return
	}
	w.Header().Set("Content-Type", mediaType)
	if response.Workflow != nil {
		if voice, ok := response.Workflow.Params["voice"].(string); ok {
			w.Header().Set("X-VRAM-Voice", voice)
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(audio)
}

// openAISpeechParams maps an OpenAI speech request onto a template's params.
// A voice the template names exactly is used as is; other OpenAI voice names
// fall back to the template's first (feminine) or second voice.
func openAISpeechParams(template *workflowtpl.Template, input, requested, instructions string) map[string]any {
	params := map[string]any{"text": input}
	for _, param := range template.Params {
		// instructions describes the voice and delivery (as in OpenAI's
		// API); only templates that declare the param receive it.
		if param.Name == "instructions" && strings.TrimSpace(instructions) != "" {
			params["instructions"] = instructions
		}
		if param.Name != "voice" || len(param.Values) == 0 || requested == "" {
			continue
		}
		voice, exact := requested, false
		for _, allowed := range param.Values {
			if strings.EqualFold(allowed, voice) {
				voice, exact = allowed, true
			}
		}
		if index, mapped := openAIVoices[strings.ToLower(voice)]; !exact && mapped && index < len(param.Values) {
			voice = param.Values[index]
		}
		params["voice"] = voice
	}
	return params
}

func (s *Server) handleOpenAITranscriptions(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "inference:submit")
	if !ok {
		return
	}
	if s.artifacts == nil {
		writeOpenAIError(w, http.StatusServiceUnavailable, "artifact store is unavailable", "server_error")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTranscriptionUpload+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "expected multipart/form-data with a file of at most 25 MB", "invalid_request_error")
		return
	}
	responseFormat := r.FormValue("response_format")
	if responseFormat == "" {
		responseFormat = "json"
	}
	if responseFormat != "json" && responseFormat != "text" && responseFormat != "verbose_json" {
		writeOpenAIError(w, http.StatusBadRequest, "response_format must be json, verbose_json or text", "invalid_request_error")
		return
	}
	template, err := s.audioWorkflow(r.FormValue("model"), defaultTranscribeWorkflow, "audio.transcribe")
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, err.Error(), "invalid_request_error")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "file is required", "invalid_request_error")
		return
	}
	defer file.Close()
	mediaType := header.Header.Get("Content-Type")
	if mediaType == "" || mediaType == "application/octet-stream" {
		mediaType = mime.TypeByExtension(strings.ToLower(filepath.Ext(header.Filename)))
	}
	if !strings.HasPrefix(mediaType, "audio/") && !strings.HasPrefix(mediaType, "video/") {
		writeOpenAIError(w, http.StatusBadRequest, "file must be audio or video", "invalid_request_error")
		return
	}
	artifact, err := s.artifacts.Put(r.Context(), p.OwnerID, "", filepath.Base(header.Filename), strings.SplitN(mediaType, ";", 2)[0], file)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "store upload: "+err.Error(), "server_error")
		return
	}
	params := map[string]any{"audio": artifact.ID}
	if language := strings.TrimSpace(r.FormValue("language")); language != "" {
		params["language"] = language
	}
	if prompt := strings.TrimSpace(r.FormValue("prompt")); prompt != "" {
		params["context"] = prompt
	}
	_, response, status, err := s.runWorkflowAndWait(r, p, template, params, "")
	if err != nil {
		writeOpenAIError(w, status, err.Error(), "server_error")
		return
	}
	text, _, err := s.readOutput(r.Context(), response, "text/")
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error")
		return
	}
	if responseFormat == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(text)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"text": strings.TrimSpace(string(text))})
}
