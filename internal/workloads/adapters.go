package workloads

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
)

type HTTPAdapter struct {
	name          string
	version       string
	kind          string
	client        *http.Client
	artifacts     artifacts.Store
	progressMu    sync.RWMutex
	comfyProgress map[string]Observation
	runMu         sync.Mutex
	runs          map[string]*httpRun
}

type httpRun struct {
	done        bool
	output      json.RawMessage
	err         error
	status      int
	startedAt   time.Time
	finishedAt  time.Time
	backendID   string
	performance *domain.ExecutionPerformance
	cancel      context.CancelFunc
}

func (a *HTTPAdapter) SetArtifactStore(store artifacts.Store) { a.artifacts = store }

func NewHTTPAdapter(name, kind string, client *http.Client) *HTTPAdapter {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	return &HTTPAdapter{name: name, version: "v1", kind: kind, client: client, comfyProgress: make(map[string]Observation), runs: make(map[string]*httpRun)}
}

func (a *HTTPAdapter) Name() string    { return a.name }
func (a *HTTPAdapter) Version() string { return a.version }
func (a *HTTPAdapter) DisruptionCapabilities() DisruptionCapabilities {
	return DisruptionCapabilities{Cancel: a.kind == "llama" || a.kind == "comfy"}
}

func (a *HTTPAdapter) Validate(ctx context.Context, req domain.WorkloadRequest) error {
	if len(req.Payload) == 0 || !json.Valid(req.Payload) {
		return fmt.Errorf("payload must be valid JSON")
	}
	switch a.kind {
	case "llama", "openrouter":
		var body struct {
			Messages []json.RawMessage `json:"messages"`
			Prompt   any               `json:"prompt"`
			Model    string            `json:"model"`
		}
		if err := json.Unmarshal(req.Payload, &body); err != nil {
			return err
		}
		if len(body.Messages) == 0 && body.Prompt == nil {
			return fmt.Errorf("LLM payload requires messages or prompt")
		}
	case "comfy":
		var body struct {
			Prompt map[string]json.RawMessage `json:"prompt"`
		}
		if err := json.Unmarshal(req.Payload, &body); err != nil {
			return err
		}
		if len(body.Prompt) == 0 {
			return fmt.Errorf("Comfy payload requires a non-empty prompt workflow")
		}
	}
	if len(req.Transformations) > 0 {
		if a.kind != "comfy" {
			return fmt.Errorf("adapter %s does not implement workflow transformations", a.name)
		}
		if _, err := applyComfyTransformations(req.Payload, req.Transformations, req.TransformationParameters); err != nil {
			return err
		}
	}
	return nil
}

func (a *HTTPAdapter) Requirements(ctx context.Context, req domain.WorkloadRequest) (Requirements, error) {
	var body struct {
		Model               string   `json:"model"`
		MaxTokens           int      `json:"max_tokens"`
		MaxCompletionTokens int      `json:"max_completion_tokens"`
		RequiredCustomNodes []string `json:"required_custom_nodes"`
	}
	_ = json.Unmarshal(req.Payload, &body)
	requiredModels := []string(nil)
	requiredNodes := append([]string(nil), body.RequiredCustomNodes...)
	if a.kind == "comfy" {
		requiredModels, requiredNodes = comfyWorkflowRequirements(req.Payload, requiredNodes)
	}
	maxOutput := req.Bounds.MaxOutput
	if maxOutput <= 0 {
		maxOutput = body.MaxCompletionTokens
		if maxOutput <= 0 {
			maxOutput = body.MaxTokens
		}
	}
	contextTokens := req.Bounds.ContextTokens
	if contextTokens <= 0 && (a.kind == "llama" || a.kind == "openrouter") {
		// Without tokenizer access, one token per payload byte is a safe upper
		// bound for admission and cloud budget reservation.
		contextTokens = len(req.Payload)
	}
	return Requirements{
		Model:               body.Model,
		RequiredModels:      requiredModels,
		CustomNodes:         requiredNodes,
		ContextTokens:       contextTokens + maxOutput,
		AcceleratorRequired: a.kind != "openrouter",
	}, nil
}

var comfyWorkflowModelInputs = map[string]struct{}{
	"ckpt_name": {}, "unet_name": {}, "vae_name": {}, "lora_name": {},
	"clip_name": {}, "clip_name1": {}, "clip_name2": {}, "clip_name3": {}, "clip_name4": {},
	"control_net_name": {}, "upscale_model": {},
}

func comfyWorkflowRequirements(payload json.RawMessage, explicitNodes []string) ([]string, []string) {
	var body struct {
		Prompt map[string]struct {
			ClassType string         `json:"class_type"`
			Inputs    map[string]any `json:"inputs"`
		} `json:"prompt"`
	}
	if json.Unmarshal(payload, &body) != nil {
		return nil, explicitNodes
	}
	models := map[string]struct{}{}
	nodes := map[string]struct{}{}
	for _, node := range explicitNodes {
		if node != "" {
			nodes[node] = struct{}{}
		}
	}
	for _, node := range body.Prompt {
		if node.ClassType != "" {
			nodes[node.ClassType] = struct{}{}
		}
		for field, value := range node.Inputs {
			if _, modelField := comfyWorkflowModelInputs[field]; !modelField {
				continue
			}
			if model, ok := value.(string); ok && model != "" && model != "pixel_space" {
				models[model] = struct{}{}
			}
		}
	}
	modelList := make([]string, 0, len(models))
	for model := range models {
		modelList = append(modelList, model)
	}
	nodeList := make([]string, 0, len(nodes))
	for node := range nodes {
		nodeList = append(nodeList, node)
	}
	sort.Strings(modelList)
	sort.Strings(nodeList)
	return modelList, nodeList
}

func (a *HTTPAdapter) Plan(ctx context.Context, req domain.WorkloadRequest, target Target) (*domain.ExecutionPlan, error) {
	if strings.TrimSpace(target.Endpoint) == "" {
		return nil, fmt.Errorf("target %s has no endpoint", target.ID)
	}
	material := append(json.RawMessage(nil), req.Payload...)
	if len(req.Transformations) > 0 {
		var err error
		material, err = applyComfyTransformations(req.Payload, req.Transformations, req.TransformationParameters)
		if err != nil {
			return nil, err
		}
	}
	return &domain.ExecutionPlan{Material: material}, nil
}

func (a *HTTPAdapter) Start(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	startedAt := time.Now().UTC()
	path := "/v1/chat/completions"
	if a.kind == "comfy" {
		path = "/prompt"
		if err := a.stageComfyInputs(ctx, req, target); err != nil {
			return nil, err
		}
	}
	payload := req.Payload
	comfyClientID := ""
	if plan != nil && len(plan.Material) > 0 {
		payload = plan.Material
	}
	if a.kind == "llama" || a.kind == "openrouter" {
		var body map[string]any
		if json.Unmarshal(payload, &body) == nil {
			body["stream"] = false
			delete(body, "governor")
			if a.kind == "openrouter" && target.Provider != "" {
				body["provider"] = map[string]any{"order": []string{target.Provider}, "allow_fallbacks": false}
			}
			if encoded, err := json.Marshal(body); err == nil {
				payload = encoded
			}
		}
	}
	if a.kind == "comfy" {
		var body map[string]any
		if json.Unmarshal(payload, &body) == nil {
			comfyClientID, _ = body["client_id"].(string)
			if comfyClientID == "" {
				comfyClientID = "vg-" + req.ID
				body["client_id"] = comfyClientID
			}
			if encoded, encodeErr := json.Marshal(body); encodeErr == nil {
				payload = encoded
			}
		}
	}
	result, status, headers, err := a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+path, target.Authorization, payload)
	if err != nil {
		if a.kind == "openrouter" {
			return nil, &BackendError{TargetID: target.ID, Retryable: true, RetryAfter: 5 * time.Second, Message: "openrouter transport failed: " + err.Error(), Cause: err}
		}
		return nil, err
	}
	if status < 200 || status >= 300 {
		message := fmt.Sprintf("%s backend returned %d: %s", a.kind, status, truncate(result, 512))
		if a.kind == "openrouter" {
			return nil, &BackendError{TargetID: target.ID, Status: status, Retryable: status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500, RetryAfter: parseRetryAfter(headers.Get("Retry-After")), Message: message}
		}
		return nil, fmt.Errorf("%s", message)
	}
	h := &domain.ExecutionHandle{StartedAt: startedAt}
	if a.kind == "comfy" {
		var accepted struct {
			PromptID string      `json:"prompt_id"`
			Number   json.Number `json:"number"`
		}
		if err := json.Unmarshal(result, &accepted); err != nil || accepted.PromptID == "" {
			return nil, fmt.Errorf("invalid Comfy submission response")
		}
		h.ExternalID = accepted.PromptID
		go a.observeComfyWebSocket(ctx, target, comfyClientID, accepted.PromptID)
	} else {
		h.Opaque = append(json.RawMessage(nil), result...)
		h.Performance = executionPerformance(startedAt, time.Now().UTC(), time.Time{}, result, "gateway_wall_clock")
		var accepted struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(result, &accepted)
		h.ExternalID = accepted.ID
	}
	return h, nil
}

// StartAsync is deliberately limited to local LLM HTTP routes. Cloud
// providers retain their synchronous start path so provider errors can make
// an immediate, bounded fallback decision. Streaming requests use
// StartStream and preserve client backpressure directly.
func (a *HTTPAdapter) StartAsync(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	if a.kind != "llama" {
		return nil, ErrUnsupported
	}
	payload := req.Payload
	if plan != nil && len(plan.Material) > 0 {
		payload = plan.Material
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, err
	}
	body["stream"] = false
	delete(body, "governor")
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	startedAt := time.Now().UTC()
	id := newID("http-run")
	runCtx, cancel := context.WithCancel(ctx)
	a.runMu.Lock()
	a.runs[id] = &httpRun{startedAt: startedAt, cancel: cancel}
	a.runMu.Unlock()
	go func() {
		result, status, _, requestErr := a.request(runCtx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/v1/chat/completions", target.Authorization, payload)
		finishedAt := time.Now().UTC()
		backendID := ""
		if requestErr == nil && status >= 200 && status < 300 {
			var accepted struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(result, &accepted)
			backendID = accepted.ID
		} else if requestErr == nil {
			requestErr = fmt.Errorf("llama backend returned %d: %s", status, truncate(result, 512))
		}
		a.runMu.Lock()
		if run := a.runs[id]; run != nil {
			run.done = true
			run.output = append(json.RawMessage(nil), result...)
			run.err = requestErr
			run.status = status
			run.finishedAt = finishedAt
			run.backendID = backendID
			run.performance = executionPerformance(startedAt, finishedAt, time.Time{}, result, "gateway_wall_clock_async")
		}
		a.runMu.Unlock()
	}()
	return &domain.ExecutionHandle{ExternalID: id, StartedAt: startedAt}, nil
}

func (a *HTTPAdapter) observeComfyWebSocket(ctx context.Context, target Target, clientID, promptID string) {
	parsed, err := url.Parse(strings.TrimRight(target.Endpoint, "/"))
	if err != nil {
		return
	}
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	} else {
		parsed.Scheme = "ws"
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/ws"
	query := parsed.Query()
	query.Set("clientId", clientID)
	parsed.RawQuery = query.Encode()
	headers := http.Header{}
	if target.Authorization != "" {
		headers.Set("Authorization", target.Authorization)
	}
	conn, _, err := websocket.Dial(ctx, parsed.String(), &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "observer complete")
	for {
		messageType, message, readErr := conn.Read(ctx)
		if readErr != nil {
			return
		}
		// Comfy interleaves binary preview frames with JSON lifecycle/progress
		// events. Binary frames are not scheduler state and must not terminate
		// the progress observer.
		if messageType != websocket.MessageText {
			continue
		}
		var event struct {
			Type string `json:"type"`
			Data struct {
				PromptID string `json:"prompt_id"`
				Node     string `json:"node"`
				Value    int    `json:"value"`
				Max      int    `json:"max"`
			} `json:"data"`
		}
		if json.Unmarshal(message, &event) != nil {
			continue
		}
		if event.Data.PromptID != "" && event.Data.PromptID != promptID {
			continue
		}
		observation := Observation{Status: domain.WorkloadRunning, ProgressStage: event.Type, ProgressNode: event.Data.Node, ProgressCurrent: event.Data.Value, ProgressTotal: event.Data.Max}
		if event.Data.Max > 0 {
			observation.Progress = float64(event.Data.Value) / float64(event.Data.Max)
		}
		a.progressMu.Lock()
		previous := a.comfyProgress[promptID]
		if observation.Progress == 0 && previous.Progress > 0 {
			observation.Progress = previous.Progress
		}
		if observation.ProgressNode == "" {
			observation.ProgressNode = previous.ProgressNode
		}
		if observation.ProgressCurrent == 0 {
			observation.ProgressCurrent = previous.ProgressCurrent
		}
		if observation.ProgressTotal == 0 {
			observation.ProgressTotal = previous.ProgressTotal
		}
		a.comfyProgress[promptID] = observation
		a.progressMu.Unlock()
		if event.Type == "execution_error" || (event.Type == "executing" && event.Data.Node == "") {
			return
		}
	}
}

func (a *HTTPAdapter) StartStream(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target, emit func([]byte) error) (*domain.ExecutionHandle, error) {
	if a.kind != "llama" && a.kind != "openrouter" {
		return nil, ErrUnsupported
	}
	var body map[string]any
	payloadSource := req.Payload
	if plan != nil && len(plan.Material) > 0 {
		payloadSource = plan.Material
	}
	if err := json.Unmarshal(payloadSource, &body); err != nil {
		return nil, err
	}
	body["stream"] = true
	body["stream_options"] = map[string]any{"include_usage": true}
	delete(body, "governor")
	if a.kind == "openrouter" && target.Provider != "" {
		body["provider"] = map[string]any{"order": []string{target.Provider}, "allow_fallbacks": false}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	backendRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	backendRequest.Header.Set("Content-Type", "application/json")
	backendRequest.Header.Set("Accept", "text/event-stream")
	if target.Authorization != "" {
		backendRequest.Header.Set("Authorization", target.Authorization)
	}
	startedAt := time.Now().UTC()
	response, err := a.client.Do(backendRequest)
	if err != nil {
		if a.kind == "openrouter" {
			return nil, &BackendError{TargetID: target.ID, Retryable: true, RetryAfter: 5 * time.Second, Message: "openrouter transport failed: " + err.Error(), Cause: err}
		}
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		detail := fmt.Sprintf("%s backend returned %d: %s", a.kind, response.StatusCode, truncate(message, 512))
		if a.kind == "openrouter" {
			return nil, &BackendError{TargetID: target.ID, Status: response.StatusCode, Retryable: response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After")), Message: detail}
		}
		return nil, fmt.Errorf("%s", detail)
	}
	handle := &domain.ExecutionHandle{StartedAt: startedAt}
	reader := bufio.NewReaderSize(response.Body, 32<<10)
	var firstToken time.Time
	var usageBody []byte
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			if err := emit(line); err != nil {
				return handle, err
			}
			trimmed := strings.TrimSpace(string(line))
			if strings.HasPrefix(trimmed, "data:") && !strings.HasSuffix(trimmed, "[DONE]") {
				body := []byte(strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")))
				var event struct {
					Choices []struct {
						Delta struct {
							Content string `json:"content"`
						} `json:"delta"`
					} `json:"choices"`
					Usage json.RawMessage `json:"usage"`
				}
				if json.Unmarshal(body, &event) == nil {
					if firstToken.IsZero() && len(event.Choices) > 0 && event.Choices[0].Delta.Content != "" {
						firstToken = time.Now().UTC()
					}
					if len(event.Usage) > 0 && string(event.Usage) != "null" {
						usageBody, _ = json.Marshal(map[string]json.RawMessage{"usage": event.Usage})
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				handle.Performance = executionPerformance(startedAt, time.Now().UTC(), firstToken, usageBody, "gateway_wall_clock_stream")
				return handle, nil
			}
			return handle, readErr
		}
	}
}

func executionPerformance(startedAt, finishedAt, firstToken time.Time, response []byte, source string) *domain.ExecutionPerformance {
	seconds := finishedAt.Sub(startedAt).Seconds()
	if seconds <= 0 {
		return nil
	}
	var body struct {
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(response, &body)
	performance := &domain.ExecutionPerformance{DurationMS: seconds * 1000, PromptTokens: body.Usage.PromptTokens, CompletionTokens: body.Usage.CompletionTokens, TotalTokens: body.Usage.TotalTokens, Source: source}
	if !firstToken.IsZero() {
		performance.TTFTMS = firstToken.Sub(startedAt).Seconds() * 1000
	}
	if performance.CompletionTokens > 0 {
		performance.DecodeTPS = float64(performance.CompletionTokens) / seconds
	}
	if performance.TotalTokens == 0 {
		performance.TotalTokens = performance.PromptTokens + performance.CompletionTokens
	}
	if performance.TotalTokens > 0 {
		performance.TotalTPS = float64(performance.TotalTokens) / seconds
	}
	return performance
}

func applyComfyTransformations(payload json.RawMessage, transformations []string, parameters json.RawMessage) (json.RawMessage, error) {
	var material any
	if err := json.Unmarshal(payload, &material); err != nil {
		return nil, err
	}
	var options struct {
		ReduceSteps struct {
			MaxSteps int `json:"max_steps"`
		} `json:"reduce_steps"`
		ReduceResolution struct {
			MaxWidth  int `json:"max_width"`
			MaxHeight int `json:"max_height"`
		} `json:"reduce_resolution"`
	}
	if len(parameters) > 0 && string(parameters) != "null" {
		if err := json.Unmarshal(parameters, &options); err != nil {
			return nil, fmt.Errorf("transformation_parameters must be valid JSON: %w", err)
		}
	}
	for _, transformation := range transformations {
		changed := false
		switch transformation {
		case "reduce_steps":
			if options.ReduceSteps.MaxSteps <= 0 {
				return nil, fmt.Errorf("reduce_steps requires transformation_parameters.reduce_steps.max_steps")
			}
			changed = clampNumericField(material, "steps", options.ReduceSteps.MaxSteps)
		case "reduce_resolution":
			if options.ReduceResolution.MaxWidth <= 0 || options.ReduceResolution.MaxHeight <= 0 {
				return nil, fmt.Errorf("reduce_resolution requires positive max_width and max_height")
			}
			changed = clampNumericField(material, "width", options.ReduceResolution.MaxWidth)
			changed = clampNumericField(material, "height", options.ReduceResolution.MaxHeight) || changed
		case "checkpoint_chunks":
			return nil, fmt.Errorf("external Comfy adapter has not proven checkpoint-safe chunk boundaries")
		default:
			return nil, fmt.Errorf("unsupported Comfy transformation %q", transformation)
		}
		if !changed {
			return nil, fmt.Errorf("transformation %q did not change any material workflow parameter", transformation)
		}
	}
	return json.Marshal(material)
}

func clampNumericField(value any, field string, maximum int) bool {
	changed := false
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			changed = clampNumericField(item, field, maximum) || changed
		}
	case map[string]any:
		if number, ok := typed[field].(float64); ok && number > float64(maximum) {
			typed[field] = maximum
			changed = true
		}
		for _, item := range typed {
			changed = clampNumericField(item, field, maximum) || changed
		}
	}
	return changed
}

func (a *HTTPAdapter) LoadModel(ctx context.Context, target Target, model string) error {
	if a.kind != "llama" || !target.SupportsModelLifecycle {
		return ErrUnsupported
	}
	if isOllamaTarget(target) {
		return a.changeOllamaModelState(ctx, target, model, -1, true)
	}
	payload, _ := json.Marshal(map[string]string{"model": model})
	result, status, _, err := a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/models/load", target.Authorization, payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("llama router load returned %d: %s", status, truncate(result, 512))
	}
	return a.waitModelState(ctx, target, model, true)
}

func (a *HTTPAdapter) UnloadModel(ctx context.Context, target Target, model string) error {
	if a.kind != "llama" || !target.SupportsModelLifecycle {
		return ErrUnsupported
	}
	if isOllamaTarget(target) {
		return a.changeOllamaModelState(ctx, target, model, 0, false)
	}
	payload, _ := json.Marshal(map[string]string{"model": model})
	result, status, _, err := a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/models/unload", target.Authorization, payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("llama router unload returned %d: %s", status, truncate(result, 512))
	}
	return a.waitModelState(ctx, target, model, false)
}

func (a *HTTPAdapter) ReclaimAccelerator(ctx context.Context, target Target) error {
	if a.kind != "comfy" {
		return ErrUnsupported
	}
	payload, _ := json.Marshal(map[string]bool{"unload_models": true, "free_memory": true})
	result, status, _, err := a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/free", target.Authorization, payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Comfy free-memory returned %d: %s", status, truncate(result, 512))
	}
	return nil
}

func isOllamaTarget(target Target) bool {
	for _, argument := range target.RuntimeArgs {
		if strings.Contains(strings.ToLower(argument), "ollama") {
			return true
		}
	}
	return false
}

func (a *HTTPAdapter) changeOllamaModelState(ctx context.Context, target Target, model string, keepAlive int, wantLoaded bool) error {
	payload, _ := json.Marshal(map[string]any{"model": model, "prompt": "", "stream": false, "keep_alive": keepAlive})
	result, status, _, err := a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/api/generate", target.Authorization, payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("ollama model transition returned %d: %s", status, truncate(result, 512))
	}
	return a.waitOllamaModelState(ctx, target, model, wantLoaded)
}

func (a *HTTPAdapter) waitOllamaModelState(ctx context.Context, target Target, model string, wantLoaded bool) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		body, status, _, err := a.request(ctx, http.MethodGet, strings.TrimRight(target.Endpoint, "/")+"/api/ps", target.Authorization, nil)
		if err == nil && status >= 200 && status < 300 {
			loaded, known := ollamaModelLoaded(body, model)
			if (wantLoaded && loaded) || (!wantLoaded && known && !loaded) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Ollama model %s loaded=%t: %w", model, wantLoaded, ctx.Err())
		case <-ticker.C:
		}
	}
}

func ollamaModelLoaded(body []byte, wanted string) (loaded, known bool) {
	var response struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if json.Unmarshal(body, &response) != nil || response.Models == nil {
		return false, false
	}
	for _, row := range response.Models {
		if row.Model == wanted || row.Name == wanted {
			return true, true
		}
	}
	return false, true
}

func (a *HTTPAdapter) waitModelState(ctx context.Context, target Target, model string, wantLoaded bool) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		body, status, _, err := a.request(ctx, http.MethodGet, strings.TrimRight(target.Endpoint, "/")+"/v1/models", target.Authorization, nil)
		if err == nil && status >= 200 && status < 300 {
			loaded, known := routerModelLoaded(body, model)
			if (wantLoaded && loaded) || (!wantLoaded && known && !loaded) || (!wantLoaded && !known) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for model %s loaded=%t: %w", model, wantLoaded, ctx.Err())
		case <-ticker.C:
		}
	}
}

func routerModelLoaded(body []byte, wanted string) (loaded, known bool) {
	var response struct {
		Data []struct {
			ID     string          `json:"id"`
			Status json.RawMessage `json:"status"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &response) != nil {
		return false, false
	}
	for _, model := range response.Data {
		if model.ID != wanted {
			continue
		}
		if len(model.Status) == 0 || string(model.Status) == "null" {
			return true, true
		}
		var status string
		if json.Unmarshal(model.Status, &status) == nil {
			return strings.EqualFold(status, "loaded") || strings.EqualFold(status, "ready"), true
		}
		var object map[string]any
		if json.Unmarshal(model.Status, &object) == nil {
			for _, key := range []string{"value", "status", "state"} {
				if value, ok := object[key].(string); ok {
					return strings.EqualFold(value, "loaded") || strings.EqualFold(value, "ready"), true
				}
			}
		}
		return false, true
	}
	return false, false
}

func (a *HTTPAdapter) Observe(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, h *domain.ExecutionHandle, target Target) (Observation, error) {
	if a.kind == "llama" && strings.HasPrefix(h.ExternalID, "http-run-") {
		a.runMu.Lock()
		run := a.runs[h.ExternalID]
		if run == nil {
			a.runMu.Unlock()
			return Observation{}, fmt.Errorf("local LLM execution state %s is unavailable", h.ExternalID)
		}
		done, runErr := run.done, run.err
		output := append(json.RawMessage(nil), run.output...)
		performance := run.performance
		a.runMu.Unlock()
		if !done {
			return Observation{Status: domain.WorkloadRunning}, nil
		}
		if runErr != nil {
			return Observation{}, runErr
		}
		h.Opaque = output
		if performance != nil {
			copy := *performance
			h.Performance = &copy
		}
		return Observation{Status: domain.WorkloadSucceeded, Progress: 1}, nil
	}
	if a.kind != "comfy" {
		return Observation{Status: domain.WorkloadSucceeded, Progress: 1}, nil
	}
	result, status, _, err := a.request(ctx, http.MethodGet, strings.TrimRight(target.Endpoint, "/")+"/history/"+h.ExternalID, target.Authorization, nil)
	if err != nil {
		return Observation{}, err
	}
	if status < 200 || status >= 300 {
		return Observation{}, fmt.Errorf("Comfy history returned %d", status)
	}
	var history map[string]json.RawMessage
	if err := json.Unmarshal(result, &history); err != nil {
		return Observation{}, err
	}
	entry, done := history[h.ExternalID]
	if !done {
		a.progressMu.RLock()
		progress := a.comfyProgress[h.ExternalID]
		a.progressMu.RUnlock()
		if progress.Status == "" {
			progress.Status = domain.WorkloadRunning
		}
		return progress, nil
	}
	var state struct {
		Status struct {
			StatusStr string `json:"status_str"`
			Completed bool   `json:"completed"`
		} `json:"status"`
	}
	_ = json.Unmarshal(entry, &state)
	if strings.EqualFold(state.Status.StatusStr, "error") {
		return Observation{Status: domain.WorkloadFailed, Error: "Comfy execution failed"}, nil
	}
	h.Opaque = append(json.RawMessage(nil), result...)
	a.progressMu.Lock()
	progress := a.comfyProgress[h.ExternalID]
	delete(a.comfyProgress, h.ExternalID)
	a.progressMu.Unlock()
	progress.Status = domain.WorkloadSucceeded
	progress.Progress = 1
	return progress, nil
}

func (a *HTTPAdapter) Yield(context.Context, *domain.ExecutionHandle, Target) error {
	return ErrUnsupported
}
func (a *HTTPAdapter) Checkpoint(context.Context, *domain.ExecutionHandle, Target) (string, error) {
	return "", ErrUnsupported
}
func (a *HTTPAdapter) Resume(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, string, Target) (*domain.ExecutionHandle, error) {
	return nil, ErrUnsupported
}

func (a *HTTPAdapter) Cancel(ctx context.Context, h *domain.ExecutionHandle, target Target) error {
	if a.kind == "llama" && h != nil && strings.HasPrefix(h.ExternalID, "http-run-") {
		a.runMu.Lock()
		run := a.runs[h.ExternalID]
		if run == nil {
			a.runMu.Unlock()
			return fmt.Errorf("local LLM execution state %s is unavailable; backend stop cannot be confirmed", h.ExternalID)
		}
		cancel := run.cancel
		done := run.done
		a.runMu.Unlock()
		if cancel != nil && !done {
			cancel()
		}
		for !done {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(25 * time.Millisecond):
				a.runMu.Lock()
				run = a.runs[h.ExternalID]
				done = run == nil || run.done
				a.runMu.Unlock()
			}
		}
		return nil
	}
	if a.kind != "comfy" || h.ExternalID == "" {
		return ErrUnsupported
	}
	defer func() { a.progressMu.Lock(); delete(a.comfyProgress, h.ExternalID); a.progressMu.Unlock() }()
	body, _ := json.Marshal(map[string][]string{"delete": {h.ExternalID}})
	_, status, _, err := a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/queue", target.Authorization, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Comfy cancel returned %d", status)
	}
	running, err := a.comfyPromptRunning(ctx, target, h.ExternalID)
	if err != nil || !running {
		return err
	}
	// Comfy's queue delete operation only removes pending prompts. A prompt
	// already executing must be interrupted explicitly; otherwise the governor
	// would release its accelerator lease while the backend kept using the GPU.
	_, status, _, err = a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/interrupt", target.Authorization, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Comfy interrupt returned %d", status)
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		running, err = a.comfyPromptRunning(ctx, target, h.ExternalID)
		if err != nil || !running {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("Comfy prompt %s remained active after interrupt", h.ExternalID)
		case <-ticker.C:
		}
	}
}

func (a *HTTPAdapter) comfyPromptRunning(ctx context.Context, target Target, promptID string) (bool, error) {
	result, status, _, err := a.request(ctx, http.MethodGet, strings.TrimRight(target.Endpoint, "/")+"/queue", target.Authorization, nil)
	if err != nil {
		return false, err
	}
	if status < 200 || status >= 300 {
		return false, fmt.Errorf("Comfy queue inspection returned %d", status)
	}
	var queue struct {
		Running []json.RawMessage `json:"queue_running"`
	}
	if err := json.Unmarshal(result, &queue); err != nil {
		return false, err
	}
	for _, raw := range queue.Running {
		var entry []json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || len(entry) < 2 {
			continue
		}
		var id string
		if json.Unmarshal(entry[1], &id) == nil && id == promptID {
			return true, nil
		}
	}
	return false, nil
}

func (a *HTTPAdapter) CollectOutputs(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, h *domain.ExecutionHandle, target Target) (json.RawMessage, []string, error) {
	if a.kind == "comfy" && a.artifacts != nil && len(h.Opaque) > 0 {
		return a.collectComfyOutputs(ctx, req, h.Opaque, target)
	}
	output := append(json.RawMessage(nil), h.Opaque...)
	if a.kind == "llama" && strings.HasPrefix(h.ExternalID, "http-run-") {
		a.runMu.Lock()
		delete(a.runs, h.ExternalID)
		a.runMu.Unlock()
	}
	return output, nil, nil
}

func (a *HTTPAdapter) stageComfyInputs(ctx context.Context, req domain.WorkloadRequest, target Target) error {
	if a.artifacts == nil || len(req.ArtifactRefs) == 0 {
		return nil
	}
	for _, artifactID := range req.ArtifactRefs {
		artifact, reader, err := a.artifacts.Open(ctx, artifactID)
		if err != nil {
			return fmt.Errorf("open Comfy input artifact %s: %w", artifactID, err)
		}
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormFile("image", artifactID)
		if err == nil {
			_, err = io.Copy(part, reader)
		}
		reader.Close()
		if err == nil {
			err = writer.WriteField("type", "input")
		}
		closeErr := writer.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		backendRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/upload/image", &body)
		if err != nil {
			return err
		}
		backendRequest.Header.Set("Content-Type", writer.FormDataContentType())
		if target.Authorization != "" {
			backendRequest.Header.Set("Authorization", target.Authorization)
		}
		response, err := a.client.Do(backendRequest)
		if err != nil {
			return err
		}
		message, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("Comfy input staging returned %d for %s (%s): %s", response.StatusCode, artifact.Name, artifactID, truncate(message, 256))
		}
	}
	return nil
}

func (a *HTTPAdapter) collectComfyOutputs(ctx context.Context, req domain.WorkloadRequest, raw json.RawMessage, target Target) (json.RawMessage, []string, error) {
	var history any
	if err := json.Unmarshal(raw, &history); err != nil {
		return nil, nil, err
	}
	var refs []string
	seen := make(map[string]string)
	var visit func(any) error
	visit = func(value any) error {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				if err := visit(item); err != nil {
					return err
				}
			}
		case map[string]any:
			filename, hasFilename := typed["filename"].(string)
			if hasFilename && filename != "" {
				subfolder, _ := typed["subfolder"].(string)
				kind, _ := typed["type"].(string)
				key := kind + "/" + subfolder + "/" + filename
				artifactID := seen[key]
				if artifactID == "" {
					query := url.Values{"filename": []string{filename}}
					if subfolder != "" {
						query.Set("subfolder", subfolder)
					}
					if kind != "" {
						query.Set("type", kind)
					}
					backendRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(target.Endpoint, "/")+"/view?"+query.Encode(), nil)
					if err != nil {
						return err
					}
					if target.Authorization != "" {
						backendRequest.Header.Set("Authorization", target.Authorization)
					}
					response, err := a.client.Do(backendRequest)
					if err != nil {
						return err
					}
					if response.StatusCode < 200 || response.StatusCode >= 300 {
						response.Body.Close()
						return fmt.Errorf("Comfy output retrieval returned %d", response.StatusCode)
					}
					mediaType := response.Header.Get("Content-Type")
					artifact, err := a.artifacts.Put(ctx, req.OwnerID, req.ID, filepath.Base(filename), mediaType, response.Body)
					response.Body.Close()
					if err != nil {
						return err
					}
					artifactID = artifact.ID
					seen[key] = artifactID
					refs = append(refs, artifactID)
				}
				typed["filename"] = artifactID
				typed["subfolder"] = ""
				typed["type"] = "output"
			}
			for _, item := range typed {
				if err := visit(item); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(history); err != nil {
		return nil, nil, err
	}
	rewritten, err := json.Marshal(history)
	return rewritten, refs, err
}

func (a *HTTPAdapter) request(ctx context.Context, method, url, authorization string, body []byte) ([]byte, int, http.Header, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return data, resp.StatusCode, resp.Header.Clone(), err
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 5 * time.Second
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 1 {
			seconds = 1
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	return 5 * time.Second
}

func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max])
}

type MockAdapter struct {
	Delay                time.Duration
	ObservedVRAMMB       int64
	ObservedSlowdown     float64
	ObservedTemperatureC float64
	mu                   sync.Mutex
	runs                 map[string]json.RawMessage
}

func NewMockAdapter() *MockAdapter     { return &MockAdapter{runs: make(map[string]json.RawMessage)} }
func (a *MockAdapter) Name() string    { return "mock" }
func (a *MockAdapter) Version() string { return "v1" }
func (a *MockAdapter) DisruptionCapabilities() DisruptionCapabilities {
	return DisruptionCapabilities{Cancel: true}
}
func (a *MockAdapter) Validate(ctx context.Context, req domain.WorkloadRequest) error {
	if !json.Valid(req.Payload) {
		return fmt.Errorf("invalid JSON payload")
	}
	return nil
}
func (a *MockAdapter) Requirements(_ context.Context, req domain.WorkloadRequest) (Requirements, error) {
	return Requirements{ContextTokens: req.Bounds.ContextTokens + req.Bounds.MaxOutput, AcceleratorRequired: true}, nil
}
func (a *MockAdapter) Plan(ctx context.Context, req domain.WorkloadRequest, target Target) (*domain.ExecutionPlan, error) {
	return &domain.ExecutionPlan{Material: req.Payload}, nil
}
func (a *MockAdapter) Start(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	if a.Delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(a.Delay):
		}
	}
	id := newID("mock")
	out, _ := json.Marshal(map[string]any{"target": target.ID, "echo": json.RawMessage(req.Payload)})
	a.mu.Lock()
	a.runs[id] = out
	a.mu.Unlock()
	return &domain.ExecutionHandle{ExternalID: id, StartedAt: time.Now().UTC()}, nil
}
func (a *MockAdapter) Observe(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, *domain.ExecutionHandle, Target) (Observation, error) {
	return Observation{Status: domain.WorkloadSucceeded, Progress: 1, VRAMUsedMB: a.ObservedVRAMMB, Slowdown: a.ObservedSlowdown, TemperatureC: a.ObservedTemperatureC}, nil
}
func (a *MockAdapter) Yield(context.Context, *domain.ExecutionHandle, Target) error {
	return ErrUnsupported
}
func (a *MockAdapter) Checkpoint(context.Context, *domain.ExecutionHandle, Target) (string, error) {
	return "", ErrUnsupported
}
func (a *MockAdapter) Resume(context.Context, domain.WorkloadRequest, *domain.ExecutionPlan, string, Target) (*domain.ExecutionHandle, error) {
	return nil, ErrUnsupported
}
func (a *MockAdapter) Cancel(context.Context, *domain.ExecutionHandle, Target) error { return nil }
func (a *MockAdapter) CollectOutputs(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, h *domain.ExecutionHandle, target Target) (json.RawMessage, []string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append(json.RawMessage(nil), a.runs[h.ExternalID]...), nil, nil
}
