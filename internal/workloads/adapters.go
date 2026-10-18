package workloads

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	checkpointRuntime "vram-governor/internal/runtime"
	"vram-governor/internal/wsproto"
)

type HTTPAdapter struct {
	name             string
	version          string
	kind             string
	client           *http.Client
	artifacts        artifacts.Store
	progressMu       sync.RWMutex
	comfyProgress    map[string]Observation
	runMu            sync.Mutex
	runs             map[string]*httpRun
	checkpointMu     sync.Mutex
	checkpoint       *CheckpointCoordinator
	checkpointProofs map[string]checkpointRuntime.CheckpointCapabilityProof
	checkpointRuns   map[string]checkpointExecution
	// checkpointEmitters binds a stream operation to the original client sink.
	// Resumed suffixes are delivered through this exact binding.
	checkpointEmitters map[string]func([]byte) error
	checkpointResolver func(context.Context, Target) (NodeControl, string, bool)
	// clock/elapsed are injectable only for deterministic timing tests. The
	// production default retains both the raw time.Time monotonic reading and
	// an opaque token so elapsed hooks cannot silently receive reconstructed or
	// UTC-normalized samples.
	clock   func() clockSample
	elapsed func(clockSample, clockSample) time.Duration
}

type clockSample struct {
	wall  time.Time
	token uint64
}

var clockToken atomic.Uint64

func newClockSample() clockSample {
	return clockSample{wall: time.Now(), token: clockToken.Add(1)}
}

type httpRun struct {
	done           bool
	output         json.RawMessage
	assistant      []byte
	err            error
	status         int
	startedAt      time.Time
	finishedAt     time.Time
	backendID      string
	performance    *domain.ExecutionPerformance
	cancel         context.CancelFunc
	stitchBase     *PartialOutput
	stitchSuffix   []byte
	unsafeToolCall bool
}

// streamSSEState owns the protocol boundary for a live OpenAI-compatible
// stream.  A resumed runtime may replay the assistant bytes that were already
// delivered before the checkpoint.  Keep that replay state here so the
// client-facing emitter sees the stitched stream, not the backend's raw
// replay.  The same state also makes the terminal marker authoritative: once
// the first DONE event is accepted the rest of the backend body is ignored.
type streamSSEState struct {
	done               bool
	rawPrefix          []byte
	rawPrefixOffset    int
	rawPrefixMatching  bool
	assistantRemaining []byte
}

func newStreamSSEState(base *PartialOutput) *streamSSEState {
	state := &streamSSEState{}
	if base == nil {
		return state
	}
	// Production llama.cpp boundaries store assistant token bytes in Prefix;
	// a few adapters persist raw SSE instead.  Only the latter is safe for a
	// byte-for-byte event replay comparison.
	if looksLikeSSEPrefix(base.Prefix) {
		state.rawPrefix = append([]byte(nil), base.Prefix...)
		state.rawPrefixMatching = len(state.rawPrefix) > 0
	}
	state.assistantRemaining = append([]byte(nil), base.AssistantContent...)
	if len(state.assistantRemaining) == 0 {
		if len(state.rawPrefix) > 0 {
			state.assistantRemaining = []byte(inspectSSEBlock(state.rawPrefix).content)
		} else {
			// Some deterministic checkpoint runtimes expose only token bytes in
			// Prefix and leave AssistantContent empty.  Treat those bytes as the
			// replay candidate so the public stream still deduplicates them.
			state.assistantRemaining = append([]byte(nil), base.Prefix...)
		}
	}
	return state
}

func looksLikeSSEPrefix(prefix []byte) bool {
	for _, line := range bytes.Split(prefix, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if payload == "[DONE]" || json.Valid([]byte(payload)) {
			return true
		}
	}
	return false
}

func (s *streamSSEState) process(block []byte) ([]byte, bool) {
	if s == nil || s.done {
		return nil, true
	}
	if sseBlockEndsResponse(block) {
		// The Responses API has no [DONE]: its last event is
		// response.completed (or failed/incomplete), forwarded unchanged.
		s.done = true
		return block, true
	}
	if sseBlockHasDone(block) {
		s.done = true
		// Canonicalize the terminal marker so every public stream has exactly
		// one byte-for-byte recognizable terminal event, regardless of whether
		// the backend used LF/CRLF or omitted the optional space after data:.
		return []byte("data: [DONE]\n\n"), true
	}

	// First try the durable raw prefix.  This handles runtimes that replay the
	// exact SSE bytes saved at the pause boundary without touching event
	// metadata, usage, or tool payloads.
	if s.rawPrefixMatching {
		expected := s.rawPrefix[s.rawPrefixOffset:]
		if len(expected) == 0 {
			s.rawPrefixMatching = false
		} else if len(block) <= len(expected) && bytes.Equal(block, expected[:len(block)]) {
			s.rawPrefixOffset += len(block)
			return nil, false
		} else if len(block) > len(expected) && bytes.Equal(block[:len(expected)], expected) {
			block = block[len(expected):]
			s.rawPrefixOffset = len(s.rawPrefix)
			s.rawPrefixMatching = false
			if len(block) == 0 {
				return nil, false
			}
		} else {
			s.rawPrefixMatching = false
		}
	}

	if len(s.assistantRemaining) > 0 {
		block = s.stripAssistantPrefix(block)
	}
	return block, false
}

func sseBlockEndsResponse(block []byte) bool {
	for _, line := range bytes.Split(block, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		var event struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))), &event) == nil {
			switch event.Type {
			case "response.completed", "response.failed", "response.incomplete":
				return true
			}
		}
	}
	return false
}

func sseBlockHasDone(block []byte) bool {
	for _, line := range bytes.Split(block, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "data:") && strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")) == "[DONE]" {
			return true
		}
	}
	return false
}

func (s *streamSSEState) stripAssistantPrefix(block []byte) []byte {
	if len(s.assistantRemaining) == 0 {
		return block
	}
	lines := bytes.SplitAfter(block, []byte("\n"))
	result := make([]byte, 0, len(block))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		result = append(result, s.stripAssistantPrefixLine(line)...)
	}
	return result
}

func (s *streamSSEState) stripAssistantPrefixLine(line []byte) []byte {
	trimmed := strings.TrimSpace(string(line))
	if !strings.HasPrefix(trimmed, "data:") || strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")) == "[DONE]" || len(s.assistantRemaining) == 0 {
		return line
	}
	dataStart := strings.Index(string(line), "data:")
	if dataStart < 0 {
		return line
	}
	payloadText := strings.TrimSpace(string(line[dataStart+len("data:"):]))
	var event map[string]json.RawMessage
	if json.Unmarshal([]byte(payloadText), &event) != nil {
		return line
	}
	var choices []json.RawMessage
	if rawChoices, ok := event["choices"]; !ok || json.Unmarshal(rawChoices, &choices) != nil {
		return line
	}
	changed := false
	for index, rawChoice := range choices {
		if len(s.assistantRemaining) == 0 {
			break
		}
		var choice map[string]json.RawMessage
		if json.Unmarshal(rawChoice, &choice) != nil {
			continue
		}
		rawDelta, ok := choice["delta"]
		if !ok {
			continue
		}
		var delta map[string]json.RawMessage
		if json.Unmarshal(rawDelta, &delta) != nil {
			continue
		}
		rawContent, ok := delta["content"]
		if !ok {
			continue
		}
		var content string
		if json.Unmarshal(rawContent, &content) != nil || content == "" {
			continue
		}
		remaining := string(s.assistantRemaining)
		switch {
		case strings.HasPrefix(content, remaining):
			content = content[len(remaining):]
			s.assistantRemaining = nil
			encodedContent, _ := json.Marshal(content)
			delta["content"] = encodedContent
			changed = true
		case strings.HasPrefix(remaining, content):
			s.assistantRemaining = []byte(remaining[len(content):])
			delta["content"] = json.RawMessage([]byte(`""`))
			changed = true
		default:
			// The first non-empty assistant delta did not replay the saved
			// prefix.  Disable content dedupe rather than accidentally removing
			// a later, legitimate occurrence of the same text.
			s.assistantRemaining = nil
		}
		if changed {
			updatedDelta, marshalErr := json.Marshal(delta)
			if marshalErr == nil {
				choice["delta"] = updatedDelta
				updatedChoice, choiceErr := json.Marshal(choice)
				if choiceErr == nil {
					choices[index] = updatedChoice
				}
			}
		}
	}
	if !changed {
		return line
	}
	event["choices"], _ = json.Marshal(choices)
	encoded, err := json.Marshal(event)
	if err != nil {
		return line
	}
	return replaceSSEDataLine(line, dataStart, encoded)
}

func replaceSSEDataLine(line []byte, dataStart int, encoded []byte) []byte {
	lineEnd := len(line)
	ending := []byte(nil)
	if lineEnd > 0 && line[lineEnd-1] == '\n' {
		lineEnd--
		ending = append(ending, '\n')
		if lineEnd > 0 && line[lineEnd-1] == '\r' {
			lineEnd--
			ending = []byte{'\r', '\n'}
		}
	}
	core := line[:lineEnd]
	post := core[dataStart+len("data:"):]
	leading := len(post) - len(bytes.TrimLeft(post, " \t"))
	result := make([]byte, 0, len(line)+len(encoded))
	result = append(result, core[:dataStart+len("data:")]...)
	result = append(result, post[:leading]...)
	result = append(result, encoded...)
	result = append(result, ending...)
	return result
}

type streamEventInfo struct {
	backendID string
	content   string
	usage     []byte
	unsafe    bool
}

func inspectSSEBlock(block []byte) streamEventInfo {
	var info streamEventInfo
	for _, line := range bytes.Split(block, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		data := []byte(strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")))
		if len(data) == 0 || string(data) == "[DONE]" {
			continue
		}
		var event struct {
			ID      string `json:"id"`
			Choices []struct {
				Delta struct {
					Content      string            `json:"content"`
					ToolCalls    []json.RawMessage `json:"tool_calls"`
					FunctionCall json.RawMessage   `json:"function_call"`
				} `json:"delta"`
			} `json:"choices"`
			Usage json.RawMessage `json:"usage"`
		}
		if json.Unmarshal(data, &event) != nil {
			continue
		}
		if info.backendID == "" {
			info.backendID = event.ID
		}
		for _, choice := range event.Choices {
			info.content += choice.Delta.Content
			if len(choice.Delta.ToolCalls) > 0 || len(choice.Delta.FunctionCall) > 0 && string(choice.Delta.FunctionCall) != "null" {
				info.unsafe = true
			}
		}
		if len(event.Usage) > 0 && string(event.Usage) != "null" {
			info.usage, _ = json.Marshal(map[string]json.RawMessage{"usage": event.Usage})
		}
	}
	return info
}

// consumeSSEStream buffers one SSE event (up to its blank-line boundary),
// applies prefix stitching before emit, and stops reading at the first
// terminal marker. EOF without that marker is a protocol failure.
func consumeSSEStream(reader *bufio.Reader, state *streamSSEState, emit func([]byte) error, observe func([]byte)) (bool, error) {
	var block []byte
	flush := func() (bool, error) {
		if len(block) == 0 {
			return false, nil
		}
		out, terminal := state.process(block)
		block = nil
		if len(out) > 0 {
			if emit != nil {
				if err := emit(out); err != nil {
					return false, err
				}
			}
			if observe != nil {
				observe(out)
			}
		}
		return terminal, nil
	}
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			block = append(block, line...)
			if strings.TrimSpace(string(line)) == "" {
				terminal, err := flush()
				if err != nil || terminal {
					return terminal, err
				}
			}
		}
		if readErr != nil {
			if len(block) > 0 {
				terminal, err := flush()
				if err != nil || terminal {
					return terminal, err
				}
			}
			if readErr != io.EOF {
				return false, readErr
			}
			if state.done {
				return true, nil
			}
			return false, fmt.Errorf("stream ended before terminal data: [DONE]")
		}
	}
}

func (a *HTTPAdapter) SetArtifactStore(store artifacts.Store) { a.artifacts = store }

func NewHTTPAdapter(name, kind string, client *http.Client) *HTTPAdapter {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	return &HTTPAdapter{name: name, version: "v1", kind: kind, client: client, comfyProgress: make(map[string]Observation), runs: make(map[string]*httpRun), checkpointRuns: make(map[string]checkpointExecution), checkpointEmitters: make(map[string]func([]byte) error), checkpointProofs: make(map[string]checkpointRuntime.CheckpointCapabilityProof)}
}

// ConfigureCheckpointChannel binds production checkpointing to the
// controller's signed node command channel. The adapter never derives a
// generation or fence itself.
func (a *HTTPAdapter) ConfigureCheckpointChannel(resolve func(context.Context, Target) (NodeControl, string, bool)) {
	a.checkpointMu.Lock()
	a.checkpointResolver = resolve
	a.checkpointMu.Unlock()
}

func (a *HTTPAdapter) clockNow() clockSample {
	if a.clock != nil {
		return a.clock()
	}
	return newClockSample()
}

func (a *HTTPAdapter) measuredPerformance(startedAt, finishedAt, firstToken clockSample, response []byte, source string) *domain.ExecutionPerformance {
	duration := finishedAt.wall.Sub(startedAt.wall)
	firstTokenElapsed := time.Duration(0)
	if firstToken.token != 0 {
		firstTokenElapsed = firstToken.wall.Sub(startedAt.wall)
	}
	if a.elapsed != nil {
		duration = a.elapsed(startedAt, finishedAt)
		if firstToken.token != 0 {
			firstTokenElapsed = a.elapsed(startedAt, firstToken)
		}
	}
	performance := executionPerformanceWithElapsed(duration, firstTokenElapsed, response, source)
	// Prompt throughput is part of the gateway timing contract. Keep the
	// legacy executionPerformance helper's historical shape unchanged while
	// publishing the complete metric for LocalLLM's clock-sampled paths.
	if performance.PromptTokens > 0 && performance.DurationMS > 0 {
		performance.PromptTPS = float64(performance.PromptTokens) / (performance.DurationMS / 1000)
	}
	return performance
}

// setClockForTest injects wall timestamps and a monotonic elapsed hook. It is
// deliberately package-private so production callers cannot replace the
// clock; tests can model NTP steps without weakening the real path.
func (a *HTTPAdapter) setClockForTest(clock func() clockSample, elapsed func(clockSample, clockSample) time.Duration) {
	a.clock = clock
	a.elapsed = elapsed
}

func (a *HTTPAdapter) Name() string    { return a.name }
func (a *HTTPAdapter) Version() string { return a.version }
func (a *HTTPAdapter) DisruptionCapabilities() DisruptionCapabilities {
	// Checkpointability is target-scoped. A global coordinator or another
	// target's proof must never widen admission for this adapter.
	return DisruptionCapabilities{Checkpoint: false, Cancel: a.kind == "llama" || a.kind == "comfy"}
}

func (a *HTTPAdapter) DisruptionCapabilitiesForTarget(target Target) DisruptionCapabilities {
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return DisruptionCapabilities{Yield: true, Checkpoint: true, Cancel: true}
	}
	checkpoint := false
	if a.kind == "llama" {
		a.checkpointMu.Lock()
		coordinator := a.checkpoint
		proof := a.checkpointProofs[target.ID]
		a.checkpointMu.Unlock()
		checkpoint = coordinator != nil && proof.Complete() && coordinator.ReadyForTarget(target, "", "", 0, 0)
	}
	return DisruptionCapabilities{Checkpoint: checkpoint, Cancel: true}
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
			Input    any               `json:"input"`
			Model    string            `json:"model"`
		}
		if err := json.Unmarshal(req.Payload, &body); err != nil {
			return err
		}
		if req.WorkloadType == WorkloadTypeEmbeddings {
			if a.kind != "llama" || body.Input == nil || body.Model == "" {
				return fmt.Errorf("embeddings require a local model and input")
			}
			break
		}
		if req.WorkloadType == WorkloadTypeResponses {
			if body.Input == nil {
				return fmt.Errorf("responses payload requires input")
			}
			break
		}
		if len(body.Messages) == 0 && body.Prompt == nil {
			return fmt.Errorf("LLM payload requires messages or prompt")
		}
	case "comfy":
		var body struct {
			Prompt        map[string]json.RawMessage `json:"prompt"`
			ManagedChunks []json.RawMessage          `json:"managed_chunks"`
		}
		if err := json.Unmarshal(req.Payload, &body); err != nil {
			return err
		}
		if len(body.Prompt) == 0 && len(body.ManagedChunks) == 0 {
			return fmt.Errorf("Comfy payload requires a non-empty prompt workflow or managed_chunks")
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

// defaultReservedOutputTokens is the output a local request reserves from its
// model's context pool when it sets no max_tokens.
const defaultReservedOutputTokens = 2048

func (a *HTTPAdapter) Requirements(ctx context.Context, req domain.WorkloadRequest) (Requirements, error) {
	var body struct {
		Model               string   `json:"model"`
		MaxTokens           int      `json:"max_tokens"`
		MaxCompletionTokens int      `json:"max_completion_tokens"`
		MaxOutputTokens     int      `json:"max_output_tokens"`
		RequiredCustomNodes []string `json:"required_custom_nodes"`
	}
	_ = json.Unmarshal(req.Payload, &body)
	requiredModels := []string(nil)
	requiredNodes := append([]string(nil), body.RequiredCustomNodes...)
	runtimeProtocol := ""
	if a.kind == "comfy" {
		var managed bool
		requiredModels, requiredNodes, managed = comfyWorkflowRequirements(req.Payload, requiredNodes)
		if managed {
			runtimeProtocol = managedComfyProtocol
		}
	}
	maxOutput := req.Bounds.MaxOutput
	for _, declared := range []int{body.MaxCompletionTokens, body.MaxTokens, body.MaxOutputTokens} {
		if maxOutput <= 0 {
			maxOutput = declared
		}
	}
	contextTokens := req.Bounds.ContextTokens
	if contextTokens <= 0 && a.kind == "openrouter" {
		// Without tokenizer access, one token per payload byte is a safe upper
		// bound for cloud budget reservation.
		contextTokens = len(req.Payload)
	}
	if a.kind == "llama" {
		// Local requests reserve context from the model's shared pool, where
		// one token per byte (3-4x too many) would starve concurrency; ~4 bytes per
		// token is typical (an underestimate is caught by the overflow retry). Clients
		// that know better send governor.context_tokens and max_tokens.
		// A declared budget below what the prompt itself needs would
		// overbook the pool ("Context size has been exceeded").
		if estimated := len(req.Payload)/4 + 1; contextTokens < estimated {
			contextTokens = estimated
		}
		if maxOutput <= 0 {
			maxOutput = defaultReservedOutputTokens
		}
	}
	return Requirements{
		Model:               body.Model,
		RequiredModels:      requiredModels,
		CustomNodes:         requiredNodes,
		ContextTokens:       contextTokens + maxOutput,
		RuntimeProtocol:     runtimeProtocol,
		AcceleratorRequired: a.kind != "openrouter",
	}, nil
}

var comfyWorkflowModelInputs = map[string]struct{}{
	"ckpt_name": {}, "unet_name": {}, "vae_name": {}, "lora_name": {},
	"clip_name": {}, "clip_name1": {}, "clip_name2": {}, "clip_name3": {}, "clip_name4": {},
	"control_net_name": {}, "upscale_model": {},
}

func comfyWorkflowRequirements(payload json.RawMessage, explicitNodes []string) ([]string, []string, bool) {
	type workflowNode struct {
		ClassType string         `json:"class_type"`
		Inputs    map[string]any `json:"inputs"`
	}
	var body struct {
		Prompt        map[string]workflowNode `json:"prompt"`
		ManagedChunks []struct {
			Prompt map[string]workflowNode `json:"prompt"`
		} `json:"managed_chunks"`
	}
	if json.Unmarshal(payload, &body) != nil {
		return nil, explicitNodes, false
	}
	models := map[string]struct{}{}
	nodes := map[string]struct{}{}
	for _, node := range explicitNodes {
		if node != "" {
			nodes[node] = struct{}{}
		}
	}
	workflows := []map[string]workflowNode{body.Prompt}
	for _, managed := range body.ManagedChunks {
		workflows = append(workflows, managed.Prompt)
	}
	for _, workflow := range workflows {
		for _, node := range workflow {
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
	return modelList, nodeList, len(body.ManagedChunks) > 0
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

// WorkloadTypeEmbeddings marks OpenAI /v1/embeddings requests; they share
// LLM admission and residency but use the runtime's embeddings route.
const WorkloadTypeEmbeddings = "llm.embeddings"

// WorkloadTypeCompletion marks legacy OpenAI /v1/completions requests.
const WorkloadTypeCompletion = "llm.completion"

// WorkloadTypeResponses marks OpenAI Responses API requests; llama.cpp serves
// /v1/responses natively.
const WorkloadTypeResponses = "llm.responses"

func llmPath(req domain.WorkloadRequest) string {
	switch req.WorkloadType {
	case WorkloadTypeEmbeddings:
		return "/v1/embeddings"
	case WorkloadTypeCompletion:
		return "/v1/completions"
	case WorkloadTypeResponses:
		return "/v1/responses"
	}
	return "/v1/chat/completions"
}

func (a *HTTPAdapter) Start(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) (*domain.ExecutionHandle, error) {
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return a.startManagedComfy(ctx, req, plan, target, "")
	}
	startedAt := a.clockNow()
	path := llmPath(req)
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
			if req.WorkloadType == WorkloadTypeEmbeddings {
				delete(body, "stream")
			} else {
				body["stream"] = false
			}
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
		return nil, &BackendError{TargetID: target.ID, Retryable: true, RetryAfter: 5 * time.Second, Message: a.kind + " transport failed: " + err.Error(), Cause: err}
	}
	if status < 200 || status >= 300 {
		limit := 512
		if a.kind == "comfy" && target.ComfyUI {
			// The web UI marks the failing nodes from Comfy's node_errors.
			limit = 64 << 10
		}
		message := fmt.Sprintf("%s backend returned %d: %s", a.kind, status, truncate(result, limit))
		return nil, &BackendError{TargetID: target.ID, Status: status, Retryable: status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500, RetryAfter: parseRetryAfter(headers.Get("Retry-After")), Message: message}
	}
	h := &domain.ExecutionHandle{StartedAt: startedAt.wall.UTC()}
	if a.kind == "comfy" {
		var accepted struct {
			PromptID string      `json:"prompt_id"`
			Number   json.Number `json:"number"`
		}
		if err := json.Unmarshal(result, &accepted); err != nil || accepted.PromptID == "" {
			return nil, fmt.Errorf("invalid Comfy submission response")
		}
		h.ExternalID = accepted.PromptID
		if !target.ComfyUI {
			// Comfy keeps one socket per client id: the web UI's browser owns
			// it, and Observe polls history instead.
			go a.observeComfyWebSocket(ctx, target, comfyClientID, accepted.PromptID)
		}
	} else {
		h.Opaque = append(json.RawMessage(nil), result...)
		h.Performance = a.measuredPerformance(startedAt, a.clockNow(), clockSample{}, result, "gateway_wall_clock")
		var accepted struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(result, &accepted)
		h.ExternalID = accepted.ID
	}
	a.recordCheckpointExecution(h, req, plan, target)
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
	if req.WorkloadType == WorkloadTypeEmbeddings {
		delete(body, "stream")
	} else {
		body["stream"] = false
	}
	delete(body, "governor")
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	startedAt := a.clockNow()
	id := newID("http-run")
	path := llmPath(req)
	runCtx, cancel := context.WithCancel(ctx)
	a.runMu.Lock()
	a.runs[id] = &httpRun{startedAt: startedAt.wall, cancel: cancel}
	a.runMu.Unlock()
	go func() {
		result, status, _, requestErr := a.request(runCtx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+path, target.Authorization, payload)
		finishedAt := a.clockNow()
		backendID := ""
		if requestErr == nil && status >= 200 && status < 300 {
			var accepted struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(result, &accepted)
			backendID = accepted.ID
		} else if requestErr == nil {
			message := fmt.Sprintf("llama backend returned %d: %s", status, truncate(result, 512))
			requestErr = &BackendError{TargetID: target.ID, Status: status, Retryable: status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500, RetryAfter: 5 * time.Second, Message: message}
		} else {
			requestErr = &BackendError{TargetID: target.ID, Retryable: true, RetryAfter: 5 * time.Second, Message: "llama transport failed: " + requestErr.Error(), Cause: requestErr}
		}
		a.runMu.Lock()
		if run := a.runs[id]; run != nil {
			run.performance = a.measuredPerformance(startedAt, finishedAt, clockSample{}, result, "gateway_wall_clock_async")
			// Publish completion only after the measured performance is attached;
			// observers must never observe a successful run without its metrics.
			run.done = true
			run.output = append(json.RawMessage(nil), result...)
			run.err = requestErr
			run.status = status
			run.finishedAt = finishedAt.wall
			run.backendID = backendID
		}
		a.runMu.Unlock()
	}()
	h := &domain.ExecutionHandle{ExternalID: id, StartedAt: startedAt.wall.UTC()}
	a.recordCheckpointExecution(h, req, plan, target)
	return h, nil
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
	if len(bytes.TrimSpace(payloadSource)) == 0 {
		payloadSource = []byte(`{}`)
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
	backendRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+llmPath(req), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	backendRequest.Header.Set("Content-Type", "application/json")
	backendRequest.Header.Set("Accept", "text/event-stream")
	if target.Authorization != "" {
		backendRequest.Header.Set("Authorization", target.Authorization)
	}
	startedAt := a.clockNow()
	response, err := a.client.Do(backendRequest)
	if err != nil {
		return nil, &BackendError{TargetID: target.ID, Retryable: true, RetryAfter: 5 * time.Second, Message: a.kind + " transport failed: " + err.Error(), Cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		detail := fmt.Sprintf("%s backend returned %d: %s", a.kind, response.StatusCode, truncate(message, 512))
		return nil, &BackendError{TargetID: target.ID, Status: response.StatusCode, Retryable: response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After")), Message: detail}
	}
	handle := &domain.ExecutionHandle{StartedAt: startedAt.wall.UTC()}
	a.recordCheckpointExecution(handle, req, plan, target)
	reader := bufio.NewReaderSize(response.Body, 32<<10)
	var firstToken clockSample
	var usageBody []byte
	state := newStreamSSEState(nil)
	done, streamErr := consumeSSEStream(reader, state, emit, func(block []byte) {
		info := inspectSSEBlock(block)
		if firstToken.token == 0 && info.content != "" {
			firstToken = a.clockNow()
		}
		if len(info.usage) > 0 {
			usageBody = info.usage
		}
	})
	if streamErr != nil {
		return handle, streamErr
	}
	if !done {
		return handle, fmt.Errorf("stream ended before terminal data: [DONE]")
	}
	handle.Performance = a.measuredPerformance(startedAt, a.clockNow(), firstToken, usageBody, "gateway_wall_clock_stream")
	return handle, nil
}

// StartStreamLive is the production streaming boundary. It returns as soon as
// the request goroutine owns the backend response, so the manager can publish
// the execution handle and checkpoint a real in-flight generation. The older
// StartStream method intentionally keeps its blocking contract for callers
// that consume a stream directly.
func (a *HTTPAdapter) StartStreamLive(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target, emit func([]byte) error) (*domain.ExecutionHandle, error) {
	if a.kind != "llama" && a.kind != "openrouter" {
		return nil, ErrUnsupported
	}
	payloadSource := req.Payload
	if plan != nil && len(plan.Material) > 0 {
		payloadSource = plan.Material
	}
	if len(bytes.TrimSpace(payloadSource)) == 0 {
		payloadSource = []byte(`{}`)
	}
	var body map[string]any
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
	return a.startLiveStream(ctx, req, plan, target, payload, emit, nil, -1, "", nil)
}

// StartStreamWithLease reserves the exact router slot before opening the
// generation. This is the only checkpointable native-LLM start boundary.
func (a *HTTPAdapter) StartStreamWithLease(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target, lease SlotLease, command CheckpointCommand, emit func([]byte) error) (*domain.ExecutionHandle, error) {
	if a.kind != "llama" {
		return nil, ErrUnsupported
	}
	a.checkpointMu.Lock()
	resolver := a.checkpointResolver
	coordinator := a.checkpoint
	a.checkpointMu.Unlock()
	if resolver == nil || coordinator == nil {
		return nil, ErrCheckpointUnavailable
	}
	a.checkpointMu.Lock()
	proof, proofOK := a.checkpointProofs[target.ID]
	a.checkpointMu.Unlock()
	if !proofOK || !proof.Complete() || !coordinator.ReadyForTarget(target, command.ModelFingerprint, command.ProfileFingerprint, command.ContextLimit, 0) {
		return nil, ErrCheckpointUnavailable
	}
	control, nodeID, ok := resolver(ctx, target)
	if !ok {
		return nil, ErrCheckpointUnavailable
	}
	lease.NodeID = nodeID
	// The conversation identity is part of the immutable operation envelope;
	// derive it before the durable create so a restart can never invent a
	// different backend conversation for the same stream.
	command = withCheckpointConversation(command)
	if err := coordinator.PrepareOperation(ctx, command, lease); err != nil {
		return nil, err
	}
	args := map[string]any{"target_kind": "llamacpp", "target_id": target.ID, "accelerator_id": lease.AcceleratorID, "model": command.ModelFingerprint, "runtime_identity": lease.RuntimeIdentity, "capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision, "profile_fingerprint": lease.ProfileFingerprint, "context_fingerprint": fmt.Sprintf("ctx:%d", lease.ContextLimit), "owner_id": lease.OwnerID, "workload_id": lease.WorkloadID, "generation": lease.Generation, "fencing_token": lease.Fence, "context_limit": lease.ContextLimit, "checkpoint_action": "slot_assign", "checkpoint_operation_id": command.ID, "idempotency_key": command.IdempotencyKey, "conversation_id": command.ConversationID}
	result, err := control(ctx, nodeID, "checkpoint_slot_assign", args, command.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	slotID := -1
	switch n := result["slot_id"].(type) {
	case int:
		slotID = n
	case int64:
		slotID = int(n)
	case float64:
		slotID = int(n)
	}
	if slotID < 0 {
		return nil, fmt.Errorf("node did not return an authoritative slot assignment")
	}
	assignedLease := lease
	assignedLease.SlotID = slotID
	// Every path after slot assignment must release the exact ownership key.
	// Keep the cleanup closure above the start command because a failed start
	// still owns the slot and must be compensated through the signed lifecycle.
	rollbackSlot := func(cause error) error {
		base := make(map[string]any, len(args)+3)
		for key, value := range args {
			base[key] = value
		}
		base["slot_id"] = slotID
		base["conversation_id"] = command.ConversationID
		pauseArgs := make(map[string]any, len(base)+2)
		for key, value := range base {
			pauseArgs[key] = value
		}
		pauseArgs["checkpoint_action"] = "pause"
		pauseArgs["idempotency_key"] = command.IdempotencyKey + ":start-rollback-pause"
		pauseErr := error(nil)
		if _, err := control(context.WithoutCancel(ctx), nodeID, "checkpoint_pause", pauseArgs, command.IdempotencyKey+":start-rollback-pause"); err != nil {
			pauseErr = err
		}
		stopArgs := make(map[string]any, len(pauseArgs)+1)
		for key, value := range pauseArgs {
			stopArgs[key] = value
		}
		stopArgs["checkpoint_action"] = "stop_confirm"
		stopArgs["idempotency_key"] = command.IdempotencyKey + ":start-rollback-stop"
		stopErr := error(nil)
		if _, err := control(context.WithoutCancel(ctx), nodeID, "checkpoint_stop_confirm", stopArgs, command.IdempotencyKey+":start-rollback-stop"); err != nil {
			stopErr = err
		}
		releaseArgs := make(map[string]any, len(stopArgs)+1)
		for key, value := range stopArgs {
			releaseArgs[key] = value
		}
		releaseArgs["checkpoint_action"] = "release"
		releaseArgs["idempotency_key"] = command.IdempotencyKey + ":start-rollback-release"
		releaseErr := error(nil)
		if _, err := control(context.WithoutCancel(ctx), nodeID, "checkpoint_release", releaseArgs, command.IdempotencyKey+":start-rollback-release"); err != nil {
			releaseErr = err
		}
		if releaseErr == nil {
			// Mirror the authoritative node cleanup in the controller row before
			// terminalizing the failed start. This keeps restart recovery from
			// mistaking a deliberately released snapshotless slot for a live one.
			if phaseErr := coordinator.RecordOperationPhase(context.WithoutCancel(ctx), command, assignedLease, "released"); phaseErr != nil {
				releaseErr = phaseErr
			} else if terminalErr := coordinator.TerminalizeOperation(context.WithoutCancel(ctx), command.ID, "failed", cause.Error()); terminalErr != nil {
				releaseErr = terminalErr
			}
		}
		if pauseErr != nil || stopErr != nil || releaseErr != nil {
			return fmt.Errorf("%w; slot rollback pause=%v stop=%v release=%v", cause, pauseErr, stopErr, releaseErr)
		}
		return cause
	}
	if err := coordinator.RecordOperationPhase(ctx, command, assignedLease, "assigned"); err != nil {
		return nil, rollbackSlot(err)
	}
	startArgs := make(map[string]any, len(args)+3)
	for key, value := range args {
		startArgs[key] = value
	}
	startArgs["slot_id"] = slotID
	startArgs["checkpoint_action"] = "start"
	startArgs["managed_stream"] = true
	startArgs["idempotency_key"] = command.IdempotencyKey + ":start"
	if _, err := control(ctx, nodeID, "checkpoint_start", startArgs, command.IdempotencyKey+":start"); err != nil {
		return nil, rollbackSlot(err)
	}
	if err := coordinator.RecordOperationPhase(ctx, command, assignedLease, "started"); err != nil {
		return nil, rollbackSlot(err)
	}
	payloadSource := req.Payload
	if plan != nil && len(plan.Material) > 0 {
		payloadSource = plan.Material
	}
	if len(bytes.TrimSpace(payloadSource)) == 0 {
		payloadSource = []byte(`{}`)
	}
	var body map[string]any
	if err := json.Unmarshal(payloadSource, &body); err != nil {
		return nil, rollbackSlot(err)
	}
	body["stream"] = true
	body["stream_options"] = map[string]any{"include_usage": true}
	body["id_slot"] = slotID
	body["cache_prompt"] = true
	delete(body, "governor")
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, rollbackSlot(err)
	}
	h, err := a.startLiveStream(ctx, req, plan, target, payload, emit, nil, slotID, command.ConversationID, nil)
	if err != nil {
		return nil, rollbackSlot(err)
	}
	// Publish the binding only after the live response goroutine exists.  The
	// operation id is immutable and is carried through checkpoint/restart;
	// ResumeWithLease uses it to recover the original emitter.
	a.checkpointMu.Lock()
	if a.checkpointEmitters == nil {
		a.checkpointEmitters = make(map[string]func([]byte) error)
	}
	a.checkpointEmitters[command.ID] = emit
	if execution := a.checkpointRuns[h.ExternalID]; execution.Target.ID != "" {
		execution.OperationID = command.ID
		execution.Emit = emit
		execution.Lease = assignedLease
		execution.ConversationID = command.ConversationID
		execution.OperationConversationID = command.ConversationID
		a.checkpointRuns[h.ExternalID] = execution
	}
	a.checkpointMu.Unlock()
	// The handle carries the immutable lease and conversation identity for
	// checkpoint/preemption and restart reconciliation.
	h.Opaque, _ = json.Marshal(map[string]any{"slot_id": slotID, "accelerator_id": lease.AcceleratorID, "generation": lease.Generation, "fence": lease.Fence, "conversation_id": command.ConversationID, "operation_id": command.ID, "node_id": nodeID, "owner_id": command.OwnerID, "workload_id": command.WorkloadID})
	return h, nil
}

func (a *HTTPAdapter) startLiveStream(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target, payload []byte, emit func([]byte) error, prefix []byte, slotID int, conversationID string, stitchBase *PartialOutput) (*domain.ExecutionHandle, error) {
	startedAt := a.clockNow()
	id := newID("http-run-stream")
	runCtx, cancel := context.WithCancel(ctx)
	initialAssistant := []byte(nil)
	if stitchBase != nil {
		initialAssistant = append(initialAssistant, stitchBase.AssistantContent...)
		if len(initialAssistant) == 0 {
			if looksLikeSSEPrefix(stitchBase.Prefix) {
				initialAssistant = []byte(inspectSSEBlock(stitchBase.Prefix).content)
			} else {
				initialAssistant = append(initialAssistant, stitchBase.Prefix...)
			}
		}
	}
	a.runMu.Lock()
	a.runs[id] = &httpRun{startedAt: startedAt.wall, cancel: cancel, output: append(json.RawMessage(nil), prefix...), assistant: initialAssistant, stitchBase: stitchBase}
	a.runMu.Unlock()
	h := &domain.ExecutionHandle{ExternalID: id, StartedAt: startedAt.wall.UTC()}
	a.recordCheckpointExecution(h, req, plan, target)
	startup := make(chan error, 1)
	go func() {
		backendRequest, requestErr := http.NewRequestWithContext(runCtx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+llmPath(req), bytes.NewReader(payload))
		if requestErr == nil {
			backendRequest.Header.Set("Content-Type", "application/json")
			backendRequest.Header.Set("Accept", "text/event-stream")
			if target.Authorization != "" {
				backendRequest.Header.Set("Authorization", target.Authorization)
			}
			if conversationID != "" {
				backendRequest.Header.Set("X-Conversation-Id", conversationID)
			}
		}
		var response *http.Response
		if requestErr == nil {
			response, requestErr = a.client.Do(backendRequest)
		}
		finishedAt := a.clockNow()
		var performance *domain.ExecutionPerformance
		var backendID string
		if requestErr == nil && (response.StatusCode < 200 || response.StatusCode >= 300) {
			message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			response.Body.Close()
			requestErr = &BackendError{TargetID: target.ID, Status: response.StatusCode, Retryable: response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After")), Message: fmt.Sprintf("%s backend returned %d: %s", a.kind, response.StatusCode, truncate(message, 512))}
		}
		// A live handle is publishable only after the backend request has been
		// accepted. This keeps transport/status failures on the synchronous
		// start seam, where a resumed slot can be compensated before return.
		startup <- requestErr
		if requestErr == nil {
			defer response.Body.Close()
			reader := bufio.NewReaderSize(response.Body, 32<<10)
			var firstToken clockSample
			var usageBody []byte
			state := newStreamSSEState(stitchBase)
			_, requestErr = consumeSSEStream(reader, state, func(block []byte) error {
				if emit != nil {
					if err := emit(block); err != nil {
						cancel()
						return err
					}
				}
				a.runMu.Lock()
				if run := a.runs[id]; run != nil {
					run.output = append(run.output, block...)
				}
				a.runMu.Unlock()
				return nil
			}, func(block []byte) {
				info := inspectSSEBlock(block)
				if backendID == "" {
					backendID = info.backendID
				}
				if firstToken.token == 0 && info.content != "" {
					firstToken = a.clockNow()
				}
				if len(info.usage) > 0 {
					usageBody = info.usage
				}
				a.runMu.Lock()
				if run := a.runs[id]; run != nil {
					if info.content != "" {
						run.assistant = append(run.assistant, []byte(info.content)...)
					}
					if info.unsafe {
						run.unsafeToolCall = true
					}
				}
				a.runMu.Unlock()
			})
			finishedAt = a.clockNow()
			if requestErr == nil {
				performance = a.measuredPerformance(startedAt, finishedAt, firstToken, usageBody, "gateway_wall_clock_live_stream")
			}
		}
		if requestErr != nil && ctx.Err() != nil && errors.Is(requestErr, context.Canceled) {
			requestErr = ctx.Err()
		}
		a.runMu.Lock()
		if run := a.runs[id]; run != nil {
			run.done = true
			run.err = requestErr
			run.performance = performance
			run.finishedAt = finishedAt.wall
			run.backendID = backendID
			run.status = http.StatusOK
		}
		a.runMu.Unlock()
	}()
	select {
	case startupErr := <-startup:
		if startupErr != nil {
			cancel()
			a.runMu.Lock()
			delete(a.runs, id)
			a.runMu.Unlock()
			a.checkpointMu.Lock()
			delete(a.checkpointRuns, h.ExternalID)
			a.checkpointMu.Unlock()
			return nil, startupErr
		}
		return h, nil
	case <-ctx.Done():
		cancel()
		a.runMu.Lock()
		delete(a.runs, id)
		a.runMu.Unlock()
		a.checkpointMu.Lock()
		delete(a.checkpointRuns, h.ExternalID)
		a.checkpointMu.Unlock()
		return nil, ctx.Err()
	}
}

func executionPerformance(startedAt, finishedAt, firstToken time.Time, response []byte, source string) *domain.ExecutionPerformance {
	firstTokenElapsed := time.Duration(0)
	if !firstToken.IsZero() {
		firstTokenElapsed = firstToken.Sub(startedAt)
	}
	return executionPerformanceWithElapsed(finishedAt.Sub(startedAt), firstTokenElapsed, response, source)
}

// executionPerformanceWithElapsed keeps the elapsed-time seam separate from
// wall timestamps. Production callers pass raw time.Now values above, which
// retain Go's monotonic reading; tests can model wall-clock jumps while
// supplying the stable monotonic elapsed measurements explicitly.
func executionPerformanceWithElapsed(duration, firstTokenElapsed time.Duration, response []byte, source string) *domain.ExecutionPerformance {
	const minimumPerformanceDuration = time.Millisecond
	if duration < minimumPerformanceDuration {
		duration = minimumPerformanceDuration
	}
	seconds := duration.Seconds()
	var body struct {
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(response, &body)
	performance := &domain.ExecutionPerformance{DurationMS: seconds * 1000, PromptTokens: body.Usage.PromptTokens, CompletionTokens: body.Usage.CompletionTokens, TotalTokens: body.Usage.TotalTokens, Source: source}
	if firstTokenElapsed > 0 {
		if firstTokenElapsed > duration {
			firstTokenElapsed = duration
		}
		performance.TTFTMS = firstTokenElapsed.Seconds() * 1000
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
	if a.kind != "llama" || !targetAllowsHTTPModelLifecycle(target) {
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
	if a.kind != "llama" || !targetAllowsHTTPModelLifecycle(target) {
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

// ObserveResidency reads the runtime's post-mutation model listing. This is
// only used by the legacy HTTP lifecycle path; signed node commands derive the
// equivalent result from the node's authoritative local state.
func (a *HTTPAdapter) ObserveResidency(ctx context.Context, target Target, model string) (ResidencyObservation, error) {
	// The legacy observer has no expected-tier argument. An absent router entry
	// is authoritative cold state, while a listed model still reports its
	// observed hot state; manager transitions use ObserveResidencyExpected below
	// when they need to distinguish a load result.
	return a.ObserveResidencyExpected(ctx, target, model, "")
}

// ObserveResidencyExpected validates the runtime listing against the tier the
// manager just requested. llama.cpp's unloaded response legitimately omits a
// model, while a load that omits it is a failed observation rather than an
// inferred success.
func (a *HTTPAdapter) ObserveResidencyExpected(ctx context.Context, target Target, model string, expected domain.ResidencyTier) (ResidencyObservation, error) {
	if a.kind != "llama" || !targetAllowsHTTPModelLifecycle(target) {
		return ResidencyObservation{}, ErrUnsupported
	}
	path := "/v1/models"
	if isOllamaTarget(target) {
		path = "/api/ps"
	}
	body, status, _, err := a.request(ctx, http.MethodGet, strings.TrimRight(target.Endpoint, "/")+path, target.Authorization, nil)
	if err != nil {
		return ResidencyObservation{}, err
	}
	if status < 200 || status >= 300 {
		return ResidencyObservation{}, fmt.Errorf("legacy runtime state returned %d: %s", status, truncate(body, 512))
	}
	state := routerModelUnknown
	var stateErr error
	if isOllamaTarget(target) {
		loaded, known := ollamaModelLoaded(body, model)
		if !known {
			state = routerModelUnknown
		} else if loaded {
			state = routerModelLoadedState
		} else {
			state = routerModelUnloaded
		}
	} else {
		state, stateErr = routerModelLoaded(body, model)
	}
	if stateErr != nil {
		return ResidencyObservation{}, stateErr
	}
	if state == routerModelUnknown {
		if expected != "" && expected != domain.ResidencyColdDisk {
			return ResidencyObservation{}, fmt.Errorf("legacy runtime did not report model %q after expected %s transition", model, expected)
		}
		return ResidencyObservation{}, fmt.Errorf("legacy runtime state for model %q is unknown", model)
	}
	loaded := state == routerModelLoadedState
	if expected == domain.ResidencyColdDisk && loaded {
		return ResidencyObservation{}, fmt.Errorf("legacy runtime still reports model %q loaded after unload", model)
	}
	if expected != "" && expected != domain.ResidencyColdDisk && !loaded {
		return ResidencyObservation{}, fmt.Errorf("legacy runtime reports model %q unloaded after expected %s transition", model, expected)
	}
	tier := domain.ResidencyColdDisk
	if loaded {
		tier = domain.ResidencyHotVRAM
	}
	fence := uint64(1)
	identity := strings.Join([]string{target.ID, target.Adapter, target.RuntimeProtocol, target.CapabilityVersion, target.ModelFingerprint}, "|")
	return ResidencyObservation{TargetID: target.ID, Model: model, RuntimeIdentity: identity, Tier: tier, FencingToken: fence, VRAMReleased: !loaded}, nil
}

// targetAllowsHTTPModelLifecycle retains the pre-residency Ollama/llama.cpp
// advertisement while honoring an explicit versioned capability envelope. An
// envelope that is present is authoritative; an absent envelope is legacy
// compatibility only and cannot be used to infer warm RAM or checkpointing.
func targetAllowsHTTPModelLifecycle(target Target) bool {
	if target.CapabilityRevision != "" && target.CapabilityRevision != domain.CapabilityContractVersion {
		return false
	}
	if target.CapabilityRevision != "" || target.Capabilities.Version != "" {
		if target.CapabilityRevision != domain.CapabilityContractVersion || target.Capabilities.Version != domain.CapabilityContractVersion {
			return false
		}
		return target.Capabilities.SupportsModelLifecycle
	}
	return target.SupportsModelLifecycle
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

// ReclaimAcceleratorObserved frees the managed harness's ComfyUI GPU cache
// and returns the harness's measured post-state, bound to the transition's
// fence. Native ComfyUI cannot do this: its /free reports nothing.
func (a *HTTPAdapter) ReclaimAcceleratorObserved(ctx context.Context, target Target, fencingToken int64) (ResidencyObservation, error) {
	if a.kind != "comfy" || target.RuntimeProtocol != managedComfyProtocol {
		return ResidencyObservation{}, ErrUnsupported
	}
	// Resolve the identity first: no side effect for a result we could not accept.
	identity, _, err := canonicalResidencyIdentity(target, "runtime-cache", false)
	if err != nil {
		return ResidencyObservation{}, err
	}
	payload, _ := json.Marshal(map[string]int64{"fencing_token": fencingToken})
	result, status, _, err := a.request(ctx, http.MethodPost, strings.TrimRight(target.Endpoint, "/")+"/v1/reclaim", target.Authorization, payload)
	if err != nil {
		return ResidencyObservation{}, fmt.Errorf("observation_unavailable: harness reclaim transport: %w", err)
	}
	var observed struct {
		Model        string `json:"model"`
		Tier         string `json:"tier"`
		FencingToken int64  `json:"fencing_token"`
		Error        string `json:"error"`
	}
	_ = json.Unmarshal(result, &observed)
	if status < 200 || status >= 300 {
		return ResidencyObservation{}, fmt.Errorf("harness reclaim returned %d: %s", status, observed.Error)
	}
	if observed.Model != "runtime-cache" || observed.Tier != string(domain.ResidencyColdDisk) || observed.FencingToken != fencingToken || fencingToken <= 0 {
		return ResidencyObservation{}, fmt.Errorf("harness reclaim result lacks the transition's fence or a cold tier")
	}
	return ResidencyObservation{TargetID: target.ID, Model: "runtime-cache", RuntimeIdentity: identity, Tier: domain.ResidencyColdDisk, FencingToken: uint64(fencingToken)}, nil
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
			state, stateErr := routerModelLoaded(body, model)
			if stateErr != nil {
				return fmt.Errorf("router model state is malformed: %w", stateErr)
			}
			if (wantLoaded && state == routerModelLoadedState) || (!wantLoaded && state == routerModelUnloaded) {
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

type routerModelState = wsproto.RouterModelState

const (
	routerModelUnknown     = wsproto.RouterModelUnknown
	routerModelUnloaded    = wsproto.RouterModelUnloaded
	routerModelLoadedState = wsproto.RouterModelLoaded
)

// routerModelLoaded returns an authoritative tri-state. A valid models list
// with no matching entry proves unloaded; transitional entries are unknown
// and must remain in the bounded polling loop. Malformed JSON or envelopes are
// errors and never become an accidental cold result.
func routerModelLoaded(body []byte, wanted string) (routerModelState, error) {
	return wsproto.ParseRouterModelState(body, wanted)
}

func (a *HTTPAdapter) Observe(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, h *domain.ExecutionHandle, target Target) (Observation, error) {
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return a.observeManagedComfy(ctx, h, target)
	}
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
			// A cancelled live segment is resolved by the manager: a preemption
			// keeps the signed checkpoint binding for the next resume, while a
			// client disconnect invokes Adapter.Cancel before releasing the
			// lease.  Cleaning up here races that decision and can erase the
			// original emitter before a queued victim is re-admitted.
			if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
				return Observation{}, runErr
			}
			if releaseErr := a.releaseCheckpointBinding(ctx, h, target); releaseErr != nil {
				return Observation{}, releaseErr
			}
			if terminalErr := a.terminalizeCheckpointHandle(ctx, h, "failed", runErr.Error()); terminalErr != nil {
				return Observation{}, fmt.Errorf("checkpoint terminalization failed: %w", terminalErr)
			}
			a.clearCheckpointBinding(h)
			return Observation{}, runErr
		}
		// A streamed run's output is the raw SSE text, not JSON: storing it as
		// the handle's json.RawMessage made the terminal workload row
		// unmarshalable, so PostgreSQL never recorded the stream as finished.
		// The stream's handle keeps its own binding document instead.
		if json.Valid(output) {
			h.Opaque = output
		}
		if performance != nil {
			copy := *performance
			h.Performance = &copy
		}
		// A normally completed resumed conversation has already committed the
		// reuse proof.  It needs the signed release boundary, not a second cancel
		// against a backend that has reached EOF.  Client cancellation and a
		// backend failure still use the cancel-first compensation path below.
		if releaseErr := a.releaseCheckpointBindingMode(ctx, h, target, false); releaseErr != nil {
			return Observation{}, releaseErr
		}
		if terminalErr := a.terminalizeCheckpointHandle(ctx, h, "completed", ""); terminalErr != nil {
			return Observation{}, fmt.Errorf("checkpoint terminalization failed: %w", terminalErr)
		}
		a.clearCheckpointBinding(h)
		return Observation{Status: domain.WorkloadSucceeded, Progress: 1}, nil
	}
	if a.kind != "comfy" {
		return Observation{Status: domain.WorkloadSucceeded, Progress: 1}, nil
	}
	result, status, _, err := a.request(ctx, http.MethodGet, strings.TrimRight(target.Endpoint, "/")+"/history/"+h.ExternalID, target.Authorization, nil)
	if err != nil {
		return Observation{}, &BackendError{TargetID: target.ID, Retryable: true, RetryAfter: 5 * time.Second, Message: "Comfy history transport failed: " + err.Error(), Cause: err}
	}
	if status < 200 || status >= 300 {
		return Observation{}, &BackendError{TargetID: target.ID, Status: status, Retryable: status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500, RetryAfter: 5 * time.Second, Message: fmt.Sprintf("Comfy history returned %d", status)}
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

// clearCheckpointBinding is called only after the backend reached a terminal
// state.  Until then both the operation record and the original emitter are
// retained so a preempted stream can be resumed exactly once.
func (a *HTTPAdapter) clearCheckpointBinding(h *domain.ExecutionHandle) {
	if a == nil || h == nil {
		return
	}
	a.checkpointMu.Lock()
	defer a.checkpointMu.Unlock()
	if execution, ok := a.checkpointRuns[h.ExternalID]; ok {
		if execution.OperationID != "" {
			delete(a.checkpointEmitters, execution.OperationID)
		}
	}
	delete(a.checkpointRuns, h.ExternalID)
}

func (a *HTTPAdapter) terminalizeCheckpointHandle(ctx context.Context, h *domain.ExecutionHandle, phase, message string) error {
	if a == nil || h == nil {
		return nil
	}
	a.checkpointMu.Lock()
	execution := a.checkpointRuns[h.ExternalID]
	coordinator := a.checkpoint
	a.checkpointMu.Unlock()
	if execution.OperationID == "" {
		var binding struct {
			OperationID string `json:"operation_id"`
		}
		if json.Unmarshal(h.Opaque, &binding) == nil {
			execution.OperationID = binding.OperationID
		}
	}
	if coordinator != nil && execution.OperationID != "" {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), leaseCleanupTimeout)
		defer cleanupCancel()
		return coordinator.TerminalizeOperation(cleanupCtx, execution.OperationID, phase, message)
	}
	return nil
}

// releaseCheckpointBinding closes the signed node-side ownership before the
// controller drops its stream binding. A completed initial stream uses a
// read-only slot query as the stop/idle confirmation; a resumed stream first
// issues its legal cancel transition so the exact conversation is drained.
func (a *HTTPAdapter) releaseCheckpointBinding(ctx context.Context, h *domain.ExecutionHandle, target Target) error {
	return a.releaseCheckpointBindingMode(ctx, h, target, true)
}

func (a *HTTPAdapter) releaseCheckpointBindingMode(ctx context.Context, h *domain.ExecutionHandle, target Target, cancelResumed bool) error {
	if a == nil || h == nil {
		return nil
	}
	a.checkpointMu.Lock()
	resolver := a.checkpointResolver
	execution, tracked := a.checkpointRuns[h.ExternalID]
	a.checkpointMu.Unlock()
	if resolver == nil {
		// Ordinary live streams do not own a signed node slot.  A resumed or
		// lease-aware stream does; silently treating a missing control channel as
		// a successful cleanup would strand that physical slot and allow a
		// later admission to overcommit it.
		if tracked && execution.OperationID != "" && execution.Lease.SlotID >= 0 {
			return ErrCheckpointUnavailable
		}
		return nil
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), leaseCleanupTimeout)
	defer cleanupCancel()
	var binding struct {
		SlotID         int    `json:"slot_id"`
		Generation     uint64 `json:"generation"`
		Fence          uint64 `json:"fence"`
		AcceleratorID  string `json:"accelerator_id"`
		ConversationID string `json:"conversation_id"`
		OperationID    string `json:"operation_id"`
		OwnerID        string `json:"owner_id"`
		WorkloadID     string `json:"workload_id"`
		SnapshotName   string `json:"snapshot_name"`
		Resumed        bool   `json:"resumed"`
	}
	if err := json.Unmarshal(h.Opaque, &binding); err != nil || binding.SlotID < 0 || binding.OperationID == "" {
		// Observe stores the final stream payload in h.Opaque. Preserve the
		// immutable lease binding in checkpointRuns so terminal success/failure
		// still performs the signed stop/release path.
		if !tracked {
			return fmt.Errorf("checkpoint cleanup binding is unavailable")
		}
		if execution.OperationID == "" || execution.Lease.SlotID < 0 {
			return nil
		}
		binding.SlotID = execution.Lease.SlotID
		binding.Generation = execution.Lease.Generation
		binding.Fence = execution.Lease.Fence
		binding.AcceleratorID = execution.Lease.AcceleratorID
		binding.ConversationID = execution.ConversationID
		binding.OperationID = execution.OperationID
		binding.Resumed = execution.Resumed
	}
	if !tracked {
		// A restarted controller has no in-memory checkpointRuns entry, but the
		// durable execution handle still carries the exact owner/workload tuple
		// needed for a signed cancel/release. Reconstruct only this immutable
		// binding; never infer a slot from target defaults.
		execution = checkpointExecution{Request: domain.WorkloadRequest{ID: binding.WorkloadID, OwnerID: binding.OwnerID}, Target: target, OperationID: binding.OperationID, Lease: SlotLease{TargetID: target.ID, NodeID: target.NodeID, AcceleratorID: binding.AcceleratorID, SlotID: binding.SlotID, OwnerID: binding.OwnerID, WorkloadID: binding.WorkloadID, Generation: binding.Generation, Fence: binding.Fence}, Resumed: binding.Resumed, ConversationID: binding.ConversationID, OperationConversationID: binding.ConversationID, SnapshotName: binding.SnapshotName}
	}
	control, nodeID, ok := resolver(cleanupCtx, target)
	if !ok {
		return ErrCheckpointUnavailable
	}
	model, profile, contextLimit := target.ModelFingerprint, "", target.ContextLimit
	if execution.Plan != nil {
		if execution.Plan.ModelFingerprint != "" {
			model = execution.Plan.ModelFingerprint
		}
		profile = execution.Plan.ProfileDigest
		if execution.Plan.TargetContextLimit > 0 {
			contextLimit = execution.Plan.TargetContextLimit
		}
	}
	base := map[string]any{
		"target_kind": "llamacpp", "target_id": target.ID, "accelerator_id": binding.AcceleratorID,
		"slot_id": binding.SlotID, "model": model, "runtime_identity": target.RuntimeIdentity,
		"capability_version": target.CapabilityVersion, "capability_revision": target.CapabilityRevision,
		"profile_fingerprint": profile, "context_fingerprint": fmt.Sprintf("ctx:%d", contextLimit),
		"context_limit": contextLimit, "owner_id": execution.Request.OwnerID, "workload_id": execution.Request.ID,
		"generation": binding.Generation, "fencing_token": binding.Fence, "checkpoint_operation_id": binding.OperationID,
		"conversation_id": binding.ConversationID,
	}
	// The initial native stream is journaled against its original conversation;
	// it has no continuation identity until a restore/resume transition.  Do
	// not manufacture one for the terminal read-only query: node-side identity
	// checks are intentionally exact, and an invented continuation would make a
	// successful normal stream look like a runtime identity change.  Resumed
	// streams, by contrast, have an explicit continuation in their durable
	// phase journal and must carry it through query/cancel/release.
	if binding.Resumed {
		base["continuation_conversation_id"] = "continuation-" + binding.OperationID
	}
	if binding.Resumed && execution.OperationConversationID != "" {
		// The phase journal keeps the original conversation identity while the
		// live handle carries the continuation conversation used by the resumed
		// HTTP stream. Read-only stop/release queries must address the journaled
		// identity; the cancel path overrides this below with the live ID.
		base["conversation_id"] = execution.OperationConversationID
	}
	if binding.Resumed && cancelResumed {
		// The cancel phase binds the node journal to the live resumed
		// conversation; its following release must carry that same identity.
		base["conversation_id"] = binding.ConversationID
	}
	if binding.Resumed && execution.SnapshotName != "" {
		base["snapshot_name"] = execution.SnapshotName
	}
	var cleanupErrs []error
	if binding.Resumed && cancelResumed {
		args := cloneArgs(base)
		args["conversation_id"] = binding.ConversationID
		args["checkpoint_action"] = "cancel"
		args["compensation_of"] = binding.OperationID
		args["idempotency_key"] = binding.OperationID + ":terminal-cancel"
		if _, err := control(cleanupCtx, nodeID, "checkpoint_cancel", args, args["idempotency_key"].(string)); err != nil {
			return fmt.Errorf("checkpoint cancel (stop unconfirmed): %w", err)
		}
	} else {
		query := cloneArgs(base)
		query["checkpoint_action"] = "state_query"
		query["idempotency_key"] = binding.OperationID + ":terminal-query"
		if _, err := control(cleanupCtx, nodeID, "checkpoint_state_query", query, query["idempotency_key"].(string)); err != nil {
			return fmt.Errorf("checkpoint stop confirmation failed (stop unconfirmed): %w", err)
		}
	}
	release := cloneArgs(base)
	release["checkpoint_action"] = "release"
	release["idempotency_key"] = binding.OperationID + ":terminal-release"
	if _, err := control(cleanupCtx, nodeID, "checkpoint_release", release, release["idempotency_key"].(string)); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("checkpoint release: %w", err))
	}
	if len(cleanupErrs) > 0 {
		return errors.Join(cleanupErrs...)
	}
	if !binding.Resumed {
		if coordinator := a.checkpoint; coordinator != nil && execution.OperationID != "" && coordinator.Operations != nil {
			op, getErr := coordinator.Operations.GetLLMCheckpointOperation(cleanupCtx, execution.OperationID)
			if getErr != nil {
				return getErr
			}
			command := CheckpointCommand{ID: op.ID, IdempotencyKey: op.IdempotencyKey, OwnerID: op.OwnerID, WorkloadID: op.WorkloadID, Generation: op.Generation, Fence: op.Fence, RuntimeIdentity: op.RuntimeIdentity, ModelFingerprint: op.ModelFingerprint, ProfileFingerprint: op.ProfileFingerprint, ContextLimit: contextLimit, ConversationID: op.ConversationID, ContinuationConversationID: op.ContinuationConversationID, CompensationOf: op.CompensationOf, WorkloadRevision: op.WorkloadRevision, SnapshotDigest: op.SnapshotDigest}
			lease := execution.Lease
			lease.TargetID, lease.NodeID, lease.AcceleratorID = op.TargetID, op.NodeID, op.AcceleratorID
			lease.OwnerID, lease.WorkloadID, lease.Generation, lease.Fence = op.OwnerID, op.WorkloadID, op.Generation, op.Fence
			lease.RuntimeIdentity, lease.ModelFingerprint, lease.ProfileFingerprint, lease.ContextLimit = op.RuntimeIdentity, op.ModelFingerprint, op.ProfileFingerprint, contextLimit
			if op.Phase != "stopped" && op.Phase != "released" && op.Phase != "completed" && op.Phase != "failed" && op.Phase != "cancelled" {
				if phaseErr := coordinator.RecordOperationPhase(cleanupCtx, command, lease, "stopped"); phaseErr != nil {
					return phaseErr
				}
			}
			if op.Phase != "released" && op.Phase != "completed" && op.Phase != "failed" && op.Phase != "cancelled" {
				if phaseErr := coordinator.RecordOperationPhase(cleanupCtx, command, lease, "released"); phaseErr != nil {
					return phaseErr
				}
			}
		}
	}
	return nil
}

func cloneArgs(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src)+3)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (a *HTTPAdapter) Yield(ctx context.Context, h *domain.ExecutionHandle, target Target) error {
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return a.controlManagedComfy(ctx, h, target, "yield", "yielded")
	}
	return ErrUnsupported
}
func (a *HTTPAdapter) Checkpoint(ctx context.Context, h *domain.ExecutionHandle, target Target) (string, error) {
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return a.checkpointManagedComfy(ctx, h, target)
	}
	if a.kind == "llama" {
		return "", ErrUnsupported // scheduler must use CheckpointWithLease
	}
	return "", ErrUnsupported
}

// CheckpointWithLease is the only native LLM checkpoint entrypoint. The
// scheduler supplies the authoritative lease and target generation; no
// adapter fallback can invent authority.
func (a *HTTPAdapter) CheckpointWithLease(ctx context.Context, h *domain.ExecutionHandle, target Target, lease SlotLease, command CheckpointCommand) (string, error) {
	if a.kind != "llama" || h == nil {
		return "", ErrUnsupported
	}
	a.checkpointMu.Lock()
	coordinator := a.checkpoint
	resolver := a.checkpointResolver
	a.checkpointMu.Unlock()
	if coordinator == nil || resolver == nil {
		return "", ErrUnsupported
	}
	a.checkpointMu.Lock()
	proof, proofOK := a.checkpointProofs[target.ID]
	a.checkpointMu.Unlock()
	if !proofOK || !proof.Complete() || !coordinator.ReadyForTarget(target, command.ModelFingerprint, command.ProfileFingerprint, command.ContextLimit, 0) {
		return "", ErrCheckpointUnavailable
	}
	control, nodeID, ok := resolver(ctx, target)
	if !ok {
		return "", ErrCheckpointUnavailable
	}
	lease.NodeID = nodeID
	if h != nil && len(h.Opaque) > 0 {
		var binding struct {
			SlotID         int    `json:"slot_id"`
			ConversationID string `json:"conversation_id"`
			AcceleratorID  string `json:"accelerator_id"`
			OperationID    string `json:"operation_id"`
		}
		if json.Unmarshal(h.Opaque, &binding) == nil {
			if binding.SlotID >= 0 {
				lease.SlotID = binding.SlotID
			}
			if binding.AcceleratorID != "" {
				lease.AcceleratorID = binding.AcceleratorID
			}
			// Slot assignment and all later phases share one durable operation
			// identity and accelerator fence. A fresh checkpoint id here would
			// be rejected as an equal-fence different operation by the node.
			if binding.OperationID != "" {
				command.ID = binding.OperationID
				command.IdempotencyKey = binding.OperationID
			}
			lease.SlotAssigned = binding.SlotID >= 0
			command.ConversationID = binding.ConversationID
		}
	}
	if command.ConversationID == "" {
		if strings.TrimSpace(target.Endpoint) == "" {
			command.ConversationID = "compat-" + command.ID
		} else {
			return "", fmt.Errorf("checkpoint requires a bound stream conversation")
		}
	}
	if command.ContinuationConversationID == "" {
		// Compensation and the successful resume both use the upstream
		// conversation protocol; never fall back to the removed action=stop
		// or legacy resume seam for a live production stream.
		command.ContinuationConversationID = "continuation-" + command.ID
	}
	// A live stream's workload projection advances for progress, telemetry, and
	// client lifecycle writes after its checkpoint operation is created. The
	// operation's original WorkloadRevision is immutable replay identity; using
	// the latest projection revision here would make a legitimate preemption
	// look like a stale/fenced command. Resolve that durable identity before the
	// coordinator replays the started row.
	if coordinator.Operations != nil {
		op, getErr := coordinator.Operations.GetLLMCheckpointOperation(ctx, command.ID)
		if getErr != nil {
			return "", fmt.Errorf("checkpoint operation identity lookup failed: %w", getErr)
		}
		if op.OwnerID != command.OwnerID || op.WorkloadID != command.WorkloadID || op.Generation != command.Generation || op.Fence != command.Fence || op.RuntimeIdentity != command.RuntimeIdentity || op.ModelFingerprint != command.ModelFingerprint || op.ProfileFingerprint != command.ProfileFingerprint {
			return "", ErrCheckpointConflict
		}
		command.WorkloadRevision = op.WorkloadRevision
		command.ConversationID = op.ConversationID
		command.ContinuationConversationID = op.ContinuationConversationID
	}
	if command.SnapshotName == "" {
		sum := sha256.Sum256([]byte(command.OwnerID + "|" + command.WorkloadID + "|" + fmt.Sprint(command.Generation)))
		command.SnapshotName = "slot-" + hex.EncodeToString(sum[:12]) + ".kv"
	}
	command = withCheckpointConversation(command)
	var prefix, assistant []byte
	if h != nil {
		a.runMu.Lock()
		if run := a.runs[h.ExternalID]; run != nil {
			prefix = append([]byte(nil), run.output...)
			assistant = append([]byte(nil), run.assistant...)
		}
		a.runMu.Unlock()
	}
	nodeRuntime := &NodeCheckpointRuntime{Control: control, NodeID: nodeID, Target: target, Command: command, OutputPrefix: prefix, AssistantContent: assistant, AssignedSlotID: -1, OutputSnapshot: func() ([]byte, []byte) {
		if h == nil {
			return nil, nil
		}
		a.runMu.Lock()
		defer a.runMu.Unlock()
		if run := a.runs[h.ExternalID]; run != nil {
			return append([]byte(nil), run.output...), append([]byte(nil), run.assistant...)
		}
		return nil, nil
	}, UnsafeToolCall: func() bool {
		if h == nil {
			return false
		}
		a.runMu.Lock()
		defer a.runMu.Unlock()
		if run := a.runs[h.ExternalID]; run != nil {
			return run.unsafeToolCall
		}
		return false
	}}
	checkpoint, err := coordinator.CheckpointWithRuntimeProof(ctx, command, lease, nodeRuntime, proof)
	return checkpoint, err
}
func (a *HTTPAdapter) Resume(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, checkpoint string, target Target) (*domain.ExecutionHandle, error) {
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return a.startManagedComfy(ctx, req, plan, target, checkpoint)
	}
	if a.kind == "llama" {
		return nil, ErrUnsupported // scheduler must use ResumeWithLease
	}
	return nil, ErrUnsupported
}

func (a *HTTPAdapter) ResumeWithLease(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, checkpoint string, target Target, lease SlotLease, command CheckpointCommand) (*domain.ExecutionHandle, error) {
	if a.kind != "llama" {
		return nil, ErrUnsupported
	}
	a.checkpointMu.Lock()
	coordinator := a.checkpoint
	resolver := a.checkpointResolver
	a.checkpointMu.Unlock()
	if coordinator == nil || resolver == nil {
		return nil, ErrUnsupported
	}
	a.checkpointMu.Lock()
	proof, proofOK := a.checkpointProofs[target.ID]
	a.checkpointMu.Unlock()
	if !proofOK || !proof.Complete() || !coordinator.ReadyForTarget(target, command.ModelFingerprint, command.ProfileFingerprint, command.ContextLimit, 0) {
		return nil, ErrCheckpointUnavailable
	}
	control, nodeID, ok := resolver(ctx, target)
	if !ok {
		return nil, ErrCheckpointUnavailable
	}
	lease.NodeID = nodeID
	command = withCheckpointConversation(command)
	// Bind the restore operation to the exact ownership manifest.  The node
	// release command needs this name even after reuse has terminalized the
	// resumable reference; omitting it turns a harmless idempotent release into
	// an ambiguous warm-state cleanup failure.
	command.SnapshotName = checkpoint
	// Recover the original stream's delivery binding before physical restore.
	// This keeps resumed suffix delivery on the same client-owned emitter.
	var resumeEmit func([]byte) error
	var sourceExecutionID string
	a.checkpointMu.Lock()
	for externalID, execution := range a.checkpointRuns {
		if execution.Request.ID == req.ID && execution.Emit != nil {
			resumeEmit = execution.Emit
			sourceExecutionID = externalID
			break
		}
	}
	if resumeEmit == nil {
		resumeEmit = a.checkpointEmitters[command.ID]
	}
	a.checkpointMu.Unlock()
	var priorStreamOutput []byte
	if sourceExecutionID != "" {
		a.runMu.Lock()
		if run := a.runs[sourceExecutionID]; run != nil {
			priorStreamOutput = append(priorStreamOutput, run.output...)
		}
		a.runMu.Unlock()
	}
	command.ContinuationConversationID = "continuation-" + command.ID
	partial := coordinator.OutputForSnapshot(req.OwnerID, checkpoint)
	savedTokens := partial.TokenCount
	if coordinator.Store != nil {
		if _, metadata, metadataErr := coordinator.Store.Get(req.OwnerID, checkpoint); metadataErr == nil && metadata.KVTokens > 0 {
			savedTokens = metadata.KVTokens
		}
	}
	if partial.UnsafeToolCall || bytes.Contains(partial.AssistantContent, []byte(`"tool_calls"`)) || bytes.Contains(partial.AssistantContent, []byte(`"function_call"`)) {
		return nil, fmt.Errorf("checkpoint continuation contains unsupported tool-call content")
	}
	nodeRuntime := &NodeCheckpointRuntime{Control: control, NodeID: nodeID, Target: target, Command: command, AssignedSlotID: -1}
	cleanupResumed := func(handle *domain.ExecutionHandle, assigned SlotLease) error {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), leaseCleanupTimeout)
		defer cleanupCancel()
		if handle != nil {
			// The handle carries the same operation key and emitter binding used
			// by the public stream. Cancel owns the resumed conversation and
			// performs the exact-key cancel/release pair. During the narrow window
			// before the controller publishes that handle, its opaque lease binding
			// may not exist yet; fall through to the runtime's signed cleanup path
			// rather than treating an unbound local cancel as sufficient.
			var binding struct {
				SlotID      int    `json:"slot_id"`
				OperationID string `json:"operation_id"`
			}
			if json.Unmarshal(handle.Opaque, &binding) == nil && binding.SlotID >= 0 && strings.TrimSpace(binding.OperationID) != "" {
				return a.Cancel(cleanupCtx, handle, target)
			}
		}
		var cleanupErrs []error
		// Resume may have been accepted even when its response was lost. A
		// signed cancel is the authoritative stop boundary. Never issue release
		// after a cancel failure: the node may still own a live generation, and
		// releasing its slot would make that generation overlap a later owner.
		if cancelErr := nodeRuntime.Cancel(cleanupCtx, assigned); cancelErr != nil {
			return fmt.Errorf("resumed cancel (stop unconfirmed): %w", cancelErr)
		}
		if releaseErr := nodeRuntime.ReleaseSlot(cleanupCtx, assigned); releaseErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("resumed release: %w", releaseErr))
		}
		return errors.Join(cleanupErrs...)
	}
	assignedLease := lease
	if err := coordinator.RestoreWithRuntimeProof(ctx, command, lease, checkpoint, nodeRuntime, proof); err != nil {
		if nodeRuntime.AssignedSlotID >= 0 {
			assignedLease.SlotID = nodeRuntime.AssignedSlotID
		}
		return nil, errors.Join(err, cleanupResumed(nil, assignedLease))
	}
	if nodeRuntime.AssignedSlotID >= 0 {
		assignedLease.SlotID = nodeRuntime.AssignedSlotID
	}
	// Physical restore is complete, but no continuation/reuse claim exists yet.
	// Bind the signed continuation conversation first, then open the one client
	// stream that owns delivery to the original emitter.
	if err := nodeRuntime.Resume(ctx, assignedLease, partial); err != nil {
		return nil, errors.Join(err, cleanupResumed(nil, assignedLease))
	}
	// PartialOutput.Prefix is the runtime's assistant-token prefix, while the
	// live handle's output is the raw SSE already sent to the client.  Resume
	// bookkeeping must retain the latter; feeding token bytes into the SSE
	// buffer would make a subsequent checkpoint's internal output malformed.
	stitchedPrefix := priorStreamOutput
	payloadSource := req.Payload
	if plan != nil && len(plan.Material) > 0 {
		payloadSource = plan.Material
	}
	if len(bytes.TrimSpace(payloadSource)) == 0 {
		payloadSource = []byte(`{}`)
	}
	var body map[string]any
	if err := json.Unmarshal(payloadSource, &body); err != nil {
		return nil, errors.Join(err, cleanupResumed(nil, assignedLease))
	}
	body["stream"] = true
	body["stream_options"] = map[string]any{"include_usage": true}
	body["id_slot"] = assignedLease.SlotID
	body["cache_prompt"] = true
	if len(partial.AssistantContent) > 0 {
		// Tool-call continuations cannot safely be reconstructed from a raw
		// assistant byte prefix; fail closed instead of duplicating a call.
		if partial.UnsafeToolCall || bytes.Contains(partial.AssistantContent, []byte(`"tool_calls"`)) || bytes.Contains(partial.AssistantContent, []byte(`"function_call"`)) {
			return nil, errors.Join(fmt.Errorf("checkpoint continuation contains unsupported tool-call content"), cleanupResumed(nil, assignedLease))
		}
		messages, ok := body["messages"].([]any)
		if !ok {
			return nil, errors.Join(fmt.Errorf("checkpoint continuation requires a messages array"), cleanupResumed(nil, assignedLease))
		}
		body["messages"] = append(messages, map[string]any{"role": "assistant", "content": string(partial.AssistantContent)})
		body["continue_final_message"] = true
	}
	delete(body, "governor")
	if a.kind == "openrouter" && target.Provider != "" {
		body["provider"] = map[string]any{"order": []string{target.Provider}, "allow_fallbacks": false}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, errors.Join(err, cleanupResumed(nil, assignedLease))
	}
	// Restore has completed through the signed node channel. The returned
	// handle now belongs to a real continuation goroutine and is observable /
	// cancellable immediately; no synthetic restored-* state is created.
	conversationID := nodeRuntime.LastResumeID
	if conversationID == "" {
		conversationID = command.ContinuationConversationID
	}
	if conversationID == "" {
		conversationID = "resume-" + command.ID
	}
	slotID := nodeRuntime.AssignedSlotID
	if slotID < 0 {
		slotID = lease.SlotID
	}
	h, err := a.startLiveStream(ctx, req, plan, target, payload, resumeEmit, stitchedPrefix, slotID, conversationID, &partial)
	if err != nil {
		return nil, errors.Join(err, cleanupResumed(nil, assignedLease))
	}
	// Publish the immutable lease binding before the continuation command. The
	// backend goroutine can emit immediately; publishing first closes the
	// disconnect race in which a client drops the response while the signed
	// continue result is still in flight.
	a.checkpointMu.Lock()
	if execution := a.checkpointRuns[h.ExternalID]; execution.Target.ID != "" {
		execution.OperationID = command.ID
		execution.SnapshotName = checkpoint
		execution.Emit = resumeEmit
		execution.Lease = assignedLease
		execution.Resumed = true
		execution.OperationConversationID = command.ConversationID
		execution.ConversationID = conversationID
		a.checkpointRuns[h.ExternalID] = execution
	}
	a.checkpointMu.Unlock()
	h.Opaque, _ = json.Marshal(map[string]any{"slot_id": slotID, "accelerator_id": lease.AcceleratorID, "generation": lease.Generation, "fence": lease.Fence, "conversation_id": conversationID, "operation_id": command.ID, "node_id": nodeID, "owner_id": command.OwnerID, "workload_id": command.WorkloadID, "snapshot_name": checkpoint, "resumed": true})
	// The HTTP response above is the actual resumed generation. Commit the
	// signed node phase only after that response is live, so reuse evidence is
	// attributable to this exact conversation and no second generation is
	// launched by the node.
	// The continuation command is the durable handoff between restore and the
	// real HTTP stream.  A client disconnect may cancel the segment context
	// immediately after the backend starts; still wait for the signed node
	// result so a later cancel cannot remain queued behind an unresolved
	// `checkpoint_continue` command.
	if err := nodeRuntime.ContinueControllerStream(context.WithoutCancel(ctx), assignedLease, conversationID, partial.AssistantContent); err != nil {
		return nil, errors.Join(err, cleanupResumed(h, assignedLease))
	}
	// Wait briefly for usage from this exact resumed conversation. A missing
	// or unrelated slot counter is a hard failure; cancel and release before
	// returning so the restored victim is never silently stranded.
	var reused int
	var reuseErr error
	deadline := time.Now().Add(3 * time.Second)
	// A bare break inside the select below only left the select: once ctx was
	// cancelled every pass returned at once and the loop spun until the
	// deadline, sending a node command per pass.
verifyReuse:
	for time.Now().Before(deadline) {
		reused, reuseErr = nodeRuntime.VerifyKVReuse(ctx, assignedLease, savedTokens)
		if reuseErr == nil && reused > 0 {
			break
		}
		select {
		case <-ctx.Done():
			reuseErr = ctx.Err()
			break verifyReuse
		case <-time.After(50 * time.Millisecond):
		}
	}
	if reuseErr != nil || reused <= 0 {
		if reuseErr == nil {
			reuseErr = fmt.Errorf("resumed conversation did not report attributable KV reuse")
		}
		return nil, errors.Join(reuseErr, cleanupResumed(h, assignedLease))
	}
	if coordinator.Operations != nil {
		if err := coordinator.FinalizeRestoreContinuation(ctx, command, assignedLease, checkpoint, partial, reused); err != nil {
			return nil, errors.Join(err, cleanupResumed(h, assignedLease))
		}
	}
	return h, nil
}

func (a *HTTPAdapter) Cancel(ctx context.Context, h *domain.ExecutionHandle, target Target) error {
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return a.cancelManagedComfy(ctx, h, target)
	}
	if a.kind == "llama" && h != nil && strings.HasPrefix(h.ExternalID, "http-run-") {
		a.runMu.Lock()
		run := a.runs[h.ExternalID]
		if run == nil {
			a.runMu.Unlock()
			// A restarted controller may retain only the durable handle. The
			// signed node cancel/release path can still fence that exact resumed
			// conversation; without that path, do not fall back to declaring the
			// backend stopped or the slot absent.  The manager must retain a
			// failed/non-duplicated terminal outcome until a later authoritative
			// reconciliation rather than re-admitting an unconfirmed execution.
			a.checkpointMu.Lock()
			resolverAvailable := a.checkpointResolver != nil
			a.checkpointMu.Unlock()
			if !resolverAvailable {
				return fmt.Errorf("durable LLM execution state cannot be confirmed: checkpoint control unavailable")
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), leaseCleanupTimeout)
			defer cleanupCancel()
			if err := a.releaseCheckpointBinding(cleanupCtx, h, target); err != nil {
				return fmt.Errorf("durable LLM execution cleanup failed: %w", err)
			}
			if err := a.terminalizeCheckpointHandle(cleanupCtx, h, "cancelled", "cancelled during controller recovery"); err != nil {
				return err
			}
			a.clearCheckpointBinding(h)
			return nil
		}
		cancel := run.cancel
		done := run.done
		a.runMu.Unlock()
		a.checkpointMu.Lock()
		_, tracked := a.checkpointRuns[h.ExternalID]
		a.checkpointMu.Unlock()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), leaseCleanupTimeout)
		defer cleanupCancel()
		if !done {
			// Cancellation of a checkpointable stream is a node-owned mutation:
			// the signed pause command issues DELETE /v1/stream and confirms the
			// bound slot before local resources are released.
		}
		if tracked {
			if releaseErr := a.releaseCheckpointBinding(cleanupCtx, h, target); releaseErr != nil {
				return releaseErr
			}
		}
		if cancel != nil && !done {
			cancel()
		}
		for !done {
			select {
			case <-cleanupCtx.Done():
				return fmt.Errorf("checkpoint cancellation did not reach a terminal backend state: %w", cleanupCtx.Err())
			case <-time.After(25 * time.Millisecond):
				a.runMu.Lock()
				run = a.runs[h.ExternalID]
				done = run == nil || run.done
				a.runMu.Unlock()
			}
		}
		if terminalErr := a.terminalizeCheckpointHandle(cleanupCtx, h, "cancelled", "cancelled by client"); terminalErr != nil {
			return terminalErr
		}
		a.clearCheckpointBinding(h)
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
	if a.kind == "comfy" && target.RuntimeProtocol == managedComfyProtocol {
		return a.collectManagedComfyOutputs(ctx, req, plan, h, target)
	}
	if a.kind == "comfy" && a.artifacts != nil && len(h.Opaque) > 0 {
		return a.collectComfyOutputs(ctx, req, plan, h.Opaque, target)
	}
	if a.kind == "llama" && strings.HasPrefix(h.ExternalID, "http-run-") {
		a.runMu.Lock()
		var output json.RawMessage
		if run := a.runs[h.ExternalID]; run != nil {
			output = append(json.RawMessage(nil), run.output...)
		}
		delete(a.runs, h.ExternalID)
		a.runMu.Unlock()
		if len(output) > 0 {
			return output, nil, nil
		}
	}
	return append(json.RawMessage(nil), h.Opaque...), nil, nil
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

func (a *HTTPAdapter) collectComfyOutputs(ctx context.Context, req domain.WorkloadRequest, plan *domain.ExecutionPlan, raw json.RawMessage, target Target) (json.RawMessage, []string, error) {
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
			if kind, _ := typed["type"].(string); hasFilename && kind == "input" {
				// Load nodes (e.g. LoadVideo) echo the request's own staged
				// inputs into the history; they are not results.
				return nil
			}
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
					var artifact *domain.Artifact
					if profile, ok := profileForPlan(target, plan); req.Plane == domain.PlaneCreatorStudio && ok {
						if !MediaTypeMatches(profile.ProducedArtifactTypes, mediaType) {
							response.Body.Close()
							return fmt.Errorf("Comfy output media type %q is not declared by %s", mediaType, profile.Ref())
						}
						options, optionsErr := artifactPutOptions(req, plan, profile, filepath.Base(filename), mediaType)
						if optionsErr != nil {
							response.Body.Close()
							return optionsErr
						}
						artifact, err = a.artifacts.PutWithMetadata(ctx, options, response.Body)
					} else {
						artifact, err = a.artifacts.Put(ctx, req.OwnerID, req.ID, filepath.Base(filename), mediaType, response.Body)
					}
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
