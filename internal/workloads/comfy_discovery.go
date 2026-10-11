package workloads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"vram-governor/internal/domain"
)

const (
	comfyObjectInfoLimit = 64 << 20
	comfyStatsLimit      = 1 << 20
	comfyFetchTimeout    = 5 * time.Second
	comfyFleetTimeout    = 10 * time.Second
	comfyMaxTargets      = 32
	comfyMaxConcurrent   = 4
)

var errComfyDiscoveryUnavailable = errors.New("Comfy discovery unavailable")

type ComfyDiscoveryTarget struct {
	Target     Target
	Generation uint64
	client     *http.Client
}

type ComfyDiscoveryResult struct {
	ObjectInfo map[string]json.RawMessage
	Devices    []map[string]any
	Conflicts  []string
	Available  int
}

type comfySourceResult struct {
	target ComfyDiscoveryTarget
	info   map[string]json.RawMessage
	stats  map[string]any
	err    error
}

// ComfyDiscoveryTargets snapshots immutable route facts and generation before
// doing any node-store or network work. Credentials remain in this package.
func (m *Manager) ComfyDiscoveryTargets(ctx context.Context, egress string) ([]ComfyDiscoveryTarget, error) {
	m.mu.RLock()
	snapshot := make([]ComfyDiscoveryTarget, 0, len(m.targets))
	for _, target := range m.targets {
		if target.Adapter != "comfy" || !target.Enabled || target.Quarantined || strings.TrimSpace(target.Endpoint) == "" {
			continue
		}
		copyTarget := cloneComfyTarget(target)
		client := http.DefaultClient
		if adapter, ok := m.adapters[target.Adapter].(*HTTPAdapter); ok && adapter.client != nil {
			client = adapter.client
		}
		clientCopy := copyComfyHTTPClient(client)
		snapshot = append(snapshot, ComfyDiscoveryTarget{Target: copyTarget, Generation: m.targetGenerations[target.ID], client: clientCopy})
	}
	m.mu.RUnlock()
	for i := range snapshot {
		m.providerMu.Lock()
		circuit := m.providerCircuits[snapshot[i].Target.ID]
		m.providerMu.Unlock()
		if circuit.OpenUntil.After(time.Now()) {
			snapshot[i].Target.CircuitState = "open"
		}
	}
	out := snapshot[:0]
	for _, source := range snapshot {
		t := source.Target
		if source.Generation == 0 || t.CircuitState == "open" || (t.Cloud && egress == string(domain.EgressLocalOnly)) || !validComfyEndpoint(t.Endpoint) {
			continue
		}
		if t.NodeID != "" {
			if m.nodes == nil { continue }
			node, err := m.nodes.GetNode(ctx, t.NodeID)
			if err != nil || node == nil || node.Observed.Connectivity != domain.ConnectivityConnected || !node.Observed.Ready || node.SchedulingState != domain.SchedulingEnabled || !node.Desired.SchedulingEnabled {
				continue
			}
			acceleratorFound := false
			for _, accelerator := range node.Accelerators {
				if accelerator.ID == t.AcceleratorID && accelerator.ID != "" {
					acceleratorFound = true
					break
				}
			}
			if !acceleratorFound {
				continue
			}
		}
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target.ID < out[j].Target.ID })
	if len(out) > comfyMaxTargets {
		return nil, fmt.Errorf("Comfy discovery fleet exceeds source limit")
	}
	return out, nil
}

func (m *Manager) ComfyTargetStillCurrent(source ComfyDiscoveryTarget) bool {
	m.mu.RLock()
	current, ok := m.targets[source.Target.ID]
	currentGeneration := m.targetGenerations[source.Target.ID]
	m.mu.RUnlock()
	return ok && currentGeneration == source.Generation && targetIdentityMatches(source.Target, current)
}

func cloneComfyTarget(t Target) Target {
	t.Models = append([]string(nil), t.Models...)
	t.CustomNodes = append([]string(nil), t.CustomNodes...)
	t.ResidentModels = append([]string(nil), t.ResidentModels...)
	t.RuntimeArgs = append([]string(nil), t.RuntimeArgs...)
	t.Profiles = append([]domain.RuntimeProfile(nil), t.Profiles...)
	for i := range t.Profiles {
		profile := &t.Profiles[i]
		profile.Operations = append([]string(nil), profile.Operations...)
		profile.Features = append([]string(nil), profile.Features...)
		profile.AcceptedArtifactTypes = append([]string(nil), profile.AcceptedArtifactTypes...)
		profile.ProducedArtifactTypes = append([]string(nil), profile.ProducedArtifactTypes...)
		profile.CompatibilityOperations = append([]string(nil), profile.CompatibilityOperations...)
		profile.InputSchema = cloneJSONSchema(profile.InputSchema)
		profile.OutputSchema = cloneJSONSchema(profile.OutputSchema)
		if profile.Availability != nil {
			availability := *profile.Availability
			profile.Availability = &availability
		}
	}
	t.RuntimeProfiles = append([]RuntimeCapacityProfile(nil), t.RuntimeProfiles...)
	return t
}

func cloneJSONSchema(schema domain.JSONSchema) domain.JSONSchema {
	if schema == nil { return nil }
	cloned, _ := cloneJSONValue(map[string]any(schema)).(map[string]any)
	return domain.JSONSchema(cloned)
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		copyMap := make(map[string]any, len(typed))
		for key, child := range typed { copyMap[key] = cloneJSONValue(child) }
		return copyMap
	case []any:
		copySlice := make([]any, len(typed))
		for i, child := range typed { copySlice[i] = cloneJSONValue(child) }
		return copySlice
	default:
		return value
	}
}

func validComfyEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}

func copyComfyHTTPClient(client *http.Client) *http.Client {
	if client == nil { client = http.DefaultClient }
	clientCopy := *client
	clientCopy.Timeout = comfyFetchTimeout
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clientCopy
}

func comfyRouteURL(endpoint, route string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !validComfyEndpoint(endpoint) {
		return "", errComfyDiscoveryUnavailable
	}
	escapedPath := strings.TrimRight(u.EscapedPath(), "/") + "/" + route
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil { return "", errComfyDiscoveryUnavailable }
	u.Path, u.RawPath = decodedPath, escapedPath
	return u.String(), nil
}

func fetchComfyJSON(ctx context.Context, source ComfyDiscoveryTarget, route string, limit int64) (json.RawMessage, error) {
	endpoint, err := comfyRouteURL(source.Target.Endpoint, route)
	if err != nil {
		return nil, errComfyDiscoveryUnavailable
	}
	requestCtx, cancel := context.WithTimeout(ctx, comfyFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errComfyDiscoveryUnavailable
	}
	req.Header.Set("Accept", "application/json")
	if source.Target.Authorization != "" {
		req.Header.Set("Authorization", source.Target.Authorization)
	}
	client := source.client
	if client == nil {
		client = copyComfyHTTPClient(http.DefaultClient)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errComfyDiscoveryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errComfyDiscoveryUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit || !utf8.Valid(body) || !json.Valid(body) {
		return nil, errComfyDiscoveryUnavailable
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&object) != nil || object == nil {
		return nil, errComfyDiscoveryUnavailable
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errComfyDiscoveryUnavailable
	}
	return append(json.RawMessage(nil), body...), nil
}

func (m *Manager) ComfyFleetDiscovery(ctx context.Context, egress string) (ComfyDiscoveryResult, error) {
	totalCtx, cancel := context.WithTimeout(ctx, comfyFleetTimeout)
	defer cancel()
	targets, err := m.ComfyDiscoveryTargets(totalCtx, egress)
	if err != nil {
		return ComfyDiscoveryResult{}, err
	}
	if len(targets) == 0 {
		return ComfyDiscoveryResult{}, errComfyDiscoveryUnavailable
	}
	results := make([]comfySourceResult, len(targets))
	sem := make(chan struct{}, comfyMaxConcurrent)
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target ComfyDiscoveryTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-totalCtx.Done():
				results[i] = comfySourceResult{target: target, err: errComfyDiscoveryUnavailable}
				return
			}
			defer func() { <-sem }()
			infoBody, infoErr := fetchComfyJSON(totalCtx, target, "object_info", comfyObjectInfoLimit)
			statsBody, statsErr := fetchComfyJSON(totalCtx, target, "system_stats", comfyStatsLimit)
			result := comfySourceResult{target: target}
			if infoErr != nil || statsErr != nil {
				result.err = errComfyDiscoveryUnavailable
				results[i] = result
				return
			}
			if json.Unmarshal(infoBody, &result.info) != nil || len(result.info) > 4096 || json.Unmarshal(statsBody, &result.stats) != nil || result.stats == nil {
				result.err = errComfyDiscoveryUnavailable
			}
			if result.err == nil {
				for name, class := range result.info { if !safeComfyClassName(name) || validateComfyClassDefinition(class) != nil { result.err = errComfyDiscoveryUnavailable; break } }
			}
			if result.err == nil && !m.ComfyTargetStillCurrent(target) { result.err = errComfyDiscoveryUnavailable }
			results[i] = result
		}(i, target)
	}
	wg.Wait()
	composed := ComfyDiscoveryResult{ObjectInfo: make(map[string]json.RawMessage), Devices: make([]map[string]any, 0, len(results))}
	seenClass := make(map[string]bool)
	conflictedClass := make(map[string]bool)
	composedBytes := 0
	for _, result := range results {
		if result.err != nil {
			continue
		}
		composed.Available++
		keys := make([]string, 0, len(result.info))
		for key := range result.info { keys = append(keys, key) }
		sort.Strings(keys)
		for _, class := range keys {
			if conflictedClass[class] { continue }
			previous, found := composed.ObjectInfo[class]
			if !found && !seenClass[class] {
				composedBytes += len(class) + len(result.info[class])
				if composedBytes > comfyObjectInfoLimit { return ComfyDiscoveryResult{}, errComfyDiscoveryUnavailable }
				composed.ObjectInfo[class] = append(json.RawMessage(nil), result.info[class]...)
				seenClass[class] = true
			} else if found && !bytes.Equal(previous, result.info[class]) {
				merged, compatible := mergeComfySchemaEnums(previous, result.info[class])
				if compatible {
					composed.ObjectInfo[class] = merged
				} else {
					composed.Conflicts = append(composed.Conflicts, class)
					delete(composed.ObjectInfo, class)
					seenClass[class], conflictedClass[class] = true, true
				}
			}
		}
		composed.Devices = append(composed.Devices, safeComfyDevices(result.target.Target.ID, result.stats)...)
	}
	sort.Strings(composed.Conflicts)
	composed.Conflicts = compactComfyConflictStrings(composed.Conflicts)
	sort.Slice(composed.Devices, func(i, j int) bool {
		left, right := composed.Devices[i], composed.Devices[j]
		leftTarget, _ := left["target_id"].(string); rightTarget, _ := right["target_id"].(string)
		if leftTarget != rightTarget { return leftTarget < rightTarget }
		return fmt.Sprint(left["index"]) < fmt.Sprint(right["index"])
	})
	if composed.Available == 0 { return ComfyDiscoveryResult{}, errComfyDiscoveryUnavailable }
	encoded, err := json.Marshal(composed.ObjectInfo)
	if err != nil || len(encoded) > comfyObjectInfoLimit { return ComfyDiscoveryResult{}, errComfyDiscoveryUnavailable }
	return composed, nil
}

func compactComfyConflictStrings(items []string) []string {
	if len(items) < 2 { return items }
	out := items[:1]
	for _, item := range items[1:] { if item != out[len(out)-1] { out = append(out, item) } }
	return out
}

func safeComfyDevices(targetID string, stats map[string]any) []map[string]any {
	var devices []map[string]any
	deviceValues, _ := stats["devices"].([]any)
	for _, raw := range deviceValues {
		device, ok := raw.(map[string]any); if !ok { continue }
		clean := map[string]any{"target_id": targetID}
		clean["available"] = true
		for _, key := range []string{"name", "type", "index", "vram_total", "vram_free", "torch_vram_total", "torch_vram_free"} {
			if value, exists := device[key]; exists && safeStatPrimitive(value) { clean[key] = value }
		}
		devices = append(devices, clean)
	}
	return devices
}

func safeStatPrimitive(value any) bool {
	switch v := value.(type) { case string: return len(v) <= 256 && !strings.ContainsAny(v, "\\/@") && !strings.Contains(v, "://"); case float64: return v >= 0 && v < 1e18; case bool: return true; default: return false }
}

func safeComfyClassName(value string) bool {
	if value == "" || len(value) > 256 { return false }
	for _, r := range value { if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') { return false } }
	return true
}

func mergeComfySchemaEnums(leftRaw, rightRaw json.RawMessage) (json.RawMessage, bool) {
	var left, right any
	if json.Unmarshal(leftRaw, &left) != nil || json.Unmarshal(rightRaw, &right) != nil { return nil, false }
	merged, compatible := mergeComfySchemaValue(left, right, nil)
	if !compatible { return nil, false }
	body, err := json.Marshal(merged)
	return body, err == nil
}

func mergeComfySchemaValue(left, right any, path []string) (any, bool) {
	switch l := left.(type) {
	case map[string]any:
		r, ok := right.(map[string]any); if !ok || len(l) != len(r) { return nil, false }
		out := make(map[string]any, len(l))
		for key, lv := range l { rv, exists := r[key]; if !exists { return nil, false }; merged, ok := mergeComfySchemaValue(lv, rv, append(path, key)); if !ok { return nil, false }; out[key] = merged }
		return out, true
	case []any:
		r, ok := right.([]any); if !ok || len(l) != len(r) { return nil, false }
		if len(path) == 3 && path[0] == "input" && (path[1] == "required" || path[1] == "optional") && len(l) > 0 {
			if kind, ok := l[0].(string); ok && (kind == "COMBO" || kind == "COMFY_DYNAMICCOMBO_V3") && reflect.DeepEqual(kind, r[0]) && len(l) == 2 {
				leftOptions, leftOK := l[1].(map[string]any); rightOptions, rightOK := r[1].(map[string]any)
				if leftOK && rightOK && len(leftOptions) == len(rightOptions) {
					out := make(map[string]any, len(leftOptions))
					for key, leftValue := range leftOptions {
						rightValue, exists := rightOptions[key]; if !exists { return nil, false }
						if key == "options" {
							leftChoices, lok := primitiveChoices(leftValue); rightChoices, rok := primitiveChoices(rightValue)
							if !lok || !rok { return nil, false }
							union := make(map[string]any)
							for _, choices := range [][]any{leftChoices,rightChoices} { for _, choice := range choices { encoded, err := json.Marshal(choice); if err != nil { return nil, false }; union[string(encoded)] = choice } }
							keys := make([]string,0,len(union)); for key := range union { keys=append(keys,key) }; sort.Strings(keys)
							choices := make([]any,0,len(keys)); for _, key := range keys { choices=append(choices,union[key]) }; out[key]=choices
						} else { merged, compatible := mergeComfySchemaValue(leftValue,rightValue,append(path,key)); if !compatible { return nil,false }; out[key]=merged }
					}
					return []any{kind,out},true
				}
			}
			leftChoices, leftOK := primitiveChoices(l[0]); rightChoices, rightOK := primitiveChoices(r[0])
			if leftOK && rightOK {
				union := make(map[string]any)
				add := func(values []any) bool { for _, value := range values { keyBytes, err := json.Marshal(value); if err != nil { return false }; union[string(keyBytes)] = value }; return true }
				if !add(leftChoices) || !add(rightChoices) { return nil, false }
				keys := make([]string, 0, len(union)); for key := range union { keys = append(keys, key) }; sort.Strings(keys)
				choices := make([]any, 0, len(keys)); for _, key := range keys { choices = append(choices, union[key]) }
				out := append([]any(nil), l...); out[0] = choices
				for i := 1; i < len(l); i++ { merged, ok := mergeComfySchemaValue(l[i], r[i], append(path, fmt.Sprint(i))); if !ok { return nil, false }; out[i] = merged }
				return out, true
			}
		}
		out := make([]any, len(l)); for i := range l { merged, ok := mergeComfySchemaValue(l[i], r[i], append(path, fmt.Sprint(i))); if !ok { return nil, false }; out[i] = merged }; return out, true
	default:
		return left, reflect.DeepEqual(left, right)
	}
}

func primitiveChoices(value any) ([]any, bool) {
	items, ok := value.([]any); if !ok || len(items) == 0 { return nil, false }
	for _, item := range items { switch item.(type) { case string, bool, float64: default: return nil, false } }
	return items, true
}

// ComfySchema fetches a candidate's live schema and binds its digest to the
// exact target identity/generation. A mock adapter is intentionally excluded.
type comfySchemaProof struct {
	targetID          string
	targetIdentity    string
	targetGeneration  uint64
	graphDigest       string
	schemaDigest      string
}

func (m *Manager) ComfySchema(ctx context.Context, expected Target, generation uint64, request domain.WorkloadRequest) (comfySchemaProof, error) {
	if expected.Adapter != "comfy" || !validComfyEndpoint(expected.Endpoint) || generation == 0 {
		return comfySchemaProof{}, errComfyDiscoveryUnavailable
	}
	m.mu.RLock()
	adapter := m.adapters[expected.Adapter]
	m.mu.RUnlock()
	httpAdapter, ok := adapter.(*HTTPAdapter)
	if !ok || httpAdapter.kind != "comfy" { return comfySchemaProof{}, errComfyDiscoveryUnavailable }
	client := httpAdapter.client
	if client == nil { client = http.DefaultClient }
	clientCopy := copyComfyHTTPClient(client)
	source := ComfyDiscoveryTarget{Target: cloneComfyTarget(expected), Generation: generation, client: clientCopy}
	body, err := fetchComfyJSON(ctx, source, "object_info", comfyObjectInfoLimit)
	if err != nil { return comfySchemaProof{}, err }
	var schema map[string]json.RawMessage
	if json.Unmarshal(body, &schema) != nil || schema == nil || len(schema) > 4096 { return comfySchemaProof{}, errComfyDiscoveryUnavailable }
	for className, classDefinition := range schema {
		if !safeComfyClassName(className) || validateComfyClassDefinition(classDefinition) != nil { return comfySchemaProof{}, errComfyDiscoveryUnavailable }
	}
	if err := validateComfyRequestSchema(request, schema); err != nil { return comfySchemaProof{}, err }
	m.mu.RLock()
	current, ok := m.targets[expected.ID]
	currentGeneration := m.targetGenerations[expected.ID]
	m.mu.RUnlock()
	if !ok || !targetIdentityMatches(expected, current) || currentGeneration != generation { return comfySchemaProof{}, errComfyDiscoveryUnavailable }
	schemaDigest := sha256.Sum256(body)
	graphDigest := sha256.Sum256(request.Payload)
	return comfySchemaProof{
		targetID: expected.ID, targetIdentity: targetExecutionFingerprint(expected), targetGeneration: generation,
		graphDigest: hex.EncodeToString(graphDigest[:]), schemaDigest: hex.EncodeToString(schemaDigest[:]),
	}, nil
}

func builtInComfyHTTPAdapter(adapter Adapter) bool {
	httpAdapter, ok := adapter.(*HTTPAdapter)
	return ok && httpAdapter.kind == "comfy"
}

func comfySchemaProofMatches(admitted, current comfySchemaProof) bool {
	return admitted.targetID != "" && admitted.targetID == current.targetID &&
		admitted.targetIdentity != "" && admitted.targetIdentity == current.targetIdentity &&
		admitted.targetGeneration != 0 && admitted.targetGeneration == current.targetGeneration &&
		admitted.graphDigest != "" && admitted.graphDigest == current.graphDigest &&
		admitted.schemaDigest != "" && admitted.schemaDigest == current.schemaDigest
}

func validateComfyRequestSchema(request domain.WorkloadRequest, schema map[string]json.RawMessage) error {
	var payload map[string]json.RawMessage
	if len(request.Payload) > comfyObjectInfoLimit || !boundedComfyJSONDepth(request.Payload, 32) || json.Unmarshal(request.Payload, &payload) != nil || payload == nil { return errComfyDiscoveryUnavailable }
	graphs := []map[string]json.RawMessage{}
	if chunksRaw, ok := payload["managed_chunks"]; ok {
		var chunks []map[string]json.RawMessage
		if json.Unmarshal(chunksRaw, &chunks) != nil || len(chunks) == 0 || len(chunks) > 1024 { return errComfyDiscoveryUnavailable }
		graphs = chunks
	} else {
		graphs = append(graphs, payload)
	}
	for _, graph := range graphs {
		if promptRaw, ok := graph["prompt"]; ok {
			var prompt map[string]json.RawMessage
			if json.Unmarshal(promptRaw, &prompt) != nil || prompt == nil { return errComfyDiscoveryUnavailable }
			graph = prompt
		}
		if err := validateComfyGraph(graph, schema); err != nil { return err }
	}
	return nil
}

type comfyNode struct {
	Class  string                     `json:"class_type"`
	Inputs map[string]json.RawMessage `json:"inputs"`
}

type comfyClass struct {
	Input  map[string]map[string]json.RawMessage `json:"input"`
	Output []string                              `json:"output"`
}

func validateComfyGraph(graph map[string]json.RawMessage, schemas map[string]json.RawMessage) error {
	if len(graph) == 0 || len(graph) > 10000 { return errComfyDiscoveryUnavailable }
	nodes := make(map[string]comfyNode, len(graph))
	classes := make(map[string]comfyClass, len(graph))
	for id, raw := range graph {
		if len(id) == 0 || len(id) > 256 || len(raw) > 1<<20 || !boundedComfyJSONDepth(raw, 16) { return errComfyDiscoveryUnavailable }
		var node comfyNode
		if json.Unmarshal(raw, &node) != nil || !safeComfyClassName(node.Class) || node.Inputs == nil || len(node.Inputs) > 2048 { return errComfyDiscoveryUnavailable }
		classRaw, ok := schemas[node.Class]
		if !ok { return errComfyDiscoveryUnavailable }
		var class comfyClass
		if json.Unmarshal(classRaw, &class) != nil || class.Input == nil { return errComfyDiscoveryUnavailable }
		if err := validateComfyClassDefinition(classRaw); err != nil { return err }
		nodes[id], classes[id] = node, class
	}
	if len(nodes) == 0 { return errComfyDiscoveryUnavailable }
	edges := make(map[string][]string, len(nodes))
	for id, node := range nodes {
		class := classes[id]
		required, optional := class.Input["required"], class.Input["optional"]
		allowedInputs := make(map[string]json.RawMessage, len(required)+len(optional))
		dynamicInputOwner := make(map[string]string)
		for name, spec := range required { allowedInputs[name] = spec; if _, exists := node.Inputs[name]; !exists { return errComfyDiscoveryUnavailable } }
		for name, spec := range optional { allowedInputs[name] = spec }
		// Expand selected conditional schemas to a bounded fixed point. Iteration order
		// is deliberately irrelevant: every selected dynamic input is revisited until
		// no new child name is admitted.
		for round := 0; round <= len(node.Inputs); round++ {
			changed := false
			for name, value := range node.Inputs {
				spec, exists := allowedInputs[name]
				if !exists { continue }
				childRequired, childOptional, dynamic, selected := comfyDynamicChildInputsExact(spec, value)
				if !dynamic { continue }
				if !selected { return errComfyDiscoveryUnavailable }
				for childName, childSpec := range childRequired {
					if old, exists := allowedInputs[childName]; exists {
						if dynamicInputOwner[childName] != name || !bytes.Equal(old, childSpec) { return errComfyDiscoveryUnavailable }
					} else { allowedInputs[childName] = childSpec; dynamicInputOwner[childName] = name; changed = true }
					if _, exists := node.Inputs[childName]; !exists { return errComfyDiscoveryUnavailable }
				}
				for childName, childSpec := range childOptional {
					if old, exists := allowedInputs[childName]; exists {
						if dynamicInputOwner[childName] != name || !bytes.Equal(old, childSpec) { return errComfyDiscoveryUnavailable }
					} else { allowedInputs[childName] = childSpec; dynamicInputOwner[childName] = name; changed = true }
				}
			}
			if !changed { break }
			if round == len(node.Inputs) { return errComfyDiscoveryUnavailable }
		}
		for name, value := range node.Inputs {
			spec, exists := allowedInputs[name]
			if !exists { return errComfyDiscoveryUnavailable }
			if comfySchemaMultiselect(spec) {
				if !comfyLiteralSupported(spec, value) { return errComfyDiscoveryUnavailable }
				continue
			}
			var link []json.RawMessage
			if json.Unmarshal(value, &link) == nil {
				var producerID string
				linkLike := len(link) > 0 && json.Unmarshal(link[0], &producerID) == nil
				if linkLike {
					var outputNumber json.Number
					if len(link) != 2 || producerID == "" || json.Unmarshal(link[1], &outputNumber) != nil || outputNumber == "" {
						return errComfyDiscoveryUnavailable
					}
					outputIndex64, parseErr := strconv.ParseInt(string(outputNumber), 10, 32)
					if parseErr != nil || outputIndex64 < 0 { return errComfyDiscoveryUnavailable }
					outputIndex := int(outputIndex64)
					producerClass, ok := classes[producerID]
					if !ok || outputIndex >= len(producerClass.Output) || !comfyInputAccepts(spec, producerClass.Output[outputIndex]) { return errComfyDiscoveryUnavailable }
					edges[producerID] = append(edges[producerID], id)
					continue
				}
				if len(link) == 2 { return errComfyDiscoveryUnavailable }
			}
			if comfyForceInput(spec) { return errComfyDiscoveryUnavailable }
			if !comfyLiteralSupported(spec, value) { return errComfyDiscoveryUnavailable }
		}
	}
	visiting, visited := make(map[string]bool), make(map[string]bool)
	var visit func(string) bool
	visit = func(id string) bool {
		if visiting[id] { return false }
		if visited[id] { return true }
		visiting[id] = true
		for _, next := range edges[id] { if !visit(next) { return false } }
		delete(visiting, id); visited[id] = true
		return true
	}
	for id := range nodes { if !visit(id) { return errComfyDiscoveryUnavailable } }
	return nil
}

func comfyForceInput(raw json.RawMessage) bool {
	var spec []json.RawMessage
	if json.Unmarshal(raw, &spec) != nil || len(spec) < 2 { return false }
	var options map[string]any
	if json.Unmarshal(spec[1], &options) != nil { return false }
	force, _ := options["forceInput"].(bool)
	return force
}

func validateComfyClassDefinition(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if len(raw) > 1<<20 || !boundedComfyJSONDepth(raw, 32) || json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) > 64 { return errComfyDiscoveryUnavailable }
	allowed := map[string]bool{"input":true,"input_order":true,"output":true,"output_is_list":true,"output_name":true,"name":true,"display_name":true,"description":true,"category":true,"output_node":true,"deprecated":true,"experimental":true,"search_aliases":true,"python_module":true,"input_is_list":true,"output_tooltips":true,"is_input_list":true,"has_intermediate_output":true,"essentials_category":true,"api_node":true,"dev_only":true,"output_matchtypes":true,"price_badge":true}
	inputRaw, inputPresent := fields["input"]
	outputRaw, outputPresent := fields["output"]
	if !inputPresent || !outputPresent { return errComfyDiscoveryUnavailable }
	var completeInput map[string]map[string]json.RawMessage
	if json.Unmarshal(inputRaw, &completeInput) != nil || completeInput == nil { return errComfyDiscoveryUnavailable }
	var completeOutput []string
	if json.Unmarshal(outputRaw, &completeOutput) != nil || completeOutput == nil || len(completeOutput) > 256 { return errComfyDiscoveryUnavailable }
	for name, value := range fields {
		if !allowed[name] || len(value) > 1<<20 { return errComfyDiscoveryUnavailable }
		switch name {
		case "input":
			var inputs map[string]map[string]json.RawMessage
			if json.Unmarshal(value, &inputs) != nil || inputs == nil || len(inputs) > 3 { return errComfyDiscoveryUnavailable }
			for group, definitions := range inputs {
				if (group != "required" && group != "optional" && group != "hidden") || definitions == nil || len(definitions) > 2048 { return errComfyDiscoveryUnavailable }
				for _, spec := range definitions { if !validComfyInputDefinitionFor(spec, group == "hidden", 0) { return errComfyDiscoveryUnavailable } }
			}
		case "input_order":
			var order map[string][]string
			if json.Unmarshal(value, &order) != nil || order == nil { return errComfyDiscoveryUnavailable }
			for key, names := range order {
				if key != "required" && key != "optional" && key != "hidden" { return errComfyDiscoveryUnavailable }
				if len(names) > 512 { return errComfyDiscoveryUnavailable }
				for _, name := range names { if !safeComfyClassName(name) { return errComfyDiscoveryUnavailable } }
			}
		case "output", "output_name":
			var values []string
			if json.Unmarshal(value, &values) != nil || values == nil { return errComfyDiscoveryUnavailable }
			for _, text := range values { if !safeComfyDisplayText(text) { return errComfyDiscoveryUnavailable } }
		case "output_tooltips":
			var values []json.RawMessage
			if json.Unmarshal(value, &values) != nil || values == nil { return errComfyDiscoveryUnavailable }
			for _, rawText := range values { if string(bytes.TrimSpace(rawText)) != "null" { var text string; if json.Unmarshal(rawText,&text) != nil || !safeComfyDisplayText(text) { return errComfyDiscoveryUnavailable } } }
		case "name", "display_name", "description", "category", "python_module", "essentials_category":
			if string(bytes.TrimSpace(value)) == "null" && (name == "display_name" || name == "description" || name == "essentials_category") { break }
			var text string
			if json.Unmarshal(value, &text) != nil { return errComfyDiscoveryUnavailable }
			if name == "description" || name == "display_name" { if !safeComfyDisplayText(text) { return errComfyDiscoveryUnavailable } } else if !safeComfyMetadataText(text, name == "category" || name == "essentials_category") { return errComfyDiscoveryUnavailable }
		case "output_is_list":
			var values []bool
			if json.Unmarshal(value, &values) != nil || values == nil { return errComfyDiscoveryUnavailable }
		case "output_node", "deprecated", "experimental", "input_is_list", "is_input_list", "has_intermediate_output", "api_node", "dev_only":
			var flag bool
			if json.Unmarshal(value, &flag) != nil { return errComfyDiscoveryUnavailable }
		case "search_aliases":
			var aliases []string
			if json.Unmarshal(value, &aliases) != nil || aliases == nil { return errComfyDiscoveryUnavailable }
			for _, alias := range aliases { if !safeComfyDisplayText(alias) { return errComfyDiscoveryUnavailable } }
		case "output_matchtypes":
			var values []any
			if string(bytes.TrimSpace(value)) == "null" { break }
			if json.Unmarshal(value, &values) != nil || values == nil || len(values) != len(completeOutput) { return errComfyDiscoveryUnavailable }
			for _, item := range values { if !safeComfySchemaMetadata(item, 0) { return errComfyDiscoveryUnavailable } }
		case "price_badge":
			var badge any
			if json.Unmarshal(value, &badge) != nil || !safeComfySchemaMetadata(badge, 0) { return errComfyDiscoveryUnavailable }
		}
	}
	for _, outputType := range completeOutput { if !safeComfyClassName(outputType) && outputType != "*" { return errComfyDiscoveryUnavailable } }
	for _, paired := range []struct { key string; present bool }{
		{"output_name", fields["output_name"] != nil},
		{"output_tooltips", fields["output_tooltips"] != nil},
		{"output_is_list", fields["output_is_list"] != nil},
	} {
		if !paired.present { continue }
		var count int
		switch paired.key {
		case "output_name":
			var values []string
			if json.Unmarshal(fields[paired.key], &values) != nil { return errComfyDiscoveryUnavailable }
			count = len(values)
		case "output_tooltips":
			var values []json.RawMessage
			if json.Unmarshal(fields[paired.key], &values) != nil { return errComfyDiscoveryUnavailable }
			count = len(values)
		case "output_is_list":
			var values []bool
			if json.Unmarshal(fields[paired.key], &values) != nil { return errComfyDiscoveryUnavailable }
			count = len(values)
		}
		if count != len(completeOutput) { return errComfyDiscoveryUnavailable }
	}
	return nil
}

func boundedComfyJSONDepth(raw []byte, maximum int) bool {
	depth := 0
	inString, escaped := false, false
	for _, value := range raw {
		if inString {
			if escaped { escaped = false; continue }
			if value == '\\' { escaped = true; continue }
			if value == '"' { inString = false }
			continue
		}
		switch value {
		case '"': inString = true
		case '{', '[':
			depth++
			if depth > maximum { return false }
		case '}', ']':
			depth--
			if depth < 0 { return false }
		}
	}
	return !inString && depth == 0
}

func validComfyInputDefinition(raw json.RawMessage) bool {
	return validComfyInputDefinitionFor(raw, false, 0)
}

func validComfyInputDefinitionFor(raw json.RawMessage, allowHidden bool, depth int) bool {
	if len(raw) > 1<<16 || depth > 16 { return false }
	if allowHidden {
		var sentinel string
		if json.Unmarshal(raw, &sentinel) == nil { return sentinel == "PROMPT" || sentinel == "EXTRA_PNGINFO" || sentinel == "UNIQUE_ID" || sentinel == "DYNPROMPT" || sentinel == "API_KEY_COMFY_ORG" || sentinel == "AUTH_TOKEN_COMFY_ORG" || sentinel == "COMFY_USAGE_SOURCE" }
	}
	var spec []json.RawMessage
	if json.Unmarshal(raw, &spec) != nil || len(spec) == 0 || len(spec) > 2 { return false }
	var name string
	isChoices := false
	if json.Unmarshal(spec[0], &name) != nil {
		var choices []any
		if json.Unmarshal(spec[0], &choices) != nil || len(choices) == 0 || len(choices) > 4096 { return false }
		isChoices = true
		for _, choice := range choices {
			switch typed := choice.(type) {
			case string:
				if !safeComfyMetadataText(typed, true) { return false }
			case bool, float64:
			default:
				return false
			}
		}
	} else if strings.Contains(name, ",") {
		parts := strings.Split(name, ",")
		if len(parts) < 2 || len(parts) > 32 { return false }
		seen := make(map[string]bool, len(parts))
		for _, part := range parts { if !safeComfyTypeToken(part) || seen[part] { return false }; seen[part] = true }
	} else if !safeComfyTypeToken(name) {
		return false
	}
	if len(spec) == 1 && (name == "COMBO" || name == "COMFY_DYNAMICCOMBO_V3") { return false }
	if len(spec) == 2 {
		var options map[string]json.RawMessage
		if json.Unmarshal(spec[1], &options) != nil || options == nil { return false }
		if name == "COMBO" || name == "COMFY_DYNAMICCOMBO_V3" {
			return validComfyComboOptions(name, options, depth)
		}
		allowed := map[string]bool{"default":true,"min":true,"max":true,"step":true,"round":true,"display":true,"multiline":true,"placeholder":true,"dynamicPrompts":true,"forceInput":true,"lazy":true,"tooltip":true,"advanced":true,"rawLink":true,"control_after_generate":true,"choices":true,"serialize":true,"deprecated":true,"options":true,"multiselect":true,"socketless":true,"display_name":true,"hidden":true,"template":true,"accept":true,"upload":true,"file_upload":true,"directory":true,"image_upload":true,"audio_upload":true,"video_upload":true,"component":true,"widgetType":true,"remote":true,"image_folder":true,"label_off":true,"label_on":true}
		numericOptionSeen := false
		for key, value := range options {
			if !allowed[key] || len(value) > 4096 { return false }
			var primitive any
			if json.Unmarshal(value, &primitive) != nil { return false }
			switch key {
			case "min", "max", "step", "round":
				number, ok := primitive.(float64); if !ok || math.IsNaN(number) || math.IsInf(number, 0) { return false }
				if key == "step" && number <= 0 { return false }
				numericOptionSeen = true
			case "forceInput", "lazy", "advanced", "multiline", "dynamicPrompts", "serialize", "deprecated", "rawLink", "multiselect", "socketless", "hidden":
				if _, ok := primitive.(bool); !ok { return false }
			case "label_off", "label_on":
				text, ok := primitive.(string); if !ok || !safeComfyDisplayText(text) { return false }
			case "upload", "file_upload", "directory", "image_upload", "audio_upload", "video_upload":
				if !validComfyUploadOption(primitive) { return false }
			case "accept":
				if !validComfyAcceptOption(primitive) { return false }
			case "tooltip", "placeholder", "display_name", "template":
				text, ok := primitive.(string); if !ok || !safeComfyDisplayText(text) { return false }
			case "choices":
				choices, ok := primitive.([]any); if !ok { return false }
				for _, choice := range choices { if !safeComfyPrimitive(choice) { return false } }
			case "default":
				if !safeComfyPrimitive(primitive) && !validComfyStructuredDefault(name, primitive) { return false }
				if valueText, ok := primitive.(string); ok && !safeComfyDisplayText(valueText) { return false }
			case "component", "widgetType", "image_folder":
				text, ok := primitive.(string); if !ok || !safeComfyMetadataText(text, true) { return false }
			case "remote":
				if !validComfyRemoteDescriptor(primitive) { return false }
			case "options":
				if !validComfyOptionsValue(primitive, depth+1) { return false }
			default:
				if !safeComfyPrimitive(primitive) { return false }
				if text, ok := primitive.(string); ok && !safeComfyMetadataText(text, false) { return false }
			}
		}
		if numericOptionSeen && (isChoices || ((name != "INT" && name != "FLOAT") && !comfyNumericUnion(name))) { return false }
		var minimum, maximum *float64
		if rawMin, exists := options["min"]; exists { var value float64; if json.Unmarshal(rawMin,&value)!=nil { return false }; minimum=&value }
		if rawMax, exists := options["max"]; exists { var value float64; if json.Unmarshal(rawMax,&value)!=nil { return false }; maximum=&value }
		if minimum != nil && maximum != nil && *minimum > *maximum { return false }
	}
	return true
}

func validComfyUploadOption(value any) bool {
	switch typed := value.(type) {
	case bool:
		return true
	case string:
		return typed == "image" || typed == "audio" || typed == "video" || typed == "file" || typed == "directory" || typed == "input"
	default:
		return false
	}
}

func validComfyAcceptOption(value any) bool {
	valid := func(text string) bool {
		if !safeComfyDisplayText(text) || len(text) > 256 { return false }
		return strings.Contains(text,"/") || text == "image" || text == "audio" || text == "video"
	}
	switch typed := value.(type) {
	case string:
		return valid(typed)
	case []any:
		if len(typed) == 0 || len(typed) > 64 { return false }
		for _, item := range typed { text, ok := item.(string); if !ok || !valid(text) { return false } }
		return true
	default:
		return false
	}
}

func validComfyComboOptions(kind string, options map[string]json.RawMessage, depth int) bool {
	if depth > 16 { return false }
	for key, raw := range options {
		switch key {
		case "options":
			var value any
			if json.Unmarshal(raw, &value) != nil || !validComfyOptionsValue(value, depth+1) { return false }
		case "multiselect", "socketless", "hidden", "image_upload":
			var flag bool
			if json.Unmarshal(raw, &flag) != nil { return false }
		case "default":
			var value any
			if json.Unmarshal(raw, &value) != nil || !safeComfySchemaMetadata(value, depth+1) { return false }
		case "display_name", "tooltip", "template", "placeholder", "component", "widgetType", "image_folder":
			var value string
			if json.Unmarshal(raw, &value) != nil || !safeComfyDisplayText(value) { return false }
		case "remote":
			var value any
			if json.Unmarshal(raw, &value) != nil || !validComfyRemoteDescriptor(value) { return false }
		default:
			return false
		}
	}
	_, hasOptions := options["options"]
	_, hasRemote := options["remote"]
	return hasOptions || kind == "COMFY_DYNAMICCOMBO_V3" || (kind == "COMBO" && hasRemote)
}

func validComfyOptionsValue(value any, depth int) bool {
	if depth > 16 { return false }
	switch typed := value.(type) {
	case []any:
		if len(typed) > 4096 { return false }
		seenKeys := make(map[string]bool)
		for _, item := range typed {
			if entry, ok := item.(map[string]any); ok {
				if key, ok := entry["key"].(string); ok { if seenKeys[key] { return false }; seenKeys[key] = true }
			}
			if !validComfyOptionsValue(item, depth+1) { return false }
		}
		return len(typed) > 0
	case map[string]any:
		_, hasOptionKey := typed["key"]
		_, hasInputs := typed["inputs"]
		if !hasOptionKey && !hasInputs {
			if len(typed) == 0 || len(typed) > 256 { return false }
			for key, item := range typed {
				if !safeComfyClassName(key) { return false }
				if child, ok := item.(map[string]any); ok {
					if rawInputs, exists := child["inputs"]; exists {
						if !validComfyOptionsValue(map[string]any{"key":key,"inputs":rawInputs}, depth+1) { return false }
						continue
					}
				}
				if !safeComfySchemaMetadata(item, depth+1) { return false }
			}
			return true
		}
		if len(typed) > 16 { return false }
		for key, item := range typed {
			if key == "key" {
				text, ok := item.(string)
				if !ok || !safeComfyClassName(text) { return false }
			} else if key == "inputs" {
				groups, ok := item.(map[string]any)
				if !ok || len(groups) > 3 { return false }
				for group, rawInputs := range groups {
					if group != "required" && group != "optional" { return false }
					inputs, ok := rawInputs.(map[string]any)
					if !ok || len(inputs) > 128 { return false }
					for name, spec := range inputs {
						encoded, err := json.Marshal(spec)
						if err != nil || !safeComfyClassName(name) || !validComfyInputDefinitionFor(encoded, false, depth+1) { return false }
					}
				}
			} else if !safeComfySchemaMetadata(item, depth+1) { return false }
		}
		_, key := typed["key"]
		_, inputs := typed["inputs"]
		return key && inputs
	default:
		return safeComfySchemaMetadata(value, depth)
	}
}

func safeComfySchemaMetadata(value any, depth int) bool {
	if depth > 16 { return false }
	switch typed := value.(type) {
	case nil, bool, float64:
		return true
	case string:
		return safeComfyMetadataText(typed, true)
	case []any:
		if len(typed) > 4096 { return false }
		for _, item := range typed { if !safeComfySchemaMetadata(item, depth+1) { return false } }
		return true
	case map[string]any:
		if len(typed) > 64 { return false }
		for key, item := range typed { if !safeComfyClassName(key) || !safeComfySchemaMetadata(item, depth+1) { return false } }
		return true
	default:
		return false
	}
}

func comfyInputAccepts(raw json.RawMessage, outputType string) bool {
	var spec []json.RawMessage
	if json.Unmarshal(raw, &spec) != nil || len(spec) == 0 { return false }
	var encoded string
	if json.Unmarshal(spec[0], &encoded) == nil {
		for _, alternative := range strings.Split(encoded, ",") { if alternative == "*" || alternative == outputType { return true } }
		return false
	}
	return false
}

func safeComfyTypeToken(value string) bool {
	if value == "INT" || value == "FLOAT" || value == "BOOLEAN" || value == "STRING" || value == "*" { return true }
	return safeComfyClassName(value)
}

func comfyNumericUnion(kind string) bool {
	parts := strings.Split(kind, ",")
	if len(parts) < 2 { return false }
	for _, part := range parts { if part != "INT" && part != "FLOAT" { return false } }
	return true
}

func comfySchemaMultiselect(rawSpec json.RawMessage) bool {
	var spec []json.RawMessage
	if json.Unmarshal(rawSpec, &spec) != nil || len(spec) < 2 { return false }
	var options map[string]json.RawMessage
	if json.Unmarshal(spec[1], &options) != nil { return false }
	var enabled bool
	return json.Unmarshal(options["multiselect"], &enabled) == nil && enabled
}

func validComfyRemoteDescriptor(value any) bool {
	remote, ok := value.(map[string]any)
	if !ok || len(remote) > 8 { return false }
	for key, item := range remote {
		switch key {
		case "route":
			text, ok := item.(string); if !ok || len(text) > 256 || !safeComfyDisplayText(text) { return false }
		case "refresh_button":
			if _, ok := item.(bool); !ok { return false }
		case "control_after_refresh":
			text, ok := item.(string); if !ok || len(text) > 256 || !safeComfyDisplayText(text) { return false }
		default: return false
		}
	}
	return true
}

func validComfyStructuredDefault(kind string, value any) bool {
	switch kind {
	case "BOUNDING_BOX":
		object, ok := value.(map[string]any)
		if !ok || len(object) != 4 { return false }
		for _, key := range []string{"x","y","width","height"} { if _, ok := object[key].(float64); !ok { return false } }
		return safeComfySchemaMetadata(value, 0)
	case "BOUNDING_BOXES", "COLORS", "COMPOSITOR", "CURVE":
		// These are UI-only structured defaults in the live catalog. Keep their
		// shape bounded and inert; custom connection types still accept no literals.
		return safeComfySchemaMetadata(value, 0) && (func() bool { switch value.(type) { case []any, map[string]any: return true; default: return false } })()
	default: return false
	}
}

func comfyLiteralSupported(rawSpec, rawValue json.RawMessage) bool {
	var spec []json.RawMessage
	if json.Unmarshal(rawSpec, &spec) != nil || len(spec) == 0 { return false }
	var choices []any
	if json.Unmarshal(spec[0], &choices) == nil && len(choices) > 0 {
		var value any
		if json.Unmarshal(rawValue, &value) != nil { return false }
		multiselect := false
		if len(spec) > 1 { var options map[string]any; if json.Unmarshal(spec[1], &options) != nil { return false }; multiselect, _ = options["multiselect"].(bool) }
		if multiselect {
			selected, ok := value.([]any); if !ok { return false }
			for _, item := range selected { if !choiceInList(choices, item) { return false } }
			return true
		}
		return choiceInList(choices, value)
	}
	var kind string
	if json.Unmarshal(spec[0], &kind) != nil { return false }
	if strings.Contains(kind, ",") {
		if comfyNumericUnion(kind) {
			if number, ok := comfyJSONRational(rawValue); ok { return comfyRationalInNumericBounds(number, spec) }
			return false
		}
		for _, member := range strings.Split(kind, ",") {
			switch member {
			case "INT":
				if comfyIntegerInBounds(rawValue, spec) { return true }
			case "FLOAT":
				if number, ok := comfyJSONRational(rawValue); ok && comfyRationalInNumericBounds(number, spec) { return true }
			case "BOOLEAN":
				var value any; if json.Unmarshal(rawValue,&value) == nil { if _, ok := value.(bool); ok { return true } }
			case "STRING":
				var value any; if json.Unmarshal(rawValue,&value) == nil { if _, ok := value.(string); ok { return true } }
			case "*":
				var value any; if json.Unmarshal(rawValue,&value) == nil { switch value.(type) { case nil,bool,float64,string: return true } }
		}
		}
		return false
	}
	if kind == "INT" { return comfyIntegerInBounds(rawValue, spec) }
	var value any
	if json.Unmarshal(rawValue, &value) != nil { return false }
	if kind == "COMBO" || kind == "COMFY_DYNAMICCOMBO_V3" {
		var options map[string]any
		if len(spec) > 1 { if json.Unmarshal(spec[1], &options) != nil { return false } }
		if multiselect, _ := options["multiselect"].(bool); multiselect {
			selected, ok := value.([]any); if !ok { return false }
			for _, item := range selected { if !comfyOptionValueContains(spec,item) { return false } }
			return true
		}
		return comfyOptionValueContains(spec,value)
	}
	switch kind {
	case "FLOAT":
		number, ok := comfyJSONRational(rawValue); return ok && comfyRationalInNumericBounds(number, spec)
	case "BOOLEAN":
		_, ok := value.(bool); return ok
	case "STRING":
		_, ok := value.(string); return ok
	case "*":
		switch value.(type) { case nil, bool, float64, string: return true; default: return false }
	default:
		return false
	}
}

func choiceInList(choices []any, value any) bool { for _, choice := range choices { if reflect.DeepEqual(choice,value) { return true } }; return false }

func comfyIntegerInBounds(rawValue json.RawMessage, spec []json.RawMessage) bool {
	value, ok := comfyJSONRational(rawValue)
	return ok && value.IsInt() && comfyRationalInNumericBounds(value,spec)
}

func comfyJSONRational(raw json.RawMessage) (*big.Rat, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil { return nil,false }
	number, ok := value.(json.Number); if !ok { return nil,false }
	return comfyBoundedRational(number.String())
}

func comfyRationalInNumericBounds(value *big.Rat, spec []json.RawMessage) bool {
	if value == nil || len(spec)<2 { return value != nil }
	var options map[string]json.RawMessage
	if json.Unmarshal(spec[1],&options)!=nil { return false }
	var minimum, maximum *big.Rat
	for key, target := range map[string]**big.Rat{"min":&minimum,"max":&maximum} {
		if raw, exists := options[key]; exists { parsed,ok:=comfyJSONRational(raw); if !ok { return false }; *target=parsed }
	}
	if minimum!=nil && value.Cmp(minimum)<0 || maximum!=nil && value.Cmp(maximum)>0 { return false }
	// Comfy's step is widget increment metadata; backend acceptance is bounded
	// by min/max and does not require values to land on an increment multiple.
	return true
}

func comfyBoundedRational(value string) (*big.Rat, bool) {
	if len(value) == 0 || len(value) > 128 { return nil, false }
	if index := strings.IndexAny(value,"eE"); index >= 0 {
		exponent, err := strconv.Atoi(value[index+1:])
		if err != nil || exponent < -1000 || exponent > 1000 { return nil, false }
	}
	return new(big.Rat).SetString(value)
}

func comfyChoiceContains(spec []json.RawMessage, selected string) bool {
	return comfyOptionValueContains(spec, selected)
}

func comfyOptionValueContains(spec []json.RawMessage, selected any) bool {
	if len(spec) < 2 { return false }
	var options map[string]any
	if json.Unmarshal(spec[1], &options) != nil { return false }
	values, ok := options["options"]
	if !ok { return false }
	var walk func(any) bool
	walk = func(value any) bool {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed { if walk(item) { return true } }
		case map[string]any:
			if key, ok := typed["key"].(string); ok && reflect.DeepEqual(key,selected) { return true }
			if key, ok := selected.(string); ok { if _, hasKey := typed["key"]; !hasKey { if _, optionMap := typed[key]; optionMap { return true } } }
		case string:
			return reflect.DeepEqual(typed,selected)
		case float64, bool:
			return reflect.DeepEqual(typed,selected)
		}
		return false
	}
	return walk(values)
}

func comfyDynamicChildInputsExact(rawSpec, rawValue json.RawMessage) (map[string]json.RawMessage, map[string]json.RawMessage, bool, bool) {
	var spec []json.RawMessage
	if json.Unmarshal(rawSpec, &spec) != nil || len(spec) < 2 { return nil, nil, false, false }
	var kind string
	if json.Unmarshal(spec[0], &kind) != nil || kind != "COMFY_DYNAMICCOMBO_V3" { return nil, nil, false, false }
	var selected string
	if json.Unmarshal(rawValue, &selected) != nil { return nil, nil, true, false }
	var options map[string]any
	if json.Unmarshal(spec[1], &options) != nil { return nil, nil, true, false }
	var find func(any) (map[string]json.RawMessage, map[string]json.RawMessage, bool)
	find = func(value any) (map[string]json.RawMessage, map[string]json.RawMessage, bool) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed { if required, optional, found := find(item); found { return required, optional, true } }
		case map[string]any:
			if key, ok := typed["key"].(string); ok {
				if key != selected { return nil, nil, false }
				inputs, _ := typed["inputs"].(map[string]any)
				required := jsonRawInputGroup(inputs["required"])
				optional := jsonRawInputGroup(inputs["optional"])
				return required, optional, true
			}
			if rawInputs, exists := typed["inputs"]; exists {
				groups, ok := rawInputs.(map[string]any); if !ok { return nil,nil,false }
				return jsonRawInputGroup(groups["required"]),jsonRawInputGroup(groups["optional"]),true
			}
			if item, exists := typed[selected]; exists { return find(item) }
		}
		return nil, nil, false
	}
	required, optional, found := find(options["options"])
	return required, optional, true, found
}

func jsonRawInputGroup(value any) map[string]json.RawMessage {
	group, _ := value.(map[string]any)
	result := make(map[string]json.RawMessage, len(group))
	for key, value := range group { encoded, err := json.Marshal(value); if err == nil { result[key] = encoded } }
	return result
}

func safeComfyPrimitive(value any) bool {
	switch typed := value.(type) {
	case nil, bool, float64:
		return true
	case string:
		return safeComfyMetadataText(typed, true)
	default:
		return false
	}
}

func safeComfyMetadataText(value string, allowRelativePath bool) bool {
	if len(value) > 4096 || !utf8.ValidString(value) || strings.Contains(value, "://") || strings.ContainsAny(value, "\\\x00\r\n") {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization:", "bearer ", "password=", "token=", "secret=", "api_key="} {
		if strings.Contains(lower, marker) { return false }
	}
	if value == "" { return true }
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || (len(value) >= 2 && value[1] == ':') { return false }
	if strings.Contains(value, "/") {
		if !allowRelativePath { return false }
		for _, part := range strings.Split(value, "/") { if part == "" || part == "." || part == ".." { return false } }
	}
	for _, r := range value { if r < 0x20 || r == 0x7f { return false } }
	return true
}

func safeComfyDisplayText(value string) bool {
	if len(value) > 16384 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00") { return false }
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization:", "bearer ", "password=", "token=", "secret=", "api_key="} { if strings.Contains(lower, marker) { return false } }
	for _, r := range value { if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f { return false } }
	return true
}
