// Package wsproto defines the small JSON message envelope multiplexed over
// the single outbound node<->controller control channel (architecture.md
// §34A). Bulk data never travels this channel — only registration,
// heartbeat/telemetry, events, acks, and (later) commands.
package wsproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"vram-governor/internal/domain"
	checkpointRuntime "vram-governor/internal/runtime"
)

// CanonicalResidencyCommandArgs is the shared signed-envelope shape for
// controller lifecycle and read-only residency commands.  The node derives
// its durable manifest and fingerprint from these exact arguments; callers
// must not add scheduler-only fields to the signed node command.
func CanonicalResidencyCommandArgs(targetID, model, runtimeIdentity, capabilityVersion, capabilityRevision, expectedTier string, fence int64) map[string]any {
	return map[string]any{
		"target_kind":         "llamacpp",
		"target_id":           targetID,
		"model":               model,
		"runtime_identity":    runtimeIdentity,
		"capability_version":  capabilityVersion,
		"capability_revision": capabilityRevision,
		"expected_tier":       expectedTier,
		"fencing_token":       fence,
	}
}

// ValidateResidencyCommandArgs is the protocol-level allowlist shared by the
// controller admission path, node envelope validation, and durable manifest
// recovery. Keeping this here prevents a field accepted by one boundary from
// being silently dropped or reinterpreted by another.
func ValidateResidencyCommandArgs(command string, args map[string]any) error {
	expected := map[string]string{
		"load_model": "hot_vram", "unload_model": "cold_disk", "warm_model": "warm_ram",
		"offload_model": "warm_ram", "demote_model": "warm_ram", "protect_warm_model": "warm_ram",
		"cleanup_warm_model": "cold_disk", "reverify_warm_model": "warm_ram", "query_model_state": "query",
	}
	tier, known := expected[command]
	if !known {
		return fmt.Errorf("unsupported residency command %q", command)
	}
	// Every action has an explicit allowlist. Keep this table centralized so
	// the HTTP admission path, node verifier, and durable manifest validator
	// cannot silently disagree about which signed fields exist.
	allowed := map[string]bool{
		"target_kind": true, "target_id": true, "model": true, "runtime_identity": true,
		"capability_version": true, "capability_revision": true, "expected_tier": true,
		"fencing_token": true,
	}
	switch command {
	case "warm_model", "offload_model", "demote_model":
		for _, key := range []string{"model_path", "path", "active_references", "protected"} {
			allowed[key] = true
		}
	case "protect_warm_model":
		for _, key := range []string{"active_references", "protected"} {
			allowed[key] = true
		}
	case "reverify_warm_model", "cleanup_warm_model":
		// These operations use the node's allowlisted model mapping and
		// authoritative local state; path/protection overrides are not signed
		// arguments and must be rejected at every boundary.
	}
	if command == "query_model_state" {
		for _, key := range []string{"expected_fence", "observed_after_fence", "original_command_id", "original_idempotency_key"} {
			allowed[key] = true
		}
	}
	// Required fields are action-specific even when their names are shared.
	// In particular, protection is never defaulted: a protect command must
	// carry both values in its signed envelope.
	if command == "protect_warm_model" {
		if _, ok := args["active_references"]; !ok {
			return fmt.Errorf("active_references is required for protect_warm_model")
		}
		if _, ok := args["protected"]; !ok {
			return fmt.Errorf("protected is required for protect_warm_model")
		}
	}
	for key := range args {
		if !allowed[key] {
			return fmt.Errorf("residency argument %s is not allowed for %s", key, command)
		}
	}
	for _, key := range []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision", "expected_tier"} {
		value, ok := args[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("residency argument %s is required", key)
		}
	}
	if args["target_kind"] != "llamacpp" || args["expected_tier"] != tier {
		return fmt.Errorf("residency target kind or expected tier is invalid")
	}
	if fence, ok := canonicalResidencyFence(args["fencing_token"]); !ok || fence < 0 {
		return fmt.Errorf("residency fencing_token must be a nonnegative integer")
	}
	if value, present := args["active_references"]; present {
		references, ok := canonicalResidencyFence(value)
		if !ok || references < 0 {
			return fmt.Errorf("active_references must be a nonnegative integer")
		}
	}
	if value, present := args["protected"]; present {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("protected must be a boolean")
		}
	}
	for _, key := range []string{"model_path", "path"} {
		if value, present := args[key]; present {
			if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" {
				return fmt.Errorf("%s must be a nonempty string", key)
			}
		}
	}
	if command == "query_model_state" {
		for _, key := range []string{"original_command_id", "original_idempotency_key"} {
			value, ok := args[key].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return fmt.Errorf("query %s is required", key)
			}
		}
		expectedFence, expectedOK := canonicalResidencyFence(args["expected_fence"])
		observedFence, observedOK := canonicalResidencyFence(args["observed_after_fence"])
		commandFence, commandFenceOK := canonicalResidencyFence(args["fencing_token"])
		if !expectedOK || !observedOK || !commandFenceOK || expectedFence < 0 || observedFence != expectedFence || commandFence != expectedFence {
			return fmt.Errorf("query fencing_token, expected_fence, and observed_after_fence must match")
		}
	}
	return nil
}

func canonicalResidencyFence(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case int32:
		return int64(number), true
	case uint64:
		if number > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(number), true
	case float64:
		if number != float64(int64(number)) {
			return 0, false
		}
		return int64(number), true
	case json.Number:
		var parsed int64
		if _, err := fmt.Sscan(string(number), &parsed); err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

// ValidateCheckpointCommandArgs is the canonical allowlist for every
// production LLM checkpoint phase. The node re-validates this after signature
// verification; controller callers cannot smuggle path or owner fields into a
// runtime-local request.
func ValidateCheckpointCommandArgs(command string, args map[string]any) error {
	const prefix = "checkpoint_"
	if !strings.HasPrefix(command, prefix) {
		return fmt.Errorf("invalid checkpoint command")
	}
	action := strings.TrimPrefix(command, prefix)
	allowedActions := map[string]bool{"slot_query": true, "slot_assign": true, "start": true, "pause": true, "save": true, "stop_confirm": true, "release": true, "reload": true, "restore": true, "reuse_verify": true, "resume": true, "rollback_resume": true, "cancel": true, "continue": true, "state_query": true}
	if !allowedActions[action] {
		return fmt.Errorf("checkpoint action %q is not allowlisted", action)
	}
	allowed := map[string]bool{"target_kind": true, "target_id": true, "accelerator_id": true, "model": true, "runtime_identity": true, "capability_version": true, "capability_revision": true, "profile_fingerprint": true, "context_fingerprint": true, "owner_id": true, "workload_id": true, "generation": true, "fencing_token": true, "context_limit": true, "checkpoint_action": true, "checkpoint_operation_id": true, "idempotency_key": true, "recovery_epoch": true, "compensation_of": true, "slot_id": true, "snapshot_name": true, "snapshot_digest": true, "saved_tokens": true, "partial_output_hash": true, "partial_output_offset": true, "conversation_id": true, "continuation_conversation_id": true, "assistant_prefix": true, "managed_stream": true, "controller_stream": true}
	for key := range args {
		if !allowed[key] {
			return fmt.Errorf("checkpoint argument %s is not allowed", key)
		}
	}
	for _, key := range []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision", "profile_fingerprint", "context_fingerprint", "owner_id", "workload_id", "checkpoint_operation_id"} {
		value, ok := args[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("checkpoint argument %s is required", key)
		}
	}
	for _, key := range []string{"accelerator_id"} {
		if value, ok := args[key].(string); !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("checkpoint argument %s is required", key)
		}
	}
	if args["target_kind"] != "llamacpp" {
		return fmt.Errorf("checkpoint target_kind must be llamacpp")
	}
	for _, key := range []string{"generation", "fencing_token", "context_limit"} {
		n, ok := canonicalResidencyFence(args[key])
		if !ok || n <= 0 {
			return fmt.Errorf("checkpoint argument %s must be positive", key)
		}
	}
	if got, _ := args["checkpoint_action"].(string); got != action {
		return fmt.Errorf("checkpoint action mismatch")
	}
	if name, ok := args["snapshot_name"].(string); ok && (name == "" || strings.ContainsAny(name, `/\\`) || strings.Contains(name, "..")) {
		return fmt.Errorf("unsafe snapshot name")
	}
	return nil
}

// ValidateOwnedStopCommandArgs is the finite wire allowlist for the local
// fixed-worker stop primitive. The query is read-only and must point back to
// the exact signed stop envelope that created the durable intent.
func ValidateOwnedStopCommandArgs(command string, args map[string]any) error {
	query := command == "llm_displacement_stop_query"
	if command != "llm_displacement_stop" && !query {
		return fmt.Errorf("unsupported owned stop command %q", command)
	}
	allowed := map[string]bool{
		"operation_id": true, "step_id": true, "target_kind": true, "target_id": true,
		"accelerator_id": true, "workload_id": true, "workload_revision": true,
		"model": true, "model_alias": true, "local_checkpoint_binding": true,
		"snapshot_name": true, "snapshot_digest": true, "recovery_epoch": true,
		"fencing_token": true,
	}
	if query {
		for _, key := range []string{"original_command_id", "original_idempotency_key", "original_envelope_sha256", "expected_fence", "observed_after_fence"} {
			allowed[key] = true
		}
	}
	for key := range args {
		if !allowed[key] {
			return fmt.Errorf("owned stop argument %s is not allowed", key)
		}
	}
	for _, key := range []string{"operation_id", "step_id", "target_id", "accelerator_id", "workload_id", "model", "model_alias", "local_checkpoint_binding", "snapshot_name", "snapshot_digest", "recovery_epoch"} {
		value, ok := args[key].(string)
		if !ok || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("owned stop argument %s is required", key)
		}
	}
	targetID, _ := args["target_id"].(string)
	if !canonicalOwnedStopTargetSyntax(targetID) {
		return fmt.Errorf("owned stop target_id is not a canonical node-qualified token")
	}
	step, _ := args["step_id"].(string)
	if step != "victim_stop" && step != "urgent_stop" {
		return fmt.Errorf("owned stop step_id is not allowlisted")
	}
	if args["target_kind"] != "llamacpp" {
		return fmt.Errorf("owned stop target kind is invalid")
	}
	revision, revisionOK := canonicalResidencyFence(args["workload_revision"])
	fence, fenceOK := canonicalResidencyFence(args["fencing_token"])
	if !revisionOK || revision <= 0 || !fenceOK || fence <= 0 {
		return fmt.Errorf("owned stop revision and fence must be positive integers")
	}
	name, _ := args["snapshot_name"].(string)
	if strings.ContainsAny(name, `/\\`) || strings.Contains(name, "..") || !strings.HasSuffix(name, ".kv") {
		return fmt.Errorf("owned stop snapshot name is unsafe")
	}
	for _, key := range []string{"local_checkpoint_binding", "snapshot_digest"} {
		value, _ := args[key].(string)
		if strings.HasPrefix(value, "sha256:") {
			value = strings.TrimPrefix(value, "sha256:")
		}
		if !isCanonicalSHA256(value) {
			return fmt.Errorf("owned stop argument %s must be a lowercase sha256 digest", key)
		}
	}
	if query {
		for _, key := range []string{"original_command_id", "original_idempotency_key", "original_envelope_sha256"} {
			value, ok := args[key].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return fmt.Errorf("owned stop query argument %s is required", key)
			}
		}
		if digest, _ := args["original_envelope_sha256"].(string); !isCanonicalSHA256(digest) {
			return fmt.Errorf("owned stop query envelope digest is invalid")
		}
		expected, expectedOK := canonicalResidencyFence(args["expected_fence"])
		observed, observedOK := canonicalResidencyFence(args["observed_after_fence"])
		if !expectedOK || !observedOK || expected != fence || observed != fence {
			return fmt.Errorf("owned stop query must preserve the original resource fence")
		}
	}
	return nil
}

// ValidatePlanRelaunchCommandArgs is a distinct typed wire contract for the
// catalog-backed urgent-load and victim-reload broker. It deliberately does
// not share the owned-stop allowlist: a stop receipt is only a predecessor
// proof and never grants generic plan, process, or command authority.
func ValidatePlanRelaunchCommandArgs(command string, args map[string]any) error {
	const urgent = "llm_displacement_plan_urgent_load"
	const victim = "llm_displacement_plan_victim_reload"
	const query = "llm_displacement_plan_query"
	if command != urgent && command != victim && command != query {
		return fmt.Errorf("unsupported plan relaunch command %q", command)
	}
	allowed := map[string]bool{
		"operation_id": true, "target_kind": true, "target_id": true,
		"accelerator_id": true, "workload_id": true, "workload_revision": true,
		"recovery_epoch": true, "fencing_token": true, "catalog_id": true,
		"prior_command_id": true, "prior_idempotency_key": true,
		"prior_receipt_sha256": true,
	}
	if command == urgent {
		allowed["linked_catalog_id"] = true
	}
	if command == query {
		for _, key := range []string{"query_step", "original_command_id", "original_idempotency_key", "original_envelope_sha256", "expected_fence", "observed_after_fence"} {
			allowed[key] = true
		}
		allowed["linked_catalog_id"] = true
	}
	for key := range args {
		if !allowed[key] {
			return fmt.Errorf("plan relaunch argument %s is not allowed", key)
		}
	}
	for _, key := range []string{"operation_id", "target_id", "accelerator_id", "workload_id", "recovery_epoch", "catalog_id", "prior_command_id", "prior_idempotency_key"} {
		value, ok := args[key].(string)
		if !ok || !canonicalPlanRelaunchToken(value) {
			return fmt.Errorf("plan relaunch argument %s is malformed", key)
		}
	}
	if args["target_kind"] != "llamacpp" || !canonicalOwnedStopTargetSyntax(fmt.Sprint(args["target_id"])) {
		return fmt.Errorf("plan relaunch target is invalid")
	}
	if command == urgent {
		linked, ok := args["linked_catalog_id"].(string)
		if !ok || !canonicalPlanRelaunchToken(linked) || linked == args["catalog_id"] {
			return fmt.Errorf("urgent load must identify distinct approved urgent and victim catalogs")
		}
	}
	if command == query {
		step, ok := args["query_step"].(string)
		if !ok || (step != "urgent_load" && step != "victim_reload") {
			return fmt.Errorf("plan relaunch query step is invalid")
		}
		for _, key := range []string{"original_command_id", "original_idempotency_key"} {
			value, ok := args[key].(string)
			if !ok || !canonicalPlanRelaunchToken(value) {
				return fmt.Errorf("plan relaunch query %s is malformed", key)
			}
		}
		if digest, ok := args["original_envelope_sha256"].(string); !ok || !isCanonicalSHA256(digest) {
			return fmt.Errorf("plan relaunch query original envelope digest is invalid")
		}
		expected, expectedOK := canonicalResidencyFence(args["expected_fence"])
		observed, observedOK := canonicalResidencyFence(args["observed_after_fence"])
		fence, fenceOK := canonicalResidencyFence(args["fencing_token"])
		if !expectedOK || !observedOK || !fenceOK || expected <= 0 || observed != expected || fence != expected {
			return fmt.Errorf("plan relaunch query fence does not match the original intent")
		}
		if step == "urgent_load" {
			linked, ok := args["linked_catalog_id"].(string)
			if !ok || !canonicalPlanRelaunchToken(linked) || linked == args["catalog_id"] {
				return fmt.Errorf("urgent-load query must preserve its distinct linked victim catalog")
			}
		} else if _, exists := args["linked_catalog_id"]; exists {
			return fmt.Errorf("victim-reload query cannot carry an unrelated linked catalog")
		}
	}
	for _, key := range []string{"prior_receipt_sha256"} {
		value, ok := args[key].(string)
		if !ok || !isCanonicalSHA256(value) {
			return fmt.Errorf("plan relaunch argument %s is invalid", key)
		}
	}
	for _, key := range []string{"workload_revision", "fencing_token"} {
		value, ok := canonicalResidencyFence(args[key])
		if !ok || value <= 0 {
			return fmt.Errorf("plan relaunch argument %s must be positive", key)
		}
	}
	if command == query {
		if args["prior_command_id"] == args["original_command_id"] || args["prior_idempotency_key"] == args["original_idempotency_key"] {
			return fmt.Errorf("plan relaunch query predecessor must differ from the queried command")
		}
	}
	return nil
}

func canonicalPlanRelaunchToken(value string) bool {
	if value == "" || len(value) > 160 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\\x00\r\n\t") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

// canonicalOwnedStopTargetSyntax validates only the wire-level shape. Exact
// membership in the configured node/server set is checked by node-agent
// preflight, where that authority is available.
func canonicalOwnedStopTargetSyntax(targetID string) bool {
	if strings.TrimSpace(targetID) != targetID || strings.ContainsAny(targetID, "/\\\x00\r\n\t") {
		return false
	}
	separator := strings.IndexByte(targetID, '-')
	return separator > 0 && separator < len(targetID)-1
}

func isCanonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// ResidencyCommandFingerprint is the shared semantic identity of a signed
// residency mutation. IDs and expiry windows are intentionally excluded;
// every replay/reconciliation boundary compares this digest against the
// canonical original arguments instead of trusting a tier alone.
func ResidencyCommandFingerprint(nodeID, command, idempotencyKey string, args map[string]any) string {
	material, _ := json.Marshal(struct {
		Key, Node, Command string
		Args               map[string]any
	}{idempotencyKey, nodeID, command, args})
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:])
}

// MsgType discriminates the envelope payload.
type MsgType string

const (
	// Node -> Controller
	MsgRegister     MsgType = "register"
	MsgHeartbeat    MsgType = "heartbeat"
	MsgTelemetry    MsgType = "telemetry"
	MsgCapabilities MsgType = "capabilities"
	MsgEvent        MsgType = "event"

	// Controller -> Node
	MsgAck           MsgType = "ack"
	MsgCommand       MsgType = "command"
	MsgCommandResult MsgType = "command_result"
)

// Envelope is the outer frame for every message on the control channel.
type Envelope struct {
	Type MsgType   `json:"type"`
	Time time.Time `json:"time"`
	// Payload is one of the Register/Heartbeat/Telemetry/Event/Ack/Command
	// structs below, encoded as raw JSON. Callers decode based on Type.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// RegisterPayload is sent once, immediately after the node dials in and
// authenticates. It carries the static facts about the node.
type RegisterPayload struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	// Ready is optional for wire compatibility with legacy agents. New agents
	// send it explicitly so a blocked processor cannot register as schedulable.
	Ready                      *bool                        `json:"ready,omitempty"`
	LocationClass              string                       `json:"location_class"`     // domain.LocationClass
	PowerControlMode           string                       `json:"power_control_mode"` // domain.PowerControlMode
	GPUPerformanceIndices      []int                        `json:"gpu_performance_indices,omitempty"`
	AgentVersion               string                       `json:"agent_version"`
	CapabilityVersion          string                       `json:"capability_version,omitempty"`
	Capabilities               domain.ResidencyCapabilities `json:"capabilities"`
	Capacity                   domain.CapacityBudget        `json:"capacity"`
	MaxAcceleratorsPerWorkload int                          `json:"max_accelerators_per_workload"`
	Adapters                   []AdapterAdvertisement       `json:"adapters,omitempty"`
}

func (p *RegisterPayload) UnmarshalJSON(data []byte) error {
	type registerPayloadAlias RegisterPayload
	var decoded registerPayloadAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	fields, err := strictObjectFields(data, "register payload", map[string]struct{}{
		"node_id": {}, "node_name": {}, "ready": {}, "location_class": {}, "power_control_mode": {},
		"gpu_performance_indices": {}, "agent_version": {}, "capability_version": {}, "capabilities": {},
		"capacity": {}, "max_accelerators_per_workload": {}, "adapters": {},
	})
	if err != nil {
		return err
	}
	if err := validateNonNullFields(fields, "register payload"); err != nil {
		return err
	}
	if raw := fields["capabilities"]; raw != nil {
		if err := validateResidencyCapabilitiesJSON(raw); err != nil {
			return err
		}
	}
	if raw := fields["capacity"]; raw != nil {
		if err := validateCapacityBudgetJSON(raw); err != nil {
			return err
		}
	}
	if raw := fields["adapters"]; raw != nil {
		var adapters []json.RawMessage
		if err := json.Unmarshal(raw, &adapters); err != nil || adapters == nil {
			return fmt.Errorf("register payload adapters must be an array")
		}
		for _, adapter := range adapters {
			if err := validateAdapterAdvertisementJSON(adapter); err != nil {
				return err
			}
		}
	}
	*p = RegisterPayload(decoded)
	return nil
}

func strictObjectFields(data []byte, label string, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		if err != nil {
			return nil, fmt.Errorf("%s must be a JSON object: %w", label, err)
		}
		return nil, fmt.Errorf("%s must be a JSON object", label)
	}
	for key := range fields {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("%s field %q is not a canonical JSON key", label, key)
		}
	}
	return fields, nil
}

func validateNonNullFields(fields map[string]json.RawMessage, label string) error {
	for key, raw := range fields {
		if string(raw) == "null" {
			return fmt.Errorf("%s field %q may not be null", label, key)
		}
	}
	return nil
}

func validateResidencyCapabilitiesJSON(raw []byte) error {
	fields, err := strictObjectFields(raw, "capabilities", map[string]struct{}{
		"version": {}, "supports_warm_ram": {}, "warm_ram_verified": {}, "warm_ram_verification": {},
		"supports_session_checkpoint": {}, "session_checkpoint_verified": {}, "session_checkpoint_proof": {},
		"supports_yield": {}, "yield_verified": {}, "yield_proof": {}, "supports_model_lifecycle": {},
		"supports_accelerator_reclaim": {}, "max_resident_models": {}, "max_accelerators_per_workload": {},
	})
	if err != nil {
		return err
	}
	return validateNonNullFields(fields, "capabilities")
}

func validateCapacityBudgetJSON(raw []byte) error {
	fields, err := strictObjectFields(raw, "capacity", map[string]struct{}{
		"vram_total_bytes": {}, "vram_reserve_bytes": {}, "vram_hard_cap_bytes": {},
		"ram_total_bytes": {}, "ram_reserve_bytes": {}, "ram_hard_cap_bytes": {},
		"disk_available_bytes": {},
	})
	if err != nil {
		return err
	}
	return validateNonNullFields(fields, "capacity")
}

func validateRuntimeProfileJSON(raw []byte) error {
	fields, err := strictObjectFields(raw, "runtime profile", map[string]struct{}{
		"id": {}, "context_limit": {}, "slots": {},
	})
	if err != nil {
		return err
	}
	return validateNonNullFields(fields, "runtime profile")
}

func validateAdapterAdvertisementJSON(raw []byte) error {
	fields, err := strictObjectFields(raw, "adapter advertisement", map[string]struct{}{
		"id": {}, "adapter": {}, "endpoint": {}, "accelerator_index": {}, "models": {},
		"resident_models": {}, "custom_nodes": {}, "version": {}, "model_fingerprint": {},
		"context_limit": {}, "slots": {}, "capacity_source": {}, "capabilities_verified": {},
		"runtime_args": {}, "supports_model_lifecycle": {}, "supports_accelerator_reclaim": {},
		"max_resident_models": {}, "warm_ram_supported": {}, "queue_running": {}, "queue_pending": {},
		"standalone_vram_mb": {}, "standalone_vram_source": {}, "standalone_vram_verified": {},
		"runtime_profiles": {}, "active_runtime_profile": {}, "supports_runtime_profile_switch": {},
		"capability_version": {}, "capability_revision": {}, "capability_generation": {}, "capabilities": {}, "capacity": {},
		"max_accelerators_per_workload": {}, "model_capacity_observations": {}, "checkpoint_proof": {},
		"model_pools": {},
	})
	if err != nil {
		return err
	}
	if err := validateNonNullFields(fields, "adapter advertisement"); err != nil {
		return err
	}
	if raw := fields["model_pools"]; raw != nil {
		var pools map[string]json.RawMessage
		if err := json.Unmarshal(raw, &pools); err != nil || pools == nil {
			return fmt.Errorf("adapter advertisement model_pools must be an object")
		}
		for model, pool := range pools {
			poolFields, err := strictObjectFields(pool, "model pool "+model, map[string]struct{}{"pool_tokens": {}, "slots": {}, "max_request_tokens": {}})
			if err != nil {
				return err
			}
			if err := validateNonNullFields(poolFields, "model pool "+model); err != nil {
				return err
			}
		}
	}
	if raw := fields["capabilities"]; raw != nil {
		if err := validateResidencyCapabilitiesJSON(raw); err != nil {
			return err
		}
	}
	if raw := fields["capacity"]; raw != nil {
		if err := validateCapacityBudgetJSON(raw); err != nil {
			return err
		}
	}
	if raw := fields["runtime_profiles"]; raw != nil {
		var profiles []json.RawMessage
		if err := json.Unmarshal(raw, &profiles); err != nil || profiles == nil {
			return fmt.Errorf("adapter advertisement runtime_profiles must be an array")
		}
		for _, profile := range profiles {
			if err := validateRuntimeProfileJSON(profile); err != nil {
				return err
			}
		}
	}
	if raw := fields["model_capacity_observations"]; raw != nil {
		var observations []json.RawMessage
		if err := json.Unmarshal(raw, &observations); err != nil || observations == nil {
			return fmt.Errorf("adapter advertisement model_capacity_observations must be an array")
		}
		for _, observation := range observations {
			if err := validateModelCapacityObservationJSON(observation); err != nil {
				return err
			}
		}
	}
	if raw := fields["checkpoint_proof"]; raw != nil {
		if err := validateCheckpointProofJSON(raw); err != nil {
			return err
		}
	}
	return nil
}

func validateCheckpointProofJSON(raw []byte) error {
	legacyZeroRequiredFields := map[string]struct{}{
		"verified": {}, "probe_only": {}, "slot_assignment": {}, "safe_boundary_pause": {}, "snapshot_save": {}, "backend_stop_confirmed": {}, "snapshot_restore": {}, "kv_reused": {}, "proven_at": {}, "node_id": {}, "target_id": {}, "model_fingerprint": {}, "runtime_identity": {}, "profile_fingerprint": {}, "context_limit": {}, "slot_id": {}, "generation": {}, "old_fence": {}, "new_fence": {}, "saved_tokens": {}, "reused_tokens": {}, "evidence_id": {}, "signature": {}, "digest": {}, "snapshot_digest": {}, "snapshot_bytes": {}, "accelerator_id": {}, "expires_at": {}, "nonce": {},
	}
	allowed := map[string]struct{}{
		"proof_version": {}, "model_alias": {}, "local_checkpoint_binding": {},
		"verified": {}, "probe_only": {}, "slot_assignment": {}, "safe_boundary_pause": {}, "snapshot_save": {}, "backend_stop_confirmed": {}, "snapshot_restore": {}, "kv_reused": {}, "proven_at": {}, "reason": {}, "node_id": {}, "target_id": {}, "model_fingerprint": {}, "runtime_identity": {}, "profile_fingerprint": {}, "context_limit": {}, "slot_id": {}, "generation": {}, "old_fence": {}, "new_fence": {}, "saved_tokens": {}, "reused_tokens": {}, "evidence_id": {}, "signature": {}, "digest": {}, "snapshot_digest": {}, "snapshot_bytes": {}, "accelerator_id": {}, "expires_at": {}, "nonce": {},
	}
	fields, err := strictObjectFields(raw, "checkpoint proof", allowed)
	if err != nil {
		return err
	}
	if len(fields) == 0 { // The zero struct is the wire representation of no proof.
		return nil
	}
	if err := validateNonNullFields(fields, "checkpoint proof"); err != nil {
		return err
	}
	// Older node encoders did not omit a zero-valued struct, so they sent all
	// pre-v2 fields as zero values. Accept only that exact representation as
	// “no claim”; legacy positive proofs remain invalid capability material.
	if len(fields) == len(legacyZeroRequiredFields) || len(fields) == len(legacyZeroRequiredFields)+1 {
		legacyShape := true
		for key := range legacyZeroRequiredFields {
			if _, ok := fields[key]; !ok {
				legacyShape = false
				break
			}
		}
		_, reasonPresent := fields["reason"]
		legacyShape = legacyShape && ((len(fields) == len(legacyZeroRequiredFields) && !reasonPresent) || (len(fields) == len(legacyZeroRequiredFields)+1 && reasonPresent))
		if legacyShape {
			var proof checkpointRuntime.CheckpointCapabilityProof
			if err := json.Unmarshal(raw, &proof); err != nil {
				return fmt.Errorf("legacy checkpoint proof is malformed: %w", err)
			}
			if proof == (checkpointRuntime.CheckpointCapabilityProof{}) {
				return nil
			}
			return fmt.Errorf("legacy checkpoint proof cannot claim capability")
		}
	}
	for key := range allowed {
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("checkpoint proof is missing required field %q", key)
		}
	}
	var proof checkpointRuntime.CheckpointCapabilityProof
	if err := json.Unmarshal(raw, &proof); err != nil || !proof.ComponentsComplete() {
		return fmt.Errorf("checkpoint proof is malformed or incomplete v2 material")
	}
	return nil
}

// rejectDuplicateJSONKeys walks every object before map decoding can collapse
// repeated keys. encoding/json otherwise accepts the last value silently.
func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func validateModelCapacityObservationJSON(raw []byte) error {
	fields, err := strictObjectFields(raw, "model capacity observation", map[string]struct{}{
		"accelerator_id": {}, "model": {}, "profile_id": {}, "model_fingerprint": {},
		"runtime_identity": {}, "capability_version": {}, "capability_revision": {},
		"model_bytes": {}, "profile_bytes": {}, "vram_reserve_bytes": {},
		"runtime_hard_cap_bytes": {}, "ram_bytes": {}, "ram_reserve_bytes": {},
		"vram_total_bytes": {}, "ram_total_bytes": {}, "unified_memory": {},
		"observed_at": {}, "source": {}, "verified": {},
	})
	if err != nil {
		return err
	}
	return validateNonNullFields(fields, "model capacity observation")
}

func (p *AdapterAdvertisement) UnmarshalJSON(data []byte) error {
	type adapterAdvertisementAlias AdapterAdvertisement
	var decoded adapterAdvertisementAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if err := validateAdapterAdvertisementJSON(data); err != nil {
		return err
	}
	*p = AdapterAdvertisement(decoded)
	return nil
}

func (p AdapterAdvertisement) MarshalJSON() ([]byte, error) {
	type adapterAdvertisementAlias AdapterAdvertisement
	encoded, err := json.Marshal(adapterAdvertisementAlias(p))
	if err != nil || p.CheckpointProof != (checkpointRuntime.CheckpointCapabilityProof{}) {
		return encoded, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	delete(fields, "checkpoint_proof")
	return json.Marshal(fields)
}

func (p *RuntimeProfileAdvertisement) UnmarshalJSON(data []byte) error {
	type runtimeProfileAdvertisementAlias RuntimeProfileAdvertisement
	var decoded runtimeProfileAdvertisementAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if err := validateRuntimeProfileJSON(data); err != nil {
		return err
	}
	*p = RuntimeProfileAdvertisement(decoded)
	return nil
}

// ModelCapacityObservationAdvertisement is emitted only when the runtime
// reports positive bytes attributable to one exact model/profile on one
// accelerator. Configured device totals are envelope facts, never footprints.
type ModelCapacityObservationAdvertisement struct {
	AcceleratorID       string    `json:"accelerator_id"`
	Model               string    `json:"model"`
	ProfileID           string    `json:"profile_id"`
	ModelFingerprint    string    `json:"model_fingerprint"`
	RuntimeIdentity     string    `json:"runtime_identity"`
	CapabilityVersion   string    `json:"capability_version"`
	CapabilityRevision  string    `json:"capability_revision"`
	ModelBytes          int64     `json:"model_bytes"`
	ProfileBytes        int64     `json:"profile_bytes"`
	VRAMReserveBytes    int64     `json:"vram_reserve_bytes"`
	RuntimeHardCapBytes int64     `json:"runtime_hard_cap_bytes"`
	RAMBytes            int64     `json:"ram_bytes"`
	RAMReserveBytes     int64     `json:"ram_reserve_bytes"`
	VRAMTotalBytes      int64     `json:"vram_total_bytes"`
	RAMTotalBytes       int64     `json:"ram_total_bytes"`
	UnifiedMemory       bool      `json:"unified_memory"`
	ObservedAt          time.Time `json:"observed_at"`
	Source              string    `json:"source"`
	Verified            bool      `json:"verified"`
}

// AdapterAdvertisement reports existing runtime capabilities. No protocol
// command permits installing arbitrary ComfyUI custom nodes.
type AdapterAdvertisement struct {
	ID                           string                                  `json:"id"`
	Adapter                      string                                  `json:"adapter"`
	Endpoint                     string                                  `json:"endpoint"`
	AcceleratorIndex             int                                     `json:"accelerator_index"`
	Models                       []string                                `json:"models,omitempty"`
	ResidentModels               []string                                `json:"resident_models,omitempty"`
	CustomNodes                  []string                                `json:"custom_nodes,omitempty"`
	Version                      string                                  `json:"version,omitempty"`
	ModelFingerprint             string                                  `json:"model_fingerprint,omitempty"`
	ContextLimit                 int                                     `json:"context_limit,omitempty"`
	Slots                        int                                     `json:"slots,omitempty"`
	CapacitySource               string                                  `json:"capacity_source,omitempty"`
	CapabilitiesVerified         bool                                    `json:"capabilities_verified,omitempty"`
	RuntimeArgs                  []string                                `json:"runtime_args,omitempty"`
	SupportsModelLifecycle       bool                                    `json:"supports_model_lifecycle,omitempty"`
	SupportsAcceleratorReclaim   bool                                    `json:"supports_accelerator_reclaim,omitempty"`
	MaxResidentModels            int                                     `json:"max_resident_models,omitempty"`
	WarmRAMSupported             bool                                    `json:"warm_ram_supported,omitempty"`
	QueueRunning                 int                                     `json:"queue_running,omitempty"`
	QueuePending                 int                                     `json:"queue_pending,omitempty"`
	StandaloneVRAMMB             int64                                   `json:"standalone_vram_mb,omitempty"`
	StandaloneVRAMSource         string                                  `json:"standalone_vram_source,omitempty"`
	StandaloneVRAMVerified       bool                                    `json:"standalone_vram_verified,omitempty"`
	RuntimeProfiles              []RuntimeProfileAdvertisement           `json:"runtime_profiles,omitempty"`
	ActiveRuntimeProfile         string                                  `json:"active_runtime_profile,omitempty"`
	SupportsRuntimeProfileSwitch bool                                    `json:"supports_runtime_profile_switch,omitempty"`
	CapabilityVersion            string                                  `json:"capability_version,omitempty"`
	CapabilityRevision           string                                  `json:"capability_revision,omitempty"`
	CapabilityGeneration         uint64                                  `json:"capability_generation,omitempty"`
	Capabilities                 domain.ResidencyCapabilities            `json:"capabilities"`
	Capacity                     domain.CapacityBudget                   `json:"capacity"`
	MaxAcceleratorsPerWorkload   int                                     `json:"max_accelerators_per_workload"`
	ModelCapacityObservations    []ModelCapacityObservationAdvertisement `json:"model_capacity_observations,omitempty"`
	// CheckpointProof is target-scoped signed evidence. The capability string
	// remains a compatibility summary; controllers must consume this identity-
	// bound record before admitting native checkpoint preemption.
	CheckpointProof checkpointRuntime.CheckpointCapabilityProof `json:"checkpoint_proof,omitempty"`

	// ModelPools is each model's shared context pool, as configured on the
	// node (llama.cpp unified KV cache): see workloads.ModelPool.
	ModelPools map[string]ModelPool `json:"model_pools,omitempty"`
}

// RuntimeProfileAdvertisement is a finite, node-allowlisted capacity mode for
// one runtime endpoint. Commands remain node-local and are never advertised.
type RuntimeProfileAdvertisement struct {
	ID           string `json:"id"`
	ContextLimit int    `json:"context_limit"`
	Slots        int    `json:"slots"`
}

// AcceleratorTelemetry mirrors live device counters measured by the node
// agent through NVIDIA or AMD's driver interfaces.
type AcceleratorTelemetry struct {
	Index            int     `json:"index"`
	Name             string  `json:"name"`
	Vendor           string  `json:"vendor,omitempty"`
	MemoryKind       string  `json:"memory_kind,omitempty"`
	VRAMTotalMB      int64   `json:"vram_total_mb"`
	VRAMUsedMB       int64   `json:"vram_used_mb"`
	VRAMFreeMB       int64   `json:"vram_free_mb"`
	UtilizationPct   float64 `json:"utilization_pct"`
	TemperatureC     float64 `json:"temperature_c"`
	Driver           string  `json:"driver,omitempty"`
	PowerDrawW       float64 `json:"power_draw_w,omitempty"`
	PowerLimitW      float64 `json:"power_limit_w,omitempty"`
	FanSpeedPct      float64 `json:"fan_speed_pct,omitempty"`
	GraphicsClockMHz float64 `json:"graphics_clock_mhz,omitempty"`
	MemoryClockMHz   float64 `json:"memory_clock_mhz,omitempty"`
	PCIeGeneration   int     `json:"pcie_generation,omitempty"`
	PCIeWidth        int     `json:"pcie_width,omitempty"`
	PerformanceState string  `json:"performance_state,omitempty"`
}

// HeartbeatPayload is sent ~every 2s (§34A). It is intentionally tiny;
// richer telemetry rides in TelemetryPayload on the same cadence in Phase 1
// (they could be decoupled later).
type HeartbeatPayload struct {
	NodeID string `json:"node_id"`
	Ready  bool   `json:"ready"`
}

// TelemetryPayload carries GPU telemetry gathered from the active driver.
type TelemetryPayload struct {
	NodeID       string                 `json:"node_id"`
	Accelerators []AcceleratorTelemetry `json:"accelerators"`
	System       SystemTelemetry        `json:"system"`
	AgentLogs    []LogEntry             `json:"agent_logs,omitempty"`
}

type SystemTelemetry struct {
	Hostname          string    `json:"hostname,omitempty"`
	OS                string    `json:"os,omitempty"`
	Kernel            string    `json:"kernel,omitempty"`
	Architecture      string    `json:"architecture,omitempty"`
	CPUModel          string    `json:"cpu_model,omitempty"`
	CPULogical        int       `json:"cpu_logical,omitempty"`
	CPUUtilizationPct float64   `json:"cpu_utilization_pct,omitempty"`
	Load1             float64   `json:"load_1,omitempty"`
	Load5             float64   `json:"load_5,omitempty"`
	Load15            float64   `json:"load_15,omitempty"`
	RAMTotalMB        int64     `json:"ram_total_mb,omitempty"`
	RAMUsedMB         int64     `json:"ram_used_mb,omitempty"`
	RAMAvailableMB    int64     `json:"ram_available_mb,omitempty"`
	SwapTotalMB       int64     `json:"swap_total_mb,omitempty"`
	SwapUsedMB        int64     `json:"swap_used_mb,omitempty"`
	RootDiskTotalMB   int64     `json:"root_disk_total_mb,omitempty"`
	RootDiskUsedMB    int64     `json:"root_disk_used_mb,omitempty"`
	RootDiskFreeMB    int64     `json:"root_disk_free_mb,omitempty"`
	NetworkAddresses  []string  `json:"network_addresses,omitempty"`
	NetworkRXBPS      float64   `json:"network_rx_bytes_per_second"`
	NetworkTXBPS      float64   `json:"network_tx_bytes_per_second"`
	UptimeSeconds     float64   `json:"uptime_seconds,omitempty"`
	SampledAt         time.Time `json:"sampled_at"`
}

type LogEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// CapabilitiesPayload refreshes runtime-derived adapter facts without
// reconnecting the node control channel.
type CapabilitiesPayload struct {
	NodeID                     string                       `json:"node_id"`
	CapabilityVersion          string                       `json:"capability_version,omitempty"`
	CapabilityRevision         string                       `json:"capability_revision,omitempty"`
	Capabilities               domain.ResidencyCapabilities `json:"capabilities"`
	Capacity                   domain.CapacityBudget        `json:"capacity"`
	MaxAcceleratorsPerWorkload int                          `json:"max_accelerators_per_workload"`
	Adapters                   []AdapterAdvertisement       `json:"adapters"`
	// EnvelopePresent distinguishes a legacy adapters-only refresh from an
	// authoritative node envelope that intentionally carries empty/false facts.
	// It is derived from JSON field presence and never serialized.
	EnvelopePresent          bool `json:"-"`
	CapabilityVersionPresent bool `json:"-"`
	CapabilitiesPresent      bool `json:"-"`
	CapacityPresent          bool `json:"-"`
	// CapacityFieldsPresent preserves field-level JSON presence for partial
	// capability refreshes. A present zero is an explicit update; an omitted
	// field inherits the registered node's authoritative value.
	CapacityFieldsPresent             map[string]bool `json:"-"`
	MaxAcceleratorsPerWorkloadPresent bool            `json:"-"`
}

func (p *CapabilitiesPayload) UnmarshalJSON(data []byte) error {
	type capabilitiesPayloadAlias CapabilitiesPayload
	var decoded capabilitiesPayloadAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	fields, err := strictObjectFields(data, "capabilities payload", map[string]struct{}{
		"node_id": {}, "capability_version": {}, "capability_revision": {}, "capabilities": {},
		"capacity": {}, "max_accelerators_per_workload": {}, "adapters": {},
	})
	if err != nil {
		return err
	}
	if err := validateNonNullFields(fields, "capabilities payload"); err != nil {
		return err
	}
	if raw := fields["capabilities"]; raw != nil {
		if err := validateResidencyCapabilitiesJSON(raw); err != nil {
			return err
		}
	}
	if raw := fields["capacity"]; raw != nil {
		if err := validateCapacityBudgetJSON(raw); err != nil {
			return err
		}
	}
	if raw := fields["adapters"]; raw != nil {
		var adapters []json.RawMessage
		if err := json.Unmarshal(raw, &adapters); err != nil || adapters == nil {
			return fmt.Errorf("capabilities payload adapters must be an array")
		}
		for _, adapter := range adapters {
			if err := validateAdapterAdvertisementJSON(adapter); err != nil {
				return err
			}
		}
	}
	_, decoded.CapabilityVersionPresent = fields["capability_version"]
	if _, ok := fields["capability_revision"]; ok {
		if string(fields["capability_revision"]) == "null" {
			return fmt.Errorf("capability_revision may not be null")
		}
	}
	_, decoded.CapabilitiesPresent = fields["capabilities"]
	_, decoded.CapacityPresent = fields["capacity"]
	if decoded.CapacityPresent {
		decoded.CapacityFieldsPresent = make(map[string]bool)
		var capacityFields map[string]json.RawMessage
		raw := fields["capacity"]
		if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &capacityFields) != nil || capacityFields == nil {
			return fmt.Errorf("capacity must be a JSON object")
		}
		for field := range capacityFields {
			decoded.CapacityFieldsPresent[field] = true
		}
	}
	_, decoded.MaxAcceleratorsPerWorkloadPresent = fields["max_accelerators_per_workload"]
	decoded.EnvelopePresent = decoded.CapabilityVersionPresent || decoded.CapabilitiesPresent || decoded.CapacityPresent || decoded.MaxAcceleratorsPerWorkloadPresent
	*p = CapabilitiesPayload(decoded)
	return nil
}

// RouterModelState is the canonical state vocabulary shared by the controller
// and node agent for llama.cpp's /v1/models endpoint.
type RouterModelState uint8

const (
	RouterModelUnknown RouterModelState = iota
	RouterModelUnloaded
	RouterModelLoaded
)

type RouterModelRecord struct {
	ID    string
	State RouterModelState
}

// ParseRouterModels validates the complete llama.cpp model envelope. A valid
// empty array means no model is resident; malformed nonmatching entries still
// fail so callers cannot infer cold state from a corrupted response.
func ParseRouterModels(body []byte) ([]RouterModelRecord, error) {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("models response is malformed: %w", err)
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, fmt.Errorf("models response is missing data array")
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Data, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("models data is not an array")
	}
	seen := make(map[string]struct{}, len(entries))
	result := make([]RouterModelRecord, 0, len(entries))
	for _, entry := range entries {
		idRaw, ok := entry["id"]
		if !ok {
			return nil, fmt.Errorf("models entry is missing id")
		}
		var id string
		if json.Unmarshal(idRaw, &id) != nil || strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("models entry id is not a nonempty string")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("models response contains duplicate id %q", id)
		}
		seen[id] = struct{}{}
		statusRaw, ok := entry["status"]
		if !ok {
			return nil, fmt.Errorf("models entry %q is missing status", id)
		}
		status, ok := routerModelStatusValue(statusRaw)
		if !ok {
			return nil, fmt.Errorf("models entry %q status is not an authoritative string", id)
		}
		var state RouterModelState
		switch status {
		case "loaded":
			state = RouterModelLoaded
		case "unloaded":
			state = RouterModelUnloaded
		case "loading", "unloading", "unknown":
			state = RouterModelUnknown
		default:
			return nil, fmt.Errorf("models entry %q has unsupported status %q", id, status)
		}
		result = append(result, RouterModelRecord{ID: id, State: state})
	}
	return result, nil
}

// routerModelStatusValue accepts llama.cpp's router status, which is either a
// bare string or an object whose "value" field carries the state.
func routerModelStatusValue(raw json.RawMessage) (string, bool) {
	var status string
	if json.Unmarshal(raw, &status) == nil {
		return status, status != ""
	}
	var object struct {
		Value *string `json:"value"`
	}
	if json.Unmarshal(raw, &object) == nil && object.Value != nil && *object.Value != "" {
		return *object.Value, true
	}
	return "", false
}

// ParseLlamaModels parses /v1/models from either a llama.cpp router (every
// entry carries a status) or a plain single-model llama-server (no entry
// carries one). A plain server serves exactly what it lists, so its models
// are reported loaded and plain=true. Mixed responses are rejected.
func ParseLlamaModels(body []byte) (records []RouterModelRecord, plain bool, err error) {
	var envelope struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &envelope) == nil && len(envelope.Data) > 0 {
		withStatus := 0
		for _, entry := range envelope.Data {
			if _, ok := entry["status"]; ok {
				withStatus++
			}
		}
		if withStatus == 0 {
			seen := make(map[string]struct{}, len(envelope.Data))
			for _, entry := range envelope.Data {
				var id string
				if json.Unmarshal(entry["id"], &id) != nil || strings.TrimSpace(id) == "" {
					return nil, false, fmt.Errorf("models entry id is not a nonempty string")
				}
				if _, duplicate := seen[id]; duplicate {
					return nil, false, fmt.Errorf("models response contains duplicate id %q", id)
				}
				seen[id] = struct{}{}
				records = append(records, RouterModelRecord{ID: id, State: RouterModelLoaded})
			}
			return records, true, nil
		}
	}
	records, err = ParseRouterModels(body)
	return records, false, err
}

func ParseRouterModelState(body []byte, wanted string) (RouterModelState, error) {
	entries, err := ParseRouterModels(body)
	if err != nil {
		return RouterModelUnknown, err
	}
	for _, entry := range entries {
		if entry.ID == wanted {
			return entry.State, nil
		}
	}
	return RouterModelUnloaded, nil
}

// EventPayload is a free-form lifecycle event (architecture.md §28). Phase 1
// does not generate any of these yet; the type exists so the wire format is
// stable when it does.
type EventPayload struct {
	NodeID   string         `json:"node_id"`
	Type     string         `json:"type"`
	Severity string         `json:"severity"`
	Payload  map[string]any `json:"payload,omitempty"`
}

// AckPayload is the controller's reply to register/heartbeat/telemetry.
type AckPayload struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	// ServerTime lets the node agent sanity-check clock skew.
	ServerTime time.Time `json:"server_time"`
}

// CommandPayload is a signed, idempotent controller-to-node command. The node
// agent rejects unknown commands and verifies node binding and expiry.
type CommandPayload struct {
	ID             string         `json:"id"`
	IdempotencyKey string         `json:"idempotency_key"`
	NodeID         string         `json:"node_id"`
	Command        string         `json:"command"`
	Args           map[string]any `json:"args,omitempty"`
	IssuedAt       time.Time      `json:"issued_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	Signature      string         `json:"signature"`
}

type CommandResultPayload struct {
	ID     string `json:"id"`
	NodeID string `json:"node_id"`
	// Status is populated for durable journaled results. Live node replies may
	// omit it because OK/Uncertain are the wire-level outcome fields.
	Status string `json:"status,omitempty"`
	OK     bool   `json:"ok"`
	// Uncertain means the command crossed a side-effect boundary but the node
	// could not prove its terminal state. Controllers must reconcile through an
	// authoritative query before treating the command as failed or succeeded.
	Uncertain   bool           `json:"uncertain,omitempty"`
	Result      map[string]any `json:"result,omitempty"`
	Error       string         `json:"error,omitempty"`
	CompletedAt time.Time      `json:"completed_at"`
}

func (p *CommandResultPayload) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	allowed := map[string]bool{"id": true, "node_id": true, "status": true, "ok": true, "uncertain": true, "result": true, "error": true, "completed_at": true}
	for key := range raw {
		if !allowed[key] {
			return fmt.Errorf("command result contains unknown field %s", key)
		}
	}
	type wire CommandResultPayload
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*p = CommandResultPayload(decoded)
	return nil
}

func SignCommand(command CommandPayload, secret []byte) (string, error) {
	material, err := commandSigningMaterial(command)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(material)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifyCommand(command CommandPayload, secret []byte) bool {
	expected, err := SignCommand(command, secret)
	return err == nil && hmac.Equal([]byte(expected), []byte(command.Signature))
}

func commandSigningMaterial(command CommandPayload) ([]byte, error) {
	return json.Marshal(struct {
		ID             string         `json:"id"`
		IdempotencyKey string         `json:"idempotency_key"`
		NodeID         string         `json:"node_id"`
		Command        string         `json:"command"`
		Args           map[string]any `json:"args,omitempty"`
		IssuedAt       time.Time      `json:"issued_at"`
		ExpiresAt      time.Time      `json:"expires_at"`
	}{command.ID, command.IdempotencyKey, command.NodeID, command.Command, command.Args, command.IssuedAt, command.ExpiresAt})
}

// CanonicalCommandEnvelope serializes every field of the signed wire command,
// including its signature, before any node-local target normalization occurs.
func CanonicalCommandEnvelope(command CommandPayload) ([]byte, error) {
	if _, err := commandSigningMaterial(command); err != nil {
		return nil, err
	}
	return json.Marshal(command)
}

// CommandSigningMaterialForOwnedStop exposes the exact HMAC input for the
// privileged local receiver; callers still need a separately pinned
// acknowledgement key and durable-intent check.
func CommandSigningMaterialForOwnedStop(command CommandPayload) ([]byte, error) {
	return commandSigningMaterial(command)
}

// CommandSigningMaterialForPlanRelaunch exposes the exact original typed
// envelope HMAC input to the separate fixed root broker validator.
func CommandSigningMaterialForPlanRelaunch(command CommandPayload) ([]byte, error) {
	return commandSigningMaterial(command)
}

// ModelPool is a model's context capacity on a runtime.
type ModelPool struct {
	PoolTokens       int `json:"pool_tokens"`
	Slots            int `json:"slots"`
	MaxRequestTokens int `json:"max_request_tokens"`
}
