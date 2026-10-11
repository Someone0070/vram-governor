package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"vram-governor/internal/wsproto"
)

// RunCheckpointLifecycleBroker is called only by the fixed root service. The
// platform implementation owns its fixed local socket and never accepts CLI
// paths, arguments, environment, unit names, or process identifiers.
func RunCheckpointLifecycleBroker(ctx context.Context) error {
	if ctx == nil {
		return errors.New("checkpoint lifecycle broker context is required")
	}
	return runCheckpointLifecycleBrokerPlatform(ctx, fixedCheckpointPlanBrokerPaths())
}

func (p *commandProcessor) executePlanRelaunch(ctx context.Context, command wsproto.CommandPayload, mutation bool, pinnedKey []byte) (map[string]any, string) {
	if ctx == nil || ctx.Err() != nil || p == nil || p.cfg == nil {
		return nil, "plan relaunch broker context is unavailable"
	}
	paths := p.planRelaunchPathSet()
	var originalWire []byte
	var key []byte
	stepID, _ := checkpointPlanRelaunchStepForCommand(command.Command)
	if mutation {
		pending, ok := p.pending[command.ID]
		if !ok || pending.CommandID != command.ID || pending.IdempotencyKey != command.IdempotencyKey || pending.Command != command.Command || pending.PlanRelaunchSigningMaterialSHA256 == "" || len(pending.PinnedPlanBrokerPublicKey) != ed25519.PublicKeySize {
			return nil, "plan relaunch durable intent is unavailable"
		}
		originalWire = append([]byte(nil), pending.OriginalEnvelope...)
		key = append([]byte(nil), pending.PinnedPlanBrokerPublicKey...)
	} else {
		stepID, _ = command.Args["query_step"].(string)
		accelerator, _ := command.Args["accelerator_id"].(string)
		operation := p.planRelaunchOperations[accelerator]
		step, exists := operation.Steps[stepID]
		if !exists || step.CommandID == "" || len(step.OriginalEnvelope) == 0 || len(step.PinnedRootPublicKey) != ed25519.PublicKeySize {
			return nil, "plan relaunch query original is unavailable"
		}
		originalWire = append([]byte(nil), step.OriginalEnvelope...)
		key = append([]byte(nil), step.PinnedRootPublicKey...)
	}
	if !mutation && stepID != "urgent_load" && stepID != "victim_reload" {
		return nil, "plan relaunch query step is invalid"
	}
	if mutation && len(pinnedKey) != 0 && !bytes.Equal(pinnedKey, key) {
		return nil, "plan relaunch key pin changed after durable intent"
	}
	requestWire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil {
		return nil, "plan relaunch request could not be canonicalized"
	}
	requestRaw, err := json.Marshal(checkpointPlanBrokerRequest{Command: requestWire})
	if err != nil || len(requestRaw) > checkpointPlanRelaunchMaxFrame {
		return nil, "plan relaunch request exceeds its fixed frame bound"
	}
	responseRaw, err := invokeCheckpointPlanBroker(ctx, paths, requestRaw)
	if err != nil {
		return nil, "root plan broker outcome is uncertain"
	}
	if len(responseRaw) == 0 || len(responseRaw) > checkpointPlanRelaunchMaxFrame || rejectDuplicateJSONKeys(responseRaw) != nil {
		return nil, "root plan broker response is malformed"
	}
	decoder := json.NewDecoder(bytes.NewReader(responseRaw))
	decoder.DisallowUnknownFields()
	var response checkpointPlanBrokerResponse
	if decoder.Decode(&response) != nil {
		return nil, "root plan broker response schema is invalid"
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		return nil, "root plan broker response has trailing data"
	}
	canonical, err := json.Marshal(response)
	if err != nil || !bytes.Equal(canonical, responseRaw) {
		return nil, "root plan broker response is not canonical"
	}
	if response.Error != "" {
		return nil, "root plan broker rejected the linked operation"
	}
	if response.Pending {
		if len(response.Receipt) != 0 {
			return nil, "root plan broker returned both a receipt and pending status"
		}
		if mutation {
			return nil, "root plan broker step remains uncertain"
		}
		return map[string]any{"action": command.Command, "operation_id": command.Args["operation_id"], "query_step": stepID, "pending": true, "reconciled": false}, ""
	}
	if len(response.Receipt) == 0 {
		return nil, "root plan broker omitted its signed operation receipt"
	}
	receipt, err := verifyCheckpointPlanRelaunchReceipt(response.Receipt, ed25519.PublicKey(key), originalWire, p.cfg.CommandSigningSecret)
	if err != nil || receipt.Step != stepID || receipt.NodeID != p.cfg.NodeID {
		return nil, "root plan broker receipt did not bind the exact durable original"
	}
	return map[string]any{"action": command.Command, "command_id": receipt.CommandID, "idempotency_key": receipt.IdempotencyKey, "receipt": base64.StdEncoding.EncodeToString(response.Receipt), "receipt_sha256": checkpointPlanRelaunchReceiptDigest(response.Receipt), "catalog_id": receipt.CatalogID, "plan_sha256": receipt.PlanSHA256, "alias": receipt.Alias, "invocation_id": receipt.InvocationID, "main_pid": receipt.MainPID, "current_incarnation": receipt.CurrentIncarnation, "reconciled": true}, ""
}

func validateCheckpointPlanRelaunchCommandTime(command wsproto.CommandPayload, now time.Time) error {
	if command.IssuedAt.IsZero() || command.ExpiresAt.IsZero() || !now.Before(command.ExpiresAt) || command.IssuedAt.After(now) || command.ExpiresAt.Sub(command.IssuedAt) > checkpointPlanBrokerMaxTimeout {
		return errors.New("plan relaunch command validity window is invalid")
	}
	return nil
}

func planRelaunchSigningMaterialDigest(command wsproto.CommandPayload) (string, error) {
	material, err := wsproto.CommandSigningMaterialForPlanRelaunch(command)
	if err != nil {
		return "", err
	}
	return sha256Hex(material), nil
}

func planRelaunchCommandStep(command wsproto.CommandPayload) (string, error) {
	if command.Command == checkpointPlanRelaunchQueryCommand {
		step, ok := command.Args["query_step"].(string)
		if !ok || (step != "urgent_load" && step != "victim_reload") {
			return "", errors.New("plan relaunch query step is invalid")
		}
		return step, nil
	}
	step, ok := checkpointPlanRelaunchStepForCommand(command.Command)
	if !ok {
		return "", fmt.Errorf("unsupported plan relaunch step %q", command.Command)
	}
	return step, nil
}
