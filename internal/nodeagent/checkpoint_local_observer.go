package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	checkpointLocalObserverVersion       = 1
	checkpointLocalObserverMaxFrame      = 64 << 10
	checkpointLocalObserverNonceBytes    = 32
	checkpointLocalObserverMaxLifetime   = 10 * time.Second
	checkpointLocalObserverSigningDomain = "vram-governor/checkpoint-local-observer-response/v1\x00"
)

var checkpointLocalObserverHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CheckpointLocalObserverResult is one short-lived signed association from the
// fixed root broker. It is observation evidence only, not checkpointability.
type CheckpointLocalObserverResult struct {
	IssuedAt  string
	ExpiresAt string
	Caller    CheckpointLocalObserverIdentity
	Init      CheckpointLocalObserverIdentity
	Worker    CheckpointLocalObserverIdentity
	Binding   CheckpointManagedBinding
}

// CheckpointLocalObserverIdentity contains only signed public process identity
// fields. The unprivileged client never opens the root worker's exe/maps/ns.
type CheckpointLocalObserverIdentity struct {
	PID               int    `json:"pid"`
	UID               uint32 `json:"uid"`
	GID               uint32 `json:"gid"`
	StartTicks        uint64 `json:"start_ticks"`
	PIDNamespaceInode uint64 `json:"pid_namespace_inode"`
	ExecutablePath    string `json:"executable_path"`
	ExecutableSHA256  string `json:"executable_sha256"`
	ControlGroup      string `json:"control_group"`
	BootID            string `json:"boot_id"`
}

type checkpointLocalObserverRequest struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
}

type checkpointLocalObserverPayload struct {
	Version   int                             `json:"version"`
	Nonce     string                          `json:"nonce"`
	IssuedAt  string                          `json:"issued_at"`
	ExpiresAt string                          `json:"expires_at"`
	Caller    CheckpointLocalObserverIdentity `json:"caller"`
	Init      CheckpointLocalObserverIdentity `json:"init"`
	Worker    CheckpointLocalObserverIdentity `json:"worker"`
	Binding   CheckpointManagedBinding        `json:"binding"`
}

type checkpointLocalObserverEnvelope struct {
	Payload   checkpointLocalObserverPayload `json:"payload"`
	Signature string                         `json:"signature"`
}

// RunCheckpointLocalObserver starts the fixed root-only, read-only Unix broker.
// It accepts no socket, policy, key, PID, plan, or caller-selected path.
func RunCheckpointLocalObserver(ctx context.Context) error {
	if ctx == nil {
		return errors.New("checkpoint local observer context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runCheckpointLocalObserverPlatform(ctx)
}

// ObserveCheckpointLocalAssociation asks only for the locally fixed managed
// worker association; request data is a fresh nonce, never process authority.
func ObserveCheckpointLocalAssociation(ctx context.Context) (CheckpointLocalObserverResult, error) {
	if ctx == nil {
		return CheckpointLocalObserverResult{}, errors.New("checkpoint local observer context is required")
	}
	if err := ctx.Err(); err != nil {
		return CheckpointLocalObserverResult{}, err
	}
	return observeCheckpointLocalObserverPlatform(ctx)
}

func checkpointLocalObserverCanonicalRequest(nonce string) ([]byte, error) {
	if !checkpointLocalObserverHex64.MatchString(nonce) {
		return nil, errors.New("checkpoint local observer nonce is malformed")
	}
	return json.Marshal(checkpointLocalObserverRequest{Version: checkpointLocalObserverVersion, Nonce: nonce})
}

func checkpointLocalObserverDecodeRequest(raw []byte) (checkpointLocalObserverRequest, error) {
	var request checkpointLocalObserverRequest
	if len(raw) == 0 || len(raw) > checkpointLocalObserverMaxFrame || checkpointLocalObserverRejectDuplicateKeys(raw) != nil {
		return request, errors.New("checkpoint local observer request is empty, oversized, or duplicated")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, errors.New("checkpoint local observer request fields are invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return request, errors.New("checkpoint local observer request contains trailing data")
	}
	canonical, err := checkpointLocalObserverCanonicalRequest(request.Nonce)
	if err != nil || request.Version != checkpointLocalObserverVersion || !bytes.Equal(raw, canonical) {
		return request, errors.New("checkpoint local observer request is noncanonical or unsupported")
	}
	return request, nil
}

func checkpointLocalObserverSign(payload checkpointLocalObserverPayload, private ed25519.PrivateKey) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("checkpoint local observer signing key is invalid")
	}
	if err := checkpointLocalObserverValidatePayload(payload, time.Now().UTC(), true); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(payload)
	if err != nil || len(canonical) > checkpointLocalObserverMaxFrame-(ed25519.SignatureSize*2) {
		return nil, errors.New("checkpoint local observer payload is unencodable or oversized")
	}
	signed := append([]byte(checkpointLocalObserverSigningDomain), canonical...)
	envelope := checkpointLocalObserverEnvelope{Payload: payload, Signature: hex.EncodeToString(ed25519.Sign(private, signed))}
	wire, err := json.Marshal(envelope)
	if err != nil || len(wire) > checkpointLocalObserverMaxFrame {
		return nil, errors.New("checkpoint local observer response exceeds its frame bound")
	}
	return wire, nil
}

func checkpointLocalObserverVerify(wire []byte, public ed25519.PublicKey, nonce string, now time.Time) (CheckpointLocalObserverResult, error) {
	var result CheckpointLocalObserverResult
	if len(wire) == 0 || len(wire) > checkpointLocalObserverMaxFrame || len(public) != ed25519.PublicKeySize || !checkpointLocalObserverHex64.MatchString(nonce) || checkpointLocalObserverRejectDuplicateKeys(wire) != nil {
		return result, errors.New("checkpoint local observer response is empty, oversized, or malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var envelope checkpointLocalObserverEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return result, errors.New("checkpoint local observer response schema is invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, errors.New("checkpoint local observer response contains trailing data")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(wire, canonical) {
		return result, errors.New("checkpoint local observer response is noncanonical")
	}
	if envelope.Payload.Nonce != nonce {
		return result, errors.New("checkpoint local observer response nonce differs from the request")
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != envelope.Signature {
		return result, errors.New("checkpoint local observer signature encoding is invalid")
	}
	payloadBytes, err := json.Marshal(envelope.Payload)
	if err != nil {
		return result, errors.New("checkpoint local observer payload cannot be canonicalized")
	}
	signed := append([]byte(checkpointLocalObserverSigningDomain), payloadBytes...)
	if !checkpointLocalObserverSignatureValid(public, signed, signature) {
		return result, errors.New("checkpoint local observer response signature is invalid")
	}
	if err := checkpointLocalObserverValidatePayload(envelope.Payload, now.UTC(), false); err != nil {
		return result, err
	}
	p := envelope.Payload
	result = CheckpointLocalObserverResult{IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, Caller: p.Caller, Init: p.Init, Worker: p.Worker, Binding: p.Binding}
	return result, nil
}

func checkpointLocalObserverSignatureValid(public ed25519.PublicKey, signed, signature []byte) bool {
	return ed25519.Verify(public, signed, signature)
}

func checkpointLocalObserverValidatePayload(payload checkpointLocalObserverPayload, now time.Time, signing bool) error {
	if payload.Version != checkpointLocalObserverVersion || !checkpointLocalObserverHex64.MatchString(payload.Nonce) {
		return errors.New("checkpoint local observer response version or nonce is invalid")
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, payload.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || expires.Before(issued) || expires.Sub(issued) <= 0 || expires.Sub(issued) > checkpointLocalObserverMaxLifetime || now.Before(issued.Add(-time.Second)) || !signing && !now.Before(expires) {
		return errors.New("checkpoint local observer response time window is invalid or expired")
	}
	for role, identity := range []CheckpointLocalObserverIdentity{payload.Caller, payload.Init, payload.Worker} {
		if err := checkpointLocalObserverValidateIdentity(identity, role == 1); err != nil {
			return err
		}
	}
	if payload.Caller.UID == 0 || payload.Init.PID != 1 || payload.Init.UID != 0 || payload.Worker.UID != 0 || payload.Caller.PIDNamespaceInode == 0 || payload.Caller.PIDNamespaceInode != payload.Init.PIDNamespaceInode || payload.Caller.PIDNamespaceInode != payload.Worker.PIDNamespaceInode || payload.Caller.BootID != payload.Init.BootID || payload.Caller.BootID != payload.Worker.BootID {
		return errors.New("checkpoint local observer caller, init, and root worker are not joined in one PID namespace")
	}
	binding := payload.Binding
	association := binding.Association
	identity, custody := association.Identity, association.Custody
	if binding.Version != checkpointLaunchPlanVersion2 || !checkpointLocalObserverHex64.MatchString(binding.CurrentIncarnation) || !checkpointLocalObserverHex64.MatchString(binding.PlanSHA256) || !checkpointLocalObserverHex64.MatchString(binding.CustodyBindingSHA256) || binding.Alias == "" || identity.PID != payload.Worker.PID || identity.ProcessStartTicks != payload.Worker.StartTicks || identity.BootID != payload.Worker.BootID || identity.ExecutablePath != payload.Worker.ExecutablePath || !strings.EqualFold(identity.ExecutableSHA256, payload.Worker.ExecutableSHA256) || association.ControlGroup != payload.Worker.ControlGroup || association.Invocation == "" || binding.GPUBytes < 0 || binding.HostRSSBytes <= 0 || identity.EvidenceKind != "controlled-source-fs-verity-v2" || identity.ServiceUnit != checkpointIdentityServiceUnit || identity.Endpoint == "" || custody.EvidenceKind != "controlled-source-fs-verity-v2" || custody.PID != identity.PID || custody.ProcessStartTicks != identity.ProcessStartTicks || custody.BootID != identity.BootID || custody.ListenerSocketInode != identity.ListenerSocketInode || custody.UnitAssociation == "" || custody.ActualAlias != binding.Alias || !strings.EqualFold(binding.CustodyBindingSHA256, custody.BindingSHA256) {
		return errors.New("checkpoint local observer managed binding is incomplete or not joined to the signed worker")
	}
	if binding.Placement.Backend != "cuda" || binding.Placement.PhysicalIdentity == "" || binding.Placement.ChildMaskUUID == "" || binding.Placement.RuntimeDeviceToken == "" || binding.Placement.RuntimeVersion == "" || !checkpointLocalObserverHex64.MatchString(custody.BindingSHA256) || !checkpointLocalObserverHex64.MatchString(custody.ArgvSHA256) {
		return errors.New("checkpoint local observer binding placement or custody identity is incomplete")
	}
	return nil
}

func checkpointLocalObserverValidateIdentity(identity CheckpointLocalObserverIdentity, allowInitPID bool) error {
	if identity.PID < 1 || (!allowInitPID && identity.PID <= 1) || identity.StartTicks == 0 || identity.PIDNamespaceInode == 0 || identity.ExecutablePath == "" || len(identity.ExecutablePath) > 4096 || !utf8.ValidString(identity.ExecutablePath) || !strings.HasPrefix(identity.ExecutablePath, "/") || path.Clean(identity.ExecutablePath) != identity.ExecutablePath || strings.Contains(identity.ExecutablePath, " (deleted)") || !checkpointLocalObserverHex64.MatchString(identity.ExecutableSHA256) || identity.ControlGroup == "" || len(identity.ControlGroup) > 4096 || !utf8.ValidString(identity.ControlGroup) || !strings.HasPrefix(identity.ControlGroup, "/") || path.Clean(identity.ControlGroup) != identity.ControlGroup || !checkpointLocalObserverBootID.MatchString(identity.BootID) {
		return errors.New("checkpoint local observer process identity is invalid")
	}
	return nil
}

var checkpointLocalObserverBootID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func checkpointLocalObserverRejectDuplicateKeys(raw []byte) error {
	if len(raw) == 0 || len(raw) > checkpointLocalObserverMaxFrame || !utf8.Valid(raw) {
		return errors.New("JSON is empty, oversized, or invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tokens int
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds fixed bound")
		}
		tokens++
		if tokens > 8192 {
			return errors.New("JSON token count exceeds fixed bound")
		}
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
					return errors.New("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("JSON object duplicates key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
