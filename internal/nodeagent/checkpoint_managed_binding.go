package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const checkpointManagedBindingTimeout = 20 * time.Second
const checkpointManagedHTTPMax = 16 << 10

// CheckpointManagedBinding is a fresh association of the fixed launch plan,
// authenticated staged-load receipt, active local worker, live backend alias,
// and physical per-process placement. CurrentIncarnation binds the present
// worker and reconstructed launch argv; the fixed plan and its context/slot
// arguments describe requested launch intent, not measured backend allocation.
// GPUBytes and HostRSSBytes are current footprint evidence. PlanSHA256 is
// content integrity only, not proof that non-argv quota or policy values were
// runtime provenance. This observation does not establish snapshot compatibility,
// cross-process KV or library compatibility, catalog ModelFingerprint authority,
// or lasting residency.
type CheckpointManagedBinding struct {
	Version              string
	CurrentIncarnation   string
	PlanSHA256           string
	CustodyBindingSHA256 string
	Alias                string
	Association          CheckpointVerifiedUnitAssociation
	Placement            CheckpointDevicePlacement
	GPUBytes             int64
	HostRSSBytes         int64
	ObservedAt           string
}

// ObserveCheckpointManagedLocalBinding observes the fixed v2 plan and its
// current managed worker entirely locally. It accepts no caller-supplied
// process, receipt, path, alias, placement facts, or bypass controls.
func ObserveCheckpointManagedLocalBinding(ctx context.Context) (CheckpointManagedBinding, error) {
	if ctx == nil {
		return CheckpointManagedBinding{}, errors.New("managed checkpoint binding context is required")
	}
	bounded, cancel := context.WithTimeout(ctx, checkpointManagedBindingTimeout)
	defer cancel()
	return observeCheckpointManagedBindingPlatform(bounded)
}

func managedCheckpointCurrentIncarnation(association CheckpointVerifiedUnitAssociation, plan CheckpointLaunchPlan, argv []string) string {
	identity := association.Identity
	custody := association.Custody
	planMaterial, _ := json.Marshal(plan)
	parts := []string{
		"checkpoint-managed-current-v2", identity.EvidenceKind, identity.Endpoint, identity.BootID, identity.ServiceUnit, association.Invocation,
		strconv.Itoa(identity.PID), strconv.FormatUint(identity.ProcessStartTicks, 10), strconv.FormatUint(identity.ListenerSocketInode, 10), association.ControlGroup,
		identity.ListenerIP, strconv.Itoa(int(identity.ListenerPort)),
		custody.ModelArgument, custody.Endpoint, custody.ServiceUnit, custody.UnitAssociation, custody.BootID,
		// BindingSHA256 authenticates receipt bytes which include historical
		// boot-time stamps. Hash the immutable receipt tuple below, not that
		// timestamp-coupled envelope digest.
		strings.ToLower(custody.Nonce), strings.ToLower(custody.ArgvSHA256), strings.ToLower(custody.VerityDigest),
		strconv.FormatUint(custody.ArtifactDevice, 10), strconv.FormatUint(custody.ArtifactInode, 10), strconv.FormatInt(custody.ArtifactSize, 10), custody.ArtifactPath, strings.ToLower(custody.ArtifactSHA256),
		strconv.FormatUint(custody.ExecutableDevice, 10), strconv.FormatUint(custody.ExecutableInode, 10), strconv.FormatInt(custody.ExecutableSize, 10), custody.ExecutablePath, strings.ToLower(custody.ExecutableSHA256), strings.ToLower(custody.ExecutableVerityDigest),
		strconv.FormatUint(identity.ExecutableDevice, 10), strconv.FormatUint(identity.ExecutableInode, 10), strconv.FormatInt(identity.ExecutableSize, 10),
		identity.ExecutablePath, strings.ToLower(identity.ExecutableSHA256), identity.ModelPath,
		strings.ToLower(identity.ModelSHA256), strconv.FormatUint(identity.ModelDevice, 10), strconv.FormatUint(identity.ModelInode, 10), strconv.FormatInt(identity.ModelSize, 10),
		string(planMaterial), plan.Alias, plan.Model.Path, strings.ToLower(plan.Model.SHA256), plan.Executable.Path,
		strings.ToLower(plan.Executable.SHA256), plan.Placement.Backend, plan.Placement.IdentityKind,
		plan.Placement.PhysicalIdentity, plan.Placement.RuntimeDeviceToken, plan.Placement.RuntimeVersion,
		strconv.Itoa(plan.Placement.MaxAccelerators), strings.Join(argv, "\x00"),
	}
	material := strings.Join(parts, "\x00")
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:])
}

func managedCheckpointExpectedArgv(plan CheckpointLaunchPlan) ([]string, error) {
	args, err := fixedCheckpointPlacementArguments(plan)
	if err != nil {
		return nil, err
	}
	for index, arg := range args {
		if arg == "{CHECKPOINT_MODEL}" {
			args[index] = "/proc/self/fd/4"
		}
	}
	if !containsExact(args, "/proc/self/fd/4") {
		return nil, errors.New("fixed managed argv lacks descriptor model argument")
	}
	return append([]string{plan.Executable.Path}, args...), nil
}

func parseManagedCheckpointArgv(raw []byte) ([]string, error) {
	if len(raw) < 2 || len(raw) > 16<<10 || raw[len(raw)-1] != 0 || raw[len(raw)-2] == 0 {
		return nil, errors.New("managed process argv is unreadable, truncated, or malformed")
	}
	parts := strings.Split(string(raw[:len(raw)-1]), "\x00")
	if len(parts) > 128 || parts[0] == "" {
		return nil, errors.New("managed process argv exceeds its bound")
	}
	for _, part := range parts {
		if part == "" {
			return nil, errors.New("managed process argv contains an empty or ambiguous argument")
		}
	}
	return parts, nil
}

func equalCheckpointArgv(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) || len(a) > 128 {
		return false
	}
	for i := range a {
		if a[i] != b[i] || strings.ContainsRune(a[i], '\x00') {
			return false
		}
	}
	return true
}

// parseManagedCheckpointModelList validates the pinned llama-server model
// response shape. It returns only the configured alias; metadata is parsed to
// reject schema drift and is never treated as allocation evidence.
func parseManagedCheckpointModelList(raw []byte, expectedAlias string) (string, error) {
	if len(raw) == 0 || len(raw) > checkpointManagedHTTPMax || !json.Valid(raw) || !checkpointLaunchAliasRE.MatchString(expectedAlias) {
		return "", errors.New("model response is invalid or outside its bound")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return "", err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil || !exactManagedJSONKeys(root, "object", "data") {
		return "", errors.New("model response has unsupported root schema")
	}
	var object string
	if json.Unmarshal(root["object"], &object) != nil || object != "list" {
		return "", errors.New("model response is not a canonical model list")
	}
	var models []json.RawMessage
	if err := json.Unmarshal(root["data"], &models); err != nil || len(models) != 1 {
		return "", errors.New("current runtime must expose exactly one unambiguous loaded model")
	}
	var model map[string]json.RawMessage
	if err := json.Unmarshal(models[0], &model); err != nil || !exactManagedJSONKeys(model, "id", "aliases", "tags", "object", "created", "owned_by", "meta") {
		return "", errors.New("model response entry has unsupported schema or aliases")
	}
	var id, kind, owner string
	if json.Unmarshal(model["id"], &id) != nil || !checkpointLaunchAliasRE.MatchString(id) || id != expectedAlias ||
		json.Unmarshal(model["object"], &kind) != nil || kind != "model" ||
		json.Unmarshal(model["owned_by"], &owner) != nil || owner != "llamacpp" {
		return "", errors.New("model response entry identity is malformed or differs from the configured alias")
	}
	aliases, err := parseManagedCheckpointStringList(model["aliases"], 32, false)
	if err != nil || len(aliases) != 1 || aliases[0] != expectedAlias {
		return "", errors.New("model response aliases are absent, ambiguous, or differ from the configured alias")
	}
	if _, err := parseManagedCheckpointStringList(model["tags"], 64, true); err != nil {
		return "", fmt.Errorf("model response tags are malformed: %w", err)
	}
	created, err := parseManagedCheckpointInteger(model["created"], 0, math.MaxInt64)
	if err != nil || created == 0 {
		return "", errors.New("model response creation timestamp is malformed")
	}
	if err := validateManagedCheckpointModelMeta(model["meta"]); err != nil {
		return "", err
	}
	return id, nil
}

func exactManagedJSONKeys(value map[string]json.RawMessage, expected ...string) bool {
	if value == nil || len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func parseManagedCheckpointStringList(raw json.RawMessage, max int, allowEmpty bool) ([]string, error) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errors.New("expected a JSON string array")
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil || len(values) > max || (!allowEmpty && len(values) == 0) {
		return nil, errors.New("string array is null, malformed, or outside its bound")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, errors.New("string array member is malformed or oversized")
		}
		if _, exists := seen[value]; exists {
			return nil, errors.New("string array contains a duplicate value")
		}
		seen[value] = struct{}{}
	}
	return values, nil
}

func parseManagedCheckpointInteger(raw json.RawMessage, min, max int64) (int64, error) {
	if len(raw) == 0 || raw[0] == '"' || raw[0] == 'n' {
		return 0, errors.New("expected a non-null JSON integer")
	}
	value, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || value < min || value > max {
		return 0, errors.New("integer is malformed or outside its bound")
	}
	return value, nil
}

func validateManagedCheckpointModelMeta(raw json.RawMessage) error {
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &meta); err != nil || !exactManagedJSONKeys(meta, "vocab_type", "n_vocab", "n_ctx", "n_ctx_train", "n_embd", "n_params", "size", "ftype") {
		return errors.New("model response metadata has unsupported schema")
	}
	for _, field := range []string{"vocab_type", "n_vocab", "n_ctx", "n_ctx_train", "n_embd", "n_params", "size"} {
		min := int64(0)
		if field != "vocab_type" {
			min = 1
		}
		if _, err := parseManagedCheckpointInteger(meta[field], min, math.MaxInt64); err != nil {
			return fmt.Errorf("model response metadata field %q is malformed", field)
		}
	}
	var fileType string
	if json.Unmarshal(meta["ftype"], &fileType) != nil || fileType == "" || len(fileType) > 64 || strings.ContainsAny(fileType, "\x00\r\n") {
		return errors.New("model response metadata field \"ftype\" is malformed")
	}
	return nil
}

func validateManagedCheckpointReceipt(binding CheckpointCustodyVerification, plan CheckpointLaunchPlan, endpoint string) error {
	if binding.EvidenceKind != "controlled-source-fs-verity-v2" || binding.ModelArgument != "/proc/self/fd/4" || !custodyDigestRE.MatchString(binding.ArgvSHA256) || !checkpointSHA256RE.MatchString(binding.BindingSHA256) || !checkpointSHA256RE.MatchString(binding.Nonce) {
		return errors.New("managed worker requires an authenticated controlled-source v2 receipt")
	}
	if binding.ServiceUnit != checkpointIdentityServiceUnit || binding.Endpoint != endpoint || binding.ActualAlias != plan.Alias || binding.UnitAssociation != "label-only-unverified" {
		return errors.New("authenticated staged receipt differs from the fixed plan")
	}
	if binding.ArtifactPath == plan.Model.Path || binding.ArtifactPath == "" || binding.ArtifactSize != plan.Model.Bytes || !strings.EqualFold(binding.ArtifactSHA256, plan.Model.SHA256) || !strings.EqualFold(binding.ExecutableSHA256, plan.Executable.SHA256) || binding.ExecutablePath == plan.Executable.Path {
		return errors.New("staged source or executable does not match its separately approved original identity")
	}
	if filepath.Base(filepath.Dir(binding.ArtifactPath)) != "models" {
		return errors.New("authenticated staged model is outside the fixed custody model directory")
	}
	return nil
}

func managedCheckpointEndpoint(plan CheckpointLaunchPlan) string {
	return "http://" + net.JoinHostPort(net.ParseIP(plan.Endpoint.Host).String(), strconv.Itoa(plan.Endpoint.Port))
}

func validateManagedCheckpointPlan(plan *PinnedCheckpointLaunchPlan) (CheckpointLaunchPlan, error) {
	if plan == nil {
		return CheckpointLaunchPlan{}, errors.New("fixed managed launch plan is unavailable")
	}
	spec := plan.Spec()
	if spec.Version != checkpointLaunchPlanVersion2 || spec.Placement == nil {
		return CheckpointLaunchPlan{}, errors.New("managed binding requires the fixed v2 launch plan")
	}
	if err := validateCheckpointFixedPlan(spec); err != nil {
		return CheckpointLaunchPlan{}, err
	}
	if _, err := fixedCheckpointPlacementArguments(spec); err != nil {
		return CheckpointLaunchPlan{}, err
	}
	return spec, nil
}
