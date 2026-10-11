package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	checkpointUnitMaxOutput      = 4096
	checkpointUnitMaxCgroupBytes = 16 << 10
)

var checkpointInvocationIDRE = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// CheckpointUnitIdentityRequest contains local policy inputs and references to
// local observers. It deliberately contains no process, unit, or cgroup facts.
type CheckpointUnitIdentityRequest struct {
	Custody       *CheckpointCustodyStore
	Identity      CheckpointIdentityRequest
	ExpectedAlias string
}

// CheckpointVerifiedUnitAssociation is returned only after custody, current
// local identity, and two fresh fixed-unit observations agree. It is not a
// checkpoint capability and does not change custody's label-only receipt.
type CheckpointVerifiedUnitAssociation struct {
	Custody      CheckpointCustodyVerification
	Identity     CheckpointLocalIdentity
	Invocation   string
	ControlGroup string
}

type checkpointUnitObservation struct {
	MainPID       int
	InvocationID  string
	ControlGroup  string
	ActiveState   string
	SubState      string
	CgroupMembers string
}

// ObserveCheckpointManagedUnit obtains every observation locally. The fixed
// unit's state and process membership are sampled around independently
// authenticated custody and process identity checks.
func ObserveCheckpointManagedUnit(ctx context.Context, req CheckpointUnitIdentityRequest) (CheckpointVerifiedUnitAssociation, error) {
	if ctx == nil {
		return CheckpointVerifiedUnitAssociation{}, errors.New("checkpoint unit identity context is required")
	}
	if err := ctx.Err(); err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	if req.Custody == nil || req.Identity.ServiceUnit != checkpointIdentityServiceUnit || req.ExpectedAlias == "" || len(req.ExpectedAlias) > 512 || strings.TrimSpace(req.ExpectedAlias) != req.ExpectedAlias || strings.ContainsAny(req.ExpectedAlias, "\x00\r\n") {
		return CheckpointVerifiedUnitAssociation{}, errors.New("checkpoint unit identity request is incomplete")
	}
	if err := validateCheckpointUnitIdentityRequest(req.Identity); err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return observeCheckpointManagedUnitPlatform(bounded, req)
}

func validateCheckpointUnitIdentityRequest(req CheckpointIdentityRequest) error {
	if _, _, _, err := parseCheckpointIdentityEndpoint(req.Endpoint); err != nil {
		return err
	}
	if req.ServiceUnit != checkpointIdentityServiceUnit {
		return errors.New("checkpoint identity service unit is not allowlisted")
	}
	if !checkpointSHA256RE.MatchString(req.ExpectedModelSHA256) || !checkpointSHA256RE.MatchString(req.ExpectedExecutableSHA256) {
		return errors.New("checkpoint identity requires exact model and executable SHA-256 allowlists")
	}
	if len(req.ApprovedModelRoots) == 0 || len(req.ApprovedModelRoots) > 16 {
		return errors.New("checkpoint identity requires bounded approved model roots")
	}
	if len(req.ModelPath) == 0 || len(req.ModelPath) > 4096 || !filepath.IsAbs(req.ModelPath) {
		return errors.New("checkpoint model path must be a bounded absolute path")
	}
	for _, candidate := range append([]string{req.ModelPath}, req.ApprovedModelRoots...) {
		if len(candidate) > 4096 {
			return errors.New("checkpoint model path or root is too long")
		}
		for _, component := range strings.Split(candidate, string(filepath.Separator)) {
			if component == ".." {
				return errors.New("checkpoint model path or root contains traversal")
			}
		}
	}
	return nil
}

func parseCheckpointUnitProperties(raw []byte) (checkpointUnitState, error) {
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput {
		return checkpointUnitState{}, errors.New("systemd unit output is empty or exceeds its bound")
	}
	values := make(map[string]string, 5)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == "" || strings.Count(line, "=") != 1 {
			return checkpointUnitState{}, errors.New("systemd unit output contains malformed property data")
		}
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState":
			if _, exists := values[key]; exists || value == "" {
				return checkpointUnitState{}, errors.New("systemd unit output contains duplicate or empty properties")
			}
			values[key] = value
		default:
			return checkpointUnitState{}, errors.New("systemd unit output contains an unexpected property")
		}
	}
	if len(values) != 5 {
		return checkpointUnitState{}, errors.New("systemd unit output is missing required properties")
	}
	pidText := values["MainPID"]
	if len(pidText) > 10 || (len(pidText) > 1 && pidText[0] == '0') {
		return checkpointUnitState{}, errors.New("systemd MainPID is malformed")
	}
	for _, c := range pidText {
		if c < '0' || c > '9' {
			return checkpointUnitState{}, errors.New("systemd MainPID is malformed")
		}
	}
	pid, err := strconv.Atoi(pidText)
	invocation := strings.ToLower(values["InvocationID"])
	if err != nil || pid <= 1 || !checkpointInvocationIDRE.MatchString(invocation) || invocation == strings.Repeat("0", 32) || !validCheckpointCgroupPath(values["ControlGroup"]) {
		return checkpointUnitState{}, errors.New("systemd unit identity is invalid")
	}
	return checkpointUnitState{MainPID: pid, InvocationID: invocation, ControlGroup: values["ControlGroup"], ActiveState: values["ActiveState"], SubState: values["SubState"]}, nil
}

// checkpointUnitState is the strictly parsed subset of systemd's fixed-unit
// properties used by the observer.
type checkpointUnitState struct {
	MainPID      int
	InvocationID string
	ControlGroup string
	ActiveState  string
	SubState     string
}

func validCheckpointCgroupPath(value string) bool {
	if len(value) < 2 || len(value) > 4096 || value[0] != '/' || strings.ContainsAny(value, "\\\x00\r\n") || path.Clean(value) != value || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func parseCheckpointCgroupMembership(raw []byte, expected string) (string, error) {
	if len(raw) == 0 || len(raw) > checkpointUnitMaxCgroupBytes || !validCheckpointCgroupPath(expected) {
		return "", errors.New("process cgroup membership is empty, oversized, or invalid")
	}
	found := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] == "" || strings.ContainsAny(parts[0]+parts[1]+parts[2], "\x00\r") {
			return "", errors.New("process cgroup membership is malformed")
		}
		for _, digit := range parts[0] {
			if digit < '0' || digit > '9' {
				return "", errors.New("process cgroup hierarchy id is malformed")
			}
		}
		if (parts[0] == "0" && parts[1] != "") || (parts[0] != "0" && parts[1] == "") || !validCheckpointCgroupMemberPath(parts[2]) {
			return "", errors.New("process cgroup hierarchy is malformed")
		}
		if parts[0] == "0" && parts[1] == "" {
			if found != "" || !validCheckpointCgroupPath(parts[2]) {
				return "", errors.New("process has ambiguous or invalid unified cgroup membership")
			}
			found = parts[2]
		}
	}
	if found == "" || found != expected {
		return "", fmt.Errorf("process is not an exact member of the systemd unit cgroup")
	}
	return found, nil
}

func validCheckpointCgroupMemberPath(value string) bool {
	if value == "/" {
		return true
	}
	return validCheckpointCgroupPath(value)
}

func joinCheckpointUnitIdentity(binding CheckpointCustodyVerification, identity CheckpointLocalIdentity, expectedAlias string, first, second checkpointUnitObservation) (CheckpointVerifiedUnitAssociation, error) {
	if !checkpointSHA256RE.MatchString(binding.BindingSHA256) || !checkpointSHA256RE.MatchString(binding.Nonce) || binding.ServiceUnit != checkpointIdentityServiceUnit || binding.UnitAssociation != "label-only-unverified" || binding.ActualAlias == "" || binding.ActualAlias != expectedAlias {
		return CheckpointVerifiedUnitAssociation{}, errors.New("custody receipt or locally expected alias is invalid")
	}
	legacy := binding.EvidenceKind == "" && (identity.EvidenceKind == "" || identity.EvidenceKind == "mapped-file-v1") && (identity.ObservedMappedBytes == 0 || identity.ObservedMappedBytes == identity.ModelSize)
	controlled := binding.EvidenceKind == "controlled-source-fs-verity-v2" && binding.ModelArgument == "/proc/self/fd/4" && custodyDigestRE.MatchString(binding.ArgvSHA256) && identity.EvidenceKind == binding.EvidenceKind && identity.ObservedMappedBytes >= 0 && identity.ObservedMappedBytes <= identity.ModelSize
	if (!legacy && !controlled) || identity.PID <= 1 || identity.ServiceUnit != checkpointIdentityServiceUnit || identity.Fingerprint == "" || identity.BootID != binding.BootID || identity.PID != binding.PID || identity.ProcessStartTicks != binding.ProcessStartTicks || identity.ListenerSocketInode != binding.ListenerSocketInode || identity.Endpoint != binding.Endpoint || identity.ExecutablePath != binding.ExecutablePath || !strings.EqualFold(identity.ExecutableSHA256, binding.ExecutableSHA256) || identity.ModelPath != binding.ArtifactPath || identity.ModelDevice != binding.ArtifactDevice || identity.ModelInode != binding.ArtifactInode || identity.ModelSize != binding.ArtifactSize || !strings.EqualFold(identity.ModelSHA256, binding.ArtifactSHA256) {
		return CheckpointVerifiedUnitAssociation{}, errors.New("custody and current local identity do not describe the same process and source")
	}
	if first != second || first.MainPID != identity.PID || first.ActiveState != "active" || first.SubState != "running" || first.CgroupMembers != first.ControlGroup {
		return CheckpointVerifiedUnitAssociation{}, errors.New("fixed systemd unit state or process membership changed or is not active")
	}
	return CheckpointVerifiedUnitAssociation{Custody: binding, Identity: identity, Invocation: first.InvocationID, ControlGroup: first.ControlGroup}, nil
}
