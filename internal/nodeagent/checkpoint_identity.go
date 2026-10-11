package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	checkpointIdentityServiceUnit = "llama-server.service"
	checkpointIdentityMaxModel    = int64(256) << 30
	checkpointIdentityMaxExe      = int64(1) << 30
)

var checkpointSHA256RE = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// CheckpointIdentityRequest pins the local process and model expected by a
// checkpoint proof. Nothing in this request is treated as an observation.
type CheckpointIdentityRequest struct {
	Endpoint                 string
	ServiceUnit              string
	ModelPath                string
	ExpectedModelSHA256      string
	ApprovedModelRoots       []string
	ExpectedExecutableSHA256 string
}

// CheckpointLoadProvenance reports whether an observer has authenticated
// evidence of the artifact's historical load source.
type CheckpointLoadProvenance string

const CheckpointLoadProvenanceUnknown CheckpointLoadProvenance = "unknown"

// CheckpointLocalIdentity is a snapshot of local process, socket, executable,
// source-file, and mapping measurements. Its exported fields are observations,
// not authority. The controlled-source evidence kind is assigned only by the
// private observer after an authenticated custody receipt is reverified; the
// receipt, not a caller-constructed identity value, supplies provenance.
type CheckpointLocalIdentity struct {
	EvidenceKind        string
	Endpoint            string
	ServiceUnit         string
	BootID              string
	PID                 int
	ProcessStartTicks   uint64
	ListenerIP          string
	ListenerPort        uint16
	ListenerSocketInode uint64
	ExecutablePath      string
	ExecutableSHA256    string
	ExecutableDevice    uint64
	ExecutableInode     uint64
	ExecutableSize      int64
	ModelPath           string
	ModelSHA256         string
	ModelDevice         uint64
	ModelInode          uint64
	ModelSize           int64
	ObservedMappedBytes int64
	Fingerprint         string
}

// HasVerifiedLoadProvenance is deliberately always false. Current process,
// socket, executable, file, and mapping observations cannot prove historical
// model-load provenance; a separate authenticated before-load receipt is
// required.
func (CheckpointLocalIdentity) HasVerifiedLoadProvenance() bool { return false }

// LoadProvenance remains unknown until a separate authenticated before-load
// receipt is verified. No caller-provided request field can promote it.
func (CheckpointLocalIdentity) LoadProvenance() CheckpointLoadProvenance {
	return CheckpointLoadProvenanceUnknown
}

// ObserveCheckpointLocalIdentity accepts only a directly managed Linux
// llama-server listener and observes its exact allowlisted GGUF inode fully
// covered by readable private mappings in that listener process. This is not
// proof that the process loaded those bytes as weights; callers must establish
// immutable before-load provenance through a separate authenticated mechanism.
// Unsupported and uncertain current states are errors.
func ObserveCheckpointLocalIdentity(ctx context.Context, req CheckpointIdentityRequest) (CheckpointLocalIdentity, error) {
	if ctx == nil {
		return CheckpointLocalIdentity{}, errors.New("checkpoint identity context is required")
	}
	if err := ctx.Err(); err != nil {
		return CheckpointLocalIdentity{}, err
	}
	boundedCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	ctx = boundedCtx
	endpoint, host, port, err := parseCheckpointIdentityEndpoint(req.Endpoint)
	if err != nil {
		return CheckpointLocalIdentity{}, err
	}
	if req.ServiceUnit != checkpointIdentityServiceUnit {
		return CheckpointLocalIdentity{}, errors.New("checkpoint identity service unit is not allowlisted")
	}
	if !checkpointSHA256RE.MatchString(req.ExpectedModelSHA256) || !checkpointSHA256RE.MatchString(req.ExpectedExecutableSHA256) {
		return CheckpointLocalIdentity{}, errors.New("checkpoint identity requires exact model and executable SHA-256 allowlists")
	}
	if len(req.ApprovedModelRoots) == 0 || len(req.ApprovedModelRoots) > 16 {
		return CheckpointLocalIdentity{}, errors.New("checkpoint identity requires bounded approved model roots")
	}
	if len(req.ModelPath) == 0 || len(req.ModelPath) > 4096 || !filepath.IsAbs(req.ModelPath) {
		return CheckpointLocalIdentity{}, errors.New("checkpoint model path must be a bounded absolute path")
	}
	for _, component := range strings.Split(req.ModelPath, string(filepath.Separator)) {
		if component == ".." {
			return CheckpointLocalIdentity{}, errors.New("checkpoint model path contains traversal")
		}
	}
	for _, root := range req.ApprovedModelRoots {
		if len(root) > 4096 {
			return CheckpointLocalIdentity{}, errors.New("approved checkpoint model root is too long")
		}
		for _, component := range strings.Split(root, string(filepath.Separator)) {
			if component == ".." {
				return CheckpointLocalIdentity{}, errors.New("approved checkpoint model root contains traversal")
			}
		}
	}
	return observeCheckpointIdentityPlatform(ctx, req, endpoint, host, port)
}

func parseCheckpointIdentityEndpoint(raw string) (canonical string, host net.IP, port uint16, err error) {
	if raw == "" || len(raw) > 512 {
		return "", nil, 0, errors.New("checkpoint identity endpoint is empty or too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", nil, 0, errors.New("checkpoint identity endpoint must be a plain local HTTP listener URL")
	}
	if u.Hostname() == "" || strings.Contains(u.Hostname(), "%") {
		return "", nil, 0, errors.New("checkpoint identity endpoint must use a literal loopback address")
	}
	host = net.ParseIP(u.Hostname())
	if host == nil || !host.IsLoopback() {
		return "", nil, 0, errors.New("checkpoint identity endpoint must use a literal loopback address")
	}
	p := u.Port()
	if p == "" {
		return "", nil, 0, errors.New("checkpoint identity endpoint requires an explicit port")
	}
	var portNumber uint64
	for _, c := range p {
		if c < '0' || c > '9' {
			return "", nil, 0, errors.New("checkpoint identity endpoint port is invalid")
		}
		portNumber = portNumber*10 + uint64(c-'0')
		if portNumber > 65535 {
			return "", nil, 0, errors.New("checkpoint identity endpoint port is invalid")
		}
	}
	if portNumber == 0 {
		return "", nil, 0, errors.New("checkpoint identity endpoint port is invalid")
	}
	return "http://" + net.JoinHostPort(host.String(), fmt.Sprint(portNumber)), host, uint16(portNumber), nil
}

func checkpointIdentityFingerprint(identity CheckpointLocalIdentity) string {
	if identity.EvidenceKind == "controlled-source-fs-verity-v2" {
		material := fmt.Sprintf("checkpoint-local-controlled-source-v2\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00%d\x00%d\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%s\x00%d\x00%d\x00%d",
			identity.Endpoint, identity.ServiceUnit, identity.BootID, identity.PID,
			identity.ProcessStartTicks, identity.ListenerIP, identity.ListenerPort, identity.ListenerSocketInode,
			identity.ExecutablePath, identity.ExecutableSHA256, identity.ExecutableDevice, identity.ExecutableInode, identity.ExecutableSize, identity.ModelPath,
			identity.ModelSHA256, identity.ModelDevice, identity.ModelInode, identity.ModelSize)
		digest := sha256.Sum256([]byte(material))
		return hex.EncodeToString(digest[:])
	}
	material := fmt.Sprintf("checkpoint-local-identity-v2\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00%d\x00%d\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d",
		identity.Endpoint, identity.ServiceUnit, identity.BootID, identity.PID,
		identity.ProcessStartTicks, identity.ListenerIP, identity.ListenerPort, identity.ListenerSocketInode,
		identity.ExecutablePath, identity.ExecutableSHA256, identity.ExecutableDevice, identity.ExecutableInode, identity.ExecutableSize, identity.ModelPath,
		identity.ModelSHA256, identity.ModelDevice, identity.ModelInode, identity.ModelSize, identity.ObservedMappedBytes)
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:])
}
